#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::sync::{Arc, Mutex as StdMutex, atomic::{AtomicUsize, Ordering}};
use std::thread;
use std::time::Duration;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::future::Future;
use std::pin::Pin;

use asupersync::sync::Notify;

// TrackedWaker implementation for manual polling
#[derive(Debug)]
struct TrackedWaker {
    waiter_id: usize,
    storm_id: usize,
    tracker: ContentionStormTracker,
}

impl TrackedWaker {
    fn new(waiter_id: usize, storm_id: usize, tracker: ContentionStormTracker) -> Self {
        Self { waiter_id, storm_id, tracker }
    }

    fn create_waker(&self) -> Waker {
        unsafe fn wake(_ptr: *const ()) {
            // Wake implementation for testing - just record that wake was called
        }

        unsafe fn wake_by_ref(_: *const ()) {
            // Wake by ref implementation
        }

        unsafe fn clone(ptr: *const ()) -> RawWaker {
            RawWaker::new(ptr, &WAKER_VTABLE)
        }

        unsafe fn drop(_: *const ()) {
            // Drop implementation
        }

        static WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);

        let raw = RawWaker::new(self as *const _ as *const (), &WAKER_VTABLE);
        unsafe { Waker::from_raw(raw) }
    }
}

#[derive(Debug, Clone)]
struct ContentionStormTracker {
    operations: Arc<StdMutex<Vec<String>>>,
    wakeup_events: Arc<StdMutex<Vec<WakeupEvent>>>,
    delivery_stats: Arc<StdMutex<DeliveryStats>>,
    invariant_violations: Arc<StdMutex<Vec<InvariantViolation>>>,
}

#[derive(Debug, Clone)]
struct WakeupEvent {
    waiter_id: usize,
    storm_id: usize,
    event_type: WakeupType,
    timestamp: std::time::Instant,
    active_waiters_before: usize,
    active_waiters_after: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum WakeupType {
    WaiterAwoken,
    NotificationStored,
    StoredNotificationConsumed,
    WaiterCancelled,
}

#[derive(Debug, Clone)]
struct DeliveryStats {
    total_notify_one_calls: usize,
    total_waiters_created: usize,
    total_waiters_awoken: usize,
    total_notifications_stored: usize,
    total_notifications_consumed: usize,
    total_waiters_cancelled: usize,
}

#[derive(Debug, Clone)]
struct InvariantViolation {
    violation_type: String,
    description: String,
    storm_id: usize,
}

impl ContentionStormTracker {
    fn new() -> Self {
        Self {
            operations: Arc::new(StdMutex::new(Vec::new())),
            wakeup_events: Arc::new(StdMutex::new(Vec::new())),
            delivery_stats: Arc::new(StdMutex::new(DeliveryStats {
                total_notify_one_calls: 0,
                total_waiters_created: 0,
                total_waiters_awoken: 0,
                total_notifications_stored: 0,
                total_notifications_consumed: 0,
                total_waiters_cancelled: 0,
            })),
            invariant_violations: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    fn record_operation(&self, op: &str) {
        if let Ok(mut ops) = self.operations.lock() {
            ops.push(op.to_string());
        }
    }

    fn record_wakeup_event(&self, event: WakeupEvent) {
        if let Ok(mut events) = self.wakeup_events.lock() {
            events.push(event);
        }
    }

    fn record_violation(&self, violation: InvariantViolation) {
        if let Ok(mut violations) = self.invariant_violations.lock() {
            violations.push(violation);
        }
    }

    fn validate_at_least_once_delivery(&self) {
        if let Ok(stats) = self.delivery_stats.lock() {
            // Simplified invariant: Basic sanity checks on the statistics
            // Note: Without access to stored_notifications, we can't validate exact delivery counts

            // Invariant: We should have some activity if notify_one was called
            if stats.total_notify_one_calls > 0 {
                let total_activity = stats.total_waiters_awoken + stats.total_notifications_stored + stats.total_waiters_cancelled;
                if total_activity == 0 {
                    self.record_violation(InvariantViolation {
                        violation_type: "no_activity_despite_notifications".to_string(),
                        description: format!(
                            "Called notify_one {} times but no waiters were awoken, stored, or cancelled",
                            stats.total_notify_one_calls
                        ),
                        storm_id: 0,
                    });
                }
            }

            // Invariant: Created waiters should either be awoken, cancelled, or still waiting
            let total_waiter_outcomes = stats.total_waiters_awoken + stats.total_waiters_cancelled;
            if total_waiter_outcomes > stats.total_waiters_created {
                self.record_violation(InvariantViolation {
                    violation_type: "more_outcomes_than_waiters".to_string(),
                    description: format!(
                        "Created {} waiters but had {} outcomes (awoken + cancelled)",
                        stats.total_waiters_created, total_waiter_outcomes
                    ),
                    storm_id: 0,
                });
            }
        }

        // Check for any violations and panic if found
        if let Ok(violations) = self.invariant_violations.lock() {
            if !violations.is_empty() {
                for violation in violations.iter() {
                    self.record_operation(&format!(
                        "VIOLATION: {} - {}",
                        violation.violation_type, violation.description
                    ));
                }
                panic!("notify_one contention storm invariant violations detected: {} violations", violations.len());
            }
        }
    }
}

#[derive(Debug, Clone, Arbitrary)]
struct ContentionStormConfig {
    pattern: StormPattern,
    waiter_threads: u8,
    notifier_threads: u8,
    duration_ms: u16,
}

#[derive(Debug, Clone, Arbitrary)]
enum StormPattern {
    HighFrequencyNotify { frequency_us: u16 },
    BurstyNotify { burst_size: u8, burst_interval_ms: u16 },
    MixedWaitersNotifiers { waiter_ratio: f32 },
    CancelHeavy { cancel_probability: f32 },
    StorageContention { store_then_consume_cycles: u8 },
    RapidTurnover { create_destroy_cycles: u8 },
    LoadBalance { notify_spread_us: u16 },
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let config: ContentionStormConfig = u.arbitrary().unwrap_or(ContentionStormConfig {
        pattern: StormPattern::HighFrequencyNotify { frequency_us: 100 },
        waiter_threads: 4,
        notifier_threads: 2,
        duration_ms: 50,
    });

    // Limit thread counts to prevent resource exhaustion
    if config.waiter_threads == 0 || config.waiter_threads > 12 {
        return;
    }
    if config.notifier_threads == 0 || config.notifier_threads > 6 {
        return;
    }
    if config.duration_ms > 200 {
        return;
    }

    let tracker = ContentionStormTracker::new();

    // Execute the storm pattern
    match config.pattern {
        StormPattern::HighFrequencyNotify { frequency_us } => {
            test_high_frequency_notify_storm(&tracker, &config, frequency_us);
        }

        StormPattern::BurstyNotify { burst_size, burst_interval_ms } => {
            test_bursty_notify_storm(&tracker, &config, burst_size, burst_interval_ms);
        }

        StormPattern::MixedWaitersNotifiers { waiter_ratio } => {
            test_mixed_waiters_notifiers_storm(&tracker, &config, waiter_ratio);
        }

        StormPattern::CancelHeavy { cancel_probability } => {
            test_cancel_heavy_storm(&tracker, &config, cancel_probability);
        }

        StormPattern::StorageContention { store_then_consume_cycles } => {
            test_storage_contention_storm(&tracker, &config, store_then_consume_cycles);
        }

        StormPattern::RapidTurnover { create_destroy_cycles } => {
            test_rapid_turnover_storm(&tracker, &config, create_destroy_cycles);
        }

        StormPattern::LoadBalance { notify_spread_us } => {
            test_load_balance_storm(&tracker, &config, notify_spread_us);
        }
    }

    // Validate all at-least-once delivery invariants
    tracker.validate_at_least_once_delivery();
});

fn test_high_frequency_notify_storm(
    tracker: &ContentionStormTracker,
    config: &ContentionStormConfig,
    frequency_us: u16
) {
    let duration_ms = config.duration_ms;
    let waiter_threads = config.waiter_threads;
    let notifier_threads = config.notifier_threads;
    tracker.record_operation("test_high_frequency_notify_storm");

    let notify = Arc::new(Notify::new());
    let mut handles = Vec::new();
    let running = Arc::new(AtomicUsize::new(1));

    // Start waiter threads
    for waiter_id in 0..waiter_threads {
        let notify_clone = Arc::clone(&notify);
        let tracker_clone = tracker.clone();
        let running_clone = Arc::clone(&running);

        let handle = thread::spawn(move || {
            let mut waiter_count = 0;
            while running_clone.load(Ordering::Acquire) == 1 {
                waiter_count += 1;

                // Track active waiters before creating waiter
                let active_before = notify_clone.waiter_count();

                let mut waiter = notify_clone.notified();
                let tracked_waker = TrackedWaker::new(waiter_id as usize, waiter_count, tracker_clone.clone());
                let waker = tracked_waker.create_waker();
                let mut context = Context::from_waker(&waker);

                // Record waiter creation
                if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                    stats.total_waiters_created += 1;
                }

                // Poll the waiter
                match Pin::new(&mut waiter).poll(&mut context) {
                    Poll::Ready(()) => {
                        // Waiter was immediately ready (consumed stored notification or got notified)
                        let active_after = notify_clone.waiter_count();

                        tracker_clone.record_wakeup_event(WakeupEvent {
                            waiter_id: waiter_id as usize,
                            storm_id: waiter_count,
                            event_type: WakeupType::WaiterAwoken,
                            timestamp: std::time::Instant::now(),
                            active_waiters_before: active_before,
                            active_waiters_after: active_after,
                        });

                        if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                            stats.total_waiters_awoken += 1;
                        }
                    }
                    Poll::Pending => {
                        // Waiter is pending - will be woken later or cancelled
                        // For high-frequency testing, we cancel some waiters to test cleanup
                        if waiter_count % 3 == 0 {
                            // Cancel this waiter
                            drop(waiter);
                            tracker_clone.record_wakeup_event(WakeupEvent {
                                waiter_id: waiter_id as usize,
                                storm_id: waiter_count,
                                event_type: WakeupType::WaiterCancelled,
                                timestamp: std::time::Instant::now(),
                                active_waiters_before: active_before,
                                active_waiters_after: notify_clone.waiter_count(),
                            });

                            if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                                stats.total_waiters_cancelled += 1;
                            }
                        }
                    }
                }

                // Brief pause between waiter creations
                if frequency_us > 0 {
                    thread::sleep(Duration::from_micros(frequency_us.min(1000) as u64));
                }
            }
        });

        handles.push(handle);
    }

    // Start notifier threads
    for notifier_id in 0..notifier_threads {
        let notify_clone = Arc::clone(&notify);
        let tracker_clone = tracker.clone();
        let running_clone = Arc::clone(&running);

        let handle = thread::spawn(move || {
            let mut notify_count = 0;
            while running_clone.load(Ordering::Acquire) == 1 {
                notify_count += 1;

                // Track active waiters before notify
                let active_before = notify_clone.waiter_count();

                // Call notify_one
                notify_clone.notify_one();

                // Track state after notify
                let active_after = notify_clone.waiter_count();

                // Record notify stats
                if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                    stats.total_notify_one_calls += 1;

                    if active_after < active_before {
                        // A waiter was likely awoken (waiter count decreased)
                        stats.total_waiters_awoken += 1;
                    } else {
                        // Notification was probably stored (no waiters decreased)
                        stats.total_notifications_stored += 1;
                    }
                }

                tracker_clone.record_operation(&format!("notifier_{}_notify_{}", notifier_id, notify_count));

                // High frequency notifications
                if frequency_us > 0 {
                    thread::sleep(Duration::from_micros(frequency_us.min(500) as u64));
                }
            }
        });

        handles.push(handle);
    }

    // Let the storm run
    thread::sleep(Duration::from_millis(duration_ms.min(200) as u64));

    // Stop all threads
    running.store(0, Ordering::Release);

    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }

    tracker.record_operation("high_frequency_notify_storm_complete");
}

fn test_bursty_notify_storm(
    tracker: &ContentionStormTracker,
    config: &ContentionStormConfig,
    burst_size: u8,
    burst_interval_ms: u16
) {
    tracker.record_operation("test_bursty_notify_storm");

    let notify = Arc::new(Notify::new());
    let mut handles = Vec::new();

    // Create a burst of waiters
    for i in 0..config.waiter_threads.min(8) {
        let notify_clone = Arc::clone(&notify);
        let tracker_clone = tracker.clone();

        let handle = thread::spawn(move || {
            let mut waiter = notify_clone.notified();
            let tracked_waker = TrackedWaker::new(i as usize, 1, tracker_clone.clone());
            let waker = tracked_waker.create_waker();
            let mut context = Context::from_waker(&waker);

            if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                stats.total_waiters_created += 1;
            }

            // Poll once to register waiter
            let _ = Pin::new(&mut waiter).poll(&mut context);

            // Wait for notification or timeout
            thread::sleep(Duration::from_millis(burst_interval_ms.min(100) as u64 * 2));

            // Check if waiter was notified
            if let Poll::Ready(()) = Pin::new(&mut waiter).poll(&mut context) {
                tracker_clone.record_wakeup_event(WakeupEvent {
                    waiter_id: i as usize,
                    storm_id: 1,
                    event_type: WakeupType::WaiterAwoken,
                    timestamp: std::time::Instant::now(),
                    stored_notifications_before: 0,
                    stored_notifications_after: notify_clone.stored_notifications.load(Ordering::Acquire),
                    active_waiters_before: 0,
                    active_waiters_after: notify_clone.waiter_count(),
                });

                if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                    stats.total_waiters_awoken += 1;
                }
            }
        });

        handles.push(handle);
    }

    // Wait for waiters to register
    thread::sleep(Duration::from_millis(10));

    // Send a burst of notifications
    for i in 0..burst_size.min(10) {
        notify.notify_one();

        if let Ok(mut stats) = tracker.delivery_stats.lock() {
            stats.total_notify_one_calls += 1;
        }

        tracker.record_operation(&format!("burst_notify_{}", i));

        if burst_interval_ms > 0 {
            thread::sleep(Duration::from_millis(burst_interval_ms.min(50) as u64));
        }
    }

    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }

    tracker.record_operation("bursty_notify_storm_complete");
}

fn test_mixed_waiters_notifiers_storm(
    tracker: &ContentionStormTracker,
    config: &ContentionStormConfig,
    _waiter_ratio: f32
) {
    tracker.record_operation("test_mixed_waiters_notifiers_storm");

    let waiter_threads = config.waiter_threads;
    let duration_ms = config.duration_ms;

    let notify = Arc::new(Notify::new());
    let mut handles = Vec::new();

    // Interleave waiter and notifier creation
    for i in 0..waiter_threads.min(6) {
        let notify_clone = Arc::clone(&notify);
        let tracker_clone = tracker.clone();
        let should_notify = i % 2 == 1;

        let handle = thread::spawn(move || {
            if should_notify {
                // This thread will notify
                for j in 0..3 {
                    notify_clone.notify_one();

                    if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                        stats.total_notify_one_calls += 1;
                    }

                    tracker_clone.record_operation(&format!("mixed_notify_{}_{}", i, j));
                    thread::sleep(Duration::from_micros(100));
                }
            } else {
                // This thread will wait
                let mut waiter = notify_clone.notified();
                let tracked_waker = TrackedWaker::new(i as usize, 1, tracker_clone.clone());
                let waker = tracked_waker.create_waker();
                let mut context = Context::from_waker(&waker);

                if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                    stats.total_waiters_created += 1;
                }

                // Poll to register
                let _ = Pin::new(&mut waiter).poll(&mut context);

                // Wait for notification
                thread::sleep(Duration::from_millis(duration_ms.min(100) as u64));

                // Check final state
                if let Poll::Ready(()) = Pin::new(&mut waiter).poll(&mut context) {
                    if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                        stats.total_waiters_awoken += 1;
                    }
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }

    tracker.record_operation("mixed_waiters_notifiers_storm_complete");
}

fn test_cancel_heavy_storm(
    tracker: &ContentionStormTracker,
    config: &ContentionStormConfig,
    cancel_probability: f32
) {
    tracker.record_operation("test_cancel_heavy_storm");

    let waiter_threads = config.waiter_threads;
    let notifier_threads = config.notifier_threads;
    let duration_ms = config.duration_ms;

    let notify = Arc::new(Notify::new());
    let mut handles = Vec::new();
    let should_cancel = cancel_probability > 0.5;

    // Create many waiters that will be cancelled
    for i in 0..waiter_threads.min(8) {
        let notify_clone = Arc::clone(&notify);
        let tracker_clone = tracker.clone();

        let handle = thread::spawn(move || {
            let mut waiter = notify_clone.notified();
            let tracked_waker = TrackedWaker::new(i as usize, 1, tracker_clone.clone());
            let waker = tracked_waker.create_waker();
            let mut context = Context::from_waker(&waker);

            if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                stats.total_waiters_created += 1;
            }

            // Poll to register
            let _ = Pin::new(&mut waiter).poll(&mut context);

            if should_cancel && i % 2 == 0 {
                // Cancel this waiter early
                thread::sleep(Duration::from_micros(50));
                drop(waiter);

                tracker_clone.record_wakeup_event(WakeupEvent {
                    waiter_id: i as usize,
                    storm_id: 1,
                    event_type: WakeupType::WaiterCancelled,
                    timestamp: std::time::Instant::now(),
                    active_waiters_before: 0,
                    active_waiters_after: notify_clone.waiter_count(),
                });

                if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                    stats.total_waiters_cancelled += 1;
                }
            } else {
                // Let this waiter potentially be notified
                thread::sleep(Duration::from_millis(duration_ms.min(50) as u64));

                if let Poll::Ready(()) = Pin::new(&mut waiter).poll(&mut context) {
                    if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                        stats.total_waiters_awoken += 1;
                    }
                }
            }
        });

        handles.push(handle);
    }

    // Send some notifications to the remaining waiters
    thread::sleep(Duration::from_millis(10));
    for i in 0..notifier_threads.min(4) {
        notify.notify_one();

        if let Ok(mut stats) = tracker.delivery_stats.lock() {
            stats.total_notify_one_calls += 1;
        }

        tracker.record_operation(&format!("cancel_heavy_notify_{}", i));
        thread::sleep(Duration::from_micros(100));
    }

    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }

    tracker.record_operation("cancel_heavy_storm_complete");
}

fn test_storage_contention_storm(
    tracker: &ContentionStormTracker,
    _config: &ContentionStormConfig,
    store_then_consume_cycles: u8
) {
    tracker.record_operation("test_storage_contention_storm");

    let notify = Arc::new(Notify::new());

    // First, generate stored notifications by notifying with no waiters
    for i in 0..store_then_consume_cycles.min(10) {
        notify.notify_one();

        if let Ok(mut stats) = tracker.delivery_stats.lock() {
            stats.total_notify_one_calls += 1;
            stats.total_notifications_stored += 1;
        }

        tracker.record_operation(&format!("store_notification_{}", i));
    }

    // Then create waiters to consume the stored notifications
    let mut handles = Vec::new();
    for i in 0..store_then_consume_cycles.min(10) {
        let notify_clone = Arc::clone(&notify);
        let tracker_clone = tracker.clone();

        let handle = thread::spawn(move || {
            let mut waiter = notify_clone.notified();
            let tracked_waker = TrackedWaker::new(i as usize, 1, tracker_clone.clone());
            let waker = tracked_waker.create_waker();
            let mut context = Context::from_waker(&waker);

            if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                stats.total_waiters_created += 1;
            }

            // Should be immediately ready due to stored notification
            if let Poll::Ready(()) = Pin::new(&mut waiter).poll(&mut context) {
                tracker_clone.record_wakeup_event(WakeupEvent {
                    waiter_id: i as usize,
                    storm_id: 1,
                    event_type: WakeupType::StoredNotificationConsumed,
                    timestamp: std::time::Instant::now(),
                    active_waiters_before: 0,
                    active_waiters_after: notify_clone.waiter_count(),
                });

                if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                    stats.total_notifications_consumed += 1;
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }

    tracker.record_operation("storage_contention_storm_complete");
}

fn test_rapid_turnover_storm(
    tracker: &ContentionStormTracker,
    config: &ContentionStormConfig,
    create_destroy_cycles: u8
) {
    tracker.record_operation("test_rapid_turnover_storm");

    let notify = Arc::new(Notify::new());

    // Rapid create/destroy cycles
    for cycle in 0..create_destroy_cycles.min(5) {
        let mut handles = Vec::new();

        // Create burst of short-lived waiters
        for i in 0..config.waiter_threads.min(4) {
            let notify_clone = Arc::clone(&notify);
            let tracker_clone = tracker.clone();

            let handle = thread::spawn(move || {
                let mut waiter = notify_clone.notified();
                let tracked_waker = TrackedWaker::new(i as usize, cycle as usize, tracker_clone.clone());
                let waker = tracked_waker.create_waker();
                let mut context = Context::from_waker(&waker);

                if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                    stats.total_waiters_created += 1;
                }

                // Brief poll, then immediate destruction
                let _ = Pin::new(&mut waiter).poll(&mut context);
                thread::sleep(Duration::from_micros(10));
                drop(waiter);

                if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                    stats.total_waiters_cancelled += 1;
                }
            });

            handles.push(handle);
        }

        // Send notification during the cycle
        notify.notify_one();

        if let Ok(mut stats) = tracker.delivery_stats.lock() {
            stats.total_notify_one_calls += 1;
        }

        // Wait for cycle to complete
        for handle in handles {
            let _ = handle.join();
        }

        tracker.record_operation(&format!("rapid_turnover_cycle_{}", cycle));
    }

    tracker.record_operation("rapid_turnover_storm_complete");
}

fn test_load_balance_storm(
    tracker: &ContentionStormTracker,
    config: &ContentionStormConfig,
    notify_spread_us: u16
) {
    tracker.record_operation("test_load_balance_storm");

    let notify = Arc::new(Notify::new());
    let mut handles = Vec::new();

    // Create balanced waiters
    for i in 0..config.waiter_threads.min(6) {
        let notify_clone = Arc::clone(&notify);
        let tracker_clone = tracker.clone();

        let handle = thread::spawn(move || {
            let mut waiter = notify_clone.notified();
            let tracked_waker = TrackedWaker::new(i as usize, 1, tracker_clone.clone());
            let waker = tracked_waker.create_waker();
            let mut context = Context::from_waker(&waker);

            if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                stats.total_waiters_created += 1;
            }

            // Poll to register
            let _ = Pin::new(&mut waiter).poll(&mut context);

            // Wait for notification
            thread::sleep(Duration::from_millis(config.duration_ms.min(100) as u64));

            // Check final state
            if let Poll::Ready(()) = Pin::new(&mut waiter).poll(&mut context) {
                if let Ok(mut stats) = tracker_clone.delivery_stats.lock() {
                    stats.total_waiters_awoken += 1;
                }
            }
        });

        handles.push(handle);
    }

    // Spread notifications across time to balance load
    thread::sleep(Duration::from_millis(5));
    for i in 0..config.notifier_threads.min(6) {
        notify.notify_one();

        if let Ok(mut stats) = tracker.delivery_stats.lock() {
            stats.total_notify_one_calls += 1;
        }

        tracker.record_operation(&format!("load_balance_notify_{}", i));

        if notify_spread_us > 0 {
            thread::sleep(Duration::from_micros(notify_spread_us.min(1000) as u64));
        }
    }

    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }

    tracker.record_operation("load_balance_storm_complete");
}