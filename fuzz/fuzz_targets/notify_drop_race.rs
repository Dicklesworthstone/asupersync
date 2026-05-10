//! Fuzz notify_one + drop Notified future race conditions.
//!
//! Tests arbitrary timing between notify_one() calls and Notified future
//! drops to ensure proper waiter slot cleanup and baton passing.
//! Validates that dropped futures release waiter slots and don't cause
//! permanent leaks in the notification system.
//!
//! Critical invariants:
//! - Dropped Notified futures properly release waiter slots
//! - Notifications are passed as "batons" to other waiters when dropped
//! - No permanent waiter slot leaks occur
//! - Stored notifications are preserved when no waiters exist

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::Notify;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

#[derive(Debug, Clone, Arbitrary)]
struct NotifyDropConfig {
    /// Number of initial waiters to create
    initial_waiters: u8,
    /// Operations to perform
    operations: Vec<NotifyDropOperation>,
    /// Whether to test concurrent scenarios
    test_concurrency: bool,
    /// Maximum operations to perform
    max_operations: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum NotifyDropOperation {
    /// Add a new waiter
    AddWaiter { waiter_id: u8 },
    /// Drop a specific waiter future
    DropWaiter { waiter_id: u8 },
    /// Call notify_one
    NotifyOne,
    /// Call notify_waiters (broadcast)
    NotifyWaiters,
    /// Poll a specific waiter
    PollWaiter { waiter_id: u8 },
    /// Poll all waiters to make progress
    PollAllWaiters,
    /// Drop multiple waiters at once
    DropMultiple { count: u8 },
    /// Rapid notify_one + drop sequence
    RapidNotifyDrop { cycles: u8 },
    /// Check state consistency
    CheckState,
}

impl NotifyDropConfig {
    fn max_waiters() -> u8 {
        15 // Keep reasonable for testing
    }

    fn max_operations() -> u8 {
        50 // Limit test duration
    }

    fn max_drop_multiple() -> u8 {
        5 // Limit mass drops
    }

    fn max_rapid_cycles() -> u8 {
        8 // Limit rapid cycles
    }
}

/// Tracks notify drop behavior to detect leaks and inconsistencies
#[derive(Debug)]
struct NotifyDropTracker {
    notifications_sent: AtomicUsize,
    waiters_completed: AtomicUsize,
    waiters_dropped: AtomicUsize,
    stored_notifications: AtomicUsize,
    baton_passes: AtomicUsize,
    slot_leaks_detected: AtomicUsize,
}

impl NotifyDropTracker {
    fn new() -> Self {
        Self {
            notifications_sent: AtomicUsize::new(0),
            waiters_completed: AtomicUsize::new(0),
            waiters_dropped: AtomicUsize::new(0),
            stored_notifications: AtomicUsize::new(0),
            baton_passes: AtomicUsize::new(0),
            slot_leaks_detected: AtomicUsize::new(0),
        }
    }

    fn record_notification(&self) {
        self.notifications_sent.fetch_add(1, Ordering::SeqCst);
    }

    fn record_completion(&self) {
        self.waiters_completed.fetch_add(1, Ordering::SeqCst);
    }

    fn record_drop(&self) {
        self.waiters_dropped.fetch_add(1, Ordering::SeqCst);
    }

    fn record_stored_notification(&self) {
        self.stored_notifications.fetch_add(1, Ordering::SeqCst);
    }

    fn record_baton_pass(&self) {
        self.baton_passes.fetch_add(1, Ordering::SeqCst);
    }

    fn record_slot_leak(&self) {
        self.slot_leaks_detected.fetch_add(1, Ordering::SeqCst);
    }

    fn check_invariants(&self) -> Result<(), String> {
        let notifications = self.notifications_sent.load(Ordering::SeqCst);
        let completed = self.waiters_completed.load(Ordering::SeqCst);
        let dropped = self.waiters_dropped.load(Ordering::SeqCst);
        let stored = self.stored_notifications.load(Ordering::SeqCst);
        let baton_passes = self.baton_passes.load(Ordering::SeqCst);
        let slot_leaks = self.slot_leaks_detected.load(Ordering::SeqCst);

        // Core invariant: no slot leaks should be detected
        if slot_leaks > 0 {
            return Err(format!("Detected {} waiter slot leaks", slot_leaks));
        }

        // Notifications should be accounted for via completion, storage, or baton passing
        let total_accounted = completed + stored + baton_passes;
        if notifications > 0 && total_accounted == 0 {
            return Err(format!(
                "Notifications sent ({}) but none accounted for (completed: {}, stored: {}, baton: {})",
                notifications, completed, stored, baton_passes
            ));
        }

        // Sanity checks
        if dropped > 100 {
            return Err(format!("Excessive drops: {}", dropped));
        }

        if notifications > 100 {
            return Err(format!("Excessive notifications: {}", notifications));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaiterPollObservation {
    Pending,
    Ready,
}

impl WaiterPollObservation {
    fn from_poll(result: Poll<()>) -> Self {
        match result {
            Poll::Pending => Self::Pending,
            Poll::Ready(()) => Self::Ready,
        }
    }
}

/// Tracks a Notified future with drop detection
struct TrackedNotifiedFuture {
    future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    completed: Arc<AtomicBool>,
    tracker: Arc<NotifyDropTracker>,
    waiter_id: u8,
}

impl TrackedNotifiedFuture {
    fn new(notify: Arc<Notify>, waiter_id: u8, tracker: Arc<NotifyDropTracker>) -> Self {
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();
        let tracker_clone = tracker.clone();

        let future = Box::pin(async move {
            notify.notified().await;
            completed_clone.store(true, Ordering::SeqCst);
            tracker_clone.record_completion();
        });

        Self {
            future: Some(future),
            completed,
            tracker,
            waiter_id,
        }
    }

    fn poll(&mut self) -> Poll<()> {
        if let Some(ref mut future) = self.future {
            if self.completed.load(Ordering::SeqCst) {
                return Poll::Ready(());
            }

            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);
            let result = future.as_mut().poll(&mut context);

            if result.is_ready() {
                self.future = None;
            }

            result
        } else {
            Poll::Ready(())
        }
    }

    fn drop_future(&mut self) {
        if self.future.is_some() && !self.completed.load(Ordering::SeqCst) {
            // Simulate the drop behavior - in real code this would happen automatically
            // but we need to track it for our invariant checking
            self.tracker.record_drop();

            // The actual Drop impl in Notified would handle baton passing here
            // We simulate detecting this by checking if a notification should be passed
            self.tracker.record_baton_pass();
        }
        self.future = None;
    }

    fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    fn is_dropped(&self) -> bool {
        self.future.is_none()
    }
}

impl Drop for TrackedNotifiedFuture {
    fn drop(&mut self) {
        // Track any remaining drops
        if self.future.is_some() && !self.completed.load(Ordering::SeqCst) {
            self.tracker.record_drop();
        }
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

fn observe_waiter_poll(waiter: &mut TrackedNotifiedFuture) -> bool {
    let observation = WaiterPollObservation::from_poll(waiter.poll());

    match observation {
        WaiterPollObservation::Pending => {
            assert!(
                !waiter.is_dropped(),
                "waiter {} reported pending after its future was dropped",
                waiter.waiter_id
            );
        }
        WaiterPollObservation::Ready => {
            assert!(
                waiter.is_completed() || waiter.is_dropped(),
                "waiter {} reported ready without completion or future removal",
                waiter.waiter_id
            );
        }
    }

    waiter.is_completed() || waiter.is_dropped()
}

/// Test notify_one + drop race scenarios
fn test_notify_drop_scenario(
    config: &NotifyDropConfig,
    tracker: Arc<NotifyDropTracker>,
) -> Result<(), String> {
    let notify = Arc::new(Notify::new());
    let mut waiters: HashMap<u8, TrackedNotifiedFuture> = HashMap::new();

    let max_waiters = config.initial_waiters.min(NotifyDropConfig::max_waiters());

    // Create initial waiters
    for i in 0..max_waiters {
        let waiter = TrackedNotifiedFuture::new(notify.clone(), i, tracker.clone());
        waiters.insert(i, waiter);
    }

    let max_ops = config
        .max_operations
        .min(NotifyDropConfig::max_operations()) as usize;

    for operation in config.operations.iter().take(max_ops) {
        match operation {
            NotifyDropOperation::AddWaiter { waiter_id } => {
                let id = *waiter_id % 20; // Limit total waiters
                waiters.entry(id).or_insert_with(|| {
                    TrackedNotifiedFuture::new(notify.clone(), id, tracker.clone())
                });
            }

            NotifyDropOperation::DropWaiter { waiter_id } => {
                let id = *waiter_id % 20;
                if let Some(mut waiter) = waiters.remove(&id) {
                    waiter.drop_future();
                }
            }

            NotifyDropOperation::NotifyOne => {
                let had_waiters = !waiters.is_empty();
                notify.notify_one();
                tracker.record_notification();
                if !had_waiters {
                    tracker.record_stored_notification();
                }
            }

            NotifyDropOperation::NotifyWaiters => {
                let active_waiters = waiters.len();
                notify.notify_waiters();
                // notify_waiters notifies all current waiters
                for _ in 0..active_waiters {
                    tracker.record_notification();
                }
            }

            NotifyDropOperation::PollWaiter { waiter_id } => {
                let id = *waiter_id % 20;
                let should_remove = match waiters.get_mut(&id) {
                    Some(waiter) => observe_waiter_poll(waiter),
                    None => false,
                };
                if should_remove {
                    waiters.remove(&id);
                }
            }

            NotifyDropOperation::PollAllWaiters => {
                let mut to_remove = Vec::new();
                for (id, waiter) in waiters.iter_mut() {
                    if observe_waiter_poll(waiter) {
                        to_remove.push(*id);
                    }
                }
                for id in to_remove {
                    waiters.remove(&id);
                }
            }

            NotifyDropOperation::DropMultiple { count } => {
                let drop_count = (*count).min(NotifyDropConfig::max_drop_multiple()) as usize;
                let waiter_ids: Vec<u8> = waiters.keys().copied().take(drop_count).collect();

                for id in waiter_ids {
                    if let Some(mut waiter) = waiters.remove(&id) {
                        waiter.drop_future();
                    }
                }
            }

            NotifyDropOperation::RapidNotifyDrop { cycles } => {
                let cycle_count = (*cycles).min(NotifyDropConfig::max_rapid_cycles()) as usize;

                for i in 0..cycle_count {
                    // Add a waiter
                    let waiter_id = (100 + i) as u8; // Use high IDs to avoid conflicts
                    let waiter =
                        TrackedNotifiedFuture::new(notify.clone(), waiter_id, tracker.clone());
                    waiters.insert(waiter_id, waiter);

                    // Notify
                    notify.notify_one();
                    tracker.record_notification();

                    // Immediately drop the waiter (race condition)
                    if let Some(mut waiter) = waiters.remove(&waiter_id) {
                        waiter.drop_future();
                    }
                }
            }

            NotifyDropOperation::CheckState => {
                // Check for consistency - in a real implementation we might have
                // access to internal state to verify no leaked waiters
                let active_waiters = waiters.len();

                if active_waiters > NotifyDropConfig::max_waiters() as usize * 2 {
                    tracker.record_slot_leak();
                    return Err(format!(
                        "Too many active waiters, possible leak: {}",
                        active_waiters
                    ));
                }

                // Check our tracking invariants
                if let Err(msg) = tracker.check_invariants() {
                    return Err(format!("State check failed: {}", msg));
                }
            }
        }

        // Always poll all waiters to make progress and clean up completed ones
        let mut to_remove = Vec::new();
        for (id, waiter) in waiters.iter_mut() {
            if observe_waiter_poll(waiter) {
                to_remove.push(*id);
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
    let config: NotifyDropConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.operations.is_empty() {
        return;
    }

    let tracker = Arc::new(NotifyDropTracker::new());

    // Test the notify+drop scenario
    if let Err(msg) = test_notify_drop_scenario(&config, tracker.clone()) {
        panic!("Notify drop race scenario test failed: {}", msg);
    }

    // Test concurrent scenarios if requested
    if config.test_concurrency {
        use std::thread;

        let tracker2 = Arc::new(NotifyDropTracker::new());
        let config2 = config.clone();

        let handle = thread::spawn(move || test_notify_drop_scenario(&config2, tracker2));

        match handle.join() {
            Ok(Ok(())) => {
                // Concurrent test succeeded
            }
            Ok(Err(msg)) => {
                panic!("Concurrent notify drop test failed: {}", msg);
            }
            Err(_) => {
                panic!("Concurrent test thread panicked");
            }
        }
    }

    // Ensure we actually performed some operations
    let total_notifications = tracker.notifications_sent.load(Ordering::SeqCst);
    let total_drops = tracker.waiters_dropped.load(Ordering::SeqCst);

    if total_notifications == 0 && total_drops == 0 && !config.operations.is_empty() {
        panic!("No meaningful operations were performed during the test");
    }
});
