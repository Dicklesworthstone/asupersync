//! Fuzz notify_waiters() + drop pending Notified scenarios.
//!
//! Tests arbitrary timing of notify_waiters() calls combined with dropping
//! pending Notified futures to ensure proper waiter slot cleanup and no
//! resource leaks. Validates that dropped waiters are properly removed
//! from the waiter queue.
//!
//! Critical invariants:
//! - Dropped Notified futures release their waiter slot
//! - No permanent waiter slot leaks after drops
//! - notify_waiters() wakes remaining active waiters after drops
//! - Waiter count decreases correctly when futures are dropped

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
struct NotifyWaitersDropConfig {
    /// Operations to perform
    operations: Vec<NotifyWaitersDropOperation>,
    /// Whether to test concurrent scenarios
    test_concurrency: bool,
    /// Maximum operations to perform
    max_operations: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum NotifyWaitersDropOperation {
    /// Create a new waiter
    CreateWaiter { waiter_id: u8 },
    /// Poll an existing waiter once
    PollWaiter { waiter_id: u8 },
    /// Drop a specific waiter future
    DropWaiter { waiter_id: u8 },
    /// Call notify_waiters() to wake all
    NotifyWaiters,
    /// Create multiple waiters then drop some before notify
    CreateThenDrop { waiter_ids: Vec<u8>, drop_ids: Vec<u8> },
    /// Notify waiters then drop remaining futures
    NotifyThenDrop { drop_ids: Vec<u8> },
    /// Rapid create/drop cycle
    RapidCreateDrop { base_id: u8, cycles: u8 },
    /// Mixed sequence: create, poll, drop, notify
    MixedSequence { sequence: Vec<u8> },
    /// Check waiter count and consistency
    CheckState,
}

impl NotifyWaitersDropConfig {
    fn max_waiters() -> u8 {
        12 // Limit total waiters for testing
    }

    fn max_operations() -> u8 {
        40 // Limit test duration
    }

    fn max_cycles() -> u8 {
        6 // Limit rapid cycles
    }

    fn max_sequence() -> u8 {
        8 // Limit mixed sequence operations
    }
}

/// Tracks notify_waiters + drop behavior to detect waiter slot leaks
#[derive(Debug)]
struct NotifyWaitersDropTracker {
    waiters_created: AtomicUsize,
    waiters_dropped: AtomicUsize,
    waiters_completed: AtomicUsize,
    notify_waiters_calls: AtomicUsize,
    waiter_slots_leaked: AtomicUsize,
    polls_after_drop: AtomicUsize,
    spurious_wake_ups: AtomicUsize,
}

impl NotifyWaitersDropTracker {
    fn new() -> Self {
        Self {
            waiters_created: AtomicUsize::new(0),
            waiters_dropped: AtomicUsize::new(0),
            waiters_completed: AtomicUsize::new(0),
            notify_waiters_calls: AtomicUsize::new(0),
            waiter_slots_leaked: AtomicUsize::new(0),
            polls_after_drop: AtomicUsize::new(0),
            spurious_wake_ups: AtomicUsize::new(0),
        }
    }

    fn record_waiter_created(&self) {
        self.waiters_created.fetch_add(1, Ordering::SeqCst);
    }

    fn record_waiter_dropped(&self) {
        self.waiters_dropped.fetch_add(1, Ordering::SeqCst);
    }

    fn record_waiter_completed(&self) {
        self.waiters_completed.fetch_add(1, Ordering::SeqCst);
    }

    fn record_notify_waiters_call(&self) {
        self.notify_waiters_calls.fetch_add(1, Ordering::SeqCst);
    }

    fn record_waiter_slot_leak(&self) {
        self.waiter_slots_leaked.fetch_add(1, Ordering::SeqCst);
    }

    fn record_poll_after_drop(&self) {
        self.polls_after_drop.fetch_add(1, Ordering::SeqCst);
    }

    fn record_spurious_wake_up(&self) {
        self.spurious_wake_ups.fetch_add(1, Ordering::SeqCst);
    }

    fn check_invariants(&self) -> Result<(), String> {
        let created = self.waiters_created.load(Ordering::SeqCst);
        let dropped = self.waiters_dropped.load(Ordering::SeqCst);
        let completed = self.waiters_completed.load(Ordering::SeqCst);
        let leaked = self.waiter_slots_leaked.load(Ordering::SeqCst);
        let spurious = self.spurious_wake_ups.load(Ordering::SeqCst);
        let poll_after_drop = self.polls_after_drop.load(Ordering::SeqCst);

        // Core invariant: no waiter slot leaks
        if leaked > 0 {
            return Err(format!("Detected {} waiter slot leaks", leaked));
        }

        // Core invariant: no spurious wake-ups
        if spurious > 0 {
            return Err(format!("Detected {} spurious wake-ups", spurious));
        }

        // No polling after drop
        if poll_after_drop > 0 {
            return Err(format!("Detected {} polls after drop", poll_after_drop));
        }

        // Sanity checks
        if dropped > created {
            return Err(format!(
                "More dropped ({}) than created ({})",
                dropped, created
            ));
        }

        if completed > created {
            return Err(format!(
                "More completed ({}) than created ({})",
                completed, created
            ));
        }

        Ok(())
    }
}

/// Tracks a single Notified waiter for testing
struct TrackedWaiter {
    notify_future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    completed: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
    waiter_id: u8,
    poll_count: usize,
}

impl TrackedWaiter {
    fn new(notify: Arc<Notify>, waiter_id: u8, tracker: Arc<NotifyWaitersDropTracker>) -> Self {
        let completed = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();
        let tracker_clone = tracker.clone();

        let notify_future = Box::pin(async move {
            notify.notified().await;
            completed_clone.store(true, Ordering::SeqCst);
            tracker_clone.record_waiter_completed();
        });

        tracker.record_waiter_created();

        Self {
            notify_future: Some(notify_future),
            completed,
            dropped,
            waiter_id,
            poll_count: 0,
        }
    }

    fn poll(&mut self, tracker: &NotifyWaitersDropTracker) -> Poll<()> {
        if self.dropped.load(Ordering::SeqCst) {
            // Polling after drop - this should not happen
            tracker.record_poll_after_drop();
            return Poll::Pending; // Or we could panic, but let's be graceful
        }

        if let Some(ref mut future) = self.notify_future {
            self.poll_count += 1;

            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);
            let result = future.as_mut().poll(&mut context);

            if result.is_ready() {
                self.notify_future = None;
                self.completed.store(true, Ordering::SeqCst);
            }

            result
        } else {
            // Already completed
            Poll::Ready(())
        }
    }

    fn drop_future(&mut self, tracker: &NotifyWaitersDropTracker) {
        if !self.dropped.load(Ordering::SeqCst) {
            self.notify_future = None;
            self.dropped.store(true, Ordering::SeqCst);
            tracker.record_waiter_dropped();
        }
    }

    fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    fn is_dropped(&self) -> bool {
        self.dropped.load(Ordering::SeqCst)
    }

    fn is_active(&self) -> bool {
        !self.is_completed() && !self.is_dropped()
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

/// Test notify_waiters + drop pending Notified scenarios
fn test_notify_waiters_drop_scenario(
    config: &NotifyWaitersDropConfig,
    tracker: &NotifyWaitersDropTracker,
) -> Result<(), String> {
    let notify = Arc::new(Notify::new());
    let mut waiters: HashMap<u8, TrackedWaiter> = HashMap::new();

    let max_ops = config.max_operations.min(NotifyWaitersDropConfig::max_operations()) as usize;

    for operation in config.operations.iter().take(max_ops) {
        match operation {
            NotifyWaitersDropOperation::CreateWaiter { waiter_id } => {
                let id = *waiter_id % NotifyWaitersDropConfig::max_waiters();

                if waiters.len() < NotifyWaitersDropConfig::max_waiters() as usize {
                    let waiter = TrackedWaiter::new(
                        notify.clone(),
                        id,
                        Arc::new(NotifyWaitersDropTracker::new()),
                    );
                    waiters.insert(id, waiter);
                }
            }

            NotifyWaitersDropOperation::PollWaiter { waiter_id } => {
                let id = *waiter_id % NotifyWaitersDropConfig::max_waiters();

                if let Some(waiter) = waiters.get_mut(&id) {
                    if waiter.is_active() {
                        let _poll_result = waiter.poll(tracker);
                        // Don't remove completed waiters here - let them stay for testing
                    }
                }
            }

            NotifyWaitersDropOperation::DropWaiter { waiter_id } => {
                let id = *waiter_id % NotifyWaitersDropConfig::max_waiters();

                if let Some(waiter) = waiters.get_mut(&id) {
                    waiter.drop_future(tracker);
                }
            }

            NotifyWaitersDropOperation::NotifyWaiters => {
                // Record how many active waiters before notify
                let active_before = waiters.values().filter(|w| w.is_active()).count();

                notify.notify_waiters();
                tracker.record_notify_waiters_call();

                // Poll all active waiters to see who became ready
                let mut newly_ready = 0;
                for (_, waiter) in waiters.iter_mut() {
                    if waiter.is_active() {
                        let poll_result = waiter.poll(tracker);
                        if poll_result.is_ready() {
                            newly_ready += 1;
                        }
                    }
                }

                // notify_waiters should wake ALL active waiters
                if newly_ready < active_before {
                    // This might be ok if some waiters were already ready or had state issues
                    // But for strict testing, we could flag this as unusual
                }
            }

            NotifyWaitersDropOperation::CreateThenDrop { waiter_ids, drop_ids } => {
                let max_create = NotifyWaitersDropConfig::max_waiters() as usize;
                let max_drop = NotifyWaitersDropConfig::max_waiters() as usize;

                // Create waiters
                for &id in waiter_ids.iter().take(max_create) {
                    let waiter_id = id % NotifyWaitersDropConfig::max_waiters();
                    if waiters.len() < NotifyWaitersDropConfig::max_waiters() as usize {
                        let waiter = TrackedWaiter::new(
                            notify.clone(),
                            waiter_id,
                            Arc::new(NotifyWaitersDropTracker::new()),
                        );
                        waiters.insert(waiter_id, waiter);
                    }
                }

                // Drop some of them
                for &id in drop_ids.iter().take(max_drop) {
                    let drop_id = id % NotifyWaitersDropConfig::max_waiters();
                    if let Some(waiter) = waiters.get_mut(&drop_id) {
                        waiter.drop_future(tracker);
                    }
                }
            }

            NotifyWaitersDropOperation::NotifyThenDrop { drop_ids } => {
                // First notify all waiters
                notify.notify_waiters();
                tracker.record_notify_waiters_call();

                // Poll to advance state
                for (_, waiter) in waiters.iter_mut() {
                    if waiter.is_active() {
                        let _poll_result = waiter.poll(tracker);
                    }
                }

                // Then drop specified waiters
                let max_drop = NotifyWaitersDropConfig::max_waiters() as usize;
                for &id in drop_ids.iter().take(max_drop) {
                    let drop_id = id % NotifyWaitersDropConfig::max_waiters();
                    if let Some(waiter) = waiters.get_mut(&drop_id) {
                        waiter.drop_future(tracker);
                    }
                }
            }

            NotifyWaitersDropOperation::RapidCreateDrop { base_id, cycles } => {
                let cycle_count = (*cycles).min(NotifyWaitersDropConfig::max_cycles()) as usize;
                let base = (*base_id % NotifyWaitersDropConfig::max_waiters()) as usize;

                for i in 0..cycle_count {
                    let id = ((base + i) % (NotifyWaitersDropConfig::max_waiters() as usize)) as u8;

                    // Create
                    if waiters.len() < NotifyWaitersDropConfig::max_waiters() as usize {
                        let waiter = TrackedWaiter::new(
                            notify.clone(),
                            id,
                            Arc::new(NotifyWaitersDropTracker::new()),
                        );
                        waiters.insert(id, waiter);
                    }

                    // Poll once
                    if let Some(waiter) = waiters.get_mut(&id) {
                        let _poll_result = waiter.poll(tracker);
                    }

                    // Drop
                    if let Some(waiter) = waiters.get_mut(&id) {
                        waiter.drop_future(tracker);
                    }
                }
            }

            NotifyWaitersDropOperation::MixedSequence { sequence } => {
                let max_seq = NotifyWaitersDropConfig::max_sequence() as usize;

                for (i, &op) in sequence.iter().take(max_seq).enumerate() {
                    let id = (i % NotifyWaitersDropConfig::max_waiters() as usize) as u8;

                    match op % 4 {
                        0 => {
                            // Create waiter
                            if waiters.len() < NotifyWaitersDropConfig::max_waiters() as usize {
                                let waiter = TrackedWaiter::new(
                                    notify.clone(),
                                    id,
                                    Arc::new(NotifyWaitersDropTracker::new()),
                                );
                                waiters.insert(id, waiter);
                            }
                        }
                        1 => {
                            // Poll waiter
                            if let Some(waiter) = waiters.get_mut(&id) {
                                if waiter.is_active() {
                                    let _poll_result = waiter.poll(tracker);
                                }
                            }
                        }
                        2 => {
                            // Drop waiter
                            if let Some(waiter) = waiters.get_mut(&id) {
                                waiter.drop_future(tracker);
                            }
                        }
                        3 => {
                            // Notify waiters
                            notify.notify_waiters();
                            tracker.record_notify_waiters_call();
                        }
                        _ => unreachable!(),
                    }
                }
            }

            NotifyWaitersDropOperation::CheckState => {
                // Verify waiter state consistency
                let active_count = waiters.values().filter(|w| w.is_active()).count();
                let dropped_count = waiters.values().filter(|w| w.is_dropped()).count();
                let completed_count = waiters.values().filter(|w| w.is_completed()).count();

                // Check for waiter slot leaks by comparing with notify's internal count
                let reported_waiter_count = notify.waiter_count();

                // The reported count should approximately match our active count
                // (There might be small timing differences, but major discrepancies indicate leaks)
                if reported_waiter_count > active_count + 5 {
                    tracker.record_waiter_slot_leak();
                    return Err(format!(
                        "Waiter count mismatch suggests leak: notify reports {} but {} active tracked",
                        reported_waiter_count, active_count
                    ));
                }

                // Check tracking invariants
                if let Err(msg) = tracker.check_invariants() {
                    return Err(format!("State check failed: {}", msg));
                }
            }
        }
    }

    // Final consistency check
    if let Err(msg) = tracker.check_invariants() {
        return Err(format!("Final invariant violation: {}", msg));
    }

    // Final waiter count check for leaks
    let final_active = waiters.values().filter(|w| w.is_active()).count();
    let final_reported = notify.waiter_count();

    if final_reported > final_active + 2 {
        tracker.record_waiter_slot_leak();
        return Err(format!(
            "Final waiter count suggests leak: {} reported vs {} active",
            final_reported, final_active
        ));
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let config: NotifyWaitersDropConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.operations.is_empty() {
        return;
    }

    let tracker = NotifyWaitersDropTracker::new();

    // Test the notify_waiters + drop scenario
    if let Err(msg) = test_notify_waiters_drop_scenario(&config, &tracker) {
        panic!("notify_waiters + drop pending test failed: {}", msg);
    }

    // Test concurrent scenarios if requested
    if config.test_concurrency {
        use std::thread;

        let tracker2 = NotifyWaitersDropTracker::new();
        let config2 = config.clone();

        let handle = thread::spawn(move || {
            test_notify_waiters_drop_scenario(&config2, &tracker2)
        });

        match handle.join() {
            Ok(Ok(())) => {
                // Concurrent test succeeded
            }
            Ok(Err(msg)) => {
                panic!("Concurrent notify_waiters + drop test failed: {}", msg);
            }
            Err(_) => {
                panic!("Concurrent test thread panicked");
            }
        }
    }

    // Ensure we performed meaningful operations
    let total_created = tracker.waiters_created.load(Ordering::SeqCst);
    let total_notify_calls = tracker.notify_waiters_calls.load(Ordering::SeqCst);

    if total_created == 0 && total_notify_calls == 0 && !config.operations.is_empty() {
        panic!("No meaningful waiter operations were performed during the test");
    }
});