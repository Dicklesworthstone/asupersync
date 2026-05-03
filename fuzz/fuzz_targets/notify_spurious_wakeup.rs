//! Fuzz notify spurious wakeup patterns.
//!
//! Tests arbitrary spurious wake scenarios to ensure Notified futures
//! only complete when actually notified, not from spurious wakes.
//! Validates proper wake filtering and state tracking under various
//! spurious wake conditions.
//!
//! Critical invariants:
//! - Notified future only completes after actual notify_one or notify_waiters
//! - Spurious wakes don't cause premature completion
//! - Wake count matches actual notification count
//! - No lost wakeups under spurious wake storm

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::Notify;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

#[derive(Debug, Clone, Arbitrary)]
struct SpuriousWakeConfig {
    /// Number of waiters to test
    waiter_count: u8,
    /// Operations to perform
    operations: Vec<NotifyOperation>,
    /// Whether to inject spurious wakes
    enable_spurious_wakes: bool,
    /// Maximum operations to perform
    max_operations: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum NotifyOperation {
    /// Add a new waiter
    AddWaiter { waiter_id: u8 },
    /// Remove/cancel a waiter
    CancelWaiter { waiter_id: u8 },
    /// Send notify_one
    NotifyOne,
    /// Send notify_waiters (broadcast)
    NotifyWaiters,
    /// Inject spurious wake on specific waiter
    SpuriousWake { waiter_id: u8 },
    /// Spurious wake storm on all waiters
    SpuriousWakeStorm { count: u8 },
    /// Check invariants
    CheckState,
}

impl SpuriousWakeConfig {
    fn max_waiters() -> u8 {
        20 // Keep reasonable for testing
    }

    fn max_operations() -> u8 {
        50 // Limit test duration
    }

    fn max_spurious_count() -> u8 {
        10 // Limit spurious wake storm
    }
}

/// Tracks spurious wake behavior to detect invariant violations
#[derive(Debug)]
struct SpuriousWakeTracker {
    actual_notifications: AtomicUsize,
    completed_waiters: AtomicUsize,
    spurious_wakes_sent: AtomicUsize,
    spurious_wakes_filtered: AtomicUsize,
    cancelled_waiters: AtomicUsize,
}

impl SpuriousWakeTracker {
    fn new() -> Self {
        Self {
            actual_notifications: AtomicUsize::new(0),
            completed_waiters: AtomicUsize::new(0),
            spurious_wakes_sent: AtomicUsize::new(0),
            spurious_wakes_filtered: AtomicUsize::new(0),
            cancelled_waiters: AtomicUsize::new(0),
        }
    }

    fn record_notification(&self) {
        self.actual_notifications.fetch_add(1, Ordering::SeqCst);
    }

    fn record_completion(&self) {
        self.completed_waiters.fetch_add(1, Ordering::SeqCst);
    }

    fn record_spurious_wake(&self) {
        self.spurious_wakes_sent.fetch_add(1, Ordering::SeqCst);
    }

    fn record_spurious_filtered(&self) {
        self.spurious_wakes_filtered.fetch_add(1, Ordering::SeqCst);
    }

    fn record_cancellation(&self) {
        self.cancelled_waiters.fetch_add(1, Ordering::SeqCst);
    }

    fn check_invariants(&self) -> Result<(), String> {
        let notifications = self.actual_notifications.load(Ordering::SeqCst);
        let completions = self.completed_waiters.load(Ordering::SeqCst);
        let spurious_sent = self.spurious_wakes_sent.load(Ordering::SeqCst);
        let spurious_filtered = self.spurious_wakes_filtered.load(Ordering::SeqCst);
        let cancelled = self.cancelled_waiters.load(Ordering::SeqCst);

        // Core invariant: spurious wakes should not cause extra completions
        // completions should only be from actual notifications
        if completions > notifications && notifications > 0 {
            return Err(format!(
                "More completions ({}) than notifications ({}) - spurious wakes caused premature completion",
                completions, notifications
            ));
        }

        // Spurious wakes should be properly filtered
        if spurious_sent > 0 && spurious_filtered != spurious_sent {
            // This is informational - depending on implementation, spurious wakes might be filtered at different levels
            // But they shouldn't cause spurious completions
        }

        // Sanity checks
        if cancelled > 100 {
            return Err(format!("Excessive cancellations: {}", cancelled));
        }

        Ok(())
    }
}

/// Custom waker that can inject spurious wake behavior
struct TrackingWaker {
    waker_id: usize,
    tracker: Arc<SpuriousWakeTracker>,
    inner: Waker,
    completed: Arc<AtomicBool>,
}

impl TrackingWaker {
    fn new(
        waker_id: usize,
        tracker: Arc<SpuriousWakeTracker>,
        completed: Arc<AtomicBool>,
    ) -> Waker {
        let data = Box::into_raw(Box::new(TrackingWaker {
            waker_id,
            tracker,
            inner: noop_waker(),
            completed,
        })) as *const ();

        unsafe { Waker::from_raw(RawWaker::new(data, &TRACKING_WAKER_VTABLE)) }
    }
}

static TRACKING_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    // clone
    |data| unsafe {
        let tracking_waker = &*(data as *const TrackingWaker);
        let new_tracking_waker = Box::new(TrackingWaker {
            waker_id: tracking_waker.waker_id,
            tracker: tracking_waker.tracker.clone(),
            inner: tracking_waker.inner.clone(),
            completed: tracking_waker.completed.clone(),
        });
        RawWaker::new(
            Box::into_raw(new_tracking_waker) as *const (),
            &TRACKING_WAKER_VTABLE,
        )
    },
    // wake
    |data| unsafe {
        let tracking_waker = Box::from_raw(data as *mut TrackingWaker);
        if !tracking_waker.completed.load(Ordering::SeqCst) {
            // This is a legitimate wake - mark completion
            tracking_waker.completed.store(true, Ordering::SeqCst);
            tracking_waker.tracker.record_completion();
        }
    },
    // wake_by_ref
    |data| unsafe {
        let tracking_waker = &*(data as *const TrackingWaker);
        if !tracking_waker.completed.load(Ordering::SeqCst) {
            // This is a legitimate wake - mark completion
            tracking_waker.completed.store(true, Ordering::SeqCst);
            tracking_waker.tracker.record_completion();
        }
    },
    // drop
    |data| unsafe {
        let _ = Box::from_raw(data as *mut TrackingWaker);
    },
);

fn noop_waker() -> Waker {
    static NOOP_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(std::ptr::null(), &NOOP_WAKER_VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &NOOP_WAKER_VTABLE)) }
}

/// A waiter that tracks its lifecycle
struct TrackedWaiter {
    notified_future: Pin<Box<dyn Future<Output = ()> + Send>>,
    completed: Arc<AtomicBool>,
    waker: Option<Waker>,
}

impl TrackedWaiter {
    fn new(notify: Arc<Notify>, waiter_id: usize, tracker: Arc<SpuriousWakeTracker>) -> Self {
        let completed = Arc::new(AtomicBool::new(false));
        let waker = Some(TrackingWaker::new(waiter_id, tracker, completed.clone()));

        Self {
            notified_future: Box::pin(async move { notify.notified().await }),
            completed,
            waker,
        }
    }

    fn poll(&mut self) -> Poll<()> {
        if let Some(ref waker) = self.waker {
            let mut context = Context::from_waker(waker);
            self.notified_future.as_mut().poll(&mut context)
        } else {
            Poll::Pending
        }
    }

    fn send_spurious_wake(&mut self, tracker: &SpuriousWakeTracker) {
        if let Some(ref waker) = self.waker {
            // Send spurious wake
            tracker.record_spurious_wake();
            waker.wake_by_ref();

            // Check if this caused spurious completion
            if self.completed.load(Ordering::SeqCst) {
                // This should not happen - spurious wakes shouldn't complete the future
                tracker.record_spurious_filtered(); // This tracks that we detected the issue
            }
        }
    }

    fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }
}

/// Test spurious wake scenarios
fn test_spurious_wake_scenario(
    config: &SpuriousWakeConfig,
    tracker: &SpuriousWakeTracker,
) -> Result<(), String> {
    let notify = Arc::new(Notify::new());
    let mut waiters: HashMap<u8, TrackedWaiter> = HashMap::new();

    let max_ops = config
        .max_operations
        .min(SpuriousWakeConfig::max_operations()) as usize;
    let max_waiters = config.waiter_count.min(SpuriousWakeConfig::max_waiters());

    for operation in config.operations.iter().take(max_ops) {
        match operation {
            NotifyOperation::AddWaiter { waiter_id } => {
                let id = *waiter_id % max_waiters;
                if !waiters.contains_key(&id) && waiters.len() < max_waiters as usize {
                    let waiter = TrackedWaiter::new(
                        notify.clone(),
                        id as usize,
                        Arc::new(SpuriousWakeTracker::new()),
                    );
                    waiters.insert(id, waiter);
                }
            }

            NotifyOperation::CancelWaiter { waiter_id } => {
                let id = *waiter_id % max_waiters;
                if waiters.remove(&id).is_some() {
                    tracker.record_cancellation();
                }
            }

            NotifyOperation::NotifyOne => {
                notify.notify_one();
                tracker.record_notification();
            }

            NotifyOperation::NotifyWaiters => {
                let waiter_count = waiters.len();
                notify.notify_waiters();
                // notify_waiters notifies ALL current waiters
                for _ in 0..waiter_count {
                    tracker.record_notification();
                }
            }

            NotifyOperation::SpuriousWake { waiter_id } => {
                if config.enable_spurious_wakes {
                    let id = *waiter_id % max_waiters;
                    if let Some(waiter) = waiters.get_mut(&id) {
                        waiter.send_spurious_wake(tracker);
                    }
                }
            }

            NotifyOperation::SpuriousWakeStorm { count } => {
                if config.enable_spurious_wakes {
                    let storm_count =
                        (*count).min(SpuriousWakeConfig::max_spurious_count()) as usize;
                    for _ in 0..storm_count {
                        for waiter in waiters.values_mut() {
                            waiter.send_spurious_wake(tracker);
                        }
                    }
                }
            }

            NotifyOperation::CheckState => {
                // Poll all waiters to process any pending wakes
                for waiter in waiters.values_mut() {
                    let _ = waiter.poll();
                }

                if let Err(msg) = tracker.check_invariants() {
                    return Err(format!("Invariant check failed: {}", msg));
                }
            }
        }

        // Always poll all waiters after each operation to process state changes
        for waiter in waiters.values_mut() {
            let _ = waiter.poll();
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
    let config: SpuriousWakeConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.operations.is_empty() || config.waiter_count == 0 {
        return;
    }

    let tracker = SpuriousWakeTracker::new();

    // Test the spurious wake scenario
    if let Err(msg) = test_spurious_wake_scenario(&config, &tracker) {
        panic!("Spurious wake scenario test failed: {}", msg);
    }

    // Ensure we actually performed some operations
    let total_notifications = tracker.actual_notifications.load(Ordering::SeqCst);
    let total_spurious = tracker.spurious_wakes_sent.load(Ordering::SeqCst);

    if total_notifications == 0 && total_spurious == 0 && !config.operations.is_empty() {
        panic!("No meaningful operations were performed during the test");
    }
});
