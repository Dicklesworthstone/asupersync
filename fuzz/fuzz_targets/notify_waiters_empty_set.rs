//! Fuzz notify_waiters() under empty waiter sets.
//!
//! Tests arbitrary call patterns of notify_waiters() when no waiters are
//! present to ensure it's a no-op (not an error). Validates that empty-set
//! notification doesn't create stored tokens or cause other side effects.
//!
//! Critical invariants:
//! - notify_waiters() with zero waiters is always a no-op
//! - No stored notifications created from empty-set broadcasts
//! - Empty-set broadcasts do not make later waiters immediately ready
//! - Subsequent waiters behave correctly after empty broadcasts

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
    stored_tokens_created: AtomicUsize,
    waiters_created: AtomicUsize,
    waiters_completed: AtomicUsize,
    invariant_violations: AtomicUsize,
}

impl EmptyNotifyTracker {
    fn new() -> Self {
        Self {
            empty_notify_waiters_calls: AtomicUsize::new(0),
            empty_notify_one_calls: AtomicUsize::new(0),
            stored_tokens_created: AtomicUsize::new(0),
            waiters_created: AtomicUsize::new(0),
            waiters_completed: AtomicUsize::new(0),
            invariant_violations: AtomicUsize::new(0),
        }
    }

    fn record_empty_notify_waiters(&self) {
        self.empty_notify_waiters_calls
            .fetch_add(1, Ordering::SeqCst);
    }

    fn record_empty_notify_one(&self) {
        self.empty_notify_one_calls.fetch_add(1, Ordering::SeqCst);
    }

    fn record_stored_token_created(&self) {
        self.stored_tokens_created.fetch_add(1, Ordering::SeqCst);
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
        let violations = self.invariant_violations.load(Ordering::SeqCst);

        // Core invariant: no invariant violations should be detected
        if violations > 0 {
            return Err(format!("Detected {} invariant violations", violations));
        }

        // Sanity checks
        if empty_waiters_calls > 1000 {
            return Err(format!(
                "Excessive notify_waiters calls: {}",
                empty_waiters_calls
            ));
        }

        if empty_one_calls > 1000 {
            return Err(format!("Excessive notify_one calls: {}", empty_one_calls));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaiterPollObservation {
    Pending,
    Ready,
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
        let completion_tracker = tracker.clone();

        let notify_future = Box::pin(async move {
            notify.notified().await;
            completed_clone.store(true, Ordering::SeqCst);
            completion_tracker.record_waiter_completed();
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

fn observe_waiter_poll(waiter: &mut TrackedWaiter) -> WaiterPollObservation {
    let observation = match waiter.poll() {
        Poll::Pending => WaiterPollObservation::Pending,
        Poll::Ready(()) => WaiterPollObservation::Ready,
    };

    match observation {
        WaiterPollObservation::Pending => {
            assert!(
                waiter.notify_future.is_some(),
                "waiter {} reported pending after its future was removed",
                waiter.waiter_id
            );
        }
        WaiterPollObservation::Ready => {
            assert!(
                waiter.is_completed() || waiter.notify_future.is_none(),
                "waiter {} reported ready without completion or future removal",
                waiter.waiter_id
            );
        }
    }

    observation
}

fn probe_stored_notification(
    notify: &Arc<Notify>,
    tracker: &Arc<EmptyNotifyTracker>,
    waiter_id: u8,
) -> WaiterPollObservation {
    let mut probe = TrackedWaiter::new(notify.clone(), waiter_id, tracker.clone());
    let observation = observe_waiter_poll(&mut probe);
    probe.drop_future();
    observation
}

fn assert_empty_notify_waiters_did_not_store(
    notify: &Arc<Notify>,
    tracker: &Arc<EmptyNotifyTracker>,
    expected_stored_tokens: &mut usize,
    context: &str,
) -> Result<(), String> {
    const PROBE_WAITER_ID: u8 = 250;
    let expected_before_probe = *expected_stored_tokens;

    for token_index in 0..expected_before_probe {
        if probe_stored_notification(notify, tracker, PROBE_WAITER_ID)
            != WaiterPollObservation::Ready
        {
            return Err(format!(
                "{} lost expected stored notification {} of {}",
                context,
                token_index + 1,
                expected_before_probe
            ));
        }
    }

    *expected_stored_tokens = 0;

    if probe_stored_notification(notify, tracker, PROBE_WAITER_ID) == WaiterPollObservation::Ready {
        tracker.record_invariant_violation();
        return Err(format!(
            "{} created a stored notification from notify_waiters() with no waiters",
            context
        ));
    }

    let waiter_count = notify.waiter_count();
    if waiter_count != 0 {
        return Err(format!(
            "{} probe waiter leaked, {} waiters remain",
            context, waiter_count
        ));
    }

    Ok(())
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
    tracker: Arc<EmptyNotifyTracker>,
) -> Result<(), String> {
    let notify = Arc::new(Notify::new());
    let mut waiters: HashMap<u8, TrackedWaiter> = HashMap::new();
    let mut expected_stored_tokens = 0usize;

    let max_ops = config
        .max_operations
        .min(NotifyWaitersEmptyConfig::max_operations()) as usize;

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

                // Call notify_waiters with empty set
                notify.notify_waiters();
                tracker.record_empty_notify_waiters();

                assert_empty_notify_waiters_did_not_store(
                    &notify,
                    &tracker,
                    &mut expected_stored_tokens,
                    "notify_waiters() with empty waiter set",
                )?;
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

                // Call notify_one with empty set
                let notified_waiter = notify.notify_one();
                tracker.record_empty_notify_one();

                // notify_one SHOULD create stored notification even with no waiters
                if notified_waiter {
                    tracker.record_invariant_violation();
                    return Err(
                        "notify_one() reported a waiter notification with empty waiter set"
                            .to_string(),
                    );
                }
                expected_stored_tokens = expected_stored_tokens.saturating_add(1);
                tracker.record_stored_token_created();
            }

            EmptyNotifyOperation::TemporaryWaiter { waiter_id } => {
                let id = *waiter_id % 10;

                // Create a waiter briefly then drop it immediately
                let waiter = TrackedWaiter::new(notify.clone(), id, tracker.clone());

                // Poll once to register it
                let mut temp_waiter = waiter;
                if observe_waiter_poll(&mut temp_waiter) == WaiterPollObservation::Ready {
                    expected_stored_tokens = expected_stored_tokens.saturating_sub(1);
                }

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
                let repeat_count =
                    (*count).min(NotifyWaitersEmptyConfig::max_repeated_notifications()) as usize;

                for i in 0..repeat_count {
                    // Verify no waiters each time
                    let waiter_count = notify.waiter_count();
                    if waiter_count > 0 {
                        return Err(format!(
                            "Repeated notify_waiters[{}] called with {} waiters, expected 0",
                            i, waiter_count
                        ));
                    }

                    notify.notify_waiters();
                    tracker.record_empty_notify_waiters();

                    let context = format!("Repeated notify_waiters[{}]", i);
                    assert_empty_notify_waiters_did_not_store(
                        &notify,
                        &tracker,
                        &mut expected_stored_tokens,
                        &context,
                    )?;
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

                    if op % 2 == 0 {
                        notify.notify_waiters();
                        tracker.record_empty_notify_waiters();

                        let context = format!("Mixed notify_waiters[{}]", i);
                        assert_empty_notify_waiters_did_not_store(
                            &notify,
                            &tracker,
                            &mut expected_stored_tokens,
                            &context,
                        )?;
                    } else {
                        let notified_waiter = notify.notify_one();
                        tracker.record_empty_notify_one();

                        // notify_one should create stored notifications
                        if notified_waiter {
                            tracker.record_invariant_violation();
                            return Err(format!(
                                "Mixed notify_one[{}] reported a waiter notification with empty waiter set",
                                i
                            ));
                        }
                        expected_stored_tokens = expected_stored_tokens.saturating_add(1);
                        tracker.record_stored_token_created();
                    }
                }
            }

            EmptyNotifyOperation::PostEmptyWaiter { waiter_id } => {
                let id = *waiter_id % 10;

                // Create waiter after empty notifications
                waiters
                    .entry(id)
                    .or_insert_with(|| TrackedWaiter::new(notify.clone(), id, tracker.clone()));

                // Poll the waiter to see its initial state
                if let Some(waiter) = waiters.get_mut(&id) {
                    // Check if it's immediately ready (consumed stored notification)
                    if observe_waiter_poll(waiter) == WaiterPollObservation::Ready {
                        expected_stored_tokens = expected_stored_tokens.saturating_sub(1);
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
            if observe_waiter_poll(waiter) == WaiterPollObservation::Ready {
                expected_stored_tokens = expected_stored_tokens.saturating_sub(1);
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

    let tracker = Arc::new(EmptyNotifyTracker::new());

    // Test the empty notify_waiters scenario
    if let Err(msg) = test_empty_notify_waiters_scenario(&config, tracker.clone()) {
        panic!("Empty notify_waiters scenario test failed: {}", msg);
    }

    // Test concurrent scenarios if requested
    if config.test_concurrency {
        use std::thread;

        let tracker2 = Arc::new(EmptyNotifyTracker::new());
        let config2 = config.clone();

        let handle = thread::spawn(move || test_empty_notify_waiters_scenario(&config2, tracker2));

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
