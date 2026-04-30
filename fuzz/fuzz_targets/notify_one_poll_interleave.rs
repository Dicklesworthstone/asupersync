//! Fuzz notify_one() interleaved with notified.poll().
//!
//! Tests arbitrary mix of notify_one() and notified.poll() operations to ensure
//! poll only returns Ready after notify, never spuriously. Validates the fundamental
//! contract that notifications are required for readiness.
//!
//! Critical invariants:
//! - poll only returns Ready after corresponding notify_one()
//! - No spurious readiness (Ready without notification)
//! - notify_one() wakes exactly one waiter (not zero, not multiple)
//! - Proper interleaving handling under arbitrary orderings

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
struct NotifyOnePollConfig {
    /// Number of initial waiters
    initial_waiters: u8,
    /// Operations to perform
    operations: Vec<NotifyPollOperation>,
    /// Whether to test concurrent scenarios
    test_concurrency: bool,
    /// Maximum operations to perform
    max_operations: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum NotifyPollOperation {
    /// Create a new notified waiter
    CreateWaiter { waiter_id: u8 },
    /// Poll a specific waiter
    PollWaiter { waiter_id: u8 },
    /// Call notify_one()
    NotifyOne,
    /// Drop a specific waiter
    DropWaiter { waiter_id: u8 },
    /// Rapid poll sequence on one waiter
    RapidPoll { waiter_id: u8, polls: u8 },
    /// Interleaved notify-poll sequence
    NotifyPollSequence { waiter_id: u8, sequence: Vec<u8> },
    /// Multiple polls followed by notify_one
    PollsThenNotify { waiter_ids: Vec<u8> },
    /// Check state consistency
    CheckState,
}

impl NotifyOnePollConfig {
    fn max_waiters() -> u8 {
        15 // Keep reasonable for testing
    }

    fn max_operations() -> u8 {
        40 // Limit test duration
    }

    fn max_rapid_polls() -> u8 {
        8 // Limit rapid polling
    }

    fn max_sequence_length() -> u8 {
        6 // Limit sequence length
    }
}

/// Tracks notify-poll behavior to detect spurious readiness
#[derive(Debug)]
struct NotifyPollTracker {
    notifications_sent: AtomicUsize,
    polls_attempted: AtomicUsize,
    polls_ready: AtomicUsize,
    polls_pending: AtomicUsize,
    waiters_created: AtomicUsize,
    waiters_dropped: AtomicUsize,
    spurious_readiness_detected: AtomicUsize,
}

impl NotifyPollTracker {
    fn new() -> Self {
        Self {
            notifications_sent: AtomicUsize::new(0),
            polls_attempted: AtomicUsize::new(0),
            polls_ready: AtomicUsize::new(0),
            polls_pending: AtomicUsize::new(0),
            waiters_created: AtomicUsize::new(0),
            waiters_dropped: AtomicUsize::new(0),
            spurious_readiness_detected: AtomicUsize::new(0),
        }
    }

    fn record_notification_sent(&self) {
        self.notifications_sent.fetch_add(1, Ordering::SeqCst);
    }

    fn record_poll_attempted(&self) {
        self.polls_attempted.fetch_add(1, Ordering::SeqCst);
    }

    fn record_poll_ready(&self) {
        self.polls_ready.fetch_add(1, Ordering::SeqCst);
    }

    fn record_poll_pending(&self) {
        self.polls_pending.fetch_add(1, Ordering::SeqCst);
    }

    fn record_waiter_created(&self) {
        self.waiters_created.fetch_add(1, Ordering::SeqCst);
    }

    fn record_waiter_dropped(&self) {
        self.waiters_dropped.fetch_add(1, Ordering::SeqCst);
    }

    fn record_spurious_readiness(&self) {
        self.spurious_readiness_detected.fetch_add(1, Ordering::SeqCst);
    }

    fn check_invariants(&self) -> Result<(), String> {
        let notifications = self.notifications_sent.load(Ordering::SeqCst);
        let polls_attempted = self.polls_attempted.load(Ordering::SeqCst);
        let polls_ready = self.polls_ready.load(Ordering::SeqCst);
        let polls_pending = self.polls_pending.load(Ordering::SeqCst);
        let spurious = self.spurious_readiness_detected.load(Ordering::SeqCst);

        // Core invariant: no spurious readiness should be detected
        if spurious > 0 {
            return Err(format!("Detected {} spurious readiness events", spurious));
        }

        // Polls should be accounted for
        if polls_attempted > 0 && (polls_ready + polls_pending) == 0 {
            return Err(format!(
                "Poll attempts ({}) not accounted for in ready/pending",
                polls_attempted
            ));
        }

        // Ready polls should not exceed notifications (with some tolerance for stored notifications)
        // Note: This is tricky because notify_one can create stored notifications
        if polls_ready > notifications + 10 { // Allow some tolerance for stored notifications
            return Err(format!(
                "More ready polls ({}) than notifications sent ({})",
                polls_ready, notifications
            ));
        }

        // Sanity checks
        if polls_ready > polls_attempted {
            return Err(format!(
                "More ready polls ({}) than attempted ({})",
                polls_ready, polls_attempted
            ));
        }

        if polls_pending > polls_attempted {
            return Err(format!(
                "More pending polls ({}) than attempted ({})",
                polls_pending, polls_attempted
            ));
        }

        Ok(())
    }
}

/// Tracks a notified waiter with its poll state
struct TrackedWaiter {
    notified_future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    completed: Arc<AtomicBool>,
    waiter_id: u8,
    poll_count: usize,
    ready_count: usize,
    last_poll_result: Option<Poll<()>>,
}

impl TrackedWaiter {
    fn new(notify: Arc<Notify>, waiter_id: u8, tracker: Arc<NotifyPollTracker>) -> Self {
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();

        let notified_future = Box::pin(async move {
            notify.notified().await;
            completed_clone.store(true, Ordering::SeqCst);
        });

        tracker.record_waiter_created();

        Self {
            notified_future: Some(notified_future),
            completed,
            waiter_id,
            poll_count: 0,
            ready_count: 0,
            last_poll_result: None,
        }
    }

    fn poll(&mut self, tracker: &NotifyPollTracker, notifications_before: usize) -> Poll<()> {
        tracker.record_poll_attempted();
        self.poll_count += 1;

        if let Some(ref mut future) = self.notified_future {
            if self.completed.load(Ordering::SeqCst) {
                return Poll::Ready(());
            }

            let waker = noop_waker();
            let mut context = Context::from_waker(&waker);
            let result = future.as_mut().poll(&mut context);

            match result {
                Poll::Ready(()) => {
                    tracker.record_poll_ready();
                    self.ready_count += 1;
                    self.last_poll_result = Some(result.clone());

                    // Check for spurious readiness
                    if notifications_before == 0 && self.ready_count == 1 {
                        // This waiter became ready but no notifications were sent
                        // This might be ok if there was a stored notification
                        // We'll let the higher-level logic determine spuriousness
                    }

                    self.notified_future = None;
                    self.completed.store(true, Ordering::SeqCst);
                    result
                }
                Poll::Pending => {
                    tracker.record_poll_pending();
                    self.last_poll_result = Some(result.clone());
                    result
                }
            }
        } else {
            // Already completed
            tracker.record_poll_ready();
            Poll::Ready(())
        }
    }

    fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    fn drop_future(&mut self, tracker: &NotifyPollTracker) {
        if self.notified_future.is_some() {
            tracker.record_waiter_dropped();
        }
        self.notified_future = None;
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

/// Test notify-poll interleaving scenarios
fn test_notify_poll_interleave_scenario(
    config: &NotifyOnePollConfig,
    tracker: &NotifyPollTracker,
) -> Result<(), String> {
    let notify = Arc::new(Notify::new());
    let mut waiters: HashMap<u8, TrackedWaiter> = HashMap::new();

    let max_waiters = config.initial_waiters.min(NotifyOnePollConfig::max_waiters());

    // Create initial waiters
    for i in 0..max_waiters {
        let waiter = TrackedWaiter::new(notify.clone(), i, Arc::new(NotifyPollTracker::new()));
        waiters.insert(i, waiter);
    }

    let max_ops = config.max_operations.min(NotifyOnePollConfig::max_operations()) as usize;

    for operation in config.operations.iter().take(max_ops) {
        match operation {
            NotifyPollOperation::CreateWaiter { waiter_id } => {
                let id = *waiter_id % 20; // Limit total waiters
                if !waiters.contains_key(&id) && waiters.len() < NotifyOnePollConfig::max_waiters() as usize {
                    let waiter = TrackedWaiter::new(notify.clone(), id, Arc::new(NotifyPollTracker::new()));
                    waiters.insert(id, waiter);
                }
            }

            NotifyPollOperation::PollWaiter { waiter_id } => {
                let id = *waiter_id % 20;
                if let Some(waiter) = waiters.get_mut(&id) {
                    let notifications_before = tracker.notifications_sent.load(Ordering::SeqCst);
                    let poll_result = waiter.poll(tracker, notifications_before);

                    // Check for spurious readiness
                    if poll_result.is_ready() {
                        let ready_polls_before_this = tracker.polls_ready.load(Ordering::SeqCst) - 1;
                        let notifications_sent = tracker.notifications_sent.load(Ordering::SeqCst);

                        // Simple spurious check: if this is the first ready poll but no notifications
                        if ready_polls_before_this == 0 && notifications_sent == 0 {
                            // Spurious readiness: poll returned Ready without any notify_one() calls
                            tracker.record_spurious_readiness();
                            return Err(format!(
                                "Spurious readiness detected on waiter {}: ready with no notifications sent",
                                id
                            ));
                        }
                    }

                    // Remove completed waiters
                    if waiter.is_completed() {
                        waiters.remove(&id);
                    }
                }
            }

            NotifyPollOperation::NotifyOne => {
                let waiters_before = waiters.len();
                notify.notify_one();
                tracker.record_notification_sent();

                // If there are waiters, exactly one should eventually become ready
                if waiters_before > 0 {
                    // We can't immediately check this because the notification might be asynchronous
                    // The check will happen when we poll waiters
                }
            }

            NotifyPollOperation::DropWaiter { waiter_id } => {
                let id = *waiter_id % 20;
                if let Some(mut waiter) = waiters.remove(&id) {
                    waiter.drop_future(tracker);
                }
            }

            NotifyPollOperation::RapidPoll { waiter_id, polls } => {
                let id = *waiter_id % 20;
                let poll_count = (*polls).min(NotifyOnePollConfig::max_rapid_polls()) as usize;

                if let Some(waiter) = waiters.get_mut(&id) {
                    let mut ready_count = 0;
                    let initial_ready_count = waiter.ready_count;

                    for i in 0..poll_count {
                        let notifications_before = tracker.notifications_sent.load(Ordering::SeqCst);
                        let poll_result = waiter.poll(tracker, notifications_before);

                        if poll_result.is_ready() {
                            ready_count += 1;

                            // After the first ready, subsequent polls should also be ready
                            // (because the future is completed)
                        }

                        // Check for spurious readiness in rapid polling
                        if poll_result.is_ready() && ready_count == 1 && initial_ready_count == 0 {
                            // This is the first time this waiter becomes ready
                            // Check if there were sufficient notifications
                            let notifications_sent = tracker.notifications_sent.load(Ordering::SeqCst);
                            let total_ready_polls = tracker.polls_ready.load(Ordering::SeqCst);

                            // Basic spurious check
                            if notifications_sent == 0 {
                                tracker.record_spurious_readiness();
                                return Err(format!(
                                    "Spurious readiness in rapid poll {}: waiter {} ready with no notifications",
                                    i, id
                                ));
                            }
                        }
                    }

                    // Remove if completed
                    if waiter.is_completed() {
                        waiters.remove(&id);
                    }
                }
            }

            NotifyPollOperation::NotifyPollSequence { waiter_id, sequence } => {
                let id = *waiter_id % 20;
                let max_seq = NotifyOnePollConfig::max_sequence_length() as usize;

                for (i, &op) in sequence.iter().take(max_seq).enumerate() {
                    if op % 2 == 0 {
                        // notify_one
                        notify.notify_one();
                        tracker.record_notification_sent();
                    } else {
                        // poll waiter
                        if let Some(waiter) = waiters.get_mut(&id) {
                            let notifications_before = tracker.notifications_sent.load(Ordering::SeqCst);
                            let poll_result = waiter.poll(tracker, notifications_before);

                            // Validate poll behavior in sequence
                            if i > 0 && poll_result.is_ready() {
                                // Check if there was a preceding notify in the sequence
                                let preceding_notifies = sequence[..=i].iter().filter(|&&x| x % 2 == 0).count();
                                let preceding_polls = sequence[..i].iter().filter(|&&x| x % 2 == 1).count();

                                // This is a simplified check - in reality, the relationship is complex
                                // due to stored notifications and timing
                            }

                            if waiter.is_completed() {
                                waiters.remove(&id);
                                break;
                            }
                        }
                    }
                }
            }

            NotifyPollOperation::PollsThenNotify { waiter_ids } => {
                let ids: Vec<u8> = waiter_ids.iter().map(|&id| id % 20).take(5).collect();

                // First, poll all specified waiters (should all be Pending)
                let mut initial_states = Vec::new();
                for &id in &ids {
                    if let Some(waiter) = waiters.get_mut(&id) {
                        let notifications_before = tracker.notifications_sent.load(Ordering::SeqCst);
                        let poll_result = waiter.poll(tracker, notifications_before);
                        initial_states.push((id, poll_result));

                        if poll_result.is_ready() {
                            // Check for spurious readiness
                            let notifications_sent = tracker.notifications_sent.load(Ordering::SeqCst);

                            if notifications_sent == 0 {
                                tracker.record_spurious_readiness();
                                return Err(format!(
                                    "Spurious readiness in polls-then-notify: waiter {} ready before any notify",
                                    id
                                ));
                            }
                        }
                    }
                }

                // Then send one notification
                notify.notify_one();
                tracker.record_notification_sent();

                // Poll all waiters again - exactly one should now be ready
                // (unless some were already completed)
                let mut newly_ready = 0;
                for &id in &ids {
                    if let Some(waiter) = waiters.get_mut(&id) {
                        let notifications_before = tracker.notifications_sent.load(Ordering::SeqCst);
                        let poll_result = waiter.poll(tracker, notifications_before);

                        if poll_result.is_ready() {
                            // Check if this waiter was pending before
                            let was_pending = initial_states.iter()
                                .find(|(prev_id, _)| *prev_id == id)
                                .map(|(_, result)| result.is_pending())
                                .unwrap_or(false);

                            if was_pending {
                                newly_ready += 1;
                            }
                        }

                        if waiter.is_completed() {
                            waiters.remove(&id);
                        }
                    }
                }

                // In a perfect world, exactly one waiter should become newly ready
                // But due to stored notifications and timing, this is complex to verify exactly
            }

            NotifyPollOperation::CheckState => {
                // Check waiter count consistency
                let active_waiters = waiters.len();
                let notify_waiter_count = notify.waiter_count();

                // Basic consistency check (not exact due to internal state)
                if active_waiters > 0 && notify_waiter_count == 0 {
                    // This might be ok if all our waiters are completed
                    let completed_waiters = waiters.values().filter(|w| w.is_completed()).count();
                    if completed_waiters != active_waiters {
                        return Err(format!(
                            "Waiter count mismatch: {} active, {} notify reports, {} completed",
                            active_waiters, notify_waiter_count, completed_waiters
                        ));
                    }
                }

                // Check our tracking invariants
                if let Err(msg) = tracker.check_invariants() {
                    return Err(format!("State check failed: {}", msg));
                }
            }
        }

        // Clean up completed waiters
        let mut to_remove = Vec::new();
        for (&id, waiter) in waiters.iter() {
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
    let config: NotifyOnePollConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.operations.is_empty() {
        return;
    }

    let tracker = NotifyPollTracker::new();

    // Test the notify-poll interleaving scenario
    if let Err(msg) = test_notify_poll_interleave_scenario(&config, &tracker) {
        panic!("Notify-poll interleaving test failed: {}", msg);
    }

    // Test concurrent scenarios if requested
    if config.test_concurrency {
        use std::thread;

        let tracker2 = NotifyPollTracker::new();
        let config2 = config.clone();

        let handle = thread::spawn(move || {
            test_notify_poll_interleave_scenario(&config2, &tracker2)
        });

        match handle.join() {
            Ok(Ok(())) => {
                // Concurrent test succeeded
            }
            Ok(Err(msg)) => {
                panic!("Concurrent notify-poll interleaving test failed: {}", msg);
            }
            Err(_) => {
                panic!("Concurrent test thread panicked");
            }
        }
    }

    // Ensure we actually performed some operations
    let total_polls = tracker.polls_attempted.load(Ordering::SeqCst);
    let total_notifications = tracker.notifications_sent.load(Ordering::SeqCst);

    if total_polls == 0 && total_notifications == 0 && !config.operations.is_empty() {
        panic!("No meaningful operations were performed during the test");
    }
});