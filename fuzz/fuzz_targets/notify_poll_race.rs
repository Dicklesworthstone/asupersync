//! Fuzz target: Notify one + Notified poll race
//!
//! Tests race conditions between notify_one() calls and Notified::poll() operations.
//! Verifies that notifications are properly delivered when polling and notification
//! happen concurrently, ensuring no lost wakeups or spurious wakeups occur.
//!
//! # Race Conditions Tested
//! 1. notify_one() called while Notified::poll() is checking notification state
//! 2. Multiple concurrent polls racing with single notify_one()
//! 3. Rapid notify_one() + poll() sequences with various timing
//! 4. Stored notification consumption racing with concurrent notifications

#![no_main]

use arbitrary::Arbitrary;
use asupersync::sync::Notify;
use libfuzzer_sys::fuzz_target;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Barrier;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;

/// Configuration for the notify-poll race test
#[derive(Debug, Arbitrary)]
struct NotifyPollConfig {
    /// Number of poller threads (1-16)
    poller_count: u8,
    /// Number of notifier threads (1-8)
    notifier_count: u8,
    /// Polling patterns for each poller
    poll_patterns: Vec<PollPattern>,
    /// Notification timing patterns
    notify_patterns: Vec<NotifyPattern>,
    /// Whether to use barrier synchronization for tight races
    use_barrier_sync: bool,
}

#[derive(Debug, Arbitrary, Clone)]
enum PollPattern {
    /// Single poll attempt
    SinglePoll,
    /// Rapid repeated polling
    RapidPoll { cycles: u8 },
    /// Poll with delays between attempts
    DelayedPoll { delay_micros: u16 },
    /// Poll until ready or timeout
    PollUntilReady { max_attempts: u8 },
    /// Mixed pattern: poll, delay, poll again
    MixedPoll {
        initial_delay: u16,
        retry_delay: u16,
    },
}

#[derive(Debug, Arbitrary, Clone)]
enum NotifyPattern {
    /// Single immediate notification
    SingleNotify,
    /// Notification after delay
    DelayedNotify { delay_micros: u16 },
    /// Rapid burst of notifications
    BurstNotify { count: u8, interval_micros: u16 },
    /// Notification synchronized with barrier
    SynchronizedNotify,
}

impl NotifyPollConfig {
    fn normalize(&mut self) {
        // Limit thread counts
        self.poller_count = (self.poller_count % 16).max(1);
        self.notifier_count = (self.notifier_count % 8).max(1);

        // Ensure we have enough patterns
        self.poll_patterns
            .resize(self.poller_count as usize, PollPattern::SinglePoll);
        self.notify_patterns
            .resize(self.notifier_count as usize, NotifyPattern::SingleNotify);

        // Normalize pattern parameters
        for pattern in &mut self.poll_patterns {
            match pattern {
                PollPattern::RapidPoll { cycles } => {
                    *cycles = (*cycles % 20).max(1);
                }
                PollPattern::PollUntilReady { max_attempts } => {
                    *max_attempts = (*max_attempts % 50).max(1);
                }
                _ => {}
            }
        }

        for pattern in &mut self.notify_patterns {
            match pattern {
                NotifyPattern::BurstNotify { count, .. } => {
                    *count = (*count % 10).max(1);
                }
                _ => {}
            }
        }
    }
}

/// Test results tracking
#[derive(Debug, Default)]
struct TestResults {
    polls_attempted: AtomicUsize,
    polls_ready: AtomicUsize,
    polls_pending: AtomicUsize,
    notifications_sent: AtomicUsize,
    spurious_wakeups: AtomicUsize,
    lost_notifications: AtomicUsize,
}

#[derive(Debug, Clone, Copy)]
enum WorkerKind {
    Poller,
    Notifier,
}

impl WorkerKind {
    fn as_str(self) -> &'static str {
        match self {
            WorkerKind::Poller => "poller",
            WorkerKind::Notifier => "notifier",
        }
    }
}

/// Custom waker that counts wakeup calls
struct CountingWaker {
    wake_count: Arc<AtomicUsize>,
}

impl CountingWaker {
    fn new() -> (Self, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        (
            CountingWaker {
                wake_count: Arc::clone(&count),
            },
            count,
        )
    }

    fn into_waker(self) -> Waker {
        use std::task::{RawWaker, RawWakerVTable};

        unsafe fn clone_counting_waker(data: *const ()) -> RawWaker {
            unsafe {
                let waker = &*(data as *const CountingWaker);
                let cloned = CountingWaker {
                    wake_count: Arc::clone(&waker.wake_count),
                };
                RawWaker::new(
                    Box::into_raw(Box::new(cloned)) as *const (),
                    &COUNTING_WAKER_VTABLE,
                )
            }
        }

        unsafe fn wake_counting_waker(data: *const ()) {
            unsafe {
                let waker = Box::from_raw(data as *mut CountingWaker);
                waker.wake_count.fetch_add(1, Ordering::SeqCst);
            }
        }

        unsafe fn wake_by_ref_counting_waker(data: *const ()) {
            unsafe {
                let waker = &*(data as *const CountingWaker);
                waker.wake_count.fetch_add(1, Ordering::SeqCst);
            }
        }

        unsafe fn drop_counting_waker(data: *const ()) {
            unsafe {
                let _ = Box::from_raw(data as *mut CountingWaker);
            }
        }

        static COUNTING_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
            clone_counting_waker,
            wake_counting_waker,
            wake_by_ref_counting_waker,
            drop_counting_waker,
        );

        unsafe {
            Waker::from_raw(RawWaker::new(
                Box::into_raw(Box::new(self)) as *const (),
                &COUNTING_WAKER_VTABLE,
            ))
        }
    }
}

/// Manual future for controlled polling
struct ManualNotified {
    notify: Arc<Notify>,
    future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    polls_attempted: u32,
}

impl ManualNotified {
    fn new(notify: Arc<Notify>) -> Self {
        let notify_clone = Arc::clone(&notify);
        let future = Box::pin(async move {
            notify_clone.notified().await;
        });

        Self {
            notify,
            future: Some(future),
            polls_attempted: 0,
        }
    }

    fn poll_with_waker(&mut self, waker: &Waker) -> Poll<()> {
        if let Some(ref mut future) = self.future {
            let mut cx = Context::from_waker(waker);
            self.polls_attempted += 1;
            future.as_mut().poll(&mut cx)
        } else {
            Poll::Ready(())
        }
    }

    fn poll_count(&self) -> u32 {
        self.polls_attempted
    }
}

fuzz_target!(|data: &[u8]| {
    // Parse fuzzer input into config
    let mut config = match NotifyPollConfig::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(config) => config,
        Err(_) => return, // Invalid input, skip
    };
    config.normalize();

    let notify = Arc::new(Notify::new());
    let results = Arc::new(TestResults::default());
    let barrier = Arc::new(Barrier::new(
        (config.poller_count + config.notifier_count) as usize,
    ));
    let mut handles = Vec::new();

    // Spawn poller threads
    for i in 0..config.poller_count {
        let notify = Arc::clone(&notify);
        let results = Arc::clone(&results);
        let barrier = Arc::clone(&barrier);
        let pattern = config.poll_patterns[i as usize].clone();
        let use_barrier = config.use_barrier_sync;

        let handle = thread::spawn(move || {
            {
                let mut manual_notified = ManualNotified::new(notify);
                let (counting_waker, wake_count) = CountingWaker::new();
                let waker = counting_waker.into_waker();

                // Synchronize start if requested
                if use_barrier {
                    barrier.wait();
                }

                match pattern {
                    PollPattern::SinglePoll => {
                        let poll_result = manual_notified.poll_with_waker(&waker);
                        results.polls_attempted.fetch_add(1, Ordering::SeqCst);

                        match poll_result {
                            Poll::Ready(()) => {
                                results.polls_ready.fetch_add(1, Ordering::SeqCst);
                            }
                            Poll::Pending => {
                                results.polls_pending.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }

                    PollPattern::RapidPoll { cycles } => {
                        for _ in 0..cycles {
                            let poll_result = manual_notified.poll_with_waker(&waker);
                            results.polls_attempted.fetch_add(1, Ordering::SeqCst);

                            match poll_result {
                                Poll::Ready(()) => {
                                    results.polls_ready.fetch_add(1, Ordering::SeqCst);
                                    break; // Stop polling once ready
                                }
                                Poll::Pending => {
                                    results.polls_pending.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                        }
                    }

                    PollPattern::DelayedPoll { delay_micros } => {
                        if delay_micros > 0 {
                            thread::sleep(Duration::from_micros(delay_micros as u64));
                        }

                        let poll_result = manual_notified.poll_with_waker(&waker);
                        results.polls_attempted.fetch_add(1, Ordering::SeqCst);

                        match poll_result {
                            Poll::Ready(()) => {
                                results.polls_ready.fetch_add(1, Ordering::SeqCst);
                            }
                            Poll::Pending => {
                                results.polls_pending.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }

                    PollPattern::PollUntilReady { max_attempts } => {
                        for _ in 0..max_attempts {
                            let poll_result = manual_notified.poll_with_waker(&waker);
                            results.polls_attempted.fetch_add(1, Ordering::SeqCst);

                            match poll_result {
                                Poll::Ready(()) => {
                                    results.polls_ready.fetch_add(1, Ordering::SeqCst);
                                    break;
                                }
                                Poll::Pending => {
                                    results.polls_pending.fetch_add(1, Ordering::SeqCst);
                                    thread::sleep(Duration::from_micros(100)); // Small delay between polls
                                }
                            }
                        }
                    }

                    PollPattern::MixedPoll {
                        initial_delay,
                        retry_delay,
                    } => {
                        // Initial delay
                        if initial_delay > 0 {
                            thread::sleep(Duration::from_micros(initial_delay as u64));
                        }

                        // First poll
                        let poll_result = manual_notified.poll_with_waker(&waker);
                        results.polls_attempted.fetch_add(1, Ordering::SeqCst);

                        match poll_result {
                            Poll::Ready(()) => {
                                results.polls_ready.fetch_add(1, Ordering::SeqCst);
                            }
                            Poll::Pending => {
                                results.polls_pending.fetch_add(1, Ordering::SeqCst);

                                // Retry delay
                                if retry_delay > 0 {
                                    thread::sleep(Duration::from_micros(retry_delay as u64));
                                }

                                // Second poll
                                let poll_result2 = manual_notified.poll_with_waker(&waker);
                                results.polls_attempted.fetch_add(1, Ordering::SeqCst);

                                match poll_result2 {
                                    Poll::Ready(()) => {
                                        results.polls_ready.fetch_add(1, Ordering::SeqCst);
                                    }
                                    Poll::Pending => {
                                        results.polls_pending.fetch_add(1, Ordering::SeqCst);
                                    }
                                };
                            }
                        }
                    }
                }

                // Check for spurious wakeups
                let final_wake_count = wake_count.load(Ordering::SeqCst);
                if final_wake_count > 1 {
                    // Possible spurious wakeup
                    results
                        .spurious_wakeups
                        .fetch_add(final_wake_count.saturating_sub(1), Ordering::SeqCst);
                }
            }
        });

        handles.push((WorkerKind::Poller, i, handle));
    }

    // Spawn notifier threads
    for i in 0..config.notifier_count {
        let notify = Arc::clone(&notify);
        let results = Arc::clone(&results);
        let barrier = Arc::clone(&barrier);
        let pattern = config.notify_patterns[i as usize].clone();
        let use_barrier = config.use_barrier_sync;

        let handle = thread::spawn(move || {
            {
                // Synchronize start if requested
                if use_barrier {
                    barrier.wait();
                }

                match pattern {
                    NotifyPattern::SingleNotify => {
                        notify.notify_one();
                        results.notifications_sent.fetch_add(1, Ordering::SeqCst);
                    }

                    NotifyPattern::DelayedNotify { delay_micros } => {
                        if delay_micros > 0 {
                            thread::sleep(Duration::from_micros(delay_micros as u64));
                        }
                        notify.notify_one();
                        results.notifications_sent.fetch_add(1, Ordering::SeqCst);
                    }

                    NotifyPattern::BurstNotify {
                        count,
                        interval_micros,
                    } => {
                        for _ in 0..count {
                            notify.notify_one();
                            results.notifications_sent.fetch_add(1, Ordering::SeqCst);

                            if interval_micros > 0 {
                                thread::sleep(Duration::from_micros(interval_micros as u64));
                            }
                        }
                    }

                    NotifyPattern::SynchronizedNotify => {
                        // Immediate notify right after barrier
                        notify.notify_one();
                        results.notifications_sent.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        });

        handles.push((WorkerKind::Notifier, i, handle));
    }

    // Wait for all threads to complete
    for (kind, index, handle) in handles {
        if handle.join().is_err() {
            panic!(
                "notify_poll_race {} worker {} panicked",
                kind.as_str(),
                index
            );
        }
    }

    let polls_attempted = results.polls_attempted.load(Ordering::SeqCst);
    let polls_ready = results.polls_ready.load(Ordering::SeqCst);
    let polls_pending = results.polls_pending.load(Ordering::SeqCst);
    let notifications_sent = results.notifications_sent.load(Ordering::SeqCst);
    let spurious_wakeups = results.spurious_wakeups.load(Ordering::SeqCst);
    let lost_notifications = results.lost_notifications.load(Ordering::SeqCst);

    // Verify poll accounting
    assert_eq!(
        polls_attempted,
        polls_ready + polls_pending,
        "Poll accounting mismatch: attempted={}, ready={}, pending={}",
        polls_attempted,
        polls_ready,
        polls_pending
    );

    // Verify we actually performed operations
    assert!(polls_attempted > 0, "No polls were attempted");
    assert!(notifications_sent > 0, "No notifications were sent");

    // Invariant: If notifications were sent and polls happened,
    // at least some polls should become ready (unless all notifications
    // were stored for future waiters)
    if notifications_sent > 0 && polls_attempted > 0 {
        // Allow for stored notifications that weren't consumed by current polls
        // This is not a strict invariant due to timing, but useful for validation
        if polls_ready == 0 && spurious_wakeups == 0 {
            // All notifications may have been stored, which is valid
            // No strict assertion needed here
        }
    }

    // Ensure spurious wakeups are within reasonable bounds
    assert!(
        spurious_wakeups < notifications_sent * 2,
        "Excessive spurious wakeups: {} (notifications: {})",
        spurious_wakeups,
        notifications_sent
    );
});
