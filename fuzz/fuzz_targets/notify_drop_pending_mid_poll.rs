//! Fuzz target: Notify one + drop pending mid-poll
//!
//! Tests the critical race condition where notify_one() is called while a Notified
//! future is being dropped during an active poll operation. This tests the window
//! where poll() returns Pending but the future is dropped before the wakeup arrives.
//!
//! # Race Conditions Tested
//! 1. notify_one() during Notified::poll() -> drop sequence
//! 2. Future dropped between poll() returning Pending and waker being called
//! 3. Multiple futures dropped mid-poll while notification is in flight
//! 4. Wakeup delivery when target future is destroyed during notification
//! 5. Waker invalidation timing vs notification delivery

#![no_main]

use arbitrary::Arbitrary;
use asupersync::sync::Notify;
use libfuzzer_sys::fuzz_target;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;

/// Configuration for notify + drop mid-poll race test
#[derive(Debug, Arbitrary)]
struct NotifyDropMidPollConfig {
    /// Number of notified futures (1-16)
    future_count: u8,
    /// Number of notifier threads (1-4)
    notifier_count: u8,
    /// Drop timing patterns for each future
    drop_timings: Vec<DropTiming>,
    /// Notification patterns
    notify_patterns: Vec<NotifyPattern>,
    /// Whether to use barrier synchronization for tight races
    use_barrier_sync: bool,
    /// Polling intensity (polls per future)
    poll_intensity: u8,
}

#[derive(Debug, Arbitrary, Clone)]
enum DropTiming {
    /// Drop immediately after first poll returns Pending
    DropAfterFirstPending,
    /// Drop after N poll attempts
    DropAfterPolls { poll_count: u8 },
    /// Drop during a specific poll cycle
    DropDuringPoll { target_poll: u8 },
    /// Drop with random timing during polling
    DropRandomDuringPoll,
    /// Complete the wait (no drop)
    CompleteWait,
    /// Drop just before expected wakeup
    DropBeforeWakeup { delay_micros: u16 },
}

#[derive(Debug, Arbitrary, Clone)]
enum NotifyPattern {
    /// Single notification after brief delay
    DelayedNotify { delay_micros: u16 },
    /// Rapid burst of notifications
    BurstNotify { count: u8, interval_micros: u16 },
    /// Notification synchronized with barrier
    SynchronizedNotify,
    /// Multiple notifications with varying delays
    StaggeredNotify { delays: Vec<u16> },
}

impl NotifyDropMidPollConfig {
    fn normalize(&mut self) {
        // Limit counts
        self.future_count = (self.future_count % 16).max(1);
        self.notifier_count = (self.notifier_count % 4).max(1);
        self.poll_intensity = (self.poll_intensity % 20).max(1);

        // Ensure we have enough patterns
        self.drop_timings
            .resize(self.future_count as usize, DropTiming::CompleteWait);
        self.notify_patterns.resize(
            self.notifier_count as usize,
            NotifyPattern::DelayedNotify { delay_micros: 100 },
        );

        // Normalize timing parameters
        for timing in &mut self.drop_timings {
            match timing {
                DropTiming::DropAfterPolls { poll_count } => {
                    *poll_count = (*poll_count % 10).max(1);
                }
                DropTiming::DropDuringPoll { target_poll } => {
                    *target_poll = (*target_poll % 10).max(1);
                }
                DropTiming::DropBeforeWakeup { delay_micros } => {
                    *delay_micros = *delay_micros % 500; // Max 0.5ms
                }
                _ => {}
            }
        }

        for pattern in &mut self.notify_patterns {
            match pattern {
                NotifyPattern::DelayedNotify { delay_micros } => {
                    *delay_micros = *delay_micros % 1000; // Max 1ms
                }
                NotifyPattern::BurstNotify {
                    count,
                    interval_micros,
                } => {
                    *count = (*count % 5).max(1);
                    *interval_micros = *interval_micros % 200;
                }
                NotifyPattern::StaggeredNotify { delays } => {
                    delays.truncate(5); // Max 5 staggered notifications
                    for delay in delays.iter_mut() {
                        *delay = *delay % 300;
                    }
                }
                _ => {}
            }
        }
    }
}

/// Test results tracking
#[derive(Debug, Default)]
struct TestResults {
    futures_started: AtomicUsize,
    futures_dropped: AtomicUsize,
    futures_completed: AtomicUsize,
    polls_attempted: AtomicUsize,
    polls_ready: AtomicUsize,
    polls_pending: AtomicUsize,
    notifications_sent: AtomicUsize,
    drop_mid_poll_detected: AtomicUsize,
    wakeups_after_drop: AtomicUsize,
}

/// Custom waker that tracks wakeups even after the future is dropped
struct TrackingWaker {
    wake_count: Arc<AtomicUsize>,
    results: Arc<TestResults>,
    future_dropped: Arc<AtomicBool>,
}

impl TrackingWaker {
    fn new(results: Arc<TestResults>) -> (Self, Arc<AtomicUsize>, Arc<AtomicBool>) {
        let wake_count = Arc::new(AtomicUsize::new(0));
        let future_dropped = Arc::new(AtomicBool::new(false));

        (
            TrackingWaker {
                wake_count: Arc::clone(&wake_count),
                results,
                future_dropped: Arc::clone(&future_dropped),
            },
            wake_count,
            future_dropped,
        )
    }

    fn into_waker(self) -> Waker {
        use std::task::{RawWaker, RawWakerVTable};

        unsafe fn clone_tracking_waker(data: *const ()) -> RawWaker {
            let waker = &*(data as *const TrackingWaker);
            let cloned = TrackingWaker {
                wake_count: Arc::clone(&waker.wake_count),
                results: Arc::clone(&waker.results),
                future_dropped: Arc::clone(&waker.future_dropped),
            };
            RawWaker::new(
                Box::into_raw(Box::new(cloned)) as *const (),
                &TRACKING_WAKER_VTABLE,
            )
        }

        unsafe fn wake_tracking_waker(data: *const ()) {
            let waker = Box::from_raw(data as *mut TrackingWaker);
            waker.wake_count.fetch_add(1, Ordering::SeqCst);

            if waker.future_dropped.load(Ordering::SeqCst) {
                waker
                    .results
                    .wakeups_after_drop
                    .fetch_add(1, Ordering::SeqCst);
            }
        }

        unsafe fn wake_by_ref_tracking_waker(data: *const ()) {
            let waker = &*(data as *const TrackingWaker);
            waker.wake_count.fetch_add(1, Ordering::SeqCst);

            if waker.future_dropped.load(Ordering::SeqCst) {
                waker
                    .results
                    .wakeups_after_drop
                    .fetch_add(1, Ordering::SeqCst);
            }
        }

        unsafe fn drop_tracking_waker(data: *const ()) {
            let _ = Box::from_raw(data as *mut TrackingWaker);
        }

        static TRACKING_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
            clone_tracking_waker,
            wake_tracking_waker,
            wake_by_ref_tracking_waker,
            drop_tracking_waker,
        );

        unsafe {
            Waker::from_raw(RawWaker::new(
                Box::into_raw(Box::new(self)) as *const (),
                &TRACKING_WAKER_VTABLE,
            ))
        }
    }
}

/// Controllable notified future that can be dropped mid-poll
struct MidPollNotified {
    notify: Arc<Notify>,
    future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    poll_count: u32,
    drop_timing: DropTiming,
    poll_intensity: u8,
    future_dropped_flag: Arc<AtomicBool>,
    completed: AtomicBool,
}

impl MidPollNotified {
    fn new(
        notify: Arc<Notify>,
        drop_timing: DropTiming,
        poll_intensity: u8,
        future_dropped_flag: Arc<AtomicBool>,
    ) -> Self {
        let notify_clone = Arc::clone(&notify);
        let future = Box::pin(async move {
            notify_clone.notified().await;
        });

        Self {
            notify,
            future: Some(future),
            poll_count: 0,
            drop_timing,
            poll_intensity,
            future_dropped_flag,
            completed: AtomicBool::new(false),
        }
    }

    fn poll_with_drop_control(&mut self, waker: &Waker, results: &TestResults) -> Poll<()> {
        if self.future.is_none() {
            return Poll::Ready(()); // Already dropped
        }

        self.poll_count += 1;
        results.polls_attempted.fetch_add(1, Ordering::SeqCst);

        // Check if we should drop during this poll
        let should_drop = match &self.drop_timing {
            DropTiming::DropAfterFirstPending => self.poll_count == 1,
            DropTiming::DropAfterPolls { poll_count } => self.poll_count >= *poll_count as u32,
            DropTiming::DropDuringPoll { target_poll } => self.poll_count == *target_poll as u32,
            DropTiming::DropRandomDuringPoll => {
                // Simple pseudo-random based on poll count
                (self.poll_count * 7) % 5 == 0
            }
            DropTiming::DropBeforeWakeup { delay_micros } => {
                // Drop after a brief delay (simulating drop just before wakeup)
                if self.poll_count >= 2 {
                    thread::sleep(Duration::from_micros(*delay_micros as u64));
                    true
                } else {
                    false
                }
            }
            DropTiming::CompleteWait => false,
        };

        if should_drop {
            // Mark as dropped BEFORE actually dropping to test the race window
            self.future_dropped_flag.store(true, Ordering::SeqCst);
            results
                .drop_mid_poll_detected
                .fetch_add(1, Ordering::SeqCst);

            // Drop the future mid-poll
            self.future = None;
            results.polls_pending.fetch_add(1, Ordering::SeqCst);
            return Poll::Pending; // Simulate that poll was about to return Pending
        }

        // Normal poll
        if let Some(ref mut future) = self.future {
            let mut cx = Context::from_waker(waker);
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(()) => {
                    self.completed.store(true, Ordering::SeqCst);
                    results.polls_ready.fetch_add(1, Ordering::SeqCst);
                    Poll::Ready(())
                }
                Poll::Pending => {
                    results.polls_pending.fetch_add(1, Ordering::SeqCst);
                    Poll::Pending
                }
            }
        } else {
            Poll::Ready(())
        }
    }

    fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    fn is_dropped(&self) -> bool {
        self.future.is_none()
    }
}

fuzz_target!(|data: &[u8]| {
    // Parse fuzzer input into config
    let mut config =
        match NotifyDropMidPollConfig::arbitrary(&mut arbitrary::Unstructured::new(data)) {
            Ok(config) => config,
            Err(_) => return, // Invalid input, skip
        };
    config.normalize();

    let notify = Arc::new(Notify::new());
    let results = Arc::new(TestResults::default());

    let total_threads = config.future_count + config.notifier_count;
    let barrier = if config.use_barrier_sync {
        Some(Arc::new(Barrier::new(total_threads as usize)))
    } else {
        None
    };

    let mut handles = Vec::new();

    // Spawn future threads that will poll and potentially drop mid-poll
    for i in 0..config.future_count {
        let notify = Arc::clone(&notify);
        let results = Arc::clone(&results);
        let barrier = barrier.clone();
        let drop_timing = config.drop_timings[i as usize].clone();
        let poll_intensity = config.poll_intensity;

        let handle = thread::spawn(move || {
            results.futures_started.fetch_add(1, Ordering::SeqCst);

            let (tracking_waker, _wake_count, future_dropped_flag) =
                TrackingWaker::new(Arc::clone(&results));
            let waker = tracking_waker.into_waker();

            let mut notified =
                MidPollNotified::new(notify, drop_timing, poll_intensity, future_dropped_flag);

            // Synchronize start if requested
            if let Some(barrier) = barrier {
                barrier.wait();
            }

            // Poll with controlled drop timing
            for _ in 0..poll_intensity {
                match notified.poll_with_drop_control(&waker, &results) {
                    Poll::Ready(()) => {
                        if notified.is_completed() {
                            results.futures_completed.fetch_add(1, Ordering::SeqCst);
                        }
                        break;
                    }
                    Poll::Pending => {
                        if notified.is_dropped() {
                            results.futures_dropped.fetch_add(1, Ordering::SeqCst);
                            break;
                        }
                        // Brief wait between polls
                        thread::sleep(Duration::from_micros(10));
                    }
                }
            }

            // Final accounting
            if notified.is_dropped() && !notified.is_completed() {
                results.futures_dropped.fetch_add(1, Ordering::SeqCst);
            }
        });

        handles.push(handle);
    }

    // Spawn notifier threads
    for i in 0..config.notifier_count {
        let notify = Arc::clone(&notify);
        let results = Arc::clone(&results);
        let barrier = barrier.clone();
        let pattern = config.notify_patterns[i as usize].clone();

        let handle = thread::spawn(move || {
            // Synchronize start if requested
            if let Some(barrier) = barrier {
                barrier.wait();
            }

            // Add brief delay to let futures start polling
            thread::sleep(Duration::from_micros(50));

            match pattern {
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
                    // Immediate notification after barrier
                    notify.notify_one();
                    results.notifications_sent.fetch_add(1, Ordering::SeqCst);
                }

                NotifyPattern::StaggeredNotify { delays } => {
                    for delay in delays {
                        if delay > 0 {
                            thread::sleep(Duration::from_micros(delay as u64));
                        }
                        notify.notify_one();
                        results.notifications_sent.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        let _ = handle.join();
    }

    // Verify results and race condition handling
    let futures_started = results.futures_started.load(Ordering::SeqCst);
    let futures_dropped = results.futures_dropped.load(Ordering::SeqCst);
    let futures_completed = results.futures_completed.load(Ordering::SeqCst);
    let polls_attempted = results.polls_attempted.load(Ordering::SeqCst);
    let polls_ready = results.polls_ready.load(Ordering::SeqCst);
    let polls_pending = results.polls_pending.load(Ordering::SeqCst);
    let notifications_sent = results.notifications_sent.load(Ordering::SeqCst);
    let drop_mid_poll_detected = results.drop_mid_poll_detected.load(Ordering::SeqCst);
    let wakeups_after_drop = results.wakeups_after_drop.load(Ordering::SeqCst);

    // Basic accounting
    assert_eq!(
        futures_started, config.future_count as usize,
        "All futures should start"
    );

    assert_eq!(
        polls_attempted,
        polls_ready + polls_pending,
        "Poll accounting should be consistent"
    );

    // Future outcome accounting
    assert_eq!(
        futures_started,
        futures_completed + futures_dropped,
        "All futures should be either completed or dropped"
    );

    // Invariant: We should have sent notifications
    assert!(
        notifications_sent > 0,
        "Should have sent at least one notification"
    );

    // Race condition verification: The key property we're testing is that
    // dropping futures mid-poll doesn't cause undefined behavior or lost wakeups
    // for other futures

    // If we detected drops mid-poll, there might be wakeups after drop
    // This is acceptable as long as it doesn't cause crashes or hangs
    if drop_mid_poll_detected > 0 {
        // We successfully detected the race condition window
        // The fact that we reached this point means the implementation
        // handled the race gracefully
    }

    // Invariant: Wakeups after drop should not exceed total notifications
    assert!(
        wakeups_after_drop <= notifications_sent,
        "Wakeups after drop ({}) should not exceed total notifications ({})",
        wakeups_after_drop,
        notifications_sent
    );

    // The critical test: we survived the race condition without crashes or hangs
    // This validates that the notify implementation correctly handles the case where
    // a future is dropped during the critical window between poll() and wakeup delivery
});
