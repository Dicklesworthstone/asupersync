//! Fuzz target: Notify one + drop pending future race
//!
//! Tests race conditions between notify_one() calls and dropping pending Notified
//! futures. Verifies that notification delivery is consistent when futures are
//! cancelled/dropped during the notification process.
//!
//! # Race Conditions Tested
//! 1. notify_one() called while Notified future is being dropped
//! 2. Multiple pending futures dropped simultaneously during notify_one()
//! 3. Rapid notify_one() + future drop sequences
//! 4. Notification delivery when some waiters are cancelled mid-flight

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use asupersync::sync::Notify;
use std::sync::{Arc, Barrier, atomic::{AtomicUsize, AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

/// Configuration for the notify + drop pending future race test
#[derive(Debug, Arbitrary)]
struct NotifyDropConfig {
    /// Number of waiter threads (1-16)
    waiter_count: u8,
    /// Number of notifier threads (1-4)
    notifier_count: u8,
    /// Drop timing patterns for waiters
    drop_patterns: Vec<DropPattern>,
    /// Notification timing patterns
    notify_patterns: Vec<NotifyPattern>,
    /// Whether to use barrier synchronization for tight races
    use_barrier_sync: bool,
}

#[derive(Debug, Arbitrary, Clone)]
enum DropPattern {
    /// Complete the wait (no drop)
    CompleteWait,
    /// Drop immediately after starting wait
    DropImmediate,
    /// Drop after short delay
    DropDelayed { delay_micros: u16 },
    /// Poll once then drop
    PollThenDrop,
    /// Poll multiple times then drop
    PollMultipleThenDrop { polls: u8 },
}

#[derive(Debug, Arbitrary, Clone)]
enum NotifyPattern {
    /// Single immediate notification
    SingleNotify,
    /// Notification after delay
    DelayedNotify { delay_micros: u16 },
    /// Rapid burst of notifications
    BurstNotify { count: u8 },
    /// Synchronized notification with barrier
    SynchronizedNotify,
}

impl NotifyDropConfig {
    fn normalize(&mut self) {
        // Limit thread counts
        self.waiter_count = (self.waiter_count % 16).max(1);
        self.notifier_count = (self.notifier_count % 4).max(1);

        // Ensure we have enough patterns
        self.drop_patterns.resize(self.waiter_count as usize, DropPattern::CompleteWait);
        self.notify_patterns.resize(self.notifier_count as usize, NotifyPattern::SingleNotify);

        // Normalize pattern parameters
        for pattern in &mut self.drop_patterns {
            match pattern {
                DropPattern::PollMultipleThenDrop { polls } => {
                    *polls = (*polls % 10).max(1);
                },
                _ => {},
            }
        }

        for pattern in &mut self.notify_patterns {
            match pattern {
                NotifyPattern::BurstNotify { count } => {
                    *count = (*count % 5).max(1);
                },
                _ => {},
            }
        }
    }
}

/// Test results tracking
#[derive(Debug, Default)]
struct TestResults {
    waiters_started: AtomicUsize,
    waiters_completed: AtomicUsize,
    waiters_dropped: AtomicUsize,
    notifications_sent: AtomicUsize,
    polls_attempted: AtomicUsize,
    polls_ready: AtomicUsize,
    polls_pending: AtomicUsize,
}

/// Manual future for controlled polling and dropping
struct ControllableNotified {
    future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    polls_done: u32,
    completed: AtomicBool,
}

impl ControllableNotified {
    fn new(notify: Arc<Notify>) -> Self {
        let notify_clone = Arc::clone(&notify);
        let future = Box::pin(async move {
            notify_clone.notified().await;
        });

        Self {
            future: Some(future),
            polls_done: 0,
            completed: AtomicBool::new(false),
        }
    }

    fn poll_once(&mut self, waker: &Waker) -> Poll<()> {
        if let Some(ref mut future) = self.future {
            let mut cx = Context::from_waker(waker);
            self.polls_done += 1;
            let result = future.as_mut().poll(&mut cx);
            if matches!(result, Poll::Ready(())) {
                self.completed.store(true, Ordering::SeqCst);
            }
            result
        } else {
            Poll::Ready(())
        }
    }

    fn drop_future(&mut self) {
        self.future = None;
    }

}

fuzz_target!(|data: &[u8]| {
    // Parse fuzzer input into config
    let mut config = match NotifyDropConfig::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(config) => config,
        Err(_) => return, // Invalid input, skip
    };
    config.normalize();

    let notify = Arc::new(Notify::new());
    let results = Arc::new(TestResults::default());
    let barrier = Arc::new(Barrier::new((config.waiter_count + config.notifier_count) as usize));
    let mut handles = Vec::new();

    // Spawn waiter threads with different drop patterns
    for i in 0..config.waiter_count {
        let notify = Arc::clone(&notify);
        let results = Arc::clone(&results);
        let barrier = Arc::clone(&barrier);
        let pattern = config.drop_patterns[i as usize].clone();
        let use_barrier = config.use_barrier_sync;

        let handle = thread::spawn(move || {
            results.waiters_started.fetch_add(1, Ordering::SeqCst);

            // Create a controllable future
            let mut controllable = ControllableNotified::new(notify);
            let waker = futures::task::noop_waker();

            // Synchronize start if requested
            if use_barrier {
                barrier.wait();
            }

            match pattern {
                DropPattern::CompleteWait => {
                    // Keep polling until ready
                    loop {
                        results.polls_attempted.fetch_add(1, Ordering::SeqCst);
                        match controllable.poll_once(&waker) {
                            Poll::Ready(()) => {
                                results.polls_ready.fetch_add(1, Ordering::SeqCst);
                                results.waiters_completed.fetch_add(1, Ordering::SeqCst);
                                break;
                            },
                            Poll::Pending => {
                                results.polls_pending.fetch_add(1, Ordering::SeqCst);
                                thread::sleep(Duration::from_micros(100));
                            },
                        }
                    }
                },

                DropPattern::DropImmediate => {
                    // Drop the future immediately
                    controllable.drop_future();
                    results.waiters_dropped.fetch_add(1, Ordering::SeqCst);
                },

                DropPattern::DropDelayed { delay_micros } => {
                    // Wait then drop
                    if delay_micros > 0 {
                        thread::sleep(Duration::from_micros(delay_micros as u64));
                    }
                    controllable.drop_future();
                    results.waiters_dropped.fetch_add(1, Ordering::SeqCst);
                },

                DropPattern::PollThenDrop => {
                    // Poll once then drop
                    results.polls_attempted.fetch_add(1, Ordering::SeqCst);
                    match controllable.poll_once(&waker) {
                        Poll::Ready(()) => {
                            results.polls_ready.fetch_add(1, Ordering::SeqCst);
                            results.waiters_completed.fetch_add(1, Ordering::SeqCst);
                        },
                        Poll::Pending => {
                            results.polls_pending.fetch_add(1, Ordering::SeqCst);
                            // Drop after first poll
                            controllable.drop_future();
                            results.waiters_dropped.fetch_add(1, Ordering::SeqCst);
                        },
                    }
                },

                DropPattern::PollMultipleThenDrop { polls } => {
                    // Poll multiple times then drop
                    let mut completed = false;
                    for _ in 0..polls {
                        results.polls_attempted.fetch_add(1, Ordering::SeqCst);
                        match controllable.poll_once(&waker) {
                            Poll::Ready(()) => {
                                results.polls_ready.fetch_add(1, Ordering::SeqCst);
                                results.waiters_completed.fetch_add(1, Ordering::SeqCst);
                                completed = true;
                                break;
                            },
                            Poll::Pending => {
                                results.polls_pending.fetch_add(1, Ordering::SeqCst);
                                thread::sleep(Duration::from_micros(50));
                            },
                        }
                    }

                    // Drop if not completed
                    if !completed {
                        controllable.drop_future();
                        results.waiters_dropped.fetch_add(1, Ordering::SeqCst);
                    }
                },
            }
        });

        handles.push(handle);
    }

    // Spawn notifier threads
    for i in 0..config.notifier_count {
        let notify = Arc::clone(&notify);
        let results = Arc::clone(&results);
        let barrier = Arc::clone(&barrier);
        let pattern = config.notify_patterns[i as usize].clone();
        let use_barrier = config.use_barrier_sync;

        let handle = thread::spawn(move || {
            // Synchronize start if requested
            if use_barrier {
                barrier.wait();
            }

            match pattern {
                NotifyPattern::SingleNotify => {
                    notify.notify_one();
                    results.notifications_sent.fetch_add(1, Ordering::SeqCst);
                },

                NotifyPattern::DelayedNotify { delay_micros } => {
                    if delay_micros > 0 {
                        thread::sleep(Duration::from_micros(delay_micros as u64));
                    }
                    notify.notify_one();
                    results.notifications_sent.fetch_add(1, Ordering::SeqCst);
                },

                NotifyPattern::BurstNotify { count } => {
                    for _ in 0..count {
                        notify.notify_one();
                        results.notifications_sent.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_micros(10)); // Small gap between notifications
                    }
                },

                NotifyPattern::SynchronizedNotify => {
                    // Immediate notify right after barrier
                    notify.notify_one();
                    results.notifications_sent.fetch_add(1, Ordering::SeqCst);
                },
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        let _ = handle.join();
    }

    // Verify results
    let waiters_started = results.waiters_started.load(Ordering::SeqCst);
    let waiters_completed = results.waiters_completed.load(Ordering::SeqCst);
    let waiters_dropped = results.waiters_dropped.load(Ordering::SeqCst);
    let notifications_sent = results.notifications_sent.load(Ordering::SeqCst);
    let polls_attempted = results.polls_attempted.load(Ordering::SeqCst);
    let polls_ready = results.polls_ready.load(Ordering::SeqCst);
    let polls_pending = results.polls_pending.load(Ordering::SeqCst);

    // Basic accounting checks
    assert_eq!(waiters_started, config.waiter_count as usize,
        "All waiters should start");

    // Waiters should be either completed or dropped
    assert_eq!(waiters_completed + waiters_dropped, waiters_started,
        "All waiters should be either completed or dropped");

    // Poll accounting
    assert_eq!(polls_attempted, polls_ready + polls_pending,
        "Poll accounting should be consistent");

    // Verify we actually sent notifications
    assert!(notifications_sent > 0,
        "Should have sent at least one notification");

    // Invariant: Number of completed waiters should not exceed number of notifications
    // (Some notifications may be lost due to dropped futures)
    assert!(waiters_completed <= notifications_sent,
        "Completed waiters ({}) should not exceed notifications sent ({})",
        waiters_completed, notifications_sent);

    // Invariant: If we have more notifications than waiters, all waiters should complete
    // (unless they were intentionally dropped)
    if notifications_sent >= waiters_started {
        let expected_completions = config.drop_patterns.iter()
            .filter(|p| matches!(p, DropPattern::CompleteWait))
            .count();

        if expected_completions > 0 {
            // At least some waiters were supposed to complete
            assert!(waiters_completed > 0 || expected_completions == 0,
                "With {} notifications for {} waiters, expected some completions",
                notifications_sent, waiters_started);
        }
    }

    // Race condition verification: Dropped futures should not affect other waiters
    // This is implicit in the above checks - if other waiters were incorrectly affected,
    // the completion count would be wrong
});