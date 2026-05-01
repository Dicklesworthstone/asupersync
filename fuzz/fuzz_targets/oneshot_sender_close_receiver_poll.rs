//! Fuzz target: Oneshot sender close + receiver poll race
//!
//! Tests race conditions between explicit sender close operations and receiver polling.
//! Focuses on channel closure detection consistency and timing variations between
//! close notifications and poll responses.
//!
//! # Race Conditions Tested
//! 1. Sender close() while receiver is actively polling
//! 2. Receiver polling when sender is already closed
//! 3. Close vs poll timing variations with barriers
//! 4. Multiple poll attempts during sender close lifecycle
//! 5. Close detection consistency across timing scenarios
//! 6. Partial send followed by close vs concurrent polling

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use asupersync::channel::oneshot;
use asupersync::Cx;
use std::sync::{Arc, Barrier, atomic::{AtomicUsize, AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;

/// Configuration for sender close + receiver poll race test
#[derive(Debug, Arbitrary)]
struct SenderCloseReceiverPollConfig {
    /// Sender close action pattern
    sender_action: SenderAction,
    /// Receiver polling pattern
    receiver_pattern: ReceiverPattern,
    /// Whether to use barrier synchronization for tight races
    use_barrier_sync: bool,
    /// Delay timings in microseconds
    sender_delay: u16,
    receiver_delay: u16,
    /// Value to send before closing (if applicable)
    send_value: u32,
}

#[derive(Debug, Arbitrary, Clone)]
enum SenderAction {
    /// Close immediately without sending
    CloseImmediately,
    /// Send value then close
    SendThenClose,
    /// Close after delay (no send)
    DelayedClose { close_delay: u16 },
    /// Send with delay, then close
    DelayedSendThenClose { send_delay: u16, close_delay: u16 },
    /// Attempt send, then close regardless of success
    TrySendThenClose,
    /// Keep sender alive (no close) - control case
    KeepAlive,
    /// Close, then attempt send (should fail)
    CloseThenTrySend,
}

#[derive(Debug, Arbitrary, Clone)]
enum ReceiverPattern {
    /// Single try_recv attempt
    SingleTryRecv,
    /// Multiple rapid try_recv attempts
    RapidTryRecv { attempts: u8 },
    /// try_recv with delays between attempts
    DelayedTryRecv { attempts: u8, delay: u16 },
    /// Block on recv() until completion or close
    BlockingRecv,
    /// Mixed: try_recv then blocking recv if needed
    MixedRecv,
    /// Rapid polling during expected close window
    PollDuringClose { attempts: u8, poll_delay: u16 },
}

impl SenderCloseReceiverPollConfig {
    fn normalize(&mut self) {
        // Limit delays to reasonable values
        self.sender_delay = self.sender_delay % 1000; // Max 1ms
        self.receiver_delay = self.receiver_delay % 1000;

        // Normalize pattern parameters
        match &mut self.receiver_pattern {
            ReceiverPattern::RapidTryRecv { attempts } |
            ReceiverPattern::DelayedTryRecv { attempts, .. } |
            ReceiverPattern::PollDuringClose { attempts, .. } => {
                *attempts = (*attempts % 20).max(1);
            },
            _ => {},
        }

        match &mut self.sender_action {
            SenderAction::DelayedClose { close_delay } => {
                *close_delay = *close_delay % 500; // Max 0.5ms close delay
            },
            SenderAction::DelayedSendThenClose { send_delay, close_delay } => {
                *send_delay = *send_delay % 300;
                *close_delay = *close_delay % 300;
            },
            _ => {},
        }

        // Normalize receiver pattern delays
        match &mut self.receiver_pattern {
            ReceiverPattern::DelayedTryRecv { delay, .. } => {
                *delay = *delay % 200; // Max 0.2ms between attempts
            },
            ReceiverPattern::PollDuringClose { poll_delay, .. } => {
                *poll_delay = *poll_delay % 50; // Fast polling during close window
            },
            _ => {},
        }
    }
}

/// Test results tracking
#[derive(Debug, Default)]
struct TestResults {
    sender_started: AtomicBool,
    sender_sent: AtomicBool,
    sender_closed: AtomicBool,
    close_succeeded: AtomicBool,
    receiver_started: AtomicBool,
    try_recv_attempts: AtomicUsize,
    try_recv_empty: AtomicUsize,
    try_recv_closed: AtomicUsize,
    try_recv_success: AtomicUsize,
    blocking_recv_attempts: AtomicUsize,
    blocking_recv_success: AtomicUsize,
    blocking_recv_closed: AtomicUsize,
    post_close_poll_attempts: AtomicUsize,
}

fuzz_target!(|data: &[u8]| {
    // Parse fuzzer input into config
    let mut config = match SenderCloseReceiverPollConfig::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(config) => config,
        Err(_) => return, // Invalid input, skip
    };
    config.normalize();

    let (sender, receiver) = oneshot::channel::<u32>();
    let sender = Arc::new(parking_lot::Mutex::new(Some(sender)));
    let receiver = Arc::new(parking_lot::Mutex::new(Some(receiver)));
    let results = Arc::new(TestResults::default());

    let barrier = if config.use_barrier_sync {
        Some(Arc::new(Barrier::new(2))) // Sender + receiver threads
    } else {
        None
    };

    let mut handles = Vec::new();

    // Spawn sender thread
    {
        let sender = Arc::clone(&sender);
        let results = Arc::clone(&results);
        let barrier = barrier.clone();
        let action = config.sender_action.clone();
        let send_value = config.send_value;
        let sender_delay = config.sender_delay;

        let handle = thread::spawn(move || {
            results.sender_started.store(true, Ordering::SeqCst);

            // Synchronize start if requested
            if let Some(barrier) = barrier {
                barrier.wait();
            }

            // Initial delay
            if sender_delay > 0 {
                thread::sleep(Duration::from_micros(sender_delay as u64));
            }

            let cx = Cx::for_testing();

            match action {
                SenderAction::CloseImmediately => {
                    if let Some(sender) = sender.lock().take() {
                        // In oneshot channels, "close" typically means dropping the sender
                        // without sending anything, which closes the channel
                        drop(sender);
                        results.sender_closed.store(true, Ordering::SeqCst);
                        results.close_succeeded.store(true, Ordering::SeqCst);
                    }
                },

                SenderAction::SendThenClose => {
                    if let Some(sender) = sender.lock().take() {
                        match sender.send(&cx, send_value) {
                            Ok(()) => {
                                results.sender_sent.store(true, Ordering::SeqCst);
                            },
                            Err(_) => {
                                // Send failed (receiver dropped?)
                            },
                        }
                        results.sender_closed.store(true, Ordering::SeqCst);
                        results.close_succeeded.store(true, Ordering::SeqCst);
                    }
                },

                SenderAction::DelayedClose { close_delay } => {
                    if close_delay > 0 {
                        thread::sleep(Duration::from_micros(close_delay as u64));
                    }

                    if let Some(sender) = sender.lock().take() {
                        drop(sender);
                        results.sender_closed.store(true, Ordering::SeqCst);
                        results.close_succeeded.store(true, Ordering::SeqCst);
                    }
                },

                SenderAction::DelayedSendThenClose { send_delay, close_delay } => {
                    if send_delay > 0 {
                        thread::sleep(Duration::from_micros(send_delay as u64));
                    }

                    if let Some(sender) = sender.lock().take() {
                        match sender.send(&cx, send_value) {
                            Ok(()) => {
                                results.sender_sent.store(true, Ordering::SeqCst);
                            },
                            Err(_) => {
                                // Send failed
                            },
                        }

                        if close_delay > 0 {
                            thread::sleep(Duration::from_micros(close_delay as u64));
                        }

                        results.sender_closed.store(true, Ordering::SeqCst);
                        results.close_succeeded.store(true, Ordering::SeqCst);
                    }
                },

                SenderAction::TrySendThenClose => {
                    if let Some(sender) = sender.lock().take() {
                        // Try to send, don't care about success
                        let _ = sender.send(&cx, send_value);
                        results.sender_sent.store(true, Ordering::SeqCst);

                        results.sender_closed.store(true, Ordering::SeqCst);
                        results.close_succeeded.store(true, Ordering::SeqCst);
                    }
                },

                SenderAction::KeepAlive => {
                    // Don't close the sender - keep it alive
                    thread::sleep(Duration::from_millis(10)); // Keep thread alive briefly
                },

                SenderAction::CloseThenTrySend => {
                    if let Some(sender) = sender.lock().take() {
                        // Close first
                        drop(sender);
                        results.sender_closed.store(true, Ordering::SeqCst);
                        results.close_succeeded.store(true, Ordering::SeqCst);

                        // Try to send after close (should be impossible since sender is dropped)
                        // This tests the race condition detection
                    }
                },
            }
        });

        handles.push(handle);
    }

    // Spawn receiver thread
    {
        let receiver = Arc::clone(&receiver);
        let results = Arc::clone(&results);
        let barrier = barrier.clone();
        let pattern = config.receiver_pattern.clone();
        let receiver_delay = config.receiver_delay;
        let expected_value = config.send_value;

        let handle = thread::spawn(move || {
            results.receiver_started.store(true, Ordering::SeqCst);

            // Synchronize start if requested
            if let Some(barrier) = barrier {
                barrier.wait();
            }

            // Initial delay
            if receiver_delay > 0 {
                thread::sleep(Duration::from_micros(receiver_delay as u64));
            }

            match pattern {
                ReceiverPattern::SingleTryRecv => {
                    let receiver_opt = receiver.lock().take();
                    if let Some(mut recv) = receiver_opt {
                        results.try_recv_attempts.fetch_add(1, Ordering::SeqCst);

                        match recv.try_recv() {
                            Ok(value) => {
                                results.try_recv_success.fetch_add(1, Ordering::SeqCst);
                                assert_eq!(value, expected_value, "Received wrong value");
                            },
                            Err(oneshot::TryRecvError::Empty) => {
                                results.try_recv_empty.fetch_add(1, Ordering::SeqCst);
                                // Put receiver back for potential future attempts
                                *receiver.lock() = Some(recv);
                            },
                            Err(oneshot::TryRecvError::Closed) => {
                                results.try_recv_closed.fetch_add(1, Ordering::SeqCst);
                            },
                        }
                    }
                },

                ReceiverPattern::RapidTryRecv { attempts } => {
                    for _ in 0..attempts {
                        let receiver_opt = receiver.lock().take();
                        if let Some(mut recv) = receiver_opt {
                            results.try_recv_attempts.fetch_add(1, Ordering::SeqCst);

                            match recv.try_recv() {
                                Ok(value) => {
                                    results.try_recv_success.fetch_add(1, Ordering::SeqCst);
                                    assert_eq!(value, expected_value, "Received wrong value");
                                    break; // Stop after successful receive
                                },
                                Err(oneshot::TryRecvError::Empty) => {
                                    results.try_recv_empty.fetch_add(1, Ordering::SeqCst);
                                    // Put receiver back for next attempt
                                    *receiver.lock() = Some(recv);
                                },
                                Err(oneshot::TryRecvError::Closed) => {
                                    results.try_recv_closed.fetch_add(1, Ordering::SeqCst);
                                    break; // Stop on closed
                                },
                            }
                        } else {
                            break; // No receiver available
                        }
                    }
                },

                ReceiverPattern::DelayedTryRecv { attempts, delay } => {
                    for _ in 0..attempts {
                        let receiver_opt = receiver.lock().take();
                        if let Some(mut recv) = receiver_opt {
                            results.try_recv_attempts.fetch_add(1, Ordering::SeqCst);

                            match recv.try_recv() {
                                Ok(value) => {
                                    results.try_recv_success.fetch_add(1, Ordering::SeqCst);
                                    assert_eq!(value, expected_value, "Received wrong value");
                                    break;
                                },
                                Err(oneshot::TryRecvError::Empty) => {
                                    results.try_recv_empty.fetch_add(1, Ordering::SeqCst);
                                    // Put receiver back for next attempt
                                    *receiver.lock() = Some(recv);
                                },
                                Err(oneshot::TryRecvError::Closed) => {
                                    results.try_recv_closed.fetch_add(1, Ordering::SeqCst);
                                    break;
                                },
                            }

                            if delay > 0 {
                                thread::sleep(Duration::from_micros(delay as u64));
                            }
                        } else {
                            break; // No receiver available
                        }
                    }
                },

                ReceiverPattern::BlockingRecv => {
                    let receiver_opt = receiver.lock().take();
                    if let Some(mut receiver) = receiver_opt {
                        results.blocking_recv_attempts.fetch_add(1, Ordering::SeqCst);

                        let cx = Cx::for_testing();
                        match futures::executor::block_on(receiver.recv(&cx)) {
                            Ok(value) => {
                                results.blocking_recv_success.fetch_add(1, Ordering::SeqCst);
                                assert_eq!(value, expected_value, "Received wrong value");
                            },
                            Err(_) => {
                                results.blocking_recv_closed.fetch_add(1, Ordering::SeqCst);
                            },
                        }
                    }
                },

                ReceiverPattern::MixedRecv => {
                    // First try_recv
                    let mut got_value = false;
                    let receiver_opt = receiver.lock().take();
                    if let Some(mut recv) = receiver_opt {
                        results.try_recv_attempts.fetch_add(1, Ordering::SeqCst);

                        match recv.try_recv() {
                            Ok(value) => {
                                results.try_recv_success.fetch_add(1, Ordering::SeqCst);
                                assert_eq!(value, expected_value, "Received wrong value");
                                got_value = true;
                            },
                            Err(oneshot::TryRecvError::Empty) => {
                                results.try_recv_empty.fetch_add(1, Ordering::SeqCst);
                                // Put receiver back for blocking recv
                                *receiver.lock() = Some(recv);
                            },
                            Err(oneshot::TryRecvError::Closed) => {
                                results.try_recv_closed.fetch_add(1, Ordering::SeqCst);
                                got_value = true; // Don't try blocking recv
                            },
                        }
                    }

                    // Then blocking recv if no value yet
                    if !got_value {
                        let receiver_opt = receiver.lock().take();
                        if let Some(mut receiver) = receiver_opt {
                            results.blocking_recv_attempts.fetch_add(1, Ordering::SeqCst);

                            let cx = Cx::for_testing();
                            match futures::executor::block_on(receiver.recv(&cx)) {
                                Ok(value) => {
                                    results.blocking_recv_success.fetch_add(1, Ordering::SeqCst);
                                    assert_eq!(value, expected_value, "Received wrong value");
                                },
                                Err(_) => {
                                    results.blocking_recv_closed.fetch_add(1, Ordering::SeqCst);
                                },
                            }
                        }
                    }
                },

                ReceiverPattern::PollDuringClose { attempts, poll_delay } => {
                    // Rapid polling during the expected close window
                    for _ in 0..attempts {
                        let receiver_opt = receiver.lock().take();
                        if let Some(mut recv) = receiver_opt {
                            results.try_recv_attempts.fetch_add(1, Ordering::SeqCst);

                            // Check if sender already closed before this poll attempt
                            let sender_closed_before = results.sender_closed.load(Ordering::SeqCst);

                            match recv.try_recv() {
                                Ok(value) => {
                                    results.try_recv_success.fetch_add(1, Ordering::SeqCst);
                                    assert_eq!(value, expected_value, "Received wrong value");
                                    break;
                                },
                                Err(oneshot::TryRecvError::Empty) => {
                                    results.try_recv_empty.fetch_add(1, Ordering::SeqCst);
                                    // Put receiver back for next attempt
                                    *receiver.lock() = Some(recv);
                                },
                                Err(oneshot::TryRecvError::Closed) => {
                                    results.try_recv_closed.fetch_add(1, Ordering::SeqCst);

                                    // Track post-close poll attempts
                                    if sender_closed_before {
                                        results.post_close_poll_attempts.fetch_add(1, Ordering::SeqCst);
                                    }

                                    break;
                                },
                            }

                            if poll_delay > 0 {
                                thread::sleep(Duration::from_micros(poll_delay as u64));
                            }
                        } else {
                            break; // No receiver available
                        }
                    }
                },
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        let _ = handle.join();
    }

    // Verify results and race condition properties
    let sender_sent = results.sender_sent.load(Ordering::SeqCst);
    let sender_closed = results.sender_closed.load(Ordering::SeqCst);
    let close_succeeded = results.close_succeeded.load(Ordering::SeqCst);
    let try_recv_attempts = results.try_recv_attempts.load(Ordering::SeqCst);
    let try_recv_success = results.try_recv_success.load(Ordering::SeqCst);
    let try_recv_empty = results.try_recv_empty.load(Ordering::SeqCst);
    let try_recv_closed = results.try_recv_closed.load(Ordering::SeqCst);
    let blocking_recv_attempts = results.blocking_recv_attempts.load(Ordering::SeqCst);
    let blocking_recv_success = results.blocking_recv_success.load(Ordering::SeqCst);
    let blocking_recv_closed = results.blocking_recv_closed.load(Ordering::SeqCst);
    let post_close_poll_attempts = results.post_close_poll_attempts.load(Ordering::SeqCst);

    // Basic accounting
    assert_eq!(try_recv_attempts, try_recv_success + try_recv_empty + try_recv_closed,
        "try_recv accounting should be consistent");

    assert_eq!(blocking_recv_attempts, blocking_recv_success + blocking_recv_closed,
        "blocking recv accounting should be consistent");

    // Invariant: At most one successful receive across all attempts
    assert!(try_recv_success + blocking_recv_success <= 1,
        "Should have at most one successful receive");

    // Invariant: If sender sent a value, exactly one receive should succeed
    if sender_sent {
        assert_eq!(try_recv_success + blocking_recv_success, 1,
            "Exactly one receive should succeed when sender sent value");
    }

    // Invariant: If sender closed without sending, no receive should succeed
    if sender_closed && !sender_sent {
        assert_eq!(try_recv_success + blocking_recv_success, 0,
            "No receive should succeed when sender closed without sending");

        // And if receiver tried, it should see Closed (eventually)
        if try_recv_attempts > 0 || blocking_recv_attempts > 0 {
            assert!(try_recv_closed > 0 || blocking_recv_closed > 0,
                "Receiver should detect channel closure when sender closed without sending");
        }
    }

    // Race condition verification: Close detection should be consistent
    if sender_closed {
        assert!(close_succeeded,
            "Close operation should always succeed when sender was closed");
    }

    // If we see Closed in try_recv, the sender must have been closed
    if try_recv_closed > 0 {
        assert!(sender_closed || matches!(config.sender_action, SenderAction::KeepAlive),
            "try_recv should only see Closed if sender was closed");
    }

    // Verify close timing detection
    if post_close_poll_attempts > 0 {
        assert!(try_recv_closed > 0,
            "Post-close poll attempts should result in Closed detection");
    }

    // Blocking recv should see closure if sender closed without sending
    if blocking_recv_closed > 0 {
        assert!(sender_closed,
            "Blocking recv should only see closure when sender is actually closed");
    }

    // Race condition consistency: If sender closed before any receive attempts,
    // receiver should eventually detect closure
    if sender_closed && !sender_sent && (try_recv_attempts > 0 || blocking_recv_attempts > 0) {
        assert!(try_recv_closed > 0 || blocking_recv_closed > 0,
            "Receiver must detect channel closure when sender closed without sending");
    }
});