//! Fuzz target: Oneshot sender drop + receiver poll race
//!
//! Tests race conditions between sender drop operations and receiver polling.
//! Since oneshot senders cannot be cloned, this focuses on the timing races
//! between sender lifecycle (send/drop) and concurrent receiver polling.
//!
//! # Race Conditions Tested
//! 1. Sender dropped while receiver is polling
//! 2. Receiver polling when sender is already dropped
//! 3. Send vs drop vs poll timing variations
//! 4. Multiple poll attempts during sender lifecycle transitions
//! 5. Disconnection detection consistency across timing scenarios

#![no_main]

use arbitrary::Arbitrary;
use asupersync::Cx;
use asupersync::channel::oneshot;
use libfuzzer_sys::fuzz_target;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::Duration;

/// Configuration for sender drop + receiver poll race test
#[derive(Debug, Arbitrary)]
struct SenderDropReceiverPollConfig {
    /// Sender action pattern
    sender_action: SenderAction,
    /// Receiver polling pattern
    receiver_pattern: ReceiverPattern,
    /// Whether to use barrier synchronization
    use_barrier_sync: bool,
    /// Delay timings in microseconds
    sender_delay: u16,
    receiver_delay: u16,
    /// Value to send (if sending)
    send_value: u32,
}

#[derive(Debug, Arbitrary, Clone)]
enum SenderAction {
    /// Send value then drop sender
    SendThenDrop,
    /// Drop sender immediately (no send)
    DropWithoutSend,
    /// Send value with delay, then drop
    DelayedSendThenDrop { send_delay: u16 },
    /// Hold sender alive (no drop)
    KeepAlive,
    /// Reserve then drop (abort send)
    ReserveThenDrop,
    /// Reserve then send then drop
    ReserveThenSendThenDrop,
}

#[derive(Debug, Arbitrary, Clone)]
enum ReceiverPattern {
    /// Single try_recv attempt
    SingleTryRecv,
    /// Multiple rapid try_recv attempts
    RapidTryRecv { attempts: u8 },
    /// try_recv with delays between attempts
    DelayedTryRecv { attempts: u8, delay: u16 },
    /// Block on recv() with timeout simulation
    BlockingRecv,
    /// Mixed: try_recv then blocking recv
    MixedRecv,
}

impl SenderDropReceiverPollConfig {
    fn normalize(&mut self) {
        // Limit delays to reasonable values
        self.sender_delay = self.sender_delay % 1000; // Max 1ms
        self.receiver_delay = self.receiver_delay % 1000;

        // Normalize pattern parameters
        match &mut self.receiver_pattern {
            ReceiverPattern::RapidTryRecv { attempts }
            | ReceiverPattern::DelayedTryRecv { attempts, .. } => {
                *attempts = (*attempts % 20).max(1);
            }
            _ => {}
        }

        match &mut self.sender_action {
            SenderAction::DelayedSendThenDrop { send_delay } => {
                *send_delay = *send_delay % 500; // Max 0.5ms send delay
            }
            _ => {}
        }
    }
}

/// Test results tracking
#[derive(Debug, Default)]
struct TestResults {
    sender_started: AtomicBool,
    sender_sent: AtomicBool,
    sender_dropped: AtomicBool,
    receiver_started: AtomicBool,
    try_recv_attempts: AtomicUsize,
    try_recv_empty: AtomicUsize,
    try_recv_closed: AtomicUsize,
    try_recv_success: AtomicUsize,
    blocking_recv_attempts: AtomicUsize,
    blocking_recv_success: AtomicUsize,
    blocking_recv_error: AtomicUsize,
}

fuzz_target!(|data: &[u8]| {
    // Parse fuzzer input into config
    let mut config =
        match SenderDropReceiverPollConfig::arbitrary(&mut arbitrary::Unstructured::new(data)) {
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
                SenderAction::SendThenDrop => {
                    if let Some(sender) = sender.lock().take() {
                        match sender.send(&cx, send_value) {
                            Ok(()) => {
                                results.sender_sent.store(true, Ordering::SeqCst);
                            }
                            Err(_) => {
                                // Send failed (receiver dropped?)
                            }
                        }
                        results.sender_dropped.store(true, Ordering::SeqCst);
                    }
                }

                SenderAction::DropWithoutSend => {
                    // Just drop the sender
                    if let Some(_sender) = sender.lock().take() {
                        // Drop happens automatically
                        results.sender_dropped.store(true, Ordering::SeqCst);
                    }
                }

                SenderAction::DelayedSendThenDrop { send_delay } => {
                    if send_delay > 0 {
                        thread::sleep(Duration::from_micros(send_delay as u64));
                    }

                    if let Some(sender) = sender.lock().take() {
                        match sender.send(&cx, send_value) {
                            Ok(()) => {
                                results.sender_sent.store(true, Ordering::SeqCst);
                            }
                            Err(_) => {
                                // Send failed
                            }
                        }
                        results.sender_dropped.store(true, Ordering::SeqCst);
                    }
                }

                SenderAction::KeepAlive => {
                    // Don't drop the sender
                    thread::sleep(Duration::from_millis(10)); // Keep thread alive briefly
                }

                SenderAction::ReserveThenDrop => {
                    if let Some(sender) = sender.lock().take() {
                        match sender.reserve(&cx) {
                            Ok(permit) => {
                                // Drop the permit without sending (abort)
                                drop(permit);
                            }
                            Err(_) => {
                                // Reserve failed
                            }
                        }
                        results.sender_dropped.store(true, Ordering::SeqCst);
                    }
                }

                SenderAction::ReserveThenSendThenDrop => {
                    if let Some(sender) = sender.lock().take() {
                        match sender.reserve(&cx) {
                            Ok(permit) => {
                                match permit.send(send_value) {
                                    Ok(()) => {
                                        results.sender_sent.store(true, Ordering::SeqCst);
                                    }
                                    Err(_) => {
                                        // Send failed
                                    }
                                }
                            }
                            Err(_) => {
                                // Reserve failed
                            }
                        }
                        results.sender_dropped.store(true, Ordering::SeqCst);
                    }
                }
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
                            }
                            Err(oneshot::TryRecvError::Empty) => {
                                results.try_recv_empty.fetch_add(1, Ordering::SeqCst);
                                // Put receiver back for potential future attempts
                                *receiver.lock() = Some(recv);
                            }
                            Err(oneshot::TryRecvError::Closed) => {
                                results.try_recv_closed.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                }

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
                                }
                                Err(oneshot::TryRecvError::Empty) => {
                                    results.try_recv_empty.fetch_add(1, Ordering::SeqCst);
                                    // Put receiver back for next attempt
                                    *receiver.lock() = Some(recv);
                                }
                                Err(oneshot::TryRecvError::Closed) => {
                                    results.try_recv_closed.fetch_add(1, Ordering::SeqCst);
                                    break; // Stop on closed
                                }
                            }
                        } else {
                            break; // No receiver available
                        }
                    }
                }

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
                                }
                                Err(oneshot::TryRecvError::Empty) => {
                                    results.try_recv_empty.fetch_add(1, Ordering::SeqCst);
                                    // Put receiver back for next attempt
                                    *receiver.lock() = Some(recv);
                                }
                                Err(oneshot::TryRecvError::Closed) => {
                                    results.try_recv_closed.fetch_add(1, Ordering::SeqCst);
                                    break;
                                }
                            }

                            if delay > 0 {
                                thread::sleep(Duration::from_micros(delay as u64));
                            }
                        } else {
                            break; // No receiver available
                        }
                    }
                }

                ReceiverPattern::BlockingRecv => {
                    let receiver_opt = receiver.lock().take();
                    if let Some(mut receiver) = receiver_opt {
                        results
                            .blocking_recv_attempts
                            .fetch_add(1, Ordering::SeqCst);

                        let cx = Cx::for_testing();
                        match futures::executor::block_on(receiver.recv(&cx)) {
                            Ok(value) => {
                                results.blocking_recv_success.fetch_add(1, Ordering::SeqCst);
                                assert_eq!(value, expected_value, "Received wrong value");
                            }
                            Err(_) => {
                                results.blocking_recv_error.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                }

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
                            }
                            Err(oneshot::TryRecvError::Empty) => {
                                results.try_recv_empty.fetch_add(1, Ordering::SeqCst);
                                // Put receiver back for blocking recv
                                *receiver.lock() = Some(recv);
                            }
                            Err(oneshot::TryRecvError::Closed) => {
                                results.try_recv_closed.fetch_add(1, Ordering::SeqCst);
                                got_value = true; // Don't try blocking recv
                            }
                        }
                    }

                    // Then blocking recv if no value yet
                    if !got_value {
                        let receiver_opt = receiver.lock().take();
                        if let Some(mut receiver) = receiver_opt {
                            results
                                .blocking_recv_attempts
                                .fetch_add(1, Ordering::SeqCst);

                            let cx = Cx::for_testing();
                            match futures::executor::block_on(receiver.recv(&cx)) {
                                Ok(value) => {
                                    results.blocking_recv_success.fetch_add(1, Ordering::SeqCst);
                                    assert_eq!(value, expected_value, "Received wrong value");
                                }
                                Err(_) => {
                                    results.blocking_recv_error.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                        }
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

    // Verify results
    let sender_sent = results.sender_sent.load(Ordering::SeqCst);
    let sender_dropped = results.sender_dropped.load(Ordering::SeqCst);
    let try_recv_attempts = results.try_recv_attempts.load(Ordering::SeqCst);
    let try_recv_success = results.try_recv_success.load(Ordering::SeqCst);
    let try_recv_empty = results.try_recv_empty.load(Ordering::SeqCst);
    let try_recv_closed = results.try_recv_closed.load(Ordering::SeqCst);
    let blocking_recv_attempts = results.blocking_recv_attempts.load(Ordering::SeqCst);
    let blocking_recv_success = results.blocking_recv_success.load(Ordering::SeqCst);
    let blocking_recv_error = results.blocking_recv_error.load(Ordering::SeqCst);

    // Basic accounting
    assert_eq!(
        try_recv_attempts,
        try_recv_success + try_recv_empty + try_recv_closed,
        "try_recv accounting should be consistent"
    );

    assert_eq!(
        blocking_recv_attempts,
        blocking_recv_success + blocking_recv_error,
        "blocking recv accounting should be consistent"
    );

    // Invariant: At most one successful receive across all attempts
    assert!(
        try_recv_success + blocking_recv_success <= 1,
        "Should have at most one successful receive"
    );

    // Invariant: If sender sent a value, exactly one receive should succeed
    if sender_sent {
        assert_eq!(
            try_recv_success + blocking_recv_success,
            1,
            "Exactly one receive should succeed when sender sent value"
        );
    }

    // Invariant: If sender dropped without sending, no receive should succeed
    if sender_dropped && !sender_sent {
        assert_eq!(
            try_recv_success + blocking_recv_success,
            0,
            "No receive should succeed when sender dropped without sending"
        );

        // And if receiver tried, it should see Closed (eventually)
        if try_recv_attempts > 0 || blocking_recv_attempts > 0 {
            assert!(
                try_recv_closed > 0 || blocking_recv_error > 0,
                "Receiver should detect disconnection when sender dropped without sending"
            );
        }
    }

    // Race condition verification: State transitions should be consistent
    // If we see Closed in try_recv, the sender must have been dropped
    if try_recv_closed > 0 {
        assert!(
            sender_dropped || matches!(config.sender_action, SenderAction::KeepAlive),
            "try_recv should only see Closed if sender was dropped"
        );
    }

    // Verify receive error semantics
    if blocking_recv_error > 0 {
        // Blocking recv error should only occur if sender was dropped without sending
        assert!(
            sender_dropped,
            "Blocking recv error should only occur when sender is dropped"
        );
    }
});
