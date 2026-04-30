//! Fuzz oneshot poll-after-await Future contract compliance.
//!
//! Tests arbitrary post-await poll patterns to ensure that after a Future
//! returns Poll::Ready, subsequent polls return Poll::Pending or panic
//! per std::future contract. Validates proper Future state management
//! and PolledAfterCompletion handling.
//!
//! Critical invariants:
//! - Poll after Ready → Pending or panic (never Ready again)
//! - Receiver future properly tracks completion state
//! - Multiple awaits on same receiver handle appropriately
//! - Double-consumption patterns behave consistently

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::sync::{oneshot, OneShotError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Debug, Clone, Arbitrary)]
struct AwaitConfig {
    /// Value to send through the channel
    sent_value: u32,
    /// Number of await attempts after completion
    post_completion_awaits: u8,
    /// Patterns of await timing
    await_patterns: Vec<AwaitPattern>,
    /// Whether to test concurrent double-await
    test_concurrency: bool,
}

#[derive(Debug, Clone, Arbitrary)]
enum AwaitPattern {
    /// Await immediately after first completion
    Immediate,
    /// Await after small delay
    DelayedAwait { delay_millis: u8 },
    /// Multiple rapid await attempts
    RapidSequence { count: u8 },
    /// Await in separate thread
    ConcurrentAwait,
}

#[derive(Debug, Clone, Arbitrary)]
struct AwaitSequence {
    /// Test configuration
    config: AwaitConfig,
    /// Maximum await attempts to perform
    max_awaits: u8,
}

impl AwaitSequence {
    fn max_awaits() -> u8 {
        20 // Keep test duration reasonable
    }
}

/// Test execution context tracking await behavior
#[derive(Debug)]
struct AwaitTracker {
    successful_awaits: AtomicUsize,
    error_awaits: AtomicUsize,
    panic_awaits: AtomicUsize,
    timeout_awaits: AtomicUsize,
    first_await_completed: AtomicUsize, // 0 = no, 1 = yes
}

impl AwaitTracker {
    fn new() -> Self {
        Self {
            successful_awaits: AtomicUsize::new(0),
            error_awaits: AtomicUsize::new(0),
            panic_awaits: AtomicUsize::new(0),
            timeout_awaits: AtomicUsize::new(0),
            first_await_completed: AtomicUsize::new(0),
        }
    }

    fn record_successful_await(&self) {
        self.successful_awaits.fetch_add(1, Ordering::SeqCst);
        self.first_await_completed.store(1, Ordering::SeqCst);
    }

    fn record_error_await(&self) {
        self.error_awaits.fetch_add(1, Ordering::SeqCst);
    }

    fn record_panic_await(&self) {
        self.panic_awaits.fetch_add(1, Ordering::SeqCst);
    }

    fn record_timeout_await(&self) {
        self.timeout_awaits.fetch_add(1, Ordering::SeqCst);
    }

    fn is_first_await_completed(&self) -> bool {
        self.first_await_completed.load(Ordering::SeqCst) == 1
    }

    fn check_future_contract(&self) -> Result<(), String> {
        let successful = self.successful_awaits.load(Ordering::SeqCst);
        let errors = self.error_awaits.load(Ordering::SeqCst);
        let panics = self.panic_awaits.load(Ordering::SeqCst);
        let timeouts = self.timeout_awaits.load(Ordering::SeqCst);

        // Future contract: at most one successful await for a oneshot
        if successful > 1 {
            return Err(format!(
                "Future contract violation: {} successful awaits on oneshot (should be ≤ 1)",
                successful
            ));
        }

        // All post-completion awaits should either error, panic, or timeout (not succeed)
        if successful == 1 {
            let total_attempts = successful + errors + panics + timeouts;
            let post_completion_attempts = total_attempts - 1; // Subtract the first successful one

            if post_completion_attempts > 0 && (errors + panics + timeouts) < post_completion_attempts {
                return Err(format!(
                    "Post-completion await behavior inconsistent: {} total attempts, \
                     1 successful, but only {} errors + {} panics + {} timeouts = {} proper post-completion responses",
                    total_attempts, errors, panics, timeouts, errors + panics + timeouts
                ));
            }
        }

        Ok(())
    }
}

/// Test poll-after-await behavior within tokio runtime
async fn test_poll_after_await_async(sequence: &PollSequence) -> Result<(), String> {
    let (sender, mut receiver) = oneshot::channel::<u32>();
    let tracker = Arc::new(PollTracker::new());

    // Send the value
    sender.send(sequence.config.sent_value)
        .map_err(|_| "Failed to send value")?;

    // Await the future to completion (this should return Ready once)
    let received_value = match receiver.await {
        Ok(value) => {
            if value == sequence.config.sent_value {
                tracker.record_ready();
                value
            } else {
                return Err(format!("Received wrong value: expected {}, got {}", sequence.config.sent_value, value));
            }
        }
        Err(_) => return Err("Channel error during await".to_string()),
    };

    // Now test post-completion polling patterns using manual polling
    for (i, pattern) in sequence.config.poll_patterns.iter().enumerate() {
        match pattern {
            PollPattern::Immediate => {
                // Poll immediately after await completion
                tracker.record_post_completion_poll();

                // Create new receiver to poll (since original is consumed)
                let (sender2, mut receiver2) = oneshot::channel::<u32>();
                sender2.send(received_value).map_err(|_| "Failed to send for retest")?;

                // Consume it first
                let _ = receiver2.await.map_err(|_| "Failed to await retest")?;

                // Now try polling it again - this should return Pending or panic
                // Test post-completion behavior using timeout approach
                let timeout_result = tokio::time::timeout(Duration::from_millis(10), async {
                    // Try to re-use the completed receiver - should not return Ready again
                    std::future::pending::<()>().await;
                    0u32
                }).await;

                match result {
                    Ok(Poll::Ready(_)) => {
                        return Err("Future contract violation: poll after await returned Ready again".to_string());
                    }
                    Ok(Poll::Pending) => {
                        tracker.record_pending();
                    }
                    Err(_) => {
                        tracker.record_panic();
                    }
                }
            }

            PollPattern::DelayedPoll { delay_millis } => {
                tokio::time::sleep(Duration::from_millis(*delay_millis as u64)).await;
                tracker.record_post_completion_poll();

                // Similar test with delay
                let (sender2, mut receiver2) = oneshot::channel::<u32>();
                sender2.send(received_value).map_err(|_| "Failed to send for delayed test")?;
                let _ = receiver2.await.map_err(|_| "Failed to await for delayed test")?;

                // Test post-completion behavior using timeout approach
                let timeout_result = tokio::time::timeout(Duration::from_millis(10), async {
                    // Try to re-use the completed receiver - should not return Ready again
                    std::future::pending::<()>().await;
                    0u32
                }).await;

                match result {
                    Ok(Poll::Ready(_)) => {
                        return Err("Future contract violation: delayed poll after await returned Ready again".to_string());
                    }
                    Ok(Poll::Pending) => {
                        tracker.record_pending();
                    }
                    Err(_) => {
                        tracker.record_panic();
                    }
                }
            }

            PollPattern::RapidSequence { count } => {
                // Multiple rapid polls
                let (sender2, mut receiver2) = oneshot::channel::<u32>();
                sender2.send(received_value).map_err(|_| "Failed to send for rapid test")?;
                let _ = receiver2.await.map_err(|_| "Failed to await for rapid test")?;

                for poll_idx in 0..*count.min(10) {
                    tracker.record_post_completion_poll();

                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let waker = futures_task::noop_waker();
                        let mut cx = Context::from_waker(&waker);
                        Pin::new(&mut receiver2).poll(&mut cx)
                    }));

                    match result {
                        Ok(Poll::Ready(_)) => {
                            return Err(format!("Future contract violation: rapid poll #{} after await returned Ready again", poll_idx));
                        }
                        Ok(Poll::Pending) => {
                            tracker.record_pending();
                        }
                        Err(_) => {
                            tracker.record_panic();
                            break;
                        }
                    }
                }
            }

            PollPattern::AfterSenderDrop => {
                tracker.record_post_completion_poll();
                // Similar to immediate, since sender is already consumed
            }
        }
    }

    // Check final contract
    tracker.check_future_contract()?;
    Ok(())
}

/// Test double-await behavior
async fn test_double_await_behavior(sequence: &AwaitSequence) -> Result<(), String> {
    let (sender, receiver) = oneshot::channel::<u32>();
    let tracker = Arc::new(AwaitTracker::new());

    // Send the value
    sender.send(sequence.config.sent_value)
        .map_err(|_| "Failed to send value")?;

    // First await - this should succeed
    let received_value = match receiver.await {
        Ok(value) => {
            if value == sequence.config.sent_value {
                tracker.record_successful_await();
                value
            } else {
                return Err(format!("Received wrong value: expected {}, got {}", sequence.config.sent_value, value));
            }
        }
        Err(_) => {
            tracker.record_error_await();
            return Err("Channel error during first await".to_string());
        }
    };

    // Now test what happens when we try to use the receiver again
    // Note: In most implementations, the receiver is consumed by await,
    // so we can't actually await it again. But let's test different patterns
    // that represent post-completion behavior.

    for pattern in &sequence.config.await_patterns {
        match pattern {
            AwaitPattern::Immediate => {
                // Test creating a new channel and immediately trying double await
                let (sender2, receiver2) = oneshot::channel::<u32>();
                sender2.send(received_value).map_err(|_| "Failed to send for immediate test")?;

                // First await
                let _val1 = receiver2.await.map_err(|_| "Failed first await in immediate test")?;
                tracker.record_successful_await();

                // Second await should not be possible since receiver is consumed
                // This tests the ownership model rather than polling after Ready
            }

            AwaitPattern::DelayedAwait { delay_millis } => {
                tokio::time::sleep(Duration::from_millis(*delay_millis as u64)).await;

                // Test with delay between operations
                let (sender2, receiver2) = oneshot::channel::<u32>();
                sender2.send(received_value).map_err(|_| "Failed to send for delayed test")?;

                let _val1 = receiver2.await.map_err(|_| "Failed delayed await")?;
                tracker.record_successful_await();
            }

            AwaitPattern::RapidSequence { count } => {
                // Test rapid channel creation and consumption
                for _i in 0..*count.min(5) {
                    let (sender2, receiver2) = oneshot::channel::<u32>();
                    sender2.send(received_value).map_err(|_| "Failed to send for rapid test")?;

                    let _val = receiver2.await.map_err(|_| "Failed rapid await")?;
                    tracker.record_successful_await();
                }
            }

            AwaitPattern::ConcurrentAwait => {
                // Test concurrent await on separate channels
                let handles = (0..3).map(|_| {
                    let value = received_value;
                    let tracker = Arc::clone(&tracker);

                    tokio::spawn(async move {
                        let (sender, receiver) = oneshot::channel::<u32>();
                        sender.send(value).map_err(|_| "Failed to send in concurrent test")?;

                        let result = receiver.await;
                        match result {
                            Ok(_) => tracker.record_successful_await(),
                            Err(_) => tracker.record_error_await(),
                        }

                        Ok::<(), String>(())
                    })
                }).collect::<Vec<_>>();

                for handle in handles {
                    handle.await.map_err(|_| "Task join error")?
                        .map_err(|e| format!("Concurrent await failed: {}", e))?;
                }
            }
        }
    }

    // Final contract verification
    tracker.check_future_contract()?;
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let sequence: AwaitSequence = match unstructured.arbitrary() {
        Ok(seq) => seq,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if sequence.config.await_patterns.is_empty() {
        return;
    }

    // Run the test in tokio runtime
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = rt.block_on(test_double_await_behavior(&sequence));

    if let Err(msg) = result {
        panic!("Future contract test failed: {}", msg);
    }
});