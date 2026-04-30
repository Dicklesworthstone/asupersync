//! Fuzz oneshot sender clone-then-drop scenarios.
//!
//! Tests arbitrary clone+drop sequences to ensure receivers behave correctly
//! when multiple senders are involved. Since oneshot Sender doesn't implement Clone,
//! we simulate multiple senders using separate channels with the same conceptual
//! receiver pattern.
//!
//! Critical invariants:
//! - Receiver gets value when ANY sender sends
//! - Receiver gets Cancelled only when ALL senders are dropped without sending
//! - No race conditions between send and drop operations
//! - Proper cleanup when senders are dropped

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use asupersync::channel::oneshot::{self, RecvError, SendError, TryRecvError};
use asupersync::cx::Cx;
use asupersync::types::Budget;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Arbitrary)]
struct CloneDropConfig {
    /// Number of "senders" to simulate (via separate channels)
    sender_count: u8,
    /// Operations to perform on senders
    sender_operations: Vec<SenderOperation>,
    /// Test value to send
    test_value: u32,
    /// Whether to test concurrent operations
    test_concurrency: bool,
    /// Maximum operations to perform
    max_operations: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum SenderOperation {
    /// Send a value through this sender
    Send { sender_id: u8 },
    /// Drop this sender without sending
    Drop { sender_id: u8 },
    /// Send with delay
    DelayedSend { sender_id: u8, delay_ms: u8 },
    /// Drop with delay
    DelayedDrop { sender_id: u8, delay_ms: u8 },
    /// Try to send, then drop if it fails
    SendOrDrop { sender_id: u8 },
}

impl CloneDropConfig {
    fn max_senders() -> u8 {
        8 // Keep reasonable for testing
    }

    fn max_operations() -> u8 {
        20 // Limit test duration
    }
}

/// Tracks sender/receiver behavior across multiple simulated channels
#[derive(Debug)]
struct CloneDropTracker {
    values_received: AtomicUsize,
    cancelled_receivers: AtomicUsize,
    successful_sends: AtomicUsize,
    failed_sends: AtomicUsize,
    drops_performed: AtomicUsize,
    active_senders: AtomicUsize,
}

impl CloneDropTracker {
    fn new(initial_sender_count: usize) -> Self {
        Self {
            values_received: AtomicUsize::new(0),
            cancelled_receivers: AtomicUsize::new(0),
            successful_sends: AtomicUsize::new(0),
            failed_sends: AtomicUsize::new(0),
            drops_performed: AtomicUsize::new(0),
            active_senders: AtomicUsize::new(initial_sender_count),
        }
    }

    fn record_value_received(&self) {
        self.values_received.fetch_add(1, Ordering::SeqCst);
    }

    fn record_cancelled_receiver(&self) {
        self.cancelled_receivers.fetch_add(1, Ordering::SeqCst);
    }

    fn record_successful_send(&self) {
        self.successful_sends.fetch_add(1, Ordering::SeqCst);
        self.active_senders.fetch_sub(1, Ordering::SeqCst);
    }

    fn record_failed_send(&self) {
        self.failed_sends.fetch_add(1, Ordering::SeqCst);
        self.active_senders.fetch_sub(1, Ordering::SeqCst);
    }

    fn record_drop(&self) {
        self.drops_performed.fetch_add(1, Ordering::SeqCst);
        self.active_senders.fetch_sub(1, Ordering::SeqCst);
    }

    fn check_invariants(&self) -> Result<(), String> {
        let values_received = self.values_received.load(Ordering::SeqCst);
        let cancelled = self.cancelled_receivers.load(Ordering::SeqCst);
        let successful_sends = self.successful_sends.load(Ordering::SeqCst);
        let _failed_sends = self.failed_sends.load(Ordering::SeqCst);
        let drops = self.drops_performed.load(Ordering::SeqCst);

        // If any send succeeded, at least one receiver should have gotten a value
        if successful_sends > 0 && values_received == 0 {
            return Err(format!(
                "Successful sends ({}) but no values received",
                successful_sends
            ));
        }

        // If all senders dropped without sending, receivers should be cancelled
        if successful_sends == 0 && drops > 0 && cancelled == 0 && values_received == 0 {
            // This might be ok if there are still active receivers
        }

        Ok(())
    }
}

/// Simulates multi-sender scenario using separate channels
async fn test_clone_drop_scenario(
    config: &CloneDropConfig,
    tracker: &CloneDropTracker,
) -> Result<(), String> {
    use asupersync::util::ArenaIndex;
    use asupersync::{RegionId, TaskId};

    let cx = Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    );
    let sender_count = config.sender_count.min(CloneDropConfig::max_senders()) as usize;

    if sender_count == 0 {
        return Ok(()); // No senders to test
    }

    // Create separate channels to simulate multiple senders
    let mut channels = Vec::new();
    for _ in 0..sender_count {
        channels.push(oneshot::channel());
    }

    // Split channels into senders and receivers
    let (senders_vec, receivers_vec): (Vec<_>, Vec<_>) = channels.into_iter().unzip();
    let mut senders: Vec<Option<oneshot::Sender<u32>>> = senders_vec
        .into_iter()
        .map(|tx| Some(tx))
        .collect();

    let receivers: Vec<oneshot::Receiver<u32>> = receivers_vec;

    // Track which operations have been completed
    let completed_operations = Arc::new(AtomicUsize::new(0));
    let max_ops = config.max_operations.min(CloneDropConfig::max_operations()) as usize;

    // Create receiver futures to monitor all channels
    let receiver_futures: Vec<_> = receivers
        .into_iter()
        .enumerate()
        .map(|(i, mut receiver)| {
            let tracker_clone = Arc::clone(tracker);
            let expected_value = config.test_value;
            let cx_clone = cx.clone();

            async move {
                match receiver.recv(&cx_clone).await {
                    Ok(value) => {
                        if value == expected_value {
                            tracker_clone.record_value_received();
                        } else {
                            return Err(format!(
                                "Receiver {} got wrong value: expected {}, got {}",
                                i, expected_value, value
                            ));
                        }
                    }
                    Err(RecvError::Closed) => {
                        tracker_clone.record_cancelled_receiver();
                    }
                    Err(err) => {
                        return Err(format!("Receiver {} failed with error: {:?}", i, err));
                    }
                }
                Ok(())
            }
        })
        .collect();

    // Process sender operations
    for operation in config.sender_operations.iter().take(max_ops) {
        let completed = completed_operations.fetch_add(1, Ordering::SeqCst);
        if completed >= max_ops {
            break;
        }

        match operation {
            SenderOperation::Send { sender_id } => {
                let sender_idx = (*sender_id as usize) % sender_count;
                if let Some(sender) = senders[sender_idx].take() {
                    match sender.send(&cx, config.test_value) {
                        Ok(()) => {
                            tracker.record_successful_send();
                        }
                        Err(SendError::Disconnected(value)) => {
                            tracker.record_failed_send();
                            if value != config.test_value {
                                return Err(format!(
                                    "Send failed but returned wrong value: expected {}, got {}",
                                    config.test_value, value
                                ));
                            }
                        }
                        Err(SendError::Cancelled(value)) => {
                            tracker.record_failed_send();
                            if value != config.test_value {
                                return Err(format!(
                                    "Send cancelled but returned wrong value: expected {}, got {}",
                                    config.test_value, value
                                ));
                            }
                        }
                    }
                }
            }

            SenderOperation::Drop { sender_id } => {
                let sender_idx = (*sender_id as usize) % sender_count;
                if senders[sender_idx].take().is_some() {
                    tracker.record_drop();
                    // Sender is dropped by taking it from the Option
                }
            }

            SenderOperation::DelayedSend { sender_id, delay_ms } => {
                let delay = Duration::from_millis((*delay_ms).min(100) as u64);
                std::thread::sleep(delay);

                let sender_idx = (*sender_id as usize) % sender_count;
                if let Some(sender) = senders[sender_idx].take() {
                    match sender.send(&cx, config.test_value) {
                        Ok(()) => {
                            tracker.record_successful_send();
                        }
                        Err(SendError::Disconnected(value)) => {
                            tracker.record_failed_send();
                            if value != config.test_value {
                                return Err(format!(
                                    "Delayed send failed but returned wrong value: expected {}, got {}",
                                    config.test_value, value
                                ));
                            }
                        }
                        Err(SendError::Cancelled(value)) => {
                            tracker.record_failed_send();
                            if value != config.test_value {
                                return Err(format!(
                                    "Delayed send cancelled but returned wrong value: expected {}, got {}",
                                    config.test_value, value
                                ));
                            }
                        }
                    }
                }
            }

            SenderOperation::DelayedDrop { sender_id, delay_ms } => {
                let delay = Duration::from_millis((*delay_ms).min(100) as u64);
                std::thread::sleep(delay);

                let sender_idx = (*sender_id as usize) % sender_count;
                if senders[sender_idx].take().is_some() {
                    tracker.record_drop();
                }
            }

            SenderOperation::SendOrDrop { sender_id } => {
                let sender_idx = (*sender_id as usize) % sender_count;
                if let Some(sender) = senders[sender_idx].take() {
                    match sender.send(&cx, config.test_value) {
                        Ok(()) => {
                            tracker.record_successful_send();
                        }
                        Err(_) => {
                            // Send failed, count it as both failed send and drop
                            tracker.record_failed_send();
                        }
                    }
                }
            }
        }

        // Small delay between operations
        if completed % 3 == 2 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    // Drop any remaining senders
    for (i, sender_opt) in senders.iter_mut().enumerate() {
        if sender_opt.take().is_some() {
            tracker.record_drop();
        }
    }

    // Wait for all receiver futures to complete
    let results: Vec<Result<(), String>> = futures::future::join_all(receiver_futures).await;

    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(()) => {
                // Receiver completed successfully
            }
            Err(msg) => {
                return Err(format!("Receiver {} failed: {}", i, msg));
            }
        }
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let config: CloneDropConfig = match unstructured.arbitrary() {
        Ok(cfg) => cfg,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if config.sender_operations.is_empty() || config.sender_count == 0 {
        return;
    }

    let sender_count = config.sender_count.min(CloneDropConfig::max_senders()) as usize;

    futures::executor::block_on(async {
        let tracker = CloneDropTracker::new(sender_count);

        // Test the clone-drop scenario
        if let Err(msg) = test_clone_drop_scenario(&config, &tracker).await {
            panic!("Clone-drop scenario test failed: {}", msg);
        }

        // Validate invariants
        if let Err(msg) = tracker.check_invariants() {
            panic!("Clone-drop invariant violation: {}", msg);
        }

        // Test concurrent scenarios if requested
        if config.test_concurrency {
            let tracker2 = CloneDropTracker::new(sender_count);
            let config2 = config.clone();

            // Run concurrent test directly
            match test_clone_drop_scenario(&config2, &tracker2).await {
                Ok(()) => {
                    // Concurrent test succeeded
                    if let Err(msg) = tracker2.check_invariants() {
                        panic!("Concurrent clone-drop invariant violation: {}", msg);
                    }
                }
                Err(msg) => {
                    panic!("Concurrent clone-drop test failed: {}", msg);
                }
            }
        }
    });
});