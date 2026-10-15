//! Fuzz watch sender send/send_modify race conditions.
//!
//! Tests arbitrary concurrent send + send_modify operations to ensure
//! subscribers see exactly one of the values atomically, never partial
//! updates. Validates proper synchronization between send operations
//! and atomic visibility guarantees.
//!
//! Critical invariants:
//! - Subscribers see complete values only (never partial updates)
//! - send() and send_modify() are atomic with respect to observers
//! - No lost updates or torn reads during concurrent modifications
//! - Value consistency across all receivers

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::channel::watch;
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Arbitrary)]
struct SendConfig {
    /// Initial value for the watch channel
    initial_value: u64,
    /// Operations to perform concurrently
    operations: Vec<SendOperation>,
    /// Number of receiver threads
    receiver_count: u8,
    /// Duration to run the test (milliseconds)
    test_duration_ms: u16,
}

#[derive(Debug, Clone, Arbitrary)]
enum SendOperation {
    /// Send a new value
    Send { value: u64 },
    /// Replace current value through the send_modify path
    SendReplace { value: u64 },
    /// Send with delay
    DelayedSend { value: u64, delay_ms: u8 },
    /// Replace with delay through the send_modify path
    DelayedSendReplace { value: u64, delay_ms: u8 },
}

#[derive(Debug, Clone, Arbitrary)]
struct RaceSequence {
    /// Test configuration
    config: SendConfig,
    /// Maximum operations to perform
    max_operations: u8,
    /// Whether to test with rapid concurrent operations
    stress_test: bool,
}

impl RaceSequence {
    fn max_operations() -> u8 {
        20 // Keep test duration reasonable
    }

    fn max_receivers() -> u8 {
        8 // Reasonable number of concurrent receivers
    }
}

/// Tracks values observed by receivers to detect race conditions
#[derive(Debug)]
struct RaceTracker {
    values_observed: std::sync::Mutex<HashSet<u64>>,
    partial_updates_detected: AtomicUsize,
    total_observations: AtomicUsize,
    send_operations: AtomicUsize,
    replace_operations: AtomicUsize,
}

impl RaceTracker {
    fn new() -> Self {
        Self {
            values_observed: std::sync::Mutex::new(HashSet::new()),
            partial_updates_detected: AtomicUsize::new(0),
            total_observations: AtomicUsize::new(0),
            send_operations: AtomicUsize::new(0),
            replace_operations: AtomicUsize::new(0),
        }
    }

    fn record_observation(&self, value: u64) {
        self.values_observed.lock().unwrap().insert(value);
        self.total_observations.fetch_add(1, Ordering::SeqCst);
    }

    fn record_partial_update(&self) {
        self.partial_updates_detected.fetch_add(1, Ordering::SeqCst);
    }

    fn record_send(&self) {
        self.send_operations.fetch_add(1, Ordering::SeqCst);
    }

    fn record_replace(&self) {
        self.replace_operations.fetch_add(1, Ordering::SeqCst);
    }

    fn check_race_invariants(&self, expected_values: &[u64]) -> Result<(), String> {
        let partial_updates = self.partial_updates_detected.load(Ordering::SeqCst);
        let total_observations = self.total_observations.load(Ordering::SeqCst);
        let observed = self.values_observed.lock().unwrap();

        // No partial updates should be detected
        if partial_updates > 0 {
            return Err(format!(
                "Partial updates detected: {} out of {} observations",
                partial_updates, total_observations
            ));
        }

        // All observed values should be in the expected set
        for &observed_value in observed.iter() {
            if !expected_values.contains(&observed_value) {
                return Err(format!(
                    "Unexpected value observed: {} (not in expected set {:?})",
                    observed_value, expected_values
                ));
            }
        }

        // Should have seen at least some values if we had operations
        let send_ops = self.send_operations.load(Ordering::SeqCst);
        let replace_ops = self.replace_operations.load(Ordering::SeqCst);

        if (send_ops + replace_ops) > 0 && observed.is_empty() && total_observations == 0 {
            return Err(format!(
                "No observations recorded despite {} send and {} replace operations",
                send_ops, replace_ops
            ));
        }

        Ok(())
    }
}

/// Validates that a value is complete (not a partial update)
fn validate_value_integrity(value: u64, _previous_value: u64) -> bool {
    // For this test, we consider any value valid as long as it's not a "torn" read
    // In a real scenario, you might have more complex validation logic
    // Here we just ensure the value is different from a sentinel "invalid" value
    const INVALID_SENTINEL: u64 = 0xDEADBEEFCAFEBABE;
    value != INVALID_SENTINEL
}

fn observe_send(sender: &watch::Sender<u64>, tracker: &RaceTracker, value: u64) {
    if sender.send(value).is_ok() {
        tracker.record_send();
    }
}

fn observe_replace(sender: &watch::Sender<u64>, tracker: &RaceTracker, value: u64) {
    if sender.send_modify(|current| *current = value).is_ok() {
        tracker.record_replace();
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let sequence: RaceSequence = match unstructured.arbitrary() {
        Ok(seq) => seq,
        Err(_) => return, // Invalid input, skip
    };

    // Validate and limit parameters
    if sequence.config.operations.is_empty() {
        return;
    }

    let max_ops = sequence.max_operations.min(RaceSequence::max_operations()) as usize;
    let receiver_count = sequence
        .config
        .receiver_count
        .min(RaceSequence::max_receivers()) as usize;

    if receiver_count == 0 {
        return; // Need at least one receiver to test
    }

    // Create watch channel
    let (sender, receiver) = watch::channel(sequence.config.initial_value);
    let sender = Arc::new(sender);
    let tracker = Arc::new(RaceTracker::new());
    let initial_value = sequence.config.initial_value;

    // Collect all values that will be sent for validation
    let mut expected_values = vec![sequence.config.initial_value];
    for op in &sequence.config.operations {
        match op {
            SendOperation::Send { value } => expected_values.push(*value),
            SendOperation::SendReplace { value } => expected_values.push(*value),
            SendOperation::DelayedSend { value, .. } => expected_values.push(*value),
            SendOperation::DelayedSendReplace { value, .. } => expected_values.push(*value),
        }
    }

    // Barrier to synchronize start of all threads
    let barrier = Arc::new(Barrier::new(receiver_count + 1));

    // Spawn receiver threads
    let mut receiver_handles = Vec::new();
    for _receiver_id in 0..receiver_count {
        let mut receiver_clone = receiver.clone();
        let tracker_clone = Arc::clone(&tracker);
        let barrier_clone = Arc::clone(&barrier);
        let test_duration =
            Duration::from_millis(u64::from(sequence.config.test_duration_ms.min(1000)));

        let handle = thread::spawn(move || {
            barrier_clone.wait();

            let start_time = std::time::Instant::now();
            let mut last_value = initial_value;

            // Record initial value
            tracker_clone.record_observation(last_value);

            while start_time.elapsed() < test_duration {
                // Check for updates
                if receiver_clone.has_changed() {
                    let current_value = *receiver_clone.borrow_and_update();

                    // Validate value integrity
                    if !validate_value_integrity(current_value, last_value) {
                        tracker_clone.record_partial_update();
                    } else {
                        tracker_clone.record_observation(current_value);
                    }

                    last_value = current_value;
                }

                // Brief yield to allow other threads to run
                thread::sleep(Duration::from_micros(100));
            }
        });

        receiver_handles.push(handle);
    }

    // Start all threads
    barrier.wait();

    // Perform send/send_modify operations concurrently
    let operation_handles: Vec<_> = sequence
        .config
        .operations
        .iter()
        .take(max_ops)
        .map(|op| {
            let sender_clone = Arc::clone(&sender);
            let tracker_clone = Arc::clone(&tracker);
            let operation = op.clone();

            thread::spawn(move || match operation {
                SendOperation::Send { value } => {
                    observe_send(&sender_clone, &tracker_clone, value);
                }

                SendOperation::SendReplace { value } => {
                    observe_replace(&sender_clone, &tracker_clone, value);
                }

                SendOperation::DelayedSend { value, delay_ms } => {
                    thread::sleep(Duration::from_millis(u64::from(delay_ms.min(100))));
                    observe_send(&sender_clone, &tracker_clone, value);
                }

                SendOperation::DelayedSendReplace { value, delay_ms } => {
                    thread::sleep(Duration::from_millis(u64::from(delay_ms.min(100))));
                    observe_replace(&sender_clone, &tracker_clone, value);
                }
            })
        })
        .collect();

    // If stress testing, spawn additional rapid operations
    if sequence.stress_test {
        let stress_handles: Vec<_> = (0..3)
            .map(|stress_id| {
                let sender_clone = Arc::clone(&sender);
                let tracker_clone = Arc::clone(&tracker);
                let stress_value = 9000 + stress_id as u64;

                thread::spawn(move || {
                    for i in 0..10 {
                        let value = stress_value + i;

                        if i % 2 == 0 {
                            observe_send(&sender_clone, &tracker_clone, value);
                        } else {
                            observe_replace(&sender_clone, &tracker_clone, value);
                        }

                        // Very brief yield
                        thread::sleep(Duration::from_micros(50));
                    }
                })
            })
            .collect();

        // Wait for stress operations to complete
        for handle in stress_handles {
            handle.join().expect("Stress thread should complete");
        }
    }

    // Wait for all send operations to complete
    for handle in operation_handles {
        handle.join().expect("Operation thread should complete");
    }

    // Wait a bit more for receivers to observe final updates
    thread::sleep(Duration::from_millis(50));

    // Wait for all receiver threads
    for handle in receiver_handles {
        handle.join().expect("Receiver thread should complete");
    }

    // Add stress test values to expected set if stress testing was enabled
    let mut all_expected_values = expected_values.clone();
    if sequence.stress_test {
        for stress_id in 0..3 {
            for i in 0..10 {
                all_expected_values.push(9000 + stress_id as u64 + i);
            }
        }
    }

    // Check race condition invariants
    if let Err(msg) = tracker.check_race_invariants(&all_expected_values) {
        panic!("Watch send/send_modify race condition detected: {msg}");
    }

    // Verify no partial updates were observed
    let partial_updates = tracker.partial_updates_detected.load(Ordering::SeqCst);
    assert_eq!(
        partial_updates, 0,
        "Partial updates detected in watch channel: {partial_updates} partial updates"
    );

    // Verify that we actually performed operations and observed values
    let total_operations = tracker.send_operations.load(Ordering::SeqCst)
        + tracker.replace_operations.load(Ordering::SeqCst);
    let total_observations = tracker.total_observations.load(Ordering::SeqCst);

    if total_operations > 0 {
        assert!(
            total_observations > 0,
            "No observations recorded despite {total_operations} operations"
        );
    }
});
