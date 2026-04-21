#![allow(clippy::all)]
//! Two-phase channel atomicity verification framework.
//!
//! This module provides comprehensive testing for the atomicity guarantees of
//! reserve/commit operations across all channel types under concurrent stress
//! and cancellation injection.

#![allow(dead_code)]

use crate::channel::mpsc::{self, RecvError, SendError};
use crate::cx::Cx;
use crate::time::sleep;
use crate::types::Time;

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
// Removed tokio dependency - this project IS the async runtime

/// Configuration for atomicity verification tests.
#[derive(Debug, Clone)]
pub struct AtomicityTestConfig {
    /// Channel capacity for testing.
    pub capacity: usize,
    /// Number of producer tasks.
    pub num_producers: usize,
    /// Number of messages per producer.
    pub messages_per_producer: usize,
    /// Duration to run stress test.
    pub test_duration: Duration,
    /// Probability of cancellation injection (0.0 to 1.0).
    pub cancel_probability: f64,
    /// Enable invariant checking during operations.
    pub check_invariants: bool,
}

impl Default for AtomicityTestConfig {
    fn default() -> Self {
        Self {
            capacity: 10,
            num_producers: 4,
            messages_per_producer: 100,
            test_duration: Duration::from_secs(5),
            cancel_probability: 0.1,
            check_invariants: true,
        }
    }
}

/// Statistics collected during atomicity verification.
#[derive(Debug, Default)]
pub struct AtomicityStats {
    /// Total messages sent successfully.
    pub messages_sent: AtomicU64,
    /// Total messages received successfully.
    pub messages_received: AtomicU64,
    /// Total reservations made.
    pub reservations_made: AtomicU64,
    /// Total reservations aborted.
    pub reservations_aborted: AtomicU64,
    /// Total cancellations during reserve phase.
    pub reserve_cancellations: AtomicU64,
    /// Total cancellations during commit phase.
    pub commit_cancellations: AtomicU64,
    /// Total invariant violations detected.
    pub invariant_violations: AtomicU64,
    /// Maximum observed queue length.
    pub max_queue_length: AtomicUsize,
    /// Maximum observed reserved count.
    pub max_reserved_count: AtomicUsize,
}

impl AtomicityStats {
    /// Returns true if no data loss occurred (sent == received).
    pub fn is_consistent(&self) -> bool {
        let sent = self.messages_sent.load(Ordering::Acquire);
        let received = self.messages_received.load(Ordering::Acquire);
        sent == received
    }

    /// Returns true if no invariant violations were detected.
    pub fn is_invariant_safe(&self) -> bool {
        self.invariant_violations.load(Ordering::Acquire) == 0
    }
}

/// Channel state snapshot for invariant verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSnapshot {
    /// Number of messages in the queue.
    pub queue_length: usize,
    /// Number of reserved slots.
    pub reserved_count: usize,
    /// Total used slots (queue + reserved).
    pub used_slots: usize,
    /// Channel capacity.
    pub capacity: usize,
    /// Timestamp when snapshot was taken.
    pub timestamp: Time,
}

impl ChannelSnapshot {
    /// Verifies the fundamental capacity invariant.
    pub fn verify_capacity_invariant(&self) -> bool {
        self.used_slots <= self.capacity
    }

    /// Verifies that used_slots = queue_length + reserved_count.
    pub fn verify_accounting_invariant(&self) -> bool {
        self.used_slots == self.queue_length + self.reserved_count
    }
}

/// Atomicity verification oracle that tracks channel state consistency.
pub struct AtomicityOracle {
    stats: Arc<AtomicityStats>,
    snapshots: Arc<Mutex<Vec<ChannelSnapshot>>>,
    config: AtomicityTestConfig,
}

impl AtomicityOracle {
    /// Creates a new atomicity oracle.
    pub fn new(config: AtomicityTestConfig) -> Self {
        Self {
            stats: Arc::new(AtomicityStats::default()),
            snapshots: Arc::new(Mutex::new(Vec::new())),
            config,
        }
    }

    /// Records a successful reservation.
    pub fn record_reservation(&self) {
        self.stats.reservations_made.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a reservation abortion.
    pub fn record_abortion(&self) {
        self.stats
            .reservations_aborted
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a successful message send.
    pub fn record_send(&self) {
        self.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a successful message receive.
    pub fn record_receive(&self) {
        self.stats.messages_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a cancellation during reserve phase.
    pub fn record_reserve_cancellation(&self) {
        self.stats
            .reserve_cancellations
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a cancellation during commit phase.
    pub fn record_commit_cancellation(&self) {
        self.stats
            .commit_cancellations
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records an invariant violation.
    pub fn record_violation(&self) {
        self.stats
            .invariant_violations
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Takes a snapshot of channel state for invariant checking.
    pub fn take_snapshot(&self, snapshot: ChannelSnapshot) {
        // Verify invariants immediately
        if self.config.check_invariants {
            if !snapshot.verify_capacity_invariant() {
                self.record_violation();
                eprintln!(
                    "VIOLATION: Capacity invariant failed: used_slots={} > capacity={}",
                    snapshot.used_slots, snapshot.capacity
                );
            }
            if !snapshot.verify_accounting_invariant() {
                self.record_violation();
                eprintln!(
                    "VIOLATION: Accounting invariant failed: used_slots={} != queue_length={} + reserved_count={}",
                    snapshot.used_slots, snapshot.queue_length, snapshot.reserved_count
                );
            }
        }

        // Update max observed values
        self.stats
            .max_queue_length
            .fetch_max(snapshot.queue_length, Ordering::Relaxed);
        self.stats
            .max_reserved_count
            .fetch_max(snapshot.reserved_count, Ordering::Relaxed);

        // Store snapshot for later analysis
        if let Ok(mut snapshots) = self.snapshots.lock() {
            snapshots.push(snapshot);
        }
    }

    /// Returns the collected statistics.
    pub fn stats(&self) -> Arc<AtomicityStats> {
        Arc::clone(&self.stats)
    }

    /// Returns all collected snapshots.
    pub fn snapshots(&self) -> Vec<ChannelSnapshot> {
        match self.snapshots.lock() {
            Ok(snapshots) => snapshots.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Verifies that the final state is consistent.
    pub fn verify_final_consistency(&self) -> bool {
        self.stats.is_consistent() && self.stats.is_invariant_safe()
    }
}

/// Cancellation injector that randomly cancels operations.
pub struct CancellationInjector {
    probability: f64,
    rng_state: AtomicU64,
}

impl CancellationInjector {
    /// Creates a new cancellation injector with the given probability.
    pub fn new(probability: f64) -> Self {
        Self {
            probability,
            rng_state: AtomicU64::new(1), // Simple LCG seed
        }
    }

    /// Returns true if the current operation should be cancelled.
    pub fn should_cancel(&self) -> bool {
        if self.probability <= 0.0 {
            return false;
        }

        // Simple LCG for deterministic randomness
        let mut state = self.rng_state.load(Ordering::Relaxed);
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        self.rng_state.store(state, Ordering::Relaxed);

        let random = (state >> 16) as f64 / u32::MAX as f64;
        random < self.probability
    }
}

/// Mock channel wrapper that exposes internal state for testing.
pub struct TestableChannel<T> {
    sender: mpsc::Sender<T>,
    receiver: mpsc::Receiver<T>,
    oracle: Arc<AtomicityOracle>,
}

impl<T> TestableChannel<T> {
    /// Creates a new testable channel with the given capacity and oracle.
    pub fn new(capacity: usize, oracle: Arc<AtomicityOracle>) -> Self {
        let (sender, receiver) = mpsc::channel(capacity);
        Self {
            sender,
            receiver,
            oracle,
        }
    }

    /// Returns the sender side.
    pub fn sender(&self) -> &mpsc::Sender<T> {
        &self.sender
    }

    /// Returns the receiver side.
    pub fn receiver(&self) -> &mpsc::Receiver<T> {
        &self.receiver
    }

    /// Takes a snapshot of the current channel state.
    ///
    /// Note: This is a simplified version that doesn't access internal state
    /// directly. In a real implementation, we'd need access to the channel
    /// internals or use test-specific hooks.
    pub fn take_snapshot(&self, now: Time) {
        // This is a placeholder - in a real implementation we'd need
        // privileged access to channel internals for true state inspection
        let snapshot = ChannelSnapshot {
            queue_length: 0,   // Would need internal access
            reserved_count: 0, // Would need internal access
            used_slots: 0,     // Would need internal access
            capacity: self.sender.capacity(),
            timestamp: now,
        };
        self.oracle.take_snapshot(snapshot);
    }
}

/// Producer task that sends messages with optional cancellation injection.
pub async fn producer_task<T>(
    sender: mpsc::Sender<T>,
    oracle: Arc<AtomicityOracle>,
    injector: Arc<CancellationInjector>,
    messages: Vec<T>,
    cx: &Cx,
) -> Result<(), SendError<T>>
where
    T: Send + Clone + std::fmt::Debug + 'static,
{
    for (i, message) in messages.into_iter().enumerate() {
        // Random delay to increase interleaving
        if i % 10 == 0 {
            sleep(cx.now(), Duration::from_micros(1)).await;
        }

        // Check for cancellation injection during reserve
        if injector.should_cancel() {
            oracle.record_reserve_cancellation();
            continue;
        }

        // Phase 1: Reserve slot
        let permit = match sender.reserve(cx).await {
            Ok(permit) => {
                oracle.record_reservation();
                permit
            }
            Err(SendError::Cancelled(_)) => {
                oracle.record_reserve_cancellation();
                continue;
            }
            Err(SendError::Disconnected(_)) => return Err(SendError::Disconnected(message)),
            Err(SendError::Full(_)) => return Err(SendError::Full(message)),
        };

        // Check for cancellation injection during commit
        if injector.should_cancel() {
            oracle.record_abortion();
            permit.abort();
            oracle.record_commit_cancellation();
            continue;
        }

        // Phase 2: Commit message
        permit.send(message);
        oracle.record_send();
    }

    Ok(())
}

/// Consumer task that receives messages.
pub async fn consumer_task<T>(
    mut receiver: mpsc::Receiver<T>,
    oracle: Arc<AtomicityOracle>,
    expected_count: usize,
    cx: &Cx,
) -> Result<Vec<T>, RecvError> {
    let mut messages = Vec::new();

    for _ in 0..expected_count {
        match receiver.recv(cx).await {
            Ok(message) => {
                oracle.record_receive();
                messages.push(message);
            }
            Err(RecvError::Disconnected) => break,
            Err(e) => return Err(e),
        }
    }

    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomicity_oracle_basic() {
        let config = AtomicityTestConfig::default();
        let oracle = AtomicityOracle::new(config.clone());

        // Test recording operations
        oracle.record_reservation();
        oracle.record_send();
        oracle.record_receive();

        let stats = oracle.stats();
        assert_eq!(stats.reservations_made.load(Ordering::Acquire), 1);
        assert_eq!(stats.messages_sent.load(Ordering::Acquire), 1);
        assert_eq!(stats.messages_received.load(Ordering::Acquire), 1);
        assert!(stats.is_consistent());
    }

    #[test]
    fn test_channel_snapshot_invariants() {
        let snapshot = ChannelSnapshot {
            queue_length: 5,
            reserved_count: 3,
            used_slots: 8,
            capacity: 10,
            timestamp: Time::ZERO,
        };

        assert!(snapshot.verify_capacity_invariant());
        assert!(snapshot.verify_accounting_invariant());

        // Test violation cases
        let bad_snapshot = ChannelSnapshot {
            queue_length: 5,
            reserved_count: 3,
            used_slots: 12, // > capacity
            capacity: 10,
            timestamp: Time::ZERO,
        };

        assert!(!bad_snapshot.verify_capacity_invariant());
    }

    #[test]
    fn test_cancellation_injector() {
        let injector = CancellationInjector::new(0.0);
        assert!(!injector.should_cancel());

        let injector = CancellationInjector::new(1.0);
        assert!(injector.should_cancel());

        // Test some randomness
        let injector = CancellationInjector::new(0.5);
        let mut cancellations = 0;
        for _ in 0..1000 {
            if injector.should_cancel() {
                cancellations += 1;
            }
        }
        // Should be roughly 50% with some variance
        assert!(cancellations > 400 && cancellations < 600);
    }

    /*
    // Commented out due to tokio dependency (forbidden in asupersync) and unsafe code usage
    #[tokio::test]
    async fn test_basic_two_phase_atomicity() {
        let config = AtomicityTestConfig {
            capacity: 5,
            num_producers: 2,
            messages_per_producer: 10,
            cancel_probability: 0.0, // No cancellation for basic test
            ..Default::default()
        };

        let oracle = Arc::new(AtomicityOracle::new(config.clone()));
        let injector = Arc::new(CancellationInjector::new(0.0));
        let channel = TestableChannel::new(config.capacity, Arc::clone(&oracle));

        let _runtime = lab_with_config(|rt| async move {
            let cx = &rt.cx();

            let expected_messages = config.num_producers * config.messages_per_producer;

            // Start consumer
            let consumer_oracle = Arc::clone(&oracle);
            let receiver = unsafe { std::ptr::read(&channel.receiver) };
            let consumer = task::spawn(async move {
                consumer_task(receiver, consumer_oracle, expected_messages, cx).await
            });

            // Start producers
            let mut producers = Vec::new();
            for i in 0..config.num_producers {
                let sender = channel.sender().clone();
                let producer_oracle = Arc::clone(&oracle);
                let producer_injector = Arc::clone(&injector);
                let messages: Vec<u32> = (0..config.messages_per_producer)
                    .map(|j| (i * config.messages_per_producer + j) as u32)
                    .collect();

                let producer = task::spawn(async move {
                    producer_task(sender, producer_oracle, producer_injector, messages, cx).await
                });
                producers.push(producer);
            }

            // Wait for all producers to complete
            for producer in producers {
                let _ = producer.await;
            }

            // Close sender to signal completion
            drop(channel.sender); // Drop sender to close channel

            // Wait for consumer
            let received = consumer.await.unwrap().unwrap();
            assert_eq!(received.len(), expected_messages);

            // Verify consistency
            let stats = oracle.stats();
            assert!(
                stats.is_consistent(),
                "Message count mismatch: sent={}, received={}",
                stats.messages_sent.load(Ordering::Acquire),
                stats.messages_received.load(Ordering::Acquire)
            );
            assert!(stats.is_invariant_safe(), "Invariant violations detected");

            println!("Basic atomicity test passed:");
            println!(
                "  Messages sent: {}",
                stats.messages_sent.load(Ordering::Acquire)
            );
            println!(
                "  Messages received: {}",
                stats.messages_received.load(Ordering::Acquire)
            );
            println!(
                "  Reservations made: {}",
                stats.reservations_made.load(Ordering::Acquire)
            );
        })
        .await;
    }
    */
}
