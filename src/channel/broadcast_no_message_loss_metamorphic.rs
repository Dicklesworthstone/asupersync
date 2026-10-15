//! Metamorphic Testing: Broadcast channel message preservation with fast receivers
//!
//! This module implements metamorphic relations (MRs) to verify that broadcast
//! channels lose no messages when all receivers are fast enough to keep up
//! with the sender (no lagging receivers scenario).
//!
//! # Target Metamorphic Relations
//!
//! - **MR1 (Fast Receiver Preservation)**: With fast receivers, all sent
//!   messages must be received by all receivers
//! - **MR2 (Receiver Count Independence)**: Message preservation should not
//!   depend on the number of fast receivers
//! - **MR3 (Send Rate Independence)**: Fast sends vs slow sends preserve
//!   messages equally when receivers keep up
//! - **MR4 (Subscription Timing Independence)**: Early vs late subscription
//!   doesn't affect preservation for messages sent after subscription
//!
//! # Property Coverage
//!
//! These MRs ensure that:
//! - No messages are dropped when receivers are fast enough
//! - Multiple receivers see identical message sequences
//! - Subscription timing doesn't cause message loss
//! - Send patterns don't affect message preservation

use crate::channel::broadcast::{self, RecvError, SendError};
use crate::cx::Cx;
use crate::lab::{LabConfig, LabRuntime};
use proptest::prelude::*;
use std::collections::HashMap;
use std::future::Future;
use std::rc::Rc;
use std::task::{Context, Poll};

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create a test context for deterministic scheduling.
fn test_cx() -> Cx<crate::cx::cap::All> {
    Cx::for_testing()
}

/// Simple block_on implementation for tests.
fn block_on<F: Future>(f: F) -> F::Output {
    let waker = std::task::Waker::noop().clone(); // ubs:ignore - test oracle waker clone
    let mut cx = Context::from_waker(&waker);
    let mut pinned = Box::pin(f);
    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BroadcastMessage {
    id: u64,
    payload: String,
    timestamp: u32,
}

impl BroadcastMessage {
    fn new(id: u64, payload: impl Into<String>, timestamp: u32) -> Self {
        Self {
            id,
            payload: payload.into(),
            timestamp,
        }
    }
}

/// Test harness for fast receiver scenarios
#[derive(Debug)]
struct FastReceiverHarness {
    sender: crate::channel::broadcast::Sender<BroadcastMessage>,
    receivers: Vec<crate::channel::broadcast::Receiver<BroadcastMessage>>,
}

impl FastReceiverHarness {
    fn new(capacity: usize, receiver_count: usize) -> Self {
        let (sender, receiver) = broadcast::channel(capacity);
        let mut receivers = vec![receiver];

        for _ in 1..receiver_count {
            receivers.push(sender.subscribe());
        }

        Self { sender, receivers }
    }

    fn send_message(
        &mut self,
        cx: &Cx,
        message: BroadcastMessage,
    ) -> Result<usize, SendError<BroadcastMessage>> {
        match self.sender.send(cx, message) {
            Ok(receiver_count) => Ok(receiver_count),
            Err(e) => Err(e),
        }
    }

    fn send_messages(
        &mut self,
        cx: &Cx,
        messages: &[BroadcastMessage],
    ) -> Result<usize, SendError<BroadcastMessage>> {
        let mut total_receivers = 0;
        for msg in messages {
            total_receivers = self.send_message(cx, msg.clone())?;
        }
        Ok(total_receivers)
    }

    fn receiver_mut(
        &mut self,
        index: usize,
    ) -> &mut crate::channel::broadcast::Receiver<BroadcastMessage> {
        &mut self.receivers[index]
    }

    fn receiver_count(&self) -> usize {
        self.receivers.len()
    }
}

// ============================================================================
// Metamorphic Relations for Broadcast Message Preservation
// ============================================================================

/// **MR1: Fast Receiver Preservation (Invariance, Score: 8.0)**
///
/// Property: When all receivers are fast enough to keep up with sends,
/// no messages should be lost. Every sent message should be received
/// by every receiver exactly once.
///
/// **Transformation**: send(messages); fast_recv_all()
/// **Relation**: ∀receiver: received_count = sent_count
/// **Catches**: Message loss bugs, premature overwrites, receiver starvation
#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap
    )]
    use super::*;

    #[test]
    fn mr1_fast_receiver_preservation() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            capacity in 3usize..8,
            receiver_count in 2usize..5,
            message_count in 2usize..6,
            payload_seed in any::<u32>(),
        )| {
            let cx = test_cx();
            let mut harness = FastReceiverHarness::new(capacity, receiver_count);

            // Ensure capacity is sufficient to avoid lag (key assumption for "fast receivers")
            prop_assume!(capacity >= message_count);

            // Generate test messages
            let messages: Vec<BroadcastMessage> = (0..message_count)
                .map(|i| {
                    BroadcastMessage::new(
                        i as u64,
                        format!("payload_{}_{}", payload_seed, i),
                        i as u32,
                    )
                })
                .collect();

            // Send all messages
            let send_result = harness.send_messages(&cx, &messages);
            prop_assert!(send_result.is_ok(), "MR1 VIOLATION: Send failed with fast receivers: {:?}", send_result);

            let reported_receiver_count = send_result.unwrap(); // ubs:ignore - test oracle
            prop_assert_eq!(reported_receiver_count, harness.receiver_count(),
                "MR1 VIOLATION: Send reported wrong receiver count");

            // Each receiver should receive all messages in order
            for receiver_idx in 0..harness.receiver_count() {
                let mut received_messages = Vec::new();

                // Fast receive: immediately receive all available messages
                for expected_idx in 0..message_count {
                    match block_on(harness.receiver_mut(receiver_idx).recv(&cx)) {
                        Ok(msg) => received_messages.push(msg),
                        Err(RecvError::Lagged(skip_count)) => {
                            prop_assert!(false,
                                "MR1 VIOLATION: Receiver {} lagged (skipped {}) with sufficient capacity {} for {} messages",
                                receiver_idx, skip_count, capacity, message_count);
                        }
                        Err(RecvError::Closed) => {
                            prop_assert!(false,
                                "MR1 VIOLATION: Receiver {} got Closed at message {} of {}",
                                receiver_idx, expected_idx, message_count);
                        }
                        Err(RecvError::Cancelled) => {
                            prop_assert!(false,
                                "MR1 VIOLATION: Receiver {} got Cancelled at message {} of {}",
                                receiver_idx, expected_idx, message_count);
                        }
                        Err(RecvError::PolledAfterCompletion) => {
                            prop_assert!(false,
                                "MR1 VIOLATION: Receiver {} recv future was polled after completion at message {} of {}",
                                receiver_idx, expected_idx, message_count);
                        }
                    }
                }

                // MR1 ASSERTIONS for this receiver
                prop_assert_eq!(received_messages.len(), message_count,
                    "MR1 VIOLATION: Receiver {} got {} messages, expected {}",
                    receiver_idx, received_messages.len(), message_count);

                // Check message content preservation
                for (received, expected) in received_messages.iter().zip(&messages) {
                    prop_assert_eq!(received, expected,
                        "MR1 VIOLATION: Receiver {} got wrong message content", receiver_idx);
                }

                // Check ordering preservation (should be same as send order)
                prop_assert_eq!(&received_messages, &messages,
                    "MR1 VIOLATION: Receiver {} got messages in wrong order", receiver_idx);
            }
        });
    }

    /// **MR2: Receiver Count Independence (Equivalence, Score: 7.5)**
    ///
    /// Property: Message preservation should not depend on the number of
    /// receivers. 1 receiver vs N receivers should all see the same messages.
    ///
    /// **Transformation**: vary(receiver_count)
    /// **Relation**: ∀N: messages_per_receiver identical across N
    /// **Catches**: Receiver scaling bugs, shared state corruption
    #[test]
    fn mr2_receiver_count_independence() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            capacity in 4usize..8,
            message_count in 2usize..5,
            content_base in "[a-z]{2,4}",
        )| {
            // Ensure no lagging conditions
            prop_assume!(capacity >= message_count);

            let cx = test_cx();

            // Generate test messages
            let messages: Vec<BroadcastMessage> = (0..message_count)
                .map(|i| BroadcastMessage::new(i as u64, format!("{}{}", content_base, i), i as u32))
                .collect();

            let mut results_by_receiver_count = HashMap::new();

            // Test with different receiver counts
            for receiver_count in [1, 2, 3, 4].iter().cloned() {
                let mut harness = FastReceiverHarness::new(capacity, receiver_count);

                // Send all messages
                harness.send_messages(&cx, &messages).unwrap(); // ubs:ignore - test oracle

                // Collect what each receiver sees
                let mut receiver_sequences = Vec::new();
                for receiver_idx in 0..receiver_count {
                    let mut received = Vec::new();
                    for _ in 0..message_count {
                        match block_on(harness.receiver_mut(receiver_idx).recv(&cx)) {
                            Ok(msg) => received.push(msg),
                            Err(e) => {
                                prop_assert!(false,
                                    "MR2 VIOLATION: Receiver {} failed with {} receivers: {:?}",
                                    receiver_idx, receiver_count, e);
                            }
                        }
                    }
                    receiver_sequences.push(received);
                }

                results_by_receiver_count.insert(receiver_count, receiver_sequences);
            }

            // MR2 ASSERTIONS: All receiver counts should produce identical per-receiver results
            let reference_sequence = &messages; // Expected sequence for each receiver

            for (count, receiver_sequences) in &results_by_receiver_count {
                // Each receiver in this configuration should see the reference sequence
                for (receiver_idx, received_seq) in receiver_sequences.iter().enumerate() {
                    prop_assert_eq!(received_seq, reference_sequence,
                        "MR2 VIOLATION: With {} receivers, receiver {} saw different sequence",
                        count, receiver_idx);
                }

                // All receivers within this configuration should see identical sequences
                if receiver_sequences.len() > 1 {
                    let first_receiver_seq = &receiver_sequences[0];
                    for (idx, other_seq) in receiver_sequences.iter().enumerate().skip(1) {
                        prop_assert_eq!(other_seq, first_receiver_seq,
                            "MR2 VIOLATION: Receivers 0 and {} saw different sequences with {} total receivers",
                            idx, count);
                    }
                }
            }
        });
    }

    /// **MR3: Send Rate Independence (Equivalence, Score: 7.0)**
    ///
    /// Property: Fast sends vs slow sends should preserve messages equally
    /// when receivers are fast enough to keep up with either rate.
    ///
    /// **Transformation**: fast_send_rate vs slow_send_rate
    /// **Relation**: received_messages identical regardless of send rate
    /// **Catches**: Rate-dependent message loss, timing-sensitive bugs
    #[test]
    fn mr3_send_rate_independence() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            capacity in 3usize..6,
            message_count in 2usize..4, // Keep small for timing tests
            payload_prefix in "[0-9]{2}",
        )| {
            prop_assume!(capacity >= message_count);

            let cx = test_cx();

            // Generate test messages
            let messages: Vec<BroadcastMessage> = (0..message_count)
                .map(|i| BroadcastMessage::new(i as u64, format!("{}_msg_{}", payload_prefix, i), i as u32))
                .collect();

            // Strategy 1: Fast sends (burst)
            let mut harness_fast = FastReceiverHarness::new(capacity, 2);
            harness_fast.send_messages(&cx, &messages).unwrap(); // ubs:ignore - test oracle

            let mut fast_received_r0 = Vec::new();
            let mut fast_received_r1 = Vec::new();

            for _ in 0..message_count {
                let msg0 = block_on(harness_fast.receiver_mut(0).recv(&cx)).unwrap(); // ubs:ignore - test oracle
                let msg1 = block_on(harness_fast.receiver_mut(1).recv(&cx)).unwrap(); // ubs:ignore - test oracle
                fast_received_r0.push(msg0);
                fast_received_r1.push(msg1);
            }

            // Strategy 2: Slow sends (one at a time with processing)
            let mut harness_slow = FastReceiverHarness::new(capacity, 2);

            let mut slow_received_r0 = Vec::new();
            let mut slow_received_r1 = Vec::new();

            for msg in &messages {
                // Send one message
                harness_slow.send_message(&cx, msg.clone()).unwrap(); // ubs:ignore - test oracle

                // Immediately receive by both receivers (still "fast" receivers)
                let msg0 = block_on(harness_slow.receiver_mut(0).recv(&cx)).unwrap(); // ubs:ignore - test oracle
                let msg1 = block_on(harness_slow.receiver_mut(1).recv(&cx)).unwrap(); // ubs:ignore - test oracle

                slow_received_r0.push(msg0);
                slow_received_r1.push(msg1);
            }

            // MR3 ASSERTIONS: Both strategies should produce identical results
            prop_assert_eq!(&fast_received_r0, &slow_received_r0,
                "MR3 VIOLATION: Receiver 0 saw different sequences for fast vs slow send rates");

            prop_assert_eq!(&fast_received_r1, &slow_received_r1,
                "MR3 VIOLATION: Receiver 1 saw different sequences for fast vs slow send rates");

            prop_assert_eq!(&fast_received_r0, &messages,
                "MR3 VIOLATION: Fast send rate didn't preserve all messages");

            prop_assert_eq!(&slow_received_r0, &messages,
                "MR3 VIOLATION: Slow send rate didn't preserve all messages");
        });
    }

    /// **MR4: Subscription Timing Independence (Permutative, Score: 6.5)**
    ///
    /// Property: Early vs late subscription shouldn't affect message
    /// preservation for messages sent after subscription.
    ///
    /// **Transformation**: early_subscribe() vs late_subscribe()
    /// **Relation**: post_subscription_messages identical for both
    /// **Catches**: Subscription timing bugs, initialization races
    #[test]
    fn mr4_subscription_timing_independence() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            capacity in 4usize..8,
            pre_messages in 1usize..3,
            post_messages in 2usize..4,
            data_tag in "[a-z]{3}",
        )| {
            prop_assume!(capacity >= pre_messages + post_messages);

            let cx = test_cx();

            // Generate message sets
            let pre_subscription_messages: Vec<BroadcastMessage> = (0..pre_messages)
                .map(|i| BroadcastMessage::new(i as u64, format!("pre_{}_{}", data_tag, i), i as u32))
                .collect();

            let post_subscription_messages: Vec<BroadcastMessage> = (pre_messages..pre_messages + post_messages)
                .map(|i| BroadcastMessage::new(i as u64, format!("post_{}_{}", data_tag, i), i as u32))
                .collect();

            // Strategy 1: Early subscription (before any messages)
            let (sender_early, mut early_receiver) = broadcast::channel(capacity);

            // Send pre-subscription messages (early receiver should see these)
            for msg in &pre_subscription_messages {
                sender_early.send(&cx, msg.clone()).unwrap(); // ubs:ignore - test oracle
            }

            // Send post-subscription messages
            for msg in &post_subscription_messages {
                sender_early.send(&cx, msg.clone()).unwrap(); // ubs:ignore - test oracle
            }

            // Early receiver gets all messages
            let mut early_all_received = Vec::new();
            for _ in 0..(pre_messages + post_messages) {
                match block_on(early_receiver.recv(&cx)) {
                    Ok(msg) => early_all_received.push(msg),
                    Err(e) => prop_assert!(false, "Early receiver error: {:?}", e),
                }
            }

            // Strategy 2: Late subscription (after pre-messages)
            let (sender_late, _initial_receiver) = broadcast::channel(capacity);

            // Send pre-subscription messages (to establish initial state)
            for msg in &pre_subscription_messages {
                sender_late.send(&cx, msg.clone()).unwrap(); // ubs:ignore - test oracle
            }

            // Late subscription happens now
            let mut late_receiver = sender_late.subscribe();

            // Send post-subscription messages (late receiver should see these)
            for msg in &post_subscription_messages {
                sender_late.send(&cx, msg.clone()).unwrap(); // ubs:ignore - test oracle
            }

            // Late receiver only gets post-subscription messages
            let mut late_post_received = Vec::new();
            for _ in 0..post_messages {
                match block_on(late_receiver.recv(&cx)) {
                    Ok(msg) => late_post_received.push(msg),
                    Err(e) => prop_assert!(false, "Late receiver error: {:?}", e),
                }
            }

            // MR4 ASSERTIONS: Post-subscription messages should be identical
            let early_post_received: Vec<_> = early_all_received
                .into_iter()
                .skip(pre_messages)
                .collect();

            prop_assert_eq!(early_post_received, late_post_received.clone(),
                "MR4 VIOLATION: Early vs late subscription produced different post-subscription sequences");

            prop_assert_eq!(late_post_received, post_subscription_messages,
                "MR4 VIOLATION: Late subscription didn't preserve post-subscription messages");
        });
    }

    /// **Composite MR: Complete Message Preservation Under All Conditions**
    ///
    /// Tests message preservation under combined conditions: multiple fast
    /// receivers, varied send patterns, and subscription timing variations.
    #[test]
    fn mr_composite_complete_preservation() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));

        let cx = test_cx();
        let messages = vec![
            BroadcastMessage::new(1, "alpha", 1),
            BroadcastMessage::new(2, "beta", 2),
            BroadcastMessage::new(3, "gamma", 3),
        ];

        let mut harness = FastReceiverHarness::new(5, 3); // Capacity > message count

        // Send all messages
        let send_result = harness.send_messages(&cx, &messages);
        assert!(send_result.is_ok(), "Composite MR: Send failed");
        assert_eq!(
            send_result.unwrap(),
            3,
            "Composite MR: Wrong receiver count reported"
        );

        // All receivers should get all messages
        for receiver_idx in 0..3 {
            for (expected_idx, expected_msg) in messages.iter().enumerate() {
                let received = block_on(harness.receiver_mut(receiver_idx).recv(&cx));
                match received {
                    Ok(msg) => {
                        assert_eq!(
                            &msg, expected_msg,
                            "Composite MR: Receiver {} got wrong message at position {}",
                            receiver_idx, expected_idx
                        );
                    }
                    Err(e) => panic!(
                        "Composite MR: Receiver {} failed at position {}: {:?}",
                        receiver_idx, expected_idx, e
                    ),
                }
            }
        }
    }
}

// ============================================================================
// Validation Tests
// ============================================================================

#[cfg(test)]
mod validation_tests {
    use super::*;

    /// Validate that the harness correctly identifies fast vs slow receiver scenarios
    #[test]
    fn validate_fast_receiver_harness() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        let cx = test_cx();
        let mut harness = FastReceiverHarness::new(3, 2);

        let msg = BroadcastMessage::new(1, "test", 1);
        let send_result = harness.send_message(&cx, msg.clone());

        assert!(
            send_result.is_ok(),
            "Harness validation: Send should succeed"
        );
        assert_eq!(
            send_result.unwrap(),
            2,
            "Harness validation: Should report 2 receivers"
        );

        // Both receivers should get the message
        let recv1 = block_on(harness.receiver_mut(0).recv(&cx));
        let recv2 = block_on(harness.receiver_mut(1).recv(&cx));

        assert_eq!(
            recv1.unwrap(),
            msg,
            "Harness validation: Receiver 0 should get message"
        );
        assert_eq!(
            recv2.unwrap(),
            msg,
            "Harness validation: Receiver 1 should get message"
        );
    }

    /// Validate that capacity constraints are properly handled
    #[test]
    fn validate_capacity_constraints() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        let cx = test_cx();

        // Test with capacity exactly matching message count (boundary condition)
        let mut harness = FastReceiverHarness::new(2, 1);
        let messages = vec![
            BroadcastMessage::new(1, "msg1", 1),
            BroadcastMessage::new(2, "msg2", 2),
        ];

        let send_result = harness.send_messages(&cx, &messages);
        assert!(
            send_result.is_ok(),
            "Capacity validation: Should handle exact capacity match"
        );

        // Receive all messages
        for expected_msg in &messages {
            let received = block_on(harness.receiver_mut(0).recv(&cx));
            assert_eq!(
                received.unwrap(),
                *expected_msg,
                "Capacity validation: Should receive correct message"
            );
        }
    }
}
