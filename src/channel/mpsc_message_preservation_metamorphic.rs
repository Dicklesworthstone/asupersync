//! Metamorphic Testing: MPSC message preservation under send/recv permutation
//!
//! This module implements metamorphic relations (MRs) to verify that MPSC
//! channels preserve all sent messages regardless of the order in which
//! send and receive operations are performed.
//!
//! # Target Metamorphic Relations
//!
//! - **MR1 (Send Order Independence)**: Messages {m1, m2, ..., mN} sent in
//!   any order should all be received exactly once
//! - **MR2 (Interleaved Send/Recv Equivalence)**: Interleaving sends and
//!   receives preserves message count and content
//! - **MR3 (Batch vs Streaming Equivalence)**: Sending N messages as one
//!   batch vs N individual sends produces identical receiver state
//! - **MR4 (Permutation Invariance)**: Permuting send order doesn't affect
//!   the set of received messages (only their order)
//! - **MR5 (Reservation Slot Permutation)**: Re-ordering reserved slots
//!   preserves outcomes for commutative consumers
//! - **MR6 (Deterministic Replay)**: Replaying the same trace under the lab
//!   deterministic seed yields the same output
//! - **MR7 (Decomposition)**: Splitting one logical stream into N MPSC
//!   partitions preserves total message-count and message-set invariants
//!
//! # Property Coverage
//!
//! These MRs ensure that:
//! - No messages are lost during transmission
//! - No messages are duplicated
//! - Message content is preserved exactly
//! - Channel capacity doesn't affect message preservation
//! - Different send/recv patterns are equivalent

use crate::channel::mpsc::{self, RecvError};
use crate::cx::Cx;
use crate::lab::{LabConfig, LabRuntime};
use crate::util::DetRng;
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
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
    let waker = std::task::Waker::noop().clone();
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
struct TestMessage {
    id: u64,
    content: String,
    sequence: u32,
}

impl TestMessage {
    fn new(id: u64, content: impl Into<String>, sequence: u32) -> Self {
        Self {
            id,
            content: content.into(),
            sequence,
        }
    }
}

// ============================================================================
// Metamorphic Relations for MPSC Message Preservation
// ============================================================================

/// **MR1: Send Order Independence (Permutative, Score: 8.3)**
///
/// Property: Messages {m1, m2, ..., mN} sent in any order should all be
/// received exactly once. The set of received messages must equal the set
/// of sent messages regardless of send order.
///
/// **Transformation**: permute(send_order)
/// **Relation**: set(received_messages) = set(sent_messages)
/// **Catches**: Message loss, duplication, content corruption
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

    fn messages_with_seed(message_count: usize, seed: u32) -> Vec<TestMessage> {
        (0..message_count)
            .map(|i| {
                TestMessage::new(
                    i as u64,
                    format!("trace_{seed}_{i}"),
                    seed.wrapping_add(i as u32),
                )
            })
            .collect()
    }

    fn permuted_slot_order(message_count: usize, seed: u64) -> Vec<usize> {
        let mut order: Vec<_> = (0..message_count).collect();
        let mut rng = DetRng::new(seed);
        rng.shuffle(&mut order);
        order
    }

    fn receive_reserved_slots(
        cx: &Cx,
        messages: &[TestMessage],
        slot_order: &[usize],
    ) -> Vec<TestMessage> {
        assert_eq!(
            messages.len(),
            slot_order.len(),
            "slot order must cover each reserved slot"
        );

        if messages.is_empty() {
            return Vec::new();
        }

        let (tx, mut rx) = mpsc::channel(messages.len());
        let mut permits = Vec::with_capacity(messages.len());

        for _ in messages {
            permits.push(Some(block_on(tx.reserve(cx)).unwrap()));
        }

        for &slot in slot_order {
            let permit = permits[slot] // ubs:ignore - test oracle
                .take()
                .expect("slot_order must not repeat a reservation slot");
            permit.send(messages[slot].clone()).unwrap();
        }

        let mut received = Vec::with_capacity(messages.len());
        for _ in messages {
            match block_on(rx.recv(cx)) {
                Ok(message) => received.push(message),
                Err(RecvError::Disconnected | RecvError::Cancelled | RecvError::Empty) => break,
            }
        }

        received
    }

    fn message_set(messages: &[TestMessage]) -> HashSet<TestMessage> {
        messages.iter().cloned().collect()
    }

    #[test]
    fn mr1_send_order_independence() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            capacity in 2usize..10,
            message_count in 3usize..8,
            seed in any::<u64>(),
        )| {
            let cx = test_cx();
            prop_assume!(capacity >= message_count);

            // Generate unique test messages
            let messages: Vec<TestMessage> = (0..message_count)
                .map(|i| TestMessage::new(i as u64, format!("msg_{}", i), i as u32))
                .collect();

            // Test multiple permutations of the same message set
            let mut all_received_sets = Vec::new();

            for permutation_seed in 0..3 {
                let (tx, mut rx) = mpsc::channel(capacity);
                let mut send_order = messages.clone();

                // Permute the send order using deterministic shuffling
                let mut perm_rng = DetRng::new(seed.wrapping_add(permutation_seed));
                perm_rng.shuffle(&mut send_order);

                // Send all messages in permuted order
                for msg in &send_order {
                    block_on(async {
                        let permit = tx.reserve(&cx).await.unwrap();
                        permit.send(msg.clone()).unwrap();
                    });
                }

                // Receive all messages
                let mut received_messages = Vec::new();
                for _ in 0..message_count {
                    match block_on(rx.recv(&cx)) {
                        Ok(msg) => received_messages.push(msg),
                        Err(RecvError::Disconnected | RecvError::Cancelled | RecvError::Empty) => {
                            break;
                        }
                    }
                }

                // Convert to sets for order-independent comparison
                let sent_set: HashSet<_> = messages.iter().cloned().collect();
                let received_set: HashSet<_> = received_messages.iter().cloned().collect();

                // MR1 ASSERTION: Sets must be equal regardless of send order
                prop_assert_eq!(&received_set, &sent_set,
                    "MR1 VIOLATION: Received set differs from sent set for permutation {}.\n\
                     Sent: {:?}\n\
                     Received: {:?}\n\
                     Send order was: {:?}",
                    permutation_seed, sent_set, received_set, send_order);

                // Check for duplicates
                prop_assert_eq!(received_messages.len(), received_set.len(),
                    "MR1 VIOLATION: Duplicate messages detected for permutation {}",
                    permutation_seed);

                // Check that we got exactly the expected count
                prop_assert_eq!(received_messages.len(), message_count,
                    "MR1 VIOLATION: Expected {} messages, got {} for permutation {}",
                    message_count, received_messages.len(), permutation_seed);

                all_received_sets.push(received_set);
            }

            // MR1 META-ASSERTION: All permutations should produce identical received sets
            if all_received_sets.len() > 1 {
                let reference = &all_received_sets[0];
                for (i, received_set) in all_received_sets.iter().enumerate().skip(1) {
                    prop_assert_eq!(received_set, reference,
                        "MR1 VIOLATION: Permutation {} produced different received set than reference",
                        i);
                }
            }
        });
    }

    /// **MR2: Interleaved Send/Recv Equivalence (Equivalence, Score: 7.5)**
    ///
    /// Property: Interleaving sends and receives should preserve message count
    /// and content compared to batch send followed by batch receive.
    ///
    /// **Transformation**: interleave(sends, recvs) vs batch(sends); batch(recvs)
    /// **Relation**: count(received_interleaved) = count(received_batch)
    /// **Catches**: Race conditions, state corruption during interleaving
    #[test]
    fn mr2_interleaved_send_recv_equivalence() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            capacity in 3usize..8,
            message_count in 2usize..6,
            interleave_pattern in any::<u32>(),
        )| {
            let cx = test_cx();
            prop_assume!(capacity >= message_count);

            // Generate test messages
            let messages: Vec<TestMessage> = (0..message_count)
                .map(|i| TestMessage::new(i as u64, format!("data_{}", i), i as u32))
                .collect();

            // Strategy 1: Batch send, then batch receive
            let (tx_batch, mut rx_batch) = mpsc::channel(capacity);

            // Send all messages first
            for msg in &messages {
                block_on(async {
                    let permit = tx_batch.reserve(&cx).await.unwrap();
                    permit.send(msg.clone()).unwrap();
                });
            }

            // Then receive all messages
            let mut batch_received = Vec::new();
            for _ in 0..message_count {
                match block_on(rx_batch.recv(&cx)) {
                    Ok(msg) => batch_received.push(msg),
                    Err(RecvError::Disconnected | RecvError::Cancelled | RecvError::Empty) => {
                        break;
                    }
                }
            }

            // Strategy 2: Interleaved send/receive
            let (tx_interleaved, mut rx_interleaved) = mpsc::channel(capacity);
            let mut interleaved_received = Vec::new();
            let mut sent_count = 0;

            // Use pattern to determine interleaving
            for i in 0..message_count * 2 {
                let should_send = if sent_count < message_count {
                    if interleaved_received.len() >= message_count {
                        true // Must send if we've received everything
                    } else {
                        (interleave_pattern.wrapping_add(i as u32)) % 3 == 0
                    }
                } else {
                    false
                };

                if should_send && sent_count < message_count {
                    // Send next message
                    let msg = &messages[sent_count];
                    block_on(async {
                        let permit = tx_interleaved.reserve(&cx).await.unwrap();
                        permit.send(msg.clone()).unwrap();
                    });
                    sent_count += 1;
                } else if interleaved_received.len() < sent_count {
                    // Try to receive
                    match rx_interleaved.try_recv() {
                        Ok(msg) => interleaved_received.push(msg),
                        Err(_) => {} // No message available yet
                    }
                }
            }

            while sent_count < message_count {
                let msg = &messages[sent_count];
                block_on(async {
                    let permit = tx_interleaved.reserve(&cx).await.unwrap();
                    permit.send(msg.clone()).unwrap();
                });
                sent_count += 1;
            }

            // Receive any remaining messages
            while interleaved_received.len() < sent_count {
                match block_on(rx_interleaved.recv(&cx)) {
                    Ok(msg) => interleaved_received.push(msg),
                    Err(RecvError::Disconnected | RecvError::Cancelled | RecvError::Empty) => {
                        break;
                    }
                }
            }

            // MR2 ASSERTIONS: Both strategies should produce identical results
            prop_assert_eq!(batch_received.len(), interleaved_received.len(),
                "MR2 VIOLATION: Different message counts - batch: {}, interleaved: {}",
                batch_received.len(), interleaved_received.len());

            let batch_set: HashSet<_> = batch_received.iter().cloned().collect();
            let interleaved_set: HashSet<_> = interleaved_received.iter().cloned().collect();

            prop_assert_eq!(batch_set, interleaved_set,
                "MR2 VIOLATION: Different message sets between batch and interleaved strategies");

            prop_assert_eq!(batch_received.len(), message_count,
                "MR2 VIOLATION: Batch strategy didn't receive all messages");
            prop_assert_eq!(interleaved_received.len(), message_count,
                "MR2 VIOLATION: Interleaved strategy didn't receive all messages");
        });
    }

    /// **MR3: Batch vs Streaming Equivalence (Additive, Score: 7.0)**
    ///
    /// Property: Sending N messages as one batch operation vs N individual
    /// send operations should produce identical receiver state.
    ///
    /// **Transformation**: batch(messages) vs stream(messages)
    /// **Relation**: recv_state(batch) = recv_state(stream)
    /// **Catches**: Batch operation bugs, streaming consistency issues
    #[test]
    fn mr3_batch_vs_streaming_equivalence() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            capacity in 4usize..10,
            message_count in 2usize..7,
            content_seed in any::<u32>(),
        )| {
            let cx = test_cx();
            prop_assume!(capacity >= message_count);

            // Generate test messages with deterministic content
            let messages: Vec<TestMessage> = (0..message_count)
                .map(|i| {
                    let content = format!("msg_{}_{}", i, content_seed.wrapping_add(i as u32));
                    TestMessage::new(i as u64, content, i as u32)
                })
                .collect();

            // Strategy 1: Individual streaming sends
            let (tx_stream, mut rx_stream) = mpsc::channel(capacity);
            for msg in &messages {
                block_on(async {
                    let permit = tx_stream.reserve(&cx).await.unwrap();
                    permit.send(msg.clone()).unwrap();
                });
            }

            let mut streaming_received = Vec::new();
            for _ in 0..message_count {
                match block_on(rx_stream.recv(&cx)) {
                    Ok(msg) => streaming_received.push(msg),
                    Err(RecvError::Disconnected | RecvError::Cancelled | RecvError::Empty) => {
                        break;
                    }
                }            }

            // Strategy 2: Simulated batch operation (rapid succession with no yields)
            let (tx_batch, mut rx_batch) = mpsc::channel(capacity);

            // Send all messages without yielding (simulates batch behavior)
            let batch_send_result = block_on(async {
                let mut permits = Vec::new();

                // Reserve all permits first
                for _ in 0..message_count {
                    match tx_batch.reserve(&cx).await {
                        Ok(permit) => permits.push(permit),
                        Err(e) => return Err(format!("Reserve failed: {:?}", e)),
                    }
                }

                // Then send all messages atomically
                for (permit, msg) in permits.into_iter().zip(&messages) {
                    permit.send(msg.clone()).unwrap();
                }

                Ok(())
            });

            prop_assert!(batch_send_result.is_ok(),
                "MR3 VIOLATION: Batch send operation failed: {:?}", batch_send_result);

            let mut batch_received = Vec::new();
            for _ in 0..message_count {
                match block_on(rx_batch.recv(&cx)) {
                    Ok(msg) => batch_received.push(msg),
                    Err(RecvError::Disconnected | RecvError::Cancelled | RecvError::Empty) => {
                        break;
                    }
                }
            }

            // MR3 ASSERTIONS: Both strategies should be equivalent
            prop_assert_eq!(streaming_received.len(), batch_received.len(),
                "MR3 VIOLATION: Different message counts - streaming: {}, batch: {}",
                streaming_received.len(), batch_received.len());

            // Convert to sets for order-independent comparison
            let streaming_set: HashSet<_> = streaming_received.iter().cloned().collect();
            let batch_set: HashSet<_> = batch_received.iter().cloned().collect();

            prop_assert_eq!(&streaming_set, &batch_set,
                "MR3 VIOLATION: Different message sets between streaming and batch");

            // Verify completeness
            let sent_set: HashSet<_> = messages.iter().cloned().collect();
            prop_assert_eq!(&streaming_set, &sent_set,
                "MR3 VIOLATION: Streaming didn't preserve all messages");
            prop_assert_eq!(&batch_set, &sent_set,
                "MR3 VIOLATION: Batch didn't preserve all messages");
        });
    }

    /// **MR4: Capacity Independence (Invariance, Score: 6.5)**
    ///
    /// Property: For the same set of messages, different channel capacities
    /// should not affect the final set of received messages (only timing).
    ///
    /// **Transformation**: vary(capacity)
    /// **Relation**: set(received_messages) invariant across capacities
    /// **Catches**: Capacity-dependent message loss, buffer overflow bugs
    #[test]
    fn mr4_capacity_independence() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            message_count in 2usize..6,
            content_prefix in "[a-z]{2,5}",
        )| {
            let cx = test_cx();

            // Generate test messages
            let messages: Vec<TestMessage> = (0..message_count)
                .map(|i| TestMessage::new(i as u64, format!("{}_{}", content_prefix, i), i as u32))
                .collect();

            let mut results_by_capacity = HashMap::new();

            // Test with different capacities that can hold the batch without a
            // concurrent receiver in this single-threaded harness.
            for capacity in [message_count, message_count + 1, message_count + 2] {
                let (tx, mut rx) = mpsc::channel(capacity);

                // Send all messages
                for msg in &messages {
                    block_on(async {
                        let permit = tx.reserve(&cx).await.unwrap();
                        permit.send(msg.clone()).unwrap();
                    });
                }

                // Receive all messages
                let mut received = Vec::new();
                for _ in 0..message_count {
                    match block_on(rx.recv(&cx)) {
                        Ok(msg) => received.push(msg),
                        Err(RecvError::Disconnected | RecvError::Cancelled | RecvError::Empty) => {
                            break;
                        }
                    }
                }

                let received_set: HashSet<_> = received.iter().cloned().collect();
                results_by_capacity.insert(capacity, received_set);
            }

            // MR4 ASSERTIONS: All capacities should produce the same received set
            if results_by_capacity.len() > 1 {
                let sent_set: HashSet<_> = messages.iter().cloned().collect();
                let mut reference_set: Option<&HashSet<TestMessage>> = None;

                for (capacity, received_set) in &results_by_capacity {
                    // Each capacity should receive all messages
                    prop_assert_eq!(received_set, &sent_set,
                        "MR4 VIOLATION: Capacity {} didn't receive all messages", capacity);

                    // All capacities should produce identical results
                    match reference_set {
                        None => reference_set = Some(received_set),
                        Some(reference) => {
                            prop_assert_eq!(received_set, reference,
                                "MR4 VIOLATION: Capacity {} produced different results than reference",
                                capacity);
                        }
                    }
                }
            }
        });
    }

    /// **MR5: Reservation Slot Permutation (Permutative, Score: 8.3)**
    ///
    /// Property: If all slots are reserved before any send commits, then
    /// re-ordering the reserved slot commit order must preserve the received
    /// multiset for commutative consumers.
    ///
    /// **Transformation**: reserve_all(slots); permute(commit_slots)
    /// **Relation**: set(received_original) = set(received_permuted)
    /// **Catches**: reserved-slot leaks, duplicated commits, slot/message loss
    #[test]
    fn mr5_reservation_slot_permutation_preserves_commutative_outcome() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            message_count in 2usize..8,
            seed in any::<u64>(),
            content_seed in any::<u32>(),
        )| {
            let cx = test_cx();
            let messages = messages_with_seed(message_count, content_seed);
            let original_order: Vec<_> = (0..message_count).collect();
            let permuted_order = permuted_slot_order(message_count, seed);

            let original_received = receive_reserved_slots(&cx, &messages, &original_order);
            let permuted_received = receive_reserved_slots(&cx, &messages, &permuted_order);

            prop_assert_eq!(original_received.len(), message_count,
                "MR5 VIOLATION: original reservation order lost messages");
            prop_assert_eq!(permuted_received.len(), message_count,
                "MR5 VIOLATION: permuted reservation order lost messages");
            prop_assert_eq!(message_set(&original_received), message_set(&permuted_received),
                "MR5 VIOLATION: reordering reservation slots changed the commutative outcome");
        });
    }

    /// **MR6: Deterministic Replay (Equivalence, Score: 8.0)**
    ///
    /// Property: The same deterministic lab seed and same reserved-slot trace
    /// must produce the same received sequence on replay.
    ///
    /// **Transformation**: replay(trace, seed)
    /// **Relation**: received_run_1 = received_run_2
    /// **Catches**: nondeterministic channel state, unstable reservation replay
    #[test]
    fn mr6_replaying_same_trace_under_deterministic_mode_yields_same_output() {
        proptest!(|(
            message_count in 2usize..8,
            seed in any::<u64>(),
            content_seed in any::<u32>(),
        )| {
            fn run_trace(
                message_count: usize,
                seed: u64,
                content_seed: u32,
            ) -> Vec<TestMessage> {
                let _runtime = LabRuntime::new(LabConfig::new(seed));
                let cx = test_cx();
                let messages = messages_with_seed(message_count, content_seed);
                let trace = permuted_slot_order(message_count, seed);

                receive_reserved_slots(&cx, &messages, &trace)
            }

            let first = run_trace(message_count, seed, content_seed);
            let second = run_trace(message_count, seed, content_seed);

            prop_assert_eq!(first, second,
                "MR6 VIOLATION: deterministic replay of the same reservation trace changed output");
        });
    }

    /// **MR7: Decomposition (Additive, Score: 6.7)**
    ///
    /// Property: Splitting one logical MPSC stream into N independent MPSC
    /// partitions preserves total message count and the aggregate message set.
    ///
    /// **Transformation**: split(stream, N); send_each_partition()
    /// **Relation**: sum(count(partition_outputs)) = count(single_stream_output)
    /// **Catches**: partition fan-out loss, duplicate delivery, aggregation gaps
    #[test]
    fn mr7_decomposition_into_partitions_preserves_total_count() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            message_count in 2usize..10,
            partition_count in 1usize..5,
            seed in any::<u64>(),
            content_seed in any::<u32>(),
        )| {
            let cx = test_cx();
            let partition_count = partition_count.min(message_count);
            let messages = messages_with_seed(message_count, content_seed);
            let baseline_order = permuted_slot_order(message_count, seed);
            let baseline = receive_reserved_slots(&cx, &messages, &baseline_order);
            let baseline_set = message_set(&baseline);

            let mut decomposed = Vec::new();
            for partition in 0..partition_count {
                let partition_messages: Vec<_> = messages
                    .iter()
                    .enumerate()
                    .filter(|(idx, _)| idx % partition_count == partition)
                    .map(|(_, message)| message.clone())
                    .collect();

                if partition_messages.is_empty() {
                    continue;
                }

                let partition_seed = seed.wrapping_add(partition as u64);
                let partition_order =
                    permuted_slot_order(partition_messages.len(), partition_seed);
                let mut received =
                    receive_reserved_slots(&cx, &partition_messages, &partition_order);

                decomposed.append(&mut received);
            }

            prop_assert_eq!(baseline.len(), message_count,
                "MR7 VIOLATION: baseline stream did not receive all messages");
            prop_assert_eq!(decomposed.len(), baseline.len(),
                "MR7 VIOLATION: partitioned stream changed total message count");
            prop_assert_eq!(message_set(&decomposed), baseline_set,
                "MR7 VIOLATION: partitioned stream changed the aggregate message set");
        });
    }

    /// **Composite MR: Full Preservation Under All Transformations**
    ///
    /// Combines MR1-MR4: permute send order + interleave with receives +
    /// vary capacity. All should preserve the complete message set.
    #[test]
    fn mr_composite_full_preservation() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));

        // Deterministic test case for full verification
        let messages = vec![
            TestMessage::new(1, "alpha", 1),
            TestMessage::new(2, "beta", 2),
            TestMessage::new(3, "gamma", 3),
        ];
        let sent_set: HashSet<_> = messages.iter().cloned().collect();

        let cx = test_cx();
        let (tx, mut rx) = mpsc::channel(2); // Small capacity to force blocking

        // Send in reverse order with interleaved receives
        block_on(async {
            // Send gamma
            let permit1 = tx.reserve(&cx).await.unwrap();
            permit1.send(messages[2].clone()).unwrap();

            // Receive gamma
            let received1 = rx.recv(&cx).await.unwrap();
            assert_eq!(received1, messages[2]);

            // Send beta and alpha
            let permit2 = tx.reserve(&cx).await.unwrap();
            permit2.send(messages[1].clone()).unwrap();

            let permit3 = tx.reserve(&cx).await.unwrap();
            permit3.send(messages[0].clone()).unwrap();

            // Receive remaining
            let received2 = rx.recv(&cx).await.unwrap();
            let received3 = rx.recv(&cx).await.unwrap();

            // Check that all messages were received exactly once
            let final_set: HashSet<_> = [received1, received2, received3].iter().cloned().collect();
            assert_eq!(
                final_set, sent_set,
                "Composite MR violated: not all messages preserved"
            );
        });
    }
}

// ============================================================================
// Validation Tests
// ============================================================================

#[cfg(test)]
mod validation_tests {
    use super::*;

    /// Validate that the test infrastructure correctly handles message sets
    #[test]
    fn validate_message_set_infrastructure() {
        let messages = vec![
            TestMessage::new(1, "test1", 1),
            TestMessage::new(2, "test2", 2),
        ];

        let set1: HashSet<_> = messages.iter().cloned().collect();
        let set2: HashSet<_> = messages.iter().cloned().collect();

        assert_eq!(
            set1, set2,
            "Infrastructure: identical message sets should be equal"
        );
        assert_eq!(
            set1.len(),
            2,
            "Infrastructure: should have 2 unique messages"
        );
    }

    /// Validate that permutation actually changes order
    #[test]
    fn validate_permutation_infrastructure() {
        let mut messages = vec![
            TestMessage::new(1, "a", 1),
            TestMessage::new(2, "b", 2),
            TestMessage::new(3, "c", 3),
        ];

        let original = messages.clone();

        // Manual permutation
        messages.swap(0, 2); // Should change order

        assert_ne!(
            messages, original,
            "Infrastructure: permutation should change order"
        );

        let original_set: HashSet<_> = original.iter().cloned().collect();
        let permuted_set: HashSet<_> = messages.iter().cloned().collect();

        assert_eq!(
            original_set, permuted_set,
            "Infrastructure: sets should be equal despite permutation"
        );
    }
}
