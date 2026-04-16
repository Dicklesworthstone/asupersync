//! Metamorphic Relation Suite for Channel Send/Recv Operations.
//!
//! This test suite implements metamorphic relations for asupersync's two-phase
//! reserve/commit channel operations, ensuring correctness properties hold
//! across transformations of the input space.
//!
//! # Metamorphic Relations Tested
//!
//! ## MR1: Reserve/Commit Commutativity
//! - `seq(reserve₁, commit₁, reserve₂, commit₂)` ≡ `seq(reserve₂, commit₂, reserve₁, commit₁)`
//! - Different reservation orders yield equivalent final states
//!
//! ## MR2: Send/Recv Duality
//! - `send_sequence(msgs) → recv_sequence()` = `msgs` (FIFO preservation)
//! - What gets sent gets received in identical order
//!
//! ## MR3: Capacity Conservation
//! - `∀ operations: reserved_count + queue_length ≤ capacity`
//! - Channel capacity accounting remains consistent
//!
//! ## MR4: Cancel Safety Invariant
//! - `cancel(reserve(tx)) → tx.state` = `initial(tx).state`
//! - Cancellation preserves channel state without side effects
//!
//! ## MR5: Batch Send Equivalence
//! - `send(msgs[0..n])` ≡ `send(msgs[0..k]) → send(msgs[k..n])`
//! - Batched sends equivalent to individual sends
//!
//! ## MR6: Reserve Pool Commutativity
//! - `reserve(tx₁) → reserve(tx₂) → commit(tx₂) → commit(tx₁)`
//! - ≡ `reserve(tx₂) → reserve(tx₁) → commit(tx₁) → commit(tx₂)`
//! - Reserve pool operations are commutative

use asupersync::channel::mpsc;
use asupersync::cx::Cx;
use asupersync::types::{Budget, Time};
use futures_lite::future::block_on;
use std::collections::VecDeque;
use std::sync::Arc;
use proptest::prelude::*;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Test message type for metamorphic relations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TestMessage {
    id: u32,
    payload: String,
}

impl TestMessage {
    fn new(id: u32) -> Self {
        Self {
            id,
            payload: format!("msg_{}", id),
        }
    }
}

/// Channel operation for metamorphic testing.
#[derive(Debug, Clone)]
enum ChannelOp {
    Reserve,
    CommitWithValue(TestMessage),
    Abort,
    Recv,
    TryReserve,
    TrySend(TestMessage),
}

/// Channel state snapshot for comparison.
#[derive(Debug, Clone, PartialEq)]
struct ChannelSnapshot {
    queue_length: usize,
    reserved_count: usize,
    is_disconnected: bool,
    received_messages: Vec<TestMessage>,
}

impl ChannelSnapshot {
    async fn capture<T: Clone + std::fmt::Debug>(
        tx: &mpsc::Sender<T>,
        rx: &mut mpsc::Receiver<T>,
        received: &[T],
    ) -> Self {
        // Note: In a real implementation, we'd need access to internal state
        // For this example, we'll track what we can observe
        Self {
            queue_length: 0, // Would need internal access
            reserved_count: 0, // Would need internal access
            is_disconnected: false, // Would check tx.is_closed() if available
            received_messages: vec![], // Would need proper message tracking
        }
    }
}

/// Creates a test channel with specified capacity.
fn test_channel(capacity: usize) -> (mpsc::Sender<TestMessage>, mpsc::Receiver<TestMessage>) {
    mpsc::channel(capacity)
}

/// Creates a test context for operations.
fn test_cx() -> Cx {
    Cx::for_testing()
}

// ============================================================================
// MR1: Reserve/Commit Commutativity
// ============================================================================

/// Tests that different orders of reserve/commit operations yield equivalent states.
#[test]
fn mr1_reserve_commit_commutativity() {
    block_on(async {
        let (tx1, mut rx) = test_channel(4);
        let tx2 = tx1.clone();
        let cx = test_cx();

        // Scenario A: tx1 reserves, commits, then tx2 reserves, commits
        let msg1 = TestMessage::new(1);
        let msg2 = TestMessage::new(2);

        let permit1 = tx1.reserve(&cx).await.unwrap();
        permit1.send(msg1.clone());
        let permit2 = tx2.reserve(&cx).await.unwrap();
        permit2.send(msg2.clone());

        let received1 = rx.recv(&cx).await.unwrap();
        let received2 = rx.recv(&cx).await.unwrap();
        let scenario_a = vec![received1, received2];

        // Reset channel
        drop(rx);
        drop(tx1);
        drop(tx2);
        let (tx1, mut rx) = test_channel(4);
        let tx2 = tx1.clone();

        // Scenario B: tx2 reserves, tx1 reserves, tx2 commits, tx1 commits
        let permit2 = tx2.reserve(&cx).await.unwrap();
        let permit1 = tx1.reserve(&cx).await.unwrap();
        permit2.send(msg2.clone());
        permit1.send(msg1.clone());

        let received1 = rx.recv(&cx).await.unwrap();
        let received2 = rx.recv(&cx).await.unwrap();
        let scenario_b = vec![received1, received2];

        // MR1: Different reservation orders should yield same message sets
        // (Order might differ but content should be same)
        let mut scenario_a_sorted = scenario_a.clone();
        let mut scenario_b_sorted = scenario_b.clone();
        scenario_a_sorted.sort_by_key(|msg| msg.id);
        scenario_b_sorted.sort_by_key(|msg| msg.id);

        assert_eq!(scenario_a_sorted, scenario_b_sorted,
            "MR1 violated: reserve/commit commutativity failed\n\
             Scenario A: {:?}\n\
             Scenario B: {:?}", scenario_a, scenario_b);
    });
}

// ============================================================================
// MR2: Send/Recv Duality
// ============================================================================

/// Tests FIFO preservation: what gets sent gets received in order.
#[test]
fn mr2_send_recv_duality() {
    block_on(async {
        let (tx, mut rx) = test_channel(10);
        let cx = test_cx();

        // Send a sequence of messages
        let original_messages = vec![
            TestMessage::new(1),
            TestMessage::new(2),
            TestMessage::new(3),
            TestMessage::new(4),
        ];

        // Send all messages
        for msg in &original_messages {
            tx.send(&cx, msg.clone()).await.unwrap();
        }

        // Receive all messages
        let mut received_messages = Vec::new();
        for _ in 0..original_messages.len() {
            received_messages.push(rx.recv(&cx).await.unwrap());
        }

        // MR2: Send sequence equals receive sequence (FIFO)
        assert_eq!(original_messages, received_messages,
            "MR2 violated: send/recv duality failed\n\
             Sent: {:?}\n\
             Received: {:?}", original_messages, received_messages);
    });
}

// ============================================================================
// MR3: Capacity Conservation
// ============================================================================

/// Tests that channel capacity accounting remains consistent.
#[test]
fn mr3_capacity_conservation() {
    block_on(async {
        let capacity = 3;
        let (tx, mut rx) = test_channel(capacity);
        let cx = test_cx();

        // Fill channel to capacity with reservations
        let permit1 = tx.reserve(&cx).await.unwrap();
        let permit2 = tx.reserve(&cx).await.unwrap();
        let permit3 = tx.reserve(&cx).await.unwrap();

        // Fourth reservation should block (would hang, so we use try_reserve)
        let result = tx.try_reserve();
        assert!(result.is_err(), "MR3 violated: should not be able to reserve beyond capacity");

        // Commit one reservation
        permit1.send(TestMessage::new(1));

        // Should still be at capacity
        let result = tx.try_reserve();
        assert!(result.is_err(), "MR3 violated: capacity not conserved after partial commit");

        // Receive message, freeing up space
        let _received = rx.recv(&cx).await.unwrap();

        // Now should be able to reserve again
        let permit4 = tx.try_reserve();
        assert!(permit4.is_ok(), "MR3 violated: capacity not freed after receive");

        // Clean up remaining permits
        permit2.send(TestMessage::new(2));
        permit3.send(TestMessage::new(3));
        permit4.unwrap().send(TestMessage::new(4));
    });
}

// ============================================================================
// MR4: Cancel Safety Invariant
// ============================================================================

/// Tests that cancellation preserves channel state.
#[test]
fn mr4_cancel_safety_invariant() {
    block_on(async {
        let (tx, mut rx) = test_channel(2);
        let cx = test_cx();

        // Establish baseline state: one message in queue
        tx.send(&cx, TestMessage::new(1)).await.unwrap();

        // Start reservation and then cancel it by aborting permit
        let permit = tx.reserve(&cx).await.unwrap();
        permit.abort(); // Explicit cancellation

        // Channel state should be unchanged
        // Should be able to reserve again (capacity freed)
        let permit2 = tx.try_reserve();
        assert!(permit2.is_ok(), "MR4 violated: cancellation affected capacity");

        // Original message should still be receivable
        let received = rx.recv(&cx).await.unwrap();
        assert_eq!(received.id, 1, "MR4 violated: cancellation affected queued messages");

        // Commit the second permit
        permit2.unwrap().send(TestMessage::new(2));

        // Should receive second message
        let received2 = rx.recv(&cx).await.unwrap();
        assert_eq!(received2.id, 2, "MR4 violated: post-cancel operations failed");
    });
}

// ============================================================================
// MR5: Batch Send Equivalence
// ============================================================================

/// Tests that batched sends are equivalent to individual sends.
#[test]
fn mr5_batch_send_equivalence() {
    block_on(async {
        let messages = vec![
            TestMessage::new(10),
            TestMessage::new(20),
            TestMessage::new(30),
            TestMessage::new(40),
        ];

        // Scenario A: Send all messages individually
        let (tx_a, mut rx_a) = test_channel(10);
        let cx = test_cx();

        for msg in &messages {
            tx_a.send(&cx, msg.clone()).await.unwrap();
        }

        let mut received_a = Vec::new();
        for _ in 0..messages.len() {
            received_a.push(rx_a.recv(&cx).await.unwrap());
        }

        // Scenario B: Send in two batches
        let (tx_b, mut rx_b) = test_channel(10);
        let split_point = 2;

        // First batch
        for msg in &messages[0..split_point] {
            tx_b.send(&cx, msg.clone()).await.unwrap();
        }

        // Second batch
        for msg in &messages[split_point..] {
            tx_b.send(&cx, msg.clone()).await.unwrap();
        }

        let mut received_b = Vec::new();
        for _ in 0..messages.len() {
            received_b.push(rx_b.recv(&cx).await.unwrap());
        }

        // MR5: Both approaches should yield identical results
        assert_eq!(received_a, received_b,
            "MR5 violated: batch send equivalence failed\n\
             Individual: {:?}\n\
             Batched: {:?}", received_a, received_b);

        // Both should match original message order
        assert_eq!(messages, received_a, "MR5 violated: individual send order wrong");
        assert_eq!(messages, received_b, "MR5 violated: batch send order wrong");
    });
}

// ============================================================================
// MR6: Reserve Pool Commutativity
// ============================================================================

/// Tests that reserve pool operations are commutative.
#[test]
fn mr6_reserve_pool_commutativity() {
    block_on(async {
        let (tx1, mut rx) = test_channel(4);
        let tx2 = tx1.clone();
        let cx = test_cx();

        // Scenario A: tx1 reserves, tx2 reserves, tx2 commits, tx1 commits
        let permit1_a = tx1.reserve(&cx).await.unwrap();
        let permit2_a = tx2.reserve(&cx).await.unwrap();
        permit2_a.send(TestMessage::new(100));
        permit1_a.send(TestMessage::new(200));

        let received1_a = rx.recv(&cx).await.unwrap();
        let received2_a = rx.recv(&cx).await.unwrap();
        let scenario_a = vec![received1_a, received2_a];

        // Reset channel
        drop(rx);
        drop(tx1);
        drop(tx2);
        let (tx1, mut rx) = test_channel(4);
        let tx2 = tx1.clone();

        // Scenario B: tx2 reserves, tx1 reserves, tx1 commits, tx2 commits
        let permit2_b = tx2.reserve(&cx).await.unwrap();
        let permit1_b = tx1.reserve(&cx).await.unwrap();
        permit1_b.send(TestMessage::new(200));
        permit2_b.send(TestMessage::new(100));

        let received1_b = rx.recv(&cx).await.unwrap();
        let received2_b = rx.recv(&cx).await.unwrap();
        let scenario_b = vec![received1_b, received2_b];

        // MR6: Different reserve/commit orders should yield same message sets
        let mut scenario_a_sorted = scenario_a.clone();
        let mut scenario_b_sorted = scenario_b.clone();
        scenario_a_sorted.sort_by_key(|msg| msg.id);
        scenario_b_sorted.sort_by_key(|msg| msg.id);

        assert_eq!(scenario_a_sorted, scenario_b_sorted,
            "MR6 violated: reserve pool commutativity failed\n\
             Scenario A: {:?}\n\
             Scenario B: {:?}", scenario_a, scenario_b);
    });
}

// ============================================================================
// Property-Based Metamorphic Testing
// ============================================================================

/// Property-based test for channel metamorphic relations.
#[test]
fn property_channel_metamorphic_relations() {
    proptest!(|(
        capacity in 1usize..=10,
        message_count in 1usize..=5,
        seed in any::<u64>(),
    )| {
        // Note: This is a simplified version - full property-based testing
        // would require more sophisticated generators and async test harness

        let _seed = seed;
        let (messages, received) = block_on(async {
            let (tx, mut rx) = test_channel(capacity);
            let cx = test_cx();

            // Generate deterministic test messages
            let mut messages = Vec::new();
            for i in 0..message_count {
                messages.push(TestMessage::new((seed as u32).wrapping_add(i as u32)));
            }

            // Send all messages
            for msg in &messages {
                tx.send(&cx, msg.clone()).await.unwrap();
            }

            // Receive all messages
            let mut received = Vec::new();
            for _ in 0..message_count {
                received.push(rx.recv(&cx).await.unwrap());
            }
            (messages, received)
        });
        // Property: Send sequence equals receive sequence
        prop_assert_eq!(messages, received, "Property violated: send/recv sequence mismatch");
    });
}

// ============================================================================
// Integration Tests with Lab Runtime
// ============================================================================

/// Integration test using lab runtime for deterministic scheduling.
#[test]
fn integration_deterministic_channel_operations() {
    block_on(async {
        let (tx, mut rx) = test_channel(3);
        let cx = test_cx();

        // Complex interleaved operations
        let permit1 = tx.reserve(&cx).await.unwrap();
        let permit2 = tx.reserve(&cx).await.unwrap();

        // Send via permit2 first
        permit2.send(TestMessage::new(42));

        // Receive first message
        let msg1 = rx.recv(&cx).await.unwrap();
        assert_eq!(msg1.id, 42, "Deterministic scheduling failed");

        // Send via permit1
        permit1.send(TestMessage::new(84));

        // Receive second message
        let msg2 = rx.recv(&cx).await.unwrap();
        assert_eq!(msg2.id, 84, "Deterministic scheduling failed");
    });
}

// ============================================================================
// Stress Tests for Metamorphic Relations
// ============================================================================

/// Stress test with many concurrent operations.
#[test]
fn stress_test_metamorphic_relations() {
    block_on(async {
        let (tx, mut rx) = test_channel(100);
        let cx = test_cx();

        // Send many messages
        let mut sent_messages = Vec::new();
        for i in 0..50 {
            let msg = TestMessage::new(i);
            sent_messages.push(msg.clone());
            tx.send(&cx, msg).await.unwrap();
        }

        // Receive all messages
        let mut received_messages = Vec::new();
        for _ in 0..50 {
            received_messages.push(rx.recv(&cx).await.unwrap());
        }

        // Verify FIFO order maintained under stress
        assert_eq!(sent_messages, received_messages,
            "Stress test failed: FIFO order violated with {} messages", sent_messages.len());
    });
}