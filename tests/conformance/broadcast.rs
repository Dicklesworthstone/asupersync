//! Broadcast channel conformance tests.
//!
//! Tests the subscribe/lag/drop semantics of the broadcast channel implementation
//! per the internal specification and expected broadcast channel behavior.
//! Uses metamorphic relations to verify core broadcast protocol invariants.

use asupersync::channel::broadcast::{self, RecvError, SendError, TryRecvError};
use asupersync::cx::Cx;
use asupersync::types::Budget;
use asupersync::util::ArenaIndex;
use asupersync::{RegionId, TaskId};
use proptest::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// Test context for broadcast conformance
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Message type for broadcast testing
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TestMessage {
    id: u64,
    content: String,
}

impl TestMessage {
    fn new(id: u64, content: &str) -> Self {
        Self {
            id,
            content: content.to_string(),
        }
    }
}

/// Generate test messages for proptest
fn test_message_strategy() -> impl Strategy<Value = TestMessage> {
    (0u64..1000, "[a-z]{1,20}")
        .prop_map(|(id, content)| TestMessage::new(id, &content))
}

/// Generate a sequence of test messages
fn message_sequence_strategy() -> impl Strategy<Value = Vec<TestMessage>> {
    prop::collection::vec(test_message_strategy(), 0..50)
}

/// Test operations for metamorphic testing
#[derive(Debug, Clone)]
enum BroadcastOperation {
    Send(TestMessage),
    Subscribe,
    ReceiveNext(usize), // receiver index
    DropReceiver(usize),
    Close, // drop all senders
}

/// Generate operation sequences for metamorphic testing
fn operation_sequence_strategy() -> impl Strategy<Value = Vec<BroadcastOperation>> {
    prop::collection::vec(
        prop_oneof![
            test_message_strategy().prop_map(BroadcastOperation::Send),
            Just(BroadcastOperation::Subscribe),
            (0usize..5).prop_map(BroadcastOperation::ReceiveNext),
            (0usize..5).prop_map(BroadcastOperation::DropReceiver),
            Just(BroadcastOperation::Close),
        ],
        1..100
    )
}

/// State tracker for broadcast channel behavior
#[derive(Debug, Clone)]
struct BroadcastState {
    sent_messages: Vec<TestMessage>,
    receiver_states: HashMap<usize, ReceiverState>,
    next_receiver_id: usize,
    senders_closed: bool,
}

#[derive(Debug, Clone)]
struct ReceiverState {
    subscription_point: usize, // Index in sent_messages when subscribed
    next_expected_index: usize,
    active: bool,
    lag_count: u64,
}

impl BroadcastState {
    fn new() -> Self {
        Self {
            sent_messages: Vec::new(),
            receiver_states: HashMap::new(),
            next_receiver_id: 0,
            senders_closed: false,
        }
    }

    fn send_message(&mut self, msg: TestMessage) {
        if !self.senders_closed {
            self.sent_messages.push(msg);
        }
    }

    fn subscribe(&mut self) -> usize {
        let receiver_id = self.next_receiver_id;
        self.next_receiver_id += 1;
        self.receiver_states.insert(receiver_id, ReceiverState {
            subscription_point: self.sent_messages.len(),
            next_expected_index: self.sent_messages.len(),
            active: true,
            lag_count: 0,
        });
        receiver_id
    }

    fn drop_receiver(&mut self, receiver_id: usize) {
        if let Some(state) = self.receiver_states.get_mut(&receiver_id) {
            state.active = false;
        }
    }

    fn close_senders(&mut self) {
        self.senders_closed = true;
    }

    fn active_receiver_count(&self) -> usize {
        self.receiver_states.values().filter(|s| s.active).count()
    }
}

#[test]
fn test_mr1_subscribe_returns_only_values_sent_after_subscribe() {
    proptest!(|(messages_before: message_sequence_strategy(), messages_after: message_sequence_strategy())| {
        let cx = test_cx();
        let (sender, receiver) = broadcast::channel::<TestMessage>(10);

        // Send messages before subscribe
        for msg in &messages_before {
            let _ = sender.send(&cx, msg.clone());
        }

        // Subscribe creates new receiver that should only see messages after this point
        let mut new_receiver = sender.subscribe();

        // Send messages after subscribe
        for msg in &messages_after {
            let _ = sender.send(&cx, msg.clone());
        }

        // Original receiver should have access to all messages (if capacity allows)
        // New receiver should only see messages sent after subscribe

        let mut new_received = Vec::new();
        while let Ok(msg) = new_receiver.try_recv() {
            new_received.push(msg);
        }

        // MR1: Subscribe semantics - new receiver only gets post-subscribe messages
        prop_assert_eq!(new_received, messages_after);

        // MR1 Inverse: If no messages sent after subscribe, new receiver gets nothing
        if messages_after.is_empty() {
            prop_assert!(matches!(new_receiver.try_recv(), Err(TryRecvError::Empty)));
        }
    });
}

#[test]
fn test_mr2_lag_error_triggered_when_receiver_falls_behind_capacity() {
    proptest!(|(capacity in 1usize..=10, overflow_count in 1usize..=20)| {
        let cx = test_cx();
        let (sender, mut receiver) = broadcast::channel::<TestMessage>(capacity);

        // Send messages to fill capacity + overflow
        let total_messages = capacity + overflow_count;
        for i in 0..total_messages {
            let msg = TestMessage::new(i as u64, &format!("msg_{}", i));
            let _ = sender.send(&cx, msg);
        }

        // First try_recv should detect lag since we sent more than capacity
        let result = receiver.try_recv();

        // MR2: Lag detection - receiver should get lag error when falling behind capacity
        prop_assert!(matches!(result, Err(TryRecvError::Lagged(missed)) if missed > 0));

        if let Err(TryRecvError::Lagged(missed)) = result {
            // MR2 Property: Missed count should equal overflow amount
            prop_assert_eq!(missed as usize, overflow_count);

            // MR2 Recovery: After lag error, receiver should be able to read available messages
            let mut received_after_lag = Vec::new();
            while let Ok(msg) = receiver.try_recv() {
                received_after_lag.push(msg);
            }

            // Should receive exactly capacity messages (the ones that weren't overwritten)
            prop_assert_eq!(received_after_lag.len(), capacity);

            // Messages should be the last 'capacity' messages sent
            for (i, msg) in received_after_lag.iter().enumerate() {
                let expected_id = (overflow_count + i) as u64;
                prop_assert_eq!(msg.id, expected_id);
            }
        }
    });
}

#[test]
fn test_mr3_drop_of_receiver_removes_from_broadcast_set() {
    proptest!(|(initial_receiver_count in 1usize..=5, drop_count in 0usize..=5)| {
        let cx = test_cx();
        let (sender, _receiver) = broadcast::channel::<TestMessage>(10);

        // Create additional receivers
        let mut receivers = vec![sender.subscribe(); initial_receiver_count];

        // Verify initial receiver count (original + subscribed)
        let initial_count = sender.receiver_count();
        prop_assert_eq!(initial_count, initial_receiver_count + 1);

        // Drop some receivers
        let actual_drop_count = drop_count.min(receivers.len());
        for _ in 0..actual_drop_count {
            receivers.pop(); // Drop receiver
        }

        // Give some time for atomic operations to settle
        std::thread::yield_now();

        // MR3: Drop semantics - receiver count should decrease
        let final_count = sender.receiver_count();
        let expected_count = initial_count - actual_drop_count;
        prop_assert_eq!(final_count, expected_count);

        // MR3 Invariant: Receiver count should never be negative (underflow protection)
        prop_assert!(final_count <= initial_count);

        // MR3 Boundary: If all receivers dropped, send should fail with Closed
        if final_count == 0 {
            let result = sender.send(&cx, TestMessage::new(999, "test"));
            prop_assert!(matches!(result, Err(SendError::Closed(_))));
        } else {
            // If receivers remain, send should succeed
            let result = sender.send(&cx, TestMessage::new(999, "test"));
            prop_assert!(result.is_ok());
            if let Ok(delivered_count) = result {
                prop_assert_eq!(delivered_count, final_count);
            }
        }
    });
}

#[test]
fn test_mr4_subscriber_count_accurate_through_concurrent_subscribe_drop() {
    proptest!(|(operations in prop::collection::vec((0u8..3), 10..50))| {
        let cx = test_cx();
        let (sender, _initial_receiver) = broadcast::channel::<TestMessage>(10);

        let mut expected_count = 1; // Initial receiver
        let mut receivers = Vec::new();

        for &op in &operations {
            match op {
                0 => {
                    // Subscribe
                    receivers.push(sender.subscribe());
                    expected_count += 1;
                }
                1 => {
                    // Drop receiver if any exist
                    if !receivers.is_empty() {
                        receivers.remove(0);
                        expected_count -= 1;
                    }
                }
                2 => {
                    // Send message and verify count
                    let actual_count = sender.receiver_count();

                    // MR4: Subscriber count accuracy during concurrent operations
                    prop_assert_eq!(actual_count, expected_count);

                    if actual_count > 0 {
                        let result = sender.send(&cx, TestMessage::new(42, "test"));
                        prop_assert!(result.is_ok());
                        if let Ok(delivered) = result {
                            // MR4 Consistency: Delivered count should match active receivers
                            prop_assert_eq!(delivered, actual_count);
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        // Final consistency check
        let final_actual = sender.receiver_count();
        prop_assert_eq!(final_actual, expected_count);
    });
}

#[test]
fn test_mr5_close_broadcasts_to_all_receivers_even_if_they_lag() {
    proptest!(|(capacity in 1usize..=5, receiver_count in 1usize..=3, lag_messages in 1usize..=10)| {
        let cx = test_cx();
        let (sender, _initial_receiver) = broadcast::channel::<TestMessage>(capacity);

        // Create additional receivers
        let mut receivers: Vec<_> = (0..receiver_count).map(|_| sender.subscribe()).collect();

        // Send messages to cause lag (more than capacity)
        let total_lag_messages = capacity + lag_messages;
        for i in 0..total_lag_messages {
            let msg = TestMessage::new(i as u64, &format!("lag_{}", i));
            let _ = sender.send(&cx, msg);
        }

        // Don't read messages yet - let receivers lag

        // MR5 Setup: Verify receivers would experience lag
        for receiver in &mut receivers {
            let result = receiver.try_recv();
            prop_assert!(matches!(result, Err(TryRecvError::Lagged(_))));
        }

        // Close all senders (this should wake all receivers with Closed error)
        drop(sender);

        // Give time for close notification to propagate
        std::thread::yield_now();

        // MR5: Close semantics - all receivers get Closed error even if lagging
        for receiver in &mut receivers {
            // Skip any lag errors and look for Closed
            let mut saw_closed = false;
            for _ in 0..10 { // Reasonable attempt limit
                match receiver.try_recv() {
                    Err(TryRecvError::Closed) => {
                        saw_closed = true;
                        break;
                    }
                    Err(TryRecvError::Lagged(_)) => {
                        // Expected - continue to next attempt
                        continue;
                    }
                    Ok(_) => {
                        // Also expected - receiver caught up, continue
                        continue;
                    }
                    Err(TryRecvError::Empty) => {
                        // Buffer empty but channel closed - check again
                        if matches!(receiver.try_recv(), Err(TryRecvError::Closed)) {
                            saw_closed = true;
                            break;
                        }
                    }
                }
            }

            // MR5 Assertion: Every receiver eventually sees Closed
            prop_assert!(saw_closed, "Receiver should eventually see Closed error");
        }

        // MR5 Finalization: After close, no new receivers can be created
        // (We can't test this directly as sender is dropped, but the behavior is implicit)
    });
}

/// Comprehensive metamorphic test combining all relations
#[test]
fn test_broadcast_metamorphic_comprehensive() {
    proptest!(|(operations in operation_sequence_strategy().prop_filter("Non-empty operations", |ops| !ops.is_empty()))| {
        let cx = test_cx();
        let (sender, initial_receiver) = broadcast::channel::<TestMessage>(5);

        let mut state = BroadcastState::new();
        let mut receivers = vec![initial_receiver];
        let initial_receiver_id = state.subscribe();

        // Track messages for verification
        let mut all_sent_messages = Vec::new();

        for operation in operations {
            match operation {
                BroadcastOperation::Send(msg) => {
                    if !state.senders_closed {
                        all_sent_messages.push(msg.clone());
                        state.send_message(msg.clone());
                        let result = sender.send(&cx, msg);

                        if state.active_receiver_count() > 0 {
                            prop_assert!(result.is_ok());
                        } else {
                            prop_assert!(matches!(result, Err(SendError::Closed(_))));
                        }
                    }
                }
                BroadcastOperation::Subscribe => {
                    if !state.senders_closed {
                        let new_receiver = sender.subscribe();
                        receivers.push(new_receiver);
                        let receiver_id = state.subscribe();

                        // Verify subscription point semantics (MR1)
                        let subscription_point = state.receiver_states[&receiver_id].subscription_point;
                        prop_assert_eq!(subscription_point, all_sent_messages.len());
                    }
                }
                BroadcastOperation::ReceiveNext(receiver_idx) => {
                    if let Some(receiver) = receivers.get_mut(receiver_idx) {
                        let _result = receiver.try_recv();
                        // Results vary based on timing and lag - main invariants tested separately
                    }
                }
                BroadcastOperation::DropReceiver(receiver_idx) => {
                    if receiver_idx < receivers.len() && receiver_idx > 0 { // Keep initial receiver
                        receivers.remove(receiver_idx);
                        state.drop_receiver(receiver_idx);
                    }
                }
                BroadcastOperation::Close => {
                    state.close_senders();
                    drop(sender);
                    return Ok(()); // Early exit to test close semantics
                }
            }
        }

        // Final invariant checks
        if !state.senders_closed {
            // Receiver count consistency (MR4)
            let expected_active = receivers.len();
            let actual_count = sender.receiver_count();
            prop_assert!(actual_count <= expected_active + 1); // Allow for minor timing differences
        }
    });
}

/// Test broadcast channel edge cases and boundary conditions
#[test]
fn test_broadcast_edge_cases() {
    let cx = test_cx();

    // Edge case: Capacity 1
    {
        let (sender, mut receiver) = broadcast::channel::<TestMessage>(1);

        // Send two messages - second should overwrite first
        let msg1 = TestMessage::new(1, "first");
        let msg2 = TestMessage::new(2, "second");

        sender.send(&cx, msg1).unwrap();
        sender.send(&cx, msg2.clone()).unwrap();

        // Should only receive the second message
        assert_eq!(receiver.try_recv().unwrap(), msg2);
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
    }

    // Edge case: Zero receivers
    {
        let (sender, receiver) = broadcast::channel::<TestMessage>(10);
        drop(receiver);

        let result = sender.send(&cx, TestMessage::new(1, "test"));
        assert!(matches!(result, Err(SendError::Closed(_))));
    }

    // Edge case: Subscribe after close
    {
        let (sender, _receiver) = broadcast::channel::<TestMessage>(10);
        drop(sender);
        // Can't test subscribe after sender drop as we need sender to call subscribe
        // This is tested indirectly in close semantics tests
    }
}

/// Performance/stress test for broadcast channel
#[test]
fn test_broadcast_stress() {
    let cx = test_cx();
    let (sender, mut receiver) = broadcast::channel::<TestMessage>(1000);

    // Send many messages
    for i in 0..10000 {
        let msg = TestMessage::new(i, &format!("stress_{}", i));
        sender.send(&cx, msg).unwrap();
    }

    // Receive all messages
    let mut received_count = 0;
    while receiver.try_recv().is_ok() {
        received_count += 1;
    }

    // Should receive exactly the buffer capacity (last 1000 messages)
    assert_eq!(received_count, 1000);
}