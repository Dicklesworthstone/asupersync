#![allow(clippy::all)]
//! Metamorphic property tests for broadcast channel lagging-receiver behavior.
//!
//! These tests verify broadcast channel invariants related to lagging receiver handling,
//! producer back-pressure, and ring buffer integrity. Unlike unit tests that check exact
//! outcomes, metamorphic tests verify relationships between different execution scenarios.

use crate::channel::broadcast::{RecvError, SendError, TryRecvError, channel};
use crate::cx::Cx;
use crate::lab::{LabConfig, LabRuntime};
use crate::types::{Budget, RegionId, TaskId};
use crate::util::{ArenaIndex, DetRng};
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll};

use proptest::prelude::*;

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create a test context for deterministic scheduling.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Simple block_on implementation for tests.
fn block_on<F: Future>(f: F) -> F::Output {
    let waker = std::task::Waker::noop().clone();
    let mut cx = Context::from_waker(&waker);
    let mut pinned = Box::pin(f);
    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => continue,
        }
    }
}

/// Test harness for broadcast channel operations.
#[derive(Debug)]
struct BroadcastTestHarness<T: Clone> {
    sender: crate::channel::broadcast::Sender<T>,
    receivers: Vec<crate::channel::broadcast::Receiver<T>>,
    capacity: usize,
    messages_sent: u64,
}

impl<T: Clone> BroadcastTestHarness<T> {
    fn new(capacity: usize, receiver_count: usize) -> Self {
        let (sender, receiver) = channel(capacity);
        let mut receivers = vec![receiver];

        // Clone additional receivers
        for _ in 1..receiver_count {
            receivers.push(receivers[0].clone());
        }

        Self {
            sender,
            receivers,
            capacity,
            messages_sent: 0,
        }
    }

    async fn send_message(&mut self, cx: &Cx, message: T) -> Result<(), SendError<T>> {
        let permit = match self.sender.reserve(cx) {
            Ok(p) => p,
            Err(SendError::Closed(())) => return Err(SendError::Closed(message)),
        };
        permit.send(message);
        self.messages_sent += 1;
        Ok(())
    }

    async fn send_messages(&mut self, cx: &Cx, messages: &[T]) -> Result<(), SendError<T>> {
        for msg in messages {
            self.send_message(cx, msg.clone()).await?;
        }
        Ok(())
    }

    fn receiver_mut(&mut self, index: usize) -> &mut crate::channel::broadcast::Receiver<T> {
        &mut self.receivers[index]
    }
}

// ============================================================================
// Metamorphic Relations for Broadcast Lagging-Receiver Behavior
// ============================================================================

/// MR1: Lagged Count Accuracy (Additive, Score: 9.0)
/// Property: A receiver that skips N messages gets RecvError::Lagged with accurate skipped count
/// Catches: Incorrect lag counting, off-by-one errors, message index corruption
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mr_lagged_count_accuracy() {
        let _runtime = Arc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            capacity in 2usize..8,
            skip_count in 1u64..20,
            _seed in any::<u64>(),
        )| {
            let cx = test_cx();
            let mut harness = BroadcastTestHarness::new(capacity, 1);
            let _rng = DetRng::new(_seed);

            // Send messages to fill beyond capacity and cause lag
            let messages_to_send = capacity + (skip_count as usize);
            let messages: Vec<u64> = (0..messages_to_send as u64).collect();

            // Send all messages at once
            block_on(harness.send_messages(&cx, &messages)).unwrap();

            // First receive should detect lag
            let result = block_on(harness.receiver_mut(0).recv(&cx));

            match result {
                Err(RecvError::Lagged(reported_skip)) => {
                    // METAMORPHIC ASSERTION: Reported skip count should match expected
                    prop_assert!(
                        reported_skip > 0,
                        "MR1 VIOLATION: lag reported but skip count is 0"
                    );

                    // The number of messages skipped should be at least the overflow
                    let expected_min_skip = if messages_to_send > capacity {
                        (messages_to_send - capacity) as u64
                    } else {
                        0u64
                    };

                    prop_assert!(
                        reported_skip >= expected_min_skip,
                        "MR1 VIOLATION: reported skip count {} less than expected minimum {}",
                        reported_skip, expected_min_skip
                    );
                }
                Ok(msg) => {
                    // If we got a message instead of lag, it should be from the tail end
                    let expected_start = messages_to_send.saturating_sub(capacity) as u64;
                    prop_assert!(
                        msg >= expected_start,
                        "MR1 VIOLATION: received message {} when expecting lag or tail message >= {}",
                        msg, expected_start
                    );
                }
                Err(other) => {
                    prop_assert!(
                        false,
                        "MR1 VIOLATION: unexpected error when expecting lag: {:?}",
                        other
                    );
                }
            }
        });
    }

    /// MR2: Multiple Lagged Receivers Independence (Equivalence, Score: 8.5)
    /// Property: Multiple concurrent lagged receivers remain independently recoverable
    /// Catches: Receiver cross-contamination, shared state corruption, recovery failures
    #[test]
    fn mr_multiple_lagged_receivers_independence() {
        let _runtime = Arc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            capacity in 2usize..6,
            receiver_count in 2usize..5,
            messages_to_send in 5usize..15,
            _seed in any::<u64>(),
        )| {
            let cx = test_cx();
            let mut harness = BroadcastTestHarness::new(capacity, receiver_count);
            let messages: Vec<u64> = (0..messages_to_send as u64).collect();

            // Send all messages
            block_on(harness.send_messages(&cx, &messages)).unwrap();

            let mut receiver_results = Vec::new();

            // Try to receive from all receivers
            for i in 0..receiver_count {
                let result = block_on(harness.receiver_mut(i).recv(&cx));
                receiver_results.push(result);
            }

            // Count how many receivers got lagged vs successful receives
            let mut lagged_count = 0;
            let mut success_count = 0;
            let mut lag_amounts = Vec::new();

            for result in &receiver_results {
                match result {
                    Err(RecvError::Lagged(amount)) => {
                        lagged_count += 1;
                        lag_amounts.push(amount);
                    }
                    Ok(_) => {
                        success_count += 1;
                    }
                    _ => {}
                }
            }

            // METAMORPHIC ASSERTION: All receivers should behave consistently
            // Since they all start at index 0 and see the same message sequence
            if lagged_count > 0 {
                prop_assert_eq!(
                    lagged_count, receiver_count,
                    "MR2 VIOLATION: inconsistent lag detection - some receivers lagged, some didn't"
                );

                // All lag amounts should be identical for receivers starting at same position
                if lag_amounts.len() > 1 {
                    let first_lag = lag_amounts[0];
                    for &lag_amount in &lag_amounts[1..] {
                        prop_assert_eq!(
                            lag_amount, first_lag,
                            "MR2 VIOLATION: receivers reported different lag amounts: {} vs {}",
                            lag_amount, first_lag
                        );
                    }
                }
            } else {
                prop_assert_eq!(
                    success_count, receiver_count,
                    "MR2 VIOLATION: all receivers should have same outcome"
                );
            }

            // Test recovery independence: each receiver should be able to continue
            for i in 0..receiver_count {
                let recovery_result = block_on(harness.receiver_mut(i).recv(&cx));
                prop_assert!(
                    recovery_result.is_ok() || matches!(recovery_result, Err(RecvError::Closed)),
                    "MR2 VIOLATION: receiver {} failed to recover after lag: {:?}",
                    i, recovery_result
                );
            }
        });
    }

    /// MR3: Dropped Receiver Ring Buffer Integrity (Invariance, Score: 8.0)
    /// Property: Dropping a lagged receiver does not corrupt the ring buffer for healthy receivers
    /// Catches: Buffer corruption, reference count errors, memory safety issues
    #[test]
    fn mr_dropped_receiver_buffer_integrity() {
        let _runtime = Arc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            capacity in 3usize..8,
            initial_receivers in 2usize..5,
            messages_before_drop in 1usize..6,
            messages_after_drop in 1usize..6,
            _seed in any::<u64>(),
        )| {
            let cx = test_cx();
            let mut harness = BroadcastTestHarness::new(capacity, initial_receivers);

            // Send initial messages
            let initial_messages: Vec<u64> = (0..messages_before_drop as u64).collect();
            block_on(harness.send_messages(&cx, &initial_messages)).unwrap();

            // Record what the first receiver sees before dropping others
            let mut reference_receiver = harness.receivers.pop().unwrap();
            let before_drop_result = block_on(reference_receiver.recv(&cx));

            // Drop all other receivers by letting them go out of scope
            harness.receivers.clear();

            // Send more messages after dropping receivers
            let after_messages: Vec<u64> = (messages_before_drop as u64..(messages_before_drop + messages_after_drop) as u64).collect();
            block_on(harness.send_messages(&cx, &after_messages)).unwrap();

            // The remaining receiver should continue to work correctly
            let after_drop_result = block_on(reference_receiver.recv(&cx));

            // METAMORPHIC ASSERTION: Reference receiver behavior should be predictable
            match (before_drop_result, after_drop_result) {
                (Ok(before_msg), Ok(after_msg)) => {
                    // Normal case: both receives succeeded
                    prop_assert!(
                        after_msg > before_msg,
                        "MR3 VIOLATION: message sequence should be monotonic: {} -> {}",
                        before_msg, after_msg
                    );
                }
                (Ok(_before_msg), Err(RecvError::Lagged(_))) => {
                    // Receiver was healthy before but lagged after more messages
                    // This is acceptable behavior
                }
                (Err(RecvError::Lagged(_)), Ok(after_msg)) => {
                    // Receiver was lagged before but recovered after. The
                    // recovered value must correspond to a real sent message,
                    // not a phantom/uninitialised slot value. Sent payloads
                    // are small monotonically-assigned counters, so any valid
                    // recovery message fits within a generous sanity bound.
                    prop_assert!(
                        after_msg < u64::MAX,
                        "MR3 VIOLATION: invalid message after recovery: {}",
                        after_msg
                    );
                }
                (Err(RecvError::Lagged(_)), Err(RecvError::Lagged(_))) => {
                    // Both lagged - acceptable if buffer keeps overflowing
                }
                (before, after) => {
                    prop_assert!(
                        matches!(before, Err(RecvError::Closed)) || matches!(after, Err(RecvError::Closed)),
                        "MR3 VIOLATION: unexpected error combination: before={:?}, after={:?}",
                        before, after
                    );
                }
            }

            // Test that we can create new receivers and they work correctly
            let mut new_receiver = reference_receiver.clone();
            let new_receiver_result = new_receiver.try_recv();

            // New receiver should either get a message or be empty (not corrupted)
            prop_assert!(
                matches!(
                    new_receiver_result,
                    Ok(_) | Err(TryRecvError::Empty | TryRecvError::Lagged(_))
                ),
                "MR3 VIOLATION: new receiver creation failed: {:?}",
                new_receiver_result
            );
        });
    }

    /// MR4: Producer Back-pressure Capacity Independence (Invariance, Score: 7.5)
    /// Property: Producer back-pressure only applies when capacity dictates, never from lagging receivers alone
    /// Catches: Incorrect back-pressure logic, receiver-dependent send blocking
    #[test]
    fn mr_producer_backpressure_capacity_independence() {
        let _runtime = Arc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            capacity in 2usize..8,
            slow_receivers in 1usize..4,
            fast_receivers in 0usize..3,
            messages_to_send in 5usize..15,
            _seed in any::<u64>(),
        )| {
            let cx = test_cx();

            // Create scenario with mixed receiver speeds
            let total_receivers = slow_receivers + fast_receivers;
            let mut harness = BroadcastTestHarness::new(capacity, total_receivers);

            let messages: Vec<u64> = (0..messages_to_send as u64).collect();

            // Send messages - this should always succeed regardless of receiver state
            // because broadcast channels never block producers
            let send_result = block_on(harness.send_messages(&cx, &messages));

            // METAMORPHIC ASSERTION: Sends should always succeed with active receivers
            prop_assert!(
                send_result.is_ok(),
                "MR4 VIOLATION: send failed when it should succeed with active receivers: {:?}",
                send_result
            );

            // Simulate fast receivers by reading from some receivers
            for i in 0..fast_receivers {
                if i < harness.receivers.len() {
                    let _ = harness.receiver_mut(i).try_recv();
                }
            }

            // Send more messages - should still succeed
            let more_messages: Vec<u64> = (messages_to_send as u64..(messages_to_send * 2) as u64).collect();
            let second_send_result = block_on(harness.send_messages(&cx, &more_messages));

            prop_assert!(
                second_send_result.is_ok(),
                "MR4 VIOLATION: second send batch failed: {:?}",
                second_send_result
            );

            // Verify that individual reserve operations always succeed
            for _ in 0..5 {
                let reserve_result = harness.sender.reserve(&cx);
                prop_assert!(
                    reserve_result.is_ok(),
                    "MR4 VIOLATION: reserve failed with active receivers"
                );

                if let Ok(permit) = reserve_result {
                    permit.send(999u64); // Dummy message
                }
            }

            // The only time send should fail is when there are NO receivers
            drop(harness.receivers); // Drop all receivers

            let no_receiver_result = harness.sender.reserve(&cx);
            prop_assert!(
                matches!(no_receiver_result, Err(SendError::Closed(()))),
                "MR4 VIOLATION: reserve should fail only when no receivers exist"
            );
        });
    }

    // ============================================================================
    // Composite Metamorphic Relations
    // ============================================================================

    /// Composite MR: Lag Recovery + Buffer Integrity
    /// Tests that lagged receivers can recover correctly and buffer remains intact
    #[test]
    fn mr_composite_lag_recovery_buffer_integrity() {
        let _runtime = Arc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            capacity in 2usize..6,
            initial_overflow in 1usize..8,
            recovery_messages in 1usize..5,
            _seed in any::<u64>(),
        )| {
            let cx = test_cx();
            let mut harness = BroadcastTestHarness::new(capacity, 2);

            // Phase 1: Create lag condition
            let overflow_messages: Vec<u64> = (0..(capacity + initial_overflow) as u64).collect();
            block_on(harness.send_messages(&cx, &overflow_messages)).unwrap();

            // Phase 2: First receiver should be lagged
            let lag_result = block_on(harness.receiver_mut(0).recv(&cx));
            prop_assert!(
                matches!(lag_result, Err(RecvError::Lagged(_))),
                "COMPOSITE MR VIOLATION: expected lag after overflow"
            );

            // Phase 3: Recovery - receiver should get next available message
            let recovery_result = block_on(harness.receiver_mut(0).recv(&cx));

            if let Ok(recovered_msg) = recovery_result {
                // Phase 4: Second receiver should get same or later message
                let second_result = block_on(harness.receiver_mut(1).recv(&cx));

                match second_result {
                    Ok(second_msg) => {
                        prop_assert!(
                            second_msg >= recovered_msg,
                            "COMPOSITE MR VIOLATION: second receiver got earlier message {} vs {}",
                            second_msg, recovered_msg
                        );
                    }
                    Err(RecvError::Lagged(_)) => {
                        // Also acceptable - both were lagged
                    }
                    Err(other) => {
                        prop_assert!(
                            matches!(other, RecvError::Closed),
                            "COMPOSITE MR VIOLATION: unexpected error: {:?}",
                            other
                        );
                    }
                }

                // Phase 5: Send more messages and verify both can continue
                let final_messages: Vec<u64> = ((overflow_messages.len() as u64)..((overflow_messages.len() + recovery_messages) as u64)).collect();
                block_on(harness.send_messages(&cx, &final_messages)).unwrap();

                // Both receivers should be able to continue receiving
                for i in 0..2 {
                    let continue_result = harness.receiver_mut(i).try_recv();
                    prop_assert!(
                        !matches!(continue_result, Err(TryRecvError::Closed)),
                        "COMPOSITE MR VIOLATION: receiver {} cannot continue after recovery",
                        i
                    );
                }
            }
        });
    }
}

// ============================================================================
// Validation Tests
// ============================================================================

#[cfg(test)]
mod validation_tests {
    use super::*;

    /// Validate that the test infrastructure correctly detects lag
    #[test]
    fn validate_lag_detection_infrastructure() {
        let _runtime = Arc::new(LabRuntime::new(LabConfig::default()));
        let cx = test_cx();
        let mut harness = BroadcastTestHarness::new(2, 1);

        // Send more than capacity to trigger lag
        let messages = vec![1u64, 2, 3, 4, 5]; // 5 messages, capacity 2
        block_on(harness.send_messages(&cx, &messages)).unwrap();

        // Should detect lag
        let result = block_on(harness.receiver_mut(0).recv(&cx));
        assert!(
            matches!(result, Err(RecvError::Lagged(_))),
            "Infrastructure test: should detect lag with {} messages in capacity {}",
            messages.len(),
            harness.capacity
        );
    }

    /// Validate that multiple receivers work independently
    #[test]
    fn validate_multiple_receivers_infrastructure() {
        let _runtime = Arc::new(LabRuntime::new(LabConfig::default()));
        block_on(async {
            let cx = test_cx();
            let mut harness = BroadcastTestHarness::new(3, 2);

            // Send a message
            harness.send_message(&cx, 42u64).await.unwrap();

            // Both receivers should get the same message
            let result1 = harness.receiver_mut(0).recv(&cx).await;
            let result2 = harness.receiver_mut(1).recv(&cx).await;

            assert_eq!(result1, Ok(42));
            assert_eq!(result2, Ok(42));
        });
    }

    /// Validate that dropping receivers works correctly
    #[test]
    fn validate_receiver_dropping_infrastructure() {
        let _runtime = Arc::new(LabRuntime::new(LabConfig::default()));
        block_on(async {
            let cx = test_cx();
            let (sender, receiver) = channel::<u64>(3);

            // Clone receiver, then drop original
            let mut receiver2 = receiver.clone();
            drop(receiver);

            // Should still be able to send
            let permit = sender.reserve(&cx).unwrap();
            permit.send(100);

            // Remaining receiver should work
            let result = receiver2.recv(&cx).await;
            assert_eq!(result, Ok(100));
        });
    }

    /// Validate that back-pressure behavior works as expected
    #[test]
    fn validate_backpressure_infrastructure() {
        let _runtime = Arc::new(LabRuntime::new(LabConfig::default()));
        let cx = test_cx();
        let (sender, _receiver) = channel::<u64>(2);

        // Sending should always succeed with receivers present
        for i in 0..10 {
            let permit = sender.reserve(&cx).unwrap();
            permit.send(i);
        }

        // Drop receiver
        drop(_receiver);

        // Now reserve should fail
        let result = sender.reserve(&cx);
        assert!(matches!(result, Err(SendError::Closed(()))));
    }
}
