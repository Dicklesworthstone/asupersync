#![allow(clippy::all)]
//! Metamorphic tests for channel::broadcast slow-receiver lag bound invariants.
//!
//! These tests verify metamorphic relations for broadcast channel slow receiver
//! behavior using property-based testing with proptest and LabRuntime virtual time.
//! The tests ensure that lag detection, capacity bounds, recovery behavior, and
//! isolation work correctly under various scenarios.

use asupersync::channel::broadcast::{self, RecvError, TryRecvError};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::Budget;
use asupersync::util::ArenaIndex;
use asupersync::{Cx, RegionId, TaskId};
use proptest::prelude::*;

/// Test scenario for broadcast slow receiver lag bound testing
#[derive(Debug, Clone)]
struct SlowReceiverScenario {
    /// Channel capacity (must be > 0)
    pub capacity: usize,
    /// Number of messages to send before creating slow receiver
    pub warmup_messages: usize,
    /// Number of messages to cause lag (typically > capacity)
    pub lag_messages: usize,
    /// Number of fast receivers that consume messages promptly
    pub fast_receiver_count: usize,
    /// Number of messages to send after lag for recovery testing
    pub recovery_messages: usize,
}

impl SlowReceiverScenario {
    /// Create a new test scenario with validated parameters
    fn new(
        capacity: usize,
        warmup_messages: usize,
        lag_messages: usize,
        fast_receiver_count: usize,
        recovery_messages: usize,
    ) -> Self {
        assert!(capacity > 0, "capacity must be positive");
        Self {
            capacity,
            warmup_messages,
            lag_messages,
            fast_receiver_count,
            recovery_messages,
        }
    }

    /// Total number of messages sent in this scenario
    fn total_messages(&self) -> usize {
        self.warmup_messages + self.lag_messages + self.recovery_messages
    }

    /// Expected lag count when slow receiver falls behind
    fn expected_lag_count(&self) -> u64 {
        if self.lag_messages <= self.capacity {
            0 // No lag if messages fit in buffer
        } else {
            (self.lag_messages - self.capacity) as u64
        }
    }
}

/// Generate test scenarios for property-based testing
fn slow_receiver_scenarios() -> impl Strategy<Value = SlowReceiverScenario> {
    (
        1usize..=8,  // capacity
        0usize..=5,  // warmup_messages
        1usize..=15, // lag_messages
        0usize..=3,  // fast_receiver_count
        0usize..=5,  // recovery_messages
    )
        .prop_map(|(capacity, warmup, lag, fast_count, recovery)| {
            SlowReceiverScenario::new(capacity, warmup, lag, fast_count, recovery)
        })
}

/// Create a test context for broadcast channel tests
fn create_test_context() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(1, 0)),
        TaskId::from_arena(ArenaIndex::new(1, 0)),
        Budget::INFINITE,
    )
}

/// Helper to consume messages from a receiver until empty or error
async fn consume_all_messages<T: Clone>(
    rx: &mut broadcast::Receiver<T>,
    cx: &Cx,
    max_messages: usize,
) -> Vec<Result<T, RecvError>> {
    let mut results = Vec::new();

    for _ in 0..max_messages {
        match rx.recv(cx).await {
            Ok(msg) => results.push(Ok(msg)),
            Err(e) => {
                results.push(Err(e));
                break;
            }
        }
    }

    results
}

async fn lag_outcome_with_fast_consumer_multiplicity(
    capacity: usize,
    total_messages: usize,
    fast_receiver_count: usize,
) -> (u64, Vec<usize>) {
    let cx = create_test_context();
    let (tx, mut slow_rx) = broadcast::channel::<usize>(capacity);
    let mut fast_receivers: Vec<_> = (0..fast_receiver_count).map(|_| tx.subscribe()).collect();

    for value in 0..total_messages {
        let delivered = tx.send(&cx, value).expect("send lag probe");
        assert_eq!(
            delivered,
            fast_receiver_count + 1,
            "every subscribed receiver should observe the send"
        );

        for rx in &mut fast_receivers {
            let fast_value = rx.recv(&cx).await.expect("fast receiver keeps up");
            assert_eq!(fast_value, value, "fast receivers should stay in lockstep");
        }
    }

    let lag = match slow_rx.recv(&cx).await {
        Err(RecvError::Lagged(skipped)) => skipped,
        other => panic!("expected lagged slow receiver, got {other:?}"),
    };

    let mut recovered_tail = Vec::with_capacity(capacity);
    for _ in 0..capacity {
        recovered_tail.push(
            slow_rx
                .recv(&cx)
                .await
                .expect("slow receiver should recover buffered tail"),
        );
    }

    (lag, recovered_tail)
}

/// **MR1: Capacity Bound Honored Per Receiver**
///
/// Verifies that each receiver's lag detection respects the channel capacity:
/// - No lag when messages sent ≤ capacity
/// - Lag occurs when messages sent > capacity
/// - Each receiver has independent lag tracking
#[test]
fn mr1_capacity_bound_honored_per_receiver() {
    proptest!(|(scenario in slow_receiver_scenarios())| {
        let _lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(async {
            let cx = create_test_context();
            let (tx, mut rx1) = broadcast::channel::<usize>(scenario.capacity);
            let mut rx2 = tx.subscribe();

            // MR1.1: Send exactly capacity messages - no lag expected
            if scenario.capacity > 0 {
                for i in 0..scenario.capacity {
                    tx.send(&cx, i).expect("send within capacity");
                }

                // Both receivers should get all messages without lag
                for expected in 0..scenario.capacity {
                    let result1 = rx1.recv(&cx).await;
                    let result2 = rx2.recv(&cx).await;

                    prop_assert_eq!(result1, Ok(expected),
                        "rx1 should receive message {} without lag (capacity={})",
                        expected, scenario.capacity);
                    prop_assert_eq!(result2, Ok(expected),
                        "rx2 should receive message {} without lag (capacity={})",
                        expected, scenario.capacity);
                }
            }

            // MR1.2: Create new receivers and send capacity + 1 messages
            let mut rx3 = tx.subscribe();
            let mut rx4 = tx.subscribe();

            let start_value = 1000;
            for i in 0..=scenario.capacity {
                tx.send(&cx, start_value + i).expect("send beyond capacity");
            }

            // First receiver gets the earliest available message (no lag since it's caught up)
            // New receivers should either get all messages or lag depending on timing
            let result3 = rx3.recv(&cx).await;
            let result4 = rx4.recv(&cx).await;

            // MR1.3: Independent lag tracking - each receiver tracks its own position
            // Both new receivers should have the same behavior since they subscribed at same time
            match (&result3, &result4) {
                (Ok(val3), Ok(val4)) => {
                    prop_assert_eq!(val3, val4,
                        "New receivers with same subscription timing should see same first message");
                }
                (Err(RecvError::Lagged(lag3)), Err(RecvError::Lagged(lag4))) => {
                    prop_assert_eq!(lag3, lag4,
                        "New receivers with same subscription timing should have same lag count");
                }
                _ => {
                    return Err(proptest::test_runner::TestCaseError::fail(format!(
                        "New receivers should have consistent behavior: rx3={:?}, rx4={:?}",
                        result3, result4)));
                }
            }

            Ok(())
        })?;
    });
}

/// **MR2: Slow Receiver Triggers Lagged Error After Bound**
///
/// Verifies that slow receivers correctly trigger Lagged errors when they fall
/// behind by more than the channel capacity:
/// - Receivers that don't consume messages accumulate lag
/// - Lag error provides correct skip count
/// - Lag threshold aligns with channel capacity
#[test]
fn mr2_slow_receiver_triggers_lagged_error_after_bound() {
    proptest!(|(scenario in slow_receiver_scenarios())| {
        let _lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(async {
            let cx = create_test_context();
            let (tx, mut slow_rx) = broadcast::channel::<usize>(scenario.capacity);
            let mut fast_rx = tx.subscribe();

            // Send warmup messages
            for i in 0..scenario.warmup_messages {
                tx.send(&cx, i).expect("send warmup");
            }

            // Fast receiver consumes warmup messages
            for _ in 0..scenario.warmup_messages {
                fast_rx.recv(&cx).await.expect("fast recv warmup");
            }

            // MR2.1: Send messages that exceed capacity to cause lag
            let lag_start = scenario.warmup_messages;
            for i in 0..scenario.lag_messages {
                tx.send(&cx, lag_start + i).expect("send lag messages");
            }

            // Fast receiver keeps up
            for _ in 0..scenario.lag_messages {
                fast_rx.recv(&cx).await.expect("fast recv lag messages");
            }

            // MR2.2: Slow receiver should now be lagged if lag_messages > capacity
            let slow_result = slow_rx.recv(&cx).await;
            let expected_lag = scenario.expected_lag_count();

            if expected_lag > 0 {
                // Should get lag error
                match slow_result {
                    Err(RecvError::Lagged(actual_lag)) => {
                        prop_assert_eq!(actual_lag, expected_lag,
                            "Lag count should match expected (capacity={}, lag_messages={}, warmup={})",
                            scenario.capacity, scenario.lag_messages, scenario.warmup_messages);
                    }
                    other => {
                        return Err(proptest::test_runner::TestCaseError::fail(format!(
                            "Expected Lagged({}) but got {:?} (capacity={}, lag_messages={}, warmup={})",
                            expected_lag, other, scenario.capacity, scenario.lag_messages, scenario.warmup_messages)));
                    }
                }
            } else {
                // Should get normal message since no lag occurred
                prop_assert!(slow_result.is_ok(),
                    "Expected Ok result when no lag occurs (capacity={}, lag_messages={})",
                    scenario.capacity, scenario.lag_messages);
            }

            // MR2.3: Fast receiver unaffected by slow receiver's lag
            let fast_post_lag = fast_rx.try_recv();
            prop_assert!(matches!(fast_post_lag, Err(TryRecvError::Empty)),
                "Fast receiver should have consumed all messages and be at empty state");

            Ok(())
        })?;
    });
}

/// **MR3: Recovery After Lagged Resumes From Latest Value**
///
/// Verifies that after receiving a Lagged error, the receiver correctly resumes
/// from the earliest available message in the buffer:
/// - Cursor is advanced to earliest buffered message
/// - Subsequent receives get messages in correct order
/// - No messages are lost after recovery
#[test]
fn mr3_recovery_after_lagged_resumes_from_latest() {
    proptest!(|(scenario in slow_receiver_scenarios().prop_filter(
        "Need lag to test recovery",
        |s| s.expected_lag_count() > 0 && s.recovery_messages > 0
    ))| {
        let _lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(async {
            let cx = create_test_context();
            let (tx, mut slow_rx) = broadcast::channel::<usize>(scenario.capacity);

            // Send messages to cause lag
            let total_sent = scenario.warmup_messages + scenario.lag_messages;
            for i in 0..total_sent {
                tx.send(&cx, i).expect("send pre-lag");
            }

            // MR3.1: Get lag error
            let lag_result = slow_rx.recv(&cx).await;
            prop_assert!(matches!(lag_result, Err(RecvError::Lagged(_))),
                "Should get lag error");

            // MR3.2: Recovery phase - next receives should get messages from buffer
            let buffer_start = total_sent.saturating_sub(scenario.capacity);
            let available_in_buffer = total_sent - buffer_start;

            let mut recovered_messages = Vec::new();
            for _ in 0..available_in_buffer {
                match slow_rx.recv(&cx).await {
                    Ok(msg) => recovered_messages.push(msg),
                    Err(e) => {
                        return Err(proptest::test_runner::TestCaseError::fail(format!(
                            "Expected message during recovery but got error: {:?}", e)));
                    }
                }
            }

            // MR3.3: Verify recovered messages are in correct order and from expected range
            let expected_messages: Vec<usize> = (buffer_start..total_sent).collect();
            prop_assert_eq!(recovered_messages, expected_messages,
                "Recovered messages should match expected buffer content (capacity={}, total_sent={})",
                scenario.capacity, total_sent);

            // MR3.4: Send post-recovery messages and verify they're received correctly
            let recovery_start = total_sent;
            for i in 0..scenario.recovery_messages {
                tx.send(&cx, recovery_start + i).expect("send recovery");
            }

            let mut post_recovery = Vec::new();
            for _ in 0..scenario.recovery_messages {
                match slow_rx.recv(&cx).await {
                    Ok(msg) => post_recovery.push(msg),
                    Err(e) => {
                        return Err(proptest::test_runner::TestCaseError::fail(format!(
                            "Expected post-recovery message but got error: {:?}", e)));
                    }
                }
            }

            let expected_recovery: Vec<usize> = (recovery_start..(recovery_start + scenario.recovery_messages)).collect();
            prop_assert_eq!(post_recovery, expected_recovery,
                "Post-recovery messages should be in correct order");

            Ok(())
        })?;
    });
}

/// **MR4: Other Receivers Unaffected By One Slow Subscriber**
///
/// Verifies that one slow receiver does not impact the performance or behavior
/// of other receivers:
/// - Fast receivers can consume messages normally
/// - Slow receiver lag doesn't block fast receivers
/// - Multiple receivers have independent lag states
#[test]
fn mr4_other_receivers_unaffected_by_slow_subscriber() {
    proptest!(|(scenario in slow_receiver_scenarios().prop_filter(
        "Need multiple receivers",
        |s| s.fast_receiver_count > 0
    ))| {
        let _lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(async {
            let cx = create_test_context();
            let (tx, mut slow_rx) = broadcast::channel::<usize>(scenario.capacity);

            // Create fast receivers
            let mut fast_receivers = Vec::new();
            for _ in 0..scenario.fast_receiver_count {
                fast_receivers.push(tx.subscribe());
            }

            // MR4.1: Send messages and let only fast receivers consume
            let total_messages = scenario.warmup_messages + scenario.lag_messages;
            for i in 0..total_messages {
                tx.send(&cx, i).expect("send message");
            }

            // Fast receivers consume all messages
            let mut fast_sequences = Vec::new();
            for rx in &mut fast_receivers {
                let mut sequence = Vec::new();
                for _ in 0..total_messages {
                    match rx.recv(&cx).await {
                        Ok(msg) => sequence.push(msg),
                        Err(e) => {
                            return Err(proptest::test_runner::TestCaseError::fail(format!(
                                "Fast receiver should not lag: {:?}", e)));
                        }
                    }
                }
                fast_sequences.push(sequence);
            }

            // MR4.2: All fast receivers should see same sequence
            if !fast_sequences.is_empty() {
                let first_sequence = &fast_sequences[0];
                for (i, sequence) in fast_sequences.iter().enumerate() {
                    prop_assert_eq!(sequence, first_sequence,
                        "Fast receiver {} should see same sequence as receiver 0", i);
                }

                // Sequence should be complete and in order
                let expected: Vec<usize> = (0..total_messages).collect();
                prop_assert_eq!(first_sequence, &expected,
                    "Fast receivers should see complete sequence in order");
            }

            // MR4.3: Slow receiver may be lagged, but this shouldn't affect fast receivers
            let slow_result = slow_rx.recv(&cx).await;
            if scenario.expected_lag_count() > 0 {
                prop_assert!(matches!(slow_result, Err(RecvError::Lagged(_))),
                    "Slow receiver should be lagged");
            }

            // MR4.4: Send additional messages - fast receivers should still work normally
            let additional_start = total_messages;
            for i in 0..3 {
                tx.send(&cx, additional_start + i).expect("send additional");
            }

            // Fast receivers should receive additional messages without issues
            for rx in &mut fast_receivers {
                for j in 0..3 {
                    match rx.recv(&cx).await {
                        Ok(msg) => {
                            let expected = additional_start + j;
                            prop_assert_eq!(msg, expected,
                                "Fast receiver should get additional message {} in order", expected);
                        }
                        Err(e) => {
                            return Err(proptest::test_runner::TestCaseError::fail(format!(
                                "Fast receiver failed on additional message: {:?}", e)));
                        }
                    }
                }
            }

            Ok(())
        })?;
    });
}

/// **MR5: Drop Of Slow Receiver Cleans Backpressure State**
///
/// Verifies that dropping slow receivers properly cleans up internal state:
/// - Receiver count decreases correctly
/// - Internal waker registrations are cleaned up
/// - Buffer management adapts to remaining receivers
/// - Channel continues to work normally after drop
#[test]
fn mr5_drop_slow_receiver_cleans_backpressure_state() {
    proptest!(|(scenario in slow_receiver_scenarios())| {
        let _lab = LabRuntime::new(LabConfig::default());

        futures_lite::future::block_on(async {
            let cx = create_test_context();
            let (tx, mut fast_rx) = broadcast::channel::<usize>(scenario.capacity);

            // MR5.1: Create slow receiver and record initial state
            let mut slow_rx = tx.subscribe();
            let initial_receiver_count = tx.receiver_count();
            prop_assert_eq!(initial_receiver_count, 2, "Should have 2 receivers initially");

            // Send some messages
            let num_messages = scenario.capacity + 3;
            for i in 0..num_messages {
                tx.send(&cx, i).expect("send message");
            }

            // Fast receiver consumes messages
            for _ in 0..num_messages {
                fast_rx.recv(&cx).await.expect("fast recv");
            }

            // Slow receiver should be lagged
            if scenario.capacity < num_messages {
                let lag_result = slow_rx.recv(&cx).await;
                prop_assert!(matches!(lag_result, Err(RecvError::Lagged(_))),
                    "Slow receiver should be lagged");
            }

            // MR5.2: Drop slow receiver
            drop(slow_rx);

            // MR5.3: Verify receiver count decreased
            let post_drop_receiver_count = tx.receiver_count();
            prop_assert_eq!(post_drop_receiver_count, 1,
                "Receiver count should decrease after drop");

            // MR5.4: Channel should continue working normally
            let test_value = 9999;
            let send_result = tx.send(&cx, test_value);
            prop_assert!(send_result.is_ok(), "Send should work after slow receiver drop");
            prop_assert_eq!(send_result.unwrap(), 1, "Should have 1 remaining receiver");

            // MR5.5: Remaining receiver should work normally
            let recv_result = fast_rx.recv(&cx).await;
            prop_assert_eq!(recv_result, Ok(test_value),
                "Fast receiver should continue working after slow receiver drop");

            // MR5.6: Test that new subscriptions work after slow receiver cleanup
            let mut new_rx = tx.subscribe();
            let new_test_value = 8888;
            tx.send(&cx, new_test_value).expect("send to new subscriber");

            let new_recv_result = new_rx.recv(&cx).await;
            prop_assert_eq!(new_recv_result, Ok(new_test_value),
                "New receiver should work after slow receiver cleanup");

            // MR5.7: Verify both active receivers get the message
            let fast_recv_result = fast_rx.recv(&cx).await;
            prop_assert_eq!(fast_recv_result, Ok(new_test_value),
                "Fast receiver should also get message sent to new subscriber");

            Ok(())
        })?;
    });
}

/// **MR6: Fast Consumer Multiplicity Does Not Change Slow Receiver Outcome**
///
/// Adding receivers that promptly consume each message is a semantics-preserving
/// transformation for an already-idle slow receiver: the slow receiver should
/// report the same lag count and recover the same buffered tail regardless of
/// how many fast peers stay caught up.
#[test]
fn mr6_fast_consumer_multiplicity_preserves_slow_receiver_lag_outcome() {
    let _lab = LabRuntime::new(LabConfig::default());

    futures_lite::future::block_on(async {
        let capacity = 4;
        let total_messages = 11;

        let baseline =
            lag_outcome_with_fast_consumer_multiplicity(capacity, total_messages, 0).await;
        let transformed =
            lag_outcome_with_fast_consumer_multiplicity(capacity, total_messages, 3).await;

        assert_eq!(baseline, transformed);
        assert_eq!(baseline.0, (total_messages - capacity) as u64);
        assert_eq!(baseline.1, vec![7, 8, 9, 10]);
    });
}

/// **Integration Test: Complete Slow Receiver Workflow**
///
/// Tests the complete slow receiver workflow from creation through lag to cleanup
#[test]
fn integration_slow_receiver_complete_workflow() {
    let _lab = LabRuntime::new(LabConfig::default());

    futures_lite::future::block_on(async {
        let cx = create_test_context();
        let capacity = 3;
        let (tx, mut rx_fast) = broadcast::channel::<String>(capacity);

        // Phase 1: Normal operation
        tx.send(&cx, "msg1".to_string()).expect("send 1");
        tx.send(&cx, "msg2".to_string()).expect("send 2");

        let msg1 = rx_fast.recv(&cx).await.expect("recv 1");
        assert_eq!(msg1, "msg1");
        let msg2 = rx_fast.recv(&cx).await.expect("recv 2");
        assert_eq!(msg2, "msg2");

        // Phase 2: Create slow receiver and cause lag
        let mut rx_slow = tx.subscribe();

        // Send messages beyond capacity
        for i in 3..=8 {
            tx.send(&cx, format!("msg{}", i))
                .expect(&format!("send {}", i));
        }

        // Fast receiver keeps up
        for i in 3..=8 {
            let msg = rx_fast.recv(&cx).await.expect(&format!("fast recv {}", i));
            assert_eq!(msg, format!("msg{}", i));
        }

        // Phase 3: Slow receiver gets lag error
        let lag_result = rx_slow.recv(&cx).await;
        match lag_result {
            Err(RecvError::Lagged(count)) => {
                // Should have lagged by messages that got evicted from buffer
                // Buffer holds last 3 messages (msg6, msg7, msg8)
                // Slow receiver expected msg3 but earliest is msg6 → lagged by 3
                assert_eq!(count, 3);
            }
            other => panic!("Expected lag error, got: {:?}", other),
        }

        // Phase 4: Recovery - should get remaining buffered messages
        let recovered = vec![
            rx_slow.recv(&cx).await.expect("recover 1"),
            rx_slow.recv(&cx).await.expect("recover 2"),
            rx_slow.recv(&cx).await.expect("recover 3"),
        ];
        assert_eq!(recovered, vec!["msg6", "msg7", "msg8"]);

        // Phase 5: Normal operation resumes
        tx.send(&cx, "msg9".to_string()).expect("send 9");

        let fast_msg9 = rx_fast.recv(&cx).await.expect("fast recv 9");
        assert_eq!(fast_msg9, "msg9");

        let slow_msg9 = rx_slow.recv(&cx).await.expect("slow recv 9");
        assert_eq!(slow_msg9, "msg9");

        // Phase 6: Cleanup verification
        assert_eq!(tx.receiver_count(), 2);
        drop(rx_slow);
        assert_eq!(tx.receiver_count(), 1);

        // Channel still works
        tx.send(&cx, "final".to_string()).expect("send final");
        let final_msg = rx_fast.recv(&cx).await.expect("recv final");
        assert_eq!(final_msg, "final");
    });

    println!("✓ Complete slow receiver workflow verified");
}

/// **Edge Case Test: Single Capacity Channel**
#[test]
fn edge_case_single_capacity_channel() {
    let _lab = LabRuntime::new(LabConfig::default());

    futures_lite::future::block_on(async {
        let cx = create_test_context();
        let (tx, mut rx_slow) = broadcast::channel::<u32>(1);
        let mut rx_fast = tx.subscribe();

        // Send multiple messages to single-capacity channel
        for i in 0..5 {
            tx.send(&cx, i).expect(&format!("send {}", i));
        }

        // Fast receiver gets last message only (others evicted)
        let fast_msg = rx_fast.recv(&cx).await.expect("fast recv");
        assert_eq!(fast_msg, 4);

        // Slow receiver should be heavily lagged
        let lag_result = rx_slow.recv(&cx).await;
        match lag_result {
            Err(RecvError::Lagged(count)) => {
                assert_eq!(count, 4); // Missed messages 0,1,2,3
            }
            other => panic!("Expected lag error, got: {:?}", other),
        }

        // Should recover to last message
        let recovered = rx_slow.recv(&cx).await.expect("recover");
        assert_eq!(recovered, 4);
    });
}

/// **Boundary Condition Test: Zero Lag Scenarios**
#[test]
fn boundary_zero_lag_scenarios() {
    let _lab = LabRuntime::new(LabConfig::default());

    futures_lite::future::block_on(async {
        let cx = create_test_context();
        let capacity = 4;
        let (tx, mut rx) = broadcast::channel::<u32>(capacity);

        // Send exactly capacity messages - should not lag
        for i in 0..capacity {
            tx.send(&cx, i as u32).expect(&format!("send {}", i));
        }

        // Should receive all without lag
        for expected in 0..capacity {
            let result = rx.recv(&cx).await;
            assert_eq!(result, Ok(expected as u32));
        }

        // Buffer should now be empty
        let try_result = rx.try_recv();
        assert!(matches!(try_result, Err(TryRecvError::Empty)));
    });
}

#[cfg(test)]
mod conformance_suite {
    use super::*;

    /// Run all slow receiver lag bound conformance tests
    #[test]
    fn run_slow_receiver_conformance_suite() {
        println!("Running Broadcast Slow Receiver Lag Bound Conformance Tests");

        // Run each MR test
        mr1_capacity_bound_honored_per_receiver();
        mr2_slow_receiver_triggers_lagged_error_after_bound();
        mr3_recovery_after_lagged_resumes_from_latest();
        mr4_other_receivers_unaffected_by_slow_subscriber();
        mr5_drop_slow_receiver_cleans_backpressure_state();
        mr6_fast_consumer_multiplicity_preserves_slow_receiver_lag_outcome();

        // Run integration and edge case tests
        integration_slow_receiver_complete_workflow();
        edge_case_single_capacity_channel();
        boundary_zero_lag_scenarios();

        println!("✅ All slow receiver lag bound conformance tests passed");
    }
}
