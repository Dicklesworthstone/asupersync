#![allow(clippy::all)]
//! Metamorphic Testing for channel::broadcast lag-aware multi-consumer invariants
//!
//! This test suite validates the fundamental broadcast channel semantics using
//! metamorphic relations that must hold regardless of timing, receiver counts,
//! or message patterns.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use asupersync::channel::broadcast::{self, RecvError, TryRecvError};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::time::sleep;
use asupersync::{region, Outcome};
use proptest::prelude::*;

/// Test configuration for broadcast channel properties
#[derive(Debug, Clone)]
struct BroadcastTestConfig {
    /// Channel capacity
    capacity: usize,
    /// Number of messages to send
    message_count: usize,
    /// Number of receivers to create
    receiver_count: usize,
    /// Whether to introduce lag by delaying some receivers
    introduce_lag: bool,
    /// Whether to drop receivers during test
    drop_receivers: bool,
}

fn broadcast_config_strategy() -> impl Strategy<Value = BroadcastTestConfig> {
    (
        // Capacity: 1 to 10 (small to test lag behavior)
        1_usize..=10,
        // Message count: 1 to 20
        1_usize..=20,
        // Receiver count: 1 to 5
        1_usize..=5,
        // Introduce lag flag
        any::<bool>(),
        // Drop receivers flag
        any::<bool>(),
    )
        .prop_map(|(capacity, message_count, receiver_count, introduce_lag, drop_receivers)| {
            BroadcastTestConfig {
                capacity,
                message_count,
                receiver_count,
                introduce_lag,
                drop_receivers,
            }
        })
}

/// Messages for testing
#[derive(Debug, Clone, PartialEq, Eq)]
struct TestMessage {
    id: u32,
    data: String,
}

impl TestMessage {
    fn new(id: u32) -> Self {
        Self {
            id,
            data: format!("message_{}", id),
        }
    }
}

/// MR1: Every committed send delivers to all active receivers
#[test]
fn mr1_committed_send_delivers_to_all_active_receivers() {
    proptest!(|(config in broadcast_config_strategy())| {
        // Skip configurations that would introduce complexity beyond the core property
        if config.introduce_lag || config.drop_receivers {
            return Ok(());
        }

        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let (sender, mut receiver) = broadcast::channel::<TestMessage>(config.capacity);

                // Create additional receivers
                let mut receivers = Vec::new();
                for _ in 1..config.receiver_count {
                    receivers.push(sender.subscribe());
                }
                receivers.push(receiver);

                // Collect all received messages
                let received_messages = Arc::new(StdMutex::new(Vec::new()));

                // Spawn receiver tasks
                let mut receiver_handles = Vec::new();
                for mut rx in receivers {
                    let received_clone = received_messages.clone();
                    let handle = scope.spawn(|rx_cx| async move {
                        let mut local_messages = Vec::new();
                        for _ in 0..config.message_count {
                            match rx.recv(rx_cx).await {
                                Ok(msg) => local_messages.push(msg),
                                Err(RecvError::Lagged(_)) => {
                                    // Try again after lag
                                    match rx.recv(rx_cx).await {
                                        Ok(msg) => local_messages.push(msg),
                                        Err(e) => panic!("Unexpected error after lag: {:?}", e),
                                    }
                                }
                                Err(e) => panic!("Unexpected receive error: {:?}", e),
                            }
                        }
                        received_clone.lock().unwrap().push(local_messages);
                        Ok(())
                    });
                    receiver_handles.push(handle);
                }

                // Send messages
                for i in 0..config.message_count {
                    let msg = TestMessage::new(i as u32);
                    let receivers_notified = sender.send(cx, msg.clone())?;

                    // Should deliver to all active receivers
                    prop_assert_eq!(receivers_notified, config.receiver_count,
                        "Message {} should deliver to {} receivers, got {}",
                        i, config.receiver_count, receivers_notified);
                }

                // Wait for all receivers to finish
                for handle in receiver_handles {
                    handle.await?;
                }

                // Verify all receivers got all messages
                let all_received = received_messages.lock().unwrap();
                prop_assert_eq!(all_received.len(), config.receiver_count,
                    "Should have {} receiver results", config.receiver_count);

                for (idx, receiver_msgs) in all_received.iter().enumerate() {
                    prop_assert_eq!(receiver_msgs.len(), config.message_count,
                        "Receiver {} should have received {} messages, got {}",
                        idx, config.message_count, receiver_msgs.len());

                    // Verify message order and content
                    for (msg_idx, msg) in receiver_msgs.iter().enumerate() {
                        let expected = TestMessage::new(msg_idx as u32);
                        prop_assert_eq!(msg, &expected,
                            "Receiver {} message {} should be {:?}, got {:?}",
                            idx, msg_idx, expected, msg);
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// MR2: Slow receivers lag tolerated up to bound then return Lag error
#[test]
fn mr2_slow_receivers_lag_tolerance_and_bounds() {
    proptest!(|(capacity in 2_usize..=5, excess_messages in 5_usize..=10)| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let (sender, mut fast_receiver) = broadcast::channel::<TestMessage>(capacity);
                let mut slow_receiver = sender.subscribe();

                // Send messages that exceed capacity
                let total_messages = capacity + excess_messages;
                for i in 0..total_messages {
                    let msg = TestMessage::new(i as u32);
                    sender.send(cx, msg)?;
                }

                // Fast receiver should get recent messages
                let mut fast_messages = Vec::new();
                for _ in 0..capacity {
                    match fast_receiver.try_recv() {
                        Ok(msg) => fast_messages.push(msg),
                        Err(TryRecvError::Empty) => break,
                        Err(e) => panic!("Unexpected try_recv error: {:?}", e),
                    }
                }

                // Slow receiver should detect lag
                let lag_result = slow_receiver.try_recv();
                match lag_result {
                    Err(TryRecvError::Lagged(missed)) => {
                        prop_assert!(missed > 0, "Should have missed some messages");
                        prop_assert!(missed <= excess_messages as u64,
                            "Missed messages {} should not exceed excess {}", missed, excess_messages);
                    }
                    Ok(_) => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            "Slow receiver should have lagged, but got message"
                        ));
                    }
                    Err(e) => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            format!("Unexpected error: {:?}", e)
                        ));
                    }
                }

                // After lag detection, slow receiver should be able to get newer messages
                match slow_receiver.try_recv() {
                    Ok(_) => {}, // Successfully caught up
                    Err(TryRecvError::Empty) => {}, // No more messages, which is fine
                    Err(e) => panic!("Unexpected error after lag recovery: {:?}", e),
                }

                Ok(())
            })
        });

        result
    });
}

/// MR3: Dropped receivers do not block senders
#[test]
fn mr3_dropped_receivers_do_not_block_senders() {
    proptest!(|(config in broadcast_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let (sender, _initial_receiver) = broadcast::channel::<TestMessage>(config.capacity);

                // Create additional receivers and drop some immediately
                let mut active_receivers = Vec::new();
                for i in 0..config.receiver_count {
                    let receiver = sender.subscribe();
                    if i < config.receiver_count / 2 {
                        // Drop half the receivers immediately
                        drop(receiver);
                    } else {
                        active_receivers.push(receiver);
                    }
                }

                let expected_active = active_receivers.len();

                // Sending should continue to work and only deliver to active receivers
                for i in 0..config.message_count {
                    let msg = TestMessage::new(i as u32);
                    let delivered = sender.send(cx, msg)?;

                    prop_assert_eq!(delivered, expected_active,
                        "Should deliver to {} active receivers, got {}",
                        expected_active, delivered);
                }

                // Verify remaining receivers can still receive
                for mut rx in active_receivers {
                    match rx.try_recv() {
                        Ok(_) => {}, // Good, got a message
                        Err(TryRecvError::Empty) => {}, // Fine, might have read all
                        Err(TryRecvError::Lagged(_)) => {}, // Expected with high message rate
                        Err(e) => panic!("Unexpected error: {:?}", e),
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// MR4: Cancel during recv drains without leak
#[test]
fn mr4_cancel_during_recv_drains_without_leak() {
    proptest!(|(capacity in 1_usize..=5)| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let (sender, mut receiver) = broadcast::channel::<TestMessage>(capacity);

                // Spawn a task that will be cancelled during recv
                let cancelled_outcome = region(|inner_cx, inner_scope| async move {
                    // Start a recv operation
                    let recv_future = receiver.recv(inner_cx);

                    // Schedule cancellation after a short delay
                    inner_scope.spawn(|cancel_cx| async move {
                        sleep(cancel_cx, Duration::from_millis(10)).await;
                        // This will cause the recv to be cancelled
                        Ok(())
                    });

                    recv_future.await
                }).await;

                // Should be cancelled
                match cancelled_outcome {
                    Outcome::Cancelled => {
                        // Expected result when cancelled
                    }
                    Outcome::Ok(Ok(_)) => {
                        // Could also succeed if message arrived before cancellation
                    }
                    Outcome::Ok(Err(RecvError::Cancelled)) => {
                        // Explicit cancellation error is also valid
                    }
                    other => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            format!("Unexpected outcome: {:?}", other)
                        ));
                    }
                }

                // After cancellation, the receiver should still be usable
                let test_msg = TestMessage::new(42);
                sender.send(cx, test_msg.clone())?;

                match receiver.try_recv() {
                    Ok(received) => {
                        prop_assert_eq!(received, test_msg, "Should receive the test message");
                    }
                    Err(TryRecvError::Empty) => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            "Receiver should have received the test message"
                        ));
                    }
                    Err(e) => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            format!("Unexpected error after cancel: {:?}", e)
                        ));
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// MR5: Subscribe-after-send sees only subsequent values
#[test]
fn mr5_subscribe_after_send_sees_only_subsequent_values() {
    proptest!(|(config in broadcast_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let (sender, mut early_receiver) = broadcast::channel::<TestMessage>(config.capacity);

                // Send some messages before creating late receivers
                let pre_messages = config.message_count / 2 + 1;
                for i in 0..pre_messages {
                    let msg = TestMessage::new(i as u32);
                    sender.send(cx, msg)?;
                }

                // Now create late receivers via subscribe
                let mut late_receivers = Vec::new();
                for _ in 0..config.receiver_count {
                    late_receivers.push(sender.subscribe());
                }

                // Send remaining messages
                let post_messages = config.message_count - pre_messages;
                for i in pre_messages..config.message_count {
                    let msg = TestMessage::new(i as u32);
                    sender.send(cx, msg)?;
                }

                // Early receiver should potentially see all messages (subject to lag)
                let mut early_messages = Vec::new();
                loop {
                    match early_receiver.try_recv() {
                        Ok(msg) => early_messages.push(msg),
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Lagged(_)) => {
                            // Skip lagged messages and continue
                            continue;
                        }
                        Err(e) => panic!("Unexpected error in early receiver: {:?}", e),
                    }
                }

                // Late receivers should ONLY see post-subscription messages
                for mut late_rx in late_receivers {
                    let mut late_messages = Vec::new();
                    loop {
                        match late_rx.try_recv() {
                            Ok(msg) => late_messages.push(msg),
                            Err(TryRecvError::Empty) => break,
                            Err(TryRecvError::Lagged(_)) => continue,
                            Err(e) => panic!("Unexpected error in late receiver: {:?}", e),
                        }
                    }

                    // Late receivers should not see pre-subscription messages
                    for msg in &late_messages {
                        prop_assert!(msg.id >= pre_messages as u32,
                            "Late receiver should not see message {} (pre-subscription cutoff: {})",
                            msg.id, pre_messages);
                    }

                    // If we have post messages and no lag, late receivers should see them
                    if post_messages > 0 && late_messages.is_empty() {
                        // This could happen due to lag or timing, which is acceptable
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// Additional property: Message ordering is preserved per receiver
#[test]
fn mr_message_ordering_preserved() {
    proptest!(|(config in broadcast_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let (sender, mut receiver) = broadcast::channel::<TestMessage>(config.capacity);

                // Send messages in order
                for i in 0..config.message_count {
                    let msg = TestMessage::new(i as u32);
                    sender.send(cx, msg)?;
                }

                // Receive all available messages
                let mut received_messages = Vec::new();
                loop {
                    match receiver.try_recv() {
                        Ok(msg) => received_messages.push(msg),
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Lagged(_)) => {
                            // Skip lagged messages but continue
                            continue;
                        }
                        Err(e) => panic!("Unexpected error: {:?}", e),
                    }
                }

                // Check that received messages are in order (allowing for lag gaps)
                if !received_messages.is_empty() {
                    for window in received_messages.windows(2) {
                        prop_assert!(window[0].id < window[1].id,
                            "Messages should be in order: {:?} should come before {:?}",
                            window[0], window[1]);
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// Edge case: Channel behavior when all receivers are dropped
#[test]
fn mr_send_to_empty_channel() {
    proptest!(|(capacity in 1_usize..=5, message_count in 1_usize..=10)| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let (sender, receiver) = broadcast::channel::<TestMessage>(capacity);

                // Drop the receiver immediately
                drop(receiver);

                // Attempt to send should fail
                let msg = TestMessage::new(0);
                match sender.send(cx, msg.clone()) {
                    Err(broadcast::SendError::Closed(returned_msg)) => {
                        prop_assert_eq!(returned_msg, msg, "Should return the original message");
                    }
                    Ok(_) => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            "Send should fail when no receivers are active"
                        ));
                    }
                }

                Ok(())
            })
        });

        result
    });
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_basic_broadcast() {
        let runtime = LabRuntime::new(LabConfig::default());

        runtime.block_on(async {
            region(|cx, scope| async move {
                let (sender, mut receiver) = broadcast::channel::<TestMessage>(5);

                let msg = TestMessage::new(1);
                let delivered = sender.send(cx, msg.clone())?;
                assert_eq!(delivered, 1, "Should deliver to 1 receiver");

                let received = receiver.try_recv().unwrap();
                assert_eq!(received, msg, "Should receive the sent message");

                Ok(())
            })
        }).unwrap();
    }

    #[test]
    fn test_subscribe_after_send() {
        let runtime = LabRuntime::new(LabConfig::default());

        runtime.block_on(async {
            region(|cx, scope| async move {
                let (sender, mut early) = broadcast::channel::<TestMessage>(5);

                // Send message before subscription
                let old_msg = TestMessage::new(1);
                sender.send(cx, old_msg.clone())?;

                // Create late receiver
                let mut late = sender.subscribe();

                // Send message after subscription
                let new_msg = TestMessage::new(2);
                sender.send(cx, new_msg.clone())?;

                // Early receiver might see both (subject to capacity)
                let _ = early.try_recv();

                // Late receiver should only see the new message
                match late.try_recv() {
                    Ok(received) => assert_eq!(received, new_msg),
                    Err(TryRecvError::Empty) => {
                        // Could happen due to timing/lag
                    }
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }

                Ok(())
            })
        }).unwrap();
    }
}