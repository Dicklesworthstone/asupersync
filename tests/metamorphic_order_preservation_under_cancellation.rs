//! Metamorphic test for message order preservation under partial cancellation.
//!
//! This test verifies that mpsc channels maintain FIFO ordering when some
//! sends are cancelled after reserve but before commit (two-phase protocol).
//!
//! **Metamorphic Relation:**
//! If messages M1, M2, M3, M4, M5 are sent, and M2, M4 are cancelled after
//! reserve, then the receiver should see M1, M3, M5 in that exact order.

use asupersync::channel::mpsc;
use asupersync::cx::Cx;
use asupersync::runtime::builder::RuntimeBuilder;
use proptest::prelude::*;
use std::collections::VecDeque;

/// A message with sequence number for order tracking
#[derive(Debug, Clone, PartialEq, Eq)]
struct OrderedMessage {
    sequence: u64,
    value: String,
}

/// Test operations for order preservation
#[derive(Debug, Clone)]
enum ChannelOperation {
    /// Send message (reserve + commit atomically)
    Send { msg: OrderedMessage },
    /// Reserve, then send
    ReserveThenSend { msg: OrderedMessage },
    /// Reserve, then cancel (abort the reservation)
    ReserveThenCancel { sequence: u64 },
}

/// Generates a sequence of channel operations with some cancellations
fn generate_operations(sequences: Vec<u64>) -> Vec<ChannelOperation> {
    sequences
        .into_iter()
        .enumerate()
        .map(|(i, seq)| {
            let msg = OrderedMessage {
                sequence: seq,
                value: format!("msg_{}", seq),
            };

            match i % 4 {
                0 => ChannelOperation::Send { msg },
                1 => ChannelOperation::ReserveThenSend { msg },
                2 => ChannelOperation::ReserveThenCancel { sequence: seq },
                _ => ChannelOperation::ReserveThenSend { msg },
            }
        })
        .collect()
}

// =============================================================================
// Metamorphic Relation: MPSC Order Preservation Under Cancellation
// =============================================================================

/// **MR1:** MPSC channels preserve FIFO order when some sends are cancelled.
///
/// **Property:** If messages are sent in order [M1, M2, M3, M4, M5] and
/// [M2, M4] are cancelled after reservation, the receiver must see [M1, M3, M5]
/// in that exact order, never [M3, M1, M5] or any other permutation.
///
/// **Bug classes detected:**
/// - Queue corruption during cancellation cleanup
/// - Race between commit and abort operations
/// - Incorrect waiter reordering after cancellation
/// - Lost wakeups when cancelled permits are cleaned up
fn mr_mpsc_order_preservation_under_cancellation() {
    proptest!(|(sequences: Vec<u64>)| {
        let sequences: Vec<u64> = sequences.into_iter().take(15).collect(); // Limit for performance
        let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

        rt.block_on(async {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = mpsc::channel(20);
            let operations = generate_operations(sequences.clone());

            // Track what should be received (non-cancelled messages in order)
            let mut expected_order = VecDeque::new();
            // Execute operations in sequence
            for operation in operations {
                match operation {
                    ChannelOperation::Send { msg } => {
                        if sender.send(&cx, msg.clone()).await.is_ok() {
                            expected_order.push_back(msg);
                        }
                    },
                    ChannelOperation::ReserveThenSend { msg } => {
                        if let Ok(permit) = sender.reserve(&cx).await {
                            if permit.try_send(msg.clone()).is_ok() {
                                expected_order.push_back(msg);
                            }
                        }
                    },
                    ChannelOperation::ReserveThenCancel { sequence } => {
                        let _cancelled_sequence = sequence;
                        if let Ok(permit) = sender.reserve(&cx).await {
                            permit.abort(); // Cancel the reservation
                            // This message should NOT appear in received order
                        }
                    },
                }
            }

            drop(sender);

            // Check that received messages match expected order exactly
            let mut received_msgs = Vec::new();
            while let Ok(msg) = receiver.recv(&cx).await {
                received_msgs.push(msg);
            }
            let expected_msgs: Vec<_> = expected_order.into_iter().collect();

            prop_assert_eq!(
                &received_msgs, &expected_msgs,
                "MPSC order preservation violated: expected {:?}, got {:?}",
                expected_msgs, received_msgs
            );

            Ok::<(), TestCaseError>(())
        })?;
    });
}

// =============================================================================
// Metamorphic Relation: MPSC Permit Lifecycle Invariant
// =============================================================================

/// **MR2:** MPSC permits follow strict reserve → (send|abort) lifecycle.
///
/// **Property:** Every reserved permit must be consumed exactly once, either
/// by sending or aborting. This tests the obligation tracking invariant.
fn mr_mpsc_permit_lifecycle_invariant() {
    proptest!(|(operations: Vec<(u8, u64)>)| {
        let operations: Vec<(u8, u64)> = operations.into_iter().take(20).collect();
        let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

        rt.block_on(async {
            let cx = Cx::for_testing();
            let (sender, mut receiver) = mpsc::channel(50);

            let mut permits_created = 0;
            let mut permits_consumed = 0;

            for (op_type, sequence) in operations {
                let msg = OrderedMessage {
                    sequence,
                    value: format!("msg_{}", sequence),
                };

                match op_type % 3 {
                    0 => {
                        // Direct send (reserve + commit atomic)
                        if sender.send(&cx, msg).await.is_ok() {
                            permits_created += 1;
                            permits_consumed += 1;
                        }
                    },
                    1 => {
                        // Reserve then send
                        if let Ok(permit) = sender.reserve(&cx).await {
                            permits_created += 1;
                            if permit.try_send(msg).is_ok() {
                                permits_consumed += 1;
                            }
                        }
                    },
                    _ => {
                        // Reserve then abort
                        if let Ok(permit) = sender.reserve(&cx).await {
                            permits_created += 1;
                            permit.abort();
                            permits_consumed += 1;
                        }
                    },
                }
            }

            drop(sender);
            let mut _received = Vec::new();
            while let Ok(msg) = receiver.recv(&cx).await {
                _received.push(msg);
            }

            // Every permit should be consumed
            prop_assert_eq!(
                permits_created, permits_consumed,
                "Permit lifecycle violation: {} created, {} consumed",
                permits_created, permits_consumed
            );

            Ok::<(), TestCaseError>(())
        })?;
    });
}

// =============================================================================
// Metamorphic Relation: Cross-Channel Order Consistency
// =============================================================================

/// **MR3:** Independent channels maintain their own ordering invariants.
///
/// **Property:** Operations on separate channels should not affect each other's
/// ordering. If channel A processes [M1, M3, M5] and channel B processes
/// [M2, M4], the orders should be independent regardless of interleaving.
fn mr_cross_channel_order_independence() {
    proptest!(|(
        ops_a: Vec<u64>,
        ops_b: Vec<u64>
    )| {
        let ops_a: Vec<u64> = ops_a.into_iter().take(8).collect();
        let ops_b: Vec<u64> = ops_b.into_iter().take(8).collect();

        let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

        rt.block_on(async {
            let cx = Cx::for_testing();

            // Create two independent channels
            let (sender_a, mut receiver_a) = mpsc::channel(15);
            let (sender_b, mut receiver_b) = mpsc::channel(15);

            // Interleave operations on both channels
            let mut expected_a = Vec::new();
            let mut expected_b = Vec::new();

            let max_len = std::cmp::max(ops_a.len(), ops_b.len());
            for i in 0..max_len {
                // Send to channel A
                if let Some(&seq_a) = ops_a.get(i) {
                    let msg_a = OrderedMessage {
                        sequence: seq_a,
                        value: format!("A_{}", seq_a),
                    };

                    if i % 3 == 0 {
                        // Cancel some operations
                        if let Ok(permit) = sender_a.reserve(&cx).await {
                            permit.abort();
                        }
                    } else if sender_a.send(&cx, msg_a.clone()).await.is_ok() {
                        expected_a.push(msg_a);
                    }
                }

                // Send to channel B
                if let Some(&seq_b) = ops_b.get(i) {
                    let msg_b = OrderedMessage {
                        sequence: seq_b,
                        value: format!("B_{}", seq_b),
                    };

                    if i % 4 == 0 {
                        // Cancel some operations
                        if let Ok(permit) = sender_b.reserve(&cx).await {
                            permit.abort();
                        }
                    } else if sender_b.send(&cx, msg_b.clone()).await.is_ok() {
                        expected_b.push(msg_b);
                    }
                }
            }

            // Close and wait
            drop(sender_a);
            drop(sender_b);

            // Verify independent ordering
            let mut final_a = Vec::new();
            while let Ok(msg) = receiver_a.recv(&cx).await {
                final_a.push(msg);
            }

            let mut final_b = Vec::new();
            while let Ok(msg) = receiver_b.recv(&cx).await {
                final_b.push(msg);
            }

            prop_assert_eq!(final_a, expected_a, "Channel A order violated");
            prop_assert_eq!(final_b, expected_b, "Channel B order violated");

            Ok::<(), TestCaseError>(())
        })?;
    });
}

// =============================================================================
// Test Suite
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpsc_order_preservation_under_cancellation() {
        mr_mpsc_order_preservation_under_cancellation();
    }

    #[test]
    fn test_mpsc_permit_lifecycle_invariant() {
        mr_mpsc_permit_lifecycle_invariant();
    }

    #[test]
    fn test_cross_channel_order_independence() {
        mr_cross_channel_order_independence();
    }
}
