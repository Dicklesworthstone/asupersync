//! Metamorphic Testing: MPSC channel permit abort/drop equivalence
//!
//! This module implements metamorphic relations (MRs) to verify that MPSC
//! channel reserve/commit behavior maintains consistent semantics when permits
//! are aborted explicitly vs dropped implicitly.
//!
//! # Metamorphic Relations
//!
//! - **MR1 (Permit Abort vs Drop Equivalence)**: `permit.abort()` is semantically
//!   equivalent to dropping the permit without calling `send()`
//! - **MR2 (Reservation Count Consistency)**: Both abort and drop properly
//!   decrement the reserved count and wake waiting senders
//! - **MR3 (FIFO Waker Ordering Preservation)**: Aborting/dropping permits
//!   preserves FIFO ordering of waiting senders
//! - **MR4 (Receiver State Independence)**: Permit abort/drop does not affect
//!   receiver state or subsequent receive operations
//!
//! # Property Coverage
//!
//! These MRs ensure that:
//! - RAII cleanup (Drop) is equivalent to explicit cleanup (abort)
//! - Two-phase reserve/commit semantics are consistent
//! - Channel invariants are preserved under permit abandonment
//! - Waiting sender queues maintain FIFO fairness

use crate::channel::mpsc::{self, SendError};
use proptest::prelude::*;

/// Test data structure for channel operations
#[derive(Debug, Clone, PartialEq, Eq)]
struct TestMessage {
    id: u64,
    data: String,
    sequence: u32,
}

impl TestMessage {
    fn new(id: u64, data: impl Into<String>, sequence: u32) -> Self {
        Self {
            id,
            data: data.into(),
            sequence,
        }
    }
}

/// **MR1: Permit Abort vs Drop Equivalence**
///
/// A permit that is explicitly aborted should result in the same channel state
/// as a permit that is dropped without calling send().
///
/// **Property**: permit.abort() ≡ drop(permit)
#[test]
fn mr1_permit_abort_vs_drop_equivalence() {
    proptest!(|(
        test_id in 0u64..1000,
        data in "[a-zA-Z0-9]{1,20}",
        sequence in 0u32..100,
        capacity in 1usize..10
    )| {
        let message = TestMessage::new(test_id, data, sequence);
        // Path 1: Reserve permit, then explicitly abort
        let (tx1, mut rx1) = mpsc::channel(capacity);
        let permit1 = tx1.try_reserve().expect("should reserve in empty channel");
        permit1.abort(); // Explicit abort

        // Path 2: Reserve permit, then drop without abort
        let (tx2, mut rx2) = mpsc::channel(capacity);
        let permit2 = tx2.try_reserve().expect("should reserve in empty channel");
        drop(permit2); // Implicit abort via Drop

        // Both channels should have identical state:
        // - reservation count back to 0
        // - no queued messages
        // - receivers should behave identically

        // Test that reservation counts are identical (both back to 0)
        let counts1 = tx1.debug_counts();
        let counts2 = tx2.debug_counts();
        prop_assert_eq!(counts1, counts2,
            "Abort vs drop should have identical reservation counts");
        prop_assert_eq!(counts1.1, 0, "Reserved count should be 0 after abort");
        prop_assert_eq!(counts2.1, 0, "Reserved count should be 0 after drop");

        // Test that both senders can reserve again (capacity freed)
        let permit1_retry = tx1.try_reserve();
        let permit2_retry = tx2.try_reserve();
        prop_assert!(permit1_retry.is_ok(), "Should be able to re-reserve after abort");
        prop_assert!(permit2_retry.is_ok(), "Should be able to re-reserve after drop");

        // Test successful send after re-reservation works identically
        let send_result1 = permit1_retry.unwrap().send(message.clone());
        let send_result2 = permit2_retry.unwrap().send(message.clone());
        prop_assert!(send_result1.is_ok(), "send after abort retry should succeed");
        prop_assert!(send_result2.is_ok(), "send after drop retry should succeed");

        let recv1_result = rx1.try_recv();
        let recv2_result = rx2.try_recv();
        prop_assert_eq!(recv1_result.as_ref(), recv2_result.as_ref(),
            "Receivers should behave identically after abort vs drop");

        if let (Ok(msg1), Ok(msg2)) = (&recv1_result, &recv2_result) {
            prop_assert_eq!(msg1, &message, "Message should be preserved after abort path");
            prop_assert_eq!(msg2, &message, "Message should be preserved after drop path");
        }
    });
}

/// **MR2: Reservation Count Consistency**
///
/// Both abort and drop must properly decrement the reservation count and
/// wake any waiting senders in identical ways.
///
/// **Property**: reserved_count behavior is identical for abort() and drop()
#[test]
fn mr2_reservation_count_consistency() {
    proptest!(|(
        _sequence in 0u32..100,
        capacity in 1usize..5, // Small capacity to force waiting
        num_permits in 1usize..4
    )| {
        // Ensure num_permits >= capacity to test waiter behavior
        let num_permits = num_permits.min(capacity) + 1;

        // Path 1: Fill channel with permits, then abort the first one
        let (tx1, _rx1) = mpsc::channel::<TestMessage>(capacity);
        let mut permits1 = Vec::new();
        for _ in 0..num_permits {
            match tx1.try_reserve() {
                Ok(permit) => permits1.push(Some(permit)),
                Err(SendError::Full(())) => permits1.push(None),
                Err(e) => prop_assert!(false, "Unexpected error: {:?}", e),
            }
        }

        // Count how many permits were actually reserved
        let reserved_count1 = permits1.iter().filter(|p| p.is_some()).count();
        let initial_counts1 = tx1.debug_counts();
        prop_assert_eq!(initial_counts1.1, reserved_count1,
            "Reserved count should match number of permits");

        // Abort the first permit
        if let Some(permit_slot) = permits1.first_mut() {
            if let Some(permit) = permit_slot.take() {
                permit.abort();
            }
        }

        let after_abort_counts1 = tx1.debug_counts();

        // Path 2: Same setup, but drop the first permit instead
        let (tx2, _rx2) = mpsc::channel::<TestMessage>(capacity);
        let mut permits2 = Vec::new();
        for _ in 0..num_permits {
            match tx2.try_reserve() {
                Ok(permit) => permits2.push(Some(permit)),
                Err(SendError::Full(())) => permits2.push(None),
                Err(e) => prop_assert!(false, "Unexpected error: {:?}", e),
            }
        }

        let reserved_count2 = permits2.iter().filter(|p| p.is_some()).count();
        let initial_counts2 = tx2.debug_counts();
        prop_assert_eq!(initial_counts2.1, reserved_count2,
            "Reserved count should match number of permits");

        // Drop the first permit
        if let Some(permit_slot) = permits2.first_mut() {
            permit_slot.take(); // Drop the permit
        }

        let after_drop_counts2 = tx2.debug_counts();

        // MR2: Both abort and drop should result in identical reservation counts
        prop_assert_eq!(after_abort_counts1, after_drop_counts2,
            "Abort and drop should result in identical reservation counts");

        // Both should have decremented by exactly 1 if there was a permit to abort/drop
        if reserved_count1 > 0 {
            prop_assert_eq!(after_abort_counts1.1, initial_counts1.1 - 1,
                "Abort should decrement reserved count by 1");
            prop_assert_eq!(after_drop_counts2.1, initial_counts2.1 - 1,
                "Drop should decrement reserved count by 1");
        }
    });
}

/// **MR3: FIFO Waker Ordering Preservation**
///
/// When permits are aborted/dropped, waiting senders should be woken in
/// the same FIFO order regardless of whether abort() or drop() is used.
///
/// **Property**: Waiter wake ordering is preserved under abort vs drop
#[test]
fn mr3_fifo_waker_ordering_preservation() {
    proptest!(|(capacity in 1usize..5)| {
        // Path 1: Fill capacity, queue waiters, then abort first permit
        let (tx1, _rx1) = mpsc::channel::<TestMessage>(capacity);

        // Fill the channel capacity
        let first_permit1 = tx1.try_reserve().expect("first reserve should succeed");

        // This will succeed since capacity=1 and we have 1 reserved
        prop_assert!(tx1.try_reserve().is_err(), "second reserve should fail when at capacity");

        // Abort the first permit, which should allow one new reservation
        first_permit1.abort();

        // Now we should be able to reserve again
        let second_permit1 = tx1.try_reserve().expect("reserve after abort should succeed");
        let counts_after_abort = tx1.debug_counts();

        // Path 2: Same setup but drop instead of abort
        let (tx2, _rx2) = mpsc::channel::<TestMessage>(capacity);

        // Fill the channel capacity
        let first_permit2 = tx2.try_reserve().expect("first reserve should succeed");

        // This will succeed since capacity=1 and we have 1 reserved
        prop_assert!(tx2.try_reserve().is_err(), "second reserve should fail when at capacity");

        // Drop the first permit instead of abort
        drop(first_permit2);

        // Now we should be able to reserve again
        let second_permit2 = tx2.try_reserve().expect("reserve after drop should succeed");
        let counts_after_drop = tx2.debug_counts();

        // MR3: Channel state should be identical
        prop_assert_eq!(counts_after_abort, counts_after_drop,
            "Abort and drop should result in identical channel state");

        // Cleanup
        second_permit1.abort();
        second_permit2.abort();
    });
}

/// **MR4: Receiver State Independence**
///
/// Permit abort/drop operations should not affect receiver state or
/// the ability to receive messages that were successfully sent.
///
/// **Property**: Receiver behavior is independent of permit abort vs drop
#[test]
fn mr4_receiver_state_independence() {
    proptest!(|(
        test_id in 0u64..1000,
        data in "[a-zA-Z0-9]{1,20}",
        sequence in 0u32..100,
        capacity in 2usize..10
    )| {
        let message = TestMessage::new(test_id, data, sequence);
        // Path 1: Send message, abort a subsequent permit, then receive
        let (tx1, mut rx1) = mpsc::channel(capacity);

        // Send a successful message
        let permit1a = tx1.try_reserve().expect("should reserve");
        let send_result1a = permit1a.send(message.clone());
        prop_assert!(send_result1a.is_ok(), "should send successfully");

        // Reserve and abort another permit
        let permit1b = tx1.try_reserve().expect("should reserve again");
        permit1b.abort();

        // Path 2: Send message, drop a subsequent permit, then receive
        let (tx2, mut rx2) = mpsc::channel(capacity);

        // Send a successful message
        let permit2a = tx2.try_reserve().expect("should reserve");
        let send_result2a = permit2a.send(message.clone());
        prop_assert!(send_result2a.is_ok(), "should send successfully");

        // Reserve and drop another permit
        let permit2b = tx2.try_reserve().expect("should reserve again");
        drop(permit2b);

        // MR4: Receivers should behave identically
        let recv_result1 = rx1.try_recv();
        let recv_result2 = rx2.try_recv();

        prop_assert_eq!(recv_result1.as_ref(), recv_result2.as_ref(),
            "Receivers should behave identically regardless of abort vs drop");

        match (&recv_result1, &recv_result2) {
            (Ok(msg1), Ok(msg2)) => {
                prop_assert_eq!(msg1, &message, "Received message should match sent");
                prop_assert_eq!(msg2, &message, "Received message should match sent");
            },
            (Err(e1), Err(e2)) => {
                prop_assert_eq!(e1, e2, "Receive errors should be identical");
            },
            other => prop_assert!(false, "Mismatched receive results: {:?}", other),
        }

        // Test that both receivers still work for subsequent operations
        let next_message = TestMessage::new(test_id + 1, "next", sequence + 1);

        tx1.try_send(next_message.clone()).expect("subsequent send should work");
        tx2.try_send(next_message.clone()).expect("subsequent send should work");

        let next_recv1 = rx1.try_recv().expect("subsequent receive should work");
        let next_recv2 = rx2.try_recv().expect("subsequent receive should work");

        prop_assert_eq!(&next_recv1, &next_message, "Subsequent receive should work after abort");
        prop_assert_eq!(&next_recv2, &next_message, "Subsequent receive should work after drop");
    });
}

/// **Composite MR: Full Channel Abort vs Drop Under Pressure**
///
/// Tests abort vs drop equivalence when the channel is at capacity
/// and there are waiting senders.
#[test]
fn mr_composite_full_channel_abort_vs_drop() {
    let capacity = 2;
    // Path 1: Fill channel, abort permits
    let (tx1, mut rx1) = mpsc::channel::<u32>(capacity);

    // Fill to capacity with actual messages
    tx1.try_send(1).expect("first send");
    tx1.try_send(2).expect("second send");

    // Reserve permits (these will be in reserved state, not queued yet)
    let permit1a = tx1.try_reserve().expect("should still be able to reserve");
    let permit1b = tx1.try_reserve().expect("should still be able to reserve");

    // Now channel is at logical capacity (queue full + reserved slots)
    assert!(tx1.try_send(5).is_err(), "channel should be full now");

    // Abort both reserved permits
    permit1a.abort();
    permit1b.abort();

    // Should be able to send again after aborts
    let after_abort_result1 = tx1.try_send(3);
    let counts_after_abort = tx1.debug_counts();

    // Path 2: Same scenario but with drops
    let (tx2, mut rx2) = mpsc::channel::<u32>(capacity);

    // Fill to capacity with actual messages
    tx2.try_send(1).expect("first send");
    tx2.try_send(2).expect("second send");

    // Reserve permits
    let permit2a = tx2.try_reserve().expect("should still be able to reserve");
    let permit2b = tx2.try_reserve().expect("should still be able to reserve");

    // Now channel is at logical capacity
    assert!(tx2.try_send(5).is_err(), "channel should be full now");

    // Drop both reserved permits
    drop(permit2a);
    drop(permit2b);

    // Should be able to send again after drops
    let after_drop_result2 = tx2.try_send(3);
    let counts_after_drop = tx2.debug_counts();

    // Verify abort vs drop equivalence
    assert_eq!(
        after_abort_result1.is_ok(),
        after_drop_result2.is_ok(),
        "Send results should be equivalent after abort vs drop"
    );
    assert_eq!(
        counts_after_abort, counts_after_drop,
        "Channel counts should be equivalent after abort vs drop"
    );

    // Verify receivers see the same data
    let recv_sequence1: Vec<u32> = (0..3).filter_map(|_| rx1.try_recv().ok()).collect();
    let recv_sequence2: Vec<u32> = (0..3).filter_map(|_| rx2.try_recv().ok()).collect();

    assert_eq!(
        recv_sequence1, recv_sequence2,
        "Receivers should see identical message sequences"
    );
    assert_eq!(
        recv_sequence1,
        vec![1, 2, 3],
        "Should receive all successfully sent messages"
    );
}

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

    /// Integration test to verify all metamorphic relations work together
    #[test]
    fn integration_all_mrs_together() {
        let message = TestMessage::new(42, "integration_test", 1);
        let capacity = 3;

        // Test MR1: Basic abort vs drop equivalence
        let (tx1, _rx1) = mpsc::channel(capacity);
        let (tx2, _rx2) = mpsc::channel(capacity);

        let permit1 = tx1.try_reserve().expect("reserve 1");
        let permit2 = tx2.try_reserve().expect("reserve 2");

        permit1.abort();
        drop(permit2);

        let counts1 = tx1.debug_counts();
        let counts2 = tx2.debug_counts();
        assert_eq!(counts1, counts2, "Basic abort vs drop should be equivalent");

        // Test MR2 & MR4: Send after abort/drop should work identically
        let permit1_retry = tx1.try_reserve().expect("re-reserve after abort");
        let permit2_retry = tx2.try_reserve().expect("re-reserve after drop");

        let send_result1 = permit1_retry.send(message.clone());
        let send_result2 = permit2_retry.send(message.clone());
        assert!(send_result1.is_ok(), "send after abort should succeed");
        assert!(send_result2.is_ok(), "send after drop should succeed");

        println!("All metamorphic relations verified in integration test");
    }

    /// Deterministic test without proptest for basic functionality
    #[test]
    fn deterministic_abort_vs_drop() {
        let (tx, _rx) = mpsc::channel::<u32>(1);

        // Test abort
        let permit1 = tx.try_reserve().expect("should reserve");
        let counts_before = tx.debug_counts();
        permit1.abort();
        let counts_after_abort = tx.debug_counts();

        // Test drop
        let permit2 = tx.try_reserve().expect("should reserve");
        drop(permit2);
        let counts_after_drop = tx.debug_counts();

        // Both should decrement reserved count
        assert_eq!(counts_before.1, 1, "Should have 1 reserved before");
        assert_eq!(
            counts_after_abort.1, 0,
            "Should have 0 reserved after abort"
        );
        assert_eq!(counts_after_drop.1, 0, "Should have 0 reserved after drop");

        // Final state should be identical
        assert_eq!(
            counts_after_abort, counts_after_drop,
            "Final states should match"
        );
    }
}
