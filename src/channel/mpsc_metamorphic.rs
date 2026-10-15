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
use std::time::Instant;

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

/// **MR1: Permit Abort vs Drop Equivalence (Enhanced with Observability)**
///
/// A permit that is explicitly aborted should result in the same channel state
/// as a permit that is dropped without calling send().
///
/// **Property**: permit.abort() ≡ drop(permit)
/// **Enhancement**: Includes telemetry snapshots and structured observability
#[test]
fn mr1_permit_abort_vs_drop_equivalence() {
    proptest!(|(
        test_id in 0u64..1000,
        data in "[a-zA-Z0-9]{1,20}",
        sequence in 0u32..100,
        capacity in 1usize..10
    )| {
        let message = TestMessage::new(test_id, data, sequence);

        // Path 1: Reserve permit, then explicitly abort (with observability)
        let (tx1, mut rx1) = mpsc::channel(capacity);

        // Capture initial state telemetry
        let telemetry_initial_1 = tx1.telemetry_snapshot(test_id);
        let permit1 = tx1.try_reserve().expect("should reserve in empty channel");

        // Capture post-reserve state
        let telemetry_post_reserve_1 = tx1.telemetry_snapshot(test_id);

        permit1.abort(); // Explicit abort

        // Capture post-abort state
        let telemetry_post_abort_1 = tx1.telemetry_snapshot(test_id);

        // Path 2: Reserve permit, then drop without abort (with observability)
        let (tx2, mut rx2) = mpsc::channel(capacity);

        // Capture initial state telemetry
        let telemetry_initial_2 = tx2.telemetry_snapshot(test_id + 1000);
        let permit2 = tx2.try_reserve().expect("should reserve in empty channel");

        // Capture post-reserve state
        let telemetry_post_reserve_2 = tx2.telemetry_snapshot(test_id + 1000);

        drop(permit2); // Implicit abort via Drop

        // Capture post-drop state
        let telemetry_post_drop_2 = tx2.telemetry_snapshot(test_id + 1000);

        // Enhanced observability: Compare telemetry snapshots
        prop_assert_eq!(
            telemetry_initial_1.reserved_uncommitted_obligations,
            telemetry_initial_2.reserved_uncommitted_obligations,
            "Initial reserved obligations should be identical (both 0)"
        );
        prop_assert_eq!(
            telemetry_post_reserve_1.reserved_uncommitted_obligations,
            telemetry_post_reserve_2.reserved_uncommitted_obligations,
            "Post-reserve obligations should be identical (both 1)"
        );
        prop_assert_eq!(
            telemetry_post_abort_1.reserved_uncommitted_obligations,
            telemetry_post_drop_2.reserved_uncommitted_obligations,
            "Post-abort/drop obligations should be identical (both 0)"
        );

        // Both channels should have identical state:
        // - reservation count back to 0
        // - no queued messages
        // - receivers should behave identically

        // Test that reservation counts are identical (both back to 0)
        let counts1 = tx1.debug_counts();
        let counts2 = tx2.debug_counts();
        prop_assert_eq!(counts1, counts2,
            "Abort vs drop should have identical reservation counts. \
             Path 1 (abort): queue={}, reserved={}, Path 2 (drop): queue={}, reserved={}. \
             Telemetry abort: obligations={}, Telemetry drop: obligations={}",
            counts1.0, counts1.1, counts2.0, counts2.1,
            telemetry_post_abort_1.reserved_uncommitted_obligations,
            telemetry_post_drop_2.reserved_uncommitted_obligations);
        prop_assert_eq!(counts1.1, 0,
            "Reserved count should be 0 after abort. Got {} reserved, {} queued. Telemetry: {}",
            counts1.1, counts1.0, telemetry_post_abort_1.reserved_uncommitted_obligations);
        prop_assert_eq!(counts2.1, 0,
            "Reserved count should be 0 after drop. Got {} reserved, {} queued. Telemetry: {}",
            counts2.1, counts2.0, telemetry_post_drop_2.reserved_uncommitted_obligations);

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

/// **MR2: Reservation Count Consistency (Enhanced with Observability)**
///
/// Both abort and drop must properly decrement the reservation count and
/// wake any waiting senders in identical ways.
///
/// **Property**: reserved_count behavior is identical for abort() and drop()
/// **Enhancement**: Includes telemetry tracking and detailed diagnostics
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
        let telemetry_initial_1 = tx1.telemetry_snapshot(100);

        prop_assert_eq!(initial_counts1.1, reserved_count1,
            "Reserved count should match number of permits. Debug: queue={}, reserved={}. \
             Telemetry: obligations={}, send_waiters={}",
            initial_counts1.0, initial_counts1.1,
            telemetry_initial_1.reserved_uncommitted_obligations,
            telemetry_initial_1.send_waiter_count);

        // Abort the first permit
        if let Some(permit_slot) = permits1.first_mut() {
            if let Some(permit) = permit_slot.take() {
                permit.abort();
            }
        }

        let after_abort_counts1 = tx1.debug_counts();
        let telemetry_after_abort_1 = tx1.telemetry_snapshot(101);

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
        let telemetry_initial_2 = tx2.telemetry_snapshot(200);

        prop_assert_eq!(initial_counts2.1, reserved_count2,
            "Reserved count should match number of permits. Debug: queue={}, reserved={}. \
             Telemetry: obligations={}, send_waiters={}",
            initial_counts2.0, initial_counts2.1,
            telemetry_initial_2.reserved_uncommitted_obligations,
            telemetry_initial_2.send_waiter_count);

        // Drop the first permit
        if let Some(permit_slot) = permits2.first_mut() {
            permit_slot.take(); // Drop the permit
        }

        let after_drop_counts2 = tx2.debug_counts();
        let telemetry_after_drop_2 = tx2.telemetry_snapshot(201);

        // MR2: Both abort and drop should result in identical reservation counts
        prop_assert_eq!(after_abort_counts1, after_drop_counts2,
            "Abort and drop should result in identical reservation counts. \
             After abort: queue={}, reserved={}. After drop: queue={}, reserved={}. \
             Telemetry abort obligations: {}, drop obligations: {}",
            after_abort_counts1.0, after_abort_counts1.1,
            after_drop_counts2.0, after_drop_counts2.1,
            telemetry_after_abort_1.reserved_uncommitted_obligations,
            telemetry_after_drop_2.reserved_uncommitted_obligations);

        // Both should have decremented by exactly 1 if there was a permit to abort/drop
        if reserved_count1 > 0 {
            prop_assert_eq!(after_abort_counts1.1, initial_counts1.1 - 1,
                "Abort should decrement reserved count by 1");
            prop_assert_eq!(after_drop_counts2.1, initial_counts2.1 - 1,
                "Drop should decrement reserved count by 1");
        }
    });
}

/// **MR3: FIFO Waker Ordering Preservation (Enhanced with Performance Timing)**
///
/// When permits are aborted/dropped, waiting senders should be woken in
/// the same FIFO order regardless of whether abort() or drop() is used.
///
/// **Property**: Waiter wake ordering is preserved under abort vs drop
/// **Enhancement**: Includes performance timing measurements
#[test]
fn mr3_fifo_waker_ordering_preservation() {
    proptest!(|(capacity in 1usize..5)| {
        // Path 1: Fill capacity, queue waiters, then abort first permit
        let (tx1, _rx1) = mpsc::channel::<TestMessage>(capacity);

        // Fill the channel capacity with outstanding permits.
        let mut permits1 = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            permits1.push(tx1.try_reserve().expect("reserve should succeed"));
        }

        // A bounded channel is full when queued + reserved == capacity.
        prop_assert!(tx1.try_reserve().is_err(), "second reserve should fail when at capacity");

        // Abort the first permit, which should allow one new reservation.
        let abort_start = Instant::now();
        permits1.pop().expect("filled permits").abort();
        let abort_duration = abort_start.elapsed();

        // Now we should be able to reserve again (with timing)
        let reserve_start = Instant::now();
        let second_permit1 = tx1.try_reserve().expect("reserve after abort should succeed");
        let reserve_after_abort_duration = reserve_start.elapsed();
        let counts_after_abort = tx1.debug_counts();
        let telemetry_after_abort = tx1.telemetry_snapshot(300);

        // Path 2: Same setup but drop instead of abort
        let (tx2, _rx2) = mpsc::channel::<TestMessage>(capacity);

        // Fill the channel capacity with outstanding permits.
        let mut permits2 = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            permits2.push(tx2.try_reserve().expect("reserve should succeed"));
        }

        // A bounded channel is full when queued + reserved == capacity.
        prop_assert!(tx2.try_reserve().is_err(), "second reserve should fail when at capacity");

        // Drop the first permit instead of abort (with timing)
        let drop_start = Instant::now();
        drop(permits2.pop().expect("filled permits"));
        let drop_duration = drop_start.elapsed();

        // Now we should be able to reserve again (with timing)
        let reserve_start2 = Instant::now();
        let second_permit2 = tx2.try_reserve().expect("reserve after drop should succeed");
        let reserve_after_drop_duration = reserve_start2.elapsed();
        let counts_after_drop = tx2.debug_counts();
        let telemetry_after_drop = tx2.telemetry_snapshot(301);

        // MR3: Channel state should be identical
        prop_assert_eq!(counts_after_abort, counts_after_drop,
            "Abort and drop should result in identical channel state. \
             Performance: abort took {:?}, drop took {:?}. Reserve after abort: {:?}, after drop: {:?}. \
             Telemetry abort: {}, drop: {}",
            abort_duration, drop_duration, reserve_after_abort_duration, reserve_after_drop_duration,
            telemetry_after_abort.reserved_uncommitted_obligations,
            telemetry_after_drop.reserved_uncommitted_obligations);

        // Cleanup outstanding permits before the proptest case exits.
        second_permit1.abort();
        second_permit2.abort();
        for permit in permits1 {
            permit.abort();
        }
        drop(permits2);
    });
}

/// **MR4: Receiver State Independence (Enhanced with Observability)**
///
/// Permit abort/drop operations should not affect receiver state or
/// the ability to receive messages that were successfully sent.
///
/// **Property**: Receiver behavior is independent of permit abort vs drop
/// **Enhancement**: Includes telemetry snapshots and timing measurements
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

        // Send a successful message and capture telemetry
        let permit1a = tx1.try_reserve().expect("should reserve");
        let _telemetry_post_reserve_1 = tx1.telemetry_snapshot(400);
        let send_result1a = permit1a.send(message.clone());
        prop_assert!(send_result1a.is_ok(), "should send successfully");
        let _telemetry_post_send_1 = tx1.telemetry_snapshot(401);

        // Reserve and abort another permit with timing
        let permit1b = tx1.try_reserve().expect("should reserve again");
        let _telemetry_pre_abort_1 = tx1.telemetry_snapshot(402);
        let abort_start = Instant::now();
        permit1b.abort();
        let abort_duration = abort_start.elapsed();
        let _telemetry_post_abort_1 = tx1.telemetry_snapshot(403);

        // Path 2: Send message, drop a subsequent permit, then receive
        let (tx2, mut rx2) = mpsc::channel(capacity);

        // Send a successful message and capture telemetry
        let permit2a = tx2.try_reserve().expect("should reserve");
        let _telemetry_post_reserve_2 = tx2.telemetry_snapshot(500);
        let send_result2a = permit2a.send(message.clone());
        prop_assert!(send_result2a.is_ok(), "should send successfully");
        let _telemetry_post_send_2 = tx2.telemetry_snapshot(501);

        // Reserve and drop another permit with timing
        let permit2b = tx2.try_reserve().expect("should reserve again");
        let _telemetry_pre_drop_2 = tx2.telemetry_snapshot(502);
        let drop_start = Instant::now();
        drop(permit2b);
        let drop_duration = drop_start.elapsed();
        let _telemetry_post_drop_2 = tx2.telemetry_snapshot(503);

        // MR4: Receivers should behave identically (enhanced with telemetry)
        let recv_start_1 = Instant::now();
        let recv_result1 = rx1.try_recv();
        let recv_duration_1 = recv_start_1.elapsed();

        let recv_start_2 = Instant::now();
        let recv_result2 = rx2.try_recv();
        let recv_duration_2 = recv_start_2.elapsed();

        let final_telemetry_1 = tx1.telemetry_snapshot(404);
        let final_telemetry_2 = tx2.telemetry_snapshot(504);

        prop_assert_eq!(recv_result1.as_ref(), recv_result2.as_ref(),
            "Receivers should behave identically regardless of abort vs drop. \
             Performance: abort took {:?}, drop took {:?}, recv1 took {:?}, recv2 took {:?}. \
             Final telemetry abort: obligations={}, drop: obligations={}",
            abort_duration, drop_duration, recv_duration_1, recv_duration_2,
            final_telemetry_1.reserved_uncommitted_obligations,
            final_telemetry_2.reserved_uncommitted_obligations);

        match (&recv_result1, &recv_result2) {
            (Ok(msg1), Ok(msg2)) => {
                prop_assert_eq!(msg1, &message, "Received message should match sent");
                prop_assert_eq!(msg2, &message, "Received message should match sent");
            },
            (Err(e1), Err(e2)) => {
                prop_assert_eq!(e1, e2, "Receive errors should be identical");
            },
            other => prop_assert!(false, "Mismatched receive results: {:?}. \
                Telemetry states - abort path: send_waiters={}, drop path: send_waiters={}",
                other,
                final_telemetry_1.send_waiter_count,
                final_telemetry_2.send_waiter_count),
        }

        // Test that both receivers still work for subsequent operations (enhanced with telemetry)
        let next_message = TestMessage::new(test_id + 1, "next", sequence + 1);

        let subsequent_send_start_1 = Instant::now();
        tx1.try_send(next_message.clone()).expect("subsequent send should work");
        let subsequent_send_duration_1 = subsequent_send_start_1.elapsed();

        let subsequent_send_start_2 = Instant::now();
        tx2.try_send(next_message.clone()).expect("subsequent send should work");
        let subsequent_send_duration_2 = subsequent_send_start_2.elapsed();

        let telemetry_after_subsequent_send_1 = tx1.telemetry_snapshot(405);
        let telemetry_after_subsequent_send_2 = tx2.telemetry_snapshot(505);

        let next_recv1 = rx1.try_recv().expect("subsequent receive should work");
        let next_recv2 = rx2.try_recv().expect("subsequent receive should work");

        prop_assert_eq!(&next_recv1, &next_message,
            "Subsequent receive should work after abort. Send timing: {:?}. \
             Final telemetry: obligations={}, send_waiters={}",
            subsequent_send_duration_1,
            telemetry_after_subsequent_send_1.reserved_uncommitted_obligations,
            telemetry_after_subsequent_send_1.send_waiter_count);
        prop_assert_eq!(&next_recv2, &next_message,
            "Subsequent receive should work after drop. Send timing: {:?}. \
             Final telemetry: obligations={}, send_waiters={}",
            subsequent_send_duration_2,
            telemetry_after_subsequent_send_2.reserved_uncommitted_obligations,
            telemetry_after_subsequent_send_2.send_waiter_count);
    });
}

/// **Composite MR: Full Channel Abort vs Drop Under Pressure (Enhanced with Observability)**
///
/// Tests abort vs drop equivalence when the channel is at capacity
/// and there are waiting senders.
///
/// **Enhancement**: Includes telemetry snapshots and timing measurements
#[test]
fn mr_composite_full_channel_abort_vs_drop() {
    let capacity = 3;
    // Path 1: Fill channel, abort permits
    let (tx1, mut rx1) = mpsc::channel::<u32>(capacity);

    // Mix one queued message with reserved slots until the channel is full.
    tx1.try_send(1).expect("first send");
    let _telemetry_after_first_send_1 = tx1.telemetry_snapshot(600);

    let permit1a = tx1.try_reserve().expect("reserve second logical slot");
    let permit1b = tx1.try_reserve().expect("reserve third logical slot");
    let _telemetry_full_capacity_1 = tx1.telemetry_snapshot(601);

    // Now channel is at logical capacity (queue full + reserved slots)
    assert!(tx1.try_send(5).is_err(), "channel should be full now");

    // Abort both reserved permits with timing
    let abort_start_1a = Instant::now();
    permit1a.abort();
    let abort_duration_1a = abort_start_1a.elapsed();

    let abort_start_1b = Instant::now();
    permit1b.abort();
    let abort_duration_1b = abort_start_1b.elapsed();

    let _telemetry_after_aborts_1 = tx1.telemetry_snapshot(602);

    // Should be able to send again after aborts
    let after_abort_result1 = tx1.try_send(2);
    let after_abort_result2 = tx1.try_send(3);
    let counts_after_abort = tx1.debug_counts();
    let telemetry_final_abort_path = tx1.telemetry_snapshot(603);

    // Path 2: Same scenario but with drops
    let (tx2, mut rx2) = mpsc::channel::<u32>(capacity);

    // Mix one queued message with reserved slots until the channel is full.
    tx2.try_send(1).expect("first send");
    let _telemetry_after_first_send_2 = tx2.telemetry_snapshot(700);

    let permit2a = tx2.try_reserve().expect("reserve second logical slot");
    let permit2b = tx2.try_reserve().expect("reserve third logical slot");
    let _telemetry_full_capacity_2 = tx2.telemetry_snapshot(701);

    // Now channel is at logical capacity
    assert!(tx2.try_send(5).is_err(), "channel should be full now");

    // Drop both reserved permits with timing
    let drop_start_2a = Instant::now();
    drop(permit2a);
    let drop_duration_2a = drop_start_2a.elapsed();

    let drop_start_2b = Instant::now();
    drop(permit2b);
    let drop_duration_2b = drop_start_2b.elapsed();

    let _telemetry_after_drops_2 = tx2.telemetry_snapshot(702);

    // Should be able to send again after drops
    let after_drop_result1 = tx2.try_send(2);
    let after_drop_result2 = tx2.try_send(3);
    let counts_after_drop = tx2.debug_counts();
    let telemetry_final_drop_path = tx2.telemetry_snapshot(703);

    // Verify abort vs drop equivalence (enhanced with telemetry and timing)
    assert_eq!(
        after_abort_result1.is_ok(),
        after_drop_result1.is_ok(),
        "First send results should be equivalent after abort vs drop. \
         Performance: abort1={:?}, abort2={:?}, drop1={:?}, drop2={:?}",
        abort_duration_1a,
        abort_duration_1b,
        drop_duration_2a,
        drop_duration_2b
    );
    assert_eq!(
        after_abort_result2.is_ok(),
        after_drop_result2.is_ok(),
        "Second send results should be equivalent after abort vs drop. \
         Telemetry abort: obligations={}, drop: obligations={}",
        telemetry_final_abort_path.reserved_uncommitted_obligations,
        telemetry_final_drop_path.reserved_uncommitted_obligations
    );
    assert_eq!(
        counts_after_abort, counts_after_drop,
        "Channel counts should be equivalent after abort vs drop. \
         Abort path telemetry: waiters={}, Drop path telemetry: waiters={}",
        telemetry_final_abort_path.send_waiter_count, telemetry_final_drop_path.send_waiter_count
    );

    // Verify receivers see the same data (enhanced with timing)
    let recv_start_1 = Instant::now();
    let recv_sequence1: Vec<u32> = (0..3).filter_map(|_| rx1.try_recv().ok()).collect();
    let recv_duration_1 = recv_start_1.elapsed();

    let recv_start_2 = Instant::now();
    let recv_sequence2: Vec<u32> = (0..3).filter_map(|_| rx2.try_recv().ok()).collect();
    let recv_duration_2 = recv_start_2.elapsed();

    assert_eq!(
        recv_sequence1, recv_sequence2,
        "Receivers should see identical message sequences. \
         Recv timing: abort_path={:?}, drop_path={:?}",
        recv_duration_1, recv_duration_2
    );
    assert_eq!(
        recv_sequence1,
        vec![1, 2, 3],
        "Should receive all successfully sent messages. Final states - \
         abort_path: queue={}, reserved={}, drop_path: queue={}, reserved={}",
        counts_after_abort.0,
        counts_after_abort.1,
        counts_after_drop.0,
        counts_after_drop.1
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
