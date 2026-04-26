#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic Testing: Session Channel Protocol Invariants
//!
//! Tests the mathematical properties and protocol invariants of session-typed
//! channels with obligation tracking. Uses metamorphic relations to verify
//! that channel operations maintain consistency under various transformations.
//!
//! # Core Metamorphic Relations Tested
//!
//! ## MR1: Obligation Conservation (Additive)
//! For any sequence of operations: reserve_count = send_count + abort_count
//! - reserve() increases obligation count by 1
//! - send() decreases obligation count by 1, produces CommittedProof
//! - abort() decreases obligation count by 1, produces AbortedProof
//!
//! ## MR2: Proof Type Preservation (Equivalence)
//! f(successful_operations) always yields CommittedProof regardless of:
//! - Operation ordering (reserve→send vs direct send())
//! - Channel type (MPSC vs oneshot)
//! - Timing (async vs try_reserve)
//!
//! ## MR3: Channel State Consistency (Invertive)
//! reserve→abort→reserve on same channel yields identical state to original
//! - abort() must fully release reserved slots
//! - Channel capacity behavior must be deterministic
//!
//! ## MR4: Value Preservation (Round-trip)
//! send(X) → recv() = X for all values X
//! - Values must transit channels without modification
//! - Error cases must return original values unchanged
//!
//! ## MR5: Error Propagation Preservation (Equivalence)
//! Disconnected receivers must return identical errors regardless of:
//! - Operation path (reserve→send vs direct send())
//! - Channel type (MPSC vs oneshot)
//! - Original value type
//!
//! ## MR6: Clone Independence (Permutative)
//! For MPSC channels: clone(sender).operation() ≡ sender.operation()
//! - Cloned senders must behave identically to originals
//! - Operations on clones must not affect original state
//!
//! ## MR7: Reference Semantics (Equivalence)
//! tracked_sender.into_inner().operation() ≡ raw_sender.operation()
//! - Tracked channels must preserve underlying channel semantics
//! - Only obligation tracking should differ
//!
//! ## MR8: Capacity Boundedness (Inclusive)
//! For bounded channels: successful_sends ≤ channel_capacity
//! - Reserve operations must respect capacity limits
//! - Full channels must consistently reject new reserves
//!
//! ## MR9: Ordering Preservation (Permutative)
//! For MPSC: send_order = recv_order when no interleaving
//! - Sequential sends must preserve message ordering
//! - Concurrent sends from different threads may reorder
//!
//! ## MR10: Drop Safety (Equivalence)
//! drop(permit) ≡ panic!("OBLIGATION TOKEN LEAKED")
//! - Unconsumed permits must always panic on drop
//! - Panic message must be consistent and identifiable

use proptest::prelude::*;
use std::future::Future;
use std::task::{Context, Poll, Waker};

use asupersync::channel::session::{tracked_channel, tracked_oneshot};
use asupersync::channel::{mpsc, oneshot};
use asupersync::cx::Cx;
use asupersync::types::Budget;
use asupersync::util::ArenaIndex;
use asupersync::{RegionId, TaskId};

// Test utilities
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

fn block_on<F: Future>(f: F) -> F::Output {
    let waker = Waker::noop().clone();
    let mut cx = Context::from_waker(&waker);
    let mut pinned = Box::pin(f);
    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

// Property-based test data generators
prop_compose! {
    fn channel_operation_sequence()
        (capacity in 1usize..=20,
         operations in prop::collection::vec(operation_type(), 1..=50))
        -> (usize, Vec<ChannelOp>) {
        (capacity, operations)
    }
}

#[derive(Debug, Clone)]
enum ChannelOp {
    ReserveSend(i32),
    DirectSend(i32),
    ReserveAbort,
    Clone,
    CheckClosed,
}

fn operation_type() -> impl Strategy<Value = ChannelOp> {
    prop_oneof![
        any::<i32>().prop_map(ChannelOp::ReserveSend),
        any::<i32>().prop_map(ChannelOp::DirectSend),
        Just(ChannelOp::ReserveAbort),
        Just(ChannelOp::Clone),
        Just(ChannelOp::CheckClosed),
    ]
}

// ============================================================================
// MR1: Obligation Conservation (reserve_count = send_count + abort_count)
// ============================================================================

proptest! {
    #[test]
    fn mr1_obligation_conservation_mpsc(
        (capacity, operations) in channel_operation_sequence()
    ) {
        let cx = test_cx();
        // This test uses a single-threaded `block_on` harness with no concurrent
        // receiver, so `send()` must never rely on backpressure wakeups to make
        // progress. Size the channel for the worst-case buffered send volume.
        let max_buffered_messages = operations
            .iter()
            .filter(|op| matches!(op, ChannelOp::ReserveSend(_) | ChannelOp::DirectSend(_)))
            .count()
            .max(1);
        let (tx, mut rx) = tracked_channel::<i32>(capacity.max(max_buffered_messages));

        let mut reserve_count = 0;
        let mut send_count = 0;
        let mut abort_count = 0;
        let mut cloned_senders = Vec::new();

        for op in operations {
            match op {
                ChannelOp::ReserveSend(value) => {
                    if let Ok(permit) = tx.try_reserve() {
                        reserve_count += 1;
                        if permit.send(value).is_ok() {
                            send_count += 1;
                        } else {
                            abort_count += 1; // Failed send counts as abort
                        }
                    }
                },
                ChannelOp::DirectSend(value) => {
                    if block_on(tx.send(&cx, value)).is_ok() {
                        reserve_count += 1; // Direct send does reserve internally
                        send_count += 1;
                    } else {
                        reserve_count += 1;
                        abort_count += 1; // Failed send aborts internally
                    }
                },
                ChannelOp::ReserveAbort => {
                    if let Ok(permit) = tx.try_reserve() {
                        reserve_count += 1;
                        let _ = permit.abort();
                        abort_count += 1;
                    }
                },
                ChannelOp::Clone => {
                    cloned_senders.push(tx.clone());
                },
                ChannelOp::CheckClosed => {
                    let _ = tx.is_closed();
                },
            }
        }

        // MR1: Obligation conservation must hold
        prop_assert_eq!(reserve_count, send_count + abort_count,
            "Obligation conservation violated: {} reserves ≠ {} sends + {} aborts",
            reserve_count, send_count, abort_count);

        // Verify received values count matches successful sends
        let mut recv_count = 0;
        while rx.try_recv().is_ok() {
            recv_count += 1;
        }
        prop_assert_eq!(recv_count, send_count,
            "Value conservation violated: {} received ≠ {} sent",
            recv_count, send_count);
    }
}

// ============================================================================
// MR2: Proof Type Preservation (CommittedProof for successful operations)
// ============================================================================

proptest! {
    #[test]
    fn mr2_proof_type_preservation_mpsc(values in prop::collection::vec(any::<i32>(), 1..=10)) {
        let cx = test_cx();
        // Each iteration enqueues two messages before any receive occurs.
        let (tx, _rx) = tracked_channel::<i32>(values.len().saturating_mul(2).max(1));

        for value in values {
            // Test reserve→send path
            let permit1 = tx.try_reserve().unwrap();
            let proof1 = permit1.send(value).unwrap();
            prop_assert_eq!(proof1.kind(), asupersync::record::ObligationKind::SendPermit);

            // Test direct send path
            let proof2 = block_on(tx.send(&cx, value)).unwrap();
            prop_assert_eq!(proof2.kind(), asupersync::record::ObligationKind::SendPermit);

            // MR2: Both paths must yield identical proof types
            prop_assert_eq!(proof1.kind(), proof2.kind(),
                "Proof type preservation violated: reserve→send ≠ direct send");
        }
    }

    #[test]
    fn mr2_proof_type_preservation_oneshot(value in any::<i32>()) {
        let cx = test_cx();

        // Test oneshot reserve→send path
        let (tx1, _rx1) = tracked_oneshot::<i32>();
        let permit = tx1.reserve(&cx).expect("cx not cancelled in test");
        let proof1 = permit.send(value).unwrap();

        // Test oneshot direct send path
        let (tx2, _rx2) = tracked_oneshot::<i32>();
        let proof2 = tx2.send(&cx, value).unwrap();

        // MR2: Both oneshot paths must yield identical proof types
        prop_assert_eq!(proof1.kind(), proof2.kind(),
            "Oneshot proof type preservation violated");
        prop_assert_eq!(proof1.kind(), asupersync::record::ObligationKind::SendPermit);
    }
}

// ============================================================================
// MR3: Channel State Consistency (reserve→abort→reserve ≡ original)
// ============================================================================

proptest! {
    #[test]
    fn mr3_channel_state_consistency(capacity in 1usize..=10) {
        let (tx, _rx) = tracked_channel::<i32>(capacity);

        // Original state: should be able to reserve up to capacity
        let mut original_permits = Vec::new();
        for _ in 0..capacity {
            original_permits.push(tx.try_reserve().unwrap());
        }

        // Should be at capacity now
        prop_assert!(tx.try_reserve().is_err(), "Channel should be at capacity");

        // Abort all permits to restore original state
        for permit in original_permits {
            let _ = permit.abort();
        }

        // MR3: After abort sequence, state should be identical to original
        let mut restored_permits = Vec::new();
        for _ in 0..capacity {
            restored_permits.push(tx.try_reserve().unwrap());
        }

        // Should again be at capacity
        prop_assert!(tx.try_reserve().is_err(), "Channel should be at capacity after restore");

        // Clean up
        for permit in restored_permits {
            let _ = permit.abort();
        }
    }
}

// ============================================================================
// MR4: Value Preservation (send(X) → recv() = X)
// ============================================================================

proptest! {
    #[test]
    fn mr4_value_preservation_round_trip(values in prop::collection::vec(any::<i32>(), 1..=20)) {
        let cx = test_cx();
        let (tx, mut rx) = tracked_channel::<i32>(values.len());

        // Send all values
        for value in &values {
            let _ = block_on(tx.send(&cx, *value)).unwrap();
        }

        // Receive all values and verify preservation
        let mut received = Vec::new();
        for _ in 0..values.len() {
            received.push(block_on(rx.recv(&cx)).unwrap());
        }

        // MR4: Round-trip must preserve all values exactly
        prop_assert_eq!(received, values, "Value preservation violated in round-trip");
    }

    #[test]
    fn mr4_value_preservation_oneshot(value in any::<i32>()) {
        let cx = test_cx();
        let (tx, mut rx) = tracked_oneshot::<i32>();

        let _proof = tx.send(&cx, value).unwrap();
        let received = block_on(rx.recv(&cx)).unwrap();

        // MR4: Oneshot round-trip must preserve value exactly
        prop_assert_eq!(received, value, "Oneshot value preservation violated");
    }
}

// ============================================================================
// MR5: Error Propagation Preservation
// ============================================================================

proptest! {
    #[test]
    fn mr5_error_propagation_preservation(value in any::<i32>()) {
        let cx = test_cx();

        // Test MPSC disconnected error via reserve→send
        let (tx1, rx1) = tracked_channel::<i32>(1);
        let permit1 = tx1.try_reserve().unwrap();
        drop(rx1);
        let err1 = permit1.send(value).unwrap_err();

        // Test MPSC disconnected error via direct send
        let (tx2, rx2) = tracked_channel::<i32>(1);
        drop(rx2);
        let err2 = block_on(tx2.send(&cx, value)).unwrap_err();

        // MR5: Both error paths must preserve original value identically
        match (err1, err2) {
            (mpsc::SendError::Disconnected(v1), mpsc::SendError::Disconnected(v2)) => {
                prop_assert_eq!(v1, v2, "MPSC error value preservation violated");
                prop_assert_eq!(v1, value, "MPSC error must return original value");
            },
            _ => prop_assert!(false, "Expected Disconnected errors"),
        }

        // Test oneshot disconnected error consistency
        let (tx3, rx3) = tracked_oneshot::<i32>();
        let permit3 = tx3.reserve(&cx).expect("cx not cancelled in test");
        drop(rx3);
        let err3 = permit3.send(value).unwrap_err();

        let (tx4, rx4) = tracked_oneshot::<i32>();
        drop(rx4);
        let err4 = tx4.send(&cx, value).unwrap_err();

        // Both oneshot error paths must be identical
        match (err3, err4) {
            (oneshot::SendError::Disconnected(v3), oneshot::SendError::Disconnected(v4)) => {
                prop_assert_eq!(v3, v4, "Oneshot error value preservation violated");
                prop_assert_eq!(v3, value, "Oneshot error must return original value");
            },
        }
    }
}

// ============================================================================
// MR6: Clone Independence (clone behavior ≡ original behavior)
// ============================================================================

proptest! {
    #[test]
    fn mr6_clone_independence(values in prop::collection::vec(any::<i32>(), 1..=10)) {
        let cx = test_cx();
        let (tx, mut rx) = tracked_channel::<i32>(values.len() * 2);

        let cloned = tx.clone();

        // Send values alternately from original and clone
        for (i, value) in values.iter().enumerate() {
            if i % 2 == 0 {
                let _ = block_on(tx.send(&cx, *value)).unwrap();
            } else {
                let _ = block_on(cloned.send(&cx, *value)).unwrap();
            }
        }

        // MR6: All values must be received regardless of sender source
        let mut received = Vec::new();
        for _ in 0..values.len() {
            received.push(block_on(rx.recv(&cx)).unwrap());
        }

        prop_assert_eq!(received.len(), values.len(),
            "Clone independence violated: wrong number of values received");

        // Verify all original values were received (order may differ due to interleaving)
        for value in &values {
            prop_assert!(received.contains(value),
                "Clone independence violated: value {} missing", value);
        }
    }
}

// ============================================================================
// MR7: Reference Semantics (tracked ≡ raw for successful operations)
// ============================================================================

proptest! {
    #[test]
    fn mr7_reference_semantics_consistency(values in prop::collection::vec(any::<i32>(), 1..=5)) {
        let cx = test_cx();

        // Create tracked and raw channels with same configuration
        let (tracked_tx, mut tracked_rx) = tracked_channel::<i32>(values.len());
        let (raw_tx, mut raw_rx) = mpsc::channel::<i32>(values.len());

        // Extract raw sender from tracked for comparison
        let extracted_raw = tracked_tx.clone().into_inner();

        // Send same values through both paths
        for value in &values {
            // Raw channel operations
            let raw_permit = raw_tx.try_reserve().unwrap();
            raw_permit.send(*value);

            // Extracted raw operations (should behave identically)
            let extracted_permit = extracted_raw.try_reserve().unwrap();
            extracted_permit.send(*value);
        }

        // MR7: Both channels should receive identical value streams
        let mut raw_received = Vec::new();
        let mut extracted_received = Vec::new();

        for _ in 0..values.len() {
            raw_received.push(block_on(raw_rx.recv(&cx)).unwrap());
            extracted_received.push(block_on(tracked_rx.recv(&cx)).unwrap());
        }

        prop_assert_eq!(raw_received.as_slice(), extracted_received.as_slice(),
            "Reference semantics violated: raw ≠ extracted behavior");
        prop_assert_eq!(raw_received.as_slice(), values.as_slice(),
            "Reference semantics violated: values not preserved");
    }
}

// ============================================================================
// MR8: Capacity Boundedness (successful_sends ≤ channel_capacity)
// ============================================================================

proptest! {
    #[test]
    fn mr8_capacity_boundedness(
        capacity in 1usize..=10,
        attempt_count in 1usize..=50
    ) {
        let (tx, _rx) = tracked_channel::<i32>(capacity);

        let mut successful_reserves = 0;
        let mut permits = Vec::new();

        // Attempt more reserves than capacity allows
        for _ in 0..attempt_count {
            match tx.try_reserve() {
                Ok(permit) => {
                    successful_reserves += 1;
                    permits.push(permit);
                },
                Err(_) => break, // Channel full
            }
        }

        // MR8: Successful reserves must not exceed capacity
        prop_assert!(successful_reserves <= capacity,
            "Capacity boundedness violated: {} reserves > {} capacity",
            successful_reserves, capacity);

        // Verify exact capacity limit is respected
        if attempt_count >= capacity {
            prop_assert_eq!(successful_reserves, capacity,
                "Capacity not fully utilized: {} < {}", successful_reserves, capacity);
        }

        // Clean up permits to avoid drop panics
        for permit in permits {
            let _ = permit.abort();
        }
    }
}

// ============================================================================
// MR9: Ordering Preservation (FIFO for sequential operations)
// ============================================================================

proptest! {
    #[test]
    fn mr9_ordering_preservation_sequential(values in prop::collection::vec(any::<i32>(), 1..=20)) {
        let cx = test_cx();
        let (tx, mut rx) = tracked_channel::<i32>(values.len());

        // Send values in order sequentially (no concurrency)
        for value in &values {
            let _ = block_on(tx.send(&cx, *value)).unwrap();
        }

        // MR9: Receive order must match send order for sequential operations
        let mut received = Vec::new();
        for _ in 0..values.len() {
            received.push(block_on(rx.recv(&cx)).unwrap());
        }

        prop_assert_eq!(received, values,
            "Ordering preservation violated: received order ≠ send order");
    }
}

// ============================================================================
// MR10: Drop Safety (drop(permit) ≡ panic with specific message)
// ============================================================================

#[test]
fn mr10_drop_safety_mpsc_panic() {
    let (tx, _rx) = tracked_channel::<i32>(1);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let permit = tx.try_reserve().unwrap();
        drop(permit); // Should panic
    }));

    // MR10: Drop must always panic with specific message
    assert!(
        result.is_err(),
        "Drop safety violated: permit drop did not panic"
    );

    if let Err(panic_payload) = result {
        if let Some(message) = panic_payload.downcast_ref::<String>() {
            assert!(
                message.contains("OBLIGATION TOKEN LEAKED"),
                "Drop safety violated: wrong panic message: {}",
                message
            );
        } else if let Some(message) = panic_payload.downcast_ref::<&str>() {
            assert!(
                message.contains("OBLIGATION TOKEN LEAKED"),
                "Drop safety violated: wrong panic message: {}",
                message
            );
        } else {
            panic!("Drop safety violated: panic payload not string");
        }
    }
}

#[test]
fn mr10_drop_safety_oneshot_panic() {
    let cx = test_cx();
    let (tx, _rx) = tracked_oneshot::<i32>();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let permit = tx.reserve(&cx);
        drop(permit); // Should panic
    }));

    // MR10: Oneshot drop must also panic with same message
    assert!(
        result.is_err(),
        "Oneshot drop safety violated: permit drop did not panic"
    );

    if let Err(panic_payload) = result {
        if let Some(message) = panic_payload.downcast_ref::<String>() {
            assert!(
                message.contains("OBLIGATION TOKEN LEAKED"),
                "Oneshot drop safety violated: wrong panic message: {}",
                message
            );
        } else if let Some(message) = panic_payload.downcast_ref::<&str>() {
            assert!(
                message.contains("OBLIGATION TOKEN LEAKED"),
                "Oneshot drop safety violated: wrong panic message: {}",
                message
            );
        } else {
            panic!("Oneshot drop safety violated: panic payload not string");
        }
    }
}

// ============================================================================
// Compound Metamorphic Relations (Testing multiple invariants together)
// ============================================================================

proptest! {
    #[test]
    fn mr_compound_obligation_and_value_preservation(
        (capacity, operations) in channel_operation_sequence()
    ) {
        let cx = test_cx();
        let max_buffered_messages = operations
            .iter()
            .filter(|op| matches!(op, ChannelOp::ReserveSend(_) | ChannelOp::DirectSend(_)))
            .count()
            .max(1);
        let (tx, mut rx) = tracked_channel::<i32>(capacity.max(max_buffered_messages));

        let mut reserve_count = 0;
        let mut send_count = 0;
        let mut abort_count = 0;
        let mut sent_values = Vec::new();

        for op in operations {
            match op {
                ChannelOp::ReserveSend(value) => {
                    if let Ok(permit) = tx.try_reserve() {
                        reserve_count += 1;
                        if permit.send(value).is_ok() {
                            send_count += 1;
                            sent_values.push(value);
                        } else {
                            abort_count += 1;
                        }
                    }
                },
                ChannelOp::DirectSend(value) => {
                    if block_on(tx.send(&cx, value)).is_ok() {
                        reserve_count += 1;
                        send_count += 1;
                        sent_values.push(value);
                    } else {
                        reserve_count += 1;
                        abort_count += 1;
                    }
                },
                ChannelOp::ReserveAbort => {
                    if let Ok(permit) = tx.try_reserve() {
                        reserve_count += 1;
                        let _ = permit.abort();
                        abort_count += 1;
                    }
                },
                _ => {}, // Ignore other operations for this test
            }
        }

        // Compound MR: Both obligation conservation AND value preservation
        prop_assert_eq!(reserve_count, send_count + abort_count,
            "Compound test: obligation conservation violated");

        let mut received_values = Vec::new();
        while let Ok(value) = rx.try_recv() {
            received_values.push(value);
        }

        prop_assert_eq!(received_values.as_slice(), sent_values.as_slice(),
            "Compound test: value preservation violated");
        prop_assert_eq!(received_values.len(), send_count,
            "Compound test: send count mismatch");
    }
}
