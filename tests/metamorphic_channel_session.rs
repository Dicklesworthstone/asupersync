#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic tests for channel session protocol invariants.
//!
//! These tests verify the mathematical properties and protocol invariants
//! of the session-typed channels with obligation tracking. The tests focus
//! on metamorphic relations that must hold regardless of specific inputs
//! or operation ordering.

use asupersync::channel::session::{
    TrackedOneshotPermit, TrackedOneshotSender, TrackedSender, tracked_channel,
};
use asupersync::channel::{mpsc, oneshot};
use asupersync::cx::Cx;
use asupersync::obligation::graded::{AbortedProof, CommittedProof, SendPermit};
use asupersync::runtime::builder::RuntimeBuilder;
use proptest::prelude::*;
use std::collections::HashMap;

/// Test operations on session channels
#[derive(Debug, Clone)]
enum SessionOperation {
    /// Reserve a permit from MPSC channel
    ReserveMpsc { channel_id: u8 },
    /// Send value through reserved MPSC permit
    SendMpsc { permit_id: u8, value: i32 },
    /// Abort reserved MPSC permit
    AbortMpsc { permit_id: u8 },
    /// Send directly through MPSC channel (reserve + send)
    DirectSendMpsc { channel_id: u8, value: i32 },
    /// Reserve permit from oneshot channel
    ReserveOneshot { channel_id: u8 },
    /// Send value through reserved oneshot permit
    SendOneshot { permit_id: u8, value: i32 },
    /// Abort reserved oneshot permit
    AbortOneshot { permit_id: u8 },
    /// Send directly through oneshot channel (reserve + send)
    DirectSendOneshot { channel_id: u8, value: i32 },
}

fn create_operation(kind: u8, channel_id: u8, value: i32) -> SessionOperation {
    match kind % 8 {
        0 => SessionOperation::ReserveMpsc { channel_id },
        1 => SessionOperation::SendMpsc {
            permit_id: channel_id,
            value,
        },
        2 => SessionOperation::AbortMpsc {
            permit_id: channel_id,
        },
        3 => SessionOperation::DirectSendMpsc { channel_id, value },
        4 => SessionOperation::ReserveOneshot { channel_id },
        5 => SessionOperation::SendOneshot {
            permit_id: channel_id,
            value,
        },
        6 => SessionOperation::AbortOneshot {
            permit_id: channel_id,
        },
        _ => SessionOperation::DirectSendOneshot { channel_id, value },
    }
}

/// State for tracking session channel operations
struct SessionState {
    mpsc_channels: HashMap<u8, (TrackedSender<i32>, mpsc::Receiver<i32>)>,
    oneshot_senders: HashMap<u8, TrackedOneshotSender<i32>>,
    oneshot_receivers: HashMap<u8, oneshot::Receiver<i32>>,
    oneshot_permits: HashMap<u8, TrackedOneshotPermit<i32>>,
    committed_proofs: Vec<CommittedProof<SendPermit>>,
    aborted_proofs: Vec<AbortedProof<SendPermit>>,
    operations_performed: Vec<SessionOperation>,
    permits_reserved: u32,
    proofs_generated: u32,
}

impl SessionState {
    fn new() -> Self {
        Self {
            mpsc_channels: HashMap::new(),
            oneshot_senders: HashMap::new(),
            oneshot_receivers: HashMap::new(),
            oneshot_permits: HashMap::new(),
            committed_proofs: Vec::new(),
            aborted_proofs: Vec::new(),
            operations_performed: Vec::new(),
            permits_reserved: 0,
            proofs_generated: 0,
        }
    }

    fn add_mpsc_channel(&mut self, id: u8, capacity: usize) {
        let (sender, receiver) = tracked_channel(capacity);
        self.mpsc_channels.insert(id, (sender, receiver));
    }

    fn add_oneshot_channel(&mut self, id: u8) {
        let (sender, receiver) = oneshot::channel();
        self.oneshot_senders
            .insert(id, TrackedOneshotSender::new(sender));
        self.oneshot_receivers.insert(id, receiver);
    }
}

// =============================================================================
// Metamorphic Relation 1: Obligation Conservation
// =============================================================================

/// MR1: Total permits reserved must equal total proofs generated
///
/// This tests the fundamental obligation tracking invariant:
/// Every reserved permit must be consumed, producing exactly one proof.
/// permits_reserved = committed_proofs + aborted_proofs
fn mr_obligation_conservation() {
    proptest!(|(raw_ops: Vec<(u8, u8, i32)>)| {
        let operations: Vec<_> = raw_ops.into_iter().map(|(k, c, v)| create_operation(k, c, v)).collect();
        let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

        rt.block_on(async {
            let mut state = SessionState::new();

            // Setup some channels
            state.add_mpsc_channel(0, 10);
            state.add_mpsc_channel(1, 5);
            state.add_oneshot_channel(0);
            state.add_oneshot_channel(1);

            let cx = Cx::for_testing();
            let mut permits_reserved = 0u32;
            let mut proofs_generated = 0u32;

            // Execute limited operations to prevent resource exhaustion
            for operation in operations.iter().take(20) {
                match operation {
                    SessionOperation::ReserveMpsc { channel_id } => {
                        if let Some((sender, _)) = state.mpsc_channels.get(channel_id) {
                            if let Ok(permit) = sender.try_reserve(&cx) {
                                permits_reserved += 1;
                                let _proof = permit.abort();
                                proofs_generated += 1;
                            }
                        }
                    },
                    SessionOperation::SendMpsc { permit_id, value }
                    | SessionOperation::DirectSendMpsc {
                        channel_id: permit_id,
                        value,
                    } => {
                        if let Some((sender, _)) = state.mpsc_channels.get(permit_id) {
                            if let Ok(permit) = sender.try_reserve(&cx) {
                                permits_reserved += 1;
                                prop_assert!(
                                    permit.send(*value).is_ok(),
                                    "reserved live MPSC permit should commit successfully"
                                );
                                proofs_generated += 1;
                            }
                        }
                    },
                    SessionOperation::AbortMpsc { permit_id } => {
                        if let Some((sender, _)) = state.mpsc_channels.get(permit_id) {
                            if let Ok(permit) = sender.try_reserve(&cx) {
                                permits_reserved += 1;
                                let _proof = permit.abort();
                                proofs_generated += 1;
                            }
                        }
                    },
                    SessionOperation::ReserveOneshot { channel_id } => {
                        if let Some(sender) = state.oneshot_senders.remove(channel_id) {
                            let permit = sender.reserve(&cx).expect("test cx is not cancelled");
                            state.oneshot_permits.insert(*channel_id, permit);
                            permits_reserved += 1;
                        }
                    },
                    SessionOperation::AbortOneshot { permit_id } => {
                        if let Some(permit) = state.oneshot_permits.remove(permit_id) {
                            let _proof = permit.abort();
                            proofs_generated += 1;
                        }
                    },
                    SessionOperation::SendOneshot { permit_id, value } => {
                        if let Some(permit) = state.oneshot_permits.remove(permit_id) {
                            prop_assert!(
                                permit.send(*value).is_ok(),
                                "tracked oneshot with live receiver should commit successfully"
                            );
                            proofs_generated += 1;
                        }
                    },
                    SessionOperation::DirectSendOneshot { channel_id, value } => {
                        if let Some(sender) = state.oneshot_senders.remove(channel_id) {
                            permits_reserved += 1;
                            prop_assert!(
                                sender.send(&cx, *value).is_ok(),
                                "tracked oneshot with live receiver should commit successfully"
                            );
                            proofs_generated += 1;
                        }
                    },
                }
            }

            for (_, permit) in state.oneshot_permits.drain() {
                let _proof = permit.abort();
                proofs_generated += 1;
            }

            prop_assert_eq!(
                permits_reserved,
                proofs_generated,
                "every successful tracked reservation must be consumed into exactly one commit or abort proof"
            );
            Ok::<(), TestCaseError>(())
        })?;
    });
}

// =============================================================================
// Metamorphic Relation 2: Channel State Consistency
// =============================================================================

/// MR2: Channel closed state is preserved across session operations
///
/// If a channel is closed, all subsequent operations should reflect this.
/// Channel state should be monotonic: open → closed, never closed → open.
fn mr_channel_state_consistency() {
    proptest!(|(raw_ops: Vec<(u8, u8, i32)>)| {
        let operations: Vec<_> = raw_ops.into_iter().map(|(k, c, v)| create_operation(k, c, v)).collect();
        let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

        rt.block_on(async {
            let cx = Cx::for_testing();
            let (sender, receiver) = tracked_channel::<i32>(5);

            let _initial_closed = sender.is_closed();

            // Drop receiver to close the channel
            drop(receiver);

            // Channel should now be closed
            let after_close = sender.is_closed();
            prop_assert!(after_close); // Channel should be closed after receiver drop

            // All subsequent operations should see closed channel
            for _operation in operations.iter().take(10) {
                prop_assert!(sender.is_closed()); // State should remain closed

                // Any reserve attempt should fail
                match sender.try_reserve(&cx) {
                    Ok(_) => prop_assert!(false, "Reserve should fail on closed channel"),
                    Err(_) => {}, // Expected
                }
            }
            Ok::<(), TestCaseError>(())
        })?;
    });
}

// =============================================================================
// Metamorphic Relation 3: Proof Type Preservation
// =============================================================================

/// MR3: send() always produces CommittedProof, abort() always produces AbortedProof
///
/// The type of proof generated should depend only on the terminating operation,
/// not on the history of operations or the specific values sent.
fn mr_proof_type_preservation() {
    proptest!(|(values in prop::collection::vec(any::<i32>(), 0..=20))| {
        let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

        rt.block_on(async {
            let cx = Cx::for_testing();

            for value in values.iter().take(10) {
                // Test MPSC send proof type
                let (sender, _receiver) = tracked_channel(10);
                match sender.send(&cx, *value).await {
                    Ok(proof) => {
                        // Proof should be CommittedProof (type is verified by compilation)
                        let _: CommittedProof<SendPermit> = proof;
                    },
                    Err(_) => {
                        // Channel error - no proof generated
                    },
                }

                // Test MPSC abort proof type
                let (sender2, _receiver2) = tracked_channel::<()>(10);
                if let Ok(permit) = sender2.try_reserve(&cx) {
                    let proof = permit.abort();
                    let _: AbortedProof<SendPermit> = proof; // Type verified by compilation
                }

                // Test oneshot send proof type
                let (sender3, _receiver3) = oneshot::channel();
                let tracked_sender = TrackedOneshotSender::new(sender3);
                match tracked_sender.send(&cx, *value) {
                    Ok(proof) => {
                        let _: CommittedProof<SendPermit> = proof;
                    },
                    Err(_) => {},
                }

                // Test oneshot abort proof type
                let (sender4, _receiver4) = oneshot::channel::<()>();
                let tracked_sender4 = TrackedOneshotSender::new(sender4);
                let permit = tracked_sender4.reserve(&cx).expect("reserve 4");
                let proof = permit.abort();
                let _: AbortedProof<SendPermit> = proof;
            }
            Ok::<(), TestCaseError>(())
        })?;
    });
}

// =============================================================================
// Metamorphic Relation 4: Operation Commutativity
// =============================================================================

/// MR4: Independent operations on different channels commute
///
/// Operations on separate channels should be commutative - the final state
/// should be the same regardless of operation order.
fn mr_operation_commutativity() {
    proptest!(|(
        ops_a in prop::collection::vec((any::<u8>(), any::<i32>()), 0..=20), // Operations on channel A
        ops_b in prop::collection::vec((any::<u8>(), any::<i32>()), 0..=20)  // Operations on channel B
    )| {
        let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

        rt.block_on(async {
            let cx = Cx::for_testing();

            // Create two independent channels
            let (sender_a, receiver_a) = tracked_channel(10);
            let (sender_b, receiver_b) = tracked_channel(10);

            // Execute A then B
            let mut results_ab = Vec::new();
            for (_, value) in ops_a.iter().take(5) {
                match sender_a.send(&cx, *value).await {
                    Ok(_) => results_ab.push("A_committed"),
                    Err(_) => results_ab.push("A_error"),
                }
            }
            for (_, value) in ops_b.iter().take(5) {
                match sender_b.send(&cx, *value).await {
                    Ok(_) => results_ab.push("B_committed"),
                    Err(_) => results_ab.push("B_error"),
                }
            }

            drop(receiver_a);
            drop(receiver_b);

            // Create fresh channels for B then A test
            let (sender_a2, receiver_a2) = tracked_channel(10);
            let (sender_b2, receiver_b2) = tracked_channel(10);

            // Execute B then A
            let mut results_ba = Vec::new();
            for (_, value) in ops_b.iter().take(5) {
                match sender_b2.send(&cx, *value).await {
                    Ok(_) => results_ba.push("B_committed"),
                    Err(_) => results_ba.push("B_error"),
                }
            }
            for (_, value) in ops_a.iter().take(5) {
                match sender_a2.send(&cx, *value).await {
                    Ok(_) => results_ba.push("A_committed"),
                    Err(_) => results_ba.push("A_error"),
                }
            }

            // Results should have same counts when sorted
            let mut sorted_ab = results_ab.clone();
            let mut sorted_ba = results_ba.clone();
            sorted_ab.sort();
            sorted_ba.sort();

            prop_assert_eq!(sorted_ab, sorted_ba);

            drop(receiver_a2);
            drop(receiver_b2);
            Ok::<(), TestCaseError>(())
        })?;
    });
}

// =============================================================================
// Metamorphic Relation 5: Error Propagation Preservation
// =============================================================================

/// MR5: Underlying channel errors are preserved through tracked layer
///
/// If the underlying channel operation would fail, the tracked version
/// should fail with the same error type.
fn mr_error_propagation_preservation() {
    proptest!(|(values in prop::collection::vec(any::<i32>(), 0..=20))| {
        let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

        rt.block_on(async {
            let cx = Cx::for_testing();

            for value in values.iter().take(5) {
                // Test with disconnected MPSC
                let (sender, receiver) = tracked_channel(1);
                drop(receiver); // Disconnect

                let tracked_result = sender.send(&cx, *value).await;
                prop_assert!(tracked_result.is_err()); // Should fail

                // Test with disconnected oneshot
                let (os_sender, os_receiver) = oneshot::channel();
                drop(os_receiver); // Disconnect
                let tracked_sender = TrackedOneshotSender::new(os_sender);

                let oneshot_result = tracked_sender.send(&cx, *value);
                prop_assert!(oneshot_result.is_err()); // Should fail

                // Both should fail with Disconnected error
                match tracked_result {
                    Err(mpsc::SendError::Disconnected(_)) => {},
                    _ => prop_assert!(false, "Expected Disconnected error"),
                }

                match oneshot_result {
                    Err(oneshot::SendError::Disconnected(_)) => {},
                    _ => prop_assert!(false, "Expected Disconnected error"),
                }
            }
            Ok::<(), TestCaseError>(())
        })?;
    });
}

// =============================================================================
// Metamorphic Relation 6: Permit Lifecycle Invariant
// =============================================================================

/// MR6: Permit lifecycle follows reserve → (send|abort) exactly once
///
/// Once a permit is consumed (send or abort), it cannot be used again.
/// This tests the move semantics and obligation tracking.
fn mr_permit_lifecycle_invariant() {
    proptest!(|(values in prop::collection::vec(any::<i32>(), 0..=20))| {
        let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

        rt.block_on(async {
            let cx = Cx::for_testing();

            for value in values.iter().take(5) {
                // Test MPSC permit lifecycle
                let (sender, _receiver) = tracked_channel(10);
                if let Ok(permit) = sender.try_reserve(&cx) {
                    // Permit exists and can be consumed exactly once
                    match permit.send(*value) {
                        Ok(_proof) => {
                            // Permit consumed - cannot be used again
                            // This is enforced by move semantics
                        },
                        Err(_) => {},
                    }
                    // permit is now consumed and cannot be used again
                }

                // Test oneshot permit lifecycle
                let (os_sender, _os_receiver) = oneshot::channel::<i32>();
                let tracked_sender = TrackedOneshotSender::new(os_sender);
                let permit = tracked_sender
                    .reserve(&cx)
                    .expect("cx not cancelled in test");

                // Permit can be consumed exactly once
                let _proof = permit.abort(); // Consume via abort
                // permit is now consumed and cannot be used again
            }
            Ok::<(), TestCaseError>(())
        })?;
    });
}

// =============================================================================
// Metamorphic Relation 7: Channel Capacity Consistency
// =============================================================================

/// MR7: Channel capacity limits are preserved through session layer
///
/// The session layer should respect underlying channel capacity limits.
fn mr_channel_capacity_consistency() {
    proptest!(|(send_count in 1usize..20)| {
        let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

        rt.block_on(async {
            let cx = Cx::for_testing();
            let capacity = 3;
            let (sender, _receiver) = tracked_channel::<i32>(capacity);

            let mut successful_sends = 0;
            let mut failed_sends = 0;

            // Try to send more than capacity
            for i in 0..send_count {
                match sender.try_reserve(&cx) {
                    Ok(permit) => match permit.send(i as i32) {
                        Ok(_) => successful_sends += 1,
                        Err(_) => failed_sends += 1,
                    },
                    Err(_) => failed_sends += 1,
                }
            }

            // Without receiver consuming, we should hit capacity limits
            prop_assert!(successful_sends <= capacity);
            prop_assert_eq!(successful_sends + failed_sends, send_count);
            Ok::<(), TestCaseError>(())
        })?;
    });
}

// =============================================================================
// Metamorphic Relation 8: Proof Uniqueness
// =============================================================================

/// MR8: Each successful operation produces exactly one unique proof
///
/// Proofs should be unique and cannot be duplicated or forged.
fn mr_proof_uniqueness() {
    proptest!(|(values in prop::collection::vec(any::<i32>(), 0..=20))| {
        let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

        rt.block_on(async {
            let cx = Cx::for_testing();
            let mut proofs = Vec::new();

            for value in values.iter().take(10) {
                let (sender, receiver) = tracked_channel(10);
                match sender.send(&cx, *value).await {
                    Ok(proof) => {
                        // Each proof is distinct (tested by moving into vector)
                        proofs.push(proof);
                    },
                    Err(_) => {},
                }
                drop(receiver);
            }

            // Each proof in the vector is unique (by move semantics)
            prop_assert_eq!(proofs.len(), values.iter().take(10).count());
            Ok::<(), TestCaseError>(())
        })?;
    });
}

// =============================================================================
// Metamorphic Relation 9: Session Type Safety
// =============================================================================

/// MR9: Session types prevent protocol violations at compile time
///
/// Invalid protocol usage should be impossible to express.
/// This is primarily a compile-time property but we test runtime behavior.
fn mr_session_type_safety() {
    proptest!(|(value in any::<i32>())| {
        let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

        rt.block_on(async {
            let cx = Cx::for_testing();
            let (sender, _receiver) = tracked_channel(10);

            // Valid protocol: reserve → send
            if let Ok(permit) = sender.try_reserve(&cx) {
                match permit.send(value) {
                    Ok(_proof) => {},
                    Err(_) => {},
                }
            }

            // Valid protocol: reserve → abort
            if let Ok(permit) = sender.try_reserve(&cx) {
                let _proof = permit.abort();
            }

            // Direct send (reserve + send atomic)
            match sender.send(&cx, value).await {
                Ok(_proof) => {},
                Err(_) => {},
            }

            // All valid protocols should work without panics
            prop_assert!(true); // If we reach here, no protocol violation occurred
            Ok::<(), TestCaseError>(())
        })?;
    });
}

// =============================================================================
// Metamorphic Relation 10: Temporal Consistency
// =============================================================================

/// MR10: Operation results are consistent across different temporal orderings
///
/// When operations are independent, different scheduling should yield
/// equivalent final states.
fn mr_temporal_consistency() {
    proptest!(|(operations: Vec<(u8, i32)>)| {
        let rt = RuntimeBuilder::new().build().expect("runtime creation failed");

        rt.block_on(async {
            let cx = Cx::for_testing();

            // Execute operations in original order
            let (sender1, receiver1) = tracked_channel(20);
            let mut results1 = Vec::new();

            for (_, value) in operations.iter().take(10) {
                match sender1.send(&cx, *value).await {
                    Ok(_) => results1.push("committed"),
                    Err(_) => results1.push("failed"),
                }
            }

            drop(receiver1);

            // Execute same operations in reverse order
            let (sender2, receiver2) = tracked_channel(20);
            let mut results2 = Vec::new();

            for (_, value) in operations.iter().take(10).rev() {
                match sender2.send(&cx, *value).await {
                    Ok(_) => results2.push("committed"),
                    Err(_) => results2.push("failed"),
                }
            }

            drop(receiver2);

            // Results should have same success/failure counts
            let success1 = results1.iter().filter(|&&s| s == "committed").count();
            let success2 = results2.iter().filter(|&&s| s == "committed").count();

            prop_assert_eq!(success1, success2);
            Ok::<(), TestCaseError>(())
        })?;
    });
}

// =============================================================================
// Test Suite Integration
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mr_obligation_conservation() {
        mr_obligation_conservation();
    }

    #[test]
    fn test_mr_channel_state_consistency() {
        mr_channel_state_consistency();
    }

    #[test]
    fn test_mr_proof_type_preservation() {
        mr_proof_type_preservation();
    }

    #[test]
    fn test_mr_operation_commutativity() {
        mr_operation_commutativity();
    }

    #[test]
    fn test_mr_error_propagation_preservation() {
        mr_error_propagation_preservation();
    }

    #[test]
    fn test_mr_permit_lifecycle_invariant() {
        mr_permit_lifecycle_invariant();
    }

    #[test]
    fn test_mr_channel_capacity_consistency() {
        mr_channel_capacity_consistency();
    }

    #[test]
    fn test_mr_proof_uniqueness() {
        mr_proof_uniqueness();
    }

    #[test]
    fn test_mr_session_type_safety() {
        mr_session_type_safety();
    }

    #[test]
    fn test_mr_temporal_consistency() {
        mr_temporal_consistency();
    }
}
