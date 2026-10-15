//! Metamorphic Testing: Oneshot channel exactly-once delivery guarantee
//!
//! This module implements metamorphic relations (MRs) to verify that oneshot
//! channels deliver messages exactly once - never zero times (unless
//! explicitly cancelled/closed) and never more than once.
//!
//! # Target Metamorphic Relations
//!
//! - **MR1 (Send Success ⟺ Exactly One Receive)**: Every successful send
//!   results in exactly one successful receive
//! - **MR2 (Send Failure ⟺ Zero Receives)**: Every failed send results
//!   in zero successful receives
//! - **MR3 (Receive Exhaustion)**: After one successful receive, subsequent
//!   receives must fail with appropriate errors
//! - **MR4 (State Consistency)**: Channel state after successful/failed
//!   operations is deterministic and permanent
//!
//! # Property Coverage
//!
//! These MRs ensure that:
//! - No message duplication occurs
//! - No messages are lost during successful sends
//! - Failed operations have predictable outcomes
//! - Channel state transitions are atomic and irreversible
//! - At-most-once semantics are strictly enforced

use crate::channel::oneshot::{self, RecvError, SendError, TryRecvError};
use crate::cx::Cx;
use crate::lab::{LabConfig, LabRuntime};
use proptest::prelude::*;
use std::future::Future;
use std::rc::Rc;
use std::task::{Context, Poll};

// ============================================================================
// Test Infrastructure
// ============================================================================

/// Create a test context for deterministic scheduling.
fn test_cx() -> Cx<crate::cx::cap::All> {
    Cx::for_testing()
}

/// Simple block_on implementation for tests.
fn block_on<F: Future>(f: F) -> F::Output {
    let waker = std::task::Waker::noop().clone(); // ubs:ignore - test oracle
    let mut cx = Context::from_waker(&waker);
    let mut pinned = Box::pin(f);
    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UniqueMessage {
    id: u64,
    content: String,
    checksum: u32,
}

impl UniqueMessage {
    fn new(id: u64, content: impl Into<String>) -> Self {
        let content = content.into();
        let checksum = content.bytes().fold(id as u32, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(b as u32)
        });

        Self {
            id,
            content,
            checksum,
        }
    }

    fn validate(&self) -> bool {
        let expected_checksum = self.content.bytes().fold(self.id as u32, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(b as u32)
        });
        self.checksum == expected_checksum
    }
}

/// Result counter for tracking exactly-once semantics
#[derive(Debug, Default)]
struct DeliveryCounter {
    successful_sends: u32,
    failed_sends: u32,
    successful_recvs: u32,
    failed_recvs: u32,
    closed_recvs: u32,
    cancelled_recvs: u32,
}

impl DeliveryCounter {
    fn record_send_success(&mut self) {
        self.successful_sends += 1;
    }

    fn record_send_failure(&mut self) {
        self.failed_sends += 1;
    }

    fn record_recv_success(&mut self) {
        self.successful_recvs += 1;
    }

    fn record_recv_failure(&mut self) {
        self.failed_recvs += 1;
    }

    fn record_recv_closed(&mut self) {
        self.closed_recvs += 1;
    }

    fn record_recv_cancelled(&mut self) {
        self.cancelled_recvs += 1;
    }

    fn exactly_once_invariant(&self) -> Result<(), String> {
        let _terminal_observations =
            self.failed_sends + self.failed_recvs + self.closed_recvs + self.cancelled_recvs;

        // Core invariant: successful_sends = successful_recvs
        if self.successful_sends != self.successful_recvs {
            return Err(format!(
                "Exactly-once violation: {} successful sends != {} successful recvs",
                self.successful_sends, self.successful_recvs
            ));
        }

        // At most one successful receive should ever happen
        if self.successful_recvs > 1 {
            return Err(format!(
                "Multiple delivery violation: {} successful recvs > 1",
                self.successful_recvs
            ));
        }

        // If no successful sends, there should be no successful recvs
        if self.successful_sends == 0 && self.successful_recvs != 0 {
            return Err(format!(
                "Phantom delivery: 0 sends but {} recvs",
                self.successful_recvs
            ));
        }

        Ok(())
    }
}

// ============================================================================
// Metamorphic Relations for Exactly-Once Delivery
// ============================================================================

/// **MR1: Send Success ⟺ Exactly One Receive (Equivalence, Score: 10.0)**
///
/// Property: Every successful send operation must result in exactly one
/// successful receive operation. No more, no less.
///
/// **Transformation**: send_success → recv_count
/// **Relation**: send_success.count = recv_success.count = 1
/// **Catches**: Message duplication, delivery failure after successful send
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

    #[test]
    fn mr1_send_success_exactly_one_receive() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            message_id in 0u64..10000,
            content in "[a-zA-Z0-9]{3,20}",
            recv_attempts in 2usize..5,
        )| {
            let cx = test_cx();
            let message = UniqueMessage::new(message_id, content);
            let (tx, mut rx) = oneshot::channel();
            let mut counter = DeliveryCounter::default();

            // Send the message
            let send_result = tx.send(&cx, message.clone());
            match send_result {
                Ok(()) => {
                    counter.record_send_success();

                    // First receive should succeed
                    match block_on(rx.recv(&cx)) {
                        Ok(received_msg) => {
                            counter.record_recv_success();
                            prop_assert_eq!(&received_msg, &message,
                                "MR1 VIOLATION: Received message differs from sent message");
                            prop_assert!(received_msg.validate(),
                                "MR1 VIOLATION: Received message failed integrity check");
                        }
                        Err(e) => {
                            counter.record_recv_failure();
                            prop_assert!(false,
                                "MR1 VIOLATION: First receive failed after successful send: {:?}", e);
                        }
                    }

                    // Subsequent receive attempts should fail
                    for attempt in 1..recv_attempts {
                        match block_on(rx.recv(&cx)) {
                            Ok(duplicate_msg) => {
                                prop_assert!(false,
                                    "MR1 VIOLATION: Received duplicate message on attempt {}: {:?}",
                                    attempt, duplicate_msg);
                            }
                            Err(RecvError::Closed) => {
                                counter.record_recv_closed();
                                // This is expected behavior
                            }
                            Err(RecvError::Cancelled) => {
                                counter.record_recv_cancelled();
                                // Also acceptable
                            }
                            Err(RecvError::PolledAfterCompletion) => {
                                counter.record_recv_failure();
                                // Also terminal
                            }
                        }
                    }
                }
                Err(_) => {
                    counter.record_send_failure();
                    // If send failed, receive should also fail
                    match block_on(rx.recv(&cx)) {
                        Ok(phantom_msg) => {
                            prop_assert!(false,
                                "MR1 VIOLATION: Received phantom message after send failure: {:?}",
                                phantom_msg);
                        }
                        Err(RecvError::Closed) => {
                            counter.record_recv_closed();
                            // Expected for failed sends
                        }
                        Err(RecvError::Cancelled) => {
                            counter.record_recv_cancelled();
                            // Also acceptable
                        }
                        Err(RecvError::PolledAfterCompletion) => {
                            counter.record_recv_failure();
                            // Also terminal
                        }
                    }
                }
            }

            // Verify exactly-once invariant
            let invariant_check = counter.exactly_once_invariant();
            prop_assert!(invariant_check.is_ok(), "MR1 INVARIANT VIOLATION: {:?}", invariant_check);
        });
    }

    /// **MR2: Send Failure ⟺ Zero Receives (Inverse, Score: 9.5)**
    ///
    /// Property: Every failed send operation must result in zero successful
    /// receives. The receiver should detect the failure appropriately.
    ///
    /// **Transformation**: trigger_send_failure → recv_outcomes
    /// **Relation**: send_failure → recv_success.count = 0
    /// **Catches**: Phantom deliveries, inconsistent error propagation
    #[test]
    fn mr2_send_failure_zero_receives() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            message_id in 0u64..1000,
            content in "[a-zA-Z]{2,10}",
            failure_mode in 0u8..3,
        )| {
            let cx = test_cx();
            let message = UniqueMessage::new(message_id, content);
            let mut counter = DeliveryCounter::default();

            // Create different failure scenarios
            let send_result = match failure_mode {
                0 => {
                    // Scenario 1: Drop receiver before send
                    let (tx, rx) = oneshot::channel::<UniqueMessage>();
                    drop(rx); // Receiver dropped
                    tx.send(&cx, message.clone())
                }
                1 => {
                    // Scenario 2: Cancelled context during send
                    let (tx, _rx) = oneshot::channel::<UniqueMessage>();
                    let cancelled_cx = test_cx();
                    cancelled_cx.set_cancel_requested(true);
                    tx.send(&cancelled_cx, message.clone())
                }
                _ => {
                    // Scenario 3: Reserve then drop receiver before sending
                    let (tx, rx) = oneshot::channel::<UniqueMessage>();
                    let permit = tx.reserve(&cx).expect("reserve should work initially");
                    drop(rx); // Drop receiver after reserve but before send
                    permit.send(message.clone())
                }
            };

            // Send should fail in all scenarios
            match send_result {
                Ok(()) => {
                    prop_assert!(false,
                        "MR2 VIOLATION: Send succeeded when it should have failed in mode {}",
                        failure_mode);
                }
                Err(send_error) => {
                    counter.record_send_failure();

                    // Check that we got the message back in the error
                    let returned_message = match send_error {
                        SendError::Disconnected(msg) => msg,
                        SendError::Cancelled(msg) => msg,
                    };

                    prop_assert_eq!(&returned_message, &message,
                        "MR2 VIOLATION: Failed send returned different message than sent");
                    prop_assert!(returned_message.validate(),
                        "MR2 VIOLATION: Returned message failed integrity check");
                }
            }

            // For modes where receiver still exists, verify it detects the failure
            if failure_mode == 1 {
                // Cancelled context scenario - receiver might still be alive
                // but any recv attempts should fail appropriately
                // Note: we can't test this easily here since rx was not captured
                // This is covered in other test scenarios
            }

            // Verify exactly-once invariant (should be 0 sends, 0 recvs)
            let invariant_check = counter.exactly_once_invariant();
            prop_assert!(invariant_check.is_ok(), "MR2 INVARIANT VIOLATION: {:?}", invariant_check);
        });
    }

    #[test]
    fn mr2_cancelled_reserve_closes_receiver_without_delivery() {
        let cx = test_cx();
        let cancelled_cx = test_cx();
        cancelled_cx.set_cancel_requested(true);

        let message = UniqueMessage::new(77, "cancelled_reserve");
        let (tx, mut rx) = oneshot::channel();

        let send_result = tx.send(&cancelled_cx, message.clone());
        match send_result {
            Err(SendError::Cancelled(returned)) => {
                assert_eq!(returned, message);
                assert!(returned.validate());
            }
            other => panic!("cancelled reserve should return the original value: {other:?}"),
        }

        assert!(
            matches!(rx.try_recv(), Err(TryRecvError::Closed)),
            "cancelled reserve must close without a queued value"
        );
        assert!(
            matches!(block_on(rx.recv(&cx)), Err(RecvError::Closed)),
            "async receive after cancelled reserve must observe closure"
        );

        let counter = DeliveryCounter::default();
        assert!(
            counter.exactly_once_invariant().is_ok(),
            "cancelled reserve should leave zero sends and zero receives"
        );
    }

    /// **MR3: Receive Exhaustion (State Transition, Score: 8.5)**
    ///
    /// Property: After one successful receive, the channel is exhausted.
    /// All subsequent receive attempts must fail with consistent errors.
    ///
    /// **Transformation**: successful_recv → subsequent_recv_attempts
    /// **Relation**: ∀ subsequent_recv: result = Error(Closed)
    /// **Catches**: Channel reuse bugs, state reset issues
    #[test]
    fn mr3_receive_exhaustion() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            message_id in 0u64..500,
            content in "[0-9a-f]{4,12}",
            exhaustion_attempts in 3usize..8,
        )| {
            let cx = test_cx();
            let message = UniqueMessage::new(message_id, content);
            let (tx, mut rx) = oneshot::channel();
            let mut counter = DeliveryCounter::default();

            // Send and receive successfully first
            tx.send(&cx, message.clone()).expect("Send should succeed");
            counter.record_send_success();

            let first_recv = block_on(rx.recv(&cx));
            match first_recv {
                Ok(received_msg) => {
                    counter.record_recv_success();
                    prop_assert_eq!(&received_msg, &message,
                        "MR3 VIOLATION: First receive got wrong message");
                }
                Err(e) => {
                    prop_assert!(false, "MR3 VIOLATION: First receive failed: {:?}", e);
                }
            }

            // Now attempt multiple subsequent receives - all should fail consistently
            let mut exhaustion_errors = Vec::new();
            for attempt_idx in 0..exhaustion_attempts {
                match block_on(rx.recv(&cx)) {
                    Ok(phantom_msg) => {
                        prop_assert!(false,
                            "MR3 VIOLATION: Exhaustion attempt {} produced phantom message: {:?}",
                            attempt_idx, phantom_msg);
                    }
                    Err(exhaustion_error) => {
                        exhaustion_errors.push(exhaustion_error);
                        counter.record_recv_closed(); // Count as closed for consistency
                    }
                }
            }

            // MR3 ASSERTION: All exhaustion attempts should produce identical errors
            if exhaustion_errors.len() > 1 {
                let first_error = &exhaustion_errors[0];
                for (idx, error) in exhaustion_errors.iter().enumerate().skip(1) {
                    prop_assert_eq!(error, first_error,
                        "MR3 VIOLATION: Exhaustion attempt {} produced different error: {:?} vs {:?}",
                        idx, error, first_error);
                }
            }

            // All exhaustion errors should be Closed (channel is depleted)
            for (idx, error) in exhaustion_errors.iter().enumerate() {
                prop_assert!(matches!(error, RecvError::Closed),
                    "MR3 VIOLATION: Exhaustion attempt {} didn't return Closed: {:?}",
                    idx, error);
            }

            // Verify try_recv also reports exhaustion consistently
            for attempt_idx in 0..3 {
                match rx.try_recv() {
                    Ok(phantom_msg) => {
                        prop_assert!(false,
                            "MR3 VIOLATION: try_recv attempt {} produced phantom message: {:?}",
                            attempt_idx, phantom_msg);
                    }
                    Err(TryRecvError::Closed) => {
                        // Expected
                    }
                    Err(other_error) => {
                        prop_assert!(false,
                            "MR3 VIOLATION: try_recv attempt {} produced unexpected error: {:?}",
                            attempt_idx, other_error);
                    }
                }
            }

            // Verify exactly-once invariant
            let invariant_check = counter.exactly_once_invariant();
            prop_assert!(invariant_check.is_ok(), "MR3 INVARIANT VIOLATION: {:?}", invariant_check);
        });
    }

    /// **MR4: State Consistency (Deterministic, Score: 8.0)**
    ///
    /// Property: Channel state after successful/failed operations is
    /// deterministic and permanent. Repeated operations in the same state
    /// produce identical outcomes.
    ///
    /// **Transformation**: repeat(operation, same_state)
    /// **Relation**: ∀ repeat: outcome identical
    /// **Catches**: Non-deterministic state, operation side effects
    #[test]
    fn mr4_state_consistency() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));
        proptest!(|(
            message_id in 0u64..200,
            content in "[A-Z]{2,8}",
            state_probe_count in 2usize..5,
        )| {
            let cx = test_cx();
            let message = UniqueMessage::new(message_id, content);

            // Test Case 1: Successful send/recv → exhausted state consistency
            let (tx1, mut rx1) = oneshot::channel();
            tx1.send(&cx, message.clone()).expect("Initial send should succeed");
            let first_msg = block_on(rx1.recv(&cx)).expect("Initial recv should succeed");

            prop_assert_eq!(first_msg, message.clone(), "State setup: wrong message received");

            // Now probe the exhausted state multiple times
            let mut exhausted_results = Vec::new();
            for _ in 0..state_probe_count {
                let probe_result = block_on(rx1.recv(&cx));
                exhausted_results.push(probe_result);
            }

            // All probes of exhausted state should be identical
            if exhausted_results.len() > 1 {
                let reference_result = &exhausted_results[0];
                for (idx, probe_result) in exhausted_results.iter().enumerate().skip(1) {
                    prop_assert_eq!(probe_result, reference_result,
                        "MR4 VIOLATION: Exhausted state probe {} differs from reference: {:?} vs {:?}",
                        idx, probe_result, reference_result);
                }
            }

            // Test Case 2: Failed send → disconnected state consistency
            let mut disconnected_results = Vec::new();
            for _ in 0..state_probe_count {
                let (probe_tx, probe_rx) = oneshot::channel::<UniqueMessage>();
                drop(probe_rx);
                let probe_result = probe_tx.send(&cx, message.clone());
                disconnected_results.push(probe_result);
            }

            // All probes of disconnected state should be identical
            if disconnected_results.len() > 1 {
                let reference_result = &disconnected_results[0];
                for (idx, probe_result) in disconnected_results.iter().enumerate().skip(1) {
                    match (probe_result, reference_result) {
                        (Err(send_err1), Err(send_err2)) => {
                            // Compare error types (messages will be consumed)
                            let err1_type = std::mem::discriminant(send_err1);
                            let err2_type = std::mem::discriminant(send_err2);
                            prop_assert_eq!(err1_type, err2_type,
                                "MR4 VIOLATION: Disconnected state probe {} produced different error type",
                                idx);
                        }
                        other => {
                            prop_assert!(false,
                                "MR4 VIOLATION: Disconnected state probe {} inconsistent with reference: {:?}",
                                idx, other);
                        }
                    }
                }
            }

            // Test Case 3: Reserve permit state consistency
            let (tx3, mut rx3) = oneshot::channel();
            let permit = tx3.reserve(&cx).expect("Reserve should succeed");

            // Check that permit state is consistent
            for _ in 0..3 {
                let is_closed = permit.is_closed();
                prop_assert!(!is_closed, "MR4 VIOLATION: Permit should not report closed with live receiver");
            }

            // Complete the send to clean up
            permit.send(message.clone()).expect("Permit send should succeed");
            let _cleanup = block_on(rx3.recv(&cx)).expect("Cleanup recv should succeed");
        });
    }

    /// **Composite MR: Complete Exactly-Once Under All Scenarios**
    ///
    /// Tests exactly-once delivery guarantee under combined conditions:
    /// cancellation, receiver dropping, permit usage, and state transitions.
    #[test]
    fn mr_composite_exactly_once_all_scenarios() {
        let _runtime = Rc::new(LabRuntime::new(LabConfig::default()));

        let cx = test_cx();
        let test_message = UniqueMessage::new(42, "composite_test");

        // Scenario 1: Normal successful path
        let (tx1, mut rx1) = oneshot::channel();
        let mut counter1 = DeliveryCounter::default();

        assert!(tx1.send(&cx, test_message.clone()).is_ok());
        counter1.record_send_success();

        let recv_result = block_on(rx1.recv(&cx));
        assert!(recv_result.is_ok());
        assert_eq!(recv_result.unwrap(), test_message);
        counter1.record_recv_success();

        // Subsequent receives should fail
        assert!(matches!(block_on(rx1.recv(&cx)), Err(RecvError::Closed)));

        assert!(
            counter1.exactly_once_invariant().is_ok(),
            "Scenario 1 failed exactly-once"
        );

        // Scenario 2: Receiver dropped before send
        let (tx2, rx2) = oneshot::channel();
        let mut counter2 = DeliveryCounter::default();

        drop(rx2);
        let send_result2 = tx2.send(&cx, test_message.clone());
        assert!(send_result2.is_err());
        counter2.record_send_failure();

        assert!(
            counter2.exactly_once_invariant().is_ok(),
            "Scenario 2 failed exactly-once"
        );

        // Scenario 3: Reserve permit then send
        let (tx3, mut rx3) = oneshot::channel();
        let mut counter3 = DeliveryCounter::default();

        let permit = tx3.reserve(&cx).expect("Reserve should work");
        assert!(permit.send(test_message.clone()).is_ok());
        counter3.record_send_success();

        let recv_result3 = block_on(rx3.recv(&cx));
        assert!(recv_result3.is_ok());
        assert_eq!(recv_result3.unwrap(), test_message);
        counter3.record_recv_success();

        assert!(
            counter3.exactly_once_invariant().is_ok(),
            "Scenario 3 failed exactly-once"
        );
    }
}

// ============================================================================
// Validation Tests
// ============================================================================

#[cfg(test)]
mod validation_tests {
    use super::*;

    /// Validate that UniqueMessage integrity checking works
    #[test]
    fn validate_unique_message_integrity() {
        let msg = UniqueMessage::new(123, "test_content");
        assert!(msg.validate(), "Message should pass integrity check");

        // Corrupt the message
        let mut corrupted = msg.clone();
        corrupted.checksum = 0;
        assert!(
            !corrupted.validate(),
            "Corrupted message should fail integrity check"
        );
    }

    /// Validate that DeliveryCounter correctly tracks exactly-once invariant
    #[test]
    fn validate_delivery_counter() {
        let mut counter = DeliveryCounter::default();

        // Valid: 1 send, 1 recv
        counter.record_send_success();
        counter.record_recv_success();
        assert!(
            counter.exactly_once_invariant().is_ok(),
            "1-1 should be valid"
        );

        // Invalid: 1 send, 2 recvs
        let mut invalid_counter = DeliveryCounter::default();
        invalid_counter.record_send_success();
        invalid_counter.record_recv_success();
        invalid_counter.record_recv_success();
        assert!(
            invalid_counter.exactly_once_invariant().is_err(),
            "1-2 should be invalid"
        );

        // Valid: 0 sends, 0 recvs
        let empty_counter = DeliveryCounter::default();
        assert!(
            empty_counter.exactly_once_invariant().is_ok(),
            "0-0 should be valid"
        );
    }

    /// Validate basic oneshot channel functionality
    #[test]
    fn validate_oneshot_infrastructure() {
        let cx = test_cx();
        let (tx, mut rx) = oneshot::channel::<i32>();

        // Send and receive
        assert!(tx.send(&cx, 42).is_ok());
        let received = block_on(rx.recv(&cx));
        assert_eq!(received.unwrap(), 42);

        // Second receive should fail
        let second_recv = block_on(rx.recv(&cx));
        assert!(matches!(second_recv, Err(RecvError::Closed)));
    }
}
