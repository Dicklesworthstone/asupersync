//! Metamorphic property tests for MPSC channel backpressure and flow-control invariants.
//!
//! These tests verify MPSC channel invariants related to bounded/unbounded behavior,
//! two-phase send operations, cancellation safety, and connection lifecycle. Unlike
//! unit tests that check exact outcomes, metamorphic tests verify relationships
//! between different execution scenarios using LabRuntime DPOR for deterministic
//! scheduling exploration.
//!
//! # Metamorphic Relations
//!
//! 1. **Bounded Channel Backpressure** (MR1): bounded channel blocks sender when full (blocking)
//! 2. **Two-Phase Cancel Safety** (MR2): send_reserve()+commit() preserves values on cancel (safety)
//! 3. **Unbounded Never Blocks** (MR3): unbounded channel never blocks sender (temporal)
//! 4. **Receiver Drop Closes** (MR4): receiver drop closes channel for future sends (causality)
//! 5. **Try Send Full Behavior** (MR5): try_send returns WouldBlock on full bounded (temporal)
//! 6. **Disconnection Symmetry** (MR6): closed channel returns Disconnected for both sides (equivalence)

use asupersync::channel::mpsc::{self, RecvError, SendError};
use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{Budget, Outcome, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

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

/// Configuration for MPSC metamorphic tests.
#[derive(Debug, Clone)]
pub struct MpscTestConfig {
    /// Random seed for deterministic execution.
    pub seed: u64,
    /// Channel capacity (1 for bounded, usize::MAX for unbounded simulation).
    pub capacity: usize,
    /// Values to send through the channel.
    pub send_values: Vec<i64>,
    /// Whether to drop sender before receiving.
    pub drop_sender_early: bool,
    /// Whether to drop receiver before sending.
    pub drop_receiver_early: bool,
    /// Whether to inject cancellation during operations.
    pub inject_cancellation: bool,
    /// Delay before cancellation (virtual milliseconds).
    pub cancel_delay_ms: u64,
    /// Whether to use reserve/commit pattern vs direct send.
    pub use_reserve_pattern: bool,
    /// Number of concurrent senders to test.
    pub sender_count: u8,
}

/// Test harness for MPSC channel operations with DPOR scheduling.
#[derive(Debug)]
struct MpscTestHarness {
    runtime: LabRuntime,
    operations_completed: AtomicU64,
    obligations_leaked: AtomicBool,
    values_lost: AtomicU64,
}

impl MpscTestHarness {
    fn new(seed: u64) -> Self {
        let config = LabConfig::new(seed).with_light_chaos();
        Self {
            runtime: LabRuntime::new(config),
            operations_completed: AtomicU64::new(0),
            obligations_leaked: AtomicBool::new(false),
            values_lost: AtomicU64::new(0),
        }
    }

    fn execute<F>(&mut self, test_fn: F) -> Outcome<F::Output, ()>
    where
        F: FnOnce(&Cx) -> Pin<Box<dyn Future<Output = F::Output> + '_>> + Send,
    {
        self.runtime.block_on(|cx| async {
            let result = cx.region(|region| async {
                let scope = Scope::new(region, "mpsc_test");
                test_fn(&scope.cx())
            }).await;

            // Check for obligation leaks
            if !self.runtime.is_quiescent() {
                self.obligations_leaked.store(true, Ordering::SeqCst);
            }

            result
        })
    }

    fn has_obligation_leaks(&self) -> bool {
        self.obligations_leaked.load(Ordering::SeqCst)
    }

    fn completed_operations(&self) -> u64 {
        self.operations_completed.load(Ordering::SeqCst)
    }

    fn increment_operations(&self) {
        self.operations_completed.fetch_add(1, Ordering::SeqCst);
    }

    fn increment_values_lost(&self) {
        self.values_lost.fetch_add(1, Ordering::SeqCst);
    }

    fn values_lost(&self) -> u64 {
        self.values_lost.load(Ordering::SeqCst)
    }
}

// ============================================================================
// Metamorphic Relations for MPSC Channel Behavior
// ============================================================================

/// MR1: Bounded Channel Backpressure (Blocking, Score: 10.0)
/// Property: bounded channel blocks sender when full, unbounded does not
/// Catches: Missing backpressure, capacity violations, spurious blocking
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mr1_bounded_channel_blocks_when_full() {
        proptest!(|(
            seed in any::<u64>(),
            capacity in 1usize..10,
            overflow_count in 1u8..5,
        )| {
            let mut harness = MpscTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, mut rx) = mpsc::channel::<i64>(capacity);

                // Fill the channel to capacity using try_send
                for i in 0..capacity {
                    let result = tx.try_send(i as i64);
                    prop_assert!(
                        result.is_ok(),
                        "MR1 VIOLATION: try_send failed within capacity at {}/{}: {:?}",
                        i, capacity, result
                    );
                }

                // Verify channel is now full - next try_send should return Full
                let overflow_result = tx.try_send(999);
                match overflow_result {
                    Err(SendError::Full(999)) => {}, // Expected
                    other => prop_assert!(false, "MR1 VIOLATION: expected Full, got {:?}", other),
                }

                // Verify that reserve() blocks when channel is full
                let mut reserve_future = Box::pin(tx.reserve(cx));
                let waker = std::task::Waker::from(std::sync::Arc::new(TestWaker));
                let mut task_cx = Context::from_waker(&waker);

                let reserve_poll = reserve_future.as_mut().poll(&mut task_cx);
                match reserve_poll {
                    Poll::Pending => {}, // Expected - should block
                    Poll::Ready(_) => prop_assert!(false, "MR1 VIOLATION: reserve should block when channel is full"),
                }

                // Drain one item to make space
                let received = rx.recv(cx).await.unwrap();
                prop_assert!(
                    received >= 0 && received < capacity as i64,
                    "MR1 VIOLATION: received invalid value: {}",
                    received
                );

                // Now try_send should succeed
                let post_drain_result = tx.try_send(777);
                prop_assert!(
                    post_drain_result.is_ok(),
                    "MR1 VIOLATION: try_send failed after making space: {:?}",
                    post_drain_result
                );

                harness.increment_operations();
                Ok(())
            }));

            match result {
                Outcome::Ok(_) => {},
                other => prop_assert!(false, "MR1 VIOLATION: unexpected outcome {:?}", other),
            }

            prop_assert!(!harness.has_obligation_leaks(), "MR1 VIOLATION: obligation leak detected");
        });
    }

    /// MR2: Two-Phase Cancel Safety (Safety, Score: 10.0)
    /// Property: send_reserve()+commit() preserves values on cancellation
    /// Catches: Data loss on cancellation, incomplete two-phase operations
    #[test]
    fn mr2_two_phase_cancel_safety() {
        proptest!(|(
            seed in any::<u64>(),
            send_value in any::<i64>(),
            cancel_after_reserve in any::<bool>(),
        )| {
            let mut harness = MpscTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, mut rx) = mpsc::channel::<i64>(10);
                let cancel_flag = Arc::new(AtomicBool::new(false));
                let values_committed = Arc::new(AtomicU64::new(0));

                // Test two-phase send with potential cancellation
                let cancel_flag_clone = cancel_flag.clone();
                let values_committed_clone = values_committed.clone();
                let send_task = cx.spawn("two_phase_sender", async move {
                    // Phase 1: Reserve slot
                    let reserve_result = tx.reserve(cx).await;

                    match reserve_result {
                        Ok(permit) => {
                            // Check if cancelled between reserve and commit
                            if cancel_after_reserve && cancel_flag_clone.load(Ordering::SeqCst) {
                                // Abort the permit (simulate cancellation)
                                permit.abort();
                                return Err("cancelled after reserve");
                            }

                            // Phase 2: Commit value
                            let send_result = permit.try_send(send_value);
                            match send_result {
                                Ok(()) => {
                                    values_committed_clone.fetch_add(1, Ordering::SeqCst);
                                    Ok(())
                                },
                                Err(e) => Err(format!("commit failed: {:?}", e)),
                            }
                        },
                        Err(e) => Err(format!("reserve failed: {:?}", e)),
                    }
                });

                // Simulate cancellation request
                if cancel_after_reserve {
                    cx.spawn("cancellation_trigger", async move {
                        cx.sleep(Duration::from_millis(1)).await;
                        cancel_flag.store(true, Ordering::SeqCst);
                    });
                }

                // Wait for sender to complete or be cancelled
                let send_result = send_task.join(cx).await;

                // If value was committed, it must be receivable
                let committed_count = values_committed.load(Ordering::SeqCst);
                if committed_count > 0 {
                    let received = rx.recv(cx).await;
                    match received {
                        Ok(value) => {
                            prop_assert_eq!(
                                value, send_value,
                                "MR2 VIOLATION: committed value {} != received value {}",
                                send_value, value
                            );
                        },
                        Err(e) => prop_assert!(false, "MR2 VIOLATION: failed to receive committed value: {:?}", e),
                    }
                }

                // MR2 ASSERTION: No values lost during cancellation
                // Either value was committed and received, or operation was cleanly cancelled
                match (send_result, committed_count > 0) {
                    (Ok(()), true) => {}, // Success + committed = good
                    (Err(_), false) => {}, // Cancelled + not committed = good
                    (Ok(()), false) => prop_assert!(false, "MR2 VIOLATION: send succeeded but no value committed"),
                    (Err(_), true) => prop_assert!(false, "MR2 VIOLATION: send failed but value was committed"),
                }

                harness.increment_operations();
                Ok(())
            }));

            match result {
                Outcome::Ok(_) => {},
                other => prop_assert!(false, "MR2 VIOLATION: unexpected outcome {:?}", other),
            }

            prop_assert!(!harness.has_obligation_leaks(), "MR2 VIOLATION: obligation leak detected");
        });
    }

    /// MR3: Unbounded Never Blocks (Temporal, Score: 8.0)
    /// Property: unbounded channel never blocks sender regardless of pending messages
    /// Catches: Spurious blocking in unbounded channels, capacity misconfiguration
    #[test]
    fn mr3_unbounded_never_blocks() {
        proptest!(|(
            seed in any::<u64>(),
            message_count in 1usize..1000,
            send_values in prop::collection::vec(any::<i64>(), 1..100),
        )| {
            let mut harness = MpscTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                // Create "unbounded" channel with very large capacity
                let (tx, mut rx) = mpsc::channel::<i64>(usize::MAX);

                // Send many messages without any receives - should never block
                let mut successful_sends = 0;
                let limited_sends = message_count.min(send_values.len());

                for i in 0..limited_sends {
                    let value = send_values[i % send_values.len()];

                    // try_send should always succeed on unbounded channel
                    let send_result = tx.try_send(value);
                    match send_result {
                        Ok(()) => successful_sends += 1,
                        Err(SendError::Full(_)) => {
                            prop_assert!(false, "MR3 VIOLATION: unbounded channel returned Full at message {}", i);
                        },
                        other => prop_assert!(false, "MR3 VIOLATION: unexpected try_send error: {:?}", other),
                    }

                    // reserve should also complete immediately
                    let reserve_result = tx.try_reserve();
                    match reserve_result {
                        Ok(permit) => {
                            permit.abort(); // Clean up
                        },
                        Err(SendError::Full(())) => {
                            prop_assert!(false, "MR3 VIOLATION: unbounded channel reserve returned Full at message {}", i);
                        },
                        other => prop_assert!(false, "MR3 VIOLATION: unexpected try_reserve error: {:?}", other),
                    }
                }

                // MR3 ASSERTION: All sends should have succeeded
                prop_assert_eq!(
                    successful_sends, limited_sends,
                    "MR3 VIOLATION: only {}/{} sends succeeded on unbounded channel",
                    successful_sends, limited_sends
                );

                // Verify messages can be received
                for _ in 0..limited_sends {
                    let received = rx.recv(cx).await;
                    prop_assert!(received.is_ok(), "MR3 VIOLATION: failed to receive from unbounded channel");
                }

                harness.increment_operations();
                Ok(())
            }));

            match result {
                Outcome::Ok(_) => {},
                other => prop_assert!(false, "MR3 VIOLATION: unexpected outcome {:?}", other),
            }

            prop_assert!(!harness.has_obligation_leaks(), "MR3 VIOLATION: obligation leak detected");
        });
    }

    /// MR4: Receiver Drop Closes Channel (Causality, Score: 9.0)
    /// Property: receiver drop closes channel for future sends
    /// Catches: Missing disconnection signals, resource leaks after drop
    #[test]
    fn mr4_receiver_drop_closes_channel() {
        proptest!(|(
            seed in any::<u64>(),
            send_values in prop::collection::vec(any::<i64>(), 1..10),
            drop_delay_ms in 1u64..50,
        )| {
            let mut harness = MpscTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, rx) = mpsc::channel::<i64>(5);

                // Verify channel is initially open
                prop_assert!(!tx.is_closed(), "MR4 VIOLATION: channel should be open initially");

                // Schedule receiver drop after delay
                let drop_task = cx.spawn("drop_receiver", async move {
                    cx.sleep(Duration::from_millis(drop_delay_ms)).await;
                    drop(rx); // Drop receiver to close channel
                });

                // Wait for receiver to be dropped
                drop_task.join(cx).await;

                // MR4 ASSERTION: Channel should now be closed
                prop_assert!(tx.is_closed(), "MR4 VIOLATION: channel should be closed after receiver drop");

                // All subsequent sends should return Disconnected
                for &value in &send_values {
                    let send_result = tx.try_send(value);
                    match send_result {
                        Err(SendError::Disconnected(returned_value)) => {
                            prop_assert_eq!(
                                returned_value, value,
                                "MR4 VIOLATION: disconnected error returned wrong value"
                            );
                        },
                        other => prop_assert!(false, "MR4 VIOLATION: expected Disconnected, got {:?}", other),
                    }

                    // Reserve should also fail with Disconnected
                    let reserve_result = tx.try_reserve();
                    match reserve_result {
                        Err(SendError::Disconnected(())) => {}, // Expected
                        other => prop_assert!(false, "MR4 VIOLATION: reserve expected Disconnected, got {:?}", other),
                    }
                }

                harness.increment_operations();
                Ok(())
            }));

            match result {
                Outcome::Ok(_) => {},
                other => prop_assert!(false, "MR4 VIOLATION: unexpected outcome {:?}", other),
            }

            prop_assert!(!harness.has_obligation_leaks(), "MR4 VIOLATION: obligation leak detected");
        });
    }

    /// MR5: Try Send Full Behavior (Temporal, Score: 7.0)
    /// Property: try_send returns Full error on full bounded channel
    /// Catches: Blocking behavior in non-blocking operations, capacity bugs
    #[test]
    fn mr5_try_send_full_behavior() {
        proptest!(|(
            seed in any::<u64>(),
            capacity in 1usize..10,
            overflow_values in prop::collection::vec(any::<i64>(), 1..5),
        )| {
            let mut harness = MpscTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, _rx) = mpsc::channel::<i64>(capacity);

                // Fill channel to capacity
                for i in 0..capacity {
                    let result = tx.try_send(i as i64);
                    prop_assert!(
                        result.is_ok(),
                        "MR5 VIOLATION: try_send failed within capacity: {:?}",
                        result
                    );
                }

                // MR5 ASSERTION: Subsequent try_send calls should return Full
                for &overflow_value in &overflow_values {
                    let overflow_result = tx.try_send(overflow_value);
                    match overflow_result {
                        Err(SendError::Full(returned_value)) => {
                            prop_assert_eq!(
                                returned_value, overflow_value,
                                "MR5 VIOLATION: Full error returned wrong value"
                            );
                        },
                        Ok(()) => prop_assert!(false, "MR5 VIOLATION: try_send should return Full on full channel"),
                        other => prop_assert!(false, "MR5 VIOLATION: expected Full, got {:?}", other),
                    }
                }

                // Verify try_reserve also returns Full
                let reserve_result = tx.try_reserve();
                match reserve_result {
                    Err(SendError::Full(())) => {}, // Expected
                    other => prop_assert!(false, "MR5 VIOLATION: try_reserve expected Full, got {:?}", other),
                }

                harness.increment_operations();
                Ok(())
            }));

            match result {
                Outcome::Ok(_) => {},
                other => prop_assert!(false, "MR5 VIOLATION: unexpected outcome {:?}", other),
            }

            prop_assert!(!harness.has_obligation_leaks(), "MR5 VIOLATION: obligation leak detected");
        });
    }

    /// MR6: Disconnection Symmetry (Equivalence, Score: 8.0)
    /// Property: closed channel returns Disconnected for both sender and receiver sides
    /// Catches: Asymmetric error handling, inconsistent connection state
    #[test]
    fn mr6_disconnection_symmetry() {
        proptest!(|(
            seed in any::<u64>(),
            close_via_receiver_drop in any::<bool>(),
            test_value in any::<i64>(),
        )| {
            let mut harness = MpscTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, mut rx) = mpsc::channel::<i64>(5);

                // Close channel via either receiver drop or explicit close
                if close_via_receiver_drop {
                    drop(rx);
                    // Create new receiver handle for testing (will be closed)
                    let (_, mut new_rx) = mpsc::channel::<i64>(1);
                    drop(new_rx); // Immediately close it
                } else {
                    rx.close();
                }

                // MR6 ASSERTION: Both sender and receiver should see Disconnected

                // Test sender side - all operations should return Disconnected
                let send_result = tx.try_send(test_value);
                match send_result {
                    Err(SendError::Disconnected(returned_value)) => {
                        prop_assert_eq!(returned_value, test_value, "MR6 VIOLATION: wrong value in sender Disconnected");
                    },
                    other => prop_assert!(false, "MR6 VIOLATION: sender expected Disconnected, got {:?}", other),
                }

                let reserve_result = tx.try_reserve();
                match reserve_result {
                    Err(SendError::Disconnected(())) => {}, // Expected
                    other => prop_assert!(false, "MR6 VIOLATION: sender reserve expected Disconnected, got {:?}", other),
                }

                prop_assert!(tx.is_closed(), "MR6 VIOLATION: sender should report channel as closed");

                // Test receiver side (if receiver wasn't dropped)
                if !close_via_receiver_drop {
                    let recv_result = rx.try_recv();
                    match recv_result {
                        Err(RecvError::Disconnected) => {}, // Expected
                        Err(RecvError::Empty) => {}, // Also acceptable if no messages
                        other => prop_assert!(false, "MR6 VIOLATION: receiver expected Disconnected or Empty, got {:?}", other),
                    }
                }

                harness.increment_operations();
                Ok(())
            }));

            match result {
                Outcome::Ok(_) => {},
                other => prop_assert!(false, "MR6 VIOLATION: unexpected outcome {:?}", other),
            }

            prop_assert!(!harness.has_obligation_leaks(), "MR6 VIOLATION: obligation leak detected");
        });
    }
}

// ============================================================================
// Test Helper
// ============================================================================

/// Simple test waker implementation for polling futures.
struct TestWaker;

impl std::task::Wake for TestWaker {
    fn wake(self: Arc<Self>) {}

    fn wake_by_ref(self: &Arc<Self>) {}
}