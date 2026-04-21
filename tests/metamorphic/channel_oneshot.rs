#![allow(clippy::all)]
//! Metamorphic property tests for oneshot channel send/recv completion invariants.
//!
//! These tests verify oneshot channel invariants related to two-phase send/recv operations,
//! cancellation safety, and obligation tracking. Unlike unit tests that check exact
//! outcomes, metamorphic tests verify relationships between different execution scenarios.
//!
//! # Metamorphic Relations
//!
//! 1. **Send-Recv Commutativity** (MR1): send-then-recv returns the exact value sent (equivalence)
//! 2. **Recv-Without-Send Blocking** (MR2): recv without send blocks until sender drops or sends (temporal)
//! 3. **Sender-Drop Disconnect** (MR3): sender drop causes recv to return RecvError::Closed (causality)
//! 4. **Receiver-Drop Disconnect** (MR4): receiver drop causes send to return SendError::Disconnected (causality)
//! 5. **Cancel-During-Recv Safety** (MR5): cancel during recv drains cleanly without obligation leak (safety)

use asupersync::channel::oneshot::{self, RecvError, SendError, TryRecvError};
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

/// Simple block_on implementation for tests.
fn block_on<F: Future>(f: F) -> F::Output {
    struct NoopWaker;
    impl std::task::Wake for NoopWaker {
        fn wake(self: std::sync::Arc<Self>) {}
    }
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

/// Configuration for oneshot metamorphic tests.
#[derive(Debug, Clone)]
pub struct OneShotTestConfig {
    /// Random seed for deterministic execution.
    pub seed: u64,
    /// Value to send through the channel.
    pub send_value: i64,
    /// Whether to drop sender before receiving.
    pub drop_sender_early: bool,
    /// Whether to drop receiver before sending.
    pub drop_receiver_early: bool,
    /// Whether to inject cancellation during recv.
    pub inject_cancellation: bool,
    /// Delay before cancellation (virtual milliseconds).
    pub cancel_delay_ms: u64,
    /// Whether to use reserve/send pattern vs direct send.
    pub use_reserve_pattern: bool,
    /// Number of concurrent operations to test.
    pub operation_count: u8,
}

/// Test harness for oneshot channel operations.
#[derive(Debug)]
struct OneShotTestHarness {
    runtime: LabRuntime,
    operations_completed: AtomicU64,
    obligations_leaked: AtomicBool,
}

impl OneShotTestHarness {
    fn new(seed: u64) -> Self {
        let config = LabConfig::new(seed).with_light_chaos();
        Self {
            runtime: LabRuntime::new(config),
            operations_completed: AtomicU64::new(0),
            obligations_leaked: AtomicBool::new(false),
        }
    }

    fn execute<F>(&mut self, test_fn: F) -> Outcome<F::Output, ()>
    where
        F: FnOnce(&Cx) -> Pin<Box<dyn Future<Output = F::Output> + '_>> + Send,
    {
        self.runtime.block_on(|cx| async {
            let result = cx.region(|region| async {
                let scope = Scope::new(region, "oneshot_test");
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
}

// ============================================================================
// Metamorphic Relations for OneShot Channel Behavior
// ============================================================================

/// MR1: Send-Recv Commutativity (Equivalence, Score: 10.0)
/// Property: send(value) followed by recv() returns exactly the same value
/// Catches: Value corruption, type conversion errors, memory safety issues
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mr1_send_recv_commutativity() {
        proptest!(|(
            seed in any::<u64>(),
            send_value in any::<i64>(),
            use_reserve in any::<bool>(),
        )| {
            let mut harness = OneShotTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, mut rx) = oneshot::channel::<i64>();

                // Send the value using either direct send or reserve/send pattern
                if use_reserve {
                    let permit = tx.reserve(cx);
                    permit.send(send_value).unwrap();
                } else {
                    tx.send(cx, send_value).unwrap();
                }

                // Receive the value
                let received_value = rx.recv(cx).await.unwrap();

                // METAMORPHIC ASSERTION: sent value equals received value
                prop_assert_eq!(
                    received_value, send_value,
                    "MR1 VIOLATION: sent {} but received {}",
                    send_value, received_value
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

    /// MR2: Recv-Without-Send Blocking (Temporal, Score: 9.0)
    /// Property: recv() without corresponding send() blocks until sender drops or sends
    /// Catches: Spurious wakeups, incorrect ready state, premature completion
    #[test]
    fn mr2_recv_without_send_blocking() {
        proptest!(|(
            seed in any::<u64>(),
            drop_delay_ms in 1u64..100,
        )| {
            let mut harness = OneShotTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, mut rx) = oneshot::channel::<i64>();

                // First, verify try_recv returns Empty (not Ready)
                match rx.try_recv() {
                    Err(TryRecvError::Empty) => {}, // Expected
                    other => prop_assert!(false, "MR2 VIOLATION: try_recv should return Empty, got {:?}", other),
                }

                // Verify channel state predicates
                prop_assert!(!rx.is_ready(), "MR2 VIOLATION: receiver should not be ready without send");
                prop_assert!(!rx.is_closed(), "MR2 VIOLATION: receiver should not be closed with sender alive");
                prop_assert!(!tx.is_closed(), "MR2 VIOLATION: sender should not be closed with receiver alive");

                // Schedule sender drop after delay
                let drop_task = cx.spawn("drop_sender", async move {
                    cx.sleep(Duration::from_millis(drop_delay_ms)).await;
                    drop(tx); // Drop sender to unblock receiver
                });

                // This recv should block until sender drops
                let recv_result = rx.recv(cx).await;

                // Should get Closed error since sender was dropped
                match recv_result {
                    Err(RecvError::Closed) => {}, // Expected
                    other => prop_assert!(false, "MR2 VIOLATION: recv should return Closed after sender drop, got {:?}", other),
                }

                // Verify final state
                prop_assert!(rx.is_closed(), "MR2 VIOLATION: receiver should be closed after sender drop");

                // Wait for drop task to complete
                drop_task.join(cx).await;

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

    /// MR3: Sender-Drop Disconnect (Causality, Score: 9.5)
    /// Property: dropping sender causes recv to return RecvError::Closed
    /// Catches: Resource cleanup failures, state inconsistency, waker retention
    #[test]
    fn mr3_sender_drop_disconnect() {
        proptest!(|(
            seed in any::<u64>(),
            drop_before_recv in any::<bool>(),
        )| {
            let mut harness = OneShotTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, mut rx) = oneshot::channel::<i64>();

                if drop_before_recv {
                    // Drop sender first, then try to receive
                    drop(tx);

                    // Should immediately return Closed
                    match rx.recv(cx).await {
                        Err(RecvError::Closed) => {}, // Expected
                        other => prop_assert!(false, "MR3 VIOLATION: recv should return Closed after early sender drop, got {:?}", other),
                    }
                } else {
                    // Start receive first, then drop sender during the wait
                    let recv_task = cx.spawn("recv_task", async move {
                        rx.recv(cx).await
                    });

                    // Give recv a chance to start waiting
                    cx.yield_now().await;

                    // Drop sender to trigger disconnect
                    drop(tx);

                    // Wait for recv to complete
                    let recv_result = recv_task.join(cx).await;

                    match recv_result {
                        Err(RecvError::Closed) => {}, // Expected
                        other => prop_assert!(false, "MR3 VIOLATION: recv should return Closed after sender drop during wait, got {:?}", other),
                    }
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

    /// MR4: Receiver-Drop Disconnect (Causality, Score: 9.5)
    /// Property: dropping receiver causes send to return SendError::Disconnected
    /// Catches: Send-after-disconnect bugs, resource cleanup failures, permit handling
    #[test]
    fn mr4_receiver_drop_disconnect() {
        proptest!(|(
            seed in any::<u64>(),
            send_value in any::<i64>(),
            use_reserve in any::<bool>(),
            drop_before_send in any::<bool>(),
        )| {
            let mut harness = OneShotTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, rx) = oneshot::channel::<i64>();

                if drop_before_send {
                    // Drop receiver first, then try to send
                    drop(rx);

                    // Verify sender detects disconnection
                    prop_assert!(tx.is_closed(), "MR4 VIOLATION: sender should detect receiver drop");

                    // Send should return Disconnected error
                    if use_reserve {
                        let permit = tx.reserve(cx);
                        prop_assert!(permit.is_closed(), "MR4 VIOLATION: permit should detect receiver drop");
                        match permit.send(send_value) {
                            Err(SendError::Disconnected(returned_value)) => {
                                prop_assert_eq!(returned_value, send_value, "MR4 VIOLATION: returned value should match sent value");
                            },
                            other => prop_assert!(false, "MR4 VIOLATION: permit send should return Disconnected, got {:?}", other),
                        }
                    } else {
                        match tx.send(cx, send_value) {
                            Err(SendError::Disconnected(returned_value)) => {
                                prop_assert_eq!(returned_value, send_value, "MR4 VIOLATION: returned value should match sent value");
                            },
                            other => prop_assert!(false, "MR4 VIOLATION: send should return Disconnected, got {:?}", other),
                        }
                    }
                } else {
                    // Reserve first (if using reserve pattern), then drop receiver
                    let permit_opt = if use_reserve {
                        Some(tx.reserve(cx))
                    } else {
                        None
                    };

                    // Drop receiver to trigger disconnect
                    drop(rx);

                    // Send should detect disconnection
                    if let Some(permit) = permit_opt {
                        prop_assert!(permit.is_closed(), "MR4 VIOLATION: permit should detect receiver drop");
                        match permit.send(send_value) {
                            Err(SendError::Disconnected(returned_value)) => {
                                prop_assert_eq!(returned_value, send_value, "MR4 VIOLATION: returned value should match sent value");
                            },
                            other => prop_assert!(false, "MR4 VIOLATION: permit send should return Disconnected after receiver drop, got {:?}", other),
                        }
                    } else {
                        prop_assert!(tx.is_closed(), "MR4 VIOLATION: sender should detect receiver drop");
                        match tx.send(cx, send_value) {
                            Err(SendError::Disconnected(returned_value)) => {
                                prop_assert_eq!(returned_value, send_value, "MR4 VIOLATION: returned value should match sent value");
                            },
                            other => prop_assert!(false, "MR4 VIOLATION: send should return Disconnected after receiver drop, got {:?}", other),
                        }
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

    /// MR5: Cancel-During-Recv Safety (Safety, Score: 10.0)
    /// Property: cancellation during recv drains cleanly without obligation leak
    /// Catches: Obligation leaks, waker retention, cancel-unsafe operations
    #[test]
    fn mr5_cancel_during_recv_safety() {
        proptest!(|(
            seed in any::<u64>(),
            cancel_delay_ms in 1u64..50,
            send_after_cancel in any::<bool>(),
        )| {
            let mut harness = OneShotTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, mut rx) = oneshot::channel::<i64>();

                // Start a recv operation in a cancellable scope
                let recv_result = cx.region(|region| async move {
                    let recv_scope = Scope::new(region, "recv_scope");
                    let recv_cx = recv_scope.cx();

                    let recv_task = recv_cx.spawn("recv_task", async move {
                        rx.recv(&recv_cx).await
                    });

                    let cancel_task = recv_cx.spawn("cancel_task", async move {
                        recv_cx.sleep(Duration::from_millis(cancel_delay_ms)).await;
                        recv_scope.cancel();
                    });

                    let (recv_result, _) = recv_cx.race((recv_task, cancel_task)).await;
                    recv_result
                }).await;

                // Recv should be cancelled or return Cancelled error
                match recv_result {
                    Outcome::Cancelled => {}, // Expected
                    Outcome::Ok(Err(RecvError::Cancelled)) => {}, // Also acceptable
                    other => prop_assert!(false, "MR5 VIOLATION: recv should be cancelled or return Cancelled, got {:?}", other),
                }

                // After cancellation, channel should still be usable if both ends exist
                if send_after_cancel {
                    // Try to send after cancellation - should still work if receiver exists
                    match tx.send(cx, 42) {
                        Ok(_) => {
                            // Sender succeeded, receiver should be able to get the value
                            match rx.recv(cx).await {
                                Ok(value) => prop_assert_eq!(value, 42, "MR5 VIOLATION: post-cancel recv should get sent value"),
                                Err(e) => prop_assert!(false, "MR5 VIOLATION: post-cancel recv failed: {:?}", e),
                            }
                        },
                        Err(SendError::Disconnected(_)) => {
                            // Receiver was dropped during cancellation - this is valid
                            prop_assert!(rx.is_closed(), "MR5 VIOLATION: if send failed, receiver should be closed");
                        },
                    }
                }

                harness.increment_operations();
                Ok(())
            }));

            match result {
                Outcome::Ok(_) => {},
                other => prop_assert!(false, "MR5 VIOLATION: unexpected outcome {:?}", other),
            }

            // CRITICAL: Verify no obligation leaks after cancellation
            prop_assert!(!harness.has_obligation_leaks(), "MR5 VIOLATION: obligation leak detected after cancellation");
            prop_assert!(harness.runtime.is_quiescent(), "MR5 VIOLATION: runtime not quiescent after cancellation");
        });
    }

    /// MR6: Reserve-Send vs Direct-Send Equivalence (Equivalence, Score: 8.0)
    /// Property: reserve().send(value) ≡ send(value) for same value and receiver state
    /// Catches: Permit handling bugs, obligation tracking differences, state inconsistencies
    #[test]
    fn mr6_reserve_send_equivalence() {
        proptest!(|(
            seed in any::<u64>(),
            send_value in any::<i64>(),
            receiver_drop_before_send in any::<bool>(),
        )| {
            let mut harness = OneShotTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                // Test direct send path
                let (tx1, mut rx1) = oneshot::channel::<i64>();
                let (tx2, mut rx2) = oneshot::channel::<i64>();

                if receiver_drop_before_send {
                    drop(rx1);
                    drop(rx2);
                }

                // Direct send
                let direct_result = tx1.send(cx, send_value);

                // Reserve-then-send
                let permit = tx2.reserve(cx);
                let reserve_result = permit.send(send_value);

                // METAMORPHIC ASSERTION: Both approaches should have same outcome
                match (direct_result, reserve_result) {
                    (Ok(()), Ok(())) => {
                        if !receiver_drop_before_send {
                            // Both should succeed, receivers should get same value
                            let val1 = rx1.recv(cx).await.unwrap();
                            let val2 = rx2.recv(cx).await.unwrap();
                            prop_assert_eq!(val1, val2, "MR6 VIOLATION: direct and reserve send produced different values");
                            prop_assert_eq!(val1, send_value, "MR6 VIOLATION: received value doesn't match sent value");
                        }
                    },
                    (Err(SendError::Disconnected(v1)), Err(SendError::Disconnected(v2))) => {
                        prop_assert_eq!(v1, v2, "MR6 VIOLATION: disconnected errors should return same value");
                        prop_assert_eq!(v1, send_value, "MR6 VIOLATION: disconnected error should return original value");
                    },
                    (r1, r2) => prop_assert!(false, "MR6 VIOLATION: direct and reserve send had different outcomes: {:?} vs {:?}", r1, r2),
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