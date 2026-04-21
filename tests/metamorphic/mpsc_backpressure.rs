#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic property tests for MPSC channel bounded capacity backpressure invariants.
//!
//! These tests verify MPSC channel behavior specifically around bounded capacity backpressure,
//! two-phase send ordering, cancellation safety, FIFO wakeup behavior, and closed channel
//! handling. Uses LabRuntime with DPOR for deterministic scheduling exploration.
//!
//! # Metamorphic Relations
//!
//! 1. **Bounded Capacity Blocking** (MR1): bounded(N) blocks senders past N in-flight
//! 2. **Two-Phase Ordering** (MR2): reserve()/send() preserves ordering by reserve order not send order
//! 3. **Cancel Releases Slot** (MR3): cancel during reserve releases slot for other senders
//! 4. **Recv FIFO Wakeup** (MR4): recv wakes bounded number of senders in FIFO order
//! 5. **Closed Channel Rejection** (MR5): closed channel rejects new reserves with Closed error

use asupersync::channel::mpsc::{self, RecvError, SendError};
use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{Budget, Outcome, RegionId, TaskId};
use asupersync::util::ArenaIndex;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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

/// Configuration for MPSC backpressure metamorphic tests.
#[derive(Debug, Clone)]
pub struct BackpressureTestConfig {
    /// Random seed for deterministic execution.
    pub seed: u64,
    /// Channel capacity (bounded).
    pub capacity: usize,
    /// Values to send through the channel.
    pub send_values: Vec<i64>,
    /// Number of concurrent senders to test.
    pub sender_count: u8,
    /// Delay before cancellation (virtual milliseconds).
    pub cancel_delay_ms: u64,
    /// Whether to inject cancellation during reserves.
    pub inject_cancellation: bool,
}

/// Test harness for MPSC backpressure operations with DPOR scheduling.
#[derive(Debug)]
struct BackpressureTestHarness {
    runtime: LabRuntime,
    operations_completed: AtomicU64,
    obligations_leaked: AtomicBool,
    blocked_operations: AtomicU64,
    wakeups_recorded: AtomicU64,
}

impl BackpressureTestHarness {
    fn new(seed: u64) -> Self {
        let config = LabConfig::new(seed).with_light_chaos();
        Self {
            runtime: LabRuntime::new(config),
            operations_completed: AtomicU64::new(0),
            obligations_leaked: AtomicBool::new(false),
            blocked_operations: AtomicU64::new(0),
            wakeups_recorded: AtomicU64::new(0),
        }
    }

    fn execute<F>(&mut self, test_fn: F) -> Outcome<F::Output, ()>
    where
        F: FnOnce(&Cx) -> Pin<Box<dyn Future<Output = F::Output> + '_>> + Send,
    {
        self.runtime.block_on(|cx| async {
            let result = cx
                .region(|region| async {
                    let scope = Scope::new(region, "mpsc_backpressure_test");
                    test_fn(&scope.cx())
                })
                .await;

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

    fn increment_blocked(&self) {
        self.blocked_operations.fetch_add(1, Ordering::SeqCst);
    }

    fn blocked_count(&self) -> u64 {
        self.blocked_operations.load(Ordering::SeqCst)
    }

    fn increment_wakeups(&self) {
        self.wakeups_recorded.fetch_add(1, Ordering::SeqCst);
    }

    fn wakeup_count(&self) -> u64 {
        self.wakeups_recorded.load(Ordering::SeqCst)
    }
}

/// Counting waker that tracks wake calls.
struct CountingWaker {
    counter: Arc<AtomicUsize>,
}

impl std::task::Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.counter.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.counter.fetch_add(1, Ordering::SeqCst);
    }
}

impl CountingWaker {
    fn new() -> (Waker, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountingWaker {
            counter: counter.clone(),
        }));
        (waker, counter)
    }
}

// ============================================================================
// Metamorphic Relations for MPSC Backpressure Behavior
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// MR1: Bounded Capacity Blocking (Blocking, Score: 10.0)
    /// Property: bounded(N) blocks senders past N in-flight (reserve returns Pending)
    /// Catches: Missing backpressure, capacity violations, infinite memory usage
    #[test]
    fn mr1_bounded_capacity_blocks_senders() {
        proptest!(|(
            seed in any::<u64>(),
            capacity in 1usize..8,
            excess_senders in 1u8..5,
        )| {
            let mut harness = BackpressureTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, _rx) = mpsc::channel::<i64>(capacity);
                let mut permits = Vec::new();
                let mut blocked_reserves = Vec::new();

                // Fill channel to capacity by reserving slots
                for i in 0..capacity {
                    let permit = tx.reserve(cx).await;
                    match permit {
                        Ok(p) => permits.push(p),
                        Err(e) => prop_assert!(false, "MR1 VIOLATION: reserve failed within capacity at {}/{}: {:?}", i, capacity, e),
                    }
                }

                // MR1 ASSERTION: Additional reserves should block (return Pending)
                for i in 0..excess_senders {
                    let mut reserve_future = Box::pin(tx.reserve(cx));
                    let (waker, wake_count) = CountingWaker::new();
                    let mut task_cx = Context::from_waker(&waker);

                    let poll_result = reserve_future.as_mut().poll(&mut task_cx);
                    match poll_result {
                        Poll::Pending => {
                            harness.increment_blocked();
                            blocked_reserves.push((reserve_future, wake_count));
                        },
                        Poll::Ready(Ok(_)) => {
                            prop_assert!(false, "MR1 VIOLATION: reserve should block when {} slots are in-flight (capacity={})", capacity, capacity);
                        },
                        Poll::Ready(Err(e)) => {
                            prop_assert!(false, "MR1 VIOLATION: unexpected reserve error when blocking expected: {:?}", e);
                        },
                    }
                }

                // Verify that blocked reserves have not been woken yet
                for (_, wake_count) in &blocked_reserves {
                    let wakes = wake_count.load(Ordering::SeqCst);
                    prop_assert_eq!(wakes, 0, "MR1 VIOLATION: blocked reserve was woken prematurely");
                }

                // Abort one permit to free a slot
                if let Some(permit) = permits.pop() {
                    permit.abort();
                }

                // MR1 ASSERTION: Exactly one blocked reserve should be woken (FIFO)
                cx.sleep(Duration::from_millis(1)).await; // Allow wakeup to propagate

                let mut woken_count = 0;
                for (_, wake_count) in &blocked_reserves {
                    let wakes = wake_count.load(Ordering::SeqCst);
                    if wakes > 0 {
                        woken_count += 1;
                    }
                }

                prop_assert_eq!(
                    woken_count, 1,
                    "MR1 VIOLATION: expected exactly 1 woken reserve after freeing 1 slot, got {}",
                    woken_count
                );

                harness.increment_operations();
                Ok(())
            }));

            match result {
                Outcome::Ok(_) => {},
                other => prop_assert!(false, "MR1 VIOLATION: unexpected outcome {:?}", other),
            }

            prop_assert!(!harness.has_obligation_leaks(), "MR1 VIOLATION: obligation leak detected");
            prop_assert!(harness.blocked_count() > 0, "MR1 VIOLATION: no blocking occurred");
        });
    }

    /// MR2: Two-Phase Ordering (Temporal, Score: 9.5)
    /// Property: reserve()/send() preserves ordering by reserve order not send order
    /// Catches: Ordering violations, race conditions in commit phase
    #[test]
    fn mr2_two_phase_ordering_preserved() {
        proptest!(|(
            seed in any::<u64>(),
            capacity in 2usize..6,
            send_count in 2u8..8,
        )| {
            let mut harness = BackpressureTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, mut rx) = mpsc::channel::<i64>(capacity);
                let mut permits = Vec::new();
                let reserve_order = Arc::new(std::sync::Mutex::new(Vec::new()));
                let commit_order = Arc::new(std::sync::Mutex::new(Vec::new()));

                // Phase 1: Reserve slots in specific order
                for i in 0..send_count {
                    let permit = tx.reserve(cx).await;
                    match permit {
                        Ok(p) => {
                            permits.push((p, i as i64));
                            reserve_order.lock().unwrap().push(i as i64);
                        },
                        Err(e) => prop_assert!(false, "MR2 VIOLATION: reserve failed: {:?}", e),
                    }
                }

                // Phase 2: Commit in reverse order to test ordering preservation
                permits.reverse();
                for (permit, value) in permits {
                    permit.send(value);
                    commit_order.lock().unwrap().push(value);
                }

                // MR2 ASSERTION: Received order should match reserve order, NOT commit order
                let mut received_order = Vec::new();
                for _ in 0..send_count {
                    let received = rx.recv(cx).await;
                    match received {
                        Ok(value) => received_order.push(value),
                        Err(e) => prop_assert!(false, "MR2 VIOLATION: recv failed: {:?}", e),
                    }
                }

                let expected_reserve_order = reserve_order.lock().unwrap().clone();
                let actual_commit_order = commit_order.lock().unwrap().clone();

                // Verify that commit order is actually different from reserve order
                prop_assert_ne!(
                    expected_reserve_order, actual_commit_order,
                    "MR2 TEST ERROR: commit order same as reserve order, test is invalid"
                );

                // MR2 CORE ASSERTION: Received order matches reserve order
                prop_assert_eq!(
                    received_order, expected_reserve_order,
                    "MR2 VIOLATION: received order {:?} != reserve order {:?} (commit order was {:?})",
                    received_order, expected_reserve_order, actual_commit_order
                );

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

    /// MR3: Cancel Releases Slot (Safety, Score: 9.0)
    /// Property: cancel during reserve releases slot for other senders (no deadlock)
    /// Catches: Resource leaks on cancellation, deadlocks, slot accounting bugs
    #[test]
    fn mr3_cancel_during_reserve_releases_slot() {
        proptest!(|(
            seed in any::<u64>(),
            capacity in 1usize..4,
            cancel_delay_ms in 1u64..10,
        )| {
            let mut harness = BackpressureTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, _rx) = mpsc::channel::<i64>(capacity);
                let mut permits = Vec::new();

                // Fill channel to capacity
                for i in 0..capacity {
                    let permit = tx.reserve(cx).await;
                    match permit {
                        Ok(p) => permits.push(p),
                        Err(e) => prop_assert!(false, "MR3 VIOLATION: reserve failed within capacity: {:?}", e),
                    }
                }

                // Start a reserve that will block
                let tx_clone = tx.clone();
                let (waker1, wake_count1) = CountingWaker::new();
                let mut blocked_reserve = Box::pin(tx_clone.reserve(cx));
                let mut task_cx1 = Context::from_waker(&waker1);

                // Verify it blocks
                let poll_result = blocked_reserve.as_mut().poll(&mut task_cx1);
                prop_assert!(
                    matches!(poll_result, Poll::Pending),
                    "MR3 VIOLATION: reserve should block when capacity is full"
                );

                // Start another reserve that will also block
                let tx_clone2 = tx.clone();
                let (waker2, wake_count2) = CountingWaker::new();
                let mut blocked_reserve2 = Box::pin(tx_clone2.reserve(cx));
                let mut task_cx2 = Context::from_waker(&waker2);
                let poll_result2 = blocked_reserve2.as_mut().poll(&mut task_cx2);
                prop_assert!(
                    matches!(poll_result2, Poll::Pending),
                    "MR3 VIOLATION: second reserve should also block"
                );

                // MR3 TEST: Cancel the first reserve by dropping it
                drop(blocked_reserve);
                cx.sleep(Duration::from_millis(cancel_delay_ms)).await;

                // Check that the cancellation didn't wake the second waiter yet
                let wakes_before = wake_count2.load(Ordering::SeqCst);

                // Free a slot by aborting a permit
                if let Some(permit) = permits.pop() {
                    permit.abort();
                }

                // Allow wakeup processing
                cx.sleep(Duration::from_millis(1)).await;

                // MR3 ASSERTION: The second waiter should be woken (slot available)
                let wakes_after = wake_count2.load(Ordering::SeqCst);
                prop_assert!(
                    wakes_after > wakes_before,
                    "MR3 VIOLATION: second waiter should be woken after slot freed, wakes before={} after={}",
                    wakes_before, wakes_after
                );

                // Verify the second reserve can now complete
                let poll_result_final = blocked_reserve2.as_mut().poll(&mut task_cx2);
                match poll_result_final {
                    Poll::Ready(Ok(_)) => {}, // Expected
                    Poll::Ready(Err(e)) => prop_assert!(false, "MR3 VIOLATION: second reserve failed: {:?}", e),
                    Poll::Pending => {
                        // May still be pending, but should succeed after another yield
                        cx.sleep(Duration::from_millis(1)).await;
                        let final_poll = blocked_reserve2.as_mut().poll(&mut task_cx2);
                        prop_assert!(
                            matches!(final_poll, Poll::Ready(Ok(_))),
                            "MR3 VIOLATION: second reserve should complete after cancellation and slot release"
                        );
                    },
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

    /// MR4: Recv FIFO Wakeup (Fairness, Score: 8.5)
    /// Property: recv wakes bounded number of senders in FIFO order
    /// Catches: Unfair wakeup ordering, starvation, wakeup cascade bugs
    #[test]
    fn mr4_recv_wakes_senders_fifo() {
        proptest!(|(
            seed in any::<u64>(),
            capacity in 1usize..3,
            waiter_count in 2u8..5,
        )| {
            let mut harness = BackpressureTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, mut rx) = mpsc::channel::<i64>(capacity);
                let mut permits = Vec::new();
                let mut blocked_reserves = Vec::new();

                // Fill channel to capacity
                for i in 0..capacity {
                    let permit = tx.reserve(cx).await;
                    match permit {
                        Ok(p) => {
                            p.send(i as i64);
                        },
                        Err(e) => prop_assert!(false, "MR4 VIOLATION: initial reserve failed: {:?}", e),
                    }
                }

                // Create waiters in order (should be woken in FIFO order)
                for i in 0..waiter_count {
                    let tx_clone = tx.clone();
                    let (waker, wake_count) = CountingWaker::new();
                    let mut reserve_future = Box::pin(tx_clone.reserve(cx));
                    let mut task_cx = Context::from_waker(&waker);

                    // Verify it blocks
                    let poll_result = reserve_future.as_mut().poll(&mut task_cx);
                    prop_assert!(
                        matches!(poll_result, Poll::Pending),
                        "MR4 VIOLATION: reserve {} should block when channel is full", i
                    );

                    blocked_reserves.push((reserve_future, wake_count, i));
                }

                // MR4 ASSERTION: Receive messages and verify FIFO wakeup order
                let mut wakeup_order = Vec::new();

                for recv_round in 0..capacity.min(waiter_count as usize) {
                    // Receive one message to free a slot
                    let received = rx.recv(cx).await;
                    prop_assert!(received.is_ok(), "MR4 VIOLATION: recv failed in round {}", recv_round);

                    // Allow wakeup to propagate
                    cx.sleep(Duration::from_millis(1)).await;

                    // Check which waiter was woken (should be the earliest)
                    for (reserve_fut, wake_count, waiter_id) in &mut blocked_reserves {
                        let wakes = wake_count.load(Ordering::SeqCst);
                        if wakes > 0 && !wakeup_order.contains(&waiter_id) {
                            wakeup_order.push(*waiter_id);

                            // Verify the woken reserve can now complete
                            let (new_waker, _) = CountingWaker::new();
                            let mut new_task_cx = Context::from_waker(&new_waker);
                            let poll_result = reserve_fut.as_mut().poll(&mut new_task_cx);
                            if matches!(poll_result, Poll::Ready(Ok(_))) {
                                // Reserve completed, break to avoid double-counting
                                break;
                            }
                        }
                    }
                }

                // MR4 CORE ASSERTION: Wakeup order should be FIFO (0, 1, 2, ...)
                let expected_fifo_order: Vec<u8> = (0..wakeup_order.len() as u8).collect();
                prop_assert_eq!(
                    wakeup_order, expected_fifo_order,
                    "MR4 VIOLATION: wakeup order {:?} is not FIFO (expected {:?})",
                    wakeup_order, expected_fifo_order
                );

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

    /// MR5: Closed Channel Rejection (Safety, Score: 8.0)
    /// Property: closed channel rejects new reserves with Closed error (no panic)
    /// Catches: Panics on closed channels, incorrect error types, resource leaks
    #[test]
    fn mr5_closed_channel_rejects_reserves() {
        proptest!(|(
            seed in any::<u64>(),
            capacity in 1usize..5,
            test_values in prop::collection::vec(any::<i64>(), 1..5),
            close_via_drop in any::<bool>(),
        )| {
            let mut harness = BackpressureTestHarness::new(seed);

            let result = harness.execute(|cx| Box::pin(async move {
                let (tx, rx) = mpsc::channel::<i64>(capacity);

                // Verify channel is initially open
                prop_assert!(!tx.is_closed(), "MR5 VIOLATION: channel should be open initially");

                // Close the channel
                if close_via_drop {
                    drop(rx);
                } else {
                    let mut rx_mut = rx;
                    rx_mut.close();
                    drop(rx_mut);
                }

                // Allow close to propagate
                cx.sleep(Duration::from_millis(1)).await;

                // MR5 ASSERTION: Channel should now be closed
                prop_assert!(tx.is_closed(), "MR5 VIOLATION: channel should be closed after receiver drop/close");

                // MR5 ASSERTION: All reserve operations should fail with Disconnected
                for &test_value in &test_values {
                    // Test try_reserve
                    let try_reserve_result = tx.try_reserve();
                    match try_reserve_result {
                        Err(SendError::Disconnected(())) => {}, // Expected
                        other => prop_assert!(false, "MR5 VIOLATION: try_reserve expected Disconnected, got {:?}", other),
                    }

                    // Test async reserve
                    let reserve_result = tx.reserve(cx).await;
                    match reserve_result {
                        Err(SendError::Disconnected(())) => {}, // Expected
                        other => prop_assert!(false, "MR5 VIOLATION: async reserve expected Disconnected, got {:?}", other),
                    }

                    // Test try_send
                    let try_send_result = tx.try_send(test_value);
                    match try_send_result {
                        Err(SendError::Disconnected(returned_value)) => {
                            prop_assert_eq!(
                                returned_value, test_value,
                                "MR5 VIOLATION: try_send returned wrong value in Disconnected error"
                            );
                        },
                        other => prop_assert!(false, "MR5 VIOLATION: try_send expected Disconnected, got {:?}", other),
                    }

                    // Test async send
                    let send_result = tx.send(cx, test_value).await;
                    match send_result {
                        Err(SendError::Disconnected(returned_value)) => {
                            prop_assert_eq!(
                                returned_value, test_value,
                                "MR5 VIOLATION: async send returned wrong value in Disconnected error"
                            );
                        },
                        other => prop_assert!(false, "MR5 VIOLATION: async send expected Disconnected, got {:?}", other),
                    }
                }

                // MR5 ASSERTION: No operations should panic or hang
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
}
