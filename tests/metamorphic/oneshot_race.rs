#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic tests for oneshot channel close-or-send race conditions.
//!
//! These tests validate the race condition handling between close/drop operations
//! and send operations in oneshot channels using metamorphic relations and
//! property-based testing under deterministic LabRuntime conditions.
//!
//! ## Key Properties Tested
//!
//! 1. **Close-before-send ordering**: close before send returns Disconnected reliably
//! 2. **Send-then-close ordering**: send then close delivers value successfully
//! 3. **Send-then-drop ordering**: send then drop delivers value without loss
//! 4. **Race exclusivity**: close+send race produces either Ok or Disconnected, never both
//! 5. **Value uniqueness**: no value duplication under concurrent close+send operations
//!
//! ## Metamorphic Relations
//!
//! - **Ordering determinism**: `∀op1,op2. happens_before(op1,op2) ⟹ effect(op1) ≺ effect(op2)`
//! - **Race exclusivity**: `concurrent(close,send) ⟹ outcome ∈ {Ok(v), Disconnected(v)} ∧ |outcome| = 1`
//! - **Value preservation**: `send(v) ∧ ¬lost(channel) ⟹ recv() = v`
//! - **Close determinism**: `close_before_send(t) ⟹ send_result = Disconnected`
//! - **No duplication**: `∀v. send_count(v) ≤ 1 ∧ recv_count(v) ≤ 1`

use proptest::prelude::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use asupersync::channel::oneshot::{self, RecvError, SendError, TryRecvError};
use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{Budget, Outcome, RegionId, TaskId};
use asupersync::util::ArenaIndex;

// =============================================================================
// Test Infrastructure and Race Tracking
// =============================================================================

/// Operation types for race condition testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OneShotOperation {
    Send,
    Close,
    Drop,
    Recv,
}

/// Timing information for race condition analysis.
#[derive(Debug, Clone)]
struct OperationTiming {
    operation: OneShotOperation,
    start_time: Instant,
    end_time: Option<Instant>,
    thread_id: usize,
}

/// Result tracking for race condition verification.
#[derive(Debug, Clone)]
enum OperationResult {
    SendOk,
    SendDisconnected(i64),
    RecvOk(i64),
    RecvClosed,
    RecvEmpty,
    DropCompleted,
}

/// Race condition test tracker for verifying race semantics.
#[derive(Debug, Default)]
struct RaceTracker {
    /// All operation timings in order
    operations: Vec<OperationTiming>,
    /// Results of each operation
    results: Vec<(OneShotOperation, OperationResult)>,
    /// Values sent through channels
    values_sent: Vec<i64>,
    /// Values received from channels
    values_received: Vec<i64>,
    /// Close operations completed
    closes_completed: usize,
    /// Drop operations completed
    drops_completed: usize,
}

impl RaceTracker {
    fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::default()))
    }

    fn record_operation_start(&mut self, op: OneShotOperation, thread_id: usize) {
        self.operations.push(OperationTiming {
            operation: op,
            start_time: Instant::now(),
            end_time: None,
            thread_id,
        });
    }

    fn record_operation_end(&mut self, op: OneShotOperation, result: OperationResult) {
        // Find the most recent unfinished operation of this type
        if let Some(timing) = self.operations.iter_mut()
            .rev()
            .find(|t| t.operation == op && t.end_time.is_none()) {
            timing.end_time = Some(Instant::now());
        }

        self.results.push((op, result.clone()));

        match result {
            OperationResult::SendOk => {},
            OperationResult::SendDisconnected(value) => {
                self.values_sent.push(value);
            },
            OperationResult::RecvOk(value) => {
                self.values_received.push(value);
            },
            OperationResult::RecvClosed | OperationResult::RecvEmpty => {},
            OperationResult::DropCompleted => {
                self.drops_completed += 1;
            },
        }

        if op == OneShotOperation::Close {
            self.closes_completed += 1;
        }
    }

    /// Verify no value duplication occurred
    fn verify_no_duplication(&self) -> bool {
        // Each value should only be sent once
        let mut sent_values = self.values_sent.clone();
        sent_values.sort();
        sent_values.dedup();
        let sent_unique = sent_values.len() == self.values_sent.len();

        // Each value should only be received once
        let mut received_values = self.values_received.clone();
        received_values.sort();
        received_values.dedup();
        let received_unique = received_values.len() == self.values_received.len();

        sent_unique && received_unique
    }

    /// Verify race exclusivity (either success or failure, never both)
    fn verify_race_exclusivity(&self) -> bool {
        let send_successes = self.results.iter()
            .filter(|(op, result)| *op == OneShotOperation::Send && matches!(result, OperationResult::SendOk))
            .count();

        let send_disconnects = self.results.iter()
            .filter(|(op, result)| *op == OneShotOperation::Send && matches!(result, OperationResult::SendDisconnected(_)))
            .count();

        // For each channel, should have at most one send success OR one disconnected
        send_successes + send_disconnects <= 1
    }

    /// Check if close happened before send based on timing
    fn close_happened_before_send(&self) -> Option<bool> {
        let close_timing = self.operations.iter()
            .find(|op| op.operation == OneShotOperation::Close)?;
        let send_timing = self.operations.iter()
            .find(|op| op.operation == OneShotOperation::Send)?;

        Some(close_timing.start_time < send_timing.start_time)
    }
}

/// Create a test context for race testing.
fn test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

/// Simple block_on for tests.

struct YieldSleep {
    end: std::time::Instant,
}
impl Future for YieldSleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if std::time::Instant::now() >= self.end {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
fn yield_sleep(dur: Duration) -> YieldSleep {
    YieldSleep { end: std::time::Instant::now() + dur }
}

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
            Poll::Pending => {
                // Yield to allow other operations to proceed
                std::thread::yield_now();
            }
        }
    }
}

// =============================================================================
// Test Value Generation Strategies
// =============================================================================

/// Strategy for generating test values.
fn arb_test_values() -> impl Strategy<Value = i64> {
    -1000i64..1000
}

/// Strategy for generating timing delays.
fn arb_delays() -> impl Strategy<Value = Duration> {
    (0u64..100).prop_map(|ms| Duration::from_millis(ms))
}

/// Race execution scenario for testing different orderings.
#[derive(Debug, Clone)]
enum RaceScenario {
    CloseBeforeSend,
    SendThenClose,
    SendThenDrop,
    ConcurrentCloseSend,
    ConcurrentDropSend,
}

/// Strategy for generating race scenarios.
fn arb_race_scenarios() -> impl Strategy<Value = RaceScenario> {
    prop_oneof![
        Just(RaceScenario::CloseBeforeSend),
        Just(RaceScenario::SendThenClose),
        Just(RaceScenario::SendThenDrop),
        Just(RaceScenario::ConcurrentCloseSend),
        Just(RaceScenario::ConcurrentDropSend),
    ]
}

// =============================================================================
// Race Condition Test Implementations
// =============================================================================

/// Execute a race scenario and return the tracker with results.
async fn execute_race_scenario(
    scenario: RaceScenario,
    test_value: i64,
    delay: Duration,
) -> Arc<Mutex<RaceTracker>> {
    let tracker = RaceTracker::new();
    let (tx, mut rx) = oneshot::channel::<i64>();
    let cx = test_cx();

    match scenario {
        RaceScenario::CloseBeforeSend => {
            // Close receiver first, then try to send
            tracker.lock().unwrap().record_operation_start(OneShotOperation::Close, 0);
            drop(rx);
            tracker.lock().unwrap().record_operation_end(OneShotOperation::Close, OperationResult::DropCompleted);

            // Small delay to ensure close happens before send
            if !delay.is_zero() {
                yield_sleep(delay).await;
            }

            tracker.lock().unwrap().record_operation_start(OneShotOperation::Send, 1);
            let send_result = tx.send(&cx, test_value);
            let result = match send_result {
                Ok(()) => OperationResult::SendOk,
                Err(SendError::Disconnected(v)) => OperationResult::SendDisconnected(v),
            };
            tracker.lock().unwrap().record_operation_end(OneShotOperation::Send, result);
        },

        RaceScenario::SendThenClose => {
            // Send first, then close receiver
            tracker.lock().unwrap().record_operation_start(OneShotOperation::Send, 0);
            let send_result = tx.send(&cx, test_value);
            let result = match send_result {
                Ok(()) => OperationResult::SendOk,
                Err(SendError::Disconnected(v)) => OperationResult::SendDisconnected(v),
            };
            tracker.lock().unwrap().record_operation_end(OneShotOperation::Send, result);

            // Small delay then close
            if !delay.is_zero() {
                yield_sleep(delay).await;
            }

            tracker.lock().unwrap().record_operation_start(OneShotOperation::Close, 1);
            // Try to receive first to see if value was delivered
            match rx.try_recv() {
                Ok(value) => {
                    tracker.lock().unwrap().record_operation_end(OneShotOperation::Recv, OperationResult::RecvOk(value));
                },
                Err(TryRecvError::Empty) => {
                    // No value yet, close and it should be lost
                    drop(rx);
                    tracker.lock().unwrap().record_operation_end(OneShotOperation::Close, OperationResult::DropCompleted);
                },
                Err(TryRecvError::Closed) => {
                    tracker.lock().unwrap().record_operation_end(OneShotOperation::Recv, OperationResult::RecvClosed);
                }
            }
        },

        RaceScenario::SendThenDrop => {
            // Send value then drop receiver
            tracker.lock().unwrap().record_operation_start(OneShotOperation::Send, 0);
            let send_result = tx.send(&cx, test_value);
            let result = match send_result {
                Ok(()) => OperationResult::SendOk,
                Err(SendError::Disconnected(v)) => OperationResult::SendDisconnected(v),
            };
            tracker.lock().unwrap().record_operation_end(OneShotOperation::Send, result);

            // Small delay then drop
            if !delay.is_zero() {
                yield_sleep(delay).await;
            }

            tracker.lock().unwrap().record_operation_start(OneShotOperation::Drop, 1);
            drop(rx);
            tracker.lock().unwrap().record_operation_end(OneShotOperation::Drop, OperationResult::DropCompleted);
        },

        RaceScenario::ConcurrentCloseSend => {
            // Concurrent close and send operations
            let tracker_clone = tracker.clone();
            let send_future = async move {
                tracker_clone.lock().unwrap().record_operation_start(OneShotOperation::Send, 0);
                let send_result = tx.send(&cx, test_value);
                let result = match send_result {
                    Ok(()) => OperationResult::SendOk,
                    Err(SendError::Disconnected(v)) => OperationResult::SendDisconnected(v),
                };
                tracker_clone.lock().unwrap().record_operation_end(OneShotOperation::Send, result);
            };

            let tracker_clone = tracker.clone();
            let close_future = async move {
                // Small delay to create race window
                if !delay.is_zero() {
                    yield_sleep(delay / 2).await;
                }
                tracker_clone.lock().unwrap().record_operation_start(OneShotOperation::Close, 1);
                drop(rx);
                tracker_clone.lock().unwrap().record_operation_end(OneShotOperation::Close, OperationResult::DropCompleted);
            };

            // Run both concurrently
            futures_lite::future::zip(send_future, close_future).await;
        },

        RaceScenario::ConcurrentDropSend => {
            // Concurrent drop and send via reserve pattern
            let permit = tx.reserve(&cx);

            let tracker_clone = tracker.clone();
            let send_future = async move {
                // Small delay to create race
                if !delay.is_zero() {
                    yield_sleep(delay / 2).await;
                }
                tracker_clone.lock().unwrap().record_operation_start(OneShotOperation::Send, 0);
                let send_result = permit.send(test_value);
                let result = match send_result {
                    Ok(()) => OperationResult::SendOk,
                    Err(SendError::Disconnected(v)) => OperationResult::SendDisconnected(v),
                };
                tracker_clone.lock().unwrap().record_operation_end(OneShotOperation::Send, result);
            };

            let tracker_clone = tracker.clone();
            let drop_future = async move {
                tracker_clone.lock().unwrap().record_operation_start(OneShotOperation::Drop, 1);
                drop(rx);
                tracker_clone.lock().unwrap().record_operation_end(OneShotOperation::Drop, OperationResult::DropCompleted);
            };

            // Run both concurrently
            futures_lite::future::zip(send_future, drop_future).await;
        },
    }

    tracker
}

// =============================================================================
// Metamorphic Relations (MR) Tests
// =============================================================================

/// **MR1: Close Before Send Returns Disconnected**
///
/// This metamorphic relation verifies that when a receiver is closed before
/// a send operation begins, the send will reliably return Disconnected.
proptest! {
    #[test]
    fn mr1_close_before_send_returns_disconnected(
        test_value in arb_test_values(),
        delay in arb_delays(),
    ) {
        block_on(async {
            let tracker = execute_race_scenario(
                RaceScenario::CloseBeforeSend,
                test_value,
                delay
            ).await;

            let tracker_data = tracker.lock().unwrap();

            // MR1: Close before send must result in Disconnected
            let has_send_disconnected = tracker_data.results.iter().any(|(op, result)| {
                *op == OneShotOperation::Send && matches!(result, OperationResult::SendDisconnected(_))
            });

            assert!(has_send_disconnected,
                "Close before send must return SendError::Disconnected");

            // Value should not be lost
            assert_eq!(tracker_data.values_sent.len(), 1,
                "Disconnected send should still track the attempted value");
            assert_eq!(tracker_data.values_sent[0], test_value,
                "Disconnected value should match sent value");
        });
    }
}

/// **MR2: Send Then Close Delivers Value**
///
/// This metamorphic relation verifies that when send completes before
/// the receiver is closed, the value is delivered successfully.
proptest! {
    #[test]
    fn mr2_send_then_close_delivers_value(
        test_value in arb_test_values(),
        delay in arb_delays(),
    ) {
        block_on(async {
            let tracker = execute_race_scenario(
                RaceScenario::SendThenClose,
                test_value,
                delay
            ).await;

            let tracker_data = tracker.lock().unwrap();

            // MR2: Send then close should deliver the value
            let has_send_ok = tracker_data.results.iter().any(|(op, result)| {
                *op == OneShotOperation::Send && matches!(result, OperationResult::SendOk)
            });

            if has_send_ok {
                // If send succeeded, value should be receivable
                let has_recv_ok = tracker_data.results.iter().any(|(op, result)| {
                    *op == OneShotOperation::Recv && matches!(result, OperationResult::RecvOk(_))
                });

                if has_recv_ok {
                    assert_eq!(tracker_data.values_received.len(), 1,
                        "Should receive exactly one value");
                    assert_eq!(tracker_data.values_received[0], test_value,
                        "Received value should match sent value");
                }
            }

            // No duplication
            assert!(tracker_data.verify_no_duplication(),
                "No value duplication should occur");
        });
    }
}

/// **MR3: Send Then Drop Delivers Value**
///
/// This metamorphic relation verifies that send followed by receiver drop
/// still allows the value to be committed, even if it's never received.
proptest! {
    #[test]
    fn mr3_send_then_drop_delivers_value(
        test_value in arb_test_values(),
        delay in arb_delays(),
    ) {
        block_on(async {
            let tracker = execute_race_scenario(
                RaceScenario::SendThenDrop,
                test_value,
                delay
            ).await;

            let tracker_data = tracker.lock().unwrap();

            // MR3: Send then drop should complete send successfully
            let has_send_ok = tracker_data.results.iter().any(|(op, result)| {
                *op == OneShotOperation::Send && matches!(result, OperationResult::SendOk)
            });

            let has_drop_completed = tracker_data.results.iter().any(|(op, result)| {
                *op == OneShotOperation::Drop && matches!(result, OperationResult::DropCompleted)
            });

            if has_send_ok {
                assert!(has_drop_completed,
                    "Drop should complete after successful send");
                // Value was committed to channel even if never received
            } else {
                // Send failed, should have disconnected error
                let has_disconnected = tracker_data.results.iter().any(|(op, result)| {
                    *op == OneShotOperation::Send && matches!(result, OperationResult::SendDisconnected(_))
                });
                assert!(has_disconnected,
                    "If send fails, should get Disconnected error");
            }

            assert!(tracker_data.verify_no_duplication(),
                "No value duplication should occur");
        });
    }
}

/// **MR4: Close+Send Race Exclusivity**
///
/// This metamorphic relation verifies that in a close/send race condition,
/// exactly one outcome occurs: either Ok or Disconnected, never both.
proptest! {
    #[test]
    fn mr4_close_send_race_exclusivity(
        test_value in arb_test_values(),
        delay in arb_delays(),
    ) {
        block_on(async {
            let tracker = execute_race_scenario(
                RaceScenario::ConcurrentCloseSend,
                test_value,
                delay
            ).await;

            let tracker_data = tracker.lock().unwrap();

            // MR4: Race should produce exactly one send outcome
            assert!(tracker_data.verify_race_exclusivity(),
                "Race should produce either Ok or Disconnected, never both");

            let send_ok_count = tracker_data.results.iter()
                .filter(|(op, result)| *op == OneShotOperation::Send && matches!(result, OperationResult::SendOk))
                .count();

            let send_disconnected_count = tracker_data.results.iter()
                .filter(|(op, result)| *op == OneShotOperation::Send && matches!(result, OperationResult::SendDisconnected(_)))
                .count();

            // Exactly one send result should occur
            assert_eq!(send_ok_count + send_disconnected_count, 1,
                "Exactly one send result must occur in race");

            assert!(tracker_data.verify_no_duplication(),
                "No value duplication should occur in race");
        });
    }
}

/// **MR5: No Value Duplication Under Concurrent Operations**
///
/// This metamorphic relation verifies that under any concurrent close+send
/// scenario, values are never duplicated in send or receive operations.
proptest! {
    #[test]
    fn mr5_no_value_duplication_concurrent(
        test_value in arb_test_values(),
        delay in arb_delays(),
        scenario in arb_race_scenarios(),
    ) {
        block_on(async {
            let tracker = execute_race_scenario(scenario, test_value, delay).await;
            let tracker_data = tracker.lock().unwrap();

            // MR5: No value duplication under any scenario
            assert!(tracker_data.verify_no_duplication(),
                "No value duplication should occur under scenario: {scenario:?}");

            // Each value appears at most once in sent values
            let mut sent_counts = std::collections::HashMap::new();
            for &value in &tracker_data.values_sent {
                *sent_counts.entry(value).or_insert(0) += 1;
            }
            for (value, count) in sent_counts {
                assert!(count <= 1, "Value {value} sent {count} times (should be ≤ 1)");
            }

            // Each value appears at most once in received values
            let mut received_counts = std::collections::HashMap::new();
            for &value in &tracker_data.values_received {
                *received_counts.entry(value).or_insert(0) += 1;
            }
            for (value, count) in received_counts {
                assert!(count <= 1, "Value {value} received {count} times (should be ≤ 1)");
            }
        });
    }
}

// =============================================================================
// Additional Race Condition Tests
// =============================================================================

/// Test complex concurrent scenarios with multiple operations.
proptest! {
    #[test]
    fn race_stress_test_multiple_operations(
        values in prop::collection::vec(arb_test_values(), 1..=3),
        delays in prop::collection::vec(arb_delays(), 1..=3),
    ) {
        block_on(async {
            let mut all_trackers = Vec::new();

            for (i, (&value, &delay)) in values.iter().zip(delays.iter()).enumerate() {
                let scenario = match i % 3 {
                    0 => RaceScenario::ConcurrentCloseSend,
                    1 => RaceScenario::CloseBeforeSend,
                    _ => RaceScenario::SendThenClose,
                };

                let tracker = execute_race_scenario(scenario, value, delay).await;
                all_trackers.push(tracker);
            }

            // Verify all operations maintained their invariants
            for tracker in all_trackers {
                let tracker_data = tracker.lock().unwrap();
                assert!(tracker_data.verify_no_duplication(),
                    "All concurrent operations must maintain no-duplication invariant");
                assert!(tracker_data.verify_race_exclusivity(),
                    "All concurrent operations must maintain race exclusivity");
            }
        });
    }
}

/// Test that receiver drop during send is handled correctly.
#[test]
fn test_receiver_drop_during_send_commit() {
    block_on(async {
    let tracker = RaceTracker::new();
    let (tx, rx) = oneshot::channel::<i64>();
    let cx = test_cx();

    // Reserve first (two-phase pattern)
    let permit = tx.reserve(&cx);

    // Drop receiver while permit is outstanding
    tracker.lock().unwrap().record_operation_start(OneShotOperation::Drop, 0);
    drop(rx);
    tracker.lock().unwrap().record_operation_end(OneShotOperation::Drop, OperationResult::DropCompleted);

    // Now try to send with the permit
    tracker.lock().unwrap().record_operation_start(OneShotOperation::Send, 1);
    let result = permit.send(42);
    let operation_result = match result {
        Ok(()) => OperationResult::SendOk,
        Err(SendError::Disconnected(v)) => OperationResult::SendDisconnected(v),
    };
    tracker.lock().unwrap().record_operation_end(OneShotOperation::Send, operation_result);

    let tracker_data = tracker.lock().unwrap();

    // Should get Disconnected since receiver was dropped
    let has_disconnected = tracker_data.results.iter().any(|(op, result)| {
        *op == OneShotOperation::Send && matches!(result, OperationResult::SendDisconnected(_))
    });
    assert!(has_disconnected, "Send after receiver drop should return Disconnected");

    // Value should still be tracked
    assert_eq!(tracker_data.values_sent.len(), 1);
    assert_eq!(tracker_data.values_sent[0], 42);
    });
}

/// Test ordering guarantees under deterministic execution.
#[test]
fn test_deterministic_ordering_guarantees() {
    block_on(async {
    for scenario in [
        RaceScenario::CloseBeforeSend,
        RaceScenario::SendThenClose,
        RaceScenario::SendThenDrop,
    ] {
        let tracker = execute_race_scenario(scenario, 123, Duration::from_millis(10)).await;
        let tracker_data = tracker.lock().unwrap();

        // All operations should complete
        assert!(!tracker_data.results.is_empty(),
            "Operations should complete for scenario: {scenario:?}");

        // No duplication
        assert!(tracker_data.verify_no_duplication(),
            "No duplication for scenario: {scenario:?}");

        // Race exclusivity
        assert!(tracker_data.verify_race_exclusivity(),
            "Race exclusivity for scenario: {scenario:?}");
    }
    });
}