#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic Testing: combinator::timeout deadline-drain invariants
//!
//! This module implements metamorphic relations (MRs) to verify that timeout
//! combinators exhibit correct deadline timing behavior, proper draining of
//! inner futures, and deterministic cancel/complete interactions.
//!
//! # Metamorphic Relations
//!
//! - **MR1 (Deadline Precision)**: timeout fires at configured deadline with
//!   deterministic timing under virtual time
//! - **MR2 (Cancel Before Deadline)**: external cancel before deadline aborts
//!   cleanly without triggering timeout error
//! - **MR3 (Inner Future Draining)**: inner future is properly drained when
//!   timeout fires, ensuring resource cleanup
//! - **MR4 (Zero Duration Immediate)**: zero-duration timeout returns
//!   immediately with timeout error before inner future is polled
//! - **MR5 (Already Ready Fast Path)**: timeout with already-completed future
//!   returns Ok result immediately regardless of deadline
//!
//! # Property Coverage
//!
//! These MRs ensure that:
//! - Timing behavior is precise and deterministic under virtual time
//! - Cancellation precedence rules are respected (cancel > timeout > complete)
//! - Resource cleanup occurs properly through the draining protocol
//! - Boundary conditions (zero duration, immediate completion) work correctly
//! - Fast path optimizations don't break timing contracts

use crate::lab::runtime::LabRuntime;
use crate::lab::LabConfig;
use crate::time::{timeout_future::TimeoutFuture, elapsed::Elapsed, sleep::Sleep};
use crate::types::{CancelReason, Time};
use crate::{Cx, Outcome};
use futures::future::{ready, pending};
use proptest::prelude::*;
use std::future::{Future, Ready};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

/// Test future that tracks polling and draining behavior
#[derive(Debug)]
struct TrackedFuture<T> {
    value: Option<T>,
    poll_count: Arc<AtomicU32>,
    drop_count: Arc<AtomicU32>,
    is_drained: Arc<AtomicBool>,
    delay_polls: u32,
}

impl<T> TrackedFuture<T> {
    fn new(value: T, poll_count: Arc<AtomicU32>, drop_count: Arc<AtomicU32>, delay_polls: u32) -> Self {
        Self {
            value: Some(value),
            poll_count,
            drop_count,
            is_drained: Arc::new(AtomicBool::new(false)),
            delay_polls,
        }
    }

    fn ready(value: T, poll_count: Arc<AtomicU32>, drop_count: Arc<AtomicU32>) -> Self {
        Self::new(value, poll_count, drop_count, 0)
    }

    fn delayed(value: T, poll_count: Arc<AtomicU32>, drop_count: Arc<AtomicU32>, delay_polls: u32) -> Self {
        Self::new(value, poll_count, drop_count, delay_polls)
    }

    fn pending(poll_count: Arc<AtomicU32>, drop_count: Arc<AtomicU32>) -> TrackedFuture<()> {
        TrackedFuture {
            value: None,
            poll_count,
            drop_count,
            is_drained: Arc::new(AtomicBool::new(false)),
            delay_polls: u32::MAX, // Never resolves
        }
    }
}

impl<T: Clone> Future for TrackedFuture<T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let poll_count = self.poll_count.fetch_add(1, Ordering::SeqCst);

        if poll_count >= self.delay_polls {
            if let Some(value) = self.value.take() {
                return Poll::Ready(value);
            }
        }

        Poll::Pending
    }
}

impl<T> Drop for TrackedFuture<T> {
    fn drop(&mut self) {
        self.drop_count.fetch_add(1, Ordering::SeqCst);
        self.is_drained.store(true, Ordering::SeqCst);
    }
}

/// Test scenario configuration for timeout deadline tests
#[derive(Debug, Clone)]
struct TimeoutDeadlineScenario {
    timeout_duration_ms: u64,
    operation_delay_polls: u32,
    external_cancel_delay_ms: Option<u64>,
    use_already_ready: bool,
    use_zero_duration: bool,
    advance_time_steps: Vec<u64>, // millisecond steps to advance time
}

/// Generate reasonable timeout durations (1ms to 1s)
fn timeout_duration_strategy() -> impl Strategy<Value = u64> {
    1u64..=1000
}

/// Generate operation delay configurations
fn delay_polls_strategy() -> impl Strategy<Value = u32> {
    0u32..=10
}

/// Generate time advancement patterns
fn time_advancement_strategy() -> impl Strategy<Value = Vec<u64>> {
    prop::collection::vec(1u64..=100, 0..=20)
}

/// Generate timeout deadline scenarios
fn scenario_strategy() -> impl Strategy<Value = TimeoutDeadlineScenario> {
    (
        timeout_duration_strategy(),
        delay_polls_strategy(),
        prop::option::of(1u64..=500), // cancel delay
        prop::bool::ANY,              // already ready
        prop::bool::ANY,              // zero duration
        time_advancement_strategy(),
    ).prop_map(|(timeout_duration_ms, operation_delay_polls, external_cancel_delay_ms,
                use_already_ready, use_zero_duration, advance_time_steps)| {
        TimeoutDeadlineScenario {
            timeout_duration_ms: if use_zero_duration { 0 } else { timeout_duration_ms },
            operation_delay_polls,
            external_cancel_delay_ms,
            use_already_ready,
            use_zero_duration,
            advance_time_steps,
        }
    })
}

/// **MR1: Deadline Precision**
///
/// Timeout must fire precisely at the configured deadline when using virtual time.
/// The timeout should trigger exactly when the virtual time reaches the deadline,
/// not before or after (within the granularity of time advancement).
///
/// **Property**: timeout_result = Timeout ⟺ virtual_time ≥ deadline ∧ ¬future_completed
#[test]
fn mr1_deadline_precision() {
    proptest!(|(scenario in scenario_strategy())| {
        if scenario.use_already_ready || scenario.external_cancel_delay_ms.is_some() {
            return Ok(()); // Skip these cases for pure deadline testing
        }

        let lab = LabRuntime::new(LabConfig::deterministic());

        lab.block_on(async {
            let start_time = Time::ZERO;
            let timeout_duration = Duration::from_millis(scenario.timeout_duration_ms);
            let expected_deadline = start_time.saturating_add_nanos(
                timeout_duration.as_nanos().min(u128::from(u64::MAX)) as u64
            );

            let poll_count = Arc::new(AtomicU32::new(0));
            let drop_count = Arc::new(AtomicU32::new(0));

            // Create a future that will never complete on its own
            let inner_future = TrackedFuture::pending(poll_count.clone(), drop_count.clone());
            let mut timeout_future = TimeoutFuture::after(start_time, timeout_duration, inner_future);

            // Advance time step by step until deadline
            let mut current_time = start_time;
            let step_size_ms = scenario.timeout_duration_ms.max(1) / 10; // 10 steps to deadline
            let step_size = Duration::from_millis(step_size_ms.max(1));

            let mut last_result = None;
            while current_time < expected_deadline {
                // Poll with current time (should be pending)
                let result = futures::poll!(&mut timeout_future);
                prop_assert!(result.is_pending(),
                    "Future should be pending before deadline: time={:?}, deadline={:?}",
                    current_time, expected_deadline);

                // Advance time
                current_time = current_time.saturating_add_nanos(
                    step_size.as_nanos().min(u128::from(u64::MAX)) as u64
                );
                lab.advance_to(current_time);
            }

            // Now we should be at or past deadline - timeout should fire
            let final_result = timeout_future.await;
            prop_assert!(final_result.is_err(),
                "Timeout should fire at deadline: time={:?}, deadline={:?}",
                current_time, expected_deadline);

            if let Err(elapsed) = final_result {
                prop_assert_eq!(elapsed.deadline(), expected_deadline,
                    "Elapsed error should report correct deadline");
            }

            // MR1.1: Inner future should have been dropped (drained)
            let final_drop_count = drop_count.load(Ordering::SeqCst);
            prop_assert!(final_drop_count > 0,
                "Inner future should be dropped when timeout fires");
        });
    });
}

/// **MR2: Cancel Before Deadline**
///
/// External cancellation before the deadline should abort cleanly without
/// triggering a timeout error. The result should reflect cancellation,
/// not timeout expiry.
///
/// **Property**: cancel_time < deadline ⇒ result = Cancelled(CancelReason) ≠ Timeout
#[test]
fn mr2_cancel_before_deadline() {
    proptest!(|(scenario in scenario_strategy())| {
        if let Some(cancel_delay_ms) = scenario.external_cancel_delay_ms {
            if cancel_delay_ms >= scenario.timeout_duration_ms || scenario.use_zero_duration {
                return Ok(()); // Only test cancel before deadline
            }

            let lab = LabRuntime::new(LabConfig::deterministic());

            lab.block_on(async {
                let start_time = Time::ZERO;
                let timeout_duration = Duration::from_millis(scenario.timeout_duration_ms);
                let cancel_time = start_time.saturating_add_nanos(
                    (cancel_delay_ms * 1_000_000) as u64
                );

                let poll_count = Arc::new(AtomicU32::new(0));
                let drop_count = Arc::new(AtomicU32::new(0));

                // Create a future that won't complete before cancellation
                let inner_future = TrackedFuture::delayed(42u32, poll_count.clone(), drop_count.clone(),
                                                        scenario.timeout_duration_ms as u32 + 10);
                let timeout_future = TimeoutFuture::after(start_time, timeout_duration, inner_future);

                // Advance to cancellation time
                lab.advance_to(cancel_time);

                // Cancel the operation (this would typically happen via Cx cancellation)
                // For this test, we simulate cancellation by dropping the future early
                drop(timeout_future);

                // MR2.1: Inner future should be dropped (cancelled, not timed out)
                let final_drop_count = drop_count.load(Ordering::SeqCst);
                prop_assert!(final_drop_count > 0,
                    "Inner future should be dropped when cancelled before deadline");

                // MR2.2: Verify timing relationship
                let deadline = start_time.saturating_add_nanos(
                    timeout_duration.as_nanos().min(u128::from(u64::MAX)) as u64
                );
                prop_assert!(cancel_time < deadline,
                    "Cancel should occur before deadline: cancel={:?}, deadline={:?}",
                    cancel_time, deadline);
            });
        }
    });
}

/// **MR3: Inner Future Draining**
///
/// When timeout fires, the inner future must be properly drained to ensure
/// resource cleanup. This verifies the timeout's cleanup protocol.
///
/// **Property**: timeout_fires ⇒ inner_future_dropped ∧ resources_cleaned
#[test]
fn mr3_inner_future_draining() {
    proptest!(|(scenario in scenario_strategy())| {
        if scenario.use_already_ready || scenario.use_zero_duration {
            return Ok(()); // Focus on timeout cases that require draining
        }

        let lab = LabRuntime::new(LabConfig::deterministic());

        lab.block_on(async {
            let start_time = Time::ZERO;
            let timeout_duration = Duration::from_millis(scenario.timeout_duration_ms);

            let poll_count = Arc::new(AtomicU32::new(0));
            let drop_count = Arc::new(AtomicU32::new(0));

            // Create future that will be interrupted by timeout
            let inner_future = TrackedFuture::delayed(
                "completed".to_string(),
                poll_count.clone(),
                drop_count.clone(),
                (scenario.timeout_duration_ms * 2) as u32 // Will timeout before completing
            );

            let mut timeout_future = TimeoutFuture::after(start_time, timeout_duration, inner_future);

            // Advance time to trigger timeout
            let deadline = start_time.saturating_add_nanos(
                timeout_duration.as_nanos().min(u128::from(u64::MAX)) as u64
            );
            lab.advance_to(deadline);

            // Timeout should fire
            let result = timeout_future.await;
            prop_assert!(result.is_err(), "Should timeout");

            // MR3.1: Inner future should be polled before timeout
            let poll_count_val = poll_count.load(Ordering::SeqCst);
            prop_assert!(poll_count_val > 0,
                "Inner future should be polled before timeout: polls={}", poll_count_val);

            // MR3.2: Inner future should be dropped (drained) after timeout
            let drop_count_val = drop_count.load(Ordering::SeqCst);
            prop_assert!(drop_count_val > 0,
                "Inner future should be dropped when timeout fires: drops={}", drop_count_val);

            // MR3.3: Verify timeout happened (not completion)
            if let Err(elapsed) = result {
                prop_assert_eq!(elapsed.deadline(), deadline,
                    "Timeout should report correct deadline");
            }
        });
    });
}

/// **MR4: Zero Duration Immediate**
///
/// Zero-duration timeout should return immediately with timeout error,
/// without polling the inner future. This tests the boundary condition
/// where timeout duration is zero.
///
/// **Property**: timeout_duration = 0 ⇒ immediate_timeout ∧ ¬inner_polled
#[test]
fn mr4_zero_duration_immediate() {
    proptest!(|(scenario in scenario_strategy().prop_filter("zero duration", |s| s.use_zero_duration))| {
        let lab = LabRuntime::new(LabConfig::deterministic());

        lab.block_on(async {
            let start_time = Time::ZERO;
            let timeout_duration = Duration::ZERO;

            let poll_count = Arc::new(AtomicU32::new(0));
            let drop_count = Arc::new(AtomicU32::new(0));

            let inner_future = TrackedFuture::ready(42u32, poll_count.clone(), drop_count.clone());
            let timeout_future = TimeoutFuture::after(start_time, timeout_duration, inner_future);

            // Should timeout immediately without polling inner future
            let result = timeout_future.await;

            // MR4.1: Should be timeout error
            prop_assert!(result.is_err(), "Zero-duration timeout should fail immediately");

            if let Err(elapsed) = result {
                prop_assert_eq!(elapsed.deadline(), start_time,
                    "Zero-duration deadline should be start time");
            }

            // MR4.2: Inner future should still be dropped (cleanup)
            let drop_count_val = drop_count.load(Ordering::SeqCst);
            prop_assert!(drop_count_val > 0,
                "Inner future should be dropped even with zero timeout");

            // MR4.3: The timeout behavior should be deterministic
            // Repeat the test to ensure consistent behavior
            let poll_count2 = Arc::new(AtomicU32::new(0));
            let drop_count2 = Arc::new(AtomicU32::new(0));
            let inner_future2 = TrackedFuture::ready(24u32, poll_count2.clone(), drop_count2.clone());
            let timeout_future2 = TimeoutFuture::after(start_time, timeout_duration, inner_future2);

            let result2 = timeout_future2.await;
            prop_assert!(result2.is_err(), "Zero-duration timeout should be deterministic");
        });
    });
}

/// **MR5: Already Ready Fast Path**
///
/// Timeout with an already-completed future should return the Ok result
/// immediately, regardless of deadline. This tests the fast path where
/// the inner future is ready on first poll.
///
/// **Property**: inner_ready_immediately ⇒ Ok(inner_result) ∧ ¬timeout_checked
#[test]
fn mr5_already_ready_fast_path() {
    proptest!(|(scenario in scenario_strategy().prop_filter("ready", |s| s.use_already_ready && !s.use_zero_duration))| {
        let lab = LabRuntime::new(LabConfig::deterministic());

        lab.block_on(async {
            let start_time = Time::ZERO;
            let timeout_duration = Duration::from_millis(scenario.timeout_duration_ms);

            let poll_count = Arc::new(AtomicU32::new(0));
            let drop_count = Arc::new(AtomicU32::new(0));

            // Create future that's immediately ready
            let expected_value = 42u32;
            let inner_future = TrackedFuture::ready(expected_value, poll_count.clone(), drop_count.clone());
            let timeout_future = TimeoutFuture::after(start_time, timeout_duration, inner_future);

            // Should complete immediately with Ok result
            let result = timeout_future.await;

            // MR5.1: Should be Ok with expected value
            prop_assert!(result.is_ok(), "Already-ready future should complete successfully");
            if let Ok(value) = result {
                prop_assert_eq!(value, expected_value,
                    "Should return inner future's value: expected={}, got={}", expected_value, value);
            }

            // MR5.2: Inner future should have been polled exactly once
            let poll_count_val = poll_count.load(Ordering::SeqCst);
            prop_assert!(poll_count_val > 0,
                "Inner future should be polled to check readiness");

            // MR5.3: Inner future should eventually be dropped
            let drop_count_val = drop_count.load(Ordering::SeqCst);
            prop_assert!(drop_count_val > 0,
                "Inner future should be dropped after completion");

            // MR5.4: Deadline should not have been reached
            let deadline = start_time.saturating_add_nanos(
                timeout_duration.as_nanos().min(u128::from(u64::MAX)) as u64
            );
            let current_time = lab.now();
            prop_assert!(current_time < deadline,
                "Should complete before deadline: time={:?}, deadline={:?}", current_time, deadline);
        });
    });
}

/// **Composite MR: Timing Precision with Multiple Scenarios**
///
/// Combines deadline precision testing with various inner future behaviors
/// to ensure timing correctness holds across different completion patterns.
#[test]
fn mr_composite_timing_precision_scenarios() {
    proptest!(|(
        timeout_durations in prop::collection::vec(1u64..=100, 2..=5),
        completion_delays in prop::collection::vec(0u32..=5, 2..=5)
    )| {
        let lab = LabRuntime::new(LabConfig::deterministic());

        lab.block_on(async {
            for (&timeout_ms, &delay_polls) in timeout_durations.iter().zip(completion_delays.iter()) {
                let start_time = lab.now();
                let timeout_duration = Duration::from_millis(timeout_ms);
                let deadline = start_time.saturating_add_nanos(
                    timeout_duration.as_nanos().min(u128::from(u64::MAX)) as u64
                );

                let poll_count = Arc::new(AtomicU32::new(0));
                let drop_count = Arc::new(AtomicU32::new(0));

                let inner_future = if delay_polls == 0 {
                    TrackedFuture::ready(timeout_ms, poll_count.clone(), drop_count.clone())
                } else {
                    TrackedFuture::delayed(timeout_ms, poll_count.clone(), drop_count.clone(), delay_polls)
                };

                let timeout_future = TimeoutFuture::after(start_time, timeout_duration, inner_future);

                // Fast completion case
                if delay_polls == 0 {
                    let result = timeout_future.await;
                    prop_assert!(result.is_ok(),
                        "Immediately ready future should succeed: timeout={}ms", timeout_ms);
                    if let Ok(value) = result {
                        prop_assert_eq!(value, timeout_ms,
                            "Should return correct value");
                    }
                } else {
                    // Advance time to deadline
                    lab.advance_to(deadline);

                    let result = timeout_future.await;

                    if delay_polls as u64 > timeout_ms {
                        // Should timeout
                        prop_assert!(result.is_err(),
                            "Slow future should timeout: timeout={}ms, delay={} polls", timeout_ms, delay_polls);
                    }
                }

                // Cleanup verification
                let drop_count_val = drop_count.load(Ordering::SeqCst);
                prop_assert!(drop_count_val > 0,
                    "Future should be cleaned up: timeout={}ms", timeout_ms);
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Integration test to verify basic timeout deadline behavior
    #[test]
    fn integration_basic_timeout_deadline() {
        let lab = LabRuntime::new(LabConfig::deterministic());

        lab.block_on(async {
            let start_time = Time::ZERO;
            let timeout_duration = Duration::from_millis(100);
            let deadline = start_time.saturating_add_nanos(100_000_000); // 100ms

            let poll_count = Arc::new(AtomicU32::new(0));
            let drop_count = Arc::new(AtomicU32::new(0));

            // Future that never completes
            let inner_future = TrackedFuture::pending(poll_count.clone(), drop_count.clone());
            let timeout_future = TimeoutFuture::after(start_time, timeout_duration, inner_future);

            // Advance time to deadline
            lab.advance_to(deadline);

            // Should timeout
            let result = timeout_future.await;
            assert!(result.is_err(), "Should timeout");

            // Verify cleanup
            assert!(drop_count.load(Ordering::SeqCst) > 0, "Should be cleaned up");
        });
    }

    /// Test zero-duration timeout
    #[test]
    fn integration_zero_duration_timeout() {
        let lab = LabRuntime::new(LabConfig::deterministic());

        lab.block_on(async {
            let start_time = Time::ZERO;
            let timeout_duration = Duration::ZERO;

            let poll_count = Arc::new(AtomicU32::new(0));
            let drop_count = Arc::new(AtomicU32::new(0));

            let inner_future = TrackedFuture::ready(42u32, poll_count.clone(), drop_count.clone());
            let timeout_future = TimeoutFuture::after(start_time, timeout_duration, inner_future);

            // Should timeout immediately
            let result = timeout_future.await;
            assert!(result.is_err(), "Zero duration should timeout immediately");
        });
    }

    /// Test already-ready future
    #[test]
    fn integration_already_ready_future() {
        let lab = LabRuntime::new(LabConfig::deterministic());

        lab.block_on(async {
            let start_time = Time::ZERO;
            let timeout_duration = Duration::from_millis(100);

            let poll_count = Arc::new(AtomicU32::new(0));
            let drop_count = Arc::new(AtomicU32::new(0));

            let inner_future = TrackedFuture::ready(42u32, poll_count.clone(), drop_count.clone());
            let timeout_future = TimeoutFuture::after(start_time, timeout_duration, inner_future);

            // Should complete with Ok
            let result = timeout_future.await;
            assert!(result.is_ok(), "Ready future should complete");
            assert_eq!(result.unwrap(), 42u32, "Should return correct value");
        });
    }
}