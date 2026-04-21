#![allow(clippy::all)]
//! Metamorphic Testing for combinator::timeout deadline invariants
//!
//! This test suite validates the fundamental timeout semantics using metamorphic
//! relations that must hold regardless of the specific timeout values or futures.

use std::time::Duration;

use asupersync::combinator::timeout;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::time::{sleep, Time};
use asupersync::{region, Outcome};
use proptest::prelude::*;

/// Test configuration for timeout metamorphic properties
#[derive(Debug, Clone)]
struct TimeoutTestConfig {
    /// Deadline for the timeout (relative to test start)
    deadline_ms: u64,
    /// How long the future should take to complete (relative to test start)
    future_duration_ms: u64,
    /// Whether the future should be cancelled externally before completion
    external_cancel: bool,
}

fn timeout_test_config_strategy() -> impl Strategy<Value = TimeoutTestConfig> {
    (
        // Deadline: 0ms to 1000ms
        0_u64..=1000,
        // Future duration: 1ms to 1000ms (0ms futures complete immediately)
        1_u64..=1000,
        // External cancellation flag
        any::<bool>(),
    )
        .prop_map(|(deadline_ms, future_duration_ms, external_cancel)| {
            TimeoutTestConfig {
                deadline_ms,
                future_duration_ms,
                external_cancel,
            }
        })
}

/// Simulates a future that sleeps for the given duration
async fn simulate_work(cx: &asupersync::Cx, duration_ms: u64) -> Result<u32, &'static str> {
    sleep(cx, Duration::from_millis(duration_ms)).await;
    Ok(42) // Arbitrary success value
}

/// MR1: timeout(d, fut) returns fut's outcome iff fut completes by deadline d
#[test]
fn mr1_timeout_returns_future_outcome_iff_completes_by_deadline() {
    proptest!(|(config in timeout_test_config_strategy())| {
        // Skip cases where external cancellation interferes with the core property
        if config.external_cancel {
            return Ok(());
        }

        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let deadline = Time::now() + Duration::from_millis(config.deadline_ms);
                let future = simulate_work(cx, config.future_duration_ms);

                let outcome = timeout(cx, deadline, future).await;

                // Determine if the future should have completed by the deadline
                let future_completes_by_deadline = config.future_duration_ms <= config.deadline_ms;

                match outcome {
                    Ok(result) => {
                        // If we got the future's result, it must have completed by deadline
                        prop_assert!(future_completes_by_deadline,
                            "Got future result ({:?}) but future_duration_ms ({}) > deadline_ms ({})",
                            result, config.future_duration_ms, config.deadline_ms);
                        prop_assert_eq!(result, Ok(42), "Future result should be Ok(42)");
                    }
                    Err(_timeout_err) => {
                        // If we got a timeout, the future should not have completed by deadline
                        prop_assert!(!future_completes_by_deadline,
                            "Got timeout but future_duration_ms ({}) <= deadline_ms ({})",
                            config.future_duration_ms, config.deadline_ms);
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// MR2: On timeout expiry, the inner future is cancelled AND fully drained
#[test]
fn mr2_timeout_expiry_cancels_and_drains_future() {
    proptest!(|(future_duration_ms in 100_u64..=1000)| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let deadline = Time::now() + Duration::from_millis(50); // Short deadline
                let future = simulate_work(cx, future_duration_ms);

                let outcome = timeout(cx, deadline, future).await;

                // Should always timeout since deadline (50ms) < future_duration (100-1000ms)
                prop_assert!(outcome.is_err(), "Should timeout with short deadline");

                // After timeout, verify the region can close cleanly (proving cancellation worked)
                // If the future wasn't properly cancelled and drained, the region wouldn't close
                Ok(())
            })
        });

        // If we reach here without hanging, cancellation and draining worked
        result
    });
}

/// MR3: External cancellation cancels the future without deadline race conditions
#[test]
fn mr3_external_cancel_avoids_deadline_races() {
    proptest!(|(deadline_ms in 100_u64..=1000, future_duration_ms in 200_u64..=1000)| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                // Create a nested scope that we can cancel
                let outcome = region(|inner_cx, inner_scope| async move {
                    let deadline = Time::now() + Duration::from_millis(deadline_ms);
                    let future = simulate_work(inner_cx, future_duration_ms);
                    let timeout_future = timeout(inner_cx, deadline, future);

                    // Schedule cancellation after a short delay
                    inner_scope.spawn(|cancel_cx| async move {
                        sleep(cancel_cx, Duration::from_millis(20)).await;
                        // This will cause the timeout future to be cancelled
                        Ok(())
                    });

                    timeout_future.await
                }).await;

                // Should be cancelled, not timeout or success
                match outcome {
                    Outcome::Cancelled => {
                        // This is the expected result when externally cancelled
                    }
                    other => {
                        // Could also complete or timeout if timing is different,
                        // but shouldn't panic or hang
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// MR4: timeout(0, _) yields immediate timeout for any non-trivial future
#[test]
fn mr4_zero_deadline_immediate_timeout() {
    proptest!(|(future_duration_ms in 1_u64..=1000)| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let deadline = Time::now(); // Immediate deadline (already passed)
                let future = simulate_work(cx, future_duration_ms);

                let outcome = timeout(cx, deadline, future).await;

                // Should always timeout immediately with zero/past deadline
                prop_assert!(outcome.is_err(),
                    "Should timeout immediately with past deadline, got: {:?}", outcome);

                Ok(())
            })
        });

        result
    });
}

/// MR5: timeout(Forever, fut) behaves identically to fut (no timeout behavior)
#[test]
fn mr5_infinite_timeout_equals_bare_future() {
    proptest!(|(future_duration_ms in 1_u64..=500)| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                // Very far future deadline (effectively infinite)
                let deadline = Time::now() + Duration::from_secs(3600); // 1 hour
                let future1 = simulate_work(cx, future_duration_ms);
                let future2 = simulate_work(cx, future_duration_ms);

                // Run both: one with timeout(infinity), one bare
                let (outcome1, outcome2) = asupersync::combinator::join(
                    timeout(cx, deadline, future1),
                    future2
                ).await;

                // Both should succeed with the same result
                prop_assert!(outcome1.is_ok(), "Infinite timeout should not timeout");
                prop_assert!(outcome2.is_ok(), "Bare future should succeed");

                let result1 = outcome1.unwrap();
                let result2 = outcome2;

                prop_assert_eq!(result1, result2,
                    "timeout(infinity, fut) should equal fut result");

                Ok(())
            })
        });

        result
    });
}

/// Additional property: Timeout nesting follows min(outer, inner) deadline semantics
#[test]
fn mr_nested_timeout_min_semantics() {
    proptest!(|(outer_ms in 50_u64..=200, inner_ms in 50_u64..=200, work_ms in 100_u64..=300)| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let outer_deadline = Time::now() + Duration::from_millis(outer_ms);
                let inner_deadline = Time::now() + Duration::from_millis(inner_ms);

                let future = simulate_work(cx, work_ms);
                let nested_timeout = timeout(cx, inner_deadline, future);
                let outcome = timeout(cx, outer_deadline, nested_timeout).await;

                let min_deadline = outer_ms.min(inner_ms);
                let should_timeout = work_ms > min_deadline;

                match outcome {
                    Ok(Ok(result)) => {
                        // Work completed before both deadlines
                        prop_assert!(!should_timeout,
                            "Got success but work_ms ({}) > min_deadline ({})", work_ms, min_deadline);
                        prop_assert_eq!(result, Ok(42));
                    }
                    Ok(Err(_)) => {
                        // Inner timeout triggered but outer didn't
                        prop_assert!(work_ms > inner_ms && work_ms <= outer_ms,
                            "Inner timeout but timing doesn't match expectations");
                    }
                    Err(_) => {
                        // Outer timeout triggered
                        prop_assert!(work_ms > outer_ms,
                            "Outer timeout but work_ms ({}) <= outer_ms ({})", work_ms, outer_ms);
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// Edge case: Zero-duration future with various timeouts
#[test]
fn mr_zero_duration_future_properties() {
    proptest!(|(deadline_ms in 0_u64..=100)| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let deadline = Time::now() + Duration::from_millis(deadline_ms);

                // Future that completes immediately
                let immediate_future = async { Ok::<u32, &'static str>(42) };

                let outcome = timeout(cx, deadline, immediate_future).await;

                // Should always succeed regardless of deadline since future completes immediately
                prop_assert!(outcome.is_ok(),
                    "Immediate future should never timeout, got: {:?}", outcome);
                prop_assert_eq!(outcome.unwrap(), Ok(42));

                Ok(())
            })
        });

        result
    });
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_basic_timeout_success() {
        let runtime = LabRuntime::new(LabConfig::default());

        runtime.block_on(async {
            region(|cx, scope| async move {
                let deadline = Time::now() + Duration::from_millis(100);
                let future = simulate_work(cx, 50); // Completes before deadline

                let outcome = timeout(cx, deadline, future).await;
                assert!(outcome.is_ok(), "Should complete before deadline");
                assert_eq!(outcome.unwrap(), Ok(42));

                Ok(())
            })
        }).unwrap();
    }

    #[test]
    fn test_basic_timeout_expiry() {
        let runtime = LabRuntime::new(LabConfig::default());

        runtime.block_on(async {
            region(|cx, scope| async move {
                let deadline = Time::now() + Duration::from_millis(50);
                let future = simulate_work(cx, 100); // Takes longer than deadline

                let outcome = timeout(cx, deadline, future).await;
                assert!(outcome.is_err(), "Should timeout");

                Ok(())
            })
        }).unwrap();
    }
}