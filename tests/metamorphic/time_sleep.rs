#![allow(warnings)]
#![allow(clippy::all)]
//! Metamorphic Testing for time::sleep cancel-drain virtual-time invariants
//!
//! Tests fundamental sleep behavior using metamorphic relations that must hold
//! regardless of specific sleep durations or cancellation patterns. Uses LabRuntime
//! with virtual time for deterministic execution and timeline control.
//!
//! ## Metamorphic Relations Tested:
//!
//! 1. **Exact timing**: sleep(d) wakes after exactly d virtual time
//! 2. **Cancel-drain**: sleep cancel does not leak timer resources
//! 3. **Reset correctness**: deadline reset reschedules correctly
//! 4. **Zero duration**: zero-duration sleep completes immediately
//! 5. **Budget deadline**: sleep past budget deadline returns DeadlineExceeded

use proptest::prelude::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::time::{Sleep, sleep, sleep_until, budget_sleep, Elapsed};
use asupersync::types::{Budget, Time};
use asupersync::{region, Outcome};

/// Test configuration for sleep metamorphic properties
#[derive(Debug, Clone)]
struct SleepTestConfig {
    /// Duration to sleep (in milliseconds)
    sleep_duration_ms: u64,
    /// Virtual time advancement step size (in milliseconds)
    advance_step_ms: u64,
    /// Whether to cancel the sleep before completion
    cancel_before_completion: bool,
    /// How long to wait before cancelling (relative to sleep duration)
    cancel_delay_ratio: f32,
}

impl SleepTestConfig {
    /// Calculate when cancellation should occur
    fn cancel_time_ms(&self) -> u64 {
        if !self.cancel_before_completion {
            return self.sleep_duration_ms + 100; // Cancel after completion
        }
        ((self.sleep_duration_ms as f32) * self.cancel_delay_ratio).max(1.0) as u64
    }
}

fn sleep_test_config_strategy() -> impl Strategy<Value = SleepTestConfig> {
    (
        // Sleep duration: 1ms to 1000ms
        1_u64..=1000,
        // Advance step: 1ms to 100ms
        1_u64..=100,
        // Cancel flag
        any::<bool>(),
        // Cancel delay ratio: 0.1 to 0.9 (cancel somewhere in middle)
        (0.1_f32..0.9),
    )
        .prop_map(|(sleep_duration_ms, advance_step_ms, cancel_before_completion, cancel_delay_ratio)| {
            SleepTestConfig {
                sleep_duration_ms,
                advance_step_ms,
                cancel_before_completion,
                cancel_delay_ratio,
            }
        })
}

/// Helper future that tracks when it was polled and completed
#[derive(Debug)]
struct TrackedSleep {
    inner: Sleep,
    polled: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
}

impl TrackedSleep {
    fn new(sleep: Sleep) -> Self {
        Self {
            inner: sleep,
            polled: Arc::new(AtomicBool::new(false)),
            completed: Arc::new(AtomicBool::new(false)),
        }
    }

    fn was_polled(&self) -> bool {
        self.polled.load(Ordering::Acquire)
    }

    fn was_completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    fn deadline(&self) -> Time {
        self.inner.deadline()
    }
}

impl Future for TrackedSleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.polled.store(true, Ordering::Release);

        match Pin::new(&mut self.inner).poll(cx) {
            Poll::Ready(()) => {
                self.completed.store(true, Ordering::Release);
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// MR1: sleep(d) wakes after exactly d virtual time
#[test]
fn mr1_sleep_wakes_after_exactly_d_virtual_time() {
    proptest!(|(duration_ms in 1_u64..=1000)| {
        let mut runtime = LabRuntime::with_config(LabConfig::deterministic());
        let start_time = runtime.now();

        let result = runtime.block_on(async {
            region(|cx, _scope| async move {
                let sleep_duration = Duration::from_millis(duration_ms);
                let expected_wake_time = start_time.saturating_add_nanos(sleep_duration.as_nanos() as u64);

                sleep(start_time, sleep_duration).await;

                let actual_wake_time = cx.now();

                // The sleep should wake at EXACTLY the expected time in virtual time
                prop_assert_eq!(actual_wake_time, expected_wake_time,
                    "Sleep duration {}ms: expected wake time {:?}, got {:?}",
                    duration_ms, expected_wake_time, actual_wake_time);

                Ok(())
            })
        });

        prop_assert!(result.is_ok(), "Sleep execution failed: {:?}", result);

        Ok(())
    });
}

/// MR2: sleep cancel does not leak timer resources
#[test]
fn mr2_sleep_cancel_does_not_leak_timer() {
    proptest!(|(config in sleep_test_config_strategy())| {
        let mut runtime = LabRuntime::with_config(LabConfig::deterministic());
        let start_time = runtime.now();

        // Count timers before test
        let timers_before = runtime.state.timer_driver_handle()
            .map_or(0, |h| h.pending_timer_count().unwrap_or(0));

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let sleep_duration = Duration::from_millis(config.sleep_duration_ms);
                let cancel_time = config.cancel_time_ms();

                let tracked_sleep = TrackedSleep::new(sleep(start_time, sleep_duration));

                let mut sleep_task = Box::pin(tracked_sleep);

                if config.cancel_before_completion {
                    // Poll the sleep to register timer, then cancel
                    let waker = futures_lite::future::poll_fn(|cx| {
                        let _ = sleep_task.as_mut().poll(cx);
                        Poll::Ready(cx.waker().clone())
                    }).await;

                    // Advance to cancel time
                    let cancel_deadline = start_time.saturating_add_nanos((cancel_time * 1_000_000) as u64);
                    let sleep_deadline = sleep_task.deadline();

                    prop_assert!(cancel_deadline < sleep_deadline,
                        "Cancel should happen before sleep completion: cancel={:?}, sleep={:?}",
                        cancel_deadline, sleep_deadline);

                    // Drop the sleep (cancel it)
                    drop(sleep_task);

                    prop_assert!(!sleep_task.was_completed(), "Sleep should not complete when cancelled");
                } else {
                    // Let sleep complete normally
                    sleep_task.await;
                    prop_assert!(sleep_task.was_completed(), "Sleep should complete normally");
                }

                Ok(())
            })
        });

        prop_assert!(result.is_ok(), "Sleep test failed: {:?}", result);

        // Check for timer leaks - should return to original count
        let timers_after = runtime.state.timer_driver_handle()
            .map_or(0, |h| h.pending_timer_count().unwrap_or(0));

        prop_assert_eq!(timers_after, timers_before,
            "Timer leak detected: before={}, after={}", timers_before, timers_after);

        Ok(())
    });
}

/// MR3: deadline reset reschedules correctly
#[test]
fn mr3_deadline_reset_reschedules_correctly() {
    proptest!(|(original_ms in 10_u64..=500, new_ms in 10_u64..=500)| {
        let mut runtime = LabRuntime::with_config(LabConfig::deterministic());
        let start_time = runtime.now();

        let result = runtime.block_on(async {
            region(|cx, _scope| async move {
                let mut sleep_future = sleep(start_time, Duration::from_millis(original_ms));
                let original_deadline = sleep_future.deadline();

                // Poll once to register timer
                let waker = futures_lite::future::poll_fn(|cx| {
                    let _ = Pin::new(&mut sleep_future).poll(cx);
                    Poll::Ready(cx.waker().clone())
                }).await;

                // Reset to new deadline before original completes
                let reset_time = start_time.saturating_add_nanos((5 * 1_000_000) as u64); // 5ms
                let new_deadline = reset_time.saturating_add_nanos((new_ms * 1_000_000) as u64);
                sleep_future.reset(new_deadline);

                prop_assert_eq!(sleep_future.deadline(), new_deadline,
                    "Reset deadline should match: expected {:?}, got {:?}",
                    new_deadline, sleep_future.deadline());

                // Complete the reset sleep
                sleep_future.await;

                let completion_time = cx.now();

                // Should complete at the NEW deadline, not the original
                prop_assert_eq!(completion_time, new_deadline,
                    "Should complete at reset deadline {:?}, got {:?}",
                    new_deadline, completion_time);

                Ok(())
            })
        });

        prop_assert!(result.is_ok(), "Reset test failed: {:?}", result);

        Ok(())
    });
}

/// MR4: zero-duration sleep completes immediately
#[test]
fn mr4_zero_duration_sleep_completes_immediately() {
    proptest!(|(advance_before_ms in 0_u64..=100)| {
        let mut runtime = LabRuntime::with_config(LabConfig::deterministic());

        // Advance time randomly before test to ensure it works at any virtual time
        if advance_before_ms > 0 {
            runtime.advance_time(advance_before_ms * 1_000_000);
        }

        let start_time = runtime.now();

        let result = runtime.block_on(async {
            region(|cx, _scope| async move {
                // Zero duration sleep
                sleep(start_time, Duration::ZERO).await;

                let completion_time = cx.now();

                // Should complete immediately - no virtual time advancement
                prop_assert_eq!(completion_time, start_time,
                    "Zero-duration sleep should complete immediately: start={:?}, completion={:?}",
                    start_time, completion_time);

                // Test sleep_until with past deadline too
                let past_deadline = start_time.saturating_sub_nanos(1_000_000); // 1ms ago
                sleep_until(past_deadline).await;

                let past_completion_time = cx.now();

                prop_assert_eq!(past_completion_time, start_time,
                    "Past deadline sleep should complete immediately: start={:?}, completion={:?}",
                    start_time, past_completion_time);

                Ok(())
            })
        });

        prop_assert!(result.is_ok(), "Zero duration test failed: {:?}", result);

        Ok(())
    });
}

/// MR5: sleep past budget deadline returns DeadlineExceeded (Elapsed)
#[test]
fn mr5_sleep_past_budget_deadline_returns_elapsed() {
    proptest!(|(budget_ms in 10_u64..=200, request_ms in 50_u64..=500)| {
        // Only test cases where requested sleep exceeds budget
        prop_assume!(request_ms > budget_ms);

        let mut runtime = LabRuntime::with_config(LabConfig::deterministic());
        let start_time = runtime.now();

        let result = runtime.block_on(async {
            region(|cx, _scope| async move {
                // Create context with limited budget
                let budget_deadline = start_time.saturating_add_nanos((budget_ms * 1_000_000) as u64);
                let budget = Budget::with_deadline(budget_deadline);

                let budget_cx = cx.with_budget(budget);

                // Try to sleep longer than budget allows
                let sleep_result = budget_sleep(&budget_cx, Duration::from_millis(request_ms), start_time).await;

                // Should return Elapsed error
                match sleep_result {
                    Err(elapsed) => {
                        prop_assert_eq!(elapsed.deadline(), budget_deadline,
                            "Elapsed deadline should match budget: budget={:?}, elapsed={:?}",
                            budget_deadline, elapsed.deadline());

                        // Virtual time should have advanced to budget deadline
                        let current_time = budget_cx.now();
                        prop_assert!(current_time >= budget_deadline,
                            "Time should advance to at least budget deadline: current={:?}, budget={:?}",
                            current_time, budget_deadline);
                    }
                    Ok(()) => {
                        prop_assert!(false,
                            "Expected Elapsed error but sleep succeeded: budget_ms={}, request_ms={}",
                            budget_ms, request_ms);
                    }
                }

                Ok(())
            })
        });

        prop_assert!(result.is_ok(), "Budget deadline test failed: {:?}", result);

        Ok(())
    });
}

/// MR6: sleep deadline and remaining duration are consistent
#[test]
fn mr6_sleep_deadline_and_remaining_duration_consistent() {
    proptest!(|(duration_ms in 1_u64..=1000, advance_ms in 0_u64..=500)| {
        let mut runtime = LabRuntime::with_config(LabConfig::deterministic());
        let start_time = runtime.now();

        let sleep_duration = Duration::from_millis(duration_ms);
        let sleep_future = sleep(start_time, sleep_duration);

        let expected_deadline = start_time.saturating_add_nanos(sleep_duration.as_nanos() as u64);

        // Deadline should be correctly calculated
        prop_assert_eq!(sleep_future.deadline(), expected_deadline,
            "Sleep deadline mismatch: expected {:?}, got {:?}",
            expected_deadline, sleep_future.deadline());

        // Advance time partway through
        if advance_ms > 0 && advance_ms < duration_ms {
            runtime.advance_time(advance_ms * 1_000_000);
            let current_time = runtime.now();

            let remaining = sleep_future.remaining(current_time);
            let expected_remaining = Duration::from_millis(duration_ms - advance_ms);

            prop_assert_eq!(remaining, expected_remaining,
                "Remaining duration mismatch: expected {:?}, got {:?}",
                expected_remaining, remaining);
        }

        Ok(())
    });
}

/// MR7: multiple concurrent sleeps with same deadline complete together
#[test]
fn mr7_concurrent_sleeps_same_deadline_complete_together() {
    proptest!(|(duration_ms in 10_u64..=500, count in 2_u8..=10)| {
        let mut runtime = LabRuntime::with_config(LabConfig::deterministic());
        let start_time = runtime.now();

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let sleep_duration = Duration::from_millis(duration_ms);
                let mut completion_times = Vec::new();

                // Spawn multiple sleeps with same deadline
                for i in 0..count {
                    let sleep_duration = sleep_duration;
                    let start_time = start_time;

                    scope.spawn(format!("sleep_{}", i), |_cx| async move {
                        let before = _cx.now();
                        sleep(start_time, sleep_duration).await;
                        let after = _cx.now();
                        (before, after)
                    })?;
                }

                // Wait for all to complete and collect times
                while !scope.is_empty() {
                    if let Some(outcome) = scope.try_join_next() {
                        match outcome {
                            Outcome::Ok((before, after)) => {
                                completion_times.push((before, after));
                            }
                            other => {
                                prop_assert!(false, "Sleep task failed: {:?}", other);
                            }
                        }
                    } else {
                        asupersync::runtime::yield_now().await;
                    }
                }

                prop_assert_eq!(completion_times.len(), count as usize,
                    "All sleeps should complete");

                let expected_deadline = start_time.saturating_add_nanos((duration_ms * 1_000_000) as u64);

                // All should complete at the same virtual time
                for (i, (_before, after)) in completion_times.iter().enumerate() {
                    prop_assert_eq!(*after, expected_deadline,
                        "Sleep {} completion time mismatch: expected {:?}, got {:?}",
                        i, expected_deadline, after);
                }

                Ok(())
            })
        });

        prop_assert!(result.is_ok(), "Concurrent sleeps test failed: {:?}", result);

        Ok(())
    });
}

/// MR8: sleep elapsed time is deterministic under virtual time
#[test]
fn mr8_sleep_elapsed_time_deterministic_virtual_time() {
    proptest!(|(seed in any::<u64>(), duration_ms in 1_u64..=100)| {
        // Run same test with same seed multiple times
        let mut results = Vec::new();

        for _run in 0..3 {
            let mut runtime = LabRuntime::with_config(
                LabConfig::deterministic().with_seed(seed)
            );
            let start_time = runtime.now();

            let result = runtime.block_on(async {
                region(|cx, _scope| async move {
                    sleep(start_time, Duration::from_millis(duration_ms)).await;
                    Ok(cx.now())
                })
            });

            match result {
                Ok(completion_time) => results.push(completion_time),
                Err(e) => prop_assert!(false, "Sleep failed: {:?}", e),
            }
        }

        // All runs with same seed should produce identical results
        prop_assert_eq!(results.len(), 3, "All runs should succeed");

        let first_result = results[0];
        for (i, &result) in results.iter().enumerate() {
            prop_assert_eq!(result, first_result,
                "Run {} result mismatch: expected {:?}, got {:?}",
                i, first_result, result);
        }

        Ok(())
    });
}

/// Integration test combining multiple MRs
#[test]
fn integration_sleep_properties_combined() {
    proptest!(|(config in sleep_test_config_strategy())| {
        let mut runtime = LabRuntime::with_config(LabConfig::deterministic());
        let start_time = runtime.now();

        let result = runtime.block_on(async {
            region(|cx, _scope| async move {
                let sleep_duration = Duration::from_millis(config.sleep_duration_ms);

                // Create and test a sleep
                let mut sleep_future = sleep(start_time, sleep_duration);
                let original_deadline = sleep_future.deadline();

                // MR1: Verify deadline calculation
                let expected_deadline = start_time.saturating_add_nanos((config.sleep_duration_ms * 1_000_000) as u64);
                prop_assert_eq!(original_deadline, expected_deadline,
                    "Initial deadline should be correct");

                // MR6: Test remaining time before sleep
                let remaining_before = sleep_future.remaining(start_time);
                prop_assert_eq!(remaining_before, sleep_duration,
                    "Remaining time at start should equal sleep duration");

                if config.cancel_before_completion {
                    // MR2: Test cancellation (drop without completion)
                    drop(sleep_future);
                } else {
                    // MR1: Test normal completion timing
                    sleep_future.await;
                    let completion_time = cx.now();
                    prop_assert_eq!(completion_time, expected_deadline,
                        "Sleep should complete at exact deadline");
                }

                Ok(())
            })
        });

        prop_assert!(result.is_ok(), "Integration test failed: {:?}", result);

        Ok(())
    });
}

#[cfg(test)]
mod sleep_edge_cases {
    use super::*;

    #[test]
    fn sleep_with_time_getter_respects_custom_time() {
        let mut custom_time = Time::from_secs(100);

        let time_getter = || custom_time;
        let deadline = Time::from_secs(105);

        let sleep_future = Sleep::with_time_getter(deadline, time_getter);

        assert_eq!(sleep_future.deadline(), deadline);
        assert!(!sleep_future.is_elapsed(custom_time));
        assert!(sleep_future.is_elapsed(deadline));
    }

    #[test]
    fn sleep_reset_clears_completion_state() {
        let start_time = Time::from_secs(10);
        let mut sleep_future = sleep(start_time, Duration::from_millis(100));

        let original_deadline = sleep_future.deadline();
        let new_deadline = start_time.saturating_add_nanos(200_000_000); // 200ms

        sleep_future.reset(new_deadline);

        assert_eq!(sleep_future.deadline(), new_deadline);
        assert_ne!(sleep_future.deadline(), original_deadline);
        assert!(!sleep_future.was_polled());
    }

    #[test]
    fn budget_sleep_respects_shorter_budget() {
        let mut runtime = LabRuntime::with_config(LabConfig::deterministic());

        let result = runtime.block_on(async {
            region(|cx, _scope| async move {
                let start_time = cx.now();
                let budget_deadline = start_time.saturating_add_nanos(50_000_000); // 50ms
                let budget = Budget::with_deadline(budget_deadline);
                let budget_cx = cx.with_budget(budget);

                // Try to sleep 100ms with 50ms budget
                let result = budget_sleep(&budget_cx, Duration::from_millis(100), start_time).await;

                match result {
                    Err(elapsed) => {
                        assert_eq!(elapsed.deadline(), budget_deadline);
                        Ok(())
                    }
                    Ok(()) => panic!("Expected budget deadline exceeded"),
                }
            })
        });

        assert!(result.is_ok());
    }
}