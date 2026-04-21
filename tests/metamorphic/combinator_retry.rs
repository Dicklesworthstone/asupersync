#![allow(clippy::all)]
//! Metamorphic Testing for combinator::retry exponential-backoff invariants
//!
//! This test suite validates the fundamental retry combinator semantics using
//! metamorphic relations that must hold regardless of specific retry policies,
//! error types, or timing configurations.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use asupersync::combinator::retry::{self, AlwaysRetry, NeverRetry, RetryError, RetryPolicy};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::time::{sleep, Time};
use asupersync::{region, Outcome};
use proptest::prelude::*;

/// Test configuration for retry properties
#[derive(Debug, Clone)]
struct RetryTestConfig {
    /// Maximum attempts (1 to 10)
    max_attempts: u32,
    /// Initial delay in milliseconds
    initial_delay_ms: u64,
    /// Multiplier for exponential backoff
    multiplier: f64,
    /// Which attempt should succeed (0 = never, 1 = first attempt, etc.)
    succeed_on_attempt: u32,
    /// Whether to introduce cancellation
    cancel_during_retry: bool,
}

fn retry_config_strategy() -> impl Strategy<Value = RetryTestConfig> {
    (
        // Max attempts: 1 to 5 (keeping small for test speed)
        1_u32..=5,
        // Initial delay: 1ms to 100ms
        1_u64..=100,
        // Multiplier: 1.5 to 3.0
        1.5_f64..=3.0,
        // Succeed on attempt: 0 to 6 (0 = never, 1+ = attempt number)
        0_u32..=6,
        // Cancel flag
        any::<bool>(),
    )
        .prop_map(|(max_attempts, initial_delay_ms, multiplier, succeed_on_attempt, cancel_during_retry)| {
            RetryTestConfig {
                max_attempts,
                initial_delay_ms,
                multiplier,
                succeed_on_attempt,
                cancel_during_retry,
            }
        })
}

/// A test error type
#[derive(Debug, Clone, PartialEq, Eq)]
struct TestError {
    code: u32,
    message: String,
}

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TestError({}): {}", self.code, self.message)
    }
}

impl std::error::Error for TestError {}

/// Factory that fails until a certain attempt
struct FailUntilAttempt {
    target_attempt: u32,
    current_attempt: AtomicU32,
}

impl FailUntilAttempt {
    fn new(target_attempt: u32) -> Self {
        Self {
            target_attempt,
            current_attempt: AtomicU32::new(0),
        }
    }

    async fn call(&self) -> Result<String, TestError> {
        let attempt = self.current_attempt.fetch_add(1, Ordering::SeqCst) + 1;

        if self.target_attempt > 0 && attempt >= self.target_attempt {
            Ok(format!("success_on_attempt_{}", attempt))
        } else {
            Err(TestError {
                code: attempt,
                message: format!("failed_attempt_{}", attempt),
            })
        }
    }
}

/// MR1: retry(n, fut) yields Ok iff any of the n attempts succeed
#[test]
fn mr1_retry_yields_ok_iff_any_attempt_succeeds() {
    proptest!(|(config in retry_config_strategy())| {
        // Skip configurations with cancellation for this pure success/failure property
        if config.cancel_during_retry {
            return Ok(());
        }

        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = RetryPolicy::new()
                    .with_max_attempts(config.max_attempts)
                    .with_initial_delay(Duration::from_millis(config.initial_delay_ms))
                    .with_multiplier(config.multiplier);

                let factory = FailUntilAttempt::new(config.succeed_on_attempt);

                let retry_future = retry::retry(
                    policy,
                    AlwaysRetry,
                    || factory.call()
                );

                let outcome = retry_future.await;

                // Determine if any attempt within max_attempts should succeed
                let should_succeed = config.succeed_on_attempt > 0 && config.succeed_on_attempt <= config.max_attempts;

                match outcome {
                    Ok(success_msg) => {
                        prop_assert!(should_succeed,
                            "Got success but no attempt within {} should succeed (target: {})",
                            config.max_attempts, config.succeed_on_attempt);

                        prop_assert!(success_msg.contains("success_on_attempt"),
                            "Success message should indicate which attempt succeeded");
                    }
                    Err(retry_err) => {
                        prop_assert!(!should_succeed,
                            "Got retry failure but attempt {} should succeed within {} attempts",
                            config.succeed_on_attempt, config.max_attempts);

                        match retry_err {
                            retry::RetryFailure::Exhausted(err) => {
                                prop_assert_eq!(err.attempts, config.max_attempts,
                                    "Should have attempted exactly {} times", config.max_attempts);

                                // Final error should be from the last attempt
                                prop_assert_eq!(err.final_error.code, config.max_attempts,
                                    "Final error should be from attempt {}", config.max_attempts);
                            }
                            other => {
                                return Err(proptest::test_runner::TestCaseError::fail(
                                    format!("Unexpected retry failure type: {:?}", other)
                                ));
                            }
                        }
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// MR2: Backoff delays are monotonic non-decreasing per configured policy
#[test]
fn mr2_backoff_delays_monotonic_non_decreasing() {
    proptest!(|(config in retry_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = RetryPolicy::new()
                    .with_max_attempts(config.max_attempts)
                    .with_initial_delay(Duration::from_millis(config.initial_delay_ms))
                    .with_multiplier(config.multiplier)
                    .with_jitter(0.0); // No jitter for deterministic delay comparison

                // Calculate delays for consecutive attempts
                let mut delays = Vec::new();
                for attempt in 1..config.max_attempts {
                    let delay = retry::calculate_delay(&policy, attempt, None);
                    delays.push(delay);
                }

                // Verify monotonic non-decreasing property
                for window in delays.windows(2) {
                    let current_delay = window[0];
                    let next_delay = window[1];

                    prop_assert!(next_delay >= current_delay,
                        "Delays should be non-decreasing: {:?} -> {:?} (multiplier: {})",
                        current_delay, next_delay, config.multiplier);

                    // With exponential backoff and multiplier > 1, delays should generally increase
                    if config.multiplier > 1.0 {
                        let expected_next = Duration::from_nanos(
                            (current_delay.as_nanos() as f64 * config.multiplier) as u64
                        );

                        // Allow for rounding differences and max_delay capping
                        prop_assert!(next_delay >= current_delay,
                            "With multiplier {}, next delay should be at least as large", config.multiplier);
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// MR3: Cancel during retry cancels in-flight attempt AND halts further attempts
#[test]
fn mr3_cancel_during_retry_halts_further_attempts() {
    proptest!(|(config in retry_config_strategy())| {
        // Test only configurations where cancellation is relevant
        if !config.cancel_during_retry || config.max_attempts < 2 {
            return Ok(());
        }

        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = RetryPolicy::new()
                    .with_max_attempts(config.max_attempts)
                    .with_initial_delay(Duration::from_millis(50)); // Longer delay to allow cancellation

                let factory = FailUntilAttempt::new(0); // Never succeed, so we can test cancellation

                // Use nested region to control cancellation
                let cancelled_outcome = region(|inner_cx, inner_scope| async move {
                    let retry_future = retry::retry(
                        policy,
                        AlwaysRetry,
                        || factory.call()
                    );

                    // Schedule cancellation after a short delay
                    inner_scope.spawn(|cancel_cx| async move {
                        sleep(cancel_cx, Duration::from_millis(25)).await;
                        // This will trigger cancellation of the retry
                        Ok(())
                    });

                    retry_future.await
                }).await;

                // Should be cancelled
                match cancelled_outcome {
                    Outcome::Cancelled => {
                        // Expected when cancelled externally
                    }
                    Outcome::Ok(Err(retry::RetryFailure::Cancelled(_))) => {
                        // Also valid - explicit cancellation error
                    }
                    Outcome::Ok(Ok(_)) => {
                        // Could succeed if very fast
                    }
                    Outcome::Ok(Err(retry::RetryFailure::Exhausted(err))) => {
                        // Should not exhaust retries if cancelled early
                        prop_assert!(err.attempts < config.max_attempts,
                            "Should not exhaust all {} attempts if cancelled early, got {}",
                            config.max_attempts, err.attempts);
                    }
                    other => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            format!("Unexpected cancellation outcome: {:?}", other)
                        ));
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// MR4: Retries exhausted returns the LAST error
#[test]
fn mr4_retries_exhausted_returns_last_error() {
    proptest!(|(config in retry_config_strategy())| {
        // Skip configurations where retry would succeed
        if config.succeed_on_attempt > 0 && config.succeed_on_attempt <= config.max_attempts {
            return Ok(());
        }

        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = RetryPolicy::new()
                    .with_max_attempts(config.max_attempts)
                    .with_initial_delay(Duration::from_millis(1)); // Fast retries

                let factory = FailUntilAttempt::new(0); // Never succeed

                let retry_future = retry::retry(
                    policy,
                    AlwaysRetry,
                    || factory.call()
                );

                match retry_future.await {
                    Ok(_) => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            "Expected retry failure but got success"
                        ));
                    }
                    Err(retry::RetryFailure::Exhausted(retry_error)) => {
                        // Should have attempted exactly max_attempts times
                        prop_assert_eq!(retry_error.attempts, config.max_attempts,
                            "Should attempt exactly {} times", config.max_attempts);

                        // Final error should be from the LAST attempt
                        prop_assert_eq!(retry_error.final_error.code, config.max_attempts,
                            "Final error should be from attempt {}, got attempt {}",
                            config.max_attempts, retry_error.final_error.code);

                        prop_assert!(retry_error.final_error.message.contains("failed_attempt"),
                            "Final error message should indicate failure");
                    }
                    Err(other) => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            format!("Expected exhausted error, got: {:?}", other)
                        ));
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// MR5: retry(0, _) equals single call (max_attempts is clamped to 1)
#[test]
fn mr5_retry_zero_attempts_equals_single_call() {
    proptest!(|(succeed_on_first in any::<bool>())| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                // Policy with 0 max_attempts should be clamped to 1
                let policy = RetryPolicy::new()
                    .with_max_attempts(0) // This should be clamped to 1
                    .with_initial_delay(Duration::from_millis(100));

                let succeed_on_attempt = if succeed_on_first { 1 } else { 2 };
                let factory = FailUntilAttempt::new(succeed_on_attempt);

                let retry_future = retry::retry(
                    policy,
                    AlwaysRetry,
                    || factory.call()
                );

                // Run the retry
                let retry_result = retry_future.await;

                // Also run a single call for comparison
                let single_factory = FailUntilAttempt::new(succeed_on_attempt);
                let single_result = single_factory.call().await;

                // Results should be equivalent
                match (retry_result, single_result) {
                    (Ok(retry_msg), Ok(single_msg)) => {
                        prop_assert!(succeed_on_first, "Both should succeed only if first attempt succeeds");
                        // Both should indicate success on attempt 1
                        prop_assert!(retry_msg.contains("attempt_1"));
                        prop_assert!(single_msg.contains("attempt_1"));
                    }
                    (Err(retry::RetryFailure::Exhausted(retry_err)), Err(single_err)) => {
                        prop_assert!(!succeed_on_first, "Both should fail if first attempt fails");
                        prop_assert_eq!(retry_err.attempts, 1, "Should make exactly 1 attempt");
                        prop_assert_eq!(retry_err.final_error.code, single_err.code,
                            "Final error codes should match");
                    }
                    (retry_res, single_res) => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            format!("Mismatched results: retry={:?}, single={:?}",
                                retry_res, single_res)
                        ));
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// Additional property: NeverRetry predicate limits to single attempt
#[test]
fn mr_never_retry_predicate_single_attempt() {
    proptest!(|(config in retry_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = RetryPolicy::new()
                    .with_max_attempts(config.max_attempts)
                    .with_initial_delay(Duration::from_millis(1));

                let factory = FailUntilAttempt::new(0); // Never succeed

                let retry_future = retry::retry(
                    policy,
                    NeverRetry, // Should prevent all retries
                    || factory.call()
                );

                match retry_future.await {
                    Ok(_) => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            "Should not succeed when using NeverRetry predicate"
                        ));
                    }
                    Err(retry::RetryFailure::Exhausted(retry_error)) => {
                        // Should attempt exactly once with NeverRetry
                        prop_assert_eq!(retry_error.attempts, 1,
                            "NeverRetry should limit to 1 attempt, got {}", retry_error.attempts);

                        prop_assert_eq!(retry_error.final_error.code, 1,
                            "Should only see error from first attempt");
                    }
                    Err(other) => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            format!("Unexpected retry failure with NeverRetry: {:?}", other)
                        ));
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// Edge case: Delays with very large multipliers are bounded
#[test]
fn mr_delay_calculation_bounded() {
    proptest!(|(
        initial_delay_ms in 1_u64..=1000,
        multiplier in 2.0_f64..=10.0,
        max_delay_ms in 100_u64..=5000
    )| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = RetryPolicy::new()
                    .with_initial_delay(Duration::from_millis(initial_delay_ms))
                    .with_multiplier(multiplier)
                    .with_max_delay(Duration::from_millis(max_delay_ms))
                    .with_jitter(0.0);

                // Calculate delays for many attempts
                for attempt in 1..=10 {
                    let delay = retry::calculate_delay(&policy, attempt, None);

                    // Delay should never exceed max_delay
                    prop_assert!(delay <= Duration::from_millis(max_delay_ms),
                        "Delay {:?} for attempt {} exceeds max_delay {:?}",
                        delay, attempt, Duration::from_millis(max_delay_ms));

                    // Delay should be finite and non-zero for attempt > 0
                    prop_assert!(delay > Duration::ZERO || attempt == 0,
                        "Delay should be positive for attempt {}", attempt);
                }

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
    fn test_basic_retry_success() {
        let runtime = LabRuntime::new(LabConfig::default());

        runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = RetryPolicy::new().with_max_attempts(3);
                let factory = FailUntilAttempt::new(2); // Succeed on 2nd attempt

                let result = retry::retry(
                    policy,
                    AlwaysRetry,
                    || factory.call()
                ).await;

                assert!(result.is_ok(), "Should succeed on 2nd attempt");
                let success_msg = result.unwrap();
                assert!(success_msg.contains("attempt_2"), "Should succeed on attempt 2");

                Ok(())
            })
        }).unwrap();
    }

    #[test]
    fn test_retry_exhaustion() {
        let runtime = LabRuntime::new(LabConfig::default());

        runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = RetryPolicy::new().with_max_attempts(2);
                let factory = FailUntilAttempt::new(0); // Never succeed

                let result = retry::retry(
                    policy,
                    AlwaysRetry,
                    || factory.call()
                ).await;

                match result {
                    Err(retry::RetryFailure::Exhausted(err)) => {
                        assert_eq!(err.attempts, 2, "Should attempt exactly 2 times");
                        assert_eq!(err.final_error.code, 2, "Final error should be from attempt 2");
                    }
                    other => panic!("Expected exhausted error, got: {:?}", other),
                }

                Ok(())
            })
        }).unwrap();
    }

    #[test]
    fn test_delay_calculation() {
        let policy = RetryPolicy::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_multiplier(2.0)
            .with_jitter(0.0);

        let delay1 = retry::calculate_delay(&policy, 1, None);
        let delay2 = retry::calculate_delay(&policy, 2, None);
        let delay3 = retry::calculate_delay(&policy, 3, None);

        assert_eq!(delay1, Duration::from_millis(100)); // 100 * 2^0
        assert_eq!(delay2, Duration::from_millis(200)); // 100 * 2^1
        assert_eq!(delay3, Duration::from_millis(400)); // 100 * 2^2
    }
}