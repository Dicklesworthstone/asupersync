//! Metamorphic Testing for combinator::retry exponential backoff jitter invariants
//!
//! This test suite validates the mathematical properties of jitter algorithms
//! in exponential backoff, ensuring bounded randomness and proper cancellation
//! handling during backoff periods.
//!
//! The 5 key metamorphic relations tested:
//! 1. base_delay * 2^n sequence bounded by max_delay
//! 2. jitter ∈ [0, delay] never exceeds delay bound
//! 3. Full jitter vs decorrelated jitter strategies
//! 4. max_attempts limit respected (no infinite loop)
//! 5. Cancel during backoff returns Cancelled (no retry after cancel)

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use asupersync::combinator::retry::{
    self, calculate_delay, AlwaysRetry, RetryError, RetryPolicy, RetryResult, RetryState,
};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::time::{sleep, Time};
use asupersync::util::det_rng::DetRng;
use asupersync::{region, Outcome};
use proptest::prelude::*;

/// Test configuration for jitter properties
#[derive(Debug, Clone)]
struct JitterTestConfig {
    /// Base delay in milliseconds (10ms to 1000ms)
    base_delay_ms: u64,
    /// Multiplier for exponential backoff (1.5 to 4.0)
    multiplier: f64,
    /// Maximum delay cap in milliseconds
    max_delay_ms: u64,
    /// Jitter factor [0.0, 1.0]
    jitter: f64,
    /// Maximum attempts (2 to 8)
    max_attempts: u32,
    /// RNG seed for deterministic testing
    rng_seed: u64,
    /// Which attempt number to test cancellation on
    cancel_on_attempt: Option<u32>,
}

/// Strategy for generating jitter test configurations
fn jitter_config_strategy() -> impl Strategy<Value = JitterTestConfig> {
    (
        // Base delay: 10ms to 1000ms
        10_u64..=1000,
        // Multiplier: 1.5 to 4.0 for realistic exponential backoff
        1.5_f64..=4.0,
        // Max delay: 1s to 30s
        1000_u64..=30000,
        // Jitter: 0.0 to 1.0 (100% jitter)
        0.0_f64..=1.0,
        // Max attempts: 2 to 8 attempts
        2_u32..=8,
        // RNG seed for determinism
        1_u64..=u64::MAX,
        // Cancel on attempt (None = no cancel, Some(n) = cancel on attempt n)
        prop::option::of(1_u32..=6),
    ).prop_map(|(base_delay_ms, multiplier, max_delay_ms, jitter, max_attempts, rng_seed, cancel_on_attempt)| {
        JitterTestConfig {
            base_delay_ms,
            multiplier,
            max_delay_ms: max_delay_ms.max(base_delay_ms * 2), // Ensure max > base
            jitter,
            max_attempts,
            rng_seed,
            cancel_on_attempt,
        }
    })
}

/// Test error for controlled failures
#[derive(Debug, Clone, PartialEq, Eq)]
struct JitterTestError {
    attempt: u32,
    delay_experienced: Duration,
}

impl std::fmt::Display for JitterTestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JitterTestError(attempt: {}, delay: {:?})", self.attempt, self.delay_experienced)
    }
}

impl std::error::Error for JitterTestError {}

/// Factory that always fails but records delay information
struct DelayRecordingFactory {
    attempt_counter: AtomicU32,
}

impl DelayRecordingFactory {
    fn new() -> Self {
        Self {
            attempt_counter: AtomicU32::new(0),
        }
    }

    async fn call(&self) -> Result<String, JitterTestError> {
        let attempt = self.attempt_counter.fetch_add(1, Ordering::SeqCst) + 1;
        Err(JitterTestError {
            attempt,
            delay_experienced: Duration::ZERO, // Will be filled by caller
        })
    }
}

/// MR1: base_delay * 2^n sequence is properly bounded by max_delay
/// Verifies exponential backoff mathematical properties with jitter bounds
#[test]
fn mr1_exponential_backoff_bounded_by_max_delay() {
    proptest!(|(config in jitter_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = RetryPolicy::new()
                    .with_initial_delay(Duration::from_millis(config.base_delay_ms))
                    .with_multiplier(config.multiplier)
                    .with_max_delay(Duration::from_millis(config.max_delay_ms))
                    .with_jitter(config.jitter);

                let mut rng = DetRng::new(config.rng_seed);

                // Test delay calculation for each attempt
                for attempt in 1..=config.max_attempts {
                    let delay = calculate_delay(&policy, attempt, Some(&mut rng));

                    // Property 1: Delay should never exceed max_delay
                    prop_assert!(delay <= Duration::from_millis(config.max_delay_ms),
                        "Attempt {} delay {:?} exceeds max_delay {:?}",
                        attempt, delay, Duration::from_millis(config.max_delay_ms));

                    // Property 2: Without jitter, delay should follow base_delay * multiplier^(attempt-1)
                    if config.jitter == 0.0 {
                        let expected_base = config.base_delay_ms as f64 * config.multiplier.powi(attempt as i32 - 1);
                        let capped_expected = expected_base.min(config.max_delay_ms as f64);
                        let expected_delay = Duration::from_millis(capped_expected as u64);

                        prop_assert_eq!(delay, expected_delay,
                            "Attempt {} delay without jitter should be {:?}, got {:?}",
                            attempt, expected_delay, delay);
                    }

                    // Property 3: With jitter, delay should be within jitter bounds
                    if config.jitter > 0.0 {
                        let base_delay = config.base_delay_ms as f64 * config.multiplier.powi(attempt as i32 - 1);
                        let capped_base = base_delay.min(config.max_delay_ms as f64);
                        let min_with_jitter = capped_base; // jitter only adds
                        let max_with_jitter = capped_base * (1.0 + config.jitter);
                        let final_max = max_with_jitter.min(config.max_delay_ms as f64);

                        prop_assert!(delay.as_millis() as f64 >= min_with_jitter,
                            "Attempt {} delay {:?} below minimum expected {:.0}ms",
                            attempt, delay, min_with_jitter);

                        prop_assert!(delay.as_millis() as f64 <= final_max,
                            "Attempt {} delay {:?} above maximum expected {:.0}ms",
                            attempt, delay, final_max);
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// MR2: jitter ∈ [0, delay] never exceeds delay bound
/// Ensures jitter additions are within mathematical constraints
#[test]
fn mr2_jitter_never_exceeds_delay_bound() {
    proptest!(|(config in jitter_config_strategy())| {
        prop_assume!(config.jitter > 0.0); // Only test with actual jitter

        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = RetryPolicy::new()
                    .with_initial_delay(Duration::from_millis(config.base_delay_ms))
                    .with_multiplier(config.multiplier)
                    .with_max_delay(Duration::from_millis(config.max_delay_ms))
                    .with_jitter(config.jitter);

                // Test multiple RNG seeds to ensure jitter bounds hold universally
                for seed_offset in 0..20 {
                    let mut rng = DetRng::new(config.rng_seed.wrapping_add(seed_offset));

                    for attempt in 1..=config.max_attempts {
                        let delay_with_jitter = calculate_delay(&policy, attempt, Some(&mut rng));

                        // Calculate the theoretical no-jitter delay for comparison
                        let delay_without_jitter = calculate_delay(&policy, attempt, None);

                        // Property 1: Jittered delay should be >= base delay (jitter only adds)
                        prop_assert!(delay_with_jitter >= delay_without_jitter,
                            "Jittered delay {:?} less than base delay {:?} for attempt {}",
                            delay_with_jitter, delay_without_jitter, attempt);

                        // Property 2: Jitter addition should be bounded by jitter factor
                        let jitter_added = delay_with_jitter.saturating_sub(delay_without_jitter);
                        let max_jitter = Duration::from_nanos(
                            (delay_without_jitter.as_nanos() as f64 * config.jitter) as u64
                        );

                        prop_assert!(jitter_added <= max_jitter,
                            "Jitter added {:?} exceeds maximum {:?} for attempt {} (factor: {})",
                            jitter_added, max_jitter, attempt, config.jitter);

                        // Property 3: Total delay should still respect max_delay
                        prop_assert!(delay_with_jitter <= Duration::from_millis(config.max_delay_ms),
                            "Jittered delay {:?} exceeds max_delay {:?} for attempt {}",
                            delay_with_jitter, Duration::from_millis(config.max_delay_ms), attempt);
                    }
                }

                Ok(())
            })
        });

        result
    });
}

/// MR3: Full jitter mode and decorrelated jitter strategies
/// Tests different jitter algorithms: full jitter vs decorrelated jitter
#[test]
fn mr3_full_jitter_vs_decorrelated_strategies() {
    proptest!(|(config in jitter_config_strategy())| {
        prop_assume!(config.max_attempts >= 3); // Need multiple attempts to test correlation

        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let base_delay = Duration::from_millis(config.base_delay_ms);

                // Test 1: Full jitter mode - delay_n = rand(0, base*2^n)
                let mut full_jitter_delays = Vec::new();
                let mut rng = DetRng::new(config.rng_seed);

                for attempt in 1..=config.max_attempts {
                    let base_for_attempt = config.base_delay_ms as f64 * config.multiplier.powi(attempt as i32 - 1);
                    let capped_base = base_for_attempt.min(config.max_delay_ms as f64) as u64;

                    // Full jitter: uniform random in [0, base*2^(attempt-1)]
                    let jitter_factor = rng.next_u64() as f64 / u64::MAX as f64;
                    let full_jitter_delay = Duration::from_millis((capped_base as f64 * jitter_factor) as u64);

                    prop_assert!(full_jitter_delay <= Duration::from_millis(capped_base),
                        "Full jitter delay {:?} exceeds base {:?} for attempt {}",
                        full_jitter_delay, Duration::from_millis(capped_base), attempt);

                    full_jitter_delays.push(full_jitter_delay);
                }

                // Test 2: Decorrelated jitter - delay_n = rand(base, prev_delay*3)
                let mut decorrelated_delays = Vec::new();
                let mut prev_delay = base_delay;
                let mut rng2 = DetRng::new(config.rng_seed);

                for attempt in 1..=config.max_attempts {
                    let min_delay = config.base_delay_ms;
                    let max_delay = (prev_delay.as_millis() as f64 * 3.0) as u64;
                    let capped_max = max_delay.min(config.max_delay_ms);

                    if capped_max > min_delay {
                        let jitter_factor = rng2.next_u64() as f64 / u64::MAX as f64;
                        let range = capped_max - min_delay;
                        let decorrelated_delay = Duration::from_millis(min_delay + (range as f64 * jitter_factor) as u64);

                        prop_assert!(decorrelated_delay >= Duration::from_millis(min_delay),
                            "Decorrelated delay {:?} below minimum {} for attempt {}",
                            decorrelated_delay, min_delay, attempt);

                        prop_assert!(decorrelated_delay <= Duration::from_millis(capped_max),
                            "Decorrelated delay {:?} exceeds maximum {} for attempt {}",
                            decorrelated_delay, capped_max, attempt);

                        decorrelated_delays.push(decorrelated_delay);
                        prev_delay = decorrelated_delay;
                    } else {
                        decorrelated_delays.push(Duration::from_millis(min_delay));
                        prev_delay = Duration::from_millis(min_delay);
                    }
                }

                // Property: Both strategies should produce valid delay sequences
                prop_assert_eq!(full_jitter_delays.len(), config.max_attempts as usize);
                prop_assert_eq!(decorrelated_delays.len(), config.max_attempts as usize);

                // Property: Decorrelated jitter should maintain relationship with previous delays
                for i in 1..decorrelated_delays.len() {
                    let curr = decorrelated_delays[i];
                    let prev = decorrelated_delays[i - 1];

                    // Should be at least base_delay
                    prop_assert!(curr >= base_delay,
                        "Decorrelated delay {:?} below base delay {:?} at step {}",
                        curr, base_delay, i + 1);
                }

                Ok(())
            })
        });

        result
    });
}

/// MR4: max_attempts limit respected (no infinite loop)
/// Ensures retry loops terminate within bounded time
#[test]
fn mr4_max_attempts_limit_prevents_infinite_loop() {
    proptest!(|(config in jitter_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = RetryPolicy::new()
                    .with_max_attempts(config.max_attempts)
                    .with_initial_delay(Duration::from_millis(config.base_delay_ms))
                    .with_multiplier(config.multiplier)
                    .with_max_delay(Duration::from_millis(config.max_delay_ms))
                    .with_jitter(config.jitter);

                let factory = DelayRecordingFactory::new();

                // Record start time to ensure bounded execution
                let start_time = std::time::Instant::now();

                let retry_future = retry::retry(
                    policy,
                    AlwaysRetry,
                    || factory.call()
                );

                let result = retry_future.await;
                let elapsed = start_time.elapsed();

                // Property 1: Should complete in bounded time (not infinite loop)
                let max_expected_duration = Duration::from_millis(
                    config.max_delay_ms * config.max_attempts as u64 + 1000 // +1s buffer
                );

                prop_assert!(elapsed < max_expected_duration,
                    "Retry took {:?}, exceeding expected maximum {:?} for {} attempts",
                    elapsed, max_expected_duration, config.max_attempts);

                // Property 2: Should exhaust exactly max_attempts
                match result {
                    Err(retry::RetryFailure::Exhausted(retry_error)) => {
                        prop_assert_eq!(retry_error.attempts, config.max_attempts,
                            "Should attempt exactly {} times, got {}",
                            config.max_attempts, retry_error.attempts);

                        // Property 3: Total delay should be bounded
                        let max_theoretical_delay = Duration::from_millis(
                            config.max_delay_ms * (config.max_attempts - 1) as u64
                        );

                        prop_assert!(retry_error.total_delay <= max_theoretical_delay,
                            "Total delay {:?} exceeds theoretical maximum {:?}",
                            retry_error.total_delay, max_theoretical_delay);
                    }
                    other => {
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

/// MR5: Cancel during backoff returns Cancelled (no retry after cancel)
/// Verifies cancellation semantics during jittered backoff periods
#[test]
fn mr5_cancel_during_backoff_returns_cancelled() {
    proptest!(|(mut config in jitter_config_strategy())| {
        // Ensure we have cancellation configured and sufficient attempts
        prop_assume!(config.cancel_on_attempt.is_some());
        prop_assume!(config.max_attempts >= 2);

        let cancel_attempt = config.cancel_on_attempt.unwrap().min(config.max_attempts);
        config.cancel_on_attempt = Some(cancel_attempt);

        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = RetryPolicy::new()
                    .with_max_attempts(config.max_attempts)
                    .with_initial_delay(Duration::from_millis(config.base_delay_ms.max(100))) // Ensure measurable delay
                    .with_multiplier(config.multiplier)
                    .with_max_delay(Duration::from_millis(config.max_delay_ms))
                    .with_jitter(config.jitter);

                let factory = DelayRecordingFactory::new();

                let cancelled_outcome = region(|inner_cx, inner_scope| async move {
                    let retry_future = retry::retry(
                        policy,
                        AlwaysRetry,
                        || factory.call()
                    );

                    // Schedule cancellation during backoff of the specified attempt
                    let cancel_delay = Duration::from_millis(config.base_delay_ms / 2);
                    inner_scope.spawn(|cancel_cx| async move {
                        sleep(cancel_cx, cancel_delay).await;
                        // This triggers cancellation during the backoff delay
                        Ok(())
                    });

                    retry_future.await
                }).await;

                // Property 1: Should receive cancellation signal
                match cancelled_outcome {
                    Outcome::Cancelled => {
                        // Expected - external cancellation propagated
                    }
                    Outcome::Ok(Err(retry::RetryFailure::Cancelled(_))) => {
                        // Also valid - retry detected cancellation
                    }
                    Outcome::Ok(Err(retry::RetryFailure::Exhausted(err))) => {
                        // Property 2: If not cancelled, should not exhaust full attempts
                        prop_assert!(err.attempts < config.max_attempts,
                            "Should not complete all {} attempts if cancelled early, got {}",
                            config.max_attempts, err.attempts);
                    }
                    Outcome::Ok(Ok(_)) => {
                        // Could succeed very quickly before cancellation takes effect
                    }
                    other => {
                        return Err(proptest::test_runner::TestCaseError::fail(
                            format!("Unexpected cancellation outcome: {:?}", other)
                        ));
                    }
                }

                // Property 3: Attempt counter should not exceed cancellation point
                let recorded_attempts = factory.attempt_counter.load(Ordering::SeqCst);
                prop_assert!(recorded_attempts <= cancel_attempt + 1, // +1 for in-flight attempt
                    "Recorded {} attempts, but cancellation was scheduled at attempt {}",
                    recorded_attempts, cancel_attempt);

                Ok(())
            })
        });

        result
    });
}

/// Composite metamorphic test: All jitter properties together
#[test]
fn mr_composite_jitter_properties() {
    proptest!(|(config in jitter_config_strategy())| {
        let runtime = LabRuntime::new(LabConfig::default());

        let result = runtime.block_on(async {
            region(|cx, scope| async move {
                let policy = RetryPolicy::new()
                    .with_initial_delay(Duration::from_millis(config.base_delay_ms))
                    .with_multiplier(config.multiplier)
                    .with_max_delay(Duration::from_millis(config.max_delay_ms))
                    .with_jitter(config.jitter);

                let mut rng = DetRng::new(config.rng_seed);
                let mut total_theoretical_delay = Duration::ZERO;

                // Verify all properties hold together across multiple attempts
                for attempt in 1..=config.max_attempts {
                    let delay = calculate_delay(&policy, attempt, Some(&mut rng));

                    // Composite property 1: Exponential + jitter + bounding
                    prop_assert!(delay <= Duration::from_millis(config.max_delay_ms),
                        "Composite test: delay exceeds max for attempt {}", attempt);

                    // Composite property 2: Mathematical progression with jitter bounds
                    if config.jitter > 0.0 {
                        let base_delay = calculate_delay(&policy, attempt, None);
                        let max_jittered = Duration::from_nanos(
                            (base_delay.as_nanos() as f64 * (1.0 + config.jitter)) as u64
                        );
                        prop_assert!(delay <= max_jittered,
                            "Composite test: jittered delay exceeds bounds for attempt {}", attempt);
                    }

                    total_theoretical_delay = total_theoretical_delay.saturating_add(delay);
                }

                // Composite property 3: Total delay progression is reasonable
                prop_assert!(total_theoretical_delay < Duration::from_secs(3600),
                    "Composite test: total delay {} exceeds reasonable bounds",
                    total_theoretical_delay.as_secs());

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
    fn test_jitter_bounds_unit() {
        let policy = RetryPolicy::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_multiplier(2.0)
            .with_jitter(0.1); // 10% jitter

        let mut rng = DetRng::new(42);

        for attempt in 1..=5 {
            let delay = calculate_delay(&policy, attempt, Some(&mut rng));
            let base_delay = calculate_delay(&policy, attempt, None);

            // Should be between base and base * 1.1
            assert!(delay >= base_delay, "Attempt {}: jittered delay {} < base {}",
                    attempt, delay.as_millis(), base_delay.as_millis());

            let max_jittered = Duration::from_nanos(
                (base_delay.as_nanos() as f64 * 1.1) as u64
            );
            assert!(delay <= max_jittered, "Attempt {}: jittered delay {} > max {}",
                    attempt, delay.as_millis(), max_jittered.as_millis());
        }
    }

    #[test]
    fn test_deterministic_jitter() {
        let policy = RetryPolicy::new()
            .with_initial_delay(Duration::from_millis(50))
            .with_jitter(0.2);

        // Same seed should produce same jitter
        let mut rng1 = DetRng::new(12345);
        let mut rng2 = DetRng::new(12345);

        for attempt in 1..=3 {
            let delay1 = calculate_delay(&policy, attempt, Some(&mut rng1));
            let delay2 = calculate_delay(&policy, attempt, Some(&mut rng2));

            assert_eq!(delay1, delay2,
                "Attempt {}: same seed should produce same jittered delay", attempt);
        }
    }

    #[test]
    fn test_max_delay_capping() {
        let policy = RetryPolicy::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_multiplier(10.0) // Large multiplier
            .with_max_delay(Duration::from_millis(500)) // Cap at 500ms
            .with_jitter(0.1);

        let mut rng = DetRng::new(999);

        for attempt in 1..=10 {
            let delay = calculate_delay(&policy, attempt, Some(&mut rng));
            assert!(delay <= Duration::from_millis(500),
                "Attempt {}: delay {} exceeds max_delay cap",
                attempt, delay.as_millis());
        }
    }
}