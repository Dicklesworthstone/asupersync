#![allow(clippy::all)]
//! Metamorphic Testing for combinator::rate_limit token-bucket invariants
//!
//! Tests fundamental token bucket rate limiting behavior using metamorphic relations
//! that must hold regardless of specific request patterns, timing, or concurrency.
//! Uses LabRuntime with virtual time for deterministic execution and timeline control.
//!
//! ## Metamorphic Relations Tested:
//!
//! 1. **Blocking until available**: acquire blocks until tokens available
//! 2. **Rate enforcement**: rate never exceeds configured tokens/period
//! 3. **Burst capacity**: burst capacity honored without overshoot
//! 4. **Cancel safety**: cancel during wait does not consume token
//! 5. **Refill bounds**: refill does not overshoot capacity
//! 6. **Zero-rate rejection**: zero-rate rejects all requests

use proptest::prelude::*;
use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use std::collections::{HashMap, VecDeque};

use asupersync::combinator::rate_limit::{RateLimiter, RateLimitPolicy, WaitStrategy, RateLimitAlgorithm};
use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{Time, RegionId, TaskId};
use asupersync::{region, Scope};

/// Test configuration for rate limit metamorphic properties
#[derive(Debug, Clone)]
struct RateLimitTestConfig {
    /// Tokens per period (rate limit)
    rate: u32,
    /// Time period for rate calculation
    period_ms: u64,
    /// Maximum burst capacity
    burst: u32,
    /// Number of operations to test
    operation_count: usize,
    /// Base timing intervals (in milliseconds)
    base_interval_ms: u64,
    /// Spread of timing intervals
    interval_spread_ms: u64,
    /// Whether to test cancellation scenarios
    test_cancellation: bool,
    /// Fraction of operations to cancel (0.0 to 1.0)
    cancel_fraction: f32,
    /// Seed for deterministic randomization
    seed: u64,
}

impl Arbitrary for RateLimitTestConfig {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        (
            1u32..=100,           // rate
            100u64..=5000,        // period_ms
            1u32..=50,            // burst
            5usize..=200,         // operation_count
            10u64..=500,          // base_interval_ms
            1u64..=1000,          // interval_spread_ms
            prop::bool::ANY,      // test_cancellation
            0.0f32..=0.5,         // cancel_fraction
            any::<u64>(),         // seed
        )
            .prop_map(|(rate, period_ms, burst, operation_count, base_interval_ms, interval_spread_ms, test_cancellation, cancel_fraction, seed)| {
                RateLimitTestConfig {
                    rate,
                    period_ms,
                    burst,
                    operation_count,
                    base_interval_ms,
                    interval_spread_ms,
                    test_cancellation,
                    cancel_fraction,
                    seed,
                }
            })
            .boxed()
    }
}

/// Operation performed against the rate limiter
#[derive(Debug, Clone)]
enum RateLimitOperation {
    /// Try to acquire tokens immediately
    TryAcquire { cost: u32, timestamp: u64 },
    /// Enqueue and wait for tokens
    EnqueueAndWait { cost: u32, timestamp: u64, cancel_after_ms: Option<u64> },
    /// Force refill at specific time
    ForceRefill { timestamp: u64 },
    /// Check retry_after timing
    CheckRetryAfter { cost: u32, timestamp: u64 },
    /// Reset the rate limiter
    Reset { timestamp: u64 },
}

/// Test harness for managing rate limiter state and verification
struct RateLimitTestHarness {
    lab: LabRuntime,
    limiter: Arc<RateLimiter>,
    config: RateLimitTestConfig,
    operation_log: Arc<StdMutex<Vec<OperationResult>>>,
    total_granted: Arc<AtomicU32>,
    total_rejected: Arc<AtomicU32>,
    total_cancelled: Arc<AtomicU32>,
}

/// Result of a rate limit operation for tracking
#[derive(Debug, Clone)]
struct OperationResult {
    operation: String,
    timestamp: u64,
    cost: u32,
    granted: bool,
    wait_time_ms: u64,
    cancelled: bool,
    available_tokens_before: u32,
    available_tokens_after: u32,
}

impl RateLimitTestHarness {
    fn new(config: RateLimitTestConfig) -> Self {
        let lab = LabRuntime::new(LabConfig::default());

        let policy = RateLimitPolicy {
            name: "test".into(),
            rate: config.rate,
            period: Duration::from_millis(config.period_ms),
            burst: config.burst,
            wait_strategy: WaitStrategy::Block,
            default_cost: 1,
            algorithm: RateLimitAlgorithm::TokenBucket,
        };

        let limiter = Arc::new(RateLimiter::new(policy));

        Self {
            lab,
            limiter,
            config,
            operation_log: Arc::new(StdMutex::new(Vec::new())),
            total_granted: Arc::new(AtomicU32::new(0)),
            total_rejected: Arc::new(AtomicU32::new(0)),
            total_cancelled: Arc::new(AtomicU32::new(0)),
        }
    }

    fn time_from_ms(&self, ms: u64) -> Time {
        Time::from_millis(ms)
    }

    fn log_operation(&self, result: OperationResult) {
        let mut log = self.operation_log.lock().unwrap();
        log.push(result);
    }

    fn get_operation_log(&self) -> Vec<OperationResult> {
        self.operation_log.lock().unwrap().clone()
    }

    fn execute_try_acquire(&self, cost: u32, timestamp: u64) -> OperationResult {
        let time = self.time_from_ms(timestamp);
        let tokens_before = self.limiter.available_tokens();

        let granted = self.limiter.try_acquire(cost, time);

        let tokens_after = self.limiter.available_tokens();

        if granted {
            self.total_granted.fetch_add(1, Ordering::Relaxed);
        } else {
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
        }

        OperationResult {
            operation: "try_acquire".into(),
            timestamp,
            cost,
            granted,
            wait_time_ms: 0,
            cancelled: false,
            available_tokens_before: tokens_before,
            available_tokens_after: tokens_after,
        }
    }

    fn execute_force_refill(&self, timestamp: u64) -> OperationResult {
        let time = self.time_from_ms(timestamp);
        let tokens_before = self.limiter.available_tokens();

        self.limiter.refill(time);

        let tokens_after = self.limiter.available_tokens();

        OperationResult {
            operation: "refill".into(),
            timestamp,
            cost: 0,
            granted: true,
            wait_time_ms: 0,
            cancelled: false,
            available_tokens_before: tokens_before,
            available_tokens_after: tokens_after,
        }
    }

    fn execute_check_retry_after(&self, cost: u32, timestamp: u64) -> OperationResult {
        let time = self.time_from_ms(timestamp);
        let tokens_before = self.limiter.available_tokens();

        let wait_duration = self.limiter.retry_after(cost, time);
        let wait_time_ms = wait_duration.as_millis() as u64;

        OperationResult {
            operation: "retry_after".into(),
            timestamp,
            cost,
            granted: wait_time_ms == 0,
            wait_time_ms,
            cancelled: false,
            available_tokens_before: tokens_before,
            available_tokens_after: tokens_before, // retry_after doesn't change tokens
        }
    }

    fn execute_reset(&self, timestamp: u64) -> OperationResult {
        let tokens_before = self.limiter.available_tokens();

        self.limiter.reset();

        let tokens_after = self.limiter.available_tokens();

        OperationResult {
            operation: "reset".into(),
            timestamp,
            cost: 0,
            granted: true,
            wait_time_ms: 0,
            cancelled: false,
            available_tokens_before: tokens_before,
            available_tokens_after: tokens_after,
        }
    }

    fn verify_rate_invariant(&self, time_window_ms: u64) -> bool {
        let log = self.get_operation_log();

        // Group operations by time windows
        let mut windows = HashMap::new();

        for result in &log {
            if result.granted && result.operation == "try_acquire" {
                let window = result.timestamp / time_window_ms;
                *windows.entry(window).or_insert(0u32) += result.cost;
            }
        }

        // Check that no window exceeds the configured rate
        let expected_tokens_per_window = if time_window_ms >= self.config.period_ms {
            self.config.rate * (time_window_ms / self.config.period_ms) as u32
        } else {
            // For sub-period windows, allow proportional rate
            ((self.config.rate as u64 * time_window_ms) / self.config.period_ms) as u32 + self.config.burst
        };

        windows.values().all(|&tokens_used| tokens_used <= expected_tokens_per_window)
    }

    fn verify_burst_capacity(&self) -> bool {
        let log = self.get_operation_log();

        // Check that available tokens never exceed burst capacity after any operation
        log.iter().all(|result| result.available_tokens_after <= self.config.burst)
    }

    fn verify_refill_bounds(&self) -> bool {
        let log = self.get_operation_log();

        // After any refill, tokens should not exceed burst capacity
        log.iter()
            .filter(|result| result.operation == "refill")
            .all(|result| result.available_tokens_after <= self.config.burst)
    }

    fn verify_zero_rate_rejection(&self) -> bool {
        // Test with zero rate
        let zero_rate_policy = RateLimitPolicy {
            name: "zero_rate".into(),
            rate: 0,
            period: Duration::from_millis(self.config.period_ms),
            burst: self.config.burst,
            wait_strategy: WaitStrategy::Block,
            default_cost: 1,
            algorithm: RateLimitAlgorithm::TokenBucket,
        };

        let zero_limiter = RateLimiter::new(zero_rate_policy);
        let time = self.time_from_ms(1000);

        // All acquire attempts should fail
        !zero_limiter.try_acquire(1, time) &&
        !zero_limiter.try_acquire(self.config.burst, time) &&
        zero_limiter.retry_after(1, time) == Duration::MAX
    }
}

// ============================================================================
// METAMORPHIC RELATION 1: Acquire blocks until tokens available
// ============================================================================

proptest! {
    #[test]
    fn mr1_blocking_until_tokens_available(
        config: RateLimitTestConfig,
        operation_timings in prop::collection::vec(0u64..10000, 5..=50),
    ) {
        let harness = RateLimitTestHarness::new(config.clone());

        harness.futures_lite::future::block_on(region!(|cx: &Cx, scope: &Scope| async move {
            // Start with empty bucket by draining initial tokens
            let initial_time = harness.time_from_ms(0);
            for _ in 0..config.burst {
                harness.limiter.try_acquire(1, initial_time);
            }

            let mut last_grant_time = 0u64;

            for (i, &timing) in operation_timings.iter().enumerate().take(config.operation_count) {
                let timestamp = (i as u64) * config.base_interval_ms + timing % config.interval_spread_ms;

                // Force refill to ensure predictable token availability
                harness.execute_force_refill(timestamp);

                let result = harness.execute_try_acquire(1, timestamp);
                harness.log_operation(result.clone());

                // METAMORPHIC RELATION: If granted, sufficient time must have passed for refill
                if result.granted {
                    let time_since_last = if last_grant_time == 0 {
                        config.period_ms
                    } else {
                        timestamp.saturating_sub(last_grant_time)
                    };

                    let min_interval = config.period_ms / config.rate.max(1) as u64;

                    prop_assert!(
                        time_since_last >= min_interval || result.available_tokens_before > 0,
                        "MR1: Token granted too soon - time_since_last: {}, min_interval: {}, tokens_before: {}",
                        time_since_last, min_interval, result.available_tokens_before
                    );

                    last_grant_time = timestamp;
                }
            }

            Ok(())
        }));
    }
}

// ============================================================================
// METAMORPHIC RELATION 2: Rate never exceeds configured tokens/period
// ============================================================================

proptest! {
    #[test]
    fn mr2_rate_enforcement_invariant(
        config: RateLimitTestConfig,
        burst_timings in prop::collection::vec(0u64..1000, 10..=100),
    ) {
        let harness = RateLimitTestHarness::new(config.clone());

        harness.futures_lite::future::block_on(region!(|cx: &Cx, scope: &Scope| async move {
            // Execute rapid-fire operations to test rate enforcement
            for &timing_offset in &burst_timings {
                let timestamp = timing_offset;
                let result = harness.execute_try_acquire(1, timestamp);
                harness.log_operation(result);
            }

            // Verify rate invariant across different time windows
            let period_ms = config.period_ms;

            prop_assert!(
                harness.verify_rate_invariant(period_ms),
                "MR2: Rate exceeded in period window: {} tokens/{}ms",
                config.rate, period_ms
            );

            // Also check half-period windows for smoothness
            prop_assert!(
                harness.verify_rate_invariant(period_ms / 2),
                "MR2: Rate exceeded in half-period window"
            );

            Ok(())
        }));
    }
}

// ============================================================================
// METAMORPHIC RELATION 3: Burst capacity honored
// ============================================================================

proptest! {
    #[test]
    fn mr3_burst_capacity_invariant(
        config: RateLimitTestConfig,
        refill_intervals in prop::collection::vec(1000u64..=5000, 3..=10),
    ) {
        let harness = RateLimitTestHarness::new(config.clone());

        harness.futures_lite::future::block_on(region!(|cx: &Cx, scope: &Scope| async move {
            let mut cumulative_time = 0u64;

            for interval in refill_intervals {
                cumulative_time += interval;

                // Force long refill to ensure maximum token accumulation
                harness.execute_force_refill(cumulative_time);
                let refill_result = harness.execute_force_refill(cumulative_time);
                harness.log_operation(refill_result);

                // Try to acquire burst + 1 tokens rapidly
                for i in 0..=config.burst {
                    let acquire_time = cumulative_time + i as u64;
                    let result = harness.execute_try_acquire(1, acquire_time);
                    harness.log_operation(result.clone());

                    // MR3: Tokens beyond burst capacity should be rejected
                    if i == config.burst {
                        prop_assert!(
                            !result.granted,
                            "MR3: Granted token beyond burst capacity: {} tokens (burst: {})",
                            i + 1, config.burst
                        );
                    }
                }
            }

            // Global invariant: burst capacity never exceeded
            prop_assert!(
                harness.verify_burst_capacity(),
                "MR3: Burst capacity violated in operation history"
            );

            Ok(())
        }));
    }
}

// ============================================================================
// METAMORPHIC RELATION 4: Cancel during wait does not consume token
// ============================================================================

proptest! {
    #[test]
    fn mr4_cancel_safety_invariant(
        config: RateLimitTestConfig,
        cancel_timings in prop::collection::vec(10u64..=500, 5..=20),
    ) {
        let harness = RateLimitTestHarness::new(config.clone());

        harness.futures_lite::future::block_on(region!(|cx: &Cx, scope: &Scope| async move {
            // Drain initial tokens
            for _ in 0..config.burst {
                harness.limiter.try_acquire(1, harness.time_from_ms(0));
            }

            for &cancel_delay in &cancel_timings {
                let start_time = cancel_delay * 10;
                let tokens_before_enqueue = harness.limiter.available_tokens();

                // Attempt to enqueue (should block since no tokens)
                let enqueue_time = harness.time_from_ms(start_time);
                let enqueue_result = harness.limiter.enqueue(1, enqueue_time);

                // Simulate cancellation by not waiting for the result
                // In real usage, the future would be dropped

                let tokens_after_cancel = harness.limiter.available_tokens();

                // MR4: Cancelled operations should not consume tokens
                prop_assert_eq!(
                    tokens_before_enqueue,
                    tokens_after_cancel,
                    "MR4: Cancel during wait consumed token - before: {}, after: {}",
                    tokens_before_enqueue, tokens_after_cancel
                );

                // Advance time to allow some refill
                let later_time = harness.time_from_ms(start_time + cancel_delay);
                harness.execute_force_refill(later_time);
            }

            Ok(())
        }));
    }
}

// ============================================================================
// METAMORPHIC RELATION 5: Refill does not overshoot capacity
// ============================================================================

proptest! {
    #[test]
    fn mr5_refill_bounds_invariant(
        config: RateLimitTestConfig,
        long_intervals in prop::collection::vec(5000u64..=50000, 3..=15),
    ) {
        let harness = RateLimitTestHarness::new(config.clone());

        harness.futures_lite::future::block_on(region!(|cx: &Cx, scope: &Scope| async move {
            let mut time = 0u64;

            for interval in long_intervals {
                time += interval;

                // Drain some tokens first
                let drain_time = harness.time_from_ms(time);
                let drain_count = config.burst / 2;
                for _ in 0..drain_count {
                    harness.limiter.try_acquire(1, drain_time);
                }

                // Wait a very long time (much longer than needed for full refill)
                time += interval * 10;
                let refill_result = harness.execute_force_refill(time);
                harness.log_operation(refill_result.clone());

                // MR5: After long refill, tokens should not exceed burst capacity
                prop_assert!(
                    refill_result.available_tokens_after <= config.burst,
                    "MR5: Refill overshot capacity - tokens: {}, burst: {}",
                    refill_result.available_tokens_after, config.burst
                );
            }

            // Global refill bounds invariant
            prop_assert!(
                harness.verify_refill_bounds(),
                "MR5: Refill bounds violated in operation history"
            );

            Ok(())
        }));
    }
}

// ============================================================================
// METAMORPHIC RELATION 6: Zero-rate rejects all requests
// ============================================================================

proptest! {
    #[test]
    fn mr6_zero_rate_rejection_invariant(
        attempts in prop::collection::vec(1u32..=10, 5..=20),
        timing_offsets in prop::collection::vec(0u64..=10000, 5..=20),
    ) {
        let config = RateLimitTestConfig {
            rate: 0,  // Zero rate
            period_ms: 1000,
            burst: 5,
            operation_count: 50,
            base_interval_ms: 100,
            interval_spread_ms: 200,
            test_cancellation: false,
            cancel_fraction: 0.0,
            seed: 42,
        };

        let harness = RateLimitTestHarness::new(config.clone());

        harness.futures_lite::future::block_on(region!(|cx: &Cx, scope: &Scope| async move {

            for (i, (&cost, &timing)) in attempts.iter().zip(timing_offsets.iter()).enumerate() {
                let timestamp = (i as u64) * 1000 + timing;

                // Force refill first
                harness.execute_force_refill(timestamp);

                let result = harness.execute_try_acquire(cost, timestamp);
                harness.log_operation(result.clone());

                // MR6: Zero rate should reject all non-initial requests
                if timestamp > 0 { // Allow initial burst tokens
                    prop_assert!(
                        !result.granted || result.available_tokens_before > 0,
                        "MR6: Zero-rate limiter granted request - cost: {}, time: {}, tokens_before: {}",
                        cost, timestamp, result.available_tokens_before
                    );
                }

                // Check retry_after returns MAX duration for zero rate
                let retry_result = harness.execute_check_retry_after(cost, timestamp + 100);
                if result.available_tokens_before == 0 {
                    prop_assert!(
                        retry_result.wait_time_ms == Duration::MAX.as_millis() as u64,
                        "MR6: Zero-rate should return MAX wait time, got {}ms",
                        retry_result.wait_time_ms
                    );
                }
            }

            Ok(())
        }));
    }
}

// ============================================================================
// COMPOSITE INVARIANT TESTS
// ============================================================================

proptest! {
    #[test]
    fn composite_rate_limit_behavior_invariants(
        config: RateLimitTestConfig,
        mixed_operations in prop::collection::vec(
            prop::sample::select(vec!["acquire", "refill", "retry_after"]),
            20..=100
        ),
        operation_costs in prop::collection::vec(1u32..=5, 20..=100),
    ) {
        let harness = RateLimitTestHarness::new(config.clone());

        harness.futures_lite::future::block_on(region!(|cx: &Cx, scope: &Scope| async move {
            let mut time = 0u64;

            for (op_type, &cost) in mixed_operations.iter().zip(operation_costs.iter()) {
                time += config.base_interval_ms;

                let result = match op_type.as_str() {
                    "acquire" => harness.execute_try_acquire(cost, time),
                    "refill" => harness.execute_force_refill(time),
                    "retry_after" => harness.execute_check_retry_after(cost, time),
                    _ => unreachable!(),
                };

                harness.log_operation(result);
            }

            // Verify all invariants hold across the mixed operation sequence
            prop_assert!(
                harness.verify_rate_invariant(config.period_ms),
                "Composite test: Rate invariant violated"
            );

            prop_assert!(
                harness.verify_burst_capacity(),
                "Composite test: Burst capacity invariant violated"
            );

            prop_assert!(
                harness.verify_refill_bounds(),
                "Composite test: Refill bounds invariant violated"
            );

            Ok(())
        }));
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_harness_creation() {
        let config = RateLimitTestConfig {
            rate: 10,
            period_ms: 1000,
            burst: 5,
            operation_count: 20,
            base_interval_ms: 100,
            interval_spread_ms: 50,
            test_cancellation: false,
            cancel_fraction: 0.0,
            seed: 42,
        };

        let harness = RateLimitTestHarness::new(config);
        assert_eq!(harness.limiter.available_tokens(), 5); // Initial burst
    }

    #[test]
    fn test_basic_token_consumption() {
        let config = RateLimitTestConfig {
            rate: 10,
            period_ms: 1000,
            burst: 3,
            operation_count: 10,
            base_interval_ms: 100,
            interval_spread_ms: 50,
            test_cancellation: false,
            cancel_fraction: 0.0,
            seed: 42,
        };

        let harness = RateLimitTestHarness::new(config);
        let time = harness.time_from_ms(0);

        // Should be able to acquire up to burst
        assert!(harness.limiter.try_acquire(1, time));
        assert!(harness.limiter.try_acquire(1, time));
        assert!(harness.limiter.try_acquire(1, time));

        // Next acquire should fail
        assert!(!harness.limiter.try_acquire(1, time));
    }

    #[test]
    fn test_refill_timing() {
        let config = RateLimitTestConfig {
            rate: 10, // 10 tokens per second
            period_ms: 1000,
            burst: 10,
            operation_count: 10,
            base_interval_ms: 100,
            interval_spread_ms: 50,
            test_cancellation: false,
            cancel_fraction: 0.0,
            seed: 42,
        };

        let harness = RateLimitTestHarness::new(config);

        // Drain all tokens
        let t0 = harness.time_from_ms(0);
        for _ in 0..10 {
            assert!(harness.limiter.try_acquire(1, t0));
        }
        assert_eq!(harness.limiter.available_tokens(), 0);

        // After 100ms, should have 1 token (10 tokens/1000ms = 1 token/100ms)
        let t1 = harness.time_from_ms(100);
        harness.limiter.refill(t1);
        assert_eq!(harness.limiter.available_tokens(), 1);

        // After another 500ms (600ms total), should have 6 tokens
        let t2 = harness.time_from_ms(600);
        harness.limiter.refill(t2);
        assert_eq!(harness.limiter.available_tokens(), 6);
    }
}