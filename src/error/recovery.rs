//! Recovery strategies for handling transient errors.
//!
//! This module provides the `RecoveryStrategy` trait and common implementations
//! like `ExponentialBackoff` and `CircuitBreaker`.

use crate::error::{Error, Recoverability};
use crate::types::Time;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

/// Strategy for recovering from transient errors.
pub trait RecoveryStrategy: Send + Sync {
    /// Decide whether to retry after an error.
    fn should_retry(&self, error: &Error, attempt: u32) -> bool;

    /// Get delay before next retry.
    fn backoff_duration(&self, attempt: u32) -> Duration;

    /// Called when recovery succeeds.
    fn on_success(&self, attempts: u32);

    /// Called when recovery is abandoned.
    fn on_give_up(&self, error: &Error, attempts: u32);
}

/// Exponential backoff with jitter.
#[derive(Debug)]
pub struct ExponentialBackoff {
    initial: Duration,
    max: Duration,
    multiplier: f64,
    max_attempts: u32,
    /// Randomization factor (0.0 to 1.0).
    jitter: f64,
}

impl ExponentialBackoff {
    /// Creates a new exponential backoff strategy.
    #[inline]
    #[must_use]
    pub fn new(initial: Duration, max: Duration, multiplier: f64, max_attempts: u32) -> Self {
        Self {
            initial,
            max,
            multiplier,
            max_attempts,
            jitter: 0.1, // Default 10% jitter
        }
    }

    /// Sets the jitter factor.
    #[inline]
    #[must_use]
    pub fn with_jitter(mut self, jitter: f64) -> Self {
        self.jitter = if jitter.is_finite() {
            jitter.clamp(0.0, 1.0)
        } else {
            0.0
        };
        self
    }
}

impl RecoveryStrategy for ExponentialBackoff {
    fn should_retry(&self, error: &Error, attempt: u32) -> bool {
        if attempt >= self.max_attempts {
            return false;
        }
        error.recoverability() == Recoverability::Transient
    }

    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]
    fn backoff_duration(&self, attempt: u32) -> Duration {
        // Saturate the exponent so very large attempt counters cannot wrap the
        // `u32 -> i32` conversion and collapse the backoff schedule.
        let exponent = i32::try_from(attempt).unwrap_or(i32::MAX);
        let factor = self.multiplier.powi(exponent);
        let mut base_ms = (self.initial.as_millis() as f64 * factor) as u64;

        // Clamp to the configured max while avoiding u128 -> u64 truncation.
        let max_ms = self.max.as_millis().min(u128::from(u64::MAX)) as u64;
        if base_ms > max_ms {
            base_ms = max_ms;
        }

        // Apply simple pseudo-random jitter (deterministic for lab if we pass rng,
        // but here we use a simple hash of parameters to be stateless/deterministic enough)
        // In real prod, we'd use thread_rng.
        // For Phase 0, we'll just vary slightly based on attempt to avoid strict lockstep.
        let jitter_amount = (base_ms as f64 * self.jitter) as u64;

        let with_jitter = if jitter_amount == 0 {
            base_ms
        } else {
            // Simple deterministic variation
            let jitter_range = jitter_amount.saturating_mul(2).max(1);
            let variation = u64::from(attempt).wrapping_mul(31) % jitter_range;
            base_ms
                .saturating_sub(jitter_amount)
                .saturating_add(variation)
        };

        Duration::from_millis(with_jitter)
    }

    fn on_success(&self, _attempts: u32) {}

    fn on_give_up(&self, _error: &Error, _attempts: u32) {}
}

/// Circuit breaker states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitState {
    /// Normal operation; requests flow through.
    Closed = 0, // Normal operation
    /// Circuit is open; requests are rejected.
    Open = 1, // Failing, reject requests
    /// Half-open probing state.
    HalfOpen = 2, // Testing recovery
}

/// Circuit breaker for failing fast when a system is unhealthy.
#[derive(Debug)]
pub struct CircuitBreaker {
    failure_threshold: u32,
    recovery_timeout: Duration,
    state: AtomicU8,
    failures: AtomicU32,
    last_failure_time: AtomicU64, // nanos
    successes_needed: u32,
    consecutive_successes: AtomicU32,
}

impl CircuitBreaker {
    /// Creates a new circuit breaker.
    #[inline]
    #[must_use]
    pub fn new(failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            failure_threshold,
            recovery_timeout,
            state: AtomicU8::new(CircuitState::Closed as u8),
            failures: AtomicU32::new(0),
            last_failure_time: AtomicU64::new(0),
            successes_needed: 1, // Require 1 success to close
            consecutive_successes: AtomicU32::new(0),
        }
    }

    /// Checks if a request should be attempted.
    pub fn should_try(&self, now: Time) -> bool {
        match self.state() {
            CircuitState::Closed | CircuitState::HalfOpen => true,
            CircuitState::Open => {
                let last = Time::from_nanos(self.last_failure_time.load(Ordering::Relaxed));
                let timeout_nanos =
                    self.recovery_timeout.as_nanos().min(u128::from(u64::MAX)) as u64;
                if now >= last.saturating_add_nanos(timeout_nanos) {
                    // Try to transition to HalfOpen
                    if self.transition(CircuitState::Open, CircuitState::HalfOpen) {
                        self.consecutive_successes.store(0, Ordering::Relaxed);
                        return true;
                    }
                    // Lost race, check state again
                    self.state() == CircuitState::HalfOpen
                } else {
                    false
                }
            }
        }
    }

    /// Records a success.
    pub fn record_success(&self) {
        if self.state() == CircuitState::HalfOpen {
            let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
            if successes >= self.successes_needed {
                self.reset();
            }
        } else {
            self.failures.store(0, Ordering::Relaxed);
        }
    }

    /// Records a failure.
    pub fn record_failure(&self, now: Time) {
        self.last_failure_time
            .store(now.as_nanos(), Ordering::Relaxed);

        match self.state() {
            CircuitState::Closed => {
                let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
                if failures >= self.failure_threshold {
                    self.transition(CircuitState::Closed, CircuitState::Open);
                }
            }
            CircuitState::HalfOpen => {
                self.transition(CircuitState::HalfOpen, CircuitState::Open);
            }
            CircuitState::Open => {
                // Reset recovery timer
            }
        }
    }

    #[inline]
    fn state(&self) -> CircuitState {
        match self.state.load(Ordering::Acquire) {
            0 => CircuitState::Closed,
            2 => CircuitState::HalfOpen,
            _ => CircuitState::Open,
        }
    }

    #[inline]
    fn transition(&self, from: CircuitState, to: CircuitState) -> bool {
        self.state
            .compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn reset(&self) {
        // Use CAS instead of unconditional store to avoid overwriting a
        // concurrent HalfOpen→Open transition from record_failure.
        if self.transition(CircuitState::HalfOpen, CircuitState::Closed) {
            self.failures.store(0, Ordering::Relaxed);
            self.consecutive_successes.store(0, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
#[path = "recovery_inline_tests.rs"]
mod tests;
