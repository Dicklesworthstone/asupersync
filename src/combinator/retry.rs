//! Retry combinator with exponential backoff.
//!
//! The retry combinator wraps a fallible operation with configurable retry logic
//! including exponential backoff, jitter, and attempt limits.
//!
//! # Design Philosophy
//!
//! Retries must be:
//! 1. **Cancel-aware**: Respect incoming cancellation between attempts
//! 2. **Budget-aware**: Total retry budget bounds all attempts combined
//! 3. **Deterministic**: Same seed → same jitter in lab runtime
//! 4. **Configurable**: Policy captures retry strategy
//!
//! # Cancellation Handling
//!
//! - Check cancellation status before each attempt
//! - Check cancellation during sleep
//! - If cancelled: do NOT start another attempt, return Cancelled immediately
//! - Any in-flight attempt continues to checkpoint (cannot force-stop)
//!
//! # Budget Integration
//!
//! Total budget for retry operation:
//! ```text
//! retry_budget = Σ(attempt_budget[i] + sleep_budget[i])
//!              = max_attempts * per_attempt_budget + Σ(delays)
//! ```

use crate::cx::Cx;
use crate::time::Sleep;
use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use crate::types::{Outcome, Time};
use crate::util::det_rng::DetRng;
use core::fmt;
use parking_lot::Mutex;
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

/// Policy for retry behavior.
///
/// Configures how retries are performed, including backoff strategy,
/// jitter, and limits.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of attempts (including the first attempt).
    /// Must be at least 1.
    pub max_attempts: u32,
    /// Initial delay before the first retry (after first failure).
    pub initial_delay: Duration,
    /// Maximum delay between retries (caps exponential growth).
    pub max_delay: Duration,
    /// Multiplier for exponential backoff (typically 2.0).
    pub multiplier: f64,
    /// Jitter factor [0.0, 1.0] - random factor added to delay.
    /// A value of 0.1 means up to 10% jitter is added.
    pub jitter: f64,
}

impl RetryPolicy {
    /// Creates a new retry policy with default settings.
    ///
    /// Defaults:
    /// - 3 attempts
    /// - 100ms initial delay
    /// - 30s max delay
    /// - 2.0 multiplier
    /// - 0.1 jitter (10%)
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
            jitter: 0.1,
        }
    }

    /// Creates a policy with the specified number of attempts.
    #[inline]
    #[must_use]
    pub fn with_max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts.max(1);
        self
    }

    /// Sets the initial delay for the first retry.
    #[inline]
    #[must_use]
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Sets the maximum delay cap.
    #[inline]
    #[must_use]
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Sets the backoff multiplier.
    #[inline]
    #[must_use]
    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier.max(1.0);
        self
    }

    /// Sets the jitter factor (0.0 to 1.0).
    #[inline]
    #[must_use]
    pub fn with_jitter(mut self, jitter: f64) -> Self {
        self.jitter = jitter.clamp(0.0, 1.0);
        self
    }

    /// Creates a policy with no jitter (fully deterministic delays).
    #[inline]
    #[must_use]
    pub fn no_jitter(mut self) -> Self {
        self.jitter = 0.0;
        self
    }

    /// Creates a policy with fixed delays (no exponential backoff).
    #[inline]
    #[must_use]
    pub fn fixed_delay(delay: Duration, max_attempts: u32) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            initial_delay: delay,
            max_delay: delay,
            multiplier: 1.0,
            jitter: 0.0,
        }
    }

    /// Creates a policy for immediate retries (no delay).
    #[inline]
    #[must_use]
    pub fn immediate(max_attempts: u32) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            multiplier: 1.0,
            jitter: 0.0,
        }
    }

    /// Validates the policy returns Ok if valid, or an error message.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_attempts == 0 {
            return Err("max_attempts must be at least 1");
        }
        if self.multiplier < 1.0 {
            return Err("multiplier must be at least 1.0");
        }
        if !(0.0..=1.0).contains(&self.jitter) {
            return Err("jitter must be between 0.0 and 1.0");
        }
        Ok(())
    }
}

impl Default for RetryPolicy {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Calculates the delay for a given attempt number.
///
/// The delay follows exponential backoff with optional jitter:
/// ```text
/// base_delay = initial_delay * multiplier^(attempt - 1)
/// capped_delay = min(base_delay, max_delay)
/// final_delay = capped_delay * (1 + jitter_factor)
/// ```
///
/// # Arguments
/// * `policy` - The retry policy
/// * `attempt` - The attempt number (1-indexed, so attempt 1 = first retry)
/// * `rng` - Deterministic RNG for jitter (optional)
///
/// # Returns
/// The delay duration for this attempt.
#[must_use]
#[allow(
    clippy::cast_possible_wrap,  // exponent is bounded by practical max_attempts values
    clippy::cast_precision_loss, // acceptable for duration calculations in millisecond-second range
    clippy::cast_sign_loss,      // final_nanos is always positive after min() capping
)]
pub fn calculate_delay(policy: &RetryPolicy, attempt: u32, rng: Option<&mut DetRng>) -> Duration {
    if attempt == 0 {
        return Duration::ZERO;
    }

    // Calculate base delay with exponential backoff
    let exponent = attempt.saturating_sub(1);

    // Safely compute multiplier^exponent, avoiding overflow and non-finite results
    let multiplier_factor = if exponent == 0 {
        1.0
    } else if policy.multiplier <= 0.0 || !policy.multiplier.is_finite() {
        // Avoid invalid multipliers
        f64::INFINITY
    } else {
        // powi saturates to infinity (or to 0 for a multiplier below 1), so
        // no exponent needs special-casing. Forcing exponents above 60 to
        // infinity made a constant (multiplier 1.0) backoff jump to
        // max_delay at the 62nd attempt.
        let safe_exponent = i32::try_from(exponent).unwrap_or(i32::MAX);
        let factor = policy.multiplier.powi(safe_exponent);
        if !factor.is_finite() {
            f64::INFINITY
        } else {
            factor
        }
    };

    // Safely convert initial_delay to f64, preserving precision for reasonable values
    let initial_nanos_f64 = if policy.initial_delay.as_nanos() <= (1u64 << 53) as u128 {
        policy.initial_delay.as_nanos() as f64
    } else {
        // Use seconds conversion for very large durations to preserve precision
        policy.initial_delay.as_secs_f64() * 1_000_000_000.0
    };

    let base_nanos = if policy.initial_delay.is_zero() {
        // Zero stays zero at every attempt. Mapping an infinite factor to an
        // infinite delay made a zero initial delay jump to max_delay once
        // powi overflowed, at attempt 1025 for multiplier 2
        // (br-asupersync-e9gn8y).
        0.0
    } else if multiplier_factor.is_infinite() {
        f64::INFINITY
    } else {
        initial_nanos_f64 * multiplier_factor
    };

    // Cap at max_delay
    let max_nanos = policy.max_delay.as_nanos() as f64;
    let capped_nanos = base_nanos.min(max_nanos);

    // Apply jitter if enabled and RNG provided
    let final_nanos = if policy.jitter > 0.0 && capped_nanos.is_finite() {
        rng.map_or(capped_nanos, |rng| {
            // Generate deterministic jitter factor in [0, jitter] with precision-safe division
            let rand_val = rng.next_u64();
            // Use high-precision division avoiding direct u64::MAX cast
            let normalized = if rand_val == u64::MAX {
                1.0
            } else {
                rand_val as f64 / (u64::MAX as f64)
            };
            let jitter_factor = normalized * policy.jitter;

            let result = capped_nanos * (1.0 + jitter_factor);
            if result.is_finite() {
                result
            } else {
                capped_nanos
            }
        })
    } else {
        capped_nanos
    };

    Duration::from_nanos(clamp_nanos_f64(final_nanos))
}

#[allow(
    clippy::cast_precision_loss, // clamp boundary requires f64 comparison
    clippy::cast_sign_loss,      // negative/NaN handled above before cast
)]
fn clamp_nanos_f64(nanos: f64) -> u64 {
    if !nanos.is_finite() || nanos <= 0.0 {
        return 0;
    }
    if nanos >= u64::MAX as f64 {
        return u64::MAX;
    }
    nanos as u64
}

/// Calculates the delay and returns the deadline.
///
/// Convenience function that adds the delay to the current time.
#[must_use]
pub fn calculate_deadline(
    policy: &RetryPolicy,
    attempt: u32,
    now: Time,
    rng: Option<&mut DetRng>,
) -> Time {
    let delay = calculate_delay(policy, attempt, rng);
    let nanos = delay.as_nanos();
    let safe_nanos = if nanos <= u128::from(u64::MAX) {
        nanos as u64
    } else {
        u64::MAX
    };
    now.saturating_add_nanos(safe_nanos)
}

/// Calculates the total worst-case budget needed for all retries.
///
/// This is the sum of all delays across max_attempts - 1 retries.
/// Note: The first attempt has no delay before it.
#[must_use]
#[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
pub fn total_delay_budget(policy: &RetryPolicy) -> Duration {
    let mut total = Duration::ZERO;
    for attempt in 1..policy.max_attempts {
        // Use None for RNG to get base delays (upper bound without jitter)
        let delay = calculate_delay(policy, attempt, None);
        // With jitter, actual delay could be up to (1 + jitter) * base
        let max_delay_nanos = clamp_nanos_f64(delay.as_nanos() as f64 * (1.0 + policy.jitter));
        let additional = Duration::from_nanos(max_delay_nanos);

        total = total.saturating_add(additional);

        if delay == policy.max_delay || max_delay_nanos == u64::MAX || total == Duration::MAX {
            // remaining loop iterations: the loop runs 1..max_attempts, so at
            // position `attempt` there are (max_attempts - 1 - attempt) left.
            let remaining_iters = (policy.max_attempts - 1).saturating_sub(attempt);
            if let Some(rest) = additional.checked_mul(remaining_iters) {
                total = total.saturating_add(rest);
            } else {
                total = Duration::MAX;
            }
            break;
        }
    }
    total
}

/// Error type for retry operations.
///
/// Contains the final error after all attempts exhausted, plus metadata
/// about the retry history.
#[derive(Debug, Clone)]
pub struct RetryError<E> {
    /// The error from the final attempt.
    pub final_error: E,
    /// Number of attempts made.
    pub attempts: u32,
    /// Total time spent retrying (not including operation time).
    pub total_delay: Duration,
}

impl<E> RetryError<E> {
    /// Creates a new retry error.
    #[must_use]
    pub const fn new(final_error: E, attempts: u32, total_delay: Duration) -> Self {
        Self {
            final_error,
            attempts,
            total_delay,
        }
    }

    /// Maps the error type.
    pub fn map<F, G: FnOnce(E) -> F>(self, f: G) -> RetryError<F> {
        RetryError {
            final_error: f(self.final_error),
            attempts: self.attempts,
            total_delay: self.total_delay,
        }
    }
}

impl<E: fmt::Display> fmt::Display for RetryError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "retry failed after {} attempts ({:?} total delay): {}",
            self.attempts, self.total_delay, self.final_error
        )
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for RetryError<E> {}

// ─── Token Bucket for Retry Rate Limiting ──────────────────────────────────

/// Token bucket for rate-limiting retry attempts.
///
/// Prevents retry storms by limiting the rate at which retries can be attempted.
/// Uses a classic token bucket algorithm where tokens refill at a steady rate
/// and operations consume tokens. To have [`retry`] loops draw on one, wrap it
/// in a [`RetryBudget`] and pass that to [`Retry::with_budget`].
#[derive(Debug, Clone)]
pub struct RetryTokenBucket {
    /// Maximum number of tokens the bucket can hold.
    capacity: u32,
    /// Current number of available tokens.
    tokens: f64,
    /// Rate at which tokens are refilled (tokens per second).
    refill_rate: f64,
    /// Last time the bucket was refilled.
    last_refill: Time,
}

impl RetryTokenBucket {
    /// Creates a new token bucket with the specified capacity and refill rate.
    ///
    /// # Arguments
    /// * `capacity` - Maximum tokens the bucket can hold
    /// * `refill_rate` - Tokens added per second
    /// * `now` - Current time
    #[must_use]
    pub fn new(capacity: u32, refill_rate: f64, now: Time) -> Self {
        Self {
            capacity,
            tokens: capacity as f64, // Start with full bucket
            refill_rate,
            last_refill: now,
        }
    }

    /// Attempts to consume tokens from the bucket.
    ///
    /// Returns `true` if the tokens were successfully consumed, `false` otherwise.
    /// The bucket is automatically refilled based on time elapsed since last update.
    pub fn try_consume(&mut self, cost: u32, now: Time) -> bool {
        self.refill(now);

        if self.tokens >= cost as f64 {
            self.tokens -= cost as f64;
            true
        } else {
            false
        }
    }

    /// Calculates when the next token will be available.
    ///
    /// Returns the duration to wait before enough tokens are available.
    #[must_use]
    pub fn time_to_tokens(&self, cost: u32) -> Duration {
        if self.tokens >= cost as f64 {
            return Duration::ZERO;
        }

        // A non-positive (or non-finite) refill rate means tokens never
        // accrue: the wait is effectively unbounded. Only the positive,
        // finite-result branch computes a duration; everything else (rate
        // <= 0, NaN, or a non-finite quotient) falls through to
        // `Duration::MAX`. This avoids `Duration::from_secs_f64` panicking on
        // `inf`/negative input, mirroring `RateLimiter::time_until_available`
        // for `rate == 0`. (`NaN > 0.0` is `false`, so NaN falls through too.)
        if self.refill_rate > 0.0 {
            let tokens_needed = cost as f64 - self.tokens;
            // A finite quotient can still exceed Duration's range (a refill rate
            // of 1e-30 gives 1e30 s), where from_secs_f64 panics.
            if let Ok(wait) = Duration::try_from_secs_f64(tokens_needed / self.refill_rate) {
                return wait;
            }
        }
        Duration::MAX
    }

    /// Refills the bucket based on time elapsed.
    fn refill(&mut self, now: Time) {
        // A time before the last refill adds nothing and must not move the
        // mark back: the same interval would then be credited twice.
        if now <= self.last_refill {
            return;
        }
        let elapsed_nanos = now.duration_since(self.last_refill);
        let elapsed_secs = elapsed_nanos as f64 / 1_000_000_000.0;

        let tokens_to_add = elapsed_secs * self.refill_rate;
        self.tokens = (self.tokens + tokens_to_add).min(self.capacity as f64);
        self.last_refill = now;
    }

    /// Returns one token taken for a retry that never started, up to capacity.
    fn refund_one(&mut self) {
        self.tokens = (self.tokens + 1.0).min(f64::from(self.capacity));
    }

    /// Returns the current number of available tokens.
    #[must_use]
    pub fn available_tokens(&self) -> u32 {
        self.tokens.floor() as u32
    }

    /// Returns the bucket capacity.
    #[must_use]
    pub const fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Returns the refill rate (tokens per second).
    #[must_use]
    pub const fn refill_rate(&self) -> f64 {
        self.refill_rate
    }
}

/// Policy that includes token bucket rate limiting for retries.
#[derive(Debug, Clone)]
pub struct RateLimitedRetryPolicy {
    /// Base retry policy (backoff, attempts, etc.).
    pub retry_policy: RetryPolicy,
    /// Optional token bucket for rate limiting.
    pub token_bucket: Option<(u32, f64)>, // (capacity, refill_rate)
}

impl RateLimitedRetryPolicy {
    /// Creates a new rate-limited retry policy.
    #[must_use]
    pub fn new(retry_policy: RetryPolicy) -> Self {
        Self {
            retry_policy,
            token_bucket: None,
        }
    }

    /// Adds token bucket rate limiting.
    ///
    /// # Arguments
    /// * `capacity` - Maximum tokens in bucket
    /// * `refill_rate` - Tokens added per second
    #[must_use]
    pub fn with_token_bucket(mut self, capacity: u32, refill_rate: f64) -> Self {
        self.token_bucket = Some((capacity, refill_rate));
        self
    }

    /// Returns a full [`RetryBudget`] built from this policy's token bucket,
    /// or `None` if it has none.
    ///
    /// Build it once, at `now`, and give clones to every retry loop it should
    /// bound, with [`Retry::with_budget`] and `self.retry_policy` as the policy.
    #[must_use]
    pub fn budget(&self, now: Time) -> Option<RetryBudget> {
        self.token_bucket.map(|(capacity, refill_rate)| {
            RetryBudget::new(RetryTokenBucket::new(capacity, refill_rate, now))
        })
    }
}

impl Default for RateLimitedRetryPolicy {
    fn default() -> Self {
        Self::new(RetryPolicy::default())
    }
}

/// A retry budget shared by many retry loops.
///
/// A [`Retry`] loop given a budget with [`Retry::with_budget`] takes one token
/// from it before each retry. A first attempt takes none. When no token is
/// left, the loop does not retry: it fails at once with the error it just got,
/// as if its attempts had run out. Give clones of one budget to every caller of
/// a dependency, and their retries together stay within the bucket's rate, so
/// an outage of that dependency does not turn into a retry storm.
///
/// Clones share the same bucket. The bucket refills on the clock the loops
/// read: the runtime's timer when there is one, the wall clock otherwise. Build
/// its [`RetryTokenBucket`] with a `now` from that clock.
///
/// A token is spent when the retry it was taken for starts. A loop cancelled
/// or dropped before then (during the backoff sleep, or while yielding after a
/// batch of ready attempts) returns the token.
#[derive(Debug, Clone)]
pub struct RetryBudget {
    bucket: Arc<Mutex<RetryTokenBucket>>,
}

impl RetryBudget {
    /// Creates a budget that draws on `bucket`.
    #[must_use]
    pub fn new(bucket: RetryTokenBucket) -> Self {
        Self {
            bucket: Arc::new(Mutex::new(bucket)),
        }
    }

    /// Takes one retry token at `now`. Returns `false` if none is available.
    pub fn try_acquire(&self, now: Time) -> bool {
        self.bucket.lock().try_consume(1, now)
    }

    /// Returns the number of whole tokens left, as of the last refill.
    #[must_use]
    pub fn available(&self) -> u32 {
        self.bucket.lock().available_tokens()
    }

    fn refund(&self) {
        self.bucket.lock().refund_one();
    }
}

/// A budget token taken for a retry that has not started. Dropping it unspent
/// returns the token, so cancellation or a dropped loop does not shrink the
/// budget other callers share.
struct AdmittedRetryToken(Option<RetryBudget>);

impl AdmittedRetryToken {
    fn spend(mut self) {
        self.0 = None;
    }
}

impl Drop for AdmittedRetryToken {
    fn drop(&mut self) {
        if let Some(budget) = self.0.take() {
            budget.refund();
        }
    }
}

/// Result type for retry operations, including cancellation.
#[derive(Debug, Clone)]
pub enum RetryResult<T, E> {
    /// Operation succeeded (possibly after retries).
    Ok(T),
    /// All attempts failed.
    Failed(RetryError<E>),
    /// Operation was cancelled.
    Cancelled(CancelReason),
    /// Operation panicked.
    Panicked(PanicPayload),
}

impl<T, E> RetryResult<T, E> {
    /// Returns true if the operation succeeded.
    #[inline]
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }

    /// Returns true if all attempts failed.
    #[inline]
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }

    /// Returns true if the operation was cancelled.
    #[inline]
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }

    /// Returns true if the operation panicked.
    #[inline]
    #[must_use]
    pub const fn is_panicked(&self) -> bool {
        matches!(self, Self::Panicked(_))
    }

    /// Converts to an Outcome.
    #[inline]
    pub fn into_outcome(self) -> Outcome<T, RetryError<E>> {
        match self {
            Self::Ok(v) => Outcome::Ok(v),
            Self::Failed(e) => Outcome::Err(e),
            Self::Cancelled(r) => Outcome::Cancelled(r),
            Self::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Converts to a standard Result.
    pub fn into_result(self) -> Result<T, RetryFailure<E>> {
        match self {
            Self::Ok(v) => Ok(v),
            Self::Failed(e) => Err(RetryFailure::Exhausted(e)),
            Self::Cancelled(r) => Err(RetryFailure::Cancelled(r)),
            Self::Panicked(p) => Err(RetryFailure::Panicked(p)),
        }
    }
}

/// Comprehensive failure type for retry operations.
#[derive(Debug, Clone)]
pub enum RetryFailure<E> {
    /// All retry attempts exhausted.
    Exhausted(RetryError<E>),
    /// Operation was cancelled.
    Cancelled(CancelReason),
    /// Operation panicked.
    Panicked(PanicPayload),
}

impl<E: fmt::Display> fmt::Display for RetryFailure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted(e) => write!(f, "{e}"),
            Self::Cancelled(r) => write!(f, "retry cancelled: {r}"),
            Self::Panicked(p) => write!(f, "retry panicked: {p}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for RetryFailure<E> {}

/// Tracks the state of a retry operation in progress.
#[derive(Debug, Clone)]
pub struct RetryState {
    /// Current attempt number (1-indexed).
    pub attempt: u32,
    /// Total delay accumulated so far.
    pub total_delay: Duration,
    /// Whether the retry was cancelled.
    pub cancelled: bool,
    /// The policy being used.
    policy: RetryPolicy,
}

impl RetryState {
    /// Creates a new retry state with the given policy.
    #[must_use]
    pub fn new(mut policy: RetryPolicy) -> Self {
        policy.max_attempts = policy.max_attempts.max(1);
        Self {
            attempt: 0,
            total_delay: Duration::ZERO,
            cancelled: false,
            policy,
        }
    }

    /// Returns true if more attempts are available.
    #[inline]
    #[must_use]
    pub fn has_attempts_remaining(&self) -> bool {
        !self.cancelled && self.attempt < self.policy.max_attempts
    }

    /// Returns the number of attempts remaining.
    #[inline]
    #[must_use]
    pub fn attempts_remaining(&self) -> u32 {
        if self.cancelled {
            0
        } else {
            self.policy.max_attempts.saturating_sub(self.attempt)
        }
    }

    /// Advances to the next attempt and returns the delay to wait.
    ///
    /// Returns `None` if no more attempts are available.
    pub fn next_attempt(&mut self, rng: Option<&mut DetRng>) -> Option<Duration> {
        if !self.has_attempts_remaining() {
            return None;
        }

        self.attempt += 1;

        // First attempt has no delay
        if self.attempt == 1 {
            return Some(Duration::ZERO);
        }

        // Calculate delay for retry
        let delay = calculate_delay(&self.policy, self.attempt - 1, rng);
        self.total_delay = self.total_delay.saturating_add(delay);
        Some(delay)
    }

    /// Marks the retry as cancelled.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Creates a RetryError from the current state and final error.
    #[must_use]
    pub fn into_error<E>(self, final_error: E) -> RetryError<E> {
        RetryError::new(final_error, self.attempt, self.total_delay)
    }

    /// Returns the policy being used.
    #[inline]
    #[must_use]
    pub const fn policy(&self) -> &RetryPolicy {
        &self.policy
    }
}

/// Constructs a `RetryResult` from an outcome and retry state.
///
/// This function is used to map the outcome of a single attempt into
/// the appropriate retry result, taking into account whether more
/// attempts are available.
///
/// # Arguments
/// * `outcome` - The outcome from the most recent attempt
/// * `state` - The current retry state
/// * `is_final` - Whether this is the final attempt (no more retries available)
pub fn make_retry_result<T, E>(
    outcome: Outcome<T, E>,
    state: &RetryState,
    is_final: bool,
) -> Option<RetryResult<T, E>> {
    match outcome {
        Outcome::Ok(v) => Some(RetryResult::Ok(v)),
        Outcome::Err(e) => {
            if is_final {
                Some(RetryResult::Failed(RetryError::new(
                    e,
                    state.attempt,
                    state.total_delay,
                )))
            } else {
                // Not final, should retry
                None
            }
        }
        Outcome::Cancelled(r) => Some(RetryResult::Cancelled(r)),
        Outcome::Panicked(p) => Some(RetryResult::Panicked(p)),
    }
}

/// Determines if an error should be retried based on a predicate.
///
/// This allows selective retry based on error type (e.g., only retry
/// transient errors, not permanent failures).
pub trait RetryPredicate<E> {
    /// Returns true if the error should trigger a retry.
    fn should_retry(&self, error: &E, attempt: u32) -> bool;
}

/// Always retry on any error.
#[derive(Debug, Clone, Copy, Default)]
pub struct AlwaysRetry;

impl<E> RetryPredicate<E> for AlwaysRetry {
    fn should_retry(&self, _error: &E, _attempt: u32) -> bool {
        true
    }
}

/// Never retry (effectively max_attempts = 1).
#[derive(Debug, Clone, Copy, Default)]
pub struct NeverRetry;

impl<E> RetryPredicate<E> for NeverRetry {
    fn should_retry(&self, _error: &E, _attempt: u32) -> bool {
        false
    }
}

/// Retry based on a closure.
#[derive(Debug, Clone, Copy)]
pub struct RetryIf<F>(pub F);

impl<E, F: Fn(&E, u32) -> bool> RetryPredicate<E> for RetryIf<F> {
    fn should_retry(&self, error: &E, attempt: u32) -> bool {
        (self.0)(error, attempt)
    }
}

/// Internal state machine for the retry future.
#[pin_project(project = RetryInnerProj)]
enum RetryInner<F> {
    /// No operation in progress, ready to start next attempt.
    Idle,
    /// Polling the inner future.
    Polling(#[pin] F),
    /// Sleeping before the next attempt.
    Sleeping(#[pin] Sleep),
    /// Finished executing.
    Completed,
}

/// A future that executes a retry loop.
///
/// This struct is created by the [`retry`] function.
#[pin_project]
pub struct Retry<F, Fut, P, Pred> {
    factory: F,
    policy: P,
    predicate: Pred,
    state: RetryState,
    budget: Option<RetryBudget>,
    admitted: Option<AdmittedRetryToken>,
    #[pin]
    inner: RetryInner<Fut>,
}

impl<F, Fut, P, Pred> Retry<F, Fut, P, Pred>
where
    P: Clone + Into<RetryPolicy>,
{
    fn new(factory: F, policy: P, predicate: Pred) -> Self {
        let policy_val = policy.clone().into();
        Self {
            factory,
            policy,
            predicate,
            state: RetryState::new(policy_val),
            budget: None,
            admitted: None,
            inner: RetryInner::Idle,
        }
    }

    /// Makes each retry of this loop take a token from `budget` first.
    ///
    /// When the budget has no token, the loop fails with the error of the
    /// attempt that just failed instead of retrying. See [`RetryBudget`].
    #[must_use]
    pub fn with_budget(mut self, budget: RetryBudget) -> Self {
        self.budget = Some(budget);
        self
    }
}

/// The time on the clock a retry loop sleeps on: the current runtime's timer
/// when it has one, the wall clock otherwise.
fn retry_clock_now() -> Time {
    Cx::current().map_or_else(crate::time::wall_now, |current| {
        current
            .timer_driver()
            .map_or_else(crate::time::wall_now, |driver| driver.now())
    })
}

// Checkpoints observe cancellation but do not yield to the executor. Bound
// synchronous retries as well as delayed ones, so an immediately-ready failure
// cannot monopolize a worker for the policy's entire attempt budget. The bound
// assumes each factory, predicate, poll, destructor, and waker callback returns.
const MAX_READY_ATTEMPTS_PER_POLL: u32 = 64;

#[cfg(test)]
mod cooperative_tests;

mod poll;

/// Creates a retry future.
///
/// # Arguments
/// * `policy` - Retry policy (max attempts, delay, jitter).
/// * `predicate` - Logic to decide if an error is retriable.
/// * `factory` - Closure that produces the future to retry.
pub fn retry<F, Fut, P, Pred>(policy: P, predicate: Pred, factory: F) -> Retry<F, Fut, P, Pred>
where
    F: FnMut() -> Fut,
    P: Into<RetryPolicy> + Clone,
{
    Retry::new(factory, policy, predicate)
}

/// Retries an operation with configurable backoff.
///
/// # Semantics
///
/// ```ignore
/// let result = retry!(
///     attempts: 3,
///     backoff: exponential(100ms, 2.0),
///     || operation()
/// ).await;
/// ```
///
/// - Retries up to `max_attempts` times
/// - Waits `delay` between attempts (optionally with exponential backoff)
/// - Returns first success, or last error after exhausting retries
/// - Respects cancellation during both operation and delay
#[macro_export]
macro_rules! retry {
    // Simple syntax: retry!(max_attempts, || operation())
    ($max:expr, $factory:expr) => {
        $crate::combinator::retry::retry(
            $crate::combinator::retry::RetryPolicy::new().with_max_attempts($max),
            $crate::combinator::retry::AlwaysRetry,
            $factory,
        )
    };

    // With predicate: retry!(max_attempts, predicate, || operation())
    ($max:expr, $predicate:expr, $factory:expr) => {
        $crate::combinator::retry::retry(
            $crate::combinator::retry::RetryPolicy::new().with_max_attempts($max),
            $predicate,
            $factory,
        )
    };
}

#[cfg(test)]
#[path = "retry_inline_tests.rs"]
mod tests;
