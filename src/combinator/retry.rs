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
use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
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
    let exponent = attempt.saturating_sub(1).min(i32::MAX as u32);
    let multiplier_factor = policy.multiplier.powi(exponent as i32);
    let base_nanos = policy.initial_delay.as_nanos() as f64 * multiplier_factor;

    // Cap at max_delay
    let max_nanos = policy.max_delay.as_nanos() as f64;
    let capped_nanos = base_nanos.min(max_nanos);

    // Apply jitter if enabled and RNG provided
    let final_nanos = if policy.jitter > 0.0 {
        rng.map_or(capped_nanos, |rng| {
            // Generate deterministic jitter factor in [0, jitter]
            let jitter_factor = (rng.next_u64() as f64 / u64::MAX as f64) * policy.jitter;
            capped_nanos * (1.0 + jitter_factor)
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
    let nanos = if nanos > u128::from(u64::MAX) {
        u64::MAX
    } else {
        nanos as u64
    };
    now.saturating_add_nanos(nanos)
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

        if delay == policy.max_delay || total == Duration::MAX {
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
/// and operations consume tokens.
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

        let tokens_needed = cost as f64 - self.tokens;
        let time_needed_secs = tokens_needed / self.refill_rate;
        Duration::from_secs_f64(time_needed_secs)
    }

    /// Refills the bucket based on time elapsed.
    fn refill(&mut self, now: Time) {
        let elapsed_nanos = now.duration_since(self.last_refill);
        let elapsed_secs = elapsed_nanos as f64 / 1_000_000_000.0;

        let tokens_to_add = elapsed_secs * self.refill_rate;
        self.tokens = (self.tokens + tokens_to_add).min(self.capacity as f64);
        self.last_refill = now;
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
}

impl Default for RateLimitedRetryPolicy {
    fn default() -> Self {
        Self::new(RetryPolicy::default())
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
            inner: RetryInner::Idle,
        }
    }
}

impl<F, Fut, P, Pred, T, E> Future for Retry<F, Fut, P, Pred>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Outcome<T, E>>,
    P: Clone + Into<RetryPolicy>,
    Pred: RetryPredicate<E>,
{
    type Output = RetryResult<T, E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            // Check cancellation from the context
            // WARNING: We must NOT force-drop the inner future if we are in Polling state,
            // because asupersync requires futures to be drained to Outcome::Cancelled.
            let cancel_reason = Cx::current().and_then(|c| {
                if c.checkpoint().is_err() {
                    Some(c.cancel_reason().unwrap_or_default())
                } else {
                    None
                }
            });

            let mut this = self.as_mut().project();

            match this.inner.as_mut().project() {
                RetryInnerProj::Completed => {
                    return Poll::Ready(RetryResult::Cancelled(CancelReason::user(
                        "polled after completion",
                    )));
                }
                RetryInnerProj::Idle => {
                    if let Some(r) = cancel_reason {
                        this.inner.set(RetryInner::Completed);
                        return Poll::Ready(RetryResult::Cancelled(r));
                    }

                    // Start next attempt or sleep
                    // Use Cx entropy if available
                    let mut rng = Cx::current().map(|c| DetRng::new(c.random_u64()));

                    if let Some(delay) = this.state.next_attempt(rng.as_mut()) {
                        if delay == Duration::ZERO {
                            // Start immediately
                            let fut = (this.factory)();
                            this.inner.set(RetryInner::Polling(fut));
                        } else {
                            // Sleep before starting
                            // Cx::current() will be used by Sleep internally
                            // We need to construct Sleep with a relative duration from "now"
                            // Sleep::after handles getting the time source correctly
                            let now = Cx::current().map_or_else(crate::time::wall_now, |current| {
                                current
                                    .timer_driver()
                                    .map_or_else(crate::time::wall_now, |driver| driver.now())
                            });

                            let sleep = Sleep::after(now, delay);
                            this.inner.set(RetryInner::Sleeping(sleep));
                        }
                    } else {
                        // This case is unreachable because we only transition to Idle
                        // if has_attempts_remaining() is true, or initially (attempt=0)
                        // where max_attempts >= 1.
                        unreachable!(
                            "Retry logic invariant violated: Idle state with no remaining attempts"
                        );
                    }
                }
                RetryInnerProj::Sleeping(sleep) => {
                    if let Some(r) = cancel_reason {
                        this.inner.set(RetryInner::Completed);
                        return Poll::Ready(RetryResult::Cancelled(r));
                    }
                    match sleep.poll(cx) {
                        Poll::Ready(()) => {
                            // Sleep done, start factory
                            let fut = (this.factory)();
                            this.inner.set(RetryInner::Polling(fut));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                RetryInnerProj::Polling(fut) => {
                    match fut.poll(cx) {
                        Poll::Ready(outcome) => {
                            match outcome {
                                Outcome::Ok(val) => {
                                    this.inner.set(RetryInner::Completed);
                                    return Poll::Ready(RetryResult::Ok(val));
                                }
                                Outcome::Err(e) => {
                                    let attempt = this.state.attempt;
                                    // Check predicate
                                    if this.predicate.should_retry(&e, attempt)
                                        && this.state.has_attempts_remaining()
                                    {
                                        // Retry
                                        this.inner.set(RetryInner::Idle);
                                        // Loop will handle Idle -> Sleeping/Polling
                                    } else {
                                        // Final failure
                                        this.inner.set(RetryInner::Completed);
                                        return Poll::Ready(RetryResult::Failed(
                                            this.state.clone().into_error(e),
                                        ));
                                    }
                                }
                                Outcome::Cancelled(r) => {
                                    this.inner.set(RetryInner::Completed);
                                    return Poll::Ready(RetryResult::Cancelled(r));
                                }
                                Outcome::Panicked(p) => {
                                    this.inner.set(RetryInner::Completed);
                                    return Poll::Ready(RetryResult::Panicked(p));
                                }
                            }
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

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
mod tests {
    use super::*;

    #[test]
    fn policy_defaults() {
        let policy = RetryPolicy::new();
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(policy.initial_delay, Duration::from_millis(100));
        assert_eq!(policy.max_delay, Duration::from_secs(30));
        assert!((policy.multiplier - 2.0).abs() < f64::EPSILON);
        assert!((policy.jitter - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn policy_builder() {
        let policy = RetryPolicy::new()
            .with_max_attempts(5)
            .with_initial_delay(Duration::from_millis(50))
            .with_max_delay(Duration::from_secs(10))
            .with_multiplier(3.0)
            .with_jitter(0.2);

        assert_eq!(policy.max_attempts, 5);
        assert_eq!(policy.initial_delay, Duration::from_millis(50));
        assert_eq!(policy.max_delay, Duration::from_secs(10));
        assert!((policy.multiplier - 3.0).abs() < f64::EPSILON);
        assert!((policy.jitter - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn policy_fixed_delay() {
        let policy = RetryPolicy::fixed_delay(Duration::from_millis(100), 3);
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(policy.initial_delay, Duration::from_millis(100));
        assert_eq!(policy.max_delay, Duration::from_millis(100));
        assert!((policy.multiplier - 1.0).abs() < f64::EPSILON);
        assert!((policy.jitter - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn policy_immediate() {
        let policy = RetryPolicy::immediate(5);
        assert_eq!(policy.max_attempts, 5);
        assert_eq!(policy.initial_delay, Duration::ZERO);
        assert_eq!(policy.max_delay, Duration::ZERO);
    }

    #[test]
    fn policy_validation() {
        let valid = RetryPolicy::new();
        assert!(valid.validate().is_ok());

        let mut invalid = RetryPolicy::new();
        invalid.max_attempts = 0;
        assert!(invalid.validate().is_err());

        invalid = RetryPolicy::new();
        invalid.multiplier = 0.5;
        assert!(invalid.validate().is_err());

        invalid = RetryPolicy::new();
        invalid.jitter = 1.5;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn calculate_delay_zero_attempt() {
        let policy = RetryPolicy::new();
        let delay = calculate_delay(&policy, 0, None);
        assert_eq!(delay, Duration::ZERO);
    }

    #[test]
    fn calculate_delay_exponential() {
        let policy = RetryPolicy::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_multiplier(2.0)
            .with_max_delay(Duration::from_secs(30))
            .no_jitter();

        // Attempt 1: 100ms
        let delay1 = calculate_delay(&policy, 1, None);
        assert_eq!(delay1, Duration::from_millis(100));

        // Attempt 2: 100 * 2 = 200ms
        let delay2 = calculate_delay(&policy, 2, None);
        assert_eq!(delay2, Duration::from_millis(200));

        // Attempt 3: 100 * 4 = 400ms
        let delay3 = calculate_delay(&policy, 3, None);
        assert_eq!(delay3, Duration::from_millis(400));

        // Attempt 4: 100 * 8 = 800ms
        let delay4 = calculate_delay(&policy, 4, None);
        assert_eq!(delay4, Duration::from_millis(800));
    }

    #[test]
    fn calculate_delay_capped() {
        let policy = RetryPolicy::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_multiplier(10.0)
            .with_max_delay(Duration::from_secs(5))
            .no_jitter();

        // Attempt 1: 1s
        let delay1 = calculate_delay(&policy, 1, None);
        assert_eq!(delay1, Duration::from_secs(1));

        // Attempt 2: 1 * 10 = 10s, but capped at 5s
        let delay2 = calculate_delay(&policy, 2, None);
        assert_eq!(delay2, Duration::from_secs(5));

        // Attempt 3: would be 100s, still capped at 5s
        let delay3 = calculate_delay(&policy, 3, None);
        assert_eq!(delay3, Duration::from_secs(5));
    }

    #[test]
    fn calculate_delay_deterministic_jitter() {
        let policy = RetryPolicy::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_jitter(0.1);

        let mut rng1 = DetRng::new(42);
        let mut rng2 = DetRng::new(42);

        // Same seed should produce same jittered delays
        let first_from_rng1 = calculate_delay(&policy, 1, Some(&mut rng1));
        let first_from_rng2 = calculate_delay(&policy, 1, Some(&mut rng2));
        assert_eq!(first_from_rng1, first_from_rng2);

        let second_from_rng1 = calculate_delay(&policy, 2, Some(&mut rng1));
        let second_from_rng2 = calculate_delay(&policy, 2, Some(&mut rng2));
        assert_eq!(second_from_rng1, second_from_rng2);
    }

    #[test]
    fn calculate_delay_jitter_within_bounds() {
        let policy = RetryPolicy::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_jitter(0.1);

        let mut rng = DetRng::new(12345);
        let base_delay = Duration::from_millis(100);
        let max_with_jitter = Duration::from_millis(110); // 100 * 1.1

        for _ in 0..100 {
            let delay = calculate_delay(&policy, 1, Some(&mut rng));
            assert!(delay >= base_delay);
            assert!(delay <= max_with_jitter);
        }
    }

    #[test]
    fn total_delay_budget_calculation() {
        let policy = RetryPolicy::new()
            .with_max_attempts(4)
            .with_initial_delay(Duration::from_millis(100))
            .with_multiplier(2.0)
            .with_max_delay(Duration::from_secs(30))
            .no_jitter();

        // Delays: attempt 1=100ms, attempt 2=200ms, attempt 3=400ms
        // Total: 100 + 200 + 400 = 700ms (for 3 retries after first attempt)
        let budget = total_delay_budget(&policy);
        assert_eq!(budget, Duration::from_millis(700));
    }

    #[test]
    fn retry_error_display() {
        let err = RetryError::new("connection failed", 3, Duration::from_millis(300));
        let display = err.to_string();
        assert!(display.contains("3 attempts"));
        assert!(display.contains("connection failed"));
    }

    #[test]
    fn retry_error_map() {
        let err = RetryError::new("error", 2, Duration::from_millis(100));
        let mapped = err.map(str::len);
        assert_eq!(mapped.final_error, 5);
        assert_eq!(mapped.attempts, 2);
    }

    #[test]
    fn retry_result_conversions() {
        let ok: RetryResult<i32, &str> = RetryResult::Ok(42);
        assert!(ok.is_ok());
        assert!(!ok.is_failed());
        assert!(!ok.is_cancelled());

        let failed: RetryResult<i32, &str> =
            RetryResult::Failed(RetryError::new("error", 3, Duration::ZERO));
        assert!(!failed.is_ok());
        assert!(failed.is_failed());

        let cancelled: RetryResult<i32, &str> = RetryResult::Cancelled(CancelReason::timeout());
        assert!(!cancelled.is_ok());
        assert!(cancelled.is_cancelled());
    }

    #[test]
    fn retry_result_into_outcome() {
        let ok: RetryResult<i32, &str> = RetryResult::Ok(42);
        let outcome = ok.into_outcome();
        assert!(outcome.is_ok());

        let failed: RetryResult<i32, &str> =
            RetryResult::Failed(RetryError::new("error", 3, Duration::ZERO));
        let outcome = failed.into_outcome();
        assert!(outcome.is_err());
    }

    #[test]
    fn retry_result_into_result() {
        let ok: RetryResult<i32, &str> = RetryResult::Ok(42);
        let result = ok.into_result();
        assert_eq!(result.unwrap(), 42);

        let failed: RetryResult<i32, &str> =
            RetryResult::Failed(RetryError::new("error", 3, Duration::ZERO));
        let result = failed.into_result();
        assert!(matches!(result, Err(RetryFailure::Exhausted(_))));
    }

    #[test]
    fn retry_state_tracks_attempts() {
        let policy = RetryPolicy::new().with_max_attempts(3);
        let mut state = RetryState::new(policy);

        assert_eq!(state.attempt, 0);
        assert!(state.has_attempts_remaining());
        assert_eq!(state.attempts_remaining(), 3);

        // First attempt
        let delay = state.next_attempt(None);
        assert_eq!(delay, Some(Duration::ZERO));
        assert_eq!(state.attempt, 1);
        assert!(state.has_attempts_remaining());

        // Second attempt (first retry)
        let delay = state.next_attempt(None);
        assert!(delay.is_some());
        assert!(delay.unwrap() > Duration::ZERO);
        assert_eq!(state.attempt, 2);
        assert!(state.has_attempts_remaining());

        // Third attempt (second retry)
        let delay = state.next_attempt(None);
        assert!(delay.is_some());
        assert_eq!(state.attempt, 3);
        assert!(!state.has_attempts_remaining());

        // No more attempts
        let delay = state.next_attempt(None);
        assert!(delay.is_none());
    }

    #[test]
    fn retry_state_cancel() {
        let policy = RetryPolicy::new().with_max_attempts(3);
        let mut state = RetryState::new(policy);

        assert!(state.has_attempts_remaining());

        state.cancel();

        assert!(!state.has_attempts_remaining());
        assert_eq!(state.attempts_remaining(), 0);
        assert!(state.next_attempt(None).is_none());
    }

    #[test]
    fn retry_state_into_error() {
        let policy = RetryPolicy::new().with_max_attempts(3);
        let mut state = RetryState::new(policy);

        state.next_attempt(None); // attempt 1
        state.next_attempt(None); // attempt 2

        let error = state.into_error("failed");
        assert_eq!(error.final_error, "failed");
        assert_eq!(error.attempts, 2);
    }

    #[test]
    fn make_retry_result_success() {
        let state = RetryState::new(RetryPolicy::new());
        let outcome: Outcome<i32, &str> = Outcome::Ok(42);
        let result = make_retry_result(outcome, &state, false);
        assert!(matches!(result, Some(RetryResult::Ok(42))));
    }

    #[test]
    fn make_retry_result_error_not_final() {
        let state = RetryState::new(RetryPolicy::new());
        let outcome: Outcome<i32, &str> = Outcome::Err("error");
        let result = make_retry_result(outcome, &state, false);
        assert!(result.is_none()); // Should retry
    }

    #[test]
    fn make_retry_result_error_final() {
        let policy = RetryPolicy::new().with_max_attempts(3);
        let mut state = RetryState::new(policy);
        state.next_attempt(None);
        state.next_attempt(None);
        state.next_attempt(None);

        let outcome: Outcome<i32, &str> = Outcome::Err("error");
        let result = make_retry_result(outcome, &state, true);
        assert!(matches!(result, Some(RetryResult::Failed(_))));
    }

    #[test]
    fn make_retry_result_cancelled() {
        let state = RetryState::new(RetryPolicy::new());
        let outcome: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());
        let result = make_retry_result(outcome, &state, false);
        assert!(matches!(result, Some(RetryResult::Cancelled(_))));
    }

    #[test]
    fn retry_predicates() {
        let always = AlwaysRetry;
        assert!(always.should_retry(&"any error", 1));
        assert!(always.should_retry(&"any error", 100));

        let never = NeverRetry;
        assert!(!never.should_retry(&"any error", 1));

        let retry_if = RetryIf(|e: &&str, _| e.contains("transient"));
        assert!(retry_if.should_retry(&"transient error", 1));
        assert!(!retry_if.should_retry(&"permanent error", 1));
    }

    #[test]
    fn retry_failure_display() {
        let exhausted: RetryFailure<&str> =
            RetryFailure::Exhausted(RetryError::new("error", 3, Duration::ZERO));
        assert!(exhausted.to_string().contains("3 attempts"));

        let cancelled: RetryFailure<&str> = RetryFailure::Cancelled(CancelReason::timeout());
        assert!(cancelled.to_string().contains("cancelled"));
    }

    #[test]
    fn calculate_deadline_adds_delay() {
        let policy = RetryPolicy::new()
            .with_initial_delay(Duration::from_millis(100))
            .no_jitter();

        let now = Time::from_nanos(1_000_000_000); // 1 second
        let deadline = calculate_deadline(&policy, 1, now, None);

        // Should be now + 100ms
        let expected = Time::from_nanos(1_100_000_000);
        assert_eq!(deadline, expected);
    }

    #[test]
    fn fixed_delay_consistent() {
        let policy = RetryPolicy::fixed_delay(Duration::from_millis(500), 5);

        // All delays should be 500ms
        for attempt in 1..=4 {
            let delay = calculate_delay(&policy, attempt, None);
            assert_eq!(delay, Duration::from_millis(500));
        }
    }

    #[test]
    fn retry_policy_debug_clone() {
        let p = RetryPolicy::new();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("RetryPolicy"), "{dbg}");
        let cloned = p;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn always_retry_debug_clone_copy_default() {
        let a = AlwaysRetry;
        let dbg = format!("{a:?}");
        assert!(dbg.contains("AlwaysRetry"), "{dbg}");
        let copied: AlwaysRetry = a;
        let cloned = a;
        let _ = (copied, cloned);
    }

    #[test]
    fn never_retry_debug_clone_copy_default() {
        let n = NeverRetry;
        let dbg = format!("{n:?}");
        assert!(dbg.contains("NeverRetry"), "{dbg}");
        let copied: NeverRetry = n;
        let cloned = n;
        let _ = (copied, cloned);
    }

    #[test]
    fn retry_state_debug_clone() {
        let s = RetryState::new(RetryPolicy::new());
        let dbg = format!("{s:?}");
        assert!(dbg.contains("RetryState"), "{dbg}");
        let cloned = s;
        assert_eq!(format!("{cloned:?}"), dbg);
    }

    #[test]
    fn test_retry_execution() {
        // Use a counter to fail the first 2 times, then succeed
        // Must use Arc/Mutex or cell because the closure is called multiple times
        // and FnMut allows mutating state.
        let mut attempts = 0;

        let future = retry(
            RetryPolicy::new()
                .with_max_attempts(3)
                .no_jitter()
                .with_initial_delay(Duration::ZERO),
            AlwaysRetry,
            move || {
                attempts += 1;
                let current_attempt = attempts;
                std::future::ready(if current_attempt < 3 {
                    Outcome::Err("fail")
                } else {
                    Outcome::Ok(42)
                })
            },
        );

        let result = futures_lite::future::block_on(future);
        assert!(result.is_ok());
        if let RetryResult::Ok(val) = result {
            assert_eq!(val, 42);
        }
    }

    #[test]
    fn test_retry_exhausted() {
        // Always fail
        let future = retry(
            RetryPolicy::new()
                .with_max_attempts(3)
                .no_jitter()
                .with_initial_delay(Duration::ZERO),
            AlwaysRetry,
            || std::future::ready(Outcome::<i32, &str>::Err("fail forever")),
        );

        let result = futures_lite::future::block_on(future);
        assert!(result.is_failed());
        if let RetryResult::Failed(err) = result {
            assert_eq!(err.attempts, 3);
            assert_eq!(err.final_error, "fail forever");
        }
    }

    // ─── Token Bucket Golden Tests ──────────────────────────────────────────

    mod token_bucket_golden_tests {
        use super::*;

        /// Helper to create a consistent test time baseline
        fn test_time_baseline() -> Time {
            Time::from_millis(1_000_000) // 1M ms = 1000 seconds
        }

        /// Golden test 1: Token refill rate respected
        ///
        /// Verifies that tokens are refilled at the exact rate specified.
        /// Tests deterministic timing across different intervals.
        #[test]
        fn golden_token_refill_rate_respected() {
            let capacity = 10;
            let refill_rate = 5.0; // 5 tokens per second
            let mut bucket = RetryTokenBucket::new(capacity, refill_rate, test_time_baseline());

            // Start with empty bucket
            let _ = bucket.try_consume(10, test_time_baseline());
            assert_eq!(bucket.available_tokens(), 0);

            // After 1 second, should have 5 tokens
            let time_1s = test_time_baseline() + Duration::from_secs(1);
            bucket.refill(time_1s);
            assert_eq!(bucket.available_tokens(), 5);

            // After 2 seconds total, should have 10 tokens (capped)
            let time_2s = test_time_baseline() + Duration::from_secs(2);
            bucket.refill(time_2s);
            assert_eq!(bucket.available_tokens(), 10);

            // After 0.5 seconds more, should still have 10 tokens (at capacity)
            let time_2_5s = time_2s + Duration::from_millis(500);
            bucket.refill(time_2_5s);
            assert_eq!(bucket.available_tokens(), 10);

            // Consume 8 tokens, leaving 2
            assert!(bucket.try_consume(8, time_2_5s));
            assert_eq!(bucket.available_tokens(), 2);

            // After 0.4 seconds, should have 2 + (0.4 * 5) = 4 tokens
            let time_2_9s = time_2_5s + Duration::from_millis(400);
            bucket.refill(time_2_9s);
            assert_eq!(bucket.available_tokens(), 4);

            // Golden assertion: exact refill rate
            assert_golden_token_refill_rate(refill_rate, &bucket, time_2_9s);
        }

        fn assert_golden_token_refill_rate(
            expected_rate: f64,
            bucket: &RetryTokenBucket,
            _now: Time,
        ) {
            const EPSILON: f64 = 0.001;
            let actual_rate = bucket.refill_rate();
            assert!(
                (actual_rate - expected_rate).abs() < EPSILON,
                "Golden token refill rate mismatch: expected {}, got {}",
                expected_rate,
                actual_rate
            );
        }

        /// Golden test 2: Burst absorbs exact bucket capacity
        ///
        /// Verifies that the bucket can handle burst traffic up to its exact capacity
        /// and no more.
        #[test]
        fn golden_burst_absorbs_exact_capacity() {
            let capacity = 5;
            let refill_rate = 1.0; // 1 token per second
            let mut bucket = RetryTokenBucket::new(capacity, refill_rate, test_time_baseline());

            // Should be able to consume exactly the capacity in one burst
            assert!(bucket.try_consume(capacity, test_time_baseline()));
            assert_eq!(bucket.available_tokens(), 0);

            // Should not be able to consume any more immediately
            assert!(!bucket.try_consume(1, test_time_baseline()));
            assert_eq!(bucket.available_tokens(), 0);

            // Reset bucket to full
            let mut bucket = RetryTokenBucket::new(capacity, refill_rate, test_time_baseline());

            // Should not be able to consume more than capacity
            assert!(!bucket.try_consume(capacity + 1, test_time_baseline()));
            assert_eq!(bucket.available_tokens(), capacity); // Should remain unchanged

            // Golden assertion: exact capacity handling
            assert_golden_burst_capacity(capacity, bucket.capacity());
        }

        fn assert_golden_burst_capacity(expected_capacity: u32, actual_capacity: u32) {
            assert_eq!(
                actual_capacity, expected_capacity,
                "Golden burst capacity mismatch: expected {}, got {}",
                expected_capacity, actual_capacity
            );
        }

        /// Golden test 3: Exhausted bucket blocks with Retry-After signal
        ///
        /// Verifies that when the bucket is exhausted, it provides accurate
        /// timing information about when tokens will be available.
        #[test]
        fn golden_exhausted_bucket_blocks_with_retry_after() {
            let capacity = 3;
            let refill_rate = 2.0; // 2 tokens per second
            let mut bucket = RetryTokenBucket::new(capacity, refill_rate, test_time_baseline());

            // Exhaust the bucket
            assert!(bucket.try_consume(capacity, test_time_baseline()));
            assert_eq!(bucket.available_tokens(), 0);

            // Try to consume 1 token - should fail
            assert!(!bucket.try_consume(1, test_time_baseline()));

            // Check retry-after signal
            let retry_after = bucket.time_to_tokens(1);
            let expected_retry_after = Duration::from_millis(500); // 1 token at 2 tokens/sec = 0.5s

            assert_golden_retry_after_signal(expected_retry_after, retry_after);

            // Try to consume 2 tokens - should need longer wait
            let retry_after_2 = bucket.time_to_tokens(2);
            let expected_retry_after_2 = Duration::from_secs(1); // 2 tokens at 2 tokens/sec = 1s

            assert_golden_retry_after_signal(expected_retry_after_2, retry_after_2);

            // Partially refill and check again
            let time_quarter_sec = test_time_baseline() + Duration::from_millis(250);
            bucket.refill(time_quarter_sec);
            assert_eq!(bucket.available_tokens(), 0); // 0.25 * 2 = 0.5 tokens, floor = 0

            let retry_after_partial = bucket.time_to_tokens(1);
            let expected_partial = Duration::from_millis(250); // Need 0.5 more tokens = 0.25s

            assert_golden_retry_after_signal(expected_partial, retry_after_partial);
        }

        fn assert_golden_retry_after_signal(expected: Duration, actual: Duration) {
            let tolerance = Duration::from_millis(1); // 1ms tolerance for floating point
            let diff = if actual > expected {
                actual - expected
            } else {
                expected - actual
            };
            assert!(
                diff <= tolerance,
                "Golden retry-after signal mismatch: expected {:?}, got {:?}, diff {:?}",
                expected,
                actual,
                diff
            );
        }

        /// Golden test 4: Tokens consumed atomically per retry
        ///
        /// Verifies that token consumption is atomic - either the full cost
        /// is consumed or nothing is consumed.
        #[test]
        fn golden_tokens_consumed_atomically() {
            let capacity = 5;
            let refill_rate = 1.0;
            let mut bucket = RetryTokenBucket::new(capacity, refill_rate, test_time_baseline());

            // Start with 3 tokens
            assert!(bucket.try_consume(2, test_time_baseline()));
            assert_eq!(bucket.available_tokens(), 3);

            // Try to consume 4 tokens atomically - should fail and leave bucket unchanged
            let tokens_before = bucket.available_tokens();
            assert!(!bucket.try_consume(4, test_time_baseline()));
            assert_eq!(bucket.available_tokens(), tokens_before);

            // Try to consume 3 tokens atomically - should succeed
            assert!(bucket.try_consume(3, test_time_baseline()));
            assert_eq!(bucket.available_tokens(), 0);

            // Multiple atomic operations in sequence
            let mut bucket = RetryTokenBucket::new(10, 5.0, test_time_baseline());

            let operations = vec![3, 2, 1, 4]; // Total: 10 tokens
            for cost in operations {
                assert!(
                    bucket.try_consume(cost, test_time_baseline()),
                    "Should be able to consume {} tokens atomically",
                    cost
                );
            }
            assert_eq!(bucket.available_tokens(), 0);

            assert_golden_atomic_consumption(&bucket);
        }

        fn assert_golden_atomic_consumption(bucket: &RetryTokenBucket) {
            // All tokens should be consumed (demonstrating atomic behavior)
            assert_eq!(
                bucket.available_tokens(),
                0,
                "Golden atomic consumption: all tokens should be consumed atomically"
            );
        }

        /// Golden test 5: LabRuntime replay identical
        ///
        /// Verifies that token bucket behavior is deterministic and replay-identical
        /// when using the same time sequence.
        #[test]
        fn golden_lab_runtime_replay_identical() {
            let capacity = 4;
            let refill_rate = 2.0;
            let time_sequence = vec![
                test_time_baseline(),
                test_time_baseline() + Duration::from_millis(500),
                test_time_baseline() + Duration::from_millis(1000),
                test_time_baseline() + Duration::from_millis(1500),
                test_time_baseline() + Duration::from_millis(2000),
            ];

            // First execution
            let mut bucket1 = RetryTokenBucket::new(capacity, refill_rate, time_sequence[0]);
            let mut trace1 = Vec::new();

            for &time in &time_sequence[1..] {
                let before_tokens = bucket1.available_tokens();
                bucket1.refill(time);
                let after_tokens = bucket1.available_tokens();
                let consumed = bucket1.try_consume(1, time);
                let final_tokens = bucket1.available_tokens();

                trace1.push((before_tokens, after_tokens, consumed, final_tokens));
            }

            // Second execution (replay)
            let mut bucket2 = RetryTokenBucket::new(capacity, refill_rate, time_sequence[0]);
            let mut trace2 = Vec::new();

            for &time in &time_sequence[1..] {
                let before_tokens = bucket2.available_tokens();
                bucket2.refill(time);
                let after_tokens = bucket2.available_tokens();
                let consumed = bucket2.try_consume(1, time);
                let final_tokens = bucket2.available_tokens();

                trace2.push((before_tokens, after_tokens, consumed, final_tokens));
            }

            // Golden assertion: traces must be identical
            assert_golden_replay_identical(&trace1, &trace2);

            // Additional determinism test with complex pattern
            let complex_pattern = vec![
                (test_time_baseline(), 2),
                (test_time_baseline() + Duration::from_millis(333), 1),
                (test_time_baseline() + Duration::from_millis(666), 3),
                (test_time_baseline() + Duration::from_millis(1000), 1),
            ];

            let trace_a = execute_token_bucket_pattern(capacity, refill_rate, &complex_pattern);
            let trace_b = execute_token_bucket_pattern(capacity, refill_rate, &complex_pattern);

            assert_golden_replay_identical(&trace_a, &trace_b);
        }

        fn execute_token_bucket_pattern(
            capacity: u32,
            refill_rate: f64,
            pattern: &[(Time, u32)],
        ) -> Vec<(bool, u32)> {
            if pattern.is_empty() {
                return Vec::new();
            }

            let mut bucket = RetryTokenBucket::new(capacity, refill_rate, pattern[0].0);
            let mut trace = Vec::new();

            for &(time, cost) in &pattern[1..] {
                bucket.refill(time);
                let consumed = bucket.try_consume(cost, time);
                let remaining = bucket.available_tokens();
                trace.push((consumed, remaining));
            }

            trace
        }

        fn assert_golden_replay_identical<T: PartialEq + std::fmt::Debug>(
            trace1: &[T],
            trace2: &[T],
        ) {
            assert_eq!(
                trace1.len(),
                trace2.len(),
                "Golden replay traces have different lengths"
            );

            for (i, (t1, t2)) in trace1.iter().zip(trace2).enumerate() {
                assert_eq!(
                    t1, t2,
                    "Golden replay mismatch at step {}: {:?} != {:?}",
                    i, t1, t2
                );
            }
        }

        /// Composite golden test: All token bucket properties together
        ///
        /// Tests multiple properties in combination to catch interaction bugs.
        #[test]
        fn golden_composite_token_bucket_properties() {
            let capacity = 6;
            let refill_rate = 3.0; // 3 tokens per second
            let mut bucket = RetryTokenBucket::new(capacity, refill_rate, test_time_baseline());

            // Property 1 + 2: Burst capacity + refill rate
            assert!(bucket.try_consume(capacity, test_time_baseline())); // Use full burst
            assert_eq!(bucket.available_tokens(), 0);

            // Property 3: Retry-after when exhausted
            let retry_after = bucket.time_to_tokens(3);
            assert_eq!(retry_after, Duration::from_secs(1)); // 3 tokens at 3 tokens/sec

            // Property 1: Refill rate over time
            let time_1s = test_time_baseline() + Duration::from_secs(1);
            bucket.refill(time_1s);
            assert_eq!(bucket.available_tokens(), 3);

            // Property 4: Atomic consumption
            assert!(bucket.try_consume(3, time_1s)); // Should consume all 3 atomically
            assert_eq!(bucket.available_tokens(), 0);

            assert!(!bucket.try_consume(1, time_1s)); // Should fail atomically

            // Property 5: Deterministic behavior
            let time_2s = test_time_baseline() + Duration::from_secs(2);
            bucket.refill(time_2s);
            assert_eq!(bucket.available_tokens(), 3); // Predictable refill

            // All properties maintained together
            assert_golden_composite_properties(&bucket, capacity, refill_rate);
        }

        fn assert_golden_composite_properties(
            bucket: &RetryTokenBucket,
            expected_capacity: u32,
            expected_refill_rate: f64,
        ) {
            assert_eq!(bucket.capacity(), expected_capacity);
            assert!((bucket.refill_rate() - expected_refill_rate).abs() < 0.001);
            assert!(bucket.available_tokens() <= expected_capacity);
        }
    }
}
