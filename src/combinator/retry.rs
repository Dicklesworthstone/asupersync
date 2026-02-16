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

use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use crate::types::{Outcome, Time};
use crate::util::det_rng::DetRng;
use core::fmt;
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
    #[must_use]
    pub fn with_max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts.max(1);
        self
    }

    /// Sets the initial delay for the first retry.
    #[must_use]
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Sets the maximum delay cap.
    #[must_use]
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Sets the backoff multiplier.
    #[must_use]
    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier.max(1.0);
        self
    }

    /// Sets the jitter factor (0.0 to 1.0).
    #[must_use]
    pub fn with_jitter(mut self, jitter: f64) -> Self {
        self.jitter = jitter.clamp(0.0, 1.0);
        self
    }

    /// Creates a policy with no jitter (fully deterministic delays).
    #[must_use]
    pub fn no_jitter(mut self) -> Self {
        self.jitter = 0.0;
        self
    }

    /// Creates a policy with fixed delays (no exponential backoff).
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
        total = total.saturating_add(Duration::from_nanos(max_delay_nanos));
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
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }

    /// Returns true if all attempts failed.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }

    /// Returns true if the operation was cancelled.
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }

    /// Returns true if the operation panicked.
    #[must_use]
    pub const fn is_panicked(&self) -> bool {
        matches!(self, Self::Panicked(_))
    }

    /// Converts to an Outcome.
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
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            attempt: 0,
            total_delay: Duration::ZERO,
            cancelled: false,
            policy,
        }
    }

    /// Returns true if more attempts are available.
    #[must_use]
    pub fn has_attempts_remaining(&self) -> bool {
        !self.cancelled && self.attempt < self.policy.max_attempts
    }

    /// Returns the number of attempts remaining.
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
) -> Option<RetryResult<T, E>>
where
    E: Clone,
{
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

/// Retries an operation with configurable backoff.
///
/// # Semantics
///
/// ```ignore
/// let result = retry!(
///     attempts: 3,
///     backoff: exponential(100ms, 2.0),
///     operation()
/// ).await;
/// ```
///
/// - Retries up to `max_attempts` times
/// - Waits `delay` between attempts (optionally with exponential backoff)
/// - Returns first success, or last error after exhausting retries
/// - Respects cancellation during both operation and delay
#[macro_export]
macro_rules! retry {
    // Full syntax with policy
    (attempts: $max:expr, backoff: $backoff:expr, $operation:expr) => {{
        // Placeholder: in real implementation, this retries with backoff
        let _ = $max;
        let _ = $backoff;
        let _ = $operation;
    }};

    // Simple syntax: retry!(max_attempts, operation)
    ($max:expr, $operation:expr) => {{
        // Placeholder: in real implementation, this retries with fixed delay
        let _ = $max;
        let _ = $operation;
    }};
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
    fn retry_state_total_delay_saturates() {
        let policy = RetryPolicy::new()
            .with_max_attempts(3)
            .with_initial_delay(Duration::from_nanos(u64::MAX))
            .with_multiplier(2.0)
            .no_jitter();
        let mut state = RetryState::new(policy);

        assert_eq!(state.next_attempt(None), Some(Duration::ZERO));
        state.total_delay = Duration::MAX;

        assert!(state.next_attempt(None).is_some());
        assert_eq!(state.total_delay, Duration::MAX);
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
    fn total_delay_budget_accumulates_large_delays() {
        let policy = RetryPolicy::new()
            .with_max_attempts(4)
            .with_initial_delay(Duration::from_nanos(u64::MAX))
            .with_max_delay(Duration::from_nanos(u64::MAX))
            .with_multiplier(2.0)
            .no_jitter();

        let unit = Duration::from_nanos(u64::MAX);
        let expected = unit.saturating_add(unit).saturating_add(unit);
        assert_eq!(total_delay_budget(&policy), expected);
    }
}
