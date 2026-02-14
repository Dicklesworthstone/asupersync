//! Timeout combinator: add a deadline to an operation.
//!
//! The timeout combinator races an operation against a deadline.
//! If the deadline expires first, the operation is cancelled and drained.
//!
//! This is semantically equivalent to: `race(operation, sleep(duration))`
//!
//! # Critical Invariant: Timed-out Operations Are Drained
//!
//! Like race, timeout guarantees that timed-out operations are cancelled AND
//! drained before returning. This ensures resources held by the operation
//! are properly released.
//!
//! # Algebraic Law: Timeout Composition
//!
//! ```text
//! timeout(d1, timeout(d2, f)) ≃ timeout(min(d1, d2), f)
//! ```
//!
//! The inner timeout is redundant if the outer is tighter.

use crate::types::{CancelReason, Outcome, Time};
use core::fmt;
use std::marker::PhantomData;
use std::time::Duration;

fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// A timeout combinator.
#[derive(Debug)]
pub struct Timeout<T> {
    /// The deadline for the operation.
    pub deadline: Time,
    _t: PhantomData<T>,
}

impl<T> Timeout<T> {
    /// Creates a new timeout with the given deadline.
    #[must_use]
    pub const fn new(deadline: Time) -> Self {
        Self {
            deadline,
            _t: PhantomData,
        }
    }

    /// Creates a timeout from a duration in nanoseconds from now.
    #[must_use]
    pub const fn after_nanos(now: Time, nanos: u64) -> Self {
        Self::new(now.saturating_add_nanos(nanos))
    }

    /// Creates a timeout from a duration in milliseconds from now.
    #[must_use]
    pub const fn after_millis(now: Time, millis: u64) -> Self {
        Self::after_nanos(now, millis.saturating_mul(1_000_000))
    }

    /// Creates a timeout from a duration in seconds from now.
    #[must_use]
    pub const fn after_secs(now: Time, secs: u64) -> Self {
        Self::after_nanos(now, secs.saturating_mul(1_000_000_000))
    }

    /// Creates a timeout from a std Duration.
    #[must_use]
    pub fn after(now: Time, duration: Duration) -> Self {
        Self::after_nanos(now, duration_to_nanos(duration))
    }

    /// Returns true if the deadline has passed.
    #[must_use]
    pub fn is_expired(&self, now: Time) -> bool {
        now >= self.deadline
    }

    /// Returns the remaining time until the deadline, or zero if expired.
    #[must_use]
    pub fn remaining(&self, now: Time) -> Duration {
        if now >= self.deadline {
            Duration::ZERO
        } else {
            let nanos = self.deadline.as_nanos().saturating_sub(now.as_nanos());
            Duration::from_nanos(nanos)
        }
    }
}

impl<T> Clone for Timeout<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Timeout<T> {}

/// Error type for timeout operations.
///
/// Returned when an operation exceeds its deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutError {
    /// The deadline that was exceeded.
    pub deadline: Time,
    /// Optional message describing what timed out.
    pub message: Option<&'static str>,
}

impl TimeoutError {
    /// Creates a new timeout error with the given deadline.
    #[must_use]
    pub const fn new(deadline: Time) -> Self {
        Self {
            deadline,
            message: None,
        }
    }

    /// Creates a new timeout error with a message.
    #[must_use]
    pub const fn with_message(deadline: Time, message: &'static str) -> Self {
        Self {
            deadline,
            message: Some(message),
        }
    }

    /// Converts to a CancelReason for use in Outcome::Cancelled.
    #[must_use]
    pub const fn into_cancel_reason(self) -> CancelReason {
        CancelReason::timeout()
    }
}

impl fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message {
            Some(msg) => write!(f, "timeout: {} (deadline: {:?})", msg, self.deadline),
            None => write!(f, "operation timed out at {:?}", self.deadline),
        }
    }
}

impl std::error::Error for TimeoutError {}

/// The result of a timed operation.
#[derive(Debug, Clone)]
pub enum TimedResult<T, E> {
    /// The operation completed in time.
    Completed(Outcome<T, E>),
    /// The operation timed out.
    TimedOut(TimeoutError),
}

impl<T, E> TimedResult<T, E> {
    /// Returns true if the operation completed.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self, Self::Completed(_))
    }

    /// Returns true if the operation timed out.
    #[must_use]
    pub const fn is_timed_out(&self) -> bool {
        matches!(self, Self::TimedOut(_))
    }

    /// Converts to an Outcome, treating timeout as cancellation.
    pub fn into_outcome(self) -> Outcome<T, E> {
        match self {
            Self::Completed(outcome) => outcome,
            Self::TimedOut(err) => Outcome::Cancelled(err.into_cancel_reason()),
        }
    }

    /// Converts to a Result, treating timeout as an error.
    pub fn into_result(self) -> Result<T, TimedError<E>> {
        match self {
            Self::Completed(outcome) => match outcome {
                Outcome::Ok(v) => Ok(v),
                Outcome::Err(e) => Err(TimedError::Error(e)),
                Outcome::Cancelled(r) => Err(TimedError::Cancelled(r)),
                Outcome::Panicked(p) => Err(TimedError::Panicked(p)),
            },
            Self::TimedOut(err) => Err(TimedError::TimedOut(err)),
        }
    }
}

/// Error type for timed operations that can fail, cancel, panic, or time out.
#[derive(Debug, Clone)]
pub enum TimedError<E> {
    /// The operation returned an error.
    Error(E),
    /// The operation was cancelled.
    Cancelled(CancelReason),
    /// The operation panicked.
    Panicked(crate::types::outcome::PanicPayload),
    /// The operation timed out.
    TimedOut(TimeoutError),
}

impl<E: fmt::Display> fmt::Display for TimedError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(e) => write!(f, "{e}"),
            Self::Cancelled(r) => write!(f, "cancelled: {r}"),
            Self::Panicked(p) => write!(f, "panicked: {p}"),
            Self::TimedOut(t) => write!(f, "{t}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for TimedError<E> {}

/// Creates a TimedResult from an outcome and a deadline check.
///
/// This is used internally to construct timeout results.
///
/// # Arguments
/// * `outcome` - The outcome from the operation
/// * `deadline` - The deadline that was set
/// * `completed_in_time` - Whether the operation completed before the deadline
#[must_use]
pub fn make_timed_result<T, E>(
    outcome: Outcome<T, E>,
    deadline: Time,
    completed_in_time: bool,
) -> TimedResult<T, E> {
    if completed_in_time {
        TimedResult::Completed(outcome)
    } else {
        TimedResult::TimedOut(TimeoutError::new(deadline))
    }
}

/// Computes the effective deadline given a requested timeout and an existing deadline.
///
/// This implements the LAW-TIMEOUT-MIN algebraic law:
/// `timeout(d1, timeout(d2, f)) ≃ timeout(min(d1, d2), f)`
///
/// # Arguments
/// * `requested` - The requested deadline
/// * `existing` - The existing deadline from scope/budget (if any)
///
/// # Returns
/// The tighter (earlier) of the two deadlines.
#[must_use]
pub const fn effective_deadline(requested: Time, existing: Option<Time>) -> Time {
    match existing {
        Some(e) if e.as_nanos() < requested.as_nanos() => e,
        _ => requested,
    }
}

/// Configuration for timeout behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutConfig {
    /// The deadline for the operation.
    pub deadline: Time,
    /// Whether to use the effective deadline (respecting nested timeouts).
    pub use_effective: bool,
}

impl TimeoutConfig {
    /// Creates a new timeout configuration.
    #[must_use]
    pub const fn new(deadline: Time) -> Self {
        Self {
            deadline,
            use_effective: true,
        }
    }

    /// Creates a configuration that ignores nested timeouts.
    #[must_use]
    pub const fn absolute(deadline: Time) -> Self {
        Self {
            deadline,
            use_effective: false,
        }
    }

    /// Returns the final deadline to use, considering any existing deadline.
    #[must_use]
    pub const fn resolve(&self, existing: Option<Time>) -> Time {
        if self.use_effective {
            effective_deadline(self.deadline, existing)
        } else {
            self.deadline
        }
    }
}

/// Runs a future with a timeout.
///
/// This macro races the provided future against a sleep, returning
/// the result if it completes in time, or an error if it times out.
///
/// # Semantics
///
/// ```ignore
/// let result = timeout!(Duration::from_secs(5), operation).await;
///
/// match result {
///     Ok(value) => println!("Completed: {:?}", value),
///     Err(Elapsed) => println!("Timed out"),
/// }
/// ```
///
/// # Cancellation Behavior
///
/// When timeout fires:
/// 1. Main future is cancelled
/// 2. Cancellation follows standard protocol (drain + finalize)
/// 3. `timeout!` returns after main future is fully drained
///
/// When main future completes:
/// 1. Sleep is cancelled
/// 2. `timeout!` returns immediately (sleep cleanup is fast)
#[macro_export]
macro_rules! timeout {
    // Basic syntax: timeout!(duration, future)
    ($duration:expr, $future:expr) => {{
        // Placeholder: in real implementation, this races against sleep
        let _ = $duration;
        let _ = $future;
    }};

    // With explicit cx: timeout!(cx, duration, future)
    ($cx:expr, $duration:expr, $future:expr) => {{
        // Placeholder: in real implementation, this races against sleep using cx
        let _ = $cx;
        let _ = $duration;
        let _ = $future;
    }};
}

/// Joins multiple futures, short-circuiting on the first error.
///
/// Unlike `join!` which waits for all futures, `try_join!` cancels
/// remaining futures when any future returns an error.
///
/// # Semantics
///
/// ```ignore
/// let (a, b, c) = try_join!(fut_a, fut_b, fut_c).await?;
/// ```
///
/// - If all succeed: return tuple of values
/// - If any fails: cancel remaining, return first error
/// - If any panics: cancel remaining, return Panicked
#[macro_export]
macro_rules! try_join {
    ($($future:expr),+ $(,)?) => {{
        // Placeholder: in real implementation, this joins with short-circuit
        $(let _ = $future;)+
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_creation() {
        let now = Time::ZERO;
        let timeout = Timeout::<()>::after_secs(now, 5);
        assert_eq!(timeout.deadline.as_nanos(), 5_000_000_000);
    }

    #[test]
    fn timeout_after_millis() {
        let now = Time::ZERO;
        let timeout = Timeout::<()>::after_millis(now, 100);
        assert_eq!(timeout.deadline.as_nanos(), 100_000_000);
    }

    #[test]
    fn timeout_after_duration() {
        let now = Time::ZERO;
        let timeout = Timeout::<()>::after(now, Duration::from_millis(250));
        assert_eq!(timeout.deadline.as_nanos(), 250_000_000);
    }

    #[test]
    fn timeout_after_duration_saturates_large_duration() {
        let now = Time::from_nanos(1);
        let timeout = Timeout::<()>::after(now, Duration::MAX);
        assert_eq!(timeout.deadline, Time::MAX);
    }

    #[test]
    fn timeout_is_expired() {
        let now = Time::from_nanos(1000);
        let past = Time::from_nanos(500);
        let future = Time::from_nanos(2000);

        let timeout_past = Timeout::<()>::new(past);
        let timeout_future = Timeout::<()>::new(future);

        assert!(timeout_past.is_expired(now));
        assert!(!timeout_future.is_expired(now));
    }

    #[test]
    fn timeout_remaining() {
        let now = Time::from_nanos(1000);
        let deadline = Time::from_nanos(1500);
        let timeout = Timeout::<()>::new(deadline);

        assert_eq!(timeout.remaining(now), Duration::from_nanos(500));

        // After deadline
        let later = Time::from_nanos(2000);
        assert_eq!(timeout.remaining(later), Duration::ZERO);
    }

    #[test]
    fn timeout_error_display() {
        let err = TimeoutError::new(Time::from_nanos(1000));
        assert!(err.to_string().contains("timed out"));

        let err_with_msg = TimeoutError::with_message(Time::from_nanos(1000), "fetch failed");
        assert!(err_with_msg.to_string().contains("fetch failed"));
    }

    #[test]
    fn timed_result_completed() {
        let result: TimedResult<i32, &str> = TimedResult::Completed(Outcome::Ok(42));

        assert!(result.is_completed());
        assert!(!result.is_timed_out());

        let outcome = result.into_outcome();
        assert!(outcome.is_ok());
    }

    #[test]
    fn timed_result_timed_out() {
        let result: TimedResult<i32, &str> =
            TimedResult::TimedOut(TimeoutError::new(Time::from_nanos(1000)));

        assert!(!result.is_completed());
        assert!(result.is_timed_out());

        let outcome = result.into_outcome();
        assert!(outcome.is_cancelled());
    }

    #[test]
    fn timed_result_into_result_ok() {
        let result: TimedResult<i32, &str> = TimedResult::Completed(Outcome::Ok(42));

        let res = result.into_result();
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 42);
    }

    #[test]
    fn timed_result_into_result_timeout() {
        let result: TimedResult<i32, &str> =
            TimedResult::TimedOut(TimeoutError::new(Time::from_nanos(1000)));

        let res = result.into_result();
        assert!(matches!(res, Err(TimedError::TimedOut(_))));
    }

    #[test]
    fn timed_result_into_result_error() {
        let result: TimedResult<i32, &str> = TimedResult::Completed(Outcome::Err("failed"));

        let res = result.into_result();
        assert!(matches!(res, Err(TimedError::Error("failed"))));
    }

    #[test]
    fn timed_result_into_result_cancelled() {
        let result: TimedResult<i32, &str> =
            TimedResult::Completed(Outcome::Cancelled(CancelReason::shutdown()));

        let res = result.into_result();
        assert!(matches!(res, Err(TimedError::Cancelled(_))));
    }

    #[test]
    fn effective_deadline_uses_tighter() {
        let requested = Time::from_nanos(1000);
        let existing = Some(Time::from_nanos(500));

        // Existing is tighter
        assert_eq!(effective_deadline(requested, existing).as_nanos(), 500);

        // Requested is tighter
        let existing2 = Some(Time::from_nanos(2000));
        assert_eq!(effective_deadline(requested, existing2).as_nanos(), 1000);

        // No existing
        assert_eq!(effective_deadline(requested, None).as_nanos(), 1000);
    }

    #[test]
    fn timeout_config_resolve() {
        let config = TimeoutConfig::new(Time::from_nanos(1000));
        let existing = Some(Time::from_nanos(500));

        // Should use tighter (existing)
        assert_eq!(config.resolve(existing).as_nanos(), 500);

        // Absolute ignores existing
        let abs_config = TimeoutConfig::absolute(Time::from_nanos(1000));
        assert_eq!(abs_config.resolve(existing).as_nanos(), 1000);
    }

    #[test]
    fn make_timed_result_completed() {
        let outcome: Outcome<i32, &str> = Outcome::Ok(42);
        let deadline = Time::from_nanos(1000);

        let result = make_timed_result(outcome, deadline, true);
        assert!(result.is_completed());
    }

    #[test]
    fn make_timed_result_timed_out() {
        let outcome: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());
        let deadline = Time::from_nanos(1000);

        let result = make_timed_result(outcome, deadline, false);
        assert!(result.is_timed_out());
    }

    #[test]
    fn timed_error_display() {
        let err: TimedError<&str> = TimedError::Error("test");
        assert_eq!(err.to_string(), "test");

        let err: TimedError<&str> = TimedError::Cancelled(CancelReason::shutdown());
        assert!(err.to_string().contains("cancelled"));

        let err: TimedError<&str> = TimedError::TimedOut(TimeoutError::new(Time::from_nanos(1000)));
        assert!(err.to_string().contains("timed out"));
    }

    #[test]
    fn timeout_clone_and_copy() {
        let t1 = Timeout::<()>::new(Time::from_nanos(1000));
        let t2 = t1; // Copy
        let t3 = t1; // Also copy (Clone is implied by Copy)

        assert_eq!(t1.deadline, t2.deadline);
        assert_eq!(t1.deadline, t3.deadline);
    }

    // ========== Timeout-race interaction tests ==========

    #[test]
    fn test_timeout_race_complete_before_deadline() {
        // Operation completes before deadline: should be Completed
        let outcome: Outcome<i32, &str> = Outcome::Ok(42);
        let deadline = Time::from_nanos(5000);
        let result = make_timed_result(outcome, deadline, true);

        assert!(result.is_completed());
        assert!(!result.is_timed_out());
        assert_eq!(result.into_result().unwrap(), 42);
    }

    #[test]
    fn test_timeout_race_deadline_fires_first() {
        // Operation did not complete before deadline: should be TimedOut
        let outcome: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());
        let deadline = Time::from_nanos(1000);
        let result = make_timed_result(outcome, deadline, false);

        assert!(result.is_timed_out());
        assert!(!result.is_completed());
        let err = result.into_result().unwrap_err();
        assert!(matches!(err, TimedError::TimedOut(_)));
    }

    #[test]
    fn test_timeout_race_error_outcome_before_deadline() {
        // Operation errors before deadline: Completed with error
        let outcome: Outcome<i32, &str> = Outcome::Err("db failure");
        let deadline = Time::from_nanos(5000);
        let result = make_timed_result(outcome, deadline, true);

        assert!(result.is_completed());
        let err = result.into_result().unwrap_err();
        assert!(matches!(err, TimedError::Error("db failure")));
    }

    #[test]
    fn test_timeout_race_panic_outcome_before_deadline() {
        // Operation panics before deadline: Completed with panic
        let outcome: Outcome<i32, &str> =
            Outcome::Panicked(crate::types::outcome::PanicPayload::new("boom"));
        let deadline = Time::from_nanos(5000);
        let result = make_timed_result(outcome, deadline, true);

        assert!(result.is_completed());
        let err = result.into_result().unwrap_err();
        assert!(matches!(err, TimedError::Panicked(_)));
    }

    #[test]
    fn test_timeout_race_cancelled_outcome_before_deadline() {
        // Operation cancelled externally (not timeout) before deadline
        let outcome: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::shutdown());
        let deadline = Time::from_nanos(5000);
        let result = make_timed_result(outcome, deadline, true);

        assert!(result.is_completed());
        let err = result.into_result().unwrap_err();
        assert!(matches!(err, TimedError::Cancelled(_)));
    }

    #[test]
    fn test_timeout_into_outcome_timeout_becomes_cancelled() {
        // TimedOut converts to Cancelled outcome (timeout semantics)
        let result: TimedResult<i32, &str> =
            TimedResult::TimedOut(TimeoutError::new(Time::from_nanos(1000)));
        let outcome = result.into_outcome();
        assert!(outcome.is_cancelled());
    }

    // ========== Zero-duration timeout ==========

    #[test]
    fn test_zero_duration_timeout() {
        let now = Time::ZERO;
        let timeout = Timeout::<()>::after_nanos(now, 0);
        assert_eq!(timeout.deadline, Time::ZERO);
        // Zero-duration timeout is immediately expired
        assert!(timeout.is_expired(now));
        assert_eq!(timeout.remaining(now), Duration::ZERO);
    }

    #[test]
    fn test_zero_duration_timeout_from_millis() {
        let now = Time::from_nanos(5000);
        let timeout = Timeout::<()>::after_millis(now, 0);
        assert_eq!(timeout.deadline.as_nanos(), 5000);
        assert!(timeout.is_expired(now));
    }

    // ========== Boundary timing ==========

    #[test]
    fn test_timeout_boundary_exact_deadline() {
        // now == deadline: should be expired
        let t = Time::from_nanos(1000);
        let timeout = Timeout::<()>::new(t);
        assert!(timeout.is_expired(t));
        assert_eq!(timeout.remaining(t), Duration::ZERO);
    }

    #[test]
    fn test_timeout_boundary_one_nano_before() {
        let deadline = Time::from_nanos(1000);
        let now = Time::from_nanos(999);
        let timeout = Timeout::<()>::new(deadline);
        assert!(!timeout.is_expired(now));
        assert_eq!(timeout.remaining(now), Duration::from_nanos(1));
    }

    #[test]
    fn test_timeout_boundary_one_nano_after() {
        let deadline = Time::from_nanos(1000);
        let now = Time::from_nanos(1001);
        let timeout = Timeout::<()>::new(deadline);
        assert!(timeout.is_expired(now));
        assert_eq!(timeout.remaining(now), Duration::ZERO);
    }

    // ========== Nested timeouts (LAW-TIMEOUT-MIN) ==========

    #[test]
    fn test_nested_timeout_inner_tighter() {
        let outer = Time::from_nanos(5000);
        let inner = Time::from_nanos(2000);
        // Inner is tighter: effective = inner
        assert_eq!(effective_deadline(outer, Some(inner)).as_nanos(), 2000);
    }

    #[test]
    fn test_nested_timeout_outer_tighter() {
        let outer = Time::from_nanos(2000);
        let inner = Time::from_nanos(5000);
        // Outer is tighter: effective = outer
        assert_eq!(effective_deadline(outer, Some(inner)).as_nanos(), 2000);
    }

    #[test]
    fn test_nested_timeout_equal_deadlines() {
        let d = Time::from_nanos(3000);
        assert_eq!(effective_deadline(d, Some(d)).as_nanos(), 3000);
    }

    #[test]
    fn test_nested_timeout_none_existing() {
        let requested = Time::from_nanos(4000);
        assert_eq!(effective_deadline(requested, None).as_nanos(), 4000);
    }

    #[test]
    fn test_triple_nested_timeout_min_wins() {
        // timeout(d1, timeout(d2, timeout(d3, f))) ≃ timeout(min(d1,d2,d3), f)
        let d1 = Time::from_nanos(5000);
        let d2 = Time::from_nanos(3000);
        let d3 = Time::from_nanos(7000);

        // Apply innermost first: effective(d3, None) = d3
        let eff1 = effective_deadline(d3, None);
        // Then: effective(d2, Some(d3)) = min(d2, d3) = d2
        let eff2 = effective_deadline(d2, Some(eff1));
        // Then: effective(d1, Some(eff2)) = min(d1, d2) = d2
        let eff3 = effective_deadline(d1, Some(eff2));

        assert_eq!(eff3.as_nanos(), 3000); // min of all three
    }

    // ========== TimeoutConfig tests ==========

    #[test]
    fn test_timeout_config_effective_respects_tighter() {
        let config = TimeoutConfig::new(Time::from_nanos(5000));
        // Existing is tighter
        assert_eq!(
            config.resolve(Some(Time::from_nanos(2000))).as_nanos(),
            2000
        );
        // Existing is looser
        assert_eq!(
            config.resolve(Some(Time::from_nanos(8000))).as_nanos(),
            5000
        );
    }

    #[test]
    fn test_timeout_config_absolute_ignores_existing() {
        let config = TimeoutConfig::absolute(Time::from_nanos(5000));
        // Even though existing is tighter, absolute ignores it
        assert_eq!(
            config.resolve(Some(Time::from_nanos(2000))).as_nanos(),
            5000
        );
    }

    #[test]
    fn test_timeout_config_equality() {
        let a = TimeoutConfig::new(Time::from_nanos(1000));
        let b = TimeoutConfig::new(Time::from_nanos(1000));
        let c = TimeoutConfig::absolute(Time::from_nanos(1000));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ========== TimeoutError edge cases ==========

    #[test]
    fn test_timeout_error_into_cancel_reason() {
        let err = TimeoutError::new(Time::from_nanos(1000));
        let reason = err.into_cancel_reason();
        assert!(matches!(
            reason.kind(),
            crate::types::cancel::CancelKind::Timeout
        ));
    }

    #[test]
    fn test_timeout_error_equality() {
        let a = TimeoutError::new(Time::from_nanos(1000));
        let b = TimeoutError::new(Time::from_nanos(1000));
        let c = TimeoutError::new(Time::from_nanos(2000));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ========== Saturating arithmetic edge cases ==========

    #[test]
    fn test_timeout_after_nanos_saturating() {
        let now = Time::from_nanos(u64::MAX - 10);
        let timeout = Timeout::<()>::after_nanos(now, 100);
        // Should saturate, not overflow
        assert!(timeout.deadline.as_nanos() >= now.as_nanos());
    }

    #[test]
    fn test_timeout_after_secs_large_value() {
        let now = Time::ZERO;
        let timeout = Timeout::<()>::after_secs(now, 1_000_000);
        assert_eq!(
            timeout.deadline.as_nanos(),
            1_000_000u64.saturating_mul(1_000_000_000)
        );
    }
}
