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

#[inline]
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
    #[inline]
    #[must_use]
    pub const fn new(deadline: Time) -> Self {
        Self {
            deadline,
            _t: PhantomData,
        }
    }

    /// Creates a timeout from a duration in nanoseconds from now.
    #[inline]
    #[must_use]
    pub const fn after_nanos(now: Time, nanos: u64) -> Self {
        Self::new(now.saturating_add_nanos(nanos))
    }

    /// Creates a timeout from a duration in milliseconds from now.
    #[inline]
    #[must_use]
    pub const fn after_millis(now: Time, millis: u64) -> Self {
        Self::after_nanos(now, millis.saturating_mul(1_000_000))
    }

    /// Creates a timeout from a duration in seconds from now.
    #[inline]
    #[must_use]
    pub const fn after_secs(now: Time, secs: u64) -> Self {
        Self::after_nanos(now, secs.saturating_mul(1_000_000_000))
    }

    /// Creates a timeout from a std Duration.
    #[inline]
    #[must_use]
    pub fn after(now: Time, duration: Duration) -> Self {
        Self::after_nanos(now, duration_to_nanos(duration))
    }

    /// Returns true if the deadline has passed.
    #[inline]
    #[must_use]
    pub fn is_expired(&self, now: Time) -> bool {
        now >= self.deadline
    }

    /// Returns the remaining time until the deadline, or zero if expired.
    #[inline]
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
    #[inline]
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
    #[inline]
    #[must_use]
    pub const fn new(deadline: Time) -> Self {
        Self {
            deadline,
            message: None,
        }
    }

    /// Creates a new timeout error with a message.
    #[inline]
    #[must_use]
    pub const fn with_message(deadline: Time, message: &'static str) -> Self {
        Self {
            deadline,
            message: Some(message),
        }
    }

    /// Converts to a CancelReason for use in Outcome::Cancelled.
    #[inline]
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
    #[inline]
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self, Self::Completed(_))
    }

    /// Returns true if the operation timed out.
    #[inline]
    #[must_use]
    pub const fn is_timed_out(&self) -> bool {
        matches!(self, Self::TimedOut(_))
    }

    /// Converts to an Outcome, treating timeout as cancellation.
    #[inline]
    pub fn into_outcome(self) -> Outcome<T, E> {
        match self {
            Self::Completed(outcome) => outcome,
            Self::TimedOut(err) => Outcome::Cancelled(err.into_cancel_reason()),
        }
    }

    /// Converts to a Result, treating timeout as an error.
    #[inline]
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
#[inline]
#[must_use]
pub fn make_timed_result<T, E>(
    outcome: Outcome<T, E>,
    deadline: Time,
    completed_in_time: bool,
) -> TimedResult<T, E> {
    if completed_in_time {
        return TimedResult::Completed(outcome);
    }

    match outcome {
        Outcome::Ok(_) | Outcome::Err(_) | Outcome::Panicked(_) => {
            // Do not drop successful results, application errors, or panics.
            // Even if the deadline passed, the operation reached a terminal state
            // other than cancellation, so we surface that outcome to prevent data loss.
            TimedResult::Completed(outcome)
        }
        Outcome::Cancelled(_) => {
            // It was cancelled (presumably by the timeout or parent).
            TimedResult::TimedOut(TimeoutError::new(deadline))
        }
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
#[inline]
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
    #[inline]
    #[must_use]
    pub const fn new(deadline: Time) -> Self {
        Self {
            deadline,
            use_effective: true,
        }
    }

    /// Creates a configuration that ignores nested timeouts.
    #[inline]
    #[must_use]
    pub const fn absolute(deadline: Time) -> Self {
        Self {
            deadline,
            use_effective: false,
        }
    }

    /// Returns the final deadline to use, considering any existing deadline.
    #[inline]
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
    // Basic syntax: timeout!(duration, future) requires ambient context, but
    // for now we require explicit cx in asupersync. We provide a dummy
    // implementation that panics to enforce cx passing.
    ($duration:expr, $future:expr) => {{ compile_error!("timeout! requires a Cx context: timeout!(cx, duration, future)") }};

    // With explicit cx: timeout!(cx, duration, future)
    ($cx:expr, $duration:expr, $future:expr) => {
        $crate::time::TimeoutFuture::after($cx.now(), $duration, $future)
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
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
    fn test_timeout_race_deadline_fires_first_preserves_panics() {
        // If the timed-out branch panics during drain, do not mask it as TimedOut.
        let outcome: Outcome<i32, &str> =
            Outcome::Panicked(crate::types::outcome::PanicPayload::new("boom"));
        let deadline = Time::from_nanos(1000);
        let result = make_timed_result(outcome, deadline, false);

        assert!(result.is_completed());
        let err = result.into_result().unwrap_err();
        assert!(matches!(err, TimedError::Panicked(_)));
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

    // =========================================================================
    // Metamorphic Relations for Timeout Race Invariants (asupersync-uj8gl0)
    // =========================================================================

    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum MockOperationOutcome {
        Complete(i32),
        Error(&'static str),
        Cancel,
        Panic,
    }

    impl MockOperationOutcome {
        fn into_outcome(self) -> Outcome<i32, &'static str> {
            match self {
                Self::Complete(val) => Outcome::Ok(val),
                Self::Error(msg) => Outcome::Err(msg),
                Self::Cancel => Outcome::Cancelled(CancelReason::shutdown()),
                Self::Panic => {
                    Outcome::Panicked(crate::types::outcome::PanicPayload::new("test panic"))
                }
            }
        }
    }

    fn mock_operation_strategy() -> impl Strategy<Value = MockOperationOutcome> {
        prop_oneof![
            any::<i16>().prop_map(|v| MockOperationOutcome::Complete(i32::from(v))),
            Just(MockOperationOutcome::Error("mock error")),
            Just(MockOperationOutcome::Cancel),
            Just(MockOperationOutcome::Panic),
        ]
    }

    /// MR1: Timeout idempotence - timeout fires exactly once, never double
    ///
    /// When a timeout deadline is reached, the timeout mechanism should fire
    /// exactly once. Repeated queries about expiration should be consistent.
    #[test]
    fn metamorphic_timeout_single_fire_idempotence() {
        proptest!(|(
            base_time in 0u64..1_000_000_000,
            timeout_duration in 1u64..10_000_000,
            elapsed_time in 10_000_000u64..20_000_000,
        )| {
            let now = Time::from_nanos(base_time);
            let timeout = Timeout::<()>::after_nanos(now, timeout_duration);
            let future_time = Time::from_nanos(base_time + elapsed_time);

            // Check expired multiple times - should be stable
            let expired_1 = timeout.is_expired(future_time);
            let expired_2 = timeout.is_expired(future_time);
            let expired_3 = timeout.is_expired(future_time);

            prop_assert_eq!(expired_1, expired_2);
            prop_assert_eq!(expired_2, expired_3);

            // Remaining time should also be stable
            let remaining_1 = timeout.remaining(future_time);
            let remaining_2 = timeout.remaining(future_time);
            prop_assert_eq!(remaining_1, remaining_2);

            // If elapsed > timeout_duration, should be expired
            if elapsed_time > timeout_duration {
                prop_assert!(expired_1);
                prop_assert_eq!(remaining_1, Duration::ZERO);
            }
        });
    }

    /// MR2: Cancel-before-timeout consistency
    ///
    /// If an operation is cancelled before the timeout fires, the result should
    /// be Completed(Cancelled), not TimedOut. The timing determines the outcome type.
    #[test]
    fn metamorphic_cancel_before_timeout_consistency() {
        proptest!(|(
            base_time in 0u64..1_000_000_000,
            timeout_duration in 10_000_000u64..50_000_000,
            completion_time in 1_000_000u64..9_999_999,
        )| {
            let now = Time::from_nanos(base_time);
            let deadline = now.saturating_add_nanos(timeout_duration);
            let completion_offset = Time::from_nanos(base_time + completion_time);

            // Operation completes (via cancellation) before timeout
            let cancelled_outcome: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::shutdown());
            let completed_in_time = completion_offset < deadline;

            prop_assert!(completed_in_time); // Test setup verification

            let result = make_timed_result(cancelled_outcome, deadline, completed_in_time);

            // Should be Completed(Cancelled), not TimedOut
            prop_assert!(result.is_completed());
            prop_assert!(!result.is_timed_out());

            match result {
                TimedResult::Completed(outcome) => {
                    prop_assert!(outcome.is_cancelled());
                }
                TimedResult::TimedOut(_) => {
                    prop_assert!(false, "Early cancellation should not be TimedOut");
                }
            }
        });
    }

    /// MR3: Concurrent timeout race determinism
    ///
    /// When multiple timeouts race, the earliest deadline should always win.
    /// The effective_deadline function implements this min() semantics.
    #[test]
    fn metamorphic_concurrent_timeout_race_determinism() {
        proptest!(|(
            timeout_durations in prop::collection::vec(1_000_000u64..100_000_000, 2..8),
            base_time in 0u64..1_000_000_000,
        )| {
            let now = Time::from_nanos(base_time);

            // Create multiple timeout deadlines
            let deadlines: Vec<Time> = timeout_durations.iter()
                .map(|&duration| now.saturating_add_nanos(duration))
                .collect();

            // Find the earliest deadline manually
            let min_deadline = deadlines.iter().min().copied().unwrap();

            // Apply effective_deadline reduction sequentially
            let mut effective = deadlines[0];
            for &deadline in deadlines.iter().skip(1) {
                effective = effective_deadline(deadline, Some(effective));
            }

            prop_assert_eq!(effective, min_deadline);

            // Apply in different orders - should be commutative/associative
            let mut reverse_effective = deadlines[deadlines.len() - 1];
            for &deadline in deadlines.iter().rev().skip(1) {
                reverse_effective = effective_deadline(deadline, Some(reverse_effective));
            }

            prop_assert_eq!(effective, reverse_effective);

            // The minimum deadline should be <= all original deadlines
            for &deadline in &deadlines {
                prop_assert!(effective.as_nanos() <= deadline.as_nanos());
            }
        });
    }

    /// MR4: Nested timeout composition law (LAW-TIMEOUT-MIN)
    ///
    /// timeout(d1, timeout(d2, f)) ≃ timeout(min(d1, d2), f)
    /// This should hold regardless of which timeout is outer/inner.
    #[test]
    fn metamorphic_nested_timeout_composition_law() {
        proptest!(|(
            d1 in 1_000_000u64..50_000_000,
            d2 in 1_000_000u64..50_000_000,
            d3 in 1_000_000u64..50_000_000,
            base_time in 0u64..1_000_000_000,
        )| {
            let now = Time::from_nanos(base_time);
            let deadline1 = now.saturating_add_nanos(d1);
            let deadline2 = now.saturating_add_nanos(d2);
            let deadline3 = now.saturating_add_nanos(d3);

            // timeout(d1, timeout(d2, f)) = effective_deadline(d1, Some(d2))
            let nested_12 = effective_deadline(deadline1, Some(deadline2));

            // timeout(d2, timeout(d1, f)) = effective_deadline(d2, Some(d1))
            let nested_21 = effective_deadline(deadline2, Some(deadline1));

            // Both should equal min(d1, d2)
            let min_12 = if deadline1.as_nanos() <= deadline2.as_nanos() {
                deadline1
            } else {
                deadline2
            };

            prop_assert_eq!(nested_12, min_12);
            prop_assert_eq!(nested_21, min_12);
            prop_assert_eq!(nested_12, nested_21);

            // Triple nesting: timeout(d1, timeout(d2, timeout(d3, f)))
            let triple_nested = effective_deadline(deadline1,
                Some(effective_deadline(deadline2, Some(deadline3))));
            let min_123 = [deadline1, deadline2, deadline3].iter().min().copied().unwrap();

            prop_assert_eq!(triple_nested, min_123);
        });
    }

    /// MR5: Operation completion vs timeout race correctness
    ///
    /// When operation and timeout race, the first to complete should win.
    /// Make_timed_result should preserve this race outcome correctly.
    #[test]
    fn metamorphic_operation_timeout_race_correctness() {
        proptest!(|(
            operation_outcome in mock_operation_strategy(),
            timeout_duration in 10_000_000u64..100_000_000,
            completion_duration in 1_000_000u64..150_000_000,
            base_time in 0u64..1_000_000_000,
        )| {
            let now = Time::from_nanos(base_time);
            let deadline = now.saturating_add_nanos(timeout_duration);
            let completion_time = now.saturating_add_nanos(completion_duration);

            let outcome = operation_outcome.into_outcome();
            let completed_in_time = completion_time < deadline;

            let result = make_timed_result(outcome.clone(), deadline, completed_in_time);

            if completed_in_time {
                // Operation won the race - should be Completed regardless of outcome type
                prop_assert!(result.is_completed());
                prop_assert!(!result.is_timed_out());

                match result {
                    TimedResult::Completed(completed_outcome) => {
                        // Should preserve the original outcome
                        prop_assert_eq!(format!("{:?}", completed_outcome), format!("{:?}", outcome));
                    }
                    TimedResult::TimedOut(_) => {
                        prop_assert!(false, "Operation that completed in time should not be TimedOut");
                    }
                }
            } else {
                // Timeout won the race
                match &outcome {
                    Outcome::Ok(_) | Outcome::Err(_) | Outcome::Panicked(_) => {
                        // Even if deadline passed, preserve non-cancellation terminal states
                        prop_assert!(result.is_completed());
                        prop_assert!(!result.is_timed_out());
                    }
                    Outcome::Cancelled(_) => {
                        // Cancellation + deadline passed = timeout
                        prop_assert!(result.is_timed_out());
                        prop_assert!(!result.is_completed());
                    }
                }
            }
        });
    }

    /// MR6: Timeout drain invariant preservation
    ///
    /// TimedOut results always convert to Cancelled outcomes, preserving
    /// the timeout→cancellation semantic mapping for downstream drain logic.
    #[test]
    fn metamorphic_timeout_drain_invariant_preservation() {
        proptest!(|(
            timeout_duration in 1_000_000u64..100_000_000,
            base_time in 0u64..1_000_000_000,
            message_present in any::<bool>(),
        )| {
            let now = Time::from_nanos(base_time);
            let deadline = now.saturating_add_nanos(timeout_duration);

            let timeout_error = if message_present {
                TimeoutError::with_message(deadline, "operation timed out")
            } else {
                TimeoutError::new(deadline)
            };

            let timed_result: TimedResult<i32, &str> = TimedResult::TimedOut(timeout_error.clone());

            prop_assert!(timed_result.is_timed_out());
            prop_assert!(!timed_result.is_completed());

            // Convert to outcome - should be Cancelled with timeout reason
            let outcome = timed_result.clone().into_outcome();
            prop_assert!(outcome.is_cancelled());

            if let Outcome::Cancelled(reason) = outcome {
                prop_assert!(matches!(reason.kind(), crate::types::cancel::CancelKind::Timeout));
            } else {
                prop_assert!(false, "TimedOut should convert to Cancelled outcome");
            }

            // Convert to Result - should be TimedOut error
            let result = timed_result.into_result();
            prop_assert!(result.is_err());

            if let Err(err) = result {
                prop_assert!(matches!(err, TimedError::TimedOut(_)));

                if let TimedError::TimedOut(timeout_err) = err {
                    prop_assert_eq!(timeout_err.deadline, deadline);
                    prop_assert_eq!(timeout_err.message.is_some(), message_present);
                }
            }
        });
    }

    /// MR7: Timeout expiration boundary consistency
    ///
    /// The transition from not-expired to expired should be deterministic
    /// and happen exactly at the deadline boundary.
    #[test]
    fn metamorphic_timeout_boundary_consistency() {
        proptest!(|(
            base_time in 1_000_000u64..1_000_000_000,
            timeout_duration in 1_000_000u64..100_000_000,
        )| {
            let now = Time::from_nanos(base_time);
            let timeout = Timeout::<()>::after_nanos(now, timeout_duration);
            let deadline = now.saturating_add_nanos(timeout_duration);

            prop_assert_eq!(timeout.deadline, deadline);

            // Just before deadline: not expired
            let before = Time::from_nanos(deadline.as_nanos().saturating_sub(1));
            prop_assert!(!timeout.is_expired(before));
            prop_assert!(timeout.remaining(before) > Duration::ZERO);

            // At deadline: expired
            prop_assert!(timeout.is_expired(deadline));
            prop_assert_eq!(timeout.remaining(deadline), Duration::ZERO);

            // After deadline: still expired
            let after = Time::from_nanos(deadline.as_nanos().saturating_add(1));
            prop_assert!(timeout.is_expired(after));
            prop_assert_eq!(timeout.remaining(after), Duration::ZERO);

            // Remaining time should decrease monotonically before deadline
            if before < deadline {
                let remaining_before = timeout.remaining(before);
                let remaining_at = timeout.remaining(deadline);
                prop_assert!(remaining_before >= remaining_at);
            }
        });
    }

    /// MR8: TimeoutConfig resolution invariants
    ///
    /// TimeoutConfig resolution should respect the use_effective flag consistently
    /// and always return deadlines that make logical sense.
    #[test]
    fn metamorphic_timeout_config_resolution_invariants() {
        proptest!(|(
            requested_time in 1_000_000u64..100_000_000,
            existing_time in 1_000_000u64..100_000_000,
            base_time in 0u64..1_000_000_000,
            use_effective in any::<bool>(),
        )| {
            let now = Time::from_nanos(base_time);
            let requested = now.saturating_add_nanos(requested_time);
            let existing = now.saturating_add_nanos(existing_time);

            let config = if use_effective {
                TimeoutConfig::new(requested)
            } else {
                TimeoutConfig::absolute(requested)
            };

            let resolved_with_existing = config.resolve(Some(existing));
            let resolved_without_existing = config.resolve(None);

            // Without existing deadline, should always return requested
            prop_assert_eq!(resolved_without_existing, requested);

            if use_effective {
                // Effective mode: should return tighter deadline
                let expected = if requested.as_nanos() <= existing.as_nanos() {
                    requested
                } else {
                    existing
                };
                prop_assert_eq!(resolved_with_existing, expected);

                // Resolved should be <= both inputs
                prop_assert!(resolved_with_existing.as_nanos() <= requested.as_nanos());
                prop_assert!(resolved_with_existing.as_nanos() <= existing.as_nanos());
            } else {
                // Absolute mode: should always return requested, ignoring existing
                prop_assert_eq!(resolved_with_existing, requested);
            }

            // Applying the same config multiple times should be idempotent
            let resolved_twice = if use_effective {
                TimeoutConfig::new(resolved_with_existing).resolve(Some(existing))
            } else {
                TimeoutConfig::absolute(resolved_with_existing).resolve(Some(existing))
            };
            prop_assert_eq!(resolved_twice, resolved_with_existing);
        });
    }
}
