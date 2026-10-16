//! Timeout combinator: add a deadline to an operation.
//!
//! The timeout combinator races an operation against a deadline. This module
//! holds the deadline value type and the outcome folders; the executing
//! entry points are:
//!
//! - [`crate::cx::Scope::timeout`], which spawns the operation as a region
//!   task and, when the deadline wins, protocol-cancels **and drains** it
//!   before returning (a late terminal outcome is surfaced through
//!   [`make_timed_result`], never lost);
//! - [`crate::time::timeout`], the lightweight inline form, which **drops**
//!   the inner future when the deadline wins and returns `Err(Elapsed)`.
//!
//! This is semantically equivalent to: `race(operation, sleep(duration))`
//!
//! # Draining Is a Property of the Entry Point
//!
//! Only `Scope::timeout` guarantees that a timed-out operation is cancelled
//! and drained before the call returns. `time::timeout` relies on `Drop` for
//! cleanup, so an operation holding a runtime obligation must use the scope
//! form (or be drained by its owner) to keep region close honest.
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
    let nanos = duration.as_nanos();
    if nanos <= u128::from(u64::MAX) {
        nanos as u64
    } else {
        u64::MAX
    }
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
/// `timeout!(cx, duration, future)` expands to
/// [`crate::time::TimeoutFuture::after`] starting at `cx.now()`: it races the
/// future against a sleep and returns `Ok(value)` if the future completes
/// first, or `Err(Elapsed)` once the deadline passes.
///
/// # Semantics
///
/// ```ignore
/// let result = timeout!(cx, Duration::from_secs(5), operation).await;
///
/// match result {
///     Ok(value) => println!("Completed: {:?}", value),
///     Err(elapsed) => println!("Timed out: {:?}", elapsed),
/// }
/// ```
///
/// # Cancellation Behavior
///
/// When the deadline passes, `timeout!` returns `Err(Elapsed)` without
/// draining the timed-out future: that future is dropped with the returned
/// `TimeoutFuture`, so cleanup it would run after observing cancellation does
/// not happen. Use [`crate::cx::Scope::timeout`] or
/// [`crate::Cx::race_drained_with_timeout`] when the operation must be
/// cancelled and its cleanup awaited before the call returns.
///
/// When the future completes first, the sleep is dropped.
#[macro_export]
macro_rules! timeout {
    // Basic syntax: timeout!(duration, future) would require ambient context.
    // Asupersync requires explicit Cx flow, so this arm is a compile-time
    // guard that points callers at the supported form.
    ($duration:expr, $future:expr) => {{ compile_error!("timeout! requires a Cx context: timeout!(cx, duration, future)") }};

    // With explicit cx: timeout!(cx, duration, future)
    ($cx:expr, $duration:expr, $future:expr) => {
        $crate::time::TimeoutFuture::after($cx.now(), $duration, $future)
    };
}

#[cfg(test)]
#[path = "timeout_inline_tests.rs"]
mod tests;
