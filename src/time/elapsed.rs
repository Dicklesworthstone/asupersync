//! Elapsed error type for timeout operations.
//!
//! The [`Elapsed`] error is returned when a timeout expires before
//! the wrapped operation completes.

use crate::types::Time;
use core::fmt;

/// Error returned when a timeout elapses.
///
/// This error indicates that a [`TimeoutFuture`](super::TimeoutFuture)
/// did not complete before its deadline. The inner future was dropped
/// without producing a value.
///
/// # Example
///
/// ```
/// use asupersync::time::Elapsed;
/// use asupersync::types::Time;
///
/// let elapsed = Elapsed::new(Time::from_secs(5));
/// assert_eq!(elapsed.deadline(), Time::from_secs(5));
/// println!("{elapsed}"); // "deadline has elapsed at Time(5000000000ns)"
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Elapsed {
    /// The deadline that was exceeded.
    deadline: Time,
}

impl Elapsed {
    /// Creates a new `Elapsed` error with the given deadline.
    #[inline]
    #[must_use]
    pub const fn new(deadline: Time) -> Self {
        Self { deadline }
    }

    /// Returns the deadline that was exceeded.
    #[inline]
    #[must_use]
    pub const fn deadline(&self) -> Time {
        self.deadline
    }

    /// Returns the deadline as nanoseconds since the epoch.
    #[inline]
    #[must_use]
    pub const fn deadline_nanos(&self) -> u64 {
        self.deadline.as_nanos()
    }
}

impl fmt::Display for Elapsed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "deadline has elapsed at {:?}", self.deadline)
    }
}

impl std::error::Error for Elapsed {}

#[cfg(test)]
#[path = "elapsed_inline_tests.rs"]
mod tests;
