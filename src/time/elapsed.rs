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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl Default for Elapsed {
    fn default() -> Self {
        Self::new(Time::ZERO)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;
    use crate::test_utils::init_test_logging;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn new_creates_with_deadline() {
        init_test("new_creates_with_deadline");
        let deadline = Time::from_secs(10);
        let elapsed = Elapsed::new(deadline);
        crate::assert_with_log!(
            elapsed.deadline() == deadline,
            "deadline matches",
            deadline,
            elapsed.deadline()
        );
        crate::test_complete!("new_creates_with_deadline");
    }

    #[test]
    fn deadline_nanos() {
        init_test("deadline_nanos");
        let elapsed = Elapsed::new(Time::from_millis(500));
        crate::assert_with_log!(
            elapsed.deadline_nanos() == 500_000_000,
            "deadline nanos",
            500_000_000u64,
            elapsed.deadline_nanos()
        );
        crate::test_complete!("deadline_nanos");
    }

    #[test]
    fn display_format() {
        init_test("display_format");
        let elapsed = Elapsed::new(Time::from_secs(5));
        let s = elapsed.to_string();
        crate::assert_with_log!(
            s.contains("elapsed"),
            "contains 'elapsed'",
            true,
            s.contains("elapsed")
        );
        crate::assert_with_log!(
            s.contains("5000000000"),
            "contains nanos",
            true,
            s.contains("5000000000")
        );
        crate::test_complete!("display_format");
    }

    #[test]
    fn default_is_zero() {
        init_test("default_is_zero");
        let elapsed = Elapsed::default();
        crate::assert_with_log!(
            elapsed.deadline() == Time::ZERO,
            "deadline zero",
            Time::ZERO,
            elapsed.deadline()
        );
        crate::test_complete!("default_is_zero");
    }

    #[test]
    fn clone_and_copy() {
        init_test("clone_and_copy");
        let e1 = Elapsed::new(Time::from_secs(1));
        let e2 = e1; // Copy
        let e3 = e1; // Also copy
        crate::assert_with_log!(e1 == e2, "e1 == e2", e2, e1);
        crate::assert_with_log!(e2 == e3, "e2 == e3", e3, e2);
        crate::test_complete!("clone_and_copy");
    }

    #[test]
    fn equality() {
        init_test("equality");
        let e1 = Elapsed::new(Time::from_secs(1));
        let e2 = Elapsed::new(Time::from_secs(1));
        let e3 = Elapsed::new(Time::from_secs(2));

        crate::assert_with_log!(e1 == e2, "e1 == e2", e2, e1);
        crate::assert_with_log!(e1 != e3, "e1 != e3", true, e1 != e3);
        crate::test_complete!("equality");
    }

    #[test]
    fn is_error() {
        init_test("is_error");
        let elapsed = Elapsed::new(Time::from_secs(1));
        // Verify it implements Error
        let _: &dyn std::error::Error = &elapsed;
        crate::test_complete!("is_error");
    }
}
