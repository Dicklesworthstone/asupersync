//! Four-valued outcome type with severity lattice.
//!
//! The outcome type represents the result of a concurrent operation:
//!
//! - `Ok(T)`: Success with value
//! - `Err(E)`: Application error
//! - `Cancelled(CancelReason)`: Operation was cancelled
//! - `Panicked(PanicPayload)`: Task panicked
//!
//! These form a severity lattice: `Ok < Err < Cancelled < Panicked`
//!
//! When aggregating outcomes (e.g., from joined tasks), the worst outcome wins.

use super::cancel::CancelReason;
use core::fmt;

/// Payload from a caught panic.
///
/// This wraps the panic value for safe transport across task boundaries.
#[derive(Debug, Clone)]
pub struct PanicPayload {
    message: String,
}

impl PanicPayload {
    /// Creates a new panic payload with the given message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the panic message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PanicPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "panic: {}", self.message)
    }
}

/// The four-valued outcome of a concurrent operation.
///
/// Forms a severity lattice where worse outcomes dominate:
/// `Ok < Err < Cancelled < Panicked`
#[derive(Debug, Clone)]
pub enum Outcome<T, E> {
    /// Success with a value.
    Ok(T),
    /// Application-level error.
    Err(E),
    /// The operation was cancelled.
    Cancelled(CancelReason),
    /// The operation panicked.
    Panicked(PanicPayload),
}

impl<T, E> Outcome<T, E> {
    /// Returns the severity level of this outcome (0 = Ok, 3 = Panicked).
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            Self::Ok(_) => 0,
            Self::Err(_) => 1,
            Self::Cancelled(_) => 2,
            Self::Panicked(_) => 3,
        }
    }

    /// Returns true if this is a terminal outcome (any non-pending state).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        true // All variants are terminal
    }

    /// Returns true if this outcome is `Ok`.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }

    /// Returns true if this outcome is `Err`.
    #[must_use]
    pub const fn is_err(&self) -> bool {
        matches!(self, Self::Err(_))
    }

    /// Returns true if this outcome is `Cancelled`.
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }

    /// Returns true if this outcome is `Panicked`.
    #[must_use]
    pub const fn is_panicked(&self) -> bool {
        matches!(self, Self::Panicked(_))
    }

    /// Converts this outcome to a standard Result, with cancellation and panic as errors.
    ///
    /// This is useful when interfacing with code that expects `Result`.
    pub fn into_result(self) -> Result<T, OutcomeError<E>> {
        match self {
            Self::Ok(v) => Ok(v),
            Self::Err(e) => Err(OutcomeError::Err(e)),
            Self::Cancelled(r) => Err(OutcomeError::Cancelled(r)),
            Self::Panicked(p) => Err(OutcomeError::Panicked(p)),
        }
    }

    /// Maps the success value using the provided function.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Outcome<U, E> {
        match self {
            Self::Ok(v) => Outcome::Ok(f(v)),
            Self::Err(e) => Outcome::Err(e),
            Self::Cancelled(r) => Outcome::Cancelled(r),
            Self::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Maps the error value using the provided function.
    pub fn map_err<F2, G: FnOnce(E) -> F2>(self, g: G) -> Outcome<T, F2> {
        match self {
            Self::Ok(v) => Outcome::Ok(v),
            Self::Err(e) => Outcome::Err(g(e)),
            Self::Cancelled(r) => Outcome::Cancelled(r),
            Self::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Returns the success value or panics.
    ///
    /// # Panics
    ///
    /// Panics if the outcome is not `Ok`.
    #[track_caller]
    pub fn unwrap(self) -> T
    where
        E: fmt::Debug,
    {
        match self {
            Self::Ok(v) => v,
            Self::Err(e) => panic!("called `Outcome::unwrap()` on an `Err` value: {e:?}"),
            Self::Cancelled(r) => {
                panic!("called `Outcome::unwrap()` on a `Cancelled` value: {r:?}")
            }
            Self::Panicked(p) => panic!("called `Outcome::unwrap()` on a `Panicked` value: {p}"),
        }
    }

    /// Returns the success value or a default.
    pub fn unwrap_or(self, default: T) -> T {
        match self {
            Self::Ok(v) => v,
            _ => default,
        }
    }

    /// Returns the success value or computes it from a closure.
    pub fn unwrap_or_else<F: FnOnce() -> T>(self, f: F) -> T {
        match self {
            Self::Ok(v) => v,
            _ => f(),
        }
    }
}

impl<T, E> From<Result<T, E>> for Outcome<T, E> {
    fn from(result: Result<T, E>) -> Self {
        match result {
            Ok(v) => Self::Ok(v),
            Err(e) => Self::Err(e),
        }
    }
}

/// Error type for converting Outcome to Result.
#[derive(Debug, Clone)]
pub enum OutcomeError<E> {
    /// Application error.
    Err(E),
    /// Cancellation.
    Cancelled(CancelReason),
    /// Panic.
    Panicked(PanicPayload),
}

impl<E: fmt::Display> fmt::Display for OutcomeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Err(e) => write!(f, "{e}"),
            Self::Cancelled(r) => write!(f, "cancelled: {r:?}"),
            Self::Panicked(p) => write!(f, "{p}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for OutcomeError<E> {}

/// Compares two outcomes by severity and returns the worse one.
///
/// This implements the lattice join operation.
pub fn join_outcomes<T, E>(a: Outcome<T, E>, b: Outcome<T, E>) -> Outcome<T, E> {
    if a.severity() >= b.severity() {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("panic"));

        assert!(ok.severity() < err.severity());
        assert!(err.severity() < cancelled.severity());
        assert!(cancelled.severity() < panicked.severity());
    }

    #[test]
    fn join_takes_worse() {
        let ok: Outcome<i32, &str> = Outcome::Ok(1);
        let err: Outcome<i32, &str> = Outcome::Err("error");

        let joined = join_outcomes(ok, err);
        assert!(joined.is_err());
    }
}
