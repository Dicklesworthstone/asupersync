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

    // =========================================================================
    // Severity Ordering Tests
    // =========================================================================

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
    fn severity_values() {
        let ok: Outcome<(), ()> = Outcome::Ok(());
        let err: Outcome<(), ()> = Outcome::Err(());
        let cancelled: Outcome<(), ()> = Outcome::Cancelled(CancelReason::default());
        let panicked: Outcome<(), ()> = Outcome::Panicked(PanicPayload::new("test"));

        assert_eq!(ok.severity(), 0);
        assert_eq!(err.severity(), 1);
        assert_eq!(cancelled.severity(), 2);
        assert_eq!(panicked.severity(), 3);
    }

    // =========================================================================
    // Predicate Tests (is_ok, is_err, is_cancelled, is_panicked, is_terminal)
    // =========================================================================

    #[test]
    fn is_ok_predicate() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let err: Outcome<i32, &str> = Outcome::Err("error");

        assert!(ok.is_ok());
        assert!(!err.is_ok());
    }

    #[test]
    fn is_err_predicate() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let err: Outcome<i32, &str> = Outcome::Err("error");

        assert!(!ok.is_err());
        assert!(err.is_err());
    }

    #[test]
    fn is_cancelled_predicate() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());

        assert!(!ok.is_cancelled());
        assert!(cancelled.is_cancelled());
    }

    #[test]
    fn is_panicked_predicate() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("oops"));

        assert!(!ok.is_panicked());
        assert!(panicked.is_panicked());
    }

    #[test]
    fn is_terminal_always_true() {
        // All Outcome variants are terminal states
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("panic"));

        assert!(ok.is_terminal());
        assert!(err.is_terminal());
        assert!(cancelled.is_terminal());
        assert!(panicked.is_terminal());
    }

    // =========================================================================
    // Join Operation Tests (Lattice Laws)
    // =========================================================================

    #[test]
    fn join_takes_worse() {
        let ok: Outcome<i32, &str> = Outcome::Ok(1);
        let err: Outcome<i32, &str> = Outcome::Err("error");

        let joined = join_outcomes(ok, err);
        assert!(joined.is_err());
    }

    #[test]
    fn join_ok_with_ok_returns_first() {
        let a: Outcome<i32, &str> = Outcome::Ok(1);
        let b: Outcome<i32, &str> = Outcome::Ok(2);

        // When equal severity, first argument wins
        let result = join_outcomes(a, b);
        assert!(matches!(result, Outcome::Ok(1)));
    }

    #[test]
    fn join_err_with_cancelled_returns_cancelled() {
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());

        let result = join_outcomes(err, cancelled);
        assert!(result.is_cancelled());
    }

    #[test]
    fn join_panicked_dominates_all() {
        let ok: Outcome<i32, &str> = Outcome::Ok(1);
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("panic"));

        assert!(join_outcomes(ok, panicked.clone()).is_panicked());
        assert!(join_outcomes(err, panicked.clone()).is_panicked());
        assert!(join_outcomes(cancelled, panicked).is_panicked());
    }

    // =========================================================================
    // Map Operations Tests
    // =========================================================================

    #[test]
    fn map_transforms_ok_value() {
        let ok: Outcome<i32, &str> = Outcome::Ok(21);
        let mapped = ok.map(|x| x * 2);
        assert!(matches!(mapped, Outcome::Ok(42)));
    }

    #[test]
    fn map_preserves_err() {
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let mapped = err.map(|x| x * 2);
        assert!(matches!(mapped, Outcome::Err("error")));
    }

    #[test]
    fn map_preserves_cancelled() {
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        let mapped = cancelled.map(|x| x * 2);
        assert!(mapped.is_cancelled());
    }

    #[test]
    fn map_preserves_panicked() {
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("oops"));
        let mapped = panicked.map(|x| x * 2);
        assert!(mapped.is_panicked());
    }

    #[test]
    fn map_err_transforms_err_value() {
        let err: Outcome<i32, &str> = Outcome::Err("short");
        let mapped = err.map_err(str::len);
        assert!(matches!(mapped, Outcome::Err(5)));
    }

    #[test]
    fn map_err_preserves_ok() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let mapped = ok.map_err(str::len);
        assert!(matches!(mapped, Outcome::Ok(42)));
    }

    // =========================================================================
    // Unwrap Operations Tests
    // =========================================================================

    #[test]
    fn unwrap_returns_value_on_ok() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        assert_eq!(ok.unwrap(), 42);
    }

    #[test]
    #[should_panic(expected = "called `Outcome::unwrap()` on an `Err` value")]
    fn unwrap_panics_on_err() {
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let _ = err.unwrap();
    }

    #[test]
    #[should_panic(expected = "called `Outcome::unwrap()` on a `Cancelled` value")]
    fn unwrap_panics_on_cancelled() {
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        let _ = cancelled.unwrap();
    }

    #[test]
    #[should_panic(expected = "called `Outcome::unwrap()` on a `Panicked` value")]
    fn unwrap_panics_on_panicked() {
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("oops"));
        let _ = panicked.unwrap();
    }

    #[test]
    fn unwrap_or_returns_value_on_ok() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        assert_eq!(ok.unwrap_or(0), 42);
    }

    #[test]
    fn unwrap_or_returns_default_on_err() {
        let err: Outcome<i32, &str> = Outcome::Err("error");
        assert_eq!(err.unwrap_or(0), 0);
    }

    #[test]
    fn unwrap_or_returns_default_on_cancelled() {
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        assert_eq!(cancelled.unwrap_or(99), 99);
    }

    #[test]
    fn unwrap_or_else_computes_default_lazily() {
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let mut called = false;
        let result = err.unwrap_or_else(|| {
            called = true;
            42
        });
        assert!(called);
        assert_eq!(result, 42);
    }

    #[test]
    fn unwrap_or_else_doesnt_call_closure_on_ok() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let result = ok.unwrap_or_else(|| panic!("should not be called"));
        assert_eq!(result, 42);
    }

    // =========================================================================
    // into_result Conversion Tests
    // =========================================================================

    #[test]
    fn into_result_ok() {
        let ok: Outcome<i32, &str> = Outcome::Ok(42);
        let result = ok.into_result();
        assert!(matches!(result, Ok(42)));
    }

    #[test]
    fn into_result_err() {
        let err: Outcome<i32, &str> = Outcome::Err("error");
        let result = err.into_result();
        assert!(matches!(result, Err(OutcomeError::Err("error"))));
    }

    #[test]
    fn into_result_cancelled() {
        let cancelled: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::default());
        let result = cancelled.into_result();
        assert!(matches!(result, Err(OutcomeError::Cancelled(_))));
    }

    #[test]
    fn into_result_panicked() {
        let panicked: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("oops"));
        let result = panicked.into_result();
        assert!(matches!(result, Err(OutcomeError::Panicked(_))));
    }

    // =========================================================================
    // From<Result> Conversion Tests
    // =========================================================================

    #[test]
    fn from_result_ok() {
        let result: Result<i32, &str> = Ok(42);
        let outcome: Outcome<i32, &str> = Outcome::from(result);
        assert!(matches!(outcome, Outcome::Ok(42)));
    }

    #[test]
    fn from_result_err() {
        let result: Result<i32, &str> = Err("error");
        let outcome: Outcome<i32, &str> = Outcome::from(result);
        assert!(matches!(outcome, Outcome::Err("error")));
    }

    // =========================================================================
    // Display Implementations Tests
    // =========================================================================

    #[test]
    fn panic_payload_display() {
        let payload = PanicPayload::new("something went wrong");
        let display = format!("{payload}");
        assert_eq!(display, "panic: something went wrong");
    }

    #[test]
    fn panic_payload_message() {
        let payload = PanicPayload::new("test message");
        assert_eq!(payload.message(), "test message");
    }

    #[test]
    fn outcome_error_display_err() {
        let error: OutcomeError<&str> = OutcomeError::Err("application error");
        let display = format!("{error}");
        assert_eq!(display, "application error");
    }

    #[test]
    fn outcome_error_display_cancelled() {
        let error: OutcomeError<&str> = OutcomeError::Cancelled(CancelReason::default());
        let display = format!("{error}");
        assert!(display.contains("cancelled"));
    }

    #[test]
    fn outcome_error_display_panicked() {
        let error: OutcomeError<&str> = OutcomeError::Panicked(PanicPayload::new("oops"));
        let display = format!("{error}");
        assert!(display.contains("panic"));
        assert!(display.contains("oops"));
    }
}
