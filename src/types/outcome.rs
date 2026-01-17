//! Four-valued outcome type with severity lattice.
//!
//! # Overview
//!
//! The [`Outcome`] type represents the result of a concurrent operation with four
//! possible states arranged in a severity lattice:
//!
//! ```text
//!           Panicked
//!              ↑
//!          Cancelled
//!              ↑
//!             Err
//!              ↑
//!             Ok
//! ```
//!
//! - [`Outcome::Ok(T)`] - Success with value
//! - [`Outcome::Err(E)`] - Application error (recoverable business logic failure)
//! - [`Outcome::Cancelled(CancelReason)`] - Operation was cancelled (external interruption)
//! - [`Outcome::Panicked(PanicPayload)`] - Task panicked (unrecoverable failure)
//!
//! # Severity Lattice
//!
//! The severity ordering `Ok < Err < Cancelled < Panicked` enables:
//!
//! - **Monotone aggregation**: When joining concurrent tasks, the worst outcome wins
//! - **Clear semantics**: Cancellation is worse than error, panic is worst
//! - **Idempotent composition**: `join(a, a) = a`
//!
//! # HTTP Status Code Mapping
//!
//! When using Outcome for HTTP handlers, the recommended status code mapping is:
//!
//! | Outcome Variant | HTTP Status | Description |
//! |-----------------|-------------|-------------|
//! | `Ok(T)` | 200 OK (or custom) | Success, response body in T |
//! | `Err(E)` | 4xx/5xx | Based on error kind |
//! | `Cancelled(_)` | 499 Client Closed Request | Request was cancelled |
//! | `Panicked(_)` | 500 Internal Server Error | Server panic caught |
//!
//! ```rust,ignore
//! async fn handler(ctx: RequestContext<'_>) -> Outcome<Response, ApiError> {
//!     let user = get_user(ctx.user_id()).await?;  // Err -> 4xx/5xx
//!     Outcome::ok(Response::json(user))           // Ok -> 200
//! }
//! // If cancelled: 499 Client Closed Request
//! // If panicked: 500 Internal Server Error
//! ```
//!
//! # Examples
//!
//! ## Basic Usage
//!
//! ```
//! use asupersync::{Outcome, CancelReason};
//!
//! // Construction using static methods
//! let success: Outcome<i32, &str> = Outcome::ok(42);
//! let failure: Outcome<i32, &str> = Outcome::err("not found");
//!
//! // Inspection
//! assert!(success.is_ok());
//! assert!(failure.is_err());
//!
//! // Transformation
//! let doubled = success.map(|x| x * 2);
//! assert_eq!(doubled.unwrap(), 84);
//! ```
//!
//! ## Aggregation (Join Semantics)
//!
//! ```
//! use asupersync::{Outcome, join_outcomes, CancelReason};
//!
//! // When joining outcomes, the worst wins
//! let ok: Outcome<(), ()> = Outcome::ok(());
//! let err: Outcome<(), ()> = Outcome::err(());
//! let cancelled: Outcome<(), ()> = Outcome::cancelled(CancelReason::timeout());
//!
//! // Err is worse than Ok
//! let joined = join_outcomes(ok.clone(), err.clone());
//! assert!(joined.is_err());
//!
//! // Cancelled is worse than Err
//! let joined = join_outcomes(err, cancelled);
//! assert!(joined.is_cancelled());
//! ```
//!
//! ## Conversion to Result
//!
//! ```
//! use asupersync::{Outcome, OutcomeError};
//!
//! let outcome: Outcome<i32, &str> = Outcome::ok(42);
//! let result: Result<i32, OutcomeError<&str>> = outcome.into_result();
//! assert!(result.is_ok());
//! ```

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

/// Severity level of an outcome.
///
/// The severity levels form a total order:
/// `Ok < Err < Cancelled < Panicked`
///
/// When aggregating outcomes (e.g., joining parallel tasks), the outcome
/// with higher severity takes precedence.
///
/// # Examples
///
/// ```
/// use asupersync::{Outcome, Severity, CancelReason};
///
/// let ok: Outcome<(), ()> = Outcome::ok(());
/// let err: Outcome<(), ()> = Outcome::err(());
///
/// assert_eq!(ok.severity(), Severity::Ok);
/// assert_eq!(err.severity(), Severity::Err);
/// assert!(Severity::Ok < Severity::Err);
/// assert!(Severity::Err < Severity::Cancelled);
/// assert!(Severity::Cancelled < Severity::Panicked);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Success - the operation completed normally.
    Ok = 0,
    /// Error - the operation failed with an application error.
    Err = 1,
    /// Cancelled - the operation was cancelled before completion.
    Cancelled = 2,
    /// Panicked - the operation panicked.
    Panicked = 3,
}

impl Severity {
    /// Returns the numeric severity value (0-3).
    ///
    /// This is useful for serialization or comparison.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Creates a Severity from a numeric value.
    ///
    /// Returns `None` if the value is out of range (> 3).
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::Err),
            2 => Some(Self::Cancelled),
            3 => Some(Self::Panicked),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::Err => write!(f, "err"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Panicked => write!(f, "panicked"),
        }
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
    // =========================================================================
    // Construction
    // =========================================================================

    /// Creates a successful outcome with the given value.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::Outcome;
    ///
    /// let outcome: Outcome<i32, &str> = Outcome::ok(42);
    /// assert!(outcome.is_ok());
    /// assert_eq!(outcome.unwrap(), 42);
    /// ```
    #[must_use]
    pub const fn ok(value: T) -> Self {
        Self::Ok(value)
    }

    /// Creates an error outcome with the given error.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::Outcome;
    ///
    /// let outcome: Outcome<i32, &str> = Outcome::err("not found");
    /// assert!(outcome.is_err());
    /// ```
    #[must_use]
    pub const fn err(error: E) -> Self {
        Self::Err(error)
    }

    /// Creates a cancelled outcome with the given reason.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::{Outcome, CancelReason};
    ///
    /// let outcome: Outcome<i32, &str> = Outcome::cancelled(CancelReason::timeout());
    /// assert!(outcome.is_cancelled());
    /// ```
    #[must_use]
    pub const fn cancelled(reason: CancelReason) -> Self {
        Self::Cancelled(reason)
    }

    /// Creates a panicked outcome with the given payload.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::{Outcome, PanicPayload};
    ///
    /// let outcome: Outcome<i32, &str> = Outcome::panicked(PanicPayload::new("oops"));
    /// assert!(outcome.is_panicked());
    /// ```
    #[must_use]
    pub const fn panicked(payload: PanicPayload) -> Self {
        Self::Panicked(payload)
    }

    // =========================================================================
    // Inspection
    // =========================================================================

    /// Returns the severity level of this outcome.
    ///
    /// The severity levels are ordered: `Ok < Err < Cancelled < Panicked`.
    /// This is useful for aggregation where the worst outcome should win.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::{Outcome, Severity, CancelReason};
    ///
    /// let ok: Outcome<i32, &str> = Outcome::ok(42);
    /// let err: Outcome<i32, &str> = Outcome::err("oops");
    /// let cancelled: Outcome<i32, &str> = Outcome::cancelled(CancelReason::timeout());
    ///
    /// assert_eq!(ok.severity(), Severity::Ok);
    /// assert_eq!(err.severity(), Severity::Err);
    /// assert_eq!(cancelled.severity(), Severity::Cancelled);
    /// assert!(ok.severity() < err.severity());
    /// ```
    #[must_use]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::Ok(_) => Severity::Ok,
            Self::Err(_) => Severity::Err,
            Self::Cancelled(_) => Severity::Cancelled,
            Self::Panicked(_) => Severity::Panicked,
        }
    }

    /// Returns the numeric severity level (0 = Ok, 3 = Panicked).
    ///
    /// Prefer [`severity()`][Self::severity] for type-safe comparisons.
    #[must_use]
    pub const fn severity_u8(&self) -> u8 {
        self.severity().as_u8()
    }

    /// Returns true if this is a terminal outcome (any non-pending state).
    ///
    /// All `Outcome` variants are terminal states.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        true // All variants are terminal
    }

    /// Returns true if this outcome is `Ok`.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::Outcome;
    ///
    /// let ok: Outcome<i32, &str> = Outcome::ok(42);
    /// let err: Outcome<i32, &str> = Outcome::err("oops");
    ///
    /// assert!(ok.is_ok());
    /// assert!(!err.is_ok());
    /// ```
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }

    /// Returns true if this outcome is `Err`.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::Outcome;
    ///
    /// let err: Outcome<i32, &str> = Outcome::err("oops");
    /// assert!(err.is_err());
    /// ```
    #[must_use]
    pub const fn is_err(&self) -> bool {
        matches!(self, Self::Err(_))
    }

    /// Returns true if this outcome is `Cancelled`.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::{Outcome, CancelReason};
    ///
    /// let cancelled: Outcome<i32, &str> = Outcome::cancelled(CancelReason::timeout());
    /// assert!(cancelled.is_cancelled());
    /// ```
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }

    /// Returns true if this outcome is `Panicked`.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::{Outcome, PanicPayload};
    ///
    /// let panicked: Outcome<i32, &str> = Outcome::panicked(PanicPayload::new("oops"));
    /// assert!(panicked.is_panicked());
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::Outcome;
    ///
    /// let err: Outcome<i32, &str> = Outcome::err("short");
    /// let mapped = err.map_err(str::len);
    /// assert!(matches!(mapped, Outcome::Err(5)));
    /// ```
    pub fn map_err<F2, G: FnOnce(E) -> F2>(self, g: G) -> Outcome<T, F2> {
        match self {
            Self::Ok(v) => Outcome::Ok(v),
            Self::Err(e) => Outcome::Err(g(e)),
            Self::Cancelled(r) => Outcome::Cancelled(r),
            Self::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Applies a function to the success value, flattening the result.
    ///
    /// This is the monadic bind operation, useful for chaining operations
    /// that might fail.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::Outcome;
    ///
    /// fn parse_int(s: &str) -> Outcome<i32, &'static str> {
    ///     s.parse::<i32>().map_err(|_| "parse error").into()
    /// }
    ///
    /// fn double(x: i32) -> Outcome<i32, &'static str> {
    ///     Outcome::ok(x * 2)
    /// }
    ///
    /// let result = parse_int("21").and_then(double);
    /// assert_eq!(result.unwrap(), 42);
    ///
    /// let result = parse_int("abc").and_then(double);
    /// assert!(result.is_err());
    /// ```
    pub fn and_then<U, F: FnOnce(T) -> Outcome<U, E>>(self, f: F) -> Outcome<U, E> {
        match self {
            Self::Ok(v) => f(v),
            Self::Err(e) => Outcome::Err(e),
            Self::Cancelled(r) => Outcome::Cancelled(r),
            Self::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Returns the success value, or computes a fallback from a closure.
    ///
    /// Unlike [`unwrap_or_else`][Self::unwrap_or_else], this returns a `Result`
    /// that preserves the distinction between different non-Ok outcomes.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::{Outcome, CancelReason};
    ///
    /// let ok: Outcome<i32, &str> = Outcome::ok(42);
    /// let result: Result<i32, &str> = ok.ok_or_else(|| "default error");
    /// assert_eq!(result, Ok(42));
    ///
    /// let cancelled: Outcome<i32, &str> = Outcome::cancelled(CancelReason::timeout());
    /// let result: Result<i32, &str> = cancelled.ok_or_else(|| "was cancelled");
    /// assert_eq!(result, Err("was cancelled"));
    /// ```
    pub fn ok_or_else<F2, G: FnOnce() -> F2>(self, f: G) -> Result<T, F2> {
        match self {
            Self::Ok(v) => Ok(v),
            _ => Err(f()),
        }
    }

    /// Joins this outcome with another, returning the outcome with higher severity.
    ///
    /// This implements the lattice join operation for aggregating outcomes
    /// from parallel tasks. The outcome with the worst (highest) severity wins.
    ///
    /// # Note on Value Handling
    ///
    /// When both outcomes are `Ok`, this method returns `self`. When both are
    /// the same non-Ok severity, the first (self) is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::{Outcome, CancelReason};
    ///
    /// let ok1: Outcome<i32, &str> = Outcome::ok(1);
    /// let ok2: Outcome<i32, &str> = Outcome::ok(2);
    /// let err: Outcome<i32, &str> = Outcome::err("error");
    /// let cancelled: Outcome<i32, &str> = Outcome::cancelled(CancelReason::timeout());
    ///
    /// // Ok + Ok = first Ok (both same severity)
    /// assert!(ok1.clone().join(ok2).is_ok());
    ///
    /// // Ok + Err = Err (Err is worse)
    /// assert!(ok1.clone().join(err.clone()).is_err());
    ///
    /// // Err + Cancelled = Cancelled (Cancelled is worse)
    /// assert!(err.join(cancelled).is_cancelled());
    /// ```
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        if self.severity() >= other.severity() {
            self
        } else {
            other
        }
    }

    // =========================================================================
    // Unwrap Operations
    // =========================================================================

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

        assert_eq!(ok.severity(), Severity::Ok);
        assert_eq!(err.severity(), Severity::Err);
        assert_eq!(cancelled.severity(), Severity::Cancelled);
        assert_eq!(panicked.severity(), Severity::Panicked);
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
