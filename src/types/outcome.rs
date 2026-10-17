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
//! - [`Outcome::Ok`] - Success with value
//! - [`Outcome::Err`] - Application error (recoverable business logic failure)
//! - [`Outcome::Cancelled`] - Operation was cancelled (external interruption)
//! - [`Outcome::Panicked`] - Task panicked (unrecoverable failure)
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
#[cfg(all(feature = "nightly-outcome-try", asupersync_try_trait))]
use core::convert::Infallible;
use core::fmt;
#[cfg(all(feature = "nightly-outcome-try", asupersync_try_trait))]
use core::ops::{ControlFlow, FromResidual, Residual, Try};
use serde::{Deserialize, Serialize};

/// Payload from a caught panic.
///
/// This wraps the panic value for safe transport across task boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanicPayload {
    message: String,
}

impl PanicPayload {
    /// Creates a new panic payload with the given message.
    #[inline]
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the panic message.
    #[inline]
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PanicPayload {
    #[inline]
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
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Creates a Severity from a numeric value.
    ///
    /// Returns `None` if the value is out of range (> 3).
    #[inline]
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
    #[inline]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
    #[must_use]
    pub const fn severity_u8(&self) -> u8 {
        self.severity().as_u8()
    }

    /// Returns true if this is a terminal outcome (any non-pending state).
    ///
    /// All `Outcome` variants are terminal states.
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
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
    #[inline]
    #[must_use]
    pub const fn is_panicked(&self) -> bool {
        matches!(self, Self::Panicked(_))
    }

    /// Converts this outcome to a standard Result, with cancellation and panic as errors.
    ///
    /// This is useful when interfacing with code that expects `Result`.
    #[inline]
    pub fn into_result(self) -> Result<T, OutcomeError<E>> {
        match self {
            Self::Ok(v) => Ok(v),
            Self::Err(e) => Err(OutcomeError::Err(e)),
            Self::Cancelled(r) => Err(OutcomeError::Cancelled(r)),
            Self::Panicked(p) => Err(OutcomeError::Panicked(p)),
        }
    }

    /// Maps the success value using the provided function.
    #[inline]
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
    #[inline]
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
    #[inline]
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
    /// instead of another value of `T`.
    ///
    /// This intentionally collapses every non-`Ok` outcome (`Err`,
    /// `Cancelled`, and `Panicked`) into the same lazily computed fallback
    /// error. Use [`into_result`][Self::into_result] if you need to preserve
    /// which terminal outcome occurred.
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
    #[inline]
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
    /// `Cancelled`, a strictly stronger [`CancelReason`] is retained. Equal-
    /// severity cancellation ties remain left-biased and return `self`.
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
    /// Implements `def.outcome.join_semantics` (#31).
    /// Left-bias: on equal severity, `self` (left argument) wins. The only
    /// `Cancelled + Cancelled` special case is when the right-hand cancellation
    /// reason has strictly higher severity and therefore strengthens the result.
    /// This is intentional: join is associative on severity, but not fully
    /// value-commutative. See `law.join.assoc` (#42).
    #[inline]
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Cancelled(mut left), Self::Cancelled(right)) => {
                if right.severity() > left.severity() {
                    left.strengthen(&right);
                }
                Self::Cancelled(left)
            }
            (left, right) => {
                if left.severity() >= right.severity() {
                    left
                } else {
                    right
                }
            }
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
    #[inline]
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

    /// Unwraps the contained `Ok` value, panicking with a custom message if not `Ok`.
    ///
    /// Similar to [`Result::expect`], but for `Outcome`.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::Outcome;
    ///
    /// let outcome: Outcome<u32, &str> = Outcome::ok(42);
    /// assert_eq!(outcome.expect("should be ok"), 42);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics with the provided message if the outcome is not `Ok`.
    #[track_caller]
    pub fn expect(self, msg: &str) -> T
    where
        E: fmt::Debug,
    {
        match self {
            Self::Ok(v) => v,
            Self::Err(e) => panic!("{msg}: {e:?}"),
            Self::Cancelled(r) => panic!("{msg}: cancelled with {r:?}"),
            Self::Panicked(p) => panic!("{msg}: panicked with {p}"),
        }
    }

    /// Unwraps the contained `Err` value, panicking with a custom message if not `Err`.
    ///
    /// Similar to [`Result::expect_err`], but for `Outcome`.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::Outcome;
    ///
    /// let outcome: Outcome<u32, &str> = Outcome::err("failed");
    /// assert_eq!(outcome.expect_err("should be error"), "failed");
    /// ```
    ///
    /// # Panics
    ///
    /// Panics with the provided message if the outcome is not `Err`.
    #[track_caller]
    pub fn expect_err(self, msg: &str) -> E
    where
        T: fmt::Debug,
    {
        match self {
            Self::Err(e) => e,
            Self::Ok(v) => panic!("{msg}: got Ok({v:?})"),
            Self::Cancelled(r) => panic!("{msg}: got Cancelled({r:?})"),
            Self::Panicked(p) => panic!("{msg}: got Panicked({p})"),
        }
    }

    /// Returns the success value or a default.
    #[inline]
    pub fn unwrap_or(self, default: T) -> T {
        match self {
            Self::Ok(v) => v,
            _ => default,
        }
    }

    /// Returns the success value or computes it from a closure.
    #[inline]
    pub fn unwrap_or_else<F: FnOnce() -> T>(self, f: F) -> T {
        match self {
            Self::Ok(v) => v,
            _ => f(),
        }
    }
}

impl<T, E> From<Result<T, E>> for Outcome<T, E> {
    #[inline]
    fn from(result: Result<T, E>) -> Self {
        match result {
            Ok(v) => Self::Ok(v),
            Err(e) => Self::Err(e),
        }
    }
}

#[cfg(all(feature = "nightly-outcome-try", asupersync_try_trait))]
impl<T, E> Try for Outcome<T, E> {
    type Output = T;
    type Residual = Outcome<Infallible, E>;

    #[inline]
    fn from_output(output: Self::Output) -> Self {
        Self::Ok(output)
    }

    #[inline]
    fn branch(self) -> ControlFlow<Self::Residual, Self::Output> {
        match self {
            Self::Ok(value) => ControlFlow::Continue(value),
            Self::Err(error) => ControlFlow::Break(Outcome::Err(error)),
            Self::Cancelled(reason) => ControlFlow::Break(Outcome::Cancelled(reason)),
            Self::Panicked(payload) => ControlFlow::Break(Outcome::Panicked(payload)),
        }
    }
}

#[cfg(all(feature = "nightly-outcome-try", asupersync_try_trait))]
impl<T, E> Residual<T> for Outcome<Infallible, E> {
    type TryType = Outcome<T, E>;
}

#[cfg(all(feature = "nightly-outcome-try", asupersync_try_trait))]
impl<T, E> FromResidual<Outcome<Infallible, E>> for Outcome<T, E> {
    #[inline]
    fn from_residual(residual: Outcome<Infallible, E>) -> Self {
        match residual {
            Outcome::Ok(value) => match value {},
            Outcome::Err(error) => Self::Err(error),
            Outcome::Cancelled(reason) => Self::Cancelled(reason),
            Outcome::Panicked(payload) => Self::Panicked(payload),
        }
    }
}

#[cfg(all(feature = "nightly-outcome-try", asupersync_try_trait))]
impl<T, E> FromResidual<Result<Infallible, E>> for Outcome<T, E> {
    #[inline]
    fn from_residual(residual: Result<Infallible, E>) -> Self {
        match residual {
            Ok(value) => match value {},
            Err(error) => Self::Err(error),
        }
    }
}

/// Error type for converting Outcome to Result.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            Self::Cancelled(r) => write!(f, "cancelled: {r}"),
            Self::Panicked(p) => write!(f, "{p}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for OutcomeError<E> {}

/// Compares two outcomes by severity and returns the worse one.
///
/// This implements the lattice join operation.
///
/// When both outcomes are `Cancelled`, a strictly stronger [`CancelReason`] is
/// kept. Equal-severity cancellation ties remain left-biased.
#[inline]
pub fn join_outcomes<T, E>(a: Outcome<T, E>, b: Outcome<T, E>) -> Outcome<T, E> {
    a.join(b)
}

#[cfg(test)]
#[path = "outcome_inline_tests.rs"]
mod tests;
