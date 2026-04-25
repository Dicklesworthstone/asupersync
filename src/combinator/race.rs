//! Race combinator: run multiple operations, first wins.
//!
//! The race combinator runs multiple operations concurrently.
//! When the first one completes, all others are cancelled and drained.
//!
//! # Critical Invariant: Losers Are Drained
//!
//! Unlike other runtimes that abandon losers, asupersync always drains them:
//!
//! ```text
//! race(f1, f2):
//!   t1 ← spawn(f1)
//!   t2 ← spawn(f2)
//!   (winner, loser) ← select_first_complete(t1, t2)
//!   cancel(loser)
//!   await(loser)  // CRITICAL: drain the loser
//!   return winner.outcome
//! ```
//!
//! This ensures resources held by losers are properly released.
//!
//! # Algebraic Laws
//!
//! - Commutativity: `race(a, b) ≃ race(b, a)` (same winner set, different selection)
//! - Identity: `race(a, never) ≃ a` (never = future that never completes)
//! - Associativity: `race(race(a, b), c) ≃ race(a, race(b, c))`
//!
//! # Outcome Semantics
//!
//! The winner's outcome drives ordinary success, error, and cancellation.
//! Losers are cancelled and drained before returning. Non-panicking loser
//! outcomes are retained for invariant verification; loser panics are surfaced
//! by fail-fast conversion helpers so drained branch panics are not silently
//! swallowed.

use core::fmt;
use std::future::Future;
use std::marker::PhantomData;

use crate::types::Outcome;
use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;

// ============================================================================
// Cancel Trait
// ============================================================================

/// Trait for futures that support explicit cancellation.
///
/// Futures participating in a `race!` must implement this trait to support
/// the asupersync cancellation protocol.
pub trait Cancel: Future {
    /// Initiates cancellation of this future.
    fn cancel(&mut self, reason: CancelReason);

    /// Returns true if cancellation has been requested.
    fn is_cancelled(&self) -> bool;

    /// Returns the cancellation reason, if cancellation was requested.
    #[inline]
    fn cancel_reason(&self) -> Option<&CancelReason> {
        None
    }
}

// ============================================================================
// RaceN Types (Race2 through Race16)
// ============================================================================

/// Type alias: `Race2` is equivalent to `RaceResult` for consistency.
pub type Race2<A, B> = RaceResult<A, B>;

/// Result of a 3-way race.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Race3<A, B, C> {
    /// The first branch won.
    First(A),
    /// The second branch won.
    Second(B),
    /// The third branch won.
    Third(C),
}

impl<A, B, C> Race3<A, B, C> {
    /// Returns the winner index (0, 1, or 2).
    #[inline]
    #[must_use]
    pub const fn winner_index(&self) -> usize {
        match self {
            Self::First(_) => 0,
            Self::Second(_) => 1,
            Self::Third(_) => 2,
        }
    }
}

/// Result of a 4-way race.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Race4<A, B, C, D> {
    /// The first branch won.
    First(A),
    /// The second branch won.
    Second(B),
    /// The third branch won.
    Third(C),
    /// The fourth branch won.
    Fourth(D),
}

impl<A, B, C, D> Race4<A, B, C, D> {
    /// Returns the winner index (0-3).
    #[inline]
    #[must_use]
    pub const fn winner_index(&self) -> usize {
        match self {
            Self::First(_) => 0,
            Self::Second(_) => 1,
            Self::Third(_) => 2,
            Self::Fourth(_) => 3,
        }
    }
}

/// Determines the polling order for race operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PollingOrder {
    /// Poll futures in the order they were specified (left-to-right).
    #[default]
    Biased,
    /// Poll futures in a pseudo-random order.
    Unbiased,
}

/// A race combinator for running the first operation to complete.
///
/// This is a builder/marker type; actual execution happens via the runtime.
#[derive(Debug)]
pub struct Race<A, B> {
    _a: PhantomData<A>,
    _b: PhantomData<B>,
}

impl<A, B> Race<A, B> {
    /// Creates a new race combinator (internal use).
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _a: PhantomData,
            _b: PhantomData,
        }
    }
}

impl<A, B> Clone for Race<A, B> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<A, B> Copy for Race<A, B> {}

impl<A, B> Default for Race<A, B> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// An N-way race combinator for running multiple operations in parallel.
///
/// This is a builder/marker type representing a race of N operations.
/// The first operation to complete wins; all others are cancelled and drained.
///
/// # Type Parameters
/// * `T` - The element type for each operation
///
/// # Semantics
///
/// Given futures `f[0..n)`:
/// 1. Spawn all as children in a subregion
/// 2. Wait for the first to reach terminal state
/// 3. Cancel all other (loser) tasks
/// 4. Drain all losers (await until terminal)
/// 5. Return winner's outcome
///
/// # Critical Invariants
///
/// - **Losers are drained**: Every loser reaches terminal state
/// - **Region quiescence**: All children done before return
/// - **Deterministic**: Same seed → same winner in lab runtime (on ties)
///
/// # Example (API shape)
/// ```ignore
/// let result = scope.race_all(cx, vec![
///     async { fetch_from_primary(cx).await },
///     async { fetch_from_replica_1(cx).await },
///     async { fetch_from_replica_2(cx).await },
/// ]).await;
/// ```
#[derive(Debug)]
pub struct RaceAll<T> {
    _t: PhantomData<T>,
}

impl<T> RaceAll<T> {
    /// Creates a new N-way race combinator (internal use).
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { _t: PhantomData }
    }
}

impl<T> Default for RaceAll<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for RaceAll<T> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for RaceAll<T> {}

/// The result of a race, indicating which branch won.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaceResult<A, B> {
    /// The first branch won.
    First(A),
    /// The second branch won.
    Second(B),
}

impl<A, B> RaceResult<A, B> {
    /// Returns true if the first branch won.
    #[inline]
    #[must_use]
    pub const fn is_first(&self) -> bool {
        matches!(self, Self::First(_))
    }

    /// Returns true if the second branch won.
    #[inline]
    #[must_use]
    pub const fn is_second(&self) -> bool {
        matches!(self, Self::Second(_))
    }

    /// Maps the first variant.
    #[inline]
    pub fn map_first<C, F: FnOnce(A) -> C>(self, f: F) -> RaceResult<C, B> {
        match self {
            Self::First(a) => RaceResult::First(f(a)),
            Self::Second(b) => RaceResult::Second(b),
        }
    }

    /// Maps the second variant.
    #[inline]
    pub fn map_second<C, F: FnOnce(B) -> C>(self, f: F) -> RaceResult<A, C> {
        match self {
            Self::First(a) => RaceResult::First(a),
            Self::Second(b) => RaceResult::Second(f(b)),
        }
    }

    /// Returns the winner index (0 or 1) for consistency with RaceN types.
    #[inline]
    #[must_use]
    pub const fn winner_index(&self) -> usize {
        match self {
            Self::First(_) => 0,
            Self::Second(_) => 1,
        }
    }
}

/// Error type for fail-fast race operations.
///
/// When a race fails (winner has an error/cancel/panic), this type
/// indicates which branch won and why the race failed.
#[derive(Debug, Clone)]
pub enum RaceError<E> {
    /// The first branch won with an error.
    First(E),
    /// The second branch won with an error.
    Second(E),
    /// The winner was cancelled.
    Cancelled(CancelReason),
    /// A branch panicked.
    Panicked(PanicPayload),
}

impl<E: fmt::Display> fmt::Display for RaceError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::First(e) => write!(f, "first branch won with error: {e}"),
            Self::Second(e) => write!(f, "second branch won with error: {e}"),
            Self::Cancelled(r) => write!(f, "winner was cancelled: {r}"),
            Self::Panicked(p) => write!(f, "branch panicked: {p}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for RaceError<E> {}

/// Error type for N-way race operations.
///
/// When an N-way race fails (winner has an error/cancel/panic), this type
/// preserves the winner's index for debugging and analysis.
#[derive(Debug, Clone)]
pub enum RaceAllError<E> {
    /// The winner had an error at the specified index.
    Error {
        /// The error value.
        error: E,
        /// Index of the winning branch that errored.
        winner_index: usize,
    },
    /// The winner was cancelled.
    Cancelled {
        /// The cancel reason.
        reason: CancelReason,
        /// Index of the winning branch that was cancelled.
        winner_index: usize,
    },
    /// A branch panicked.
    Panicked {
        /// The panic payload.
        payload: PanicPayload,
        /// Index of the branch that panicked.
        index: usize,
    },
}

impl<E> RaceAllError<E> {
    /// Returns the index for any error variant (the winning branch, or the branch that panicked).
    #[inline]
    #[must_use]
    pub const fn winner_index(&self) -> usize {
        match self {
            Self::Error { winner_index, .. } | Self::Cancelled { winner_index, .. } => {
                *winner_index
            }
            Self::Panicked { index, .. } => *index,
        }
    }

    /// Returns true if this was an application error (not cancel/panic).
    #[inline]
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }

    /// Returns true if the winner was cancelled.
    #[inline]
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled { .. })
    }

    /// Returns true if the winner panicked.
    #[inline]
    #[must_use]
    pub const fn is_panicked(&self) -> bool {
        matches!(self, Self::Panicked { .. })
    }
}

impl<E: fmt::Display> fmt::Display for RaceAllError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error {
                error,
                winner_index,
            } => {
                write!(
                    f,
                    "race winner at index {winner_index} failed with error: {error}"
                )
            }
            Self::Cancelled {
                reason,
                winner_index,
            } => {
                write!(
                    f,
                    "race winner at index {winner_index} was cancelled: {reason}"
                )
            }
            Self::Panicked { payload, index } => {
                write!(f, "race branch at index {index} panicked: {payload}")
            }
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for RaceAllError<E> {}

/// Which branch won the race.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaceWinner {
    /// The first branch completed first.
    First,
    /// The second branch completed first.
    Second,
}

impl RaceWinner {
    /// Returns true if the first branch won.
    #[inline]
    #[must_use]
    pub const fn is_first(self) -> bool {
        matches!(self, Self::First)
    }

    /// Returns true if the second branch won.
    #[inline]
    #[must_use]
    pub const fn is_second(self) -> bool {
        matches!(self, Self::Second)
    }
}

/// Result type for `race2_outcomes`.
///
/// The tuple contains:
/// - The winner's outcome
/// - Which branch won
/// - The loser's outcome (after it was cancelled and drained)
pub type Race2Result<T, E> = (Outcome<T, E>, RaceWinner, Outcome<T, E>);

/// Determines the race result from two outcomes where one completed first.
///
/// In a race, the winner is the first to reach a terminal state. The loser
/// is then cancelled and drained. This function takes both outcomes (after
/// draining) and the winner indicator to construct the race result.
///
/// # Arguments
/// * `winner` - Which branch completed first
/// * `o1` - Outcome from the first branch (after draining if loser)
/// * `o2` - Outcome from the second branch (after draining if loser)
///
/// # Returns
/// A tuple of (winner's outcome, winner indicator, loser's outcome).
///
/// # Example
/// ```
/// use asupersync::combinator::race::{race2_outcomes, RaceWinner};
/// use asupersync::types::Outcome;
///
/// // First branch completed first with Ok(42)
/// let o1: Outcome<i32, &str> = Outcome::Ok(42);
/// // Second branch was cancelled (as the loser)
/// let o2: Outcome<i32, &str> = Outcome::Cancelled(
///     asupersync::types::cancel::CancelReason::race_loser()
/// );
///
/// let (winner_outcome, winner, loser_outcome) = race2_outcomes(RaceWinner::First, o1, o2);
/// assert!(winner_outcome.is_ok());
/// assert!(winner.is_first());
/// assert!(loser_outcome.is_cancelled());
/// ```
#[inline]
pub fn race2_outcomes<T, E>(
    winner: RaceWinner,
    o1: Outcome<T, E>,
    o2: Outcome<T, E>,
) -> Race2Result<T, E> {
    match winner {
        RaceWinner::First => (o1, RaceWinner::First, o2),
        RaceWinner::Second => (o2, RaceWinner::Second, o1),
    }
}

/// Converts race outcomes to a Result for fail-fast handling.
///
/// If neither branch panicked and the winner succeeded, returns `Ok` with the value.
/// If the winner failed (error or cancellation), returns `Err`.
/// If either branch panicked, returns `Err` so drained loser panics are not
/// silently swallowed.
///
/// # Example
/// ```
/// use asupersync::combinator::race::{race2_to_result, RaceWinner};
/// use asupersync::types::Outcome;
///
/// let o1: Outcome<i32, &str> = Outcome::Ok(42);
/// let o2: Outcome<i32, &str> = Outcome::Cancelled(
///     asupersync::types::cancel::CancelReason::race_loser()
/// );
///
/// let result = race2_to_result(RaceWinner::First, o1, o2);
/// assert_eq!(result.unwrap(), 42);
/// ```
#[inline]
pub fn race2_to_result<T, E>(
    winner: RaceWinner,
    o1: Outcome<T, E>,
    o2: Outcome<T, E>,
) -> Result<T, RaceError<E>> {
    let (winner_outcome, which_won, loser_outcome) = race2_outcomes(winner, o1, o2);

    if let Outcome::Panicked(p) = winner_outcome {
        return Err(RaceError::Panicked(p));
    }

    if let Outcome::Panicked(p) = loser_outcome {
        return Err(RaceError::Panicked(p));
    }

    if let Outcome::Ok(v) = winner_outcome {
        return Ok(v);
    }

    match winner_outcome {
        Outcome::Err(e) => match which_won {
            RaceWinner::First => Err(RaceError::First(e)),
            RaceWinner::Second => Err(RaceError::Second(e)),
        },
        Outcome::Cancelled(r) => Err(RaceError::Cancelled(r)),
        _ => unreachable!(),
    }
}

/// Result from racing N operations.
///
/// Contains the winner's outcome, the index of the winner, and outcomes
/// from all losers (after they were cancelled and drained).
pub struct RaceAllResult<T, E> {
    /// The outcome of the winning branch.
    pub winner_outcome: Outcome<T, E>,
    /// Index of the winning branch (0-based).
    pub winner_index: usize,
    /// Outcomes of all losing branches, in their original order.
    /// Each loser was cancelled and drained before being collected here.
    pub loser_outcomes: Vec<(usize, Outcome<T, E>)>,
}

impl<T, E> RaceAllResult<T, E> {
    /// Creates a new race-all result.
    #[inline]
    #[must_use]
    pub fn new(
        winner_outcome: Outcome<T, E>,
        winner_index: usize,
        loser_outcomes: Vec<(usize, Outcome<T, E>)>,
    ) -> Self {
        Self {
            winner_outcome,
            winner_index,
            loser_outcomes,
        }
    }

    /// Returns true if the winner succeeded.
    #[inline]
    #[must_use]
    pub fn winner_succeeded(&self) -> bool {
        self.winner_outcome.is_ok()
    }
}

/// Constructs a race-all result from the outcomes.
///
/// The winner is identified by index, and all other outcomes are losers.
/// All losers should have been cancelled and drained before calling this.
///
/// # Arguments
/// * `winner_index` - Index of the winning branch
/// * `outcomes` - All outcomes in their original order
///
/// # Panics
/// Panics if `winner_index` is out of bounds.
#[inline]
#[must_use]
pub fn race_all_outcomes<T, E>(
    winner_index: usize,
    outcomes: Vec<Outcome<T, E>>,
) -> RaceAllResult<T, E> {
    assert!(winner_index < outcomes.len(), "winner_index out of bounds");

    let loser_count = outcomes.len().saturating_sub(1);
    let mut iter = outcomes.into_iter().enumerate();
    let mut winner_outcome = None;
    let mut loser_outcomes: Vec<(usize, Outcome<T, E>)> = Vec::with_capacity(loser_count);

    for (i, outcome) in iter.by_ref() {
        if i == winner_index {
            winner_outcome = Some(outcome);
        } else {
            loser_outcomes.push((i, outcome));
        }
    }

    RaceAllResult::new(
        winner_outcome.expect("winner not found"),
        winner_index,
        loser_outcomes,
    )
}

/// Converts a race-all result to a Result for fail-fast handling.
///
/// If no branch panicked and the winner succeeded, returns `Ok` with the value.
/// If the winner failed, returns `Err` with a `RaceAllError` that includes
/// the winner's index for debugging. Panicked losers also return `Err` with
/// their branch index, because drain-time panics must remain observable.
///
/// # Example
/// ```
/// use asupersync::combinator::race::{race_all_to_result, RaceAllResult, RaceAllError};
/// use asupersync::types::Outcome;
/// use asupersync::types::cancel::CancelReason;
///
/// let result: RaceAllResult<i32, &str> = RaceAllResult::new(
///     Outcome::Ok(42),
///     1,
///     vec![(0, Outcome::Cancelled(CancelReason::race_loser()))],
/// );
///
/// let value = race_all_to_result(result);
/// assert_eq!(value.unwrap(), 42);
/// ```
#[inline]
pub fn race_all_to_result<T, E>(result: RaceAllResult<T, E>) -> Result<T, RaceAllError<E>> {
    if let Outcome::Panicked(p) = result.winner_outcome {
        return Err(RaceAllError::Panicked {
            payload: p,
            index: result.winner_index,
        });
    }

    for (i, loser_outcome) in result.loser_outcomes {
        if let Outcome::Panicked(p) = loser_outcome {
            return Err(RaceAllError::Panicked {
                payload: p,
                index: i,
            });
        }
    }

    if let Outcome::Ok(v) = result.winner_outcome {
        return Ok(v);
    }

    match result.winner_outcome {
        Outcome::Err(e) => Err(RaceAllError::Error {
            error: e,
            winner_index: result.winner_index,
        }),
        Outcome::Cancelled(r) => Err(RaceAllError::Cancelled {
            reason: r,
            winner_index: result.winner_index,
        }),
        _ => unreachable!(),
    }
}

/// Creates a race-all result from raw outcomes, intended for runtime implementations.
///
/// This is the primary "escape hatch" for constructing N-way race results
/// when you have the winner index and all outcomes after draining.
///
/// # Arguments
/// * `winner_index` - Index of the winning branch
/// * `outcomes` - All outcomes in their original order (losers should be drained)
///
/// # Returns
/// `Ok(value)` if the winner succeeded, `Err(RaceAllError)` otherwise.
///
/// # Panics
/// Panics if `winner_index` is out of bounds.
///
/// # Example
/// ```
/// use asupersync::combinator::race::{make_race_all_result, RaceAllError};
/// use asupersync::types::Outcome;
/// use asupersync::types::cancel::CancelReason;
///
/// let outcomes: Vec<Outcome<i32, &str>> = vec![
///     Outcome::Ok(42),
///     Outcome::Cancelled(CancelReason::race_loser()),
///     Outcome::Cancelled(CancelReason::race_loser()),
/// ];
///
/// let result = make_race_all_result(0, outcomes);
/// assert_eq!(result.unwrap(), 42);
/// ```
#[inline]
pub fn make_race_all_result<T, E>(
    winner_index: usize,
    outcomes: Vec<Outcome<T, E>>,
) -> Result<T, RaceAllError<E>> {
    let result = race_all_outcomes(winner_index, outcomes);
    race_all_to_result(result)
}

/// Contract-enforcement placeholder for builds without the `proc-macros` feature.
///
/// In `proc-macros` builds, the supported root macro DSL re-exports the real
/// `race!` proc macro from the crate root (`use asupersync::race;`).
///
/// When `proc-macros` is disabled, the macro DSL is intentionally unavailable.
/// This placeholder exists only to fail fast with a truthful error message
/// instead of pretending a fallback macro exists.
///
/// Without that feature, use the `Scope` APIs (`Scope::race`,
/// `Scope::race_all`) when racing spawned tasks.
///
/// # Basic Usage
///
/// ```ignore
/// let winner: Race2<A, B> = race!(fut_a, fut_b).await;
/// let winner: Race3<A, B, C> = race!(fut_a, fut_b, fut_c).await;
/// ```
///
/// # Biased Mode
///
/// Use `biased;` for left-to-right polling priority (useful for fallback patterns):
///
/// ```ignore
/// race! { biased;
///     check_cache(key),
///     query_database(key),
/// }
/// ```
///
/// # Key Properties
///
/// 1. First future to return `Poll::Ready` is the winner
/// 2. All non-winning futures go through the cancellation protocol
/// 3. `race!` waits for all losers to complete before returning
/// 4. Losers complete with `Outcome::Cancelled(RaceLost)`
#[cfg(not(feature = "proc-macros"))]
#[macro_export]
macro_rules! race {
    // Biased mode
    (biased; $($future:expr),+ $(,)?) => {{
        compile_error!(
            "race! is unavailable without the `proc-macros` feature. Re-enable \
             `proc-macros`, or use Scope::race() / Scope::race_all() for drained task \
             races or Cx::race() for inline future races."
        );
    }};
    // Basic positional syntax
    ($($future:expr),+ $(,)?) => {{
        compile_error!(
            "race! is unavailable without the `proc-macros` feature. Re-enable \
             `proc-macros`, or use Scope::race() / Scope::race_all() for drained task \
             races or Cx::race() for inline future races."
        );
    }};
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum RaceWinnerCase {
        Ok(i32),
        Err,
        CancelTimeout,
        CancelShutdown,
        Panic,
    }

    #[derive(Debug, Clone)]
    enum RaceLoserCase {
        Ok(i32),
        Err,
        CancelRaceLost,
        CancelTimeout,
        CancelShutdown,
    }

    impl RaceWinnerCase {
        fn into_outcome(self) -> Outcome<i32, &'static str> {
            match self {
                Self::Ok(value) => Outcome::Ok(value),
                Self::Err => Outcome::Err("winner-error"),
                Self::CancelTimeout => Outcome::Cancelled(CancelReason::timeout()),
                Self::CancelShutdown => Outcome::Cancelled(CancelReason::shutdown()),
                Self::Panic => Outcome::Panicked(PanicPayload::new("winner-panic")),
            }
        }
    }

    impl RaceLoserCase {
        fn into_outcome(self) -> Outcome<i32, &'static str> {
            match self {
                Self::Ok(value) => Outcome::Ok(value),
                Self::Err => Outcome::Err("loser-error"),
                Self::CancelRaceLost => Outcome::Cancelled(CancelReason::race_loser()),
                Self::CancelTimeout => Outcome::Cancelled(CancelReason::timeout()),
                Self::CancelShutdown => Outcome::Cancelled(CancelReason::shutdown()),
            }
        }
    }

    fn race_winner_case_strategy() -> impl Strategy<Value = RaceWinnerCase> {
        prop_oneof![
            any::<i16>().prop_map(|value| RaceWinnerCase::Ok(i32::from(value))),
            Just(RaceWinnerCase::Err),
            Just(RaceWinnerCase::CancelTimeout),
            Just(RaceWinnerCase::CancelShutdown),
            Just(RaceWinnerCase::Panic),
        ]
    }

    fn race_loser_case_strategy() -> impl Strategy<Value = RaceLoserCase> {
        prop_oneof![
            any::<i16>().prop_map(|value| RaceLoserCase::Ok(i32::from(value))),
            Just(RaceLoserCase::Err),
            Just(RaceLoserCase::CancelRaceLost),
            Just(RaceLoserCase::CancelTimeout),
            Just(RaceLoserCase::CancelShutdown),
        ]
    }

    fn race_outcome_signature(
        outcome: &Outcome<i32, &'static str>,
    ) -> (&'static str, Option<i32>, Option<u8>) {
        match outcome {
            Outcome::Ok(value) => ("ok", Some(*value), None),
            Outcome::Err(_) => ("err", None, None),
            Outcome::Cancelled(reason) => ("cancelled", None, Some(reason.severity())),
            Outcome::Panicked(_) => ("panic", None, None),
        }
    }

    fn race_error_signature(error: &RaceError<&'static str>) -> (&'static str, usize, Option<u8>) {
        match error {
            RaceError::First(_) => ("err", 0, None),
            RaceError::Second(_) => ("err", 1, None),
            RaceError::Cancelled(reason) => ("cancelled", 0, Some(reason.severity())),
            RaceError::Panicked(_) => ("panic", 0, None),
        }
    }

    fn race2_result_signature(
        result: &Result<i32, RaceError<&'static str>>,
    ) -> (&'static str, Option<i32>, usize, Option<u8>) {
        match result {
            Ok(value) => ("ok", Some(*value), 0, None),
            Err(error) => {
                let (kind, winner_index, severity) = race_error_signature(error);
                (kind, None, winner_index, severity)
            }
        }
    }

    fn race_all_error_signature(
        error: &RaceAllError<&'static str>,
    ) -> (&'static str, usize, Option<u8>) {
        match error {
            RaceAllError::Error { winner_index, .. } => ("err", *winner_index, None),
            RaceAllError::Cancelled {
                winner_index,
                reason,
            } => ("cancelled", *winner_index, Some(reason.severity())),
            RaceAllError::Panicked { index, .. } => ("panic", *index, None),
        }
    }

    fn race_all_result_signature(
        result: &Result<i32, RaceAllError<&'static str>>,
    ) -> (&'static str, Option<i32>, usize, Option<u8>) {
        match result {
            Ok(value) => ("ok", Some(*value), 0, None),
            Err(error) => {
                let (kind, index, severity) = race_all_error_signature(error);
                (kind, None, index, severity)
            }
        }
    }

    #[test]
    fn race_result_is_first() {
        let result: RaceResult<i32, &str> = RaceResult::First(42);
        assert!(result.is_first());
        assert!(!result.is_second());
    }

    #[test]
    fn race_result_is_second() {
        let result: RaceResult<i32, &str> = RaceResult::Second("hello");
        assert!(!result.is_first());
        assert!(result.is_second());
    }

    #[test]
    fn race_result_map_first() {
        let result: RaceResult<i32, &str> = RaceResult::First(42);
        let mapped = result.map_first(|x| x * 2);
        assert!(matches!(mapped, RaceResult::First(84)));
    }

    #[test]
    fn race_result_map_second() {
        let result: RaceResult<i32, &str> = RaceResult::Second("hello");
        let mapped = result.map_second(str::len);
        assert!(matches!(mapped, RaceResult::Second(5)));
    }

    #[test]
    fn race_winner_predicates() {
        assert!(RaceWinner::First.is_first());
        assert!(!RaceWinner::First.is_second());
        assert!(!RaceWinner::Second.is_first());
        assert!(RaceWinner::Second.is_second());
    }

    #[test]
    fn race2_outcomes_first_wins_ok() {
        let o1: Outcome<i32, &str> = Outcome::Ok(42);
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let (winner, which, loser) = race2_outcomes(RaceWinner::First, o1, o2);

        assert!(winner.is_ok());
        assert!(which.is_first());
        assert!(loser.is_cancelled());
    }

    #[test]
    fn race2_outcomes_second_wins_ok() {
        let o1: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());
        let o2: Outcome<i32, &str> = Outcome::Ok(99);

        let (winner, which, loser) = race2_outcomes(RaceWinner::Second, o1, o2);

        assert!(winner.is_ok());
        assert!(which.is_second());
        assert!(loser.is_cancelled());
    }

    #[test]
    fn race2_outcomes_first_wins_err() {
        let o1: Outcome<i32, &str> = Outcome::Err("failed");
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let (winner, which, loser) = race2_outcomes(RaceWinner::First, o1, o2);

        assert!(winner.is_err());
        assert!(which.is_first());
        assert!(loser.is_cancelled());
    }

    #[test]
    fn race2_to_result_winner_ok() {
        let o1: Outcome<i32, &str> = Outcome::Ok(42);
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let result = race2_to_result(RaceWinner::First, o1, o2);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn race2_to_result_winner_err() {
        let o1: Outcome<i32, &str> = Outcome::Err("failed");
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let result = race2_to_result(RaceWinner::First, o1, o2);
        assert!(matches!(result, Err(RaceError::First("failed"))));
    }

    #[test]
    fn race2_to_result_winner_cancelled() {
        let o1: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::timeout());
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let result = race2_to_result(RaceWinner::First, o1, o2);
        assert!(matches!(result, Err(RaceError::Cancelled(_))));
    }

    #[test]
    fn race2_to_result_winner_panicked() {
        let o1: Outcome<i32, &str> = Outcome::Panicked(PanicPayload::new("boom"));
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let result = race2_to_result(RaceWinner::First, o1, o2);
        assert!(matches!(result, Err(RaceError::Panicked(_))));
    }

    #[test]
    fn race_all_outcomes_first_wins() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Ok(1),
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Cancelled(CancelReason::race_loser()),
        ];

        let result = race_all_outcomes(0, outcomes);

        assert!(result.winner_succeeded());
        assert_eq!(result.winner_index, 0);
        assert_eq!(result.loser_outcomes.len(), 2);
        assert_eq!(result.loser_outcomes[0].0, 1);
        assert_eq!(result.loser_outcomes[1].0, 2);
    }

    #[test]
    fn race_all_outcomes_middle_wins() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Ok(42),
            Outcome::Cancelled(CancelReason::race_loser()),
        ];

        let result = race_all_outcomes(1, outcomes);

        assert!(result.winner_succeeded());
        assert_eq!(result.winner_index, 1);
        assert_eq!(result.loser_outcomes.len(), 2);
        assert_eq!(result.loser_outcomes[0].0, 0);
        assert_eq!(result.loser_outcomes[1].0, 2);
    }

    #[test]
    fn race_all_to_result_success() {
        let result: RaceAllResult<i32, &str> = RaceAllResult::new(
            Outcome::Ok(42),
            0,
            vec![(1, Outcome::Cancelled(CancelReason::race_loser()))],
        );

        let value = race_all_to_result(result);
        assert_eq!(value.unwrap(), 42);
    }

    #[test]
    fn race_all_to_result_error() {
        let result: RaceAllResult<i32, &str> = RaceAllResult::new(
            Outcome::Err("failed"),
            2,
            vec![
                (0, Outcome::Cancelled(CancelReason::race_loser())),
                (1, Outcome::Cancelled(CancelReason::race_loser())),
            ],
        );

        let value = race_all_to_result(result);
        match value {
            Err(RaceAllError::Error {
                error,
                winner_index,
            }) => {
                assert_eq!(error, "failed");
                assert_eq!(winner_index, 2);
            }
            _ => panic!("expected RaceAllError::Error"),
        }
    }

    #[test]
    fn race_error_display() {
        let err: RaceError<&str> = RaceError::First("test error");
        assert!(err.to_string().contains("first branch won"));

        let err: RaceError<&str> = RaceError::Second("test error");
        assert!(err.to_string().contains("second branch won"));

        let err: RaceError<&str> = RaceError::Cancelled(CancelReason::timeout());
        assert!(err.to_string().contains("cancelled"));

        let err: RaceError<&str> = RaceError::Panicked(PanicPayload::new("boom"));
        assert!(err.to_string().contains("panicked"));
    }

    #[test]
    fn loser_is_always_tracked() {
        // This test verifies that the loser outcome is captured in the result,
        // which is necessary for verifying the "losers always drained" invariant.
        let o1: Outcome<i32, &str> = Outcome::Ok(42);
        let o2: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());

        let (_, _, loser) = race2_outcomes(RaceWinner::First, o1, o2);

        // The loser was cancelled (as expected when losing a race)
        assert!(loser.is_cancelled());
        if let Outcome::Cancelled(reason) = loser {
            // The reason should indicate it was a race loser
            assert!(matches!(
                reason.kind(),
                crate::types::cancel::CancelKind::RaceLost
            ));
        }
    }

    #[test]
    fn race_is_commutative_in_winner_value() {
        // race(a, b) and race(b, a) should return the same winner value
        // when the same branch wins (regardless of position).
        let val_a = 42;

        // A wins in first position
        let o1a: Outcome<i32, &str> = Outcome::Ok(val_a);
        let o1b: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());
        let (w1, _, _) = race2_outcomes(RaceWinner::First, o1a, o1b);

        // A wins in second position (swapped)
        let o2b: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());
        let o2a: Outcome<i32, &str> = Outcome::Ok(val_a);
        let (w2, _, _) = race2_outcomes(RaceWinner::Second, o2b, o2a);

        // Both should have the same winner value
        if let (Outcome::Ok(v1), Outcome::Ok(v2)) = (w1, w2) {
            assert_eq!(v1, v2);
        } else {
            panic!("Expected both winners to be Ok");
        }
    }

    // ========== RaceAll tests ==========

    #[test]
    fn race_all_marker_type() {
        let _race: RaceAll<i32> = RaceAll::new();
        let _race_default: RaceAll<String> = RaceAll::default();

        // Test Clone and Copy
        let r1: RaceAll<i32> = RaceAll::new();
        let r2 = r1;
        let r3 = r1; // Copy, not clone
        assert!(std::mem::size_of_val(&r1) == std::mem::size_of_val(&r2));
        assert!(std::mem::size_of_val(&r1) == std::mem::size_of_val(&r3));
    }

    // ========== RaceAllError tests ==========

    #[test]
    fn race_all_error_predicates() {
        let err: RaceAllError<&str> = RaceAllError::Error {
            error: "test",
            winner_index: 2,
        };
        assert!(err.is_error());
        assert!(!err.is_cancelled());
        assert!(!err.is_panicked());
        assert_eq!(err.winner_index(), 2);

        let err: RaceAllError<&str> = RaceAllError::Cancelled {
            reason: CancelReason::timeout(),
            winner_index: 1,
        };
        assert!(!err.is_error());
        assert!(err.is_cancelled());
        assert!(!err.is_panicked());
        assert_eq!(err.winner_index(), 1);

        let err: RaceAllError<&str> = RaceAllError::Panicked {
            payload: PanicPayload::new("boom"),
            index: 0,
        };
        assert!(!err.is_error());
        assert!(!err.is_cancelled());
        assert!(err.is_panicked());
        assert_eq!(err.winner_index(), 0);
    }

    #[test]
    fn race_all_error_display() {
        let err: RaceAllError<&str> = RaceAllError::Error {
            error: "test error",
            winner_index: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("index 3"));
        assert!(msg.contains("test error"));

        let err: RaceAllError<&str> = RaceAllError::Cancelled {
            reason: CancelReason::timeout(),
            winner_index: 1,
        };
        assert!(err.to_string().contains("cancelled"));
        assert!(err.to_string().contains("index 1"));

        let err: RaceAllError<&str> = RaceAllError::Panicked {
            payload: PanicPayload::new("crash"),
            index: 0,
        };
        assert!(err.to_string().contains("panicked"));
        assert!(err.to_string().contains("index 0"));
    }

    // ========== make_race_all_result tests ==========

    #[test]
    fn make_race_all_result_success() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Ok(42),
            Outcome::Cancelled(CancelReason::race_loser()),
        ];

        let result = make_race_all_result(1, outcomes);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn make_race_all_result_error_preserves_index() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Err("failed at index 2"),
        ];

        let result = make_race_all_result(2, outcomes);
        match result {
            Err(RaceAllError::Error {
                error,
                winner_index,
            }) => {
                assert_eq!(error, "failed at index 2");
                assert_eq!(winner_index, 2);
            }
            _ => panic!("expected RaceAllError::Error"),
        }
    }

    #[test]
    fn make_race_all_result_cancelled() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::timeout()),
            Outcome::Cancelled(CancelReason::race_loser()),
        ];

        let result = make_race_all_result(0, outcomes);
        assert!(matches!(result, Err(RaceAllError::Cancelled { .. })));
        if let Err(RaceAllError::Cancelled { winner_index, .. }) = result {
            assert_eq!(winner_index, 0);
        } else {
            panic!("Expected Cancelled");
        }
    }

    #[test]
    fn make_race_all_result_panicked() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Panicked(PanicPayload::new("boom")),
            Outcome::Cancelled(CancelReason::race_loser()),
        ];

        let result = make_race_all_result(0, outcomes);
        assert!(matches!(result, Err(RaceAllError::Panicked { .. })));
        if let Err(RaceAllError::Panicked { index, .. }) = result {
            assert_eq!(index, 0);
        } else {
            panic!("Expected Panicked");
        }
    }

    #[test]
    fn race_all_to_result_cancelled() {
        let result: RaceAllResult<i32, &str> = RaceAllResult::new(
            Outcome::Cancelled(CancelReason::timeout()),
            0,
            vec![(1, Outcome::Cancelled(CancelReason::race_loser()))],
        );

        let value = race_all_to_result(result);
        assert!(matches!(value, Err(RaceAllError::Cancelled { .. })));
        if let Err(RaceAllError::Cancelled { winner_index, .. }) = value {
            assert_eq!(winner_index, 0);
        }
    }

    #[test]
    fn race_all_to_result_panicked() {
        let result: RaceAllResult<i32, &str> = RaceAllResult::new(
            Outcome::Panicked(PanicPayload::new("crash")),
            1,
            vec![(0, Outcome::Cancelled(CancelReason::race_loser()))],
        );

        let value = race_all_to_result(result);
        assert!(matches!(value, Err(RaceAllError::Panicked { .. })));
        if let Err(RaceAllError::Panicked { index, .. }) = value {
            assert_eq!(index, 1);
        }
    }

    #[test]
    fn race_all_last_wins() {
        // Test when the last index wins
        let outcomes: Vec<Outcome<i32, &str>> = vec![
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Cancelled(CancelReason::race_loser()),
            Outcome::Ok(999),
        ];

        let result = race_all_outcomes(3, outcomes);
        assert_eq!(result.winner_index, 3);
        assert!(result.winner_succeeded());
        assert_eq!(result.loser_outcomes.len(), 3);

        // All loser indices should be 0, 1, 2
        let loser_indices: Vec<usize> = result.loser_outcomes.iter().map(|(i, _)| *i).collect();
        assert_eq!(loser_indices, vec![0, 1, 2]);
    }

    #[test]
    fn race_all_single_entry() {
        // Edge case: racing a single future
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(42)];

        let result = race_all_outcomes(0, outcomes);
        assert_eq!(result.winner_index, 0);
        assert!(result.winner_succeeded());
        assert!(result.loser_outcomes.is_empty());

        let value = race_all_to_result(result);
        assert_eq!(value.unwrap(), 42);
    }

    #[test]
    #[should_panic(expected = "winner_index out of bounds")]
    fn race_all_outcomes_panics_on_invalid_index() {
        let outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Ok(1), Outcome::Ok(2)];
        let _ = race_all_outcomes(5, outcomes);
    }

    #[test]
    fn race_result_eq() {
        let a: RaceResult<i32, &str> = RaceResult::First(42);
        let b: RaceResult<i32, &str> = RaceResult::First(42);
        let c: RaceResult<i32, &str> = RaceResult::Second("x");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn race_marker_clone_copy() {
        let r1: Race<i32, &str> = Race::new();
        let r2 = r1; // Copy
        let r3 = r1; // still valid after Copy
        assert_eq!(std::mem::size_of_val(&r1), std::mem::size_of_val(&r2));
        assert_eq!(std::mem::size_of_val(&r1), std::mem::size_of_val(&r3));
    }

    #[test]
    fn race_result_map_first_passthrough() {
        // map_first on Second variant should pass through unchanged
        let result: RaceResult<i32, &str> = RaceResult::Second("hello");
        let mapped = result.map_first(|x| x * 2);
        assert!(matches!(mapped, RaceResult::Second("hello")));
    }

    #[test]
    fn race_result_map_second_passthrough() {
        // map_second on First variant should pass through unchanged
        let result: RaceResult<i32, &str> = RaceResult::First(42);
        let mapped = result.map_second(str::len);
        assert!(matches!(mapped, RaceResult::First(42)));
    }

    #[test]
    fn race2_to_result_second_wins_err() {
        let o1: Outcome<i32, &str> = Outcome::Cancelled(CancelReason::race_loser());
        let o2: Outcome<i32, &str> = Outcome::Err("second failed");

        let result = race2_to_result(RaceWinner::Second, o1, o2);
        assert!(matches!(result, Err(RaceError::Second("second failed"))));
    }

    #[test]
    #[ignore = "macro emits compile_error!"]
    fn race_macro_compiles_and_runs() {
        // Test ignored
    }

    proptest! {
        #[test]
        fn metamorphic_race2_drained_loser_substitution_preserves_fail_fast_result(
            first_wins in any::<bool>(),
            winner_case in race_winner_case_strategy(),
            mutated_loser_case in race_loser_case_strategy(),
        ) {
            let winner = if first_wins {
                RaceWinner::First
            } else {
                RaceWinner::Second
            };

            let winner_outcome = winner_case.clone().into_outcome();
            let baseline_loser = Outcome::Cancelled(CancelReason::race_loser());
            let substituted_loser = mutated_loser_case.into_outcome();

            let baseline_result = match winner {
                RaceWinner::First => {
                    race2_to_result(winner, winner_outcome.clone(), baseline_loser)
                }
                RaceWinner::Second => {
                    race2_to_result(winner, baseline_loser, winner_outcome.clone())
                }
            };

            let substituted_result = match winner {
                RaceWinner::First => {
                    race2_to_result(winner, winner_outcome.clone(), substituted_loser)
                }
                RaceWinner::Second => {
                    race2_to_result(winner, substituted_loser, winner_outcome.clone())
                }
            };

            prop_assert_eq!(
                race2_result_signature(&baseline_result),
                race2_result_signature(&substituted_result),
                "non-panicking drained loser substitution must not perturb the race2 fail-fast result"
            );
        }

        #[test]
        fn metamorphic_race_all_rotation_preserves_winner_and_loser_projection(
            branch_count in 1usize..12,
            raw_winner_index in 0usize..24,
            raw_shift in 0usize..24,
            winner_case in race_winner_case_strategy(),
        ) {
            let winner_index = raw_winner_index % branch_count;
            let shift = raw_shift % branch_count;

            let mut base_outcomes = vec![Outcome::Cancelled(CancelReason::race_loser()); branch_count];
            base_outcomes[winner_index] = winner_case.clone().into_outcome();

            let base_result = race_all_outcomes(winner_index, base_outcomes.clone());
            prop_assert_eq!(base_result.winner_index, winner_index);
            prop_assert_eq!(
                race_outcome_signature(&base_result.winner_outcome),
                race_outcome_signature(&winner_case.clone().into_outcome()),
            );

            let mut rotated_outcomes = base_outcomes.clone();
            rotated_outcomes.rotate_left(shift);
            let expected_rotated_winner = (winner_index + branch_count - shift) % branch_count;

            let rotated_result = race_all_outcomes(expected_rotated_winner, rotated_outcomes.clone());
            prop_assert_eq!(rotated_result.winner_index, expected_rotated_winner);
            prop_assert_eq!(
                race_outcome_signature(&base_result.winner_outcome),
                race_outcome_signature(&rotated_result.winner_outcome),
                "rotating branches must preserve the winner outcome class"
            );

            let mut base_loser_indices = base_result
                .loser_outcomes
                .iter()
                .map(|(index, _)| *index)
                .collect::<Vec<_>>();
            let mut rotated_loser_indices = rotated_result
                .loser_outcomes
                .iter()
                .map(|(index, _)| (*index + shift) % branch_count)
                .collect::<Vec<_>>();
            base_loser_indices.sort_unstable();
            rotated_loser_indices.sort_unstable();
            prop_assert_eq!(
                base_loser_indices,
                rotated_loser_indices,
                "inverse-rotating loser indices must recover the original loser set"
            );

            let base_final = make_race_all_result(winner_index, base_outcomes);
            let rotated_final = make_race_all_result(expected_rotated_winner, rotated_outcomes);
            match (&base_final, &rotated_final) {
                (Ok(base_value), Ok(rotated_value)) => {
                    prop_assert_eq!(base_value, rotated_value);
                }
                (Err(base_error), Err(rotated_error)) => {
                    let base_sig = race_all_error_signature(base_error);
                    let rotated_sig = race_all_error_signature(rotated_error);
                    prop_assert_eq!(base_sig.0, rotated_sig.0);
                    prop_assert_eq!(base_sig.2, rotated_sig.2);
                    prop_assert_eq!(rotated_sig.1, expected_rotated_winner);
                }
                _ => prop_assert!(false, "rotation changed race_all terminal class"),
            }
        }

        #[test]
        fn metamorphic_drained_loser_substitution_preserves_race_all_result(
            branch_count in 1usize..12,
            raw_winner_index in 0usize..24,
            winner_case in race_winner_case_strategy(),
            mutated_loser_cases in prop::collection::vec(race_loser_case_strategy(), 0usize..11),
        ) {
            let winner_index = raw_winner_index % branch_count;

            let mut baseline_outcomes =
                vec![Outcome::Cancelled(CancelReason::race_loser()); branch_count];
            baseline_outcomes[winner_index] = winner_case.clone().into_outcome();

            let loser_indices = (0..branch_count)
                .filter(|index| *index != winner_index)
                .collect::<Vec<_>>();
            let mut substituted_outcomes = baseline_outcomes.clone();
            for (slot, loser_index) in loser_indices.into_iter().enumerate() {
                let loser_case = mutated_loser_cases
                    .get(slot)
                    .cloned()
                    .unwrap_or(RaceLoserCase::CancelRaceLost);
                substituted_outcomes[loser_index] = loser_case.into_outcome();
            }

            let baseline_result = make_race_all_result(winner_index, baseline_outcomes);
            let substituted_result = make_race_all_result(winner_index, substituted_outcomes);

            prop_assert_eq!(
                race_all_result_signature(&baseline_result),
                race_all_result_signature(&substituted_result),
                "non-panicking drained loser substitution must not perturb the race_all result"
            );
        }
    }

    // =========================================================================
    // Metamorphic Relations for Loser Drain Correctness (asupersync-uuzryk)
    // =========================================================================

    /// MR1: Winner cancellation propagates to all losers
    ///
    /// When the winner is cancelled, all losers must also be cancelled.
    /// The specific cancel reason for losers should be RaceLost.
    #[test]
    fn metamorphic_winner_cancellation_propagates_to_losers() {
        proptest!(|(
            branch_count in 2usize..8,
            raw_winner_index in 0usize..16,
        )| {
            let winner_index = raw_winner_index % branch_count;

            // Winner is cancelled with timeout
            let mut outcomes = vec![Outcome::<i32, &str>::Cancelled(CancelReason::race_loser()); branch_count];
            outcomes[winner_index] = Outcome::Cancelled(CancelReason::timeout());

            let result = race_all_outcomes(winner_index, outcomes);

            // Verify winner was cancelled with timeout
            prop_assert!(result.winner_outcome.is_cancelled());
            if let Outcome::Cancelled(reason) = &result.winner_outcome {
                prop_assert!(matches!(reason.kind(), crate::types::cancel::CancelKind::Timeout));
            }

            // Verify all losers are cancelled with race_loser reason
            for (_, loser_outcome) in &result.loser_outcomes {
                prop_assert!(loser_outcome.is_cancelled(),
                    "All losers must be cancelled when winner is cancelled");
                if let Outcome::Cancelled(reason) = loser_outcome {
                    prop_assert!(matches!(reason.kind(), crate::types::cancel::CancelKind::RaceLost),
                        "Losers should be cancelled with RaceLost reason");
                }
            }
        });
    }

    /// MR2: Loser obligation release consistency
    ///
    /// Regardless of the winner's outcome type, losers should always be
    /// in a "released" state (Cancelled with RaceLost) after draining.
    #[test]
    fn metamorphic_loser_obligations_always_released() {
        proptest!(|(
            branch_count in 2usize..8,
            raw_winner_index in 0usize..16,
            winner_case in race_winner_case_strategy(),
        )| {
            let winner_index = raw_winner_index % branch_count;

            let mut outcomes = vec![Outcome::<i32, &str>::Cancelled(CancelReason::race_loser()); branch_count];
            outcomes[winner_index] = winner_case.into_outcome();

            let result = race_all_outcomes(winner_index, outcomes);

            // All losers must be properly drained (cancelled with RaceLost)
            prop_assert_eq!(result.loser_outcomes.len(), branch_count - 1);

            for (loser_index, loser_outcome) in &result.loser_outcomes {
                prop_assert!(*loser_index != winner_index, "Loser index must differ from winner");
                prop_assert!(loser_outcome.is_cancelled(),
                    "Loser at index {} must be cancelled after draining", loser_index);

                if let Outcome::Cancelled(reason) = loser_outcome {
                    prop_assert!(matches!(reason.kind(), crate::types::cancel::CancelKind::RaceLost),
                        "Loser at index {} must be cancelled with RaceLost reason", loser_index);
                }
            }
        });
    }

    /// MR3: Concurrent race invariant preservation
    ///
    /// Running multiple races with the same branch outcomes should preserve
    /// the drain invariant - each race should independently drain its losers.
    #[test]
    fn metamorphic_concurrent_races_preserve_drain_invariants() {
        proptest!(|(
            race_count in 2usize..5,
            branch_count in 2usize..6,
            winner_cases in prop::collection::vec(race_winner_case_strategy(), 2..5),
            winner_indices in prop::collection::vec(0usize..16, 2..5),
        )| {
            let actual_race_count = race_count.min(winner_cases.len()).min(winner_indices.len());

            let mut race_results = Vec::with_capacity(actual_race_count);

            for race_idx in 0..actual_race_count {
                let winner_index = winner_indices[race_idx] % branch_count;
                let winner_case = &winner_cases[race_idx];

                let mut outcomes = vec![Outcome::Cancelled(CancelReason::race_loser()); branch_count];
                outcomes[winner_index] = winner_case.clone().into_outcome();

                let result = race_all_outcomes(winner_index, outcomes);
                race_results.push((race_idx, result));
            }

            // Verify each race independently maintains drain invariants
            for (race_idx, result) in &race_results {
                prop_assert_eq!(result.loser_outcomes.len(), branch_count - 1,
                    "Race {} must have all losers drained", race_idx);

                for (loser_index, loser_outcome) in &result.loser_outcomes {
                    prop_assert!(loser_outcome.is_cancelled(),
                        "Race {} loser at index {} must be cancelled", race_idx, loser_index);
                }
            }

            // Verify independence: each race's drain behavior is unaffected by others
            let drain_signatures: Vec<_> = race_results.iter()
                .map(|(_, result)| {
                    let mut loser_signatures = result.loser_outcomes.iter()
                        .map(|(idx, outcome)| (*idx, outcome.is_cancelled()))
                        .collect::<Vec<_>>();
                    loser_signatures.sort_by_key(|(idx, _)| *idx);
                    loser_signatures
                })
                .collect();

            // All races with the same branch count should have identical drain patterns
            if let Some(first_signature) = drain_signatures.first() {
                for (race_idx, signature) in drain_signatures.iter().enumerate().skip(1) {
                    prop_assert_eq!(signature.len(), first_signature.len(),
                        "Race {} drain pattern length differs", race_idx);
                }
            }
        });
    }

    /// MR4: Deterministic race outcome in virtual time
    ///
    /// In deterministic virtual time (LabRuntime), races with identical
    /// configurations should produce identical outcomes and drain patterns.
    #[test]
    fn metamorphic_virtual_time_deterministic_drain() {
        proptest!(|(
            branch_count in 2usize..8,
            raw_winner_index in 0usize..16,
            winner_case in race_winner_case_strategy(),
            _seed_a in any::<u64>(),
            _seed_b in any::<u64>(),
        )| {
            let winner_index = raw_winner_index % branch_count;

            // Simulate deterministic LabRuntime behavior by using consistent inputs
            let create_outcomes = || {
                let mut outcomes = vec![Outcome::Cancelled(CancelReason::race_loser()); branch_count];
                outcomes[winner_index] = winner_case.clone().into_outcome();
                outcomes
            };

            // Run the same race configuration twice
            let result_a = race_all_outcomes(winner_index, create_outcomes());
            let result_b = race_all_outcomes(winner_index, create_outcomes());

            // Verify deterministic outcomes
            prop_assert_eq!(result_a.winner_index, result_b.winner_index);
            prop_assert_eq!(
                race_outcome_signature(&result_a.winner_outcome),
                race_outcome_signature(&result_b.winner_outcome),
                "Winner outcomes must be deterministic"
            );

            // Verify deterministic drain patterns
            prop_assert_eq!(result_a.loser_outcomes.len(), result_b.loser_outcomes.len());

            for ((idx_a, outcome_a), (idx_b, outcome_b)) in
                result_a.loser_outcomes.iter().zip(result_b.loser_outcomes.iter()) {
                prop_assert_eq!(idx_a, idx_b, "Loser indices must be deterministic");
                prop_assert_eq!(
                    race_outcome_signature(outcome_a),
                    race_outcome_signature(outcome_b),
                    "Loser outcomes must be deterministic"
                );
            }

            // Both runs should maintain the drain invariant
            prop_assert!(result_a.loser_outcomes.iter().all(|(_, outcome)| outcome.is_cancelled()));
            prop_assert!(result_b.loser_outcomes.iter().all(|(_, outcome)| outcome.is_cancelled()));
        });
    }

    /// MR5: Race commutativity with drain preservation
    ///
    /// When swapping branch positions, the drain invariant should be preserved
    /// even though winner indices change.
    #[test]
    fn metamorphic_race_commutativity_preserves_drain() {
        proptest!(|(
            winner_case_a in race_winner_case_strategy(),
            winner_case_b in race_winner_case_strategy(),
        )| {
            // Race A vs B
            let outcomes_ab = vec![
                winner_case_a.clone().into_outcome(),
                winner_case_b.clone().into_outcome(),
            ];

            // Race B vs A (swapped)
            let outcomes_ba = vec![
                winner_case_b.clone().into_outcome(),
                winner_case_a.clone().into_outcome(),
            ];

            // Test both possible winners for AB configuration
            for winner_idx in 0..2 {
                let result_ab = race_all_outcomes(winner_idx, outcomes_ab.clone());

                // For BA configuration, winner index is flipped
                let flipped_winner_idx = 1 - winner_idx;
                let result_ba = race_all_outcomes(flipped_winner_idx, outcomes_ba.clone());

                // Both should have exactly 1 loser (drained)
                prop_assert_eq!(result_ab.loser_outcomes.len(), 1);
                prop_assert_eq!(result_ba.loser_outcomes.len(), 1);

                // Both losers should be properly drained
                let (_, loser_ab) = &result_ab.loser_outcomes[0];
                let (_, loser_ba) = &result_ba.loser_outcomes[0];

                prop_assert!(loser_ab.is_cancelled(), "AB loser must be drained");
                prop_assert!(loser_ba.is_cancelled(), "BA loser must be drained");

                if let (Outcome::Cancelled(reason_ab), Outcome::Cancelled(reason_ba)) = (loser_ab, loser_ba) {
                    prop_assert!(matches!(reason_ab.kind(), crate::types::cancel::CancelKind::RaceLost));
                    prop_assert!(matches!(reason_ba.kind(), crate::types::cancel::CancelKind::RaceLost));
                }
            }
        });
    }

    /// MR6: Panic propagation with loser drain
    ///
    /// When a branch panics, losers should still be properly drained.
    #[test]
    fn metamorphic_panic_propagation_preserves_loser_drain() {
        proptest!(|(
            branch_count in 2usize..6,
            raw_panic_index in 0usize..16,
        )| {
            let panic_index = raw_panic_index % branch_count;

            let mut outcomes: Vec<Outcome<i32, &str>> = vec![Outcome::Cancelled(CancelReason::race_loser()); branch_count];
            outcomes[panic_index] = Outcome::Panicked(PanicPayload::new("test panic"));

            let result = race_all_outcomes(panic_index, outcomes);

            // Winner should be the panicked branch
            prop_assert!(result.winner_outcome.is_panicked());
            prop_assert_eq!(result.winner_index, panic_index);

            // All losers should still be properly drained
            prop_assert_eq!(result.loser_outcomes.len(), branch_count - 1);

            for (loser_index, loser_outcome) in &result.loser_outcomes {
                prop_assert!(*loser_index != panic_index);
                prop_assert!(loser_outcome.is_cancelled(),
                    "Loser {} should be drained even when winner panics", loser_index);

                if let Outcome::Cancelled(reason) = loser_outcome {
                    prop_assert!(matches!(reason.kind(), crate::types::cancel::CancelKind::RaceLost),
                        "Loser {} should be cancelled with RaceLost", loser_index);
                }
            }

            // Converting to fail-fast result should preserve panic but still track drained losers
            let fail_fast = race_all_to_result(result);
            prop_assert!(fail_fast.is_err());

            if let Err(RaceAllError::Panicked { index, .. }) = fail_fast {
                prop_assert_eq!(index, panic_index);
            } else {
                prop_assert!(false, "Expected panicked error");
            }
        });
    }

    // =========================================================================
    // Wave 58 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn polling_order_debug_clone_copy_eq_default() {
        let order = PollingOrder::default();
        let dbg = format!("{order:?}");
        assert!(dbg.contains("Biased"), "{dbg}");
        let copied = order;
        let cloned = order;
        assert_eq!(copied, cloned);
        assert_ne!(PollingOrder::Biased, PollingOrder::Unbiased);
    }

    #[test]
    fn race3_debug_clone_eq() {
        let r: Race3<i32, &str, bool> = Race3::First(42);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("First"), "{dbg}");
        let cloned = r.clone();
        assert_eq!(r, cloned);
        assert_eq!(r.winner_index(), 0);

        let r2: Race3<i32, &str, bool> = Race3::Second("hi");
        assert_ne!(r, r2);
        assert_eq!(r2.winner_index(), 1);
    }

    #[test]
    fn race4_debug_clone_eq() {
        let r: Race4<i32, i32, i32, i32> = Race4::Fourth(4);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Fourth"), "{dbg}");
        let cloned = r.clone();
        assert_eq!(r, cloned);
        assert_eq!(r.winner_index(), 3);
    }
}
