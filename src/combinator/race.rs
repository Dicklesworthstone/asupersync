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
//! The winner's outcome is returned directly. The loser is cancelled and
//! drained, but its outcome is not part of the race result (it's tracked
//! for invariant verification only).

use core::fmt;
use std::marker::PhantomData;

use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use crate::types::Outcome;

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
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _a: PhantomData,
            _b: PhantomData,
        }
    }
}

impl<A, B> Default for Race<A, B> {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of a race, indicating which branch won.
#[derive(Debug, Clone)]
pub enum RaceResult<A, B> {
    /// The first branch won.
    First(A),
    /// The second branch won.
    Second(B),
}

impl<A, B> RaceResult<A, B> {
    /// Returns true if the first branch won.
    #[must_use]
    pub const fn is_first(&self) -> bool {
        matches!(self, Self::First(_))
    }

    /// Returns true if the second branch won.
    #[must_use]
    pub const fn is_second(&self) -> bool {
        matches!(self, Self::Second(_))
    }

    /// Maps the first variant.
    pub fn map_first<C, F: FnOnce(A) -> C>(self, f: F) -> RaceResult<C, B> {
        match self {
            Self::First(a) => RaceResult::First(f(a)),
            Self::Second(b) => RaceResult::Second(b),
        }
    }

    /// Maps the second variant.
    pub fn map_second<C, F: FnOnce(B) -> C>(self, f: F) -> RaceResult<A, C> {
        match self {
            Self::First(a) => RaceResult::First(a),
            Self::Second(b) => RaceResult::Second(f(b)),
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
    /// The winner panicked.
    Panicked(PanicPayload),
}

impl<E: fmt::Display> fmt::Display for RaceError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::First(e) => write!(f, "first branch won with error: {e}"),
            Self::Second(e) => write!(f, "second branch won with error: {e}"),
            Self::Cancelled(r) => write!(f, "winner was cancelled: {r}"),
            Self::Panicked(p) => write!(f, "winner panicked: {p}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for RaceError<E> {}

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
    #[must_use]
    pub const fn is_first(self) -> bool {
        matches!(self, Self::First)
    }

    /// Returns true if the second branch won.
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
/// If the winner succeeded, returns `Ok` with the value.
/// If the winner failed (error, cancelled, or panicked), returns `Err`.
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
pub fn race2_to_result<T, E>(
    winner: RaceWinner,
    o1: Outcome<T, E>,
    o2: Outcome<T, E>,
) -> Result<T, RaceError<E>> {
    let (winner_outcome, which_won, _loser_outcome) = race2_outcomes(winner, o1, o2);

    match winner_outcome {
        Outcome::Ok(v) => Ok(v),
        Outcome::Err(e) => match which_won {
            RaceWinner::First => Err(RaceError::First(e)),
            RaceWinner::Second => Err(RaceError::Second(e)),
        },
        Outcome::Cancelled(r) => Err(RaceError::Cancelled(r)),
        Outcome::Panicked(p) => Err(RaceError::Panicked(p)),
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
#[must_use]
pub fn race_all_outcomes<T, E>(
    winner_index: usize,
    outcomes: Vec<Outcome<T, E>>,
) -> RaceAllResult<T, E> {
    assert!(winner_index < outcomes.len(), "winner_index out of bounds");

    let mut iter = outcomes.into_iter().enumerate();
    let mut winner_outcome = None;
    let mut loser_outcomes = Vec::new();

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
/// If the winner succeeded, returns `Ok` with the value.
/// If the winner failed, returns `Err` with a `RaceError`.
pub fn race_all_to_result<T, E>(result: RaceAllResult<T, E>) -> Result<T, RaceError<E>> {
    match result.winner_outcome {
        Outcome::Ok(v) => Ok(v),
        Outcome::Err(e) => Err(RaceError::First(e)), // Use First for any error (could add index info)
        Outcome::Cancelled(r) => Err(RaceError::Cancelled(r)),
        Outcome::Panicked(p) => Err(RaceError::Panicked(p)),
    }
}

/// Macro for racing multiple futures (placeholder).
///
/// In the full implementation, this spawns tasks and races them,
/// cancelling and draining all losers when the first completes.
///
/// # Example (API shape)
/// ```ignore
/// let result = race!(
///     async { fetch_from_primary().await },
///     async { fetch_from_replica().await },
/// );
/// ```
#[macro_export]
macro_rules! race {
    ($($future:expr),+ $(,)?) => {
        // Placeholder: in real implementation, this spawns and races
        {
            $(let _ = $future;)+
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

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
            0,
            vec![(1, Outcome::Cancelled(CancelReason::race_loser()))],
        );

        let value = race_all_to_result(result);
        assert!(matches!(value, Err(RaceError::First("failed"))));
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
}
