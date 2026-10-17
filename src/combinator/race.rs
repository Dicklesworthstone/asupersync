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
/// # Example
/// ```no_run
/// # use asupersync::Cx;
/// # async fn fetch_from_primary(_cx: &Cx) -> String { String::new() }
/// # async fn fetch_from_replica_1(_cx: &Cx) -> String { String::new() }
/// # async fn fetch_from_replica_2(_cx: &Cx) -> String { String::new() }
/// # async fn demo(cx: &Cx) -> Result<(), Box<dyn std::error::Error>> {
/// let scope = cx.scope();
/// // `Scope::race_all` races task handles, not bare futures: spawn each
/// // branch into the scope first.
/// let handles = vec![
///     cx.spawn_in(&scope, |cx| async move { fetch_from_primary(&cx).await })?,
///     cx.spawn_in(&scope, |cx| async move { fetch_from_replica_1(&cx).await })?,
///     cx.spawn_in(&scope, |cx| async move { fetch_from_replica_2(&cx).await })?,
/// ];
/// // Ok((value, winner_index)); the losers are cancelled and drained first.
/// let (value, winner) = scope.race_all(cx, handles).await?;
/// # let _ = (value, winner);
/// # Ok(())
/// # }
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

// ============================================================================
// L-LOSER-DRAINED enforcement (br-asupersync-ttoyaz)
//
// asupersync_v4_formal_semantics.md §4.2 (Lemma L-LOSER-DRAINED) states that
// after `race(r, f1, f2)` completes, every loser tL satisfies:
//
//   tL.outcome ∈ {
//       Cancelled(reason)  with reason.kind ⪰ RaceLost,
//       Ok(_) | Err(_) | Panicked(_)   // loser-just-finished branch
//   }
//
// The previous shape relied entirely on `await(loser)` returning to imply this
// — true at the type level because `Outcome` has no in-flight variant, but
// invisible to readers and silently broken by any future Outcome variant
// addition. The check below is the explicit witness that the invariant holds.
// ============================================================================

/// A reason why a candidate loser-outcome violates the L-LOSER-DRAINED
/// invariant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoserDrainViolation {
    /// A loser was reported as `Cancelled` but with a kind weaker than
    /// `RaceLost`. Race losers must always carry at least `RaceLost`-tier
    /// severity (or stronger if a parent cancel already raised the bar).
    CancelKindTooWeak {
        /// Index of the offending loser in the input slice.
        index: usize,
        /// Severity tier the loser actually carried.
        seen_severity: u8,
        /// The minimum severity tier required (always `RaceLost.severity()`).
        required_severity: u8,
    },
}

impl fmt::Display for LoserDrainViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CancelKindTooWeak {
                index,
                seen_severity,
                required_severity,
            } => write!(
                f,
                "race loser at index {index} has Cancelled kind with severity {seen_severity} \
                 (required >= {required_severity} for RaceLost or stronger)"
            ),
        }
    }
}

impl std::error::Error for LoserDrainViolation {}

/// Type-level witness that all losers in a race have been drained to a
/// terminal `Outcome` consistent with L-LOSER-DRAINED.
///
/// Constructed only via [`verify_losers_drained`] (the explicit check) or
/// `assert_losers_drained` (the panicking variant used inside the result
/// constructors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "construct a LosersDrainedWitness only as part of an actual drain check"]
pub struct LosersDrainedWitness {
    losers_checked: usize,
}

impl LosersDrainedWitness {
    /// Number of losers this witness covers.
    #[inline]
    #[must_use]
    pub const fn losers_checked(&self) -> usize {
        self.losers_checked
    }
}

/// Verify that every loser outcome satisfies L-LOSER-DRAINED.
///
/// Returns `Ok(LosersDrainedWitness)` on success, `Err(LoserDrainViolation)`
/// on the first violation found.
///
/// `Outcome` itself has no non-terminal variant, so reaching this function
/// with any `Outcome` value already implies the loser's driver future
/// resolved. The interesting check this function performs is on
/// `Cancelled(reason)` losers: the reason's severity must be at least
/// `RaceLost`. Anything weaker (e.g., `User`-cancel attributed to the loser
/// without strengthening) means the race driver did not propagate the
/// `RaceLost` cancel correctly.
pub fn verify_losers_drained<T, E>(
    losers: &[&Outcome<T, E>],
) -> Result<LosersDrainedWitness, LoserDrainViolation> {
    use crate::types::cancel::CancelKind;
    let required = CancelKind::RaceLost.severity();
    for (index, outcome) in losers.iter().enumerate() {
        if let Outcome::Cancelled(reason) = outcome {
            let seen = reason.kind.severity();
            if seen < required {
                return Err(LoserDrainViolation::CancelKindTooWeak {
                    index,
                    seen_severity: seen,
                    required_severity: required,
                });
            }
        }
    }
    Ok(LosersDrainedWitness {
        losers_checked: losers.len(),
    })
}

/// Panicking variant of [`verify_losers_drained`]. Used inside the race
/// result constructors so any L-LOSER-DRAINED violation surfaces immediately
/// at the boundary between the race driver and the result-shape layer.
///
/// Wired into [`race2_outcomes`] and [`make_race_all_result`]
/// (br-asupersync-ttoyaz / br-asupersync-jf1e6h) — every race result that
/// the public API hands back to a caller passes through this assertion.
///
/// # Panics
///
/// Panics with the offending [`LoserDrainViolation`] if the check fails.
#[track_caller]
fn assert_losers_drained<T, E>(losers: &[&Outcome<T, E>]) -> LosersDrainedWitness {
    match verify_losers_drained(losers) {
        Ok(witness) => witness,
        Err(violation) => panic!("[ASUP-E302] L-LOSER-DRAINED invariant violated: {violation}"),
    }
}

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
/// # Panics
/// Panics with `[ASUP-E302]` if the loser is `Cancelled` with a reason weaker
/// than [`CancelKind::RaceLost`](crate::types::CancelKind::RaceLost), such as
/// a `Timeout` it reached on its own (see [`verify_losers_drained`]).
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
    // L-LOSER-DRAINED check: the loser must satisfy the §4.2 invariant
    // before we hand the race result back. (br-asupersync-ttoyaz)
    let _witness = match winner {
        RaceWinner::First => assert_losers_drained::<T, E>(&[&o2]),
        RaceWinner::Second => assert_losers_drained::<T, E>(&[&o1]),
    };
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
/// # Panics
/// Panics like [`race2_outcomes`] if the loser is `Cancelled` with a reason
/// weaker than `RaceLost`.
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
/// Panics if `winner_index` is out of bounds, or with `[ASUP-E302]` if a loser
/// is `Cancelled` with a reason weaker than `RaceLost` (see
/// [`verify_losers_drained`]).
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

    // L-LOSER-DRAINED check: the §4.2 invariant must hold for every loser
    // before we expose the race result. (br-asupersync-ttoyaz)
    let loser_refs: Vec<&Outcome<T, E>> =
        loser_outcomes.iter().map(|(_, outcome)| outcome).collect();
    let _witness = assert_losers_drained::<T, E>(&loser_refs);

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
/// Panics if `winner_index` is out of bounds, or with `[ASUP-E302]` if a loser
/// is `Cancelled` with a reason weaker than `RaceLost` (see
/// [`verify_losers_drained`]).
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

/// Contract-enforcement fallback for builds without the `proc-macros` feature.
///
/// In `proc-macros` builds, the supported root macro DSL re-exports the real
/// `race!` proc macro from the crate root (`use asupersync::race;`).
///
/// When `proc-macros` is disabled, the macro DSL is intentionally unavailable.
/// This fallback exists only to fail fast with a truthful error message
/// instead of pretending a fallback macro exists.
///
/// Without that feature, use the `Scope` APIs (`Scope::race`,
/// `Scope::race_all`) when racing spawned tasks.
///
/// # Real `race!` contract (with `proc-macros`)
///
/// The shipped `race!` is the proc macro re-exported at the crate root. It takes
/// an explicit `cx` first and braces its branch list; there is no positional or
/// `biased;` form (that biasing lives on `select!`). Every loser is
/// protocol-cancelled **and drained** before it returns — it never drops losers
/// — and it resolves to `Result<T, JoinError>`:
///
/// ```ignore
/// let winner = race!(cx, { primary.fetch(), backup.fetch() })?;
/// let winner = race!(cx, { "fast" => a(), "slow" => b() })?;
/// let winner = race!(cx, timeout: Duration::from_secs(5), { a(), b() })?;
/// ```
///
/// # Without `proc-macros`
///
/// This fallback is intentionally inert: it expands to a `compile_error!` rather
/// than pretending a fallback macro exists. Use the `Scope` APIs (`Scope::race`,
/// `Scope::race_all`) for drained task races, or `Cx::race` for a drop-on-cancel
/// inline future race.
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
#[path = "race_inline_tests.rs"]
mod tests;
