//! Hedge combinator for latency hedging.
//!
//! The hedge combinator implements latency hedging - start a primary task, and if
//! it does not complete within a deadline, speculatively start a backup. Return
//! whichever completes first. This is a key pattern for reducing tail latency in
//! distributed systems.
//!
//! # Motivation
//!
//! P99 latencies often exceed P50 by 10-100x. Hedging trades compute cost for latency:
//! - Primary starts immediately
//! - If deadline expires without completion, backup launches
//! - First to complete wins; loser is cancelled and drained
//! - Total latency bounded by min(primary, backup) rather than max
//!
//! # Critical Invariant: Losers Are Drained
//!
//! Like race, hedge guarantees that the losing operation (whether primary or backup)
//! is cancelled AND drained before returning:
//!
//! ```text
//! hedge(primary, backup_fn, deadline):
//!   t1 <- spawn(primary)
//!   case:
//!     | t1 completes before deadline -> return t1.outcome
//!     | deadline fires ->
//!         t2 <- spawn(backup_fn())
//!         (winner, loser) <- select_first_complete(t1, t2)
//!         cancel(loser)
//!         await(loser)  // CRITICAL: drain the loser
//!         return winner.outcome
//! ```
//!
//! # Algebraic Properties
//!
//! - If primary always completes before deadline: `hedge(p, b, d) ≃ p`
//! - If primary never completes before deadline: `hedge(p, b, d) ≃ race(p, b)`
//! - Budget composition: `hedge_budget = primary_budget + backup_budget + deadline`
//!
//! # Cancellation Handling
//!
//! - If caller requests cancel before primary completes: cancel primary, never spawn backup
//! - If caller requests cancel during race: cancel both, drain both

use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use crate::types::{Outcome, Time};
use core::fmt;
use std::marker::PhantomData;
use std::time::Duration;

/// Configuration for a hedge operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HedgeConfig {
    /// The deadline after which to spawn the backup.
    pub hedge_delay: Duration,
    /// Whether the backup was actually spawned.
    /// This is set by the runtime after execution.
    pub backup_spawned: bool,
}

impl HedgeConfig {
    /// Creates a new hedge configuration with the given delay.
    #[must_use]
    pub const fn new(hedge_delay: Duration) -> Self {
        Self {
            hedge_delay,
            backup_spawned: false,
        }
    }

    /// Creates a hedge configuration from milliseconds.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self::new(Duration::from_millis(millis))
    }

    /// Creates a hedge configuration from seconds.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self::new(Duration::from_secs(secs))
    }

    /// Returns true if the delay has elapsed.
    #[must_use]
    pub fn delay_elapsed(&self, start: Time, now: Time) -> bool {
        let elapsed_nanos = now.as_nanos().saturating_sub(start.as_nanos());
        elapsed_nanos >= self.hedge_delay_nanos_u64()
    }

    /// Computes the deadline time given a start time.
    #[must_use]
    pub fn deadline_from(&self, start: Time) -> Time {
        start.saturating_add_nanos(self.hedge_delay_nanos_u64())
    }

    fn hedge_delay_nanos_u64(&self) -> u64 {
        let nanos = self.hedge_delay.as_nanos();
        if nanos > u128::from(u64::MAX) {
            u64::MAX
        } else {
            nanos as u64
        }
    }
}

impl Default for HedgeConfig {
    fn default() -> Self {
        // Default to 100ms hedge delay - a common value for RPC hedging
        Self::from_millis(100)
    }
}

/// A hedge combinator marker type.
///
/// This is a builder/marker type; actual execution happens via the runtime.
#[derive(Debug)]
pub struct Hedge<T> {
    /// The hedge configuration.
    pub config: HedgeConfig,
    _t: PhantomData<T>,
}

impl<T> Hedge<T> {
    /// Creates a new hedge combinator with the given delay.
    #[must_use]
    pub const fn new(hedge_delay: Duration) -> Self {
        Self {
            config: HedgeConfig::new(hedge_delay),
            _t: PhantomData,
        }
    }

    /// Creates a hedge combinator from milliseconds.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self::new(Duration::from_millis(millis))
    }

    /// Creates a hedge combinator from seconds.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self::new(Duration::from_secs(secs))
    }

    /// Returns the hedge delay.
    #[must_use]
    pub const fn delay(&self) -> Duration {
        self.config.hedge_delay
    }
}

impl<T> Clone for Hedge<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Hedge<T> {}

impl<T> Default for Hedge<T> {
    fn default() -> Self {
        Self {
            config: HedgeConfig::default(),
            _t: PhantomData,
        }
    }
}

/// Which branch won in a hedged operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HedgeWinner {
    /// The primary operation completed first.
    Primary,
    /// The backup operation completed first.
    Backup,
}

impl HedgeWinner {
    /// Returns true if the primary won.
    #[must_use]
    pub const fn is_primary(self) -> bool {
        matches!(self, Self::Primary)
    }

    /// Returns true if the backup won.
    #[must_use]
    pub const fn is_backup(self) -> bool {
        matches!(self, Self::Backup)
    }
}

/// The result of a hedge operation.
#[derive(Debug, Clone)]
pub enum HedgeResult<T, E> {
    /// Primary completed before the hedge deadline (backup never spawned).
    PrimaryFast(Outcome<T, E>),
    /// Hedge race occurred; includes winner, which won, and loser (if backup was spawned).
    Raced {
        /// The winner's outcome.
        winner_outcome: Outcome<T, E>,
        /// Which branch won.
        winner: HedgeWinner,
        /// The loser's outcome after being cancelled and drained.
        /// This is always present when a race occurred.
        loser_outcome: Outcome<T, E>,
    },
}

impl<T, E> HedgeResult<T, E> {
    /// Creates a result for when primary completes before the hedge deadline.
    #[must_use]
    pub fn primary_fast(outcome: Outcome<T, E>) -> Self {
        Self::PrimaryFast(outcome)
    }

    /// Creates a result for a hedge race where primary won.
    #[must_use]
    pub fn primary_won(primary_outcome: Outcome<T, E>, backup_outcome: Outcome<T, E>) -> Self {
        Self::Raced {
            winner_outcome: primary_outcome,
            winner: HedgeWinner::Primary,
            loser_outcome: backup_outcome,
        }
    }

    /// Creates a result for a hedge race where backup won.
    #[must_use]
    pub fn backup_won(backup_outcome: Outcome<T, E>, primary_outcome: Outcome<T, E>) -> Self {
        Self::Raced {
            winner_outcome: backup_outcome,
            winner: HedgeWinner::Backup,
            loser_outcome: primary_outcome,
        }
    }

    /// Returns true if primary completed before the hedge deadline.
    #[must_use]
    pub const fn is_primary_fast(&self) -> bool {
        matches!(self, Self::PrimaryFast(_))
    }

    /// Returns true if a race occurred (backup was spawned).
    #[must_use]
    pub const fn was_raced(&self) -> bool {
        matches!(self, Self::Raced { .. })
    }

    /// Returns the winner's outcome.
    #[must_use]
    pub fn winner_outcome(&self) -> &Outcome<T, E> {
        match self {
            Self::PrimaryFast(o) => o,
            Self::Raced { winner_outcome, .. } => winner_outcome,
        }
    }

    /// Consumes self and returns the winner's outcome.
    #[must_use]
    pub fn into_winner_outcome(self) -> Outcome<T, E> {
        match self {
            Self::PrimaryFast(o) => o,
            Self::Raced { winner_outcome, .. } => winner_outcome,
        }
    }

    /// Returns true if the winner succeeded (returned Ok).
    #[must_use]
    pub fn winner_succeeded(&self) -> bool {
        self.winner_outcome().is_ok()
    }

    /// Returns which branch won (always Primary for `PrimaryFast`).
    #[must_use]
    pub const fn winner(&self) -> HedgeWinner {
        match self {
            Self::PrimaryFast(_) => HedgeWinner::Primary,
            Self::Raced { winner, .. } => *winner,
        }
    }

    /// Returns the loser's outcome, if a race occurred.
    #[must_use]
    pub fn loser_outcome(&self) -> Option<&Outcome<T, E>> {
        match self {
            Self::PrimaryFast(_) => None,
            Self::Raced { loser_outcome, .. } => Some(loser_outcome),
        }
    }
}

/// Error type for hedge operations.
///
/// When a hedge fails (winner has an error/cancel/panic), this type
/// indicates which branch won and why it failed.
#[derive(Debug, Clone)]
pub enum HedgeError<E> {
    /// Primary completed fast with an error.
    PrimaryFastError(E),
    /// Primary won the race with an error.
    PrimaryError(E),
    /// Backup won the race with an error.
    BackupError(E),
    /// The winner was cancelled.
    Cancelled(CancelReason),
    /// The winner panicked.
    Panicked(PanicPayload),
}

impl<E: fmt::Display> fmt::Display for HedgeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrimaryFastError(e) => write!(f, "primary completed fast with error: {e}"),
            Self::PrimaryError(e) => write!(f, "primary won race with error: {e}"),
            Self::BackupError(e) => write!(f, "backup won race with error: {e}"),
            Self::Cancelled(r) => write!(f, "winner was cancelled: {r}"),
            Self::Panicked(p) => write!(f, "winner panicked: {p}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for HedgeError<E> {}

/// Constructs a hedge result from outcomes based on whether backup was spawned.
///
/// # Arguments
/// * `primary_outcome` - The outcome from the primary operation
/// * `backup_spawned` - Whether the backup was spawned (deadline elapsed)
/// * `backup_outcome` - The outcome from the backup (if spawned)
/// * `winner` - Which branch won (only relevant if backup was spawned)
///
/// # Example
/// ```
/// use asupersync::combinator::hedge::{hedge_outcomes, HedgeWinner};
/// use asupersync::types::Outcome;
///
/// // Primary completed before hedge deadline
/// let result = hedge_outcomes::<i32, &str>(
///     Outcome::Ok(42),
///     false,
///     None,
///     None,
/// );
/// assert!(result.is_primary_fast());
///
/// // Hedge race occurred, backup won
/// let result = hedge_outcomes::<i32, &str>(
///     Outcome::Cancelled(asupersync::types::cancel::CancelReason::race_loser()),
///     true,
///     Some(Outcome::Ok(99)),
///     Some(HedgeWinner::Backup),
/// );
/// assert!(result.was_raced());
/// assert!(result.winner().is_backup());
/// ```
#[must_use]
pub fn hedge_outcomes<T, E>(
    primary_outcome: Outcome<T, E>,
    backup_spawned: bool,
    backup_outcome: Option<Outcome<T, E>>,
    winner: Option<HedgeWinner>,
) -> HedgeResult<T, E> {
    if backup_spawned {
        // Hedge race occurred
        let backup_outcome = backup_outcome.expect("backup_outcome required when backup_spawned");
        let winner = winner.expect("winner required when backup_spawned");

        match winner {
            HedgeWinner::Primary => HedgeResult::primary_won(primary_outcome, backup_outcome),
            HedgeWinner::Backup => HedgeResult::backup_won(backup_outcome, primary_outcome),
        }
    } else {
        assert!(
            backup_outcome.is_none(),
            "backup_outcome must be None when backup_spawned is false"
        );
        assert!(
            winner.is_none(),
            "winner must be None when backup_spawned is false"
        );
        // Primary completed before hedge deadline
        HedgeResult::primary_fast(primary_outcome)
    }
}

/// Converts a hedge result to a standard Result for fail-fast handling.
///
/// If the winner succeeded, returns `Ok` with the value.
/// If the winner failed (error, cancelled, or panicked), returns `Err`.
///
/// # Example
/// ```
/// use asupersync::combinator::hedge::{hedge_to_result, HedgeResult};
/// use asupersync::types::Outcome;
///
/// // Primary fast success
/// let result: HedgeResult<i32, &str> = HedgeResult::primary_fast(Outcome::Ok(42));
/// assert_eq!(hedge_to_result(result).unwrap(), 42);
///
/// // Backup won with error
/// let result: HedgeResult<i32, &str> = HedgeResult::backup_won(
///     Outcome::Err("backup failed"),
///     Outcome::Cancelled(asupersync::types::cancel::CancelReason::race_loser()),
/// );
/// assert!(hedge_to_result(result).is_err());
/// ```
pub fn hedge_to_result<T, E>(result: HedgeResult<T, E>) -> Result<T, HedgeError<E>> {
    match result {
        HedgeResult::PrimaryFast(outcome) => match outcome {
            Outcome::Ok(v) => Ok(v),
            Outcome::Err(e) => Err(HedgeError::PrimaryFastError(e)),
            Outcome::Cancelled(r) => Err(HedgeError::Cancelled(r)),
            Outcome::Panicked(p) => Err(HedgeError::Panicked(p)),
        },
        HedgeResult::Raced {
            winner_outcome,
            winner,
            ..
        } => match winner_outcome {
            Outcome::Ok(v) => Ok(v),
            Outcome::Err(e) => match winner {
                HedgeWinner::Primary => Err(HedgeError::PrimaryError(e)),
                HedgeWinner::Backup => Err(HedgeError::BackupError(e)),
            },
            Outcome::Cancelled(r) => Err(HedgeError::Cancelled(r)),
            Outcome::Panicked(p) => Err(HedgeError::Panicked(p)),
        },
    }
}

/// Macro for hedging an operation (not yet implemented).
///
/// In the full implementation, this spawns the primary, waits for the deadline,
/// and races with the backup if needed.
///
/// # Example (API shape)
/// ```ignore
/// let result = hedge!(
///     100.millis(),           // hedge delay
///     call_primary_server(),  // primary future
///     || call_backup_server() // backup closure (only called if needed)
/// );
/// ```
#[macro_export]
macro_rules! hedge {
    ($delay:expr, $primary:expr, $backup:expr) => {
        compile_error!(
            "hedge! macro not yet implemented; use hedge_outcomes or hedge_to_result instead"
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // HedgeConfig Tests
    // =========================================================================

    #[test]
    fn hedge_config_from_millis() {
        let config = HedgeConfig::from_millis(100);
        assert_eq!(config.hedge_delay, Duration::from_millis(100));
        assert!(!config.backup_spawned);
    }

    #[test]
    fn hedge_config_from_secs() {
        let config = HedgeConfig::from_secs(5);
        assert_eq!(config.hedge_delay, Duration::from_secs(5));
    }

    #[test]
    fn hedge_config_default() {
        let config = HedgeConfig::default();
        assert_eq!(config.hedge_delay, Duration::from_millis(100));
    }

    #[test]
    fn hedge_config_delay_elapsed() {
        let config = HedgeConfig::from_millis(100);
        let start = Time::from_nanos(1_000_000); // 1ms

        // Not elapsed yet (50ms later)
        let now = Time::from_nanos(51_000_000);
        assert!(!config.delay_elapsed(start, now));

        // Exactly at deadline (100ms later)
        let now = Time::from_nanos(101_000_000);
        assert!(config.delay_elapsed(start, now));

        // After deadline (200ms later)
        let now = Time::from_nanos(201_000_000);
        assert!(config.delay_elapsed(start, now));
    }

    #[test]
    fn hedge_config_deadline_from() {
        let config = HedgeConfig::from_millis(100);
        let start = Time::from_nanos(1_000_000); // 1ms

        let deadline = config.deadline_from(start);
        assert_eq!(deadline.as_nanos(), 101_000_000); // 101ms
    }

    #[test]
    fn hedge_config_deadline_from_saturates_on_large_duration() {
        let config = HedgeConfig::new(Duration::from_secs(u64::MAX));
        let start = Time::from_nanos(1);

        let deadline = config.deadline_from(start);
        assert_eq!(deadline, Time::MAX);
    }

    // =========================================================================
    // Hedge Combinator Type Tests
    // =========================================================================

    #[test]
    fn hedge_creation() {
        let hedge = Hedge::<()>::from_millis(200);
        assert_eq!(hedge.delay(), Duration::from_millis(200));
    }

    #[test]
    fn hedge_clone_and_copy() {
        let h1 = Hedge::<()>::from_millis(100);
        let h2 = h1; // Copy
        let h3 = h1; // Also copy

        assert_eq!(h1.delay(), h2.delay());
        assert_eq!(h1.delay(), h3.delay());
    }

    #[test]
    fn hedge_default() {
        let hedge = Hedge::<()>::default();
        assert_eq!(hedge.delay(), Duration::from_millis(100));
    }

    // =========================================================================
    // HedgeWinner Tests
    // =========================================================================

    #[test]
    fn hedge_winner_is_primary() {
        assert!(HedgeWinner::Primary.is_primary());
        assert!(!HedgeWinner::Primary.is_backup());
    }

    #[test]
    fn hedge_winner_is_backup() {
        assert!(!HedgeWinner::Backup.is_primary());
        assert!(HedgeWinner::Backup.is_backup());
    }

    // =========================================================================
    // HedgeResult Tests
    // =========================================================================

    #[test]
    fn hedge_result_primary_fast() {
        let result: HedgeResult<i32, &str> = HedgeResult::primary_fast(Outcome::Ok(42));

        assert!(result.is_primary_fast());
        assert!(!result.was_raced());
        assert!(result.winner().is_primary());
        assert!(result.winner_succeeded());
        assert!(result.loser_outcome().is_none());
    }

    #[test]
    fn hedge_result_primary_won_race() {
        let result: HedgeResult<i32, &str> = HedgeResult::primary_won(
            Outcome::Ok(42),
            Outcome::Cancelled(CancelReason::race_loser()),
        );

        assert!(!result.is_primary_fast());
        assert!(result.was_raced());
        assert!(result.winner().is_primary());
        assert!(result.winner_succeeded());
        assert!(result.loser_outcome().is_some());
        assert!(result.loser_outcome().unwrap().is_cancelled());
    }

    #[test]
    fn hedge_result_backup_won_race() {
        let result: HedgeResult<i32, &str> = HedgeResult::backup_won(
            Outcome::Ok(99),
            Outcome::Cancelled(CancelReason::race_loser()),
        );

        assert!(!result.is_primary_fast());
        assert!(result.was_raced());
        assert!(result.winner().is_backup());
        assert!(result.winner_succeeded());
        assert!(result.loser_outcome().is_some());
    }

    #[test]
    fn hedge_result_winner_outcome() {
        let result: HedgeResult<i32, &str> = HedgeResult::backup_won(
            Outcome::Ok(99),
            Outcome::Cancelled(CancelReason::race_loser()),
        );

        assert!(result.winner_outcome().is_ok());
        if let Outcome::Ok(v) = result.winner_outcome() {
            assert_eq!(*v, 99);
        }
    }

    #[test]
    fn hedge_result_into_winner_outcome() {
        let result: HedgeResult<i32, &str> = HedgeResult::primary_fast(Outcome::Ok(42));
        let outcome = result.into_winner_outcome();
        assert!(matches!(outcome, Outcome::Ok(42)));
    }

    // =========================================================================
    // hedge_outcomes Tests
    // =========================================================================

    #[test]
    fn hedge_outcomes_primary_fast() {
        let result = hedge_outcomes::<i32, &str>(Outcome::Ok(42), false, None, None);

        assert!(result.is_primary_fast());
        assert!(result.winner_succeeded());
    }

    #[test]
    fn hedge_outcomes_primary_won_race() {
        let result = hedge_outcomes::<i32, &str>(
            Outcome::Ok(42),
            true,
            Some(Outcome::Cancelled(CancelReason::race_loser())),
            Some(HedgeWinner::Primary),
        );

        assert!(result.was_raced());
        assert!(result.winner().is_primary());
        assert!(result.winner_succeeded());
    }

    #[test]
    fn hedge_outcomes_backup_won_race() {
        let result = hedge_outcomes::<i32, &str>(
            Outcome::Cancelled(CancelReason::race_loser()),
            true,
            Some(Outcome::Ok(99)),
            Some(HedgeWinner::Backup),
        );

        assert!(result.was_raced());
        assert!(result.winner().is_backup());
        assert!(result.winner_succeeded());
    }

    #[test]
    #[should_panic(expected = "backup_outcome required")]
    fn hedge_outcomes_panics_without_backup_outcome() {
        let _ =
            hedge_outcomes::<i32, &str>(Outcome::Ok(42), true, None, Some(HedgeWinner::Primary));
    }

    #[test]
    #[should_panic(expected = "winner required")]
    fn hedge_outcomes_panics_without_winner() {
        let _ = hedge_outcomes::<i32, &str>(
            Outcome::Ok(42),
            true,
            Some(Outcome::Cancelled(CancelReason::race_loser())),
            None,
        );
    }

    #[test]
    #[should_panic(expected = "backup_outcome must be None")]
    fn hedge_outcomes_panics_on_backup_outcome_when_not_spawned() {
        let _ = hedge_outcomes::<i32, &str>(
            Outcome::Ok(42),
            false,
            Some(Outcome::Cancelled(CancelReason::race_loser())),
            None,
        );
    }

    #[test]
    #[should_panic(expected = "winner must be None")]
    fn hedge_outcomes_panics_on_winner_when_not_spawned() {
        let _ = hedge_outcomes::<i32, &str>(
            Outcome::Ok(42),
            false,
            None,
            Some(HedgeWinner::Primary),
        );
    }

    // =========================================================================
    // hedge_to_result Tests
    // =========================================================================

    #[test]
    fn hedge_to_result_primary_fast_ok() {
        let result: HedgeResult<i32, &str> = HedgeResult::primary_fast(Outcome::Ok(42));
        assert_eq!(hedge_to_result(result).unwrap(), 42);
    }

    #[test]
    fn hedge_to_result_primary_fast_err() {
        let result: HedgeResult<i32, &str> = HedgeResult::primary_fast(Outcome::Err("failed"));
        assert!(matches!(
            hedge_to_result(result),
            Err(HedgeError::PrimaryFastError("failed"))
        ));
    }

    #[test]
    fn hedge_to_result_primary_won_ok() {
        let result: HedgeResult<i32, &str> = HedgeResult::primary_won(
            Outcome::Ok(42),
            Outcome::Cancelled(CancelReason::race_loser()),
        );
        assert_eq!(hedge_to_result(result).unwrap(), 42);
    }

    #[test]
    fn hedge_to_result_primary_won_err() {
        let result: HedgeResult<i32, &str> = HedgeResult::primary_won(
            Outcome::Err("primary failed"),
            Outcome::Cancelled(CancelReason::race_loser()),
        );
        assert!(matches!(
            hedge_to_result(result),
            Err(HedgeError::PrimaryError("primary failed"))
        ));
    }

    #[test]
    fn hedge_to_result_backup_won_ok() {
        let result: HedgeResult<i32, &str> = HedgeResult::backup_won(
            Outcome::Ok(99),
            Outcome::Cancelled(CancelReason::race_loser()),
        );
        assert_eq!(hedge_to_result(result).unwrap(), 99);
    }

    #[test]
    fn hedge_to_result_backup_won_err() {
        let result: HedgeResult<i32, &str> = HedgeResult::backup_won(
            Outcome::Err("backup failed"),
            Outcome::Cancelled(CancelReason::race_loser()),
        );
        assert!(matches!(
            hedge_to_result(result),
            Err(HedgeError::BackupError("backup failed"))
        ));
    }

    #[test]
    fn hedge_to_result_cancelled() {
        let result: HedgeResult<i32, &str> =
            HedgeResult::primary_fast(Outcome::Cancelled(CancelReason::shutdown()));
        assert!(matches!(
            hedge_to_result(result),
            Err(HedgeError::Cancelled(_))
        ));
    }

    #[test]
    fn hedge_to_result_panicked() {
        let result: HedgeResult<i32, &str> =
            HedgeResult::primary_fast(Outcome::Panicked(PanicPayload::new("boom")));
        assert!(matches!(
            hedge_to_result(result),
            Err(HedgeError::Panicked(_))
        ));
    }

    // =========================================================================
    // HedgeError Tests
    // =========================================================================

    #[test]
    fn hedge_error_display_primary_fast() {
        let err: HedgeError<&str> = HedgeError::PrimaryFastError("test");
        assert!(err.to_string().contains("primary completed fast"));
        assert!(err.to_string().contains("test"));
    }

    #[test]
    fn hedge_error_display_primary() {
        let err: HedgeError<&str> = HedgeError::PrimaryError("test");
        assert!(err.to_string().contains("primary won race"));
    }

    #[test]
    fn hedge_error_display_backup() {
        let err: HedgeError<&str> = HedgeError::BackupError("test");
        assert!(err.to_string().contains("backup won race"));
    }

    #[test]
    fn hedge_error_display_cancelled() {
        let err: HedgeError<&str> = HedgeError::Cancelled(CancelReason::shutdown());
        assert!(err.to_string().contains("cancelled"));
    }

    #[test]
    fn hedge_error_display_panicked() {
        let err: HedgeError<&str> = HedgeError::Panicked(PanicPayload::new("boom"));
        assert!(err.to_string().contains("panicked"));
    }

    // =========================================================================
    // Invariant Verification Tests
    // =========================================================================

    #[test]
    fn loser_is_always_tracked_in_race() {
        // When a race occurs, the loser outcome must be tracked
        let result: HedgeResult<i32, &str> = HedgeResult::primary_won(
            Outcome::Ok(42),
            Outcome::Cancelled(CancelReason::race_loser()),
        );

        let loser = result.loser_outcome().expect("loser must be tracked");
        assert!(loser.is_cancelled());

        if let Outcome::Cancelled(reason) = loser {
            assert!(matches!(
                reason.kind(),
                crate::types::cancel::CancelKind::RaceLost
            ));
        }
    }

    #[test]
    fn primary_fast_has_no_loser() {
        // When primary completes fast, there is no loser (backup never spawned)
        let result: HedgeResult<i32, &str> = HedgeResult::primary_fast(Outcome::Ok(42));

        assert!(result.loser_outcome().is_none());
    }

    #[test]
    fn hedge_commutativity_of_race_result() {
        // When a race occurs, the winner value is the same regardless of which won
        let val = 42;

        // Primary wins
        let r1: HedgeResult<i32, &str> = HedgeResult::primary_won(
            Outcome::Ok(val),
            Outcome::Cancelled(CancelReason::race_loser()),
        );

        // Backup wins with same value
        let r2: HedgeResult<i32, &str> = HedgeResult::backup_won(
            Outcome::Ok(val),
            Outcome::Cancelled(CancelReason::race_loser()),
        );

        // Both should succeed with the same value
        assert_eq!(hedge_to_result(r1).unwrap(), hedge_to_result(r2).unwrap());
    }

    #[test]
    fn hedge_result_winner_reflects_input() {
        // Verify winner field correctly reflects which branch won
        let primary_won: HedgeResult<i32, &str> = HedgeResult::primary_won(
            Outcome::Ok(1),
            Outcome::Cancelled(CancelReason::race_loser()),
        );
        assert_eq!(primary_won.winner(), HedgeWinner::Primary);

        let backup_won: HedgeResult<i32, &str> = HedgeResult::backup_won(
            Outcome::Ok(2),
            Outcome::Cancelled(CancelReason::race_loser()),
        );
        assert_eq!(backup_won.winner(), HedgeWinner::Backup);

        let primary_fast: HedgeResult<i32, &str> = HedgeResult::primary_fast(Outcome::Ok(3));
        assert_eq!(primary_fast.winner(), HedgeWinner::Primary);
    }
}
