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
//! - First to complete wins; loser is cancelled
//! - Total latency bounded by min(primary, backup) rather than max
//!
//! # Semantics Note
//!
//! This standalone future returns as soon as a winner is known. The losing branch
//! is dropped and represented as `Outcome::Cancelled(CancelReason::race_loser())`.
//! Runtime-level integrations that require explicit loser draining must enforce
//! that policy externally.
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
//! - If caller cancellation is observed before primary completes: drop primary and
//!   do not invoke the backup factory
//! - If caller requests cancel during a race: drop both attempts and return both
//!   outcomes with the caller's reason. `HedgeWinner::Primary` is the deterministic
//!   representative for this simultaneous terminal event; neither attempt won.

use crate::cx::Cx;
use crate::time::Sleep;
use crate::types::cancel::CancelReason;
use crate::types::outcome::PanicPayload;
use crate::types::{Outcome, Time};
use core::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// An adaptive hedge policy based on Marginal Conformal Prediction.
///
/// Hard-coded hedge delays are fragile: they either fire too often (wasting compute)
/// or too late (failing to mitigate tail latency). This policy maintains a sliding
/// window of recent primary execution latencies and uses conformal prediction to
/// dynamically calculate the $1-\alpha$ prediction upper bound (e.g., the true P95).
///
/// Under the assumption of exchangeability, this provides a finite-sample mathematical
/// guarantee that the hedge will only fire on true statistical outliers, optimizing
/// the exact point of the latency/cost tradeoff curve.
#[derive(Debug, Clone)]
pub struct AdaptiveHedgePolicy {
    /// Sliding window of recent primary latencies (in microseconds).
    history: Vec<u64>,
    /// Number of observations recorded so far.
    count: u64,
    /// Miscoverage target (e.g., 0.05 for P95 hedging).
    alpha: f64,
    /// Minimum threshold to prevent micro-hedging on extremely fast tasks.
    min_delay: Duration,
    /// Maximum threshold to prevent unbounded waiting on saturated systems.
    max_delay: Duration,
}

/// Split-conformal order-statistic rank for the `(1-alpha)` upper bound over
/// `n` samples, or `None` when the finite-sample bound is `+inf`.
///
/// `ceil((n+1)(1-alpha)) > n` means no order statistic covers `1-alpha` at this
/// sample size, so the distribution-free bound is `+inf` and the caller must
/// fall back to its conservative maximum rather than clamp to the largest
/// observed sample (which would under-cover).
#[allow(
    clippy::cast_precision_loss, // quantile math is float-based by definition (alpha is f64)
    clippy::cast_sign_loss       // value is clamped into [0, n-1] before conversion
)]
fn conformal_rank(n: usize, alpha: f64) -> Option<usize> {
    let q = ((n as f64 + 1.0) * (1.0 - alpha)).ceil();
    if !q.is_finite() || q <= 1.0 {
        Some(0)
    } else if q > n as f64 {
        // Strictly greater than n: the ceil((n+1)(1-alpha))-th order statistic
        // does not exist, so the split-conformal upper bound is +inf. Signal
        // the caller to use its conservative maximum. (q == n is NOT +inf: the
        // n-th order statistic is the max sample, a valid finite bound.)
        None
    } else {
        Some((q as usize).saturating_sub(1))
    }
}

impl AdaptiveHedgePolicy {
    /// Creates a new adaptive hedge policy.
    ///
    /// # Arguments
    /// * `window_size` - Size of the sliding history window (e.g., 100-1000).
    /// * `alpha` - Target miscoverage rate (e.g., 0.05 for 95% coverage).
    /// * `min_delay` - The absolute minimum delay before hedging.
    /// * `max_delay` - The absolute maximum delay before hedging.
    #[must_use]
    pub fn new(window_size: usize, alpha: f64, min_delay: Duration, max_delay: Duration) -> Self {
        assert!(window_size > 0, "window size must be positive");
        assert!(alpha > 0.0 && alpha < 1.0, "alpha must be in (0, 1)");
        Self {
            history: vec![0; window_size],
            count: 0,
            alpha,
            min_delay,
            max_delay,
        }
    }

    /// Records a new primary execution latency.
    ///
    /// This should be called with the elapsed time of successful primary operations
    /// to continually calibrate the conformal bound.
    pub fn record(&mut self, latency: Duration) {
        let micros = latency.as_micros();
        let val = if micros > u128::from(u64::MAX) {
            u64::MAX
        } else {
            micros as u64
        };
        let capacity = self.history.len() as u64;
        self.history[(self.count % capacity) as usize] = val;
        self.count += 1;
    }

    /// Calculates the dynamically calibrated hedge delay using conformal prediction.
    ///
    /// Returns the exact empirical $(1-\alpha)$ quantile of the history window,
    /// clamped between `min_delay` and `max_delay`.
    #[must_use]
    pub fn next_hedge_delay(&self) -> Duration {
        let n = (self.count).min(self.history.len() as u64) as usize;
        if n < 10 {
            // Not enough data for a stable quantile; fallback to conservative max.
            return self.max_delay;
        }

        let Some(rank) = conformal_rank(n, self.alpha) else {
            // ceil((n+1)(1-alpha)) > n: the finite-sample split-conformal upper
            // bound is +inf (no valid order statistic covers 1-alpha at this n).
            // Clamping to the max observed sample would UNDER-cover and hedge
            // more often than the alpha target; the conservative bound is
            // max_delay (matching the small-n fallback above).
            return self.max_delay;
        };

        let mut sorted = self.history[0..n].to_vec();

        // Select nth unstable is O(N) average case, faster than O(N log N) full sort.
        let (_, &mut bound_micros, _) = sorted.select_nth_unstable(rank);

        let delay = Duration::from_micros(bound_micros);

        delay.clamp(self.min_delay, self.max_delay)
    }

    /// Generates a `HedgeConfig` calibrated for the current system state.
    #[must_use]
    pub fn config(&self) -> HedgeConfig {
        HedgeConfig::new(self.next_hedge_delay())
    }

    /// Returns the configured history window capacity.
    #[must_use]
    pub fn window_size(&self) -> usize {
        self.history.len()
    }

    /// Returns the number of samples currently contributing to calibration.
    ///
    /// This value saturates at `window_size()`.
    #[must_use]
    pub fn sample_count(&self) -> usize {
        usize::try_from(self.count)
            .unwrap_or(usize::MAX)
            .min(self.history.len())
    }
}

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
        now >= self.deadline_from(start)
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

/// Which branch won in a hedged operation, or the deterministic representative
/// when external cancellation ends both branches simultaneously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HedgeWinner {
    /// The primary operation completed first, or represents simultaneous
    /// external cancellation.
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
    /// Hedge race occurred; includes both terminal outcomes and the representative branch.
    ///
    /// When external cancellation ends an active race, neither branch won. Both
    /// outcomes are cancelled with the caller's reason and `winner` is
    /// [`HedgeWinner::Primary`] as a deterministic representative.
    Raced {
        /// The winner's outcome, or the primary cancellation outcome when
        /// external cancellation ends both branches simultaneously.
        winner_outcome: Outcome<T, E>,
        /// Which branch won, or Primary as the deterministic representative
        /// for simultaneous external cancellation.
        winner: HedgeWinner,
        /// The other branch's terminal representation.
        ///
        /// This standalone future drops cancelled branches; it does not drain
        /// them. Runtime integrations that require draining must enforce that
        /// policy externally.
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

    /// Returns the winner's outcome, or the primary cancellation outcome for a
    /// simultaneously cancelled race.
    #[must_use]
    pub fn winner_outcome(&self) -> &Outcome<T, E> {
        match self {
            Self::PrimaryFast(o) => o,
            Self::Raced { winner_outcome, .. } => winner_outcome,
        }
    }

    /// Consumes self and returns the winner's outcome, or the primary
    /// cancellation outcome for a simultaneously cancelled race.
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

    /// Returns which branch won (always Primary for `PrimaryFast`). A
    /// simultaneously cancelled race also returns Primary as its deterministic
    /// representative.
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
    /// A branch panicked.
    Panicked(PanicPayload),
}

impl<E: fmt::Display> fmt::Display for HedgeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrimaryFastError(e) => write!(f, "primary completed fast with error: {e}"),
            Self::PrimaryError(e) => write!(f, "primary won race with error: {e}"),
            Self::BackupError(e) => write!(f, "backup won race with error: {e}"),
            Self::Cancelled(r) => write!(f, "winner was cancelled: {r}"),
            Self::Panicked(p) => write!(f, "branch panicked: {p}"),
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

/// A future that executes a hedge operation.
///
/// This struct is created by the [`hedge`] function.
pub struct HedgeFuture<Prim, Back, F> {
    primary: Option<Prim>,
    backup_factory: Option<F>,
    backup: Option<Back>,
    timer: Option<Sleep>,
    timer_armed: bool,
    config: HedgeConfig,
    completed: bool,
}

impl<Prim, Back, F> HedgeFuture<Prim, Back, F> {
    fn new(config: HedgeConfig, primary: Prim, backup_factory: F) -> Self {
        Self {
            primary: Some(primary),
            backup_factory: Some(backup_factory),
            backup: None,
            timer: None,
            timer_armed: false,
            config,
            completed: false,
        }
    }

    /// Starts the hedge delay. It runs from the first poll, when the primary
    /// starts: armed at construction, a future first polled after its delay
    /// launched the backup together with the primary.
    fn arm_timer(&mut self) {
        if self.timer_armed {
            return;
        }
        self.timer_armed = true;
        let now = Cx::current().map_or_else(crate::time::wall_now, |current| {
            current
                .timer_driver()
                .map_or_else(crate::time::wall_now, |driver| driver.now())
        });
        self.timer = Some(Sleep::after(now, self.config.hedge_delay));
    }

    fn finish_cancelled<T, E>(&mut self, reason: CancelReason) -> HedgeResult<T, E> {
        let backup_was_running = self.backup.is_some();

        self.completed = true;
        self.primary = None;
        self.backup = None;
        self.backup_factory = None;
        self.timer = None;

        if backup_was_running {
            // External cancellation has no race winner. Preserve the fact that
            // both attempts were active by returning a raced result, using the
            // primary as the deterministic representative and the caller's
            // reason for both dropped attempts.
            HedgeResult::primary_won(
                Outcome::Cancelled(reason.clone()),
                Outcome::Cancelled(reason),
            )
        } else {
            HedgeResult::primary_fast(Outcome::Cancelled(reason))
        }
    }
}

fn ambient_cancel_reason() -> Option<CancelReason> {
    Cx::with_current(|current| {
        if current.checkpoint().is_err() {
            Some(current.cancel_reason().unwrap_or_default())
        } else {
            None
        }
    })
    .flatten()
}

impl<Prim, Back, F, T, E> Future for HedgeFuture<Prim, Back, F>
where
    Prim: Future<Output = Outcome<T, E>> + Unpin,
    Back: Future<Output = Outcome<T, E>> + Unpin,
    F: FnOnce() -> Back + Unpin,
    T: Unpin,
    E: Unpin,
{
    type Output = HedgeResult<T, E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        // Fail closed on poll-after-completion: this future leaves the winning
        // inner future in place after returning `Ready`, so re-polling here
        // would re-poll an already-completed inner future (a `Future` contract
        // violation that most inner futures panic on). Surface it as a clear,
        // attributable panic instead — the `Select` family returns a typed
        // `PolledAfterCompletion` error, but `HedgeResult` has no error variant
        // to carry one.
        assert!(!this.completed, "HedgeFuture polled after completion");

        if let Some(reason) = ambient_cancel_reason() {
            return Poll::Ready(this.finish_cancelled(reason));
        }

        this.arm_timer();

        // Poll primary if present
        if let Some(primary) = &mut this.primary {
            if let Poll::Ready(outcome) = Pin::new(primary).poll(cx) {
                // Primary finished.
                this.completed = true;
                let backup_was_running = this.backup.is_some();
                // Actually drop the loser now so the reported race-loser
                // cancellation is truthful: the returned outcome claims the
                // backup was cancelled, so the backup future (and its pending
                // work/timer) must not outlive this poll if the completed
                // `HedgeFuture` is retained by the caller.
                this.backup = None;
                this.backup_factory = None;
                this.timer = None;
                return Poll::Ready(if backup_was_running {
                    // Backup was running, so this was a race.
                    // Dropping backup cancels it; loser is represented as race-loser cancellation.
                    HedgeResult::primary_won(
                        outcome,
                        Outcome::Cancelled(CancelReason::race_loser()),
                    )
                } else {
                    // Backup never started
                    HedgeResult::primary_fast(outcome)
                });
            }
        }

        // Check timer to start backup
        if this.timer.is_some() {
            // If timer is ready, spawn backup
            if Pin::new(this.timer.as_mut().expect("timer initialized")).poll(cx) == Poll::Ready(())
            {
                this.timer = None; // Drop timer

                // Cancellation can arrive while the primary or timer is being
                // polled. Re-check immediately before consuming the factory so
                // cancellation already observed at this cooperative boundary
                // cannot create speculative backup work.
                if let Some(reason) = ambient_cancel_reason() {
                    return Poll::Ready(this.finish_cancelled(reason));
                }

                // Timer elapsed, start backup
                this.config.backup_spawned = true;
                if let Some(factory) = this.backup_factory.take() {
                    this.backup = Some(factory());
                }
            }
        }

        // Poll backup if present
        if let Some(backup) = &mut this.backup {
            if let Poll::Ready(outcome) = Pin::new(backup).poll(cx) {
                // Backup finished first.
                this.completed = true;
                // Drop the primary loser now so the reported race-loser
                // cancellation is truthful even if the completed future is
                // retained by the caller.
                this.primary = None;
                this.timer = None;
                return Poll::Ready(HedgeResult::backup_won(
                    outcome,
                    Outcome::Cancelled(CancelReason::race_loser()),
                ));
            }
        }

        // Either inner future may request cancellation while returning
        // Pending. Observe it in the same outer poll instead of relying on a
        // later wake, which is particularly important for standalone/manual
        // polling without a runtime-owned cancellation waker.
        if let Some(reason) = ambient_cancel_reason() {
            return Poll::Ready(this.finish_cancelled(reason));
        }

        Poll::Pending
    }
}

/// Creates a hedge future.
///
/// # Arguments
/// * `config` - Hedge configuration (delay).
/// * `primary` - The primary future.
/// * `backup_factory` - Closure that produces the backup future.
pub fn hedge<Prim, Back, F>(
    config: HedgeConfig,
    primary: Prim,
    backup_factory: F,
) -> HedgeFuture<Prim, Back, F>
where
    F: FnOnce() -> Back,
{
    HedgeFuture::new(config, primary, backup_factory)
}

/// Macro for hedging an operation.
///
/// In this implementation, this races the primary against a timer, and spawns
/// the backup if the timer expires.
///
/// # Example
/// ```ignore
/// let result = hedge!(
///     HedgeConfig::from_millis(100), // hedge delay
///     call_primary_server(),         // primary future
///     || call_backup_server()        // backup closure (only called if needed)
/// ).await;
/// ```
#[macro_export]
macro_rules! hedge {
    ($config:expr, $primary:expr, $backup:expr) => {
        $crate::combinator::hedge::hedge($config, $primary, $backup)
    };
}

#[cfg(test)]
#[path = "hedge_inline_tests.rs"]
mod tests;
