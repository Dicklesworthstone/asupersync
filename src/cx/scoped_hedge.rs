//! Delayed hedging with two fully owned and drained operation subtrees.
//!
//! Implements the core plan's sections 6 and 12 (asupersync-bi2462) through
//! [`Cx::race_scoped`]. In particular, a losing operation may use an ordinary
//! child join without stranding its descendants (asupersync-inleqi). Existing
//! hedge and race entry points retain their documented behavior.

use super::scoped_race::{
    ScopedRaceBranch, ScopedRaceBranchReport, ScopedRaceClose, ScopedRaceError, ScopedRaceStop,
    ScopedRaceTask,
};
use super::{Cx, cap};
use crate::combinator::hedge::HedgeConfig;
use crate::runtime::state::SpawnError;
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::{CancelReason, Time};
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

/// One of the two operations reserved by [`Cx::hedge_scoped`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopedHedgeBranch {
    /// The operation eligible to start immediately.
    Primary,
    /// The operation eligible after the hedge delay.
    Backup,
}

/// The immutable decision that stopped useful work in a scoped hedge.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ScopedHedgeStop {
    /// This operation's terminal join was selected after its user factory
    /// started. An application error returned as the operation's value still
    /// wins; this is a first-terminal hedge, not a first-success retry.
    Winner(ScopedHedgeBranch),
    /// The explicit owner's cancellation was observed before selection.
    Cancelled(CancelReason),
    /// Submission, private-region admission, or cancellation prevented this
    /// user factory from starting before selection. Already-submitted work
    /// is still drained, and any task error remains in its branch receipt.
    NotAdmitted(ScopedHedgeBranch),
}

/// What a hedge operation actually returned, separately from selection.
///
/// A reserved wrapper that never invoked its user factory normally reports
/// `NotStarted`. A task-level error before invocation remains `Joined(Err(_))`.
pub type ScopedHedgeTask<T> = ScopedRaceTask<T>;

/// The actual whole-subtree close receipt, including cleanup failures.
pub type ScopedHedgeClose = ScopedRaceClose;

/// Independent task, private-region, submission, and close facts for a branch.
pub type ScopedHedgeBranchReport<T> = ScopedRaceBranchReport<T>;

/// Selection and both complete operation-subtree receipts for a scoped hedge.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "inspect the hedge decision and both subtree close receipts"]
pub struct ScopedHedgeReport<P, B> {
    /// The decision that stopped useful execution. Cleanup does not replace it.
    pub stop: ScopedHedgeStop,
    /// The primary operation's actual task and cleanup facts.
    pub primary: ScopedHedgeBranchReport<P>,
    /// The backup operation's actual task and cleanup facts. A delayed wrapper
    /// can own a private region even when the user factory never starts.
    pub backup: ScopedHedgeBranchReport<B>,
    /// Whether the backup's user factory was invoked, including an invocation
    /// that panicked. This is distinct from reserving its wrapper task.
    pub backup_started: bool,
    /// Strongest explicit owner cancellation observed by the scoped race,
    /// including during cleanup. It never erases a selected winner or value.
    pub owner_cancellation: Option<CancelReason>,
}

/// Refusal before either hedge operation can be submitted.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedHedgeError {
    /// A nonzero delay requires the explicit owner's authorized timer driver.
    TimerUnavailable,
    /// The explicit context has no usable runtime spawn gateway.
    Spawn(SpawnError),
}

impl std::fmt::Display for ScopedHedgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimerUnavailable => {
                f.write_str("scoped hedge delay requires an authorized timer driver")
            }
            Self::Spawn(error) => write!(f, "scoped hedge requires an owning runtime: {error}"),
        }
    }
}

impl std::error::Error for ScopedHedgeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TimerUnavailable => None,
            Self::Spawn(error) => Some(error),
        }
    }
}

/// Published by the primary itself, including factory/poll panic and refused
/// admission. The backup must not depend on the owner being scheduled promptly
/// to learn that a primary has already finished.
struct PrimaryCompletion(Arc<AtomicBool>);

impl Drop for PrimaryCompletion {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Wait only on the explicitly bound timer and cancellation registrations.
/// The timer is retired when this helper returns, before either user invocation
/// or the suppressed wrapper's final cancellation wait.
async fn backup_eligible<Caps>(
    child: &Cx<Caps>,
    owner: &Cx<Caps>,
    primary_finished: &AtomicBool,
    schedule: Option<(Time, TimerDriverHandle)>,
) -> bool {
    if child.is_cancel_requested()
        || owner.is_cancel_requested()
        || primary_finished.load(Ordering::Acquire)
    {
        return false;
    }
    let Some((deadline, driver)) = schedule else {
        return true;
    };

    let mut timer = std::pin::pin!(Sleep::with_timer_driver(deadline, driver.clone()));
    let mut child_cancelled = std::pin::pin!(child.cancelled());
    let mut owner_cancelled = std::pin::pin!(owner.cancelled());
    poll_fn(|task| {
        // A cancellation or a completed primary takes precedence over timer
        // readiness. Do not invoke a speculative factory merely to cancel it.
        if child_cancelled.as_mut().poll(task).is_ready()
            || owner_cancelled.as_mut().poll(task).is_ready()
            || primary_finished.load(Ordering::Acquire)
        {
            return Poll::Ready(false);
        }
        if driver.now() >= deadline {
            return Poll::Ready(true);
        }
        if timer.as_mut().poll_deadline(task).is_ready() {
            // A coalesced wake may precede this exact deadline. Retire the
            // completed Sleep state before polling it again, and recheck the
            // owner's clock and cancellation on a later turn.
            timer.as_mut().get_mut().reset(deadline);
            task.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await
}

fn branch_report<T>(report: ScopedRaceBranchReport<Option<T>>) -> ScopedHedgeBranchReport<T> {
    let task = match report.task {
        ScopedRaceTask::NotStarted | ScopedRaceTask::Joined(Ok(None)) => {
            ScopedHedgeTask::NotStarted
        }
        ScopedRaceTask::Joined(Ok(Some(value))) => ScopedHedgeTask::Joined(Ok(value)),
        ScopedRaceTask::Joined(Err(error)) => ScopedHedgeTask::Joined(Err(error)),
    };
    ScopedHedgeBranchReport {
        task,
        region_id: report.region_id,
        close: report.close,
        submission_error: report.submission_error,
    }
}

fn stopped(stop: ScopedRaceStop, primary_started: bool, backup_started: bool) -> ScopedHedgeStop {
    match stop {
        ScopedRaceStop::Winner(ScopedRaceBranch::Left) if primary_started => {
            ScopedHedgeStop::Winner(ScopedHedgeBranch::Primary)
        }
        ScopedRaceStop::Winner(ScopedRaceBranch::Right) if backup_started => {
            ScopedHedgeStop::Winner(ScopedHedgeBranch::Backup)
        }
        ScopedRaceStop::Winner(ScopedRaceBranch::Left)
        | ScopedRaceStop::NotAdmitted(ScopedRaceBranch::Left) => {
            ScopedHedgeStop::NotAdmitted(ScopedHedgeBranch::Primary)
        }
        ScopedRaceStop::Winner(ScopedRaceBranch::Right)
        | ScopedRaceStop::NotAdmitted(ScopedRaceBranch::Right) => {
            ScopedHedgeStop::NotAdmitted(ScopedHedgeBranch::Backup)
        }
        ScopedRaceStop::Cancelled(reason) => ScopedHedgeStop::Cancelled(reason),
    }
}

impl<Caps> Cx<Caps>
where
    Caps: cap::HasSpawn + cap::HasTime + Send + Sync + 'static,
{
    /// Hedges a primary with a delayed backup, then closes both complete
    /// operation subtrees before returning their typed receipts.
    ///
    /// The delay starts on this future's first poll, before either submission,
    /// using the explicit owner's timer and [`HedgeConfig::deadline_from`].
    /// Two private task/region slots are reserved up front, as with the existing
    /// context-aware hedge. Only the backup's **user factory** is lazy: its
    /// wrapper waits until the exact deadline before considering invocation.
    /// Immediately before invocation the wrapper checks whether the primary
    /// has finished, even if the owner has not yet observed its result. An
    /// observed completion suppresses the backup.
    /// `backup_started` distinguishes invocation from wrapper reservation.
    ///
    /// Both factories run inside their admitted tasks and receive their own
    /// contexts with the supplied capability set. A failed private-region mint
    /// never invokes user code in the parent region. The factories may return
    /// different types, and their synchronous construction panics are ordinary
    /// task outcomes. An application `Err` returned as a value is a terminal
    /// result, not a request to start or wait for the backup.
    ///
    /// Selection follows [`Cx::race_scoped`]: the first terminal task observed
    /// after its user factory starts wins, a ready primary wins a simultaneous
    /// tie, and explicit owner cancellation observed before selection takes
    /// precedence. A skipped delayed wrapper cannot become a successful backup
    /// winner. Cancellation observation is mask-agnostic and never acknowledges
    /// the owner's request or consumes its checkpoint budget.
    ///
    /// Both complete subtrees are cancelled before waiting for either direct
    /// task, including the winner's remaining descendants. Thus a losing
    /// primary may wait in an ordinary [`crate::runtime::TaskHandle::join`] on
    /// a child that needs cancellation to finish (asupersync-inleqi). Completion
    /// waits for descendants, pending admission, obligations, and finalizers;
    /// no forced destruction or bound on uncooperative cleanup is promised.
    /// The selected decision and actual typed values survive owner cancellation
    /// during cleanup. Later cancellation, loser panics, and finalizer failures
    /// remain separate facts; inspect both close receipts before treating the
    /// result as a successful quiescent close.
    ///
    /// Factories must use their supplied contexts for owned work. Captured
    /// authority for unrelated regions remains unrelated authority. Returned
    /// values must not retain obligations whose release is required to close
    /// either operation region. A delayed backup's captures remain owned until
    /// that wrapper starts or retires, even when its factory is suppressed.
    ///
    /// A nonzero delay fails before either submission if this context has no
    /// authorized timer. A zero delay performs no timer or clock access and
    /// accepts a missing or runtime-restricted timer; the method's static
    /// `HasTime` bound still applies. No ambient clock or timer fallback is used.
    /// An unpolled future invokes neither factory. Dropping a polled hedge asks
    /// both private subtrees to close, including a late admission, and leaves
    /// asynchronous cleanup to their owning region. Its delayed timer retires
    /// when the backup wrapper observes cancellation. Existing hedge APIs keep
    /// their established selection and cleanup behavior.
    ///
    /// # Errors
    ///
    /// Missing timer authority or a missing runtime gateway returns
    /// [`ScopedHedgeError`]. Per-branch submission and later admission failures
    /// remain in the report, after any admitted sibling drains. A close error
    /// does not certify quiescence, even if a useful value was selected.
    ///
    /// ```
    /// use asupersync::Cx;
    /// use asupersync::cx::{ScopedHedgeBranch, ScopedHedgeStop};
    /// use std::time::Duration;
    ///
    /// async fn example(cx: &Cx) {
    ///     let report = cx.hedge_scoped(
    ///         Duration::from_millis(25),
    ///         |_| async { 42_u32 },
    ///         |_| async { "backup value" },
    ///     ).await.expect("runtime and timer authority");
    ///     if matches!(report.stop, ScopedHedgeStop::Winner(ScopedHedgeBranch::Primary)) {
    ///         assert!(report.primary.close.as_ref().is_some_and(Result::is_ok));
    ///         assert!(report.backup.close.as_ref().is_some_and(Result::is_ok));
    ///     }
    /// }
    /// ```
    pub async fn hedge_scoped<P, B, FP, FB, FutP, FutB>(
        &self,
        delay: Duration,
        primary: FP,
        backup: FB,
    ) -> Result<ScopedHedgeReport<P, B>, ScopedHedgeError>
    where
        FP: FnOnce(Cx<Caps>) -> FutP + Send + 'static,
        FB: FnOnce(Cx<Caps>) -> FutB + Send + 'static,
        FutP: Future<Output = P> + Send + 'static,
        FutB: Future<Output = B> + Send + 'static,
        P: Send + 'static,
        B: Send + 'static,
    {
        // Capability preflight precedes admission and either user factory.
        // Construct no Sleep and do not read any clock for an immediate hedge.
        let schedule = if delay.is_zero() {
            None
        } else {
            let driver = self
                .timer_driver()
                .ok_or(ScopedHedgeError::TimerUnavailable)?;
            let deadline = HedgeConfig::new(delay).deadline_from(driver.now());
            Some((deadline, driver))
        };

        let primary_started = Arc::new(AtomicBool::new(false));
        let primary_started_in_task = Arc::clone(&primary_started);
        let primary_finished = Arc::new(AtomicBool::new(false));
        let primary_completion = PrimaryCompletion(Arc::clone(&primary_finished));
        let backup_started = Arc::new(AtomicBool::new(false));
        let backup_started_in_task = Arc::clone(&backup_started);
        let primary_owner = self.clone();
        let backup_owner = self.clone();

        let report = self
            .race_scoped(
                move |child| async move {
                    let _completion = primary_completion;
                    if primary_owner.is_cancel_requested() || child.is_cancel_requested() {
                        // Wait for this wrapper's own stop handoff before
                        // returning a synthetic non-value to the race engine.
                        child.cancelled().await;
                        return None;
                    }
                    primary_started_in_task.store(true, Ordering::Release);
                    Some(primary(child).await)
                },
                move |child| async move {
                    let eligible =
                        backup_eligible(&child, &backup_owner, primary_finished.as_ref(), schedule)
                            .await;
                    // Recheck after the timer poll: cancellation or primary
                    // completion may have been published during that poll.
                    if !eligible
                        || backup_owner.is_cancel_requested()
                        || child.is_cancel_requested()
                        || primary_finished.load(Ordering::Acquire)
                    {
                        // In particular, a finished primary is not a backup
                        // success. Its retirement may still be pending; park
                        // until the shared controller closes this subtree.
                        child.cancelled().await;
                        return None;
                    }
                    backup_started_in_task.store(true, Ordering::Release);
                    Some(backup(child).await)
                },
            )
            .await
            .map_err(|error| match error {
                ScopedRaceError::Spawn(error) => ScopedHedgeError::Spawn(error),
            })?;

        let backup_started = backup_started.load(Ordering::Acquire);
        Ok(ScopedHedgeReport {
            stop: stopped(
                report.stop,
                primary_started.load(Ordering::Acquire),
                backup_started,
            ),
            primary: branch_report(report.left),
            backup: branch_report(report.right),
            backup_started,
            owner_cancellation: report.owner_cancellation,
        })
    }
}

#[cfg(test)]
#[path = "scoped_hedge_inline_tests.rs"]
mod tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_hedge_native_tests.rs"]
mod native_tests;
