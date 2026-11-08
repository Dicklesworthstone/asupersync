//! Bounded first-terminal races over fully owned operation subtrees.
//!
//! This is the dynamic counterpart of [`Cx::race_scoped`], using the same
//! strict branch admission, task observation and region-close receipts. It
//! implements the core plan's sections 3.2, 6 and 12 (asupersync-bi2462),
//! including cancellation before joining a loser's descendants
//! (asupersync-inleqi). Existing race and quorum semantics are unchanged.

use super::scoped_race::{
    OwnedBranch, ScopedRaceBranchReport, close_receipt, observe_owner_cancellation,
    owner_cancel_reason,
};
use super::{Cx, cap};
use crate::runtime::spawn_mailbox::SpawnGateway;
use crate::runtime::state::SpawnError;
use crate::types::CancelReason;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;

/// Maximum number of factories admitted by one [`Cx::race_all_scoped`].
///
/// This bounds retained task results, region slots, close watches, and the work
/// done in one selection or drain poll. Input captures and result sizes remain
/// the caller's responsibility.
pub const MAX_SCOPED_RACE_BRANCHES: usize = 64;

/// The immutable decision that stopped useful execution of a dynamic race.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ScopedRaceAllStop {
    /// This input's terminal join was observed first after its user factory
    /// started. A returned application error, independent cancellation, or
    /// panic is a terminal outcome and can win. Already-ready ties follow
    /// input order; no wall-clock completion ordering is inferred.
    Winner {
        /// Original zero-based factory index.
        index: usize,
    },
    /// Owner cancellation was observed before choosing a terminal branch.
    Cancelled(CancelReason),
    /// Submission, private-region admission, or first user-factory invocation
    /// was refused before a winner was selected. Submitted siblings are still
    /// fully drained, and the refusing task's actual error remains observable.
    NotAdmitted {
        /// Original zero-based factory index.
        index: usize,
    },
}

/// Selection and every operation's actual task and subtree cleanup results.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "inspect the race decision and every operation's close receipt"]
pub struct ScopedRaceAllReport<T> {
    /// The decision that stopped useful work. Cleanup never replaces it.
    pub stop: ScopedRaceAllStop,
    /// One receipt for every input factory, in original input order, including
    /// factories not submitted after cancellation or refusal. The selected
    /// winner's exact value or task error remains in its own receipt.
    pub attempts: Vec<ScopedRaceBranchReport<T>>,
    /// Owner cancellation observed before return, including during cleanup.
    /// Requests are strengthened without erasing the chosen winner or values.
    pub owner_cancellation: Option<CancelReason>,
}

/// Refusal before any dynamic-race branch can be submitted.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedRaceAllError {
    /// No factory was supplied, so there can be no terminal winner.
    Empty,
    /// The input exceeds [`MAX_SCOPED_RACE_BRANCHES`].
    TooManyBranches {
        /// Number of supplied factories.
        total: usize,
    },
    /// The explicit owner has no runtime gateway for task submission.
    Spawn(SpawnError),
}

impl std::fmt::Display for ScopedRaceAllError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("scoped race requires at least one factory"),
            Self::TooManyBranches { total } => write!(
                f,
                "scoped race received {total} factories; maximum is {MAX_SCOPED_RACE_BRANCHES}"
            ),
            Self::Spawn(error) => write!(f, "scoped race admission failed: {error}"),
        }
    }
}

impl std::error::Error for ScopedRaceAllError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            Self::Empty | Self::TooManyBranches { .. } => None,
        }
    }
}

/// Own every slot before the first submission, including slots whose pending
/// admissions publish only after this controller is dropped or unwinds.
struct OwnedRaceAll<T> {
    branches: Vec<OwnedBranch<T>>,
    armed: bool,
}

impl<T> OwnedRaceAll<T> {
    fn new(total: usize, gateway: &Arc<SpawnGateway>) -> Self {
        Self {
            branches: (0..total).map(|_| OwnedBranch::new(gateway)).collect(),
            armed: true,
        }
    }

    fn request_stop(&mut self, reason: CancelReason, winner: Option<usize>) {
        let branch_reason = |index| {
            if winner == Some(index) {
                CancelReason::user("scoped race winner completed")
            } else {
                reason.clone()
            }
        };
        // Publish EVERY subtree cancellation before any direct task abort or
        // join. A losing body can be parked in a plain join on its own child;
        // cancelling only that body would not wake the descendant.
        for (index, branch) in self.branches.iter().enumerate() {
            let _ = branch.region().request_close(branch_reason(index));
        }
        for (index, branch) in self.branches.iter().enumerate() {
            branch.abort_if_running(branch_reason(index));
        }
    }
}

impl<T> Drop for OwnedRaceAll<T> {
    fn drop(&mut self) {
        if self.armed {
            self.request_stop(CancelReason::user("scoped race dropped"), None);
        }
    }
}

impl<Caps> Cx<Caps>
where
    Caps: cap::HasSpawn + Send + Sync + 'static,
{
    /// Race one to 64 factories and drain all their private subtrees.
    ///
    /// The first observed terminal task whose user factory started wins. An
    /// application `Result::Err`, an independent task cancellation, and a
    /// factory or future panic are all terminal outcomes; none is skipped in
    /// search of a success. Use [`Self::quorum_scoped`] when successful results
    /// determine selection. Already-ready task joins are inspected in input
    /// order, without claiming an exact physical completion order.
    ///
    /// Each factory receives its actual typed child context only after strict
    /// private-region admission. Use that context for owned descendants;
    /// captured authority from another region stays unrelated. Submitted work
    /// is never run in the parent as a fallback. A refusal stops admission and
    /// drains already-submitted inputs, retaining a receipt for every index.
    ///
    /// Selection requests close for ALL subtrees before joining any remaining
    /// body. Losers receive `RaceLost`; the winner's remaining descendants are
    /// also cancelled and drained. This permits a loser to await a child with
    /// an ordinary uninterruptible task join (asupersync-inleqi). Nested regions
    /// can observe `ParentCancelled` with the initiating cause retained.
    ///
    /// Owner cancellation observed before selection wins over branch readiness.
    /// Cancellation arriving during unconditional cleanup is forwarded and
    /// recorded separately, without replacing the chosen winner or actual task
    /// results. Observation neither acknowledges cancellation nor unmasks the
    /// owner. All remaining handles and region-close waits are polled together;
    /// a slow cleanup cannot prevent cancellation from reaching another branch.
    ///
    /// Inspect each task AND close receipt. A successful task value does not
    /// prove that its descendants or finalizers succeeded, and a close error
    /// does not certify quiescence. Values and factory captures must not retain
    /// obligations whose release is required to close their own regions.
    /// No timer or forced cleanup deadline is imposed: uncooperative user work
    /// can keep the operation pending indefinitely.
    ///
    /// Dropping an unpolled call starts no work. Dropping after submission
    /// requests close for every slot, including late-publishing admissions,
    /// before destroying retained results or unused factories. Synchronous
    /// drop cannot wait for cleanup; the runtime retains that responsibility.
    /// No detached cleanup task is spawned. Inputs and outputs need not be
    /// `Clone`, and output values need not be `Sync` or `Unpin`.
    ///
    /// # Errors
    /// Empty or oversized input is refused before querying runtime authority.
    /// A missing spawn gateway is refused before submission. Later submission
    /// and private-region refusals remain in the drained report.
    ///
    /// ```no_run
    /// # async fn example(cx: &asupersync::Cx) {
    /// use asupersync::cx::{RaceFactory, ScopedRaceAllStop, ScopedRaceTask};
    /// let factories: Vec<RaceFactory<Result<u32, &'static str>>> = vec![
    ///     Box::new(|_| Box::pin(async { Ok(7) })),
    ///     Box::new(|_| Box::pin(async { Err("unavailable") })),
    ///     Box::new(|_| Box::pin(async { Ok(11) })),
    /// ];
    /// let report = cx.race_all_scoped(factories).await.expect("runtime admission");
    /// if let ScopedRaceAllStop::Winner { index } = report.stop {
    ///     match &report.attempts[index].task {
    ///         ScopedRaceTask::Joined(result) => println!("winner: {result:?}"),
    ///         _ => unreachable!("a winner's user factory was invoked"),
    ///     }
    /// }
    /// assert!(report.attempts.iter().all(|attempt| matches!(attempt.close, Some(Ok(_)))));
    /// # }
    /// ```
    pub async fn race_all_scoped<T, F, Fut>(
        &self,
        factories: Vec<F>,
    ) -> Result<ScopedRaceAllReport<T>, ScopedRaceAllError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let total = factories.len();
        if total == 0 {
            return Err(ScopedRaceAllError::Empty);
        }
        if total > MAX_SCOPED_RACE_BRANCHES {
            return Err(ScopedRaceAllError::TooManyBranches { total });
        }
        let gateway = self
            .spawn_gateway_handle()
            .ok_or(ScopedRaceAllError::Spawn(SpawnError::RuntimeUnavailable))?;

        // Declaration order makes the group guard run before unused factory
        // destructors when submission or polling unwinds, including an enqueue
        // notifier that panics after publishing a request.
        let mut factories = factories.into_iter();
        let mut owned = OwnedRaceAll::new(total, &gateway);
        let mut owner_cancellation = None;
        let mut refused = None;
        for index in 0..total {
            if self.is_cancel_requested() {
                break;
            }
            let factory = factories.next().expect("one factory per input");
            if !owned.branches[index].submit(self, factory) {
                refused = Some(index);
                break;
            }
        }

        let mut cancelled = std::pin::pin!(self.cancelled());
        let stop = if observe_owner_cancellation(self, &mut owner_cancellation) {
            ScopedRaceAllStop::Cancelled(owner_cancel_reason(self))
        } else if let Some(index) = refused {
            ScopedRaceAllStop::NotAdmitted { index }
        } else {
            poll_fn(|task| {
                if cancelled.as_mut().poll(task).is_ready() {
                    observe_owner_cancellation(self, &mut owner_cancellation);
                    return Poll::Ready(ScopedRaceAllStop::Cancelled(owner_cancel_reason(self)));
                }
                for (index, branch) in owned.branches.iter_mut().enumerate() {
                    if !branch.poll_result(task) {
                        continue;
                    }
                    // A request published while consuming this ready join is
                    // still earlier than the decision's observation boundary.
                    if observe_owner_cancellation(self, &mut owner_cancellation) {
                        return Poll::Ready(ScopedRaceAllStop::Cancelled(owner_cancel_reason(
                            self,
                        )));
                    }
                    return Poll::Ready(if branch.started() {
                        ScopedRaceAllStop::Winner { index }
                    } else {
                        ScopedRaceAllStop::NotAdmitted { index }
                    });
                }
                Poll::Pending
            })
            .await
        };

        match &stop {
            ScopedRaceAllStop::Winner { index } => {
                owned.request_stop(CancelReason::race_loser(), Some(*index));
            }
            ScopedRaceAllStop::Cancelled(reason) => owned.request_stop(reason.clone(), None),
            ScopedRaceAllStop::NotAdmitted { .. } => owned.request_stop(
                CancelReason::resource_unavailable()
                    .with_message("scoped race branch admission failed"),
                None,
            ),
        }
        // Unused captures can own the last sender needed by admitted cleanup.
        // Release them after cancellation publication and before any drain wait.
        drop(factories);

        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready()
                && observe_owner_cancellation(self, &mut owner_cancellation)
            {
                owned.request_stop(owner_cancel_reason(self), None);
            }
            let mut all_done = true;
            for branch in &mut owned.branches {
                all_done &= branch.poll_result(task);
            }
            if all_done {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;

        // Terminal handles imply each admission either published a region or
        // refused it. Capture just the independent slots in close futures so a
        // retained T does not need Sync for this collecting future to be Send.
        let mut closing: Vec<_> = owned
            .branches
            .iter()
            .map(|branch| {
                let region = Arc::clone(branch.region());
                let gateway = Arc::clone(&gateway);
                Some(Box::pin(
                    async move { close_receipt(&region, &gateway).await },
                ))
            })
            .collect();
        let mut receipts = (0..total).map(|_| None).collect::<Vec<_>>();
        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready()
                && observe_owner_cancellation(self, &mut owner_cancellation)
            {
                owned.request_stop(owner_cancel_reason(self), None);
            }
            let mut all_done = true;
            for (pending, receipt) in closing.iter_mut().zip(&mut receipts) {
                if let Some(close) = pending {
                    if let Poll::Ready(closed) = close.as_mut().poll(task) {
                        *receipt = Some(closed);
                        *pending = None;
                    } else {
                        all_done = false;
                    }
                }
            }
            if all_done {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        observe_owner_cancellation(self, &mut owner_cancellation);
        let attempts = owned
            .branches
            .iter_mut()
            .zip(receipts)
            .map(|(branch, receipt)| {
                let (region, close) = receipt.expect("every subtree observed");
                branch.report(region, close)
            })
            .collect();
        owned.armed = false;
        Ok(ScopedRaceAllReport {
            stop,
            attempts,
            owner_cancellation,
        })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_race_all_inline_tests.rs"]
mod tests;
