//! Bounded success selection over private, fully drained operation subtrees.

use super::child_region::RegionQuiescence;
use super::{ChildRegionError, Cx, ScopedTimeoutClose, cap};
use crate::runtime::spawn_mailbox::{BranchRegionSlot, SpawnGateway};
use crate::runtime::state::SpawnError;
use crate::runtime::{JoinError, TaskHandle};
use crate::types::{CancelReason, RegionId};
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;

/// Maximum number of factories admitted by one scoped quorum.
pub const MAX_SCOPED_QUORUM_BRANCHES: usize = 64;

/// The event that stopped selection, independently of subsequent cleanup.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ScopedQuorumStop {
    /// Exactly the required number of successful task joins were observed.
    /// This does not certify successful descendant or finalizer cleanup.
    Satisfied,
    /// Too few unfinished candidates remained to reach the required count.
    InsufficientSuccesses,
    /// The explicit owner requested cancellation before quorum was selected.
    Cancelled(CancelReason),
    /// Submission or private-region admission refused this branch.
    NotAdmitted { index: usize },
    /// A task panic or invalid join stopped selection. Inspect its task receipt.
    TaskFailed { index: usize },
}

/// The actual task result, including values returned during cancellation drain.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedQuorumTask<T, E> {
    /// The user factory was never invoked, or this input was not submitted.
    NotStarted,
    /// Submission refused this input; earlier branches are still fully drained.
    SubmissionFailed(SpawnError),
    /// Ordinary task outcome with the original typed application result.
    Joined(Result<Result<T, E>, JoinError>),
}

/// Actual region cleanup evidence, shared with scoped timeout operations.
pub type ScopedQuorumClose = ScopedTimeoutClose;

/// Task and entire-subtree receipts for one input, in original input order.
#[derive(Debug)]
#[non_exhaustive]
pub struct ScopedQuorumAttempt<T, E> {
    /// Original factory index.
    pub index: usize,
    /// Actual task result; late successes are retained but never become votes.
    pub task: ScopedQuorumTask<T, E>,
    /// Private region, if admission minted one.
    pub region_id: Option<RegionId>,
    /// Actual close result. An error does not certify quiescence; `None` means
    /// no private region was published. Task success alone is insufficient.
    pub close: Option<Result<ScopedQuorumClose, ChildRegionError>>,
}

/// Selection and cleanup are independent facts and must both be inspected.
#[must_use = "inspect the stop reason and every task and region cleanup receipt"]
#[derive(Debug)]
#[non_exhaustive]
pub struct ScopedQuorumReport<T, E> {
    /// Why selection ended. Once satisfied, later cancellation cannot erase it.
    pub stop: ScopedQuorumStop,
    /// Requested number of successful task results.
    pub required: usize,
    /// Input indices counted before selection stopped, in observation order.
    /// Exactly `required` entries exist only for `Satisfied`; otherwise these
    /// are partial progress. No result observed during drain is added here.
    pub selected: Vec<usize>,
    /// Every original input, including unstarted inputs and late task results.
    pub attempts: Vec<ScopedQuorumAttempt<T, E>>,
}

/// Refusal before any task can be submitted.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedQuorumError {
    /// Requires `1 <= required <= total <= MAX_SCOPED_QUORUM_BRANCHES`.
    InvalidQuorum { required: usize, total: usize },
    /// No owning runtime is available. Per-branch submission errors instead
    /// remain in the report so they cannot discard earlier task results.
    Spawn(SpawnError),
}

impl std::fmt::Display for ScopedQuorumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidQuorum { required, total } => write!(
                f,
                "scoped quorum requires 1 <= required ({required}) <= total ({total}) <= {MAX_SCOPED_QUORUM_BRANCHES}"
            ),
            Self::Spawn(error) => write!(f, "scoped quorum admission failed: {error}"),
        }
    }
}

impl std::error::Error for ScopedQuorumError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            Self::InvalidQuorum { .. } => None,
        }
    }
}

enum BodyResult<T, E> {
    Value(Result<T, E>),
    NotStarted(Option<CancelReason>),
}

struct Branch<T, E> {
    region: Arc<BranchRegionSlot>,
    handle: Option<TaskHandle<BodyResult<T, E>>>,
    receipt: ScopedQuorumAttempt<T, E>,
}

impl<T, E> Branch<T, E> {
    fn joined(&mut self, result: Result<BodyResult<T, E>, JoinError>) -> Option<CancelReason> {
        // A consumed join must never be polled again, even during final drain.
        self.handle = None;
        let mut refusal = None;
        self.receipt.task = match result {
            Ok(BodyResult::Value(value)) => ScopedQuorumTask::Joined(Ok(value)),
            Ok(BodyResult::NotStarted(reason)) => {
                refusal = reason;
                ScopedQuorumTask::NotStarted
            }
            Err(error) => ScopedQuorumTask::Joined(Err(error)),
        };
        refusal
    }
}

/// Guards every slot before any enqueue, including submission notifier unwind.
/// Its Drop runs before any retained user value/error can run its destructor.
struct OwnedQuorum<T, E> {
    branches: Vec<Branch<T, E>>,
    armed: bool,
}

impl<T, E> OwnedQuorum<T, E> {
    fn new(total: usize, gateway: &Arc<SpawnGateway>) -> Self {
        Self {
            branches: (0..total)
                .map(|index| Branch {
                    region: Arc::new(BranchRegionSlot::owned(gateway)),
                    handle: None,
                    receipt: ScopedQuorumAttempt {
                        index,
                        task: ScopedQuorumTask::NotStarted,
                        region_id: None,
                        close: None,
                    },
                })
                .collect(),
            armed: true,
        }
    }

    fn request_stop(&self, reason: CancelReason) {
        // Close EVERY subtree first. Even a successful body can leave children
        // behind, and a losing body may be joining one of its own children.
        for branch in &self.branches {
            let _ = branch.region.request_close(reason.clone());
        }
        for branch in &self.branches {
            if let Some(handle) = &branch.handle
                && !handle.terminal_published()
            {
                handle.abort_with_reason(reason.clone());
            }
        }
    }
}

impl<T, E> Drop for OwnedQuorum<T, E> {
    fn drop(&mut self) {
        if self.armed {
            self.request_stop(CancelReason::user("scoped quorum dropped"));
        }
    }
}

fn owner_reason<Caps>(owner: &Cx<Caps>) -> CancelReason {
    owner
        .cancel_reason()
        .unwrap_or_else(|| CancelReason::user("scoped quorum owner cancelled"))
}

impl<Caps> Cx<Caps>
where
    Caps: cap::HasSpawn + Send + Sync + 'static,
{
    /// Selects `required` successful tasks from at most 64 lazy factories, each
    /// in its own private region, then closes and drains EVERY entire subtree.
    ///
    /// Factories receive the admitted context with the caller's exact typed
    /// capabilities. Use that supplied context for owned descendants. Captured
    /// unrelated authority remains unrelated. A factory is never invoked when
    /// private-region admission falls back to the parent. No timer is required.
    ///
    /// Application errors and independent task cancellations count against
    /// quorum without defeating other candidates. A task panic or admission
    /// refusal stops selection. An impossible quorum cancels remaining work
    /// immediately. Ready joins are scanned in input order, at most 64 per
    /// poll; a parked group does not self-wake. This selects successful tasks,
    /// not agreement between their values or rollback of committed effects.
    ///
    /// Owner cancellation is observed without acknowledging or unmasking it,
    /// before candidate joins. Once quorum is selected it remains selected:
    /// later owner cancellation, late task outcomes, and cleanup failures are
    /// never allowed to rewrite that fact. Inspect every receipt independently;
    /// `Satisfied` is NOT evidence of successful finalizer/descendant cleanup.
    /// Every value/error, including an unselected late success, is retained.
    ///
    /// All regions, including selected branches, receive close BEFORE any
    /// draining join. Then tasks, descendants, pending admissions, obligations,
    /// and finalizers are awaited without a cancellation short circuit. Cleanup
    /// is cooperative and has no forced deadline. Values and errors must not
    /// retain obligations required to close their own operation region.
    ///
    /// Drop requests close for every slot before dropping retained results;
    /// even a region published after drop inherits that request. Drop cannot
    /// await cleanup; the runtime remains the asynchronous ownership backstop.
    ///
    /// # Errors
    ///
    /// Invalid bounds or a missing runtime are refused before admission. After
    /// any submission, all failures remain in the report and admitted work is
    /// drained. `Result::Ok(report)` itself does not claim successful quorum.
    ///
    /// ```
    /// use asupersync::Cx;
    /// use asupersync::cx::{RaceFactory, ScopedQuorumStop, ScopedQuorumTask};
    /// use asupersync::runtime::JoinError;
    /// use asupersync::types::Outcome;
    ///
    /// async fn example(cx: &Cx) -> Result<Vec<u32>, Box<dyn std::error::Error>> {
    ///     let factories: Vec<RaceFactory<Result<u32, &'static str>>> = vec![
    ///         Box::new(|_| Box::pin(async { Ok(7) })),
    ///         Box::new(|_| Box::pin(async { Ok(11) })),
    ///     ];
    ///     let report = cx.quorum_scoped(2, factories).await?;
    ///     let clean = report.attempts.iter().all(|attempt| {
    ///         let Some(Ok(close)) = &attempt.close else { return false };
    ///         attempt.region_id.is_some()
    ///             && close.cleanup_outcome.is_none()
    ///             && close.descendant_panic.is_none()
    ///             && !matches!(&close.outcome, Outcome::Err(_) | Outcome::Panicked(_))
    ///             && !matches!(&attempt.task, ScopedQuorumTask::Joined(Err(
    ///                 JoinError::Panicked(_) | JoinError::PolledAfterCompletion
    ///             )))
    ///     });
    ///     if !matches!(report.stop, ScopedQuorumStop::Satisfied) || !clean {
    ///         return Err("quorum selection or subtree cleanup failed".into());
    ///     }
    ///     report.selected.iter().map(|&index| {
    ///         match &report.attempts[index].task {
    ///             ScopedQuorumTask::Joined(Ok(Ok(value))) => Ok(*value),
    ///             _ => Err("selected task has no successful value".into()),
    ///         }
    ///     }).collect()
    /// }
    /// ```
    pub async fn quorum_scoped<T, E, F, Fut>(
        &self,
        required: usize,
        factories: Vec<F>,
    ) -> Result<ScopedQuorumReport<T, E>, ScopedQuorumError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: Send + 'static,
    {
        let total = factories.len();
        if required == 0 || required > total || total > MAX_SCOPED_QUORUM_BRANCHES {
            return Err(ScopedQuorumError::InvalidQuorum { required, total });
        }
        let gateway = self
            .spawn_gateway_handle()
            .ok_or(ScopedQuorumError::Spawn(SpawnError::RuntimeUnavailable))?;
        // The guard is declared AFTER the iterator: cancellation requests must
        // precede destruction of any unsubmitted caller-owned factories too.
        let mut factories = factories.into_iter();
        let mut owned = OwnedQuorum::new(total, &gateway);
        let mut admission_stop = None;
        for index in 0..total {
            if self.is_cancel_requested() {
                admission_stop = Some(ScopedQuorumStop::Cancelled(owner_reason(self)));
                break;
            }
            let factory = factories.next().expect("one factory for each input");
            let region = Arc::clone(&owned.branches[index].region);
            let factory_region = Arc::clone(&region);
            let factory_owner = self.clone();
            match self.spawn_owned_branch(region, move |body| async move {
                if factory_region.get().is_none() {
                    return BodyResult::NotStarted(None);
                }
                if factory_owner.is_cancel_requested() {
                    return BodyResult::NotStarted(Some(owner_reason(&factory_owner)));
                }
                if factory_region.close_requested() || body.is_cancel_requested() {
                    return BodyResult::NotStarted(None);
                }
                BodyResult::Value(factory(body).await)
            }) {
                Ok(handle) => owned.branches[index].handle = Some(handle),
                Err(error) => {
                    owned.branches[index].receipt.task = ScopedQuorumTask::SubmissionFailed(error);
                    admission_stop = Some(ScopedQuorumStop::NotAdmitted { index });
                    break;
                }
            }
        }

        let mut selected = Vec::with_capacity(required);
        let stop = if let Some(stop) = admission_stop {
            stop
        } else {
            let mut remaining = total;
            let mut cancelled = std::pin::pin!(self.cancelled());
            poll_fn(|task| {
                if cancelled.as_mut().poll(task).is_ready() {
                    return Poll::Ready(ScopedQuorumStop::Cancelled(owner_reason(self)));
                }
                for (index, branch) in owned.branches.iter_mut().enumerate() {
                    let Some(handle) = &mut branch.handle else {
                        continue;
                    };
                    let Poll::Ready(result) = handle.poll_join(task) else {
                        continue;
                    };
                    if let Some(reason) = branch.joined(result) {
                        return Poll::Ready(ScopedQuorumStop::Cancelled(reason));
                    }
                    // A different worker can request owner cancellation after
                    // the observer's poll but before this terminal join.
                    if self.is_cancel_requested() {
                        return Poll::Ready(ScopedQuorumStop::Cancelled(owner_reason(self)));
                    }
                    remaining -= 1;
                    if branch.region.get().is_none() {
                        return Poll::Ready(ScopedQuorumStop::NotAdmitted { index });
                    }
                    match &branch.receipt.task {
                        ScopedQuorumTask::Joined(Ok(Ok(_))) => selected.push(index),
                        ScopedQuorumTask::Joined(Ok(Err(_)) | Err(JoinError::Cancelled(_))) => {}
                        ScopedQuorumTask::Joined(Err(_)) => {
                            return Poll::Ready(ScopedQuorumStop::TaskFailed { index });
                        }
                        ScopedQuorumTask::NotStarted | ScopedQuorumTask::SubmissionFailed(_) => {
                            return Poll::Ready(ScopedQuorumStop::NotAdmitted { index });
                        }
                    }
                    if selected.len() == required {
                        return Poll::Ready(ScopedQuorumStop::Satisfied);
                    }
                    if selected.len() + remaining < required {
                        return Poll::Ready(ScopedQuorumStop::InsufficientSuccesses);
                    }
                }
                Poll::Pending
            })
            .await
        };
        let reason = match &stop {
            ScopedQuorumStop::Satisfied => CancelReason::race_loser(),
            ScopedQuorumStop::Cancelled(reason) => reason.clone(),
            _ => CancelReason::fail_fast(),
        };
        owned.request_stop(reason);
        // Unsubmitted factories may hold the last sender/permit needed by an
        // admitted branch's cleanup. Release them after fan-out but BEFORE any
        // join; the armed guard still protects every slot if Drop unwinds.
        drop(factories);

        // No branch's join can block cancellation of another branch's subtree.
        // All body receipts stay owned until ALL region barriers have settled.
        for branch in &mut owned.branches {
            if branch.handle.is_some() {
                let result = poll_fn(|task| {
                    branch
                        .handle
                        .as_mut()
                        .expect("unconsumed branch join")
                        .poll_join(task)
                })
                .await;
                let _ = branch.joined(result);
            }
        }
        for branch in &mut owned.branches {
            if let Some(minted) = branch.region.get() {
                branch.receipt.region_id = Some(minted.region_id);
                let closed =
                    RegionQuiescence::watch(minted.close_notify(), Some(Arc::clone(&gateway)))
                        .await;
                branch.receipt.close = Some(closed.and_then(|()| {
                    minted
                        .close_outcome()
                        .map(|receipt| ScopedQuorumClose {
                            outcome: receipt.outcome,
                            cleanup_outcome: receipt.cleanup_outcome,
                            descendant_panic: receipt.descendant_panic,
                        })
                        .ok_or(ChildRegionError::RuntimeUnavailable)
                }));
            }
        }
        owned.armed = false;
        let attempts = std::mem::take(&mut owned.branches)
            .into_iter()
            .map(|branch| branch.receipt)
            .collect();
        Ok(ScopedQuorumReport {
            stop,
            required,
            selected,
            attempts,
        })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_quorum_inline_tests.rs"]
mod tests;
