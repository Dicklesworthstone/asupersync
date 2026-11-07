//! A typed race whose two private operation subtrees close before it returns.

use super::child_region::RegionQuiescence;
use super::{ChildRegionError, Cx, cap};
use crate::record::task::TaskOutcome;
use crate::runtime::spawn_mailbox::{BranchRegionSlot, SpawnGateway};
use crate::runtime::state::SpawnError;
use crate::runtime::{JoinError, TaskHandle};
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::types::{CancelReason, PanicPayload, RegionId};
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::{Context, Poll};

/// One of the two operations admitted by [`Cx::race_scoped`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopedRaceBranch {
    /// The first factory passed to the race.
    Left,
    /// The second factory passed to the race.
    Right,
}

/// The immutable decision that stopped useful execution of a scoped race.
///
/// A branch's eventual task result and its subtree's cleanup outcome are
/// separate facts. Later cancellation or a losing branch's panic does not
/// replace a winner that was already selected.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ScopedRaceStop {
    /// This branch's terminal join was observed first after its user factory
    /// started. The task may have returned a value, been cancelled, or panicked.
    Winner(ScopedRaceBranch),
    /// The explicit owner's cancellation was observed before selecting a
    /// branch. The complete cancellation reason is preserved.
    Cancelled(CancelReason),
    /// This branch was refused submission, private-region admission, or its
    /// first user-factory invocation before a winner was selected. Any
    /// already-submitted sibling is drained.
    NotAdmitted(ScopedRaceBranch),
}

/// What one branch task actually returned after it finished draining.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedRaceTask<T> {
    /// No task was submitted, or the private-region wrapper refused to invoke
    /// its user factory. A cancellation before first poll can instead retain
    /// its ordinary task-level error in [`Self::Joined`].
    NotStarted,
    /// The ordinary task join result, including values returned after the task
    /// acknowledges cancellation. An error before factory invocation remains
    /// a task fact but cannot select that branch as a winner.
    Joined(Result<T, JoinError>),
}

/// The actual runtime close receipt for one private branch subtree.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ScopedRaceClose {
    /// Runtime task/region outcome, including ordinary close cancellation.
    pub outcome: TaskOutcome,
    /// Finalizer/cleanup failure retained separately from both task results.
    pub cleanup_outcome: Option<TaskOutcome>,
    /// This region's panic or the first panic propagated by a descendant.
    pub descendant_panic: Option<PanicPayload>,
}

/// Independent task, submission, and whole-subtree cleanup facts for a branch.
#[derive(Debug)]
#[non_exhaustive]
pub struct ScopedRaceBranchReport<T> {
    /// What the direct branch task returned, without replacing the race's
    /// decision or its sibling's task result.
    pub task: ScopedRaceTask<T>,
    /// The private region, when admission minted one.
    pub region_id: Option<RegionId>,
    /// The actual close receipt. `None` means no private region was published;
    /// an error does not certify quiescence.
    pub close: Option<Result<ScopedRaceClose, ChildRegionError>>,
    /// A synchronous refusal to submit this branch. Later admission failures
    /// are retained in `task` instead. No error means neither that submission
    /// occurred nor that the user factory ran.
    pub submission_error: Option<SpawnError>,
}

/// A scoped race's immutable decision and both branches' complete receipts.
#[derive(Debug)]
#[non_exhaustive]
pub struct ScopedRaceReport<L, R> {
    /// The condition that stopped useful execution.
    pub stop: ScopedRaceStop,
    /// The first operation's task and cleanup results.
    pub left: ScopedRaceBranchReport<L>,
    /// The second operation's task and cleanup results.
    pub right: ScopedRaceBranchReport<R>,
    /// Cancellation observed on the explicit owner before returning, including
    /// during unconditional cleanup. Reasons are strengthened while draining;
    /// this fact never erases a previously selected `Winner` or task value.
    pub owner_cancellation: Option<CancelReason>,
}

/// A refusal before either scoped branch can be submitted.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedRaceError {
    /// The explicit context has no runtime gateway for task submission.
    Spawn(SpawnError),
}

impl std::fmt::Display for ScopedRaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(error) => write!(f, "scoped race admission failed: {error}"),
        }
    }
}

impl std::error::Error for ScopedRaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
        }
    }
}

enum BodyResult<T> {
    Value(T),
    NotStarted,
}

struct OwnedBranch<T> {
    region: Arc<BranchRegionSlot>,
    started: Arc<AtomicBool>,
    handle: Option<TaskHandle<BodyResult<T>>>,
    result: Option<Result<BodyResult<T>, JoinError>>,
    submission_error: Option<SpawnError>,
}

impl<T> OwnedBranch<T> {
    fn new(gateway: &Arc<SpawnGateway>) -> Self {
        Self {
            region: Arc::new(BranchRegionSlot::owned(gateway)),
            started: Arc::new(AtomicBool::new(false)),
            handle: None,
            result: None,
            submission_error: None,
        }
    }

    fn submit<Caps, F, Fut>(&mut self, owner: &Cx<Caps>, operation: F) -> bool
    where
        Caps: cap::HasSpawn + Send + Sync + 'static,
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let factory_region = Arc::clone(&self.region);
        let factory_owner = owner.clone();
        let started = Arc::clone(&self.started);
        match owner.spawn_owned_branch(Arc::clone(&self.region), move |body_cx| async move {
            // Ordinary races can fall back to the parent on a refused region
            // mint. This API promises two private subtrees, so such a fallback
            // must never invoke user work.
            if factory_region.get().is_none()
                || factory_region.close_requested()
                || factory_owner.is_cancel_requested()
                || body_cx.is_cancel_requested()
            {
                return BodyResult::NotStarted;
            }
            // A factory panic is a genuine branch terminal. A cancelled or
            // refused task that never reached this point is not a winner.
            started.store(true, Ordering::Release);
            BodyResult::Value(operation(body_cx).await)
        }) {
            Ok(handle) => {
                self.handle = Some(handle);
                true
            }
            Err(error) => {
                self.submission_error = Some(error);
                false
            }
        }
    }

    fn abort_if_running(&self, reason: CancelReason) {
        if let Some(handle) = &self.handle
            && !handle.terminal_published()
        {
            handle.abort_with_reason(reason);
        }
    }

    fn poll_result(&mut self, task: &mut Context<'_>) -> bool {
        if self.result.is_some() {
            return true;
        }
        let Some(handle) = &mut self.handle else {
            return true;
        };
        match handle.poll_join(task) {
            Poll::Ready(result) => {
                self.result = Some(result);
                true
            }
            Poll::Pending => false,
        }
    }

    fn decision(&self, branch: ScopedRaceBranch) -> ScopedRaceStop {
        if self.started.load(Ordering::Acquire) {
            ScopedRaceStop::Winner(branch)
        } else {
            ScopedRaceStop::NotAdmitted(branch)
        }
    }

    fn report(
        &mut self,
        region_id: Option<RegionId>,
        close: Option<Result<ScopedRaceClose, ChildRegionError>>,
    ) -> ScopedRaceBranchReport<T> {
        let task = match self.result.take() {
            Some(Ok(BodyResult::Value(value))) => ScopedRaceTask::Joined(Ok(value)),
            Some(Err(error)) => ScopedRaceTask::Joined(Err(error)),
            Some(Ok(BodyResult::NotStarted)) | None => ScopedRaceTask::NotStarted,
        };
        ScopedRaceBranchReport {
            task,
            region_id,
            close,
            submission_error: self.submission_error.take(),
        }
    }
}

/// Both slots exist before either enqueue. Drop closes both subtrees before
/// destroying retained results, handles, or user-owned values, even if a
/// notifier unwinds after publishing a request but before returning its handle.
struct OwnedRace<L, R> {
    left: OwnedBranch<L>,
    right: OwnedBranch<R>,
    armed: bool,
}

impl<L, R> OwnedRace<L, R> {
    fn request_stop(&self, left: CancelReason, right: CancelReason) {
        // Publish both region requests before either direct-task abort. A
        // losing task can be blocked in a plain join on its own descendant
        // (br-asupersync-inleqi); joining it first would deadlock the drain.
        let _ = self.left.region.request_close(left.clone());
        let _ = self.right.region.request_close(right.clone());
        self.left.abort_if_running(left);
        self.right.abort_if_running(right);
    }
}

impl<L, R> Drop for OwnedRace<L, R> {
    fn drop(&mut self) {
        if self.armed {
            let reason = CancelReason::user("scoped race dropped");
            self.request_stop(reason.clone(), reason);
        }
    }
}

fn owner_cancel_reason<Caps>(owner: &Cx<Caps>) -> CancelReason {
    owner
        .cancel_reason()
        .unwrap_or_else(|| CancelReason::user("scoped race owner cancelled"))
}

/// Records a newly observed or stronger reason without acknowledging the
/// owner's cancellation or charging its checkpoint budget.
fn observe_owner_cancellation<Caps>(
    owner: &Cx<Caps>,
    observed: &mut Option<CancelReason>,
) -> bool {
    if !owner.is_cancel_requested() {
        return false;
    }
    let reason = owner_cancel_reason(owner);
    if let Some(previous) = observed {
        previous.strengthen(&reason)
    } else {
        *observed = Some(reason);
        true
    }
}

fn unstarted_branch<T>() -> ScopedRaceBranchReport<T> {
    ScopedRaceBranchReport {
        task: ScopedRaceTask::NotStarted,
        region_id: None,
        close: None,
        submission_error: None,
    }
}

async fn close_receipt(
    region: &Arc<BranchRegionSlot>,
    gateway: &Arc<SpawnGateway>,
) -> (
    Option<RegionId>,
    Option<Result<ScopedRaceClose, ChildRegionError>>,
) {
    let Some(minted) = region.get() else {
        return (None, None);
    };
    let closed = RegionQuiescence::watch(minted.close_notify(), Some(Arc::clone(gateway))).await;
    let receipt = closed.and_then(|()| {
        minted
            .close_outcome()
            .map(|outcome| ScopedRaceClose {
                outcome: outcome.outcome,
                cleanup_outcome: outcome.cleanup_outcome,
                descendant_panic: outcome.descendant_panic,
            })
            .ok_or(ChildRegionError::RuntimeUnavailable)
    });
    (Some(minted.region_id), Some(receipt))
}

impl<Caps> Cx<Caps>
where
    Caps: cap::HasSpawn + Send + Sync + 'static,
{
    /// Races two factories in private regions, then cancels and drains both
    /// complete subtrees before returning their typed results.
    ///
    /// The factories may return different types. The first terminal task join
    /// observed after its factory started selects the winner, whether that
    /// task returned a value, was cancelled, or panicked. If both are ready
    /// when selection polls them, the left branch wins. Cancellation already
    /// requested on this explicit owner takes precedence over selecting either
    /// ready branch. Refusal observed before a winner selects `NotAdmitted`
    /// and drains every submitted sibling instead of becoming a winning
    /// result. Refusal observed after selection remains a branch task fact.
    ///
    /// After selection, the losing **region** is cancelled before its task is
    /// joined. A losing task may therefore wait in an ordinary
    /// [`TaskHandle::join`] for a child that finishes only after cancellation
    /// (br-asupersync-inleqi). The winner's remaining descendants are also
    /// cancelled and drained. Both close receipts include descendants, pending
    /// admissions, obligations, and finalizers. Non-cooperative code can delay
    /// this drain indefinitely; the race never substitutes forced destruction.
    ///
    /// The decision is immutable during cleanup. A later owner cancellation
    /// is forwarded and recorded separately in `owner_cancellation`; it does
    /// not erase a winner, the winner's typed value, or a loser's acknowledged
    /// cancellation result. A losing panic and a finalizer failure likewise
    /// remain separate report facts. Inspect both `close` fields before
    /// treating the report as a successful quiescent close.
    ///
    /// Cancellation observation is mask-agnostic, like [`Cx::cancelled`], and
    /// never acknowledges the owner's request or changes its mask. Only this
    /// context's runtime and spawn authority are used; no timer is required.
    /// An already-cancelled owner invokes neither factory. Private admission
    /// preserves the supplied capability set and strict spawn authorization;
    /// a refused distinct-region mint never runs the factory in the parent.
    ///
    /// Factories must use their supplied context for owned work. Retained
    /// contexts, including nested race winners, cannot escape these subtrees
    /// after close. Explicitly captured authority for unrelated regions is
    /// still unrelated authority. Returned values must not retain obligations
    /// whose release is required to close either operation region.
    ///
    /// Dropping this future requests close for both subtrees, including close
    /// requests handed to admission before it publishes a private region.
    /// Drop cannot await cleanup; the enclosing region remains the eventual
    /// drain backstop. Existing race APIs keep their established behavior.
    ///
    /// # Errors
    ///
    /// A missing runtime gateway returns [`ScopedRaceError`] before submission.
    /// Synchronous submission failures instead appear in the corresponding
    /// branch's `submission_error`; the report is returned only after draining
    /// any sibling already submitted. Later admission errors retain the
    /// ordinary task join result. A close error does not certify quiescence.
    ///
    /// ```
    /// use asupersync::Cx;
    /// use asupersync::cx::{ScopedRaceBranch, ScopedRaceStop, ScopedRaceTask};
    ///
    /// async fn example(cx: &Cx) {
    ///     let report = cx.race_scoped(
    ///         |_| async { 42_u32 },
    ///         |_| async { "other result type" },
    ///     ).await.expect("runtime gateway");
    ///     match report.stop {
    ///         ScopedRaceStop::Winner(ScopedRaceBranch::Left) => {
    ///             assert!(matches!(report.left.task, ScopedRaceTask::Joined(Ok(42))));
    ///         }
    ///         ScopedRaceStop::Winner(ScopedRaceBranch::Right) => {
    ///             assert!(matches!(report.right.task, ScopedRaceTask::Joined(Ok("other result type"))));
    ///         }
    ///         _ => {}
    ///     }
    /// }
    /// ```
    pub async fn race_scoped<L, R, FL, FR, FutL, FutR>(
        &self,
        left: FL,
        right: FR,
    ) -> Result<ScopedRaceReport<L, R>, ScopedRaceError>
    where
        FL: FnOnce(Cx<Caps>) -> FutL + Send + 'static,
        FR: FnOnce(Cx<Caps>) -> FutR + Send + 'static,
        FutL: Future<Output = L> + Send + 'static,
        FutR: Future<Output = R> + Send + 'static,
        L: Send + 'static,
        R: Send + 'static,
    {
        let gateway = self
            .spawn_gateway_handle()
            .ok_or(ScopedRaceError::Spawn(SpawnError::RuntimeUnavailable))?;
        let mut owner_cancellation = None;
        if observe_owner_cancellation(self, &mut owner_cancellation) {
            return Ok(ScopedRaceReport {
                stop: ScopedRaceStop::Cancelled(
                    owner_cancellation.clone().expect("owner request observed"),
                ),
                left: unstarted_branch(),
                right: unstarted_branch(),
                owner_cancellation,
            });
        }

        // An unsubmitted right factory is retired only after stop requests
        // have been handed to both slots, before waiting for any cleanup.
        let mut right_factory = Some(right);
        let mut owned = OwnedRace {
            left: OwnedBranch::new(&gateway),
            right: OwnedBranch::new(&gateway),
            armed: true,
        };
        let refused = if !owned.left.submit(self, left) {
            Some(ScopedRaceBranch::Left)
        } else if self.is_cancel_requested() {
            // Cancellation observed between submissions starts no new branch.
            None
        } else if !owned
            .right
            .submit(self, right_factory.take().expect("right factory submitted once"))
        {
            Some(ScopedRaceBranch::Right)
        } else {
            None
        };

        let mut cancelled = std::pin::pin!(self.cancelled());
        let stop = if observe_owner_cancellation(self, &mut owner_cancellation) {
            ScopedRaceStop::Cancelled(
                owner_cancellation.clone().expect("owner request observed"),
            )
        } else if let Some(branch) = refused {
            ScopedRaceStop::NotAdmitted(branch)
        } else {
            poll_fn(|task| {
                if cancelled.as_mut().poll(task).is_ready() {
                    observe_owner_cancellation(self, &mut owner_cancellation);
                    return Poll::Ready(ScopedRaceStop::Cancelled(owner_cancel_reason(self)));
                }
                let decision = if owned.left.poll_result(task) {
                    Some(owned.left.decision(ScopedRaceBranch::Left))
                } else if owned.right.poll_result(task) {
                    Some(owned.right.decision(ScopedRaceBranch::Right))
                } else {
                    None
                };
                if let Some(decision) = decision {
                    // A cancellation published while consuming a ready join
                    // still precedes the decision's final observation point.
                    if observe_owner_cancellation(self, &mut owner_cancellation) {
                        Poll::Ready(ScopedRaceStop::Cancelled(owner_cancel_reason(self)))
                    } else {
                        Poll::Ready(decision)
                    }
                } else {
                    Poll::Pending
                }
            })
            .await
        };

        let (left_reason, right_reason) = match &stop {
            ScopedRaceStop::Winner(ScopedRaceBranch::Left) => (
                CancelReason::user("scoped race winner completed"),
                CancelReason::race_loser(),
            ),
            ScopedRaceStop::Winner(ScopedRaceBranch::Right) => (
                CancelReason::race_loser(),
                CancelReason::user("scoped race winner completed"),
            ),
            ScopedRaceStop::Cancelled(reason) => (reason.clone(), reason.clone()),
            ScopedRaceStop::NotAdmitted(_) => {
                let reason = CancelReason::resource_unavailable()
                    .with_message("scoped race branch admission failed");
                (reason.clone(), reason)
            }
        };
        owned.request_stop(left_reason, right_reason);
        drop(right_factory);

        // Poll both handles in every drain turn. Neither a result retained on
        // one side nor owner cancellation can stop progress on the other.
        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready()
                && observe_owner_cancellation(self, &mut owner_cancellation)
            {
                let reason = owner_cancellation.clone().expect("owner request observed");
                owned.request_stop(reason.clone(), reason);
            }
            let left_done = owned.left.poll_result(task);
            let right_done = owned.right.poll_result(task);
            if left_done && right_done {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;

        // Terminal handles imply admission has either published its region or
        // refused it. Watch both actual close receipts concurrently, retaining
        // the outer owner until all asynchronous cleanup has finished.
        let mut left_closed = None;
        let mut right_closed = None;
        {
            // Keep these captures independent of the retained generic results.
            // Borrowing the whole owner here would unnecessarily require L/R:
            // Sync for the race future to remain Send.
            let left_region_slot = Arc::clone(&owned.left.region);
            let right_region_slot = Arc::clone(&owned.right.region);
            let mut left_close = std::pin::pin!(close_receipt(&left_region_slot, &gateway));
            let mut right_close = std::pin::pin!(close_receipt(&right_region_slot, &gateway));
            poll_fn(|task| {
                if cancelled.as_mut().poll(task).is_ready()
                    && observe_owner_cancellation(self, &mut owner_cancellation)
                {
                    // Both direct handles are already retired. Only the
                    // descendant/finalizer regions still need strengthening.
                    let reason = owner_cancellation.clone().expect("owner request observed");
                    let _ = left_region_slot.request_close(reason.clone());
                    let _ = right_region_slot.request_close(reason);
                }
                if left_closed.is_none()
                    && let Poll::Ready(receipt) = left_close.as_mut().poll(task)
                {
                    left_closed = Some(receipt);
                }
                if right_closed.is_none()
                    && let Poll::Ready(receipt) = right_close.as_mut().poll(task)
                {
                    right_closed = Some(receipt);
                }
                if left_closed.is_some() && right_closed.is_some() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
        observe_owner_cancellation(self, &mut owner_cancellation);
        let (left_region, left_close) = left_closed.expect("left subtree observed");
        let (right_region, right_close) = right_closed.expect("right subtree observed");
        let left = owned.left.report(left_region, left_close);
        let right = owned.right.report(right_region, right_close);
        owned.armed = false;
        Ok(ScopedRaceReport {
            stop,
            left,
            right,
            owner_cancellation,
        })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_race_inline_tests.rs"]
mod tests;
