//! All-settled factory joins with one fully drained private subtree per input.
//!
//! Reuses the owned branch admission and region-close barriers used by scoped
//! race, quorum and retry (core plan sections 6 and 12, asupersync-bi2462).

use super::child_region::RegionQuiescence;
use super::{ChildRegionError, Cx, ScopedTimeoutClose, cap};
use crate::runtime::spawn_mailbox::{BranchRegionSlot, SpawnGateway};
use crate::runtime::state::SpawnError;
use crate::runtime::{JoinError, TaskHandle};
use crate::types::{CancelReason, RegionId};
use std::any::Any;
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

/// Maximum number of factories admitted by one scoped join.
pub const MAX_SCOPED_JOIN_BRANCHES: usize = 64;

/// Why an all-settled join stopped waiting for ordinary body completion.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ScopedJoinStop {
    /// Every submitted factory ran and its task joined, including task errors
    /// and panics. This does not assert that bodies or subtree cleanup succeeded.
    /// Empty input also completes, without requiring an owning runtime.
    Completed,
    /// The explicit owner requested cancellation before all bodies joined.
    Cancelled(CancelReason),
    /// Submission, private-region admission, or first factory invocation was
    /// refused for this input. All already-submitted inputs are still drained.
    NotAdmitted {
        /// Zero-based input position of the refused branch.
        index: usize,
    },
}

/// Actual task evidence, independently of owner cancellation and region close.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedJoinTask<T> {
    /// No task was submitted, or its wrapper refused the user factory.
    /// A task cancelled before its first poll can instead retain its ordinary
    /// cancellation error in [`Self::Joined`].
    NotStarted,
    /// Submission refused before a task handle was returned.
    SubmissionFailed(SpawnError),
    /// The unchanged task join result. `T` can itself be a typed `Result` or
    /// `Outcome`; application failures are values and do not cancel siblings.
    Joined(Result<T, JoinError>),
}

/// Actual whole-subtree cleanup evidence, shared with scoped timeout operations.
pub type ScopedJoinClose = ScopedTimeoutClose;

/// Independent task and private-region cleanup facts for one input.
#[derive(Debug)]
#[non_exhaustive]
pub struct ScopedJoinAttempt<T> {
    /// Zero-based input position; reports preserve input order.
    pub index: usize,
    /// Actual task result, including values returned after cancellation acknowledgement.
    pub task: ScopedJoinTask<T>,
    /// Private region identity, when strict admission minted one.
    pub region_id: Option<RegionId>,
    /// The actual close receipt. `None` means no private region was published;
    /// an error does not certify quiescence, even if the body returned a value.
    pub close: Option<Result<ScopedJoinClose, ChildRegionError>>,
}

/// Input-order task results and every operation's independent close receipt.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "inspect every task result and subtree cleanup receipt"]
pub struct ScopedJoinReport<T> {
    /// Why ordinary body collection ended; cleanup cannot rewrite this fact.
    pub stop: ScopedJoinStop,
    /// Every original input, including unstarted or refused factories.
    pub attempts: Vec<ScopedJoinAttempt<T>>,
    /// Cancellation observed before return, including during unconditional
    /// cleanup. Later strengthening never erases a previously collected result.
    pub owner_cancellation: Option<CancelReason>,
}

/// A heterogeneous pair with the same ownership contract as the dynamic join.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "inspect both task results and subtree cleanup receipts"]
pub struct ScopedJoinPairReport<L, R> {
    /// Why ordinary body collection ended.
    pub stop: ScopedJoinStop,
    /// First input's typed result and private-region close receipt; index zero.
    pub left: ScopedJoinAttempt<L>,
    /// Second input's typed result and private-region close receipt; index one.
    pub right: ScopedJoinAttempt<R>,
    /// Cancellation observed before return, independently of collected values.
    pub owner_cancellation: Option<CancelReason>,
}

/// Refusal before any factory can be submitted.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedJoinError {
    /// The caller supplied more than [`MAX_SCOPED_JOIN_BRANCHES`] factories.
    TooManyBranches {
        /// Number of supplied factories.
        total: usize,
    },
    /// The explicit context has no runtime gateway. Per-input submission
    /// refusals instead remain in the report after any admission was attempted.
    Spawn(SpawnError),
}

impl std::fmt::Display for ScopedJoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyBranches { total } => write!(
                f, "scoped join has {total} inputs; at most {MAX_SCOPED_JOIN_BRANCHES} are supported",
            ),
            Self::Spawn(error) => write!(f, "scoped join requires an owning runtime: {error}"),
        }
    }
}

impl std::error::Error for ScopedJoinError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            Self::TooManyBranches { .. } => None,
        }
    }
}

enum BodyResult<T> {
    Value(T),
    NotStarted,
}

struct Branch<T> {
    region: Arc<BranchRegionSlot>,
    started: Arc<AtomicBool>,
    handle: Option<TaskHandle<BodyResult<T>>>,
    receipt: ScopedJoinAttempt<T>,
}

impl<T> Branch<T> {
    /// Consume each persistent join registration exactly once. Close the
    /// completed body's subtree promptly, without cancelling other branches.
    fn poll_result(&mut self, task: &mut Context<'_>) -> bool {
        let Some(handle) = &mut self.handle else {
            return true;
        };
        let Poll::Ready(result) = handle.poll_join(task) else {
            return false;
        };
        self.handle = None;
        self.receipt.task = match result {
            Ok(BodyResult::Value(value)) => ScopedJoinTask::Joined(Ok(value)),
            Ok(BodyResult::NotStarted) => ScopedJoinTask::NotStarted,
            Err(error) => ScopedJoinTask::Joined(Err(error)),
        };
        let _ = self.region.request_close(CancelReason::user("scoped join body completed"));
        true
    }
}

/// Every slot is guarded before any enqueue. This guard's Drop requests all
/// closes before retained values or unused factories can run their destructors.
struct OwnedJoin<T> {
    branches: Vec<Branch<T>>,
    armed: bool,
}

impl<T> OwnedJoin<T> {
    fn new(total: usize, gateway: &Arc<SpawnGateway>) -> Self {
        Self {
            branches: (0..total).map(|index| Branch {
                region: Arc::new(BranchRegionSlot::owned(gateway)),
                started: Arc::new(AtomicBool::new(false)),
                handle: None,
                receipt: ScopedJoinAttempt {
                    index,
                    task: ScopedJoinTask::NotStarted,
                    region_id: None,
                    close: None,
                },
            }).collect(),
            armed: true,
        }
    }

    fn request_stop(&self, reason: CancelReason) {
        let mut first_panic = None;
        // Publish every subtree cancellation BEFORE any direct-task abort.
        // A body can be parked in an ordinary join on its own descendant.
        for branch in &self.branches {
            contain_callback(&mut first_panic, || {
                let _ = branch.region.request_close(reason.clone());
            });
        }
        for branch in &self.branches {
            if let Some(handle) = &branch.handle
                && !handle.terminal_published()
            {
                contain_callback(&mut first_panic, || {
                    handle.abort_with_reason(reason.clone());
                });
            }
        }
        if let Some(payload) = first_panic {
            resume_unwind(payload);
        }
    }
}

// A broken notifier/waker must not prevent cancellation reaching later slots.
// During an existing unwind, forget secondary panic payloads rather than
// risking a second panic from either the callback or its payload destructor.
fn contain_callback(first: &mut Option<Box<dyn Any + Send>>, f: impl FnOnce()) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(f)) {
        if first.is_none() && !std::thread::panicking() {
            *first = Some(payload);
        } else {
            std::mem::forget(payload);
        }
    }
}

impl<T> Drop for OwnedJoin<T> {
    fn drop(&mut self) {
        if self.armed {
            self.request_stop(CancelReason::user("scoped join dropped"));
        }
    }
}

fn owner_reason<Caps>(owner: &Cx<Caps>) -> CancelReason {
    owner.cancel_reason().unwrap_or_else(|| CancelReason::user("scoped join owner cancelled"))
}

/// Observe without acknowledging cancellation or charging the owner's budget.
fn observe_owner<Caps>(owner: &Cx<Caps>, observed: &mut Option<CancelReason>) -> bool {
    if !owner.is_cancel_requested() {
        return false;
    }
    let reason = owner_reason(owner);
    if let Some(previous) = observed {
        previous.strengthen(&reason)
    } else {
        *observed = Some(reason);
        true
    }
}

async fn close_receipt(
    region: Arc<BranchRegionSlot>,
    gateway: Arc<SpawnGateway>,
) -> (Option<RegionId>, Option<Result<ScopedJoinClose, ChildRegionError>>) {
    let Some(minted) = region.get() else {
        return (None, None);
    };
    let closed = RegionQuiescence::watch(minted.close_notify(), Some(gateway)).await;
    let receipt = closed.and_then(|()| {
        minted.close_outcome().map(|receipt| ScopedJoinClose {
            outcome: receipt.outcome,
            cleanup_outcome: receipt.cleanup_outcome,
            descendant_panic: receipt.descendant_panic,
        }).ok_or(ChildRegionError::RuntimeUnavailable)
    });
    (Some(minted.region_id), Some(receipt))
}

impl<Caps> Cx<Caps>
where
    Caps: cap::HasSpawn + Send + Sync + 'static,
{
    /// Run at most 64 factories in private regions, retaining every result in
    /// input order and closing every complete subtree before returning.
    ///
    /// This is an all-settled join: an application error, independent task
    /// cancellation, or panic does not cancel other admitted factories. A
    /// returned `T` may itself be a typed `Result` or `Outcome`; it is preserved
    /// unchanged. Unlike [`Self::quorum_scoped`], there is no success threshold
    /// and no fail-fast selection. Inspect task AND close receipts: `Completed`
    /// does not mean that either the operations or their cleanup succeeded.
    ///
    /// Factories run only after strict private-region admission, with their
    /// actual typed child context. Use that context for owned descendants;
    /// captured unrelated authority stays unrelated. A completed body closes
    /// its own subtree promptly, including remaining descendants. Other bodies
    /// continue normally. Results remain retained until every task, descendant,
    /// pending admission, obligation and finalizer has crossed its barrier.
    /// Values must not retain obligations needed to close their own regions.
    ///
    /// Owner cancellation and admission refusal close ALL subtrees before
    /// joining remaining bodies, including a body joining its own child. The
    /// actual late results remain in the report. Owner cancellation is observed
    /// without acknowledgement or unmasking; cancellation observed during final
    /// cleanup is recorded separately and cannot rewrite an earlier `Completed`.
    /// No timer or forced deadline is involved. Uncooperative work may delay
    /// completion indefinitely; a close error never certifies quiescence.
    ///
    /// Dropping an unpolled call starts no work. Dropping an admitted call
    /// requests close for every private subtree, including regions published
    /// after drop. Drop cannot synchronously drain; the runtime retains that
    /// asynchronous responsibility. No detached cleanup task is spawned.
    /// Polling is bounded by the 64-input ceiling and a parked group does not
    /// self-wake. Results need not be `Clone`, `Sync`, or `Unpin`.
    ///
    /// # Errors
    /// Too many inputs or a missing runtime are refused before submission.
    /// Empty input completes without runtime authority. After submission begins,
    /// individual refusals remain in the fully drained report.
    ///
    /// ```no_run
    /// # async fn example(cx: &asupersync::Cx) {
    /// use asupersync::cx::{RaceFactory, ScopedJoinStop, ScopedJoinTask};
    /// let factories: Vec<RaceFactory<Result<u32, &'static str>>> = vec![
    ///     Box::new(|_| Box::pin(async { Ok(7) })),
    ///     Box::new(|_| Box::pin(async { Err("unavailable") })),
    /// ];
    /// let report = cx.join_all_scoped(factories).await.expect("runtime admission");
    /// assert!(matches!(report.stop, ScopedJoinStop::Completed));
    /// assert!(matches!(report.attempts[0].task, ScopedJoinTask::Joined(Ok(Ok(7)))));
    /// assert!(matches!(report.attempts[1].task, ScopedJoinTask::Joined(Ok(Err("unavailable")))));
    /// assert!(report.attempts.iter().all(|attempt| matches!(attempt.close, Some(Ok(_)))));
    /// # }
    /// ```
    pub async fn join_all_scoped<T, F, Fut>(
        &self,
        factories: Vec<F>,
    ) -> Result<ScopedJoinReport<T>, ScopedJoinError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let total = factories.len();
        if total > MAX_SCOPED_JOIN_BRANCHES {
            return Err(ScopedJoinError::TooManyBranches { total });
        }
        if total == 0 {
            return Ok(ScopedJoinReport {
                stop: ScopedJoinStop::Completed,
                attempts: Vec::new(),
                owner_cancellation: None,
            });
        }
        let gateway = self.spawn_gateway_handle()
            .ok_or(ScopedJoinError::Spawn(SpawnError::RuntimeUnavailable))?;
        // Guard declared after the iterator: cancellation must precede unused
        // factory destructors if this future is abandoned or unwinds.
        let mut factories = factories.into_iter();
        let mut owned = OwnedJoin::new(total, &gateway);
        let mut owner_cancellation = None;
        let mut admission_stop = None;
        for index in 0..total {
            if observe_owner(self, &mut owner_cancellation) {
                admission_stop = Some(ScopedJoinStop::Cancelled(owner_reason(self)));
                break;
            }
            let factory = factories.next().expect("one factory for each input");
            let region = Arc::clone(&owned.branches[index].region);
            let factory_region = Arc::clone(&region);
            let started = Arc::clone(&owned.branches[index].started);
            let factory_owner = self.clone();
            match self.spawn_owned_branch(region, move |body| async move {
                if factory_region.get().is_none()
                    || factory_region.close_requested()
                    || factory_owner.is_cancel_requested()
                    || body.is_cancel_requested()
                {
                    return BodyResult::NotStarted;
                }
                started.store(true, Ordering::Release);
                BodyResult::Value(factory(body).await)
            }) {
                Ok(handle) => owned.branches[index].handle = Some(handle),
                Err(error) => {
                    owned.branches[index].receipt.task = ScopedJoinTask::SubmissionFailed(error);
                    admission_stop = Some(ScopedJoinStop::NotAdmitted { index });
                    break;
                }
            }
        }

        let mut cancelled = std::pin::pin!(self.cancelled());
        let stop = if observe_owner(self, &mut owner_cancellation) {
            ScopedJoinStop::Cancelled(owner_reason(self))
        } else if let Some(stop) = admission_stop {
            stop
        } else {
            poll_fn(|task| {
                if cancelled.as_mut().poll(task).is_ready() {
                    observe_owner(self, &mut owner_cancellation);
                    return Poll::Ready(ScopedJoinStop::Cancelled(owner_reason(self)));
                }
                let mut all_done = true;
                for branch in &mut owned.branches {
                    if branch.poll_result(task) {
                        if observe_owner(self, &mut owner_cancellation) {
                            return Poll::Ready(ScopedJoinStop::Cancelled(owner_reason(self)));
                        }
                        if !branch.started.load(Ordering::Acquire) {
                            return Poll::Ready(ScopedJoinStop::NotAdmitted {
                                index: branch.receipt.index,
                            });
                        }
                    } else {
                        all_done = false;
                    }
                }
                if all_done {
                    Poll::Ready(ScopedJoinStop::Completed)
                } else {
                    Poll::Pending
                }
            }).await
        };
        let reason = match &stop {
            ScopedJoinStop::Cancelled(reason) => reason.clone(),
            ScopedJoinStop::NotAdmitted { .. } => CancelReason::fail_fast(),
            ScopedJoinStop::Completed => CancelReason::user("scoped join completed"),
        };
        owned.request_stop(reason);
        // These captures can own the last sender needed by admitted cleanup.
        drop(factories);

        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready()
                && observe_owner(self, &mut owner_cancellation)
            {
                owned.request_stop(owner_reason(self));
            }
            let mut all_done = true;
            for branch in &mut owned.branches {
                all_done &= branch.poll_result(task);
            }
            if all_done { Poll::Ready(()) } else { Poll::Pending }
        }).await;

        // Each watch captures only the region slot, not &Branch<T>. This keeps
        // the collecting future Send even when a retained T is not Sync.
        let mut closing: Vec<_> = owned.branches.iter().map(|branch| {
            Some(Box::pin(close_receipt(Arc::clone(&branch.region), Arc::clone(&gateway))))
        }).collect();
        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready()
                && observe_owner(self, &mut owner_cancellation)
            {
                owned.request_stop(owner_reason(self));
            }
            let mut all_done = true;
            for (branch, pending) in owned.branches.iter_mut().zip(&mut closing) {
                if let Some(close) = pending {
                    if let Poll::Ready((region, receipt)) = close.as_mut().poll(task) {
                        branch.receipt.region_id = region;
                        branch.receipt.close = receipt;
                        *pending = None;
                    } else {
                        all_done = false;
                    }
                }
            }
            if all_done { Poll::Ready(()) } else { Poll::Pending }
        }).await;
        observe_owner(self, &mut owner_cancellation);
        owned.armed = false;
        let attempts = std::mem::take(&mut owned.branches).into_iter()
            .map(|branch| branch.receipt).collect();
        Ok(ScopedJoinReport { stop, attempts, owner_cancellation })
    }

    /// Join two differently typed factories with [`Self::join_all_scoped`]'s
    /// all-settled, per-operation subtree cleanup contract.
    ///
    /// A failed or panicked left body does not cancel the right body, or vice
    /// versa. Owner cancellation and strict admission refusal still close both
    /// subtrees before drain. This uses the same collector as the dynamic join;
    /// the typed adapter does not create a coordinator task or another region.
    pub async fn join_scoped<L, R, FL, FR, FutL, FutR>(
        &self,
        left: FL,
        right: FR,
    ) -> Result<ScopedJoinPairReport<L, R>, ScopedJoinError>
    where
        FL: FnOnce(Cx<Caps>) -> FutL + Send + 'static,
        FR: FnOnce(Cx<Caps>) -> FutR + Send + 'static,
        FutL: Future<Output = L> + Send + 'static,
        FutR: Future<Output = R> + Send + 'static,
        L: Send + 'static,
        R: Send + 'static,
    {
        let factories: Vec<PairFactory<Caps, L, R>> = vec![
            Box::new(move |cx| Box::pin(async move { PairValue::Left(left(cx).await) })),
            Box::new(move |cx| Box::pin(async move { PairValue::Right(right(cx).await) })),
        ];
        let report = self.join_all_scoped(factories).await?;
        let mut attempts = report.attempts.into_iter();
        let left = map_attempt(attempts.next().expect("left input retained"), |value| match value {
            PairValue::Left(value) => value,
            PairValue::Right(_) => unreachable!("left factory returns only a left value"),
        });
        let right = map_attempt(attempts.next().expect("right input retained"), |value| match value {
            PairValue::Right(value) => value,
            PairValue::Left(_) => unreachable!("right factory returns only a right value"),
        });
        Ok(ScopedJoinPairReport {
            stop: report.stop,
            left,
            right,
            owner_cancellation: report.owner_cancellation,
        })
    }
}

enum PairValue<L, R> { Left(L), Right(R) }

type PairFactory<Caps, L, R> = Box<
    dyn FnOnce(Cx<Caps>) -> Pin<Box<dyn Future<Output = PairValue<L, R>> + Send>> + Send,
>;

fn map_attempt<T, U>(attempt: ScopedJoinAttempt<T>, f: impl FnOnce(T) -> U) -> ScopedJoinAttempt<U> {
    let task = match attempt.task {
        ScopedJoinTask::NotStarted => ScopedJoinTask::NotStarted,
        ScopedJoinTask::SubmissionFailed(error) => ScopedJoinTask::SubmissionFailed(error),
        ScopedJoinTask::Joined(result) => ScopedJoinTask::Joined(result.map(f)),
    };
    ScopedJoinAttempt {
        index: attempt.index, task, region_id: attempt.region_id, close: attempt.close,
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_join_inline_tests.rs"]
mod tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_join_native_tests.rs"]
mod native_tests;
