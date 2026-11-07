//! A deadline for useful work with an owned, fully drained operation subtree.

use super::child_region::RegionQuiescence;
use super::{ChildRegionError, Cx, cap};
use crate::record::task::TaskOutcome;
use crate::runtime::spawn_mailbox::BranchRegionSlot;
use crate::runtime::state::SpawnError;
use crate::runtime::{JoinError, TaskHandle};
use crate::time::Sleep;
use crate::types::{CancelReason, PanicPayload, RegionId, Time};
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

/// Why a scoped timeout stopped accepting useful work.
///
/// This fact is independent of the task's eventual result and the region's
/// cleanup result. An operation may acknowledge cancellation and return a
/// useful value during the drain without erasing `TimedOut` or `Cancelled`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ScopedTimeoutStop {
    /// The operation's terminal join was observed before a stop request.
    /// The task may have returned a value, failed, or panicked.
    TaskFinished,
    /// The explicit owner's timer reached the deadline first.
    TimedOut,
    /// The explicit owner requested cancellation. The complete reason is kept.
    Cancelled(CancelReason),
    /// Admission was unavailable or revoked before the user factory ran.
    /// A private region may already exist, so inspect its close receipt too.
    /// The task receipt can also contain an admission failure.
    NotAdmitted,
}

/// What the operation task actually returned after it finished draining.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedTimeoutTask<T> {
    /// The user factory was refused before invocation.
    NotStarted,
    /// The ordinary task join result, including acknowledged late values.
    /// A join error can also describe cancellation before the factory started.
    Joined(Result<T, JoinError>),
}

/// The runtime's actual close result after the private subtree is quiescent.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ScopedTimeoutClose {
    /// Runtime task/region outcome, including ordinary close cancellation.
    pub outcome: TaskOutcome,
    /// Finalizer/cleanup failure, retained independently of the body result.
    pub cleanup_outcome: Option<TaskOutcome>,
    /// This region's panic or the first panic propagated by a descendant.
    pub descendant_panic: Option<PanicPayload>,
}

/// Independent stop, task, and whole-region cleanup receipts.
#[derive(Debug)]
#[non_exhaustive]
pub struct ScopedTimeoutReport<T> {
    /// The condition that stopped useful execution.
    pub stop: ScopedTimeoutStop,
    /// The operation's actual task result, without replacing the stop reason.
    pub task: ScopedTimeoutTask<T>,
    /// The private region, when admission minted one.
    pub region_id: Option<RegionId>,
    /// The actual region close receipt, including descendant and finalizer
    /// failures. `None` means no private region was published. An error does
    /// not certify quiescence, even if the operation task returned a value.
    pub close: Option<Result<ScopedTimeoutClose, ChildRegionError>>,
    /// Absolute deadline in the explicit owner's timer domain.
    pub deadline: Time,
}

/// Refusal before an operation can be submitted to its owning runtime.
#[derive(Debug)]
#[non_exhaustive]
pub enum ScopedTimeoutError {
    /// The explicit context has no authorized timer driver.
    TimerUnavailable,
    /// The context or runtime refused task submission.
    Spawn(SpawnError),
}

impl std::fmt::Display for ScopedTimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimerUnavailable => {
                f.write_str("scoped timeout requires time capability and a timer driver")
            }
            Self::Spawn(error) => write!(f, "scoped timeout admission failed: {error}"),
        }
    }
}

impl std::error::Error for ScopedTimeoutError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            Self::TimerUnavailable => None,
        }
    }
}

enum BodyResult<T> {
    Value(T),
    NotStarted(ScopedTimeoutStop),
}

/// Exists before enqueue, including before a notifier can unwind. A later
/// admission publication inherits a close request even if the task handle has
/// not yet been returned to this owner.
struct OwnedOperation<T> {
    region: Arc<BranchRegionSlot>,
    handle: Option<TaskHandle<BodyResult<T>>>,
    armed: bool,
}

impl<T> OwnedOperation<T> {
    fn request_stop(&self, reason: CancelReason) {
        // Cancel the entire region before joining/aborting the direct task:
        // its cleanup may itself be waiting for a descendant's cancellation.
        let _ = self.region.request_close(reason.clone());
        if let Some(handle) = &self.handle
            && !handle.terminal_published()
        {
            handle.abort_with_reason(reason);
        }
    }
}

impl<T> Drop for OwnedOperation<T> {
    fn drop(&mut self) {
        if self.armed {
            self.request_stop(CancelReason::user("scoped timeout dropped"));
        }
    }
}

fn owner_cancel_reason<Caps>(owner: &Cx<Caps>) -> CancelReason {
    owner
        .cancel_reason()
        .unwrap_or_else(|| CancelReason::user("scoped timeout owner cancelled"))
}

fn not_started<T>(stop: ScopedTimeoutStop, deadline: Time) -> ScopedTimeoutReport<T> {
    ScopedTimeoutReport {
        stop,
        task: ScopedTimeoutTask::NotStarted,
        region_id: None,
        close: None,
        deadline,
    }
}

impl<Caps> Cx<Caps>
where
    Caps: cap::HasSpawn + cap::HasTime + Send + Sync + 'static,
{
    /// Runs one operation in a private region, then cancels and drains its
    /// entire subtree before returning.
    ///
    /// The duration starts on the first poll and saturates at [`Time::MAX`].
    /// It bounds useful execution, **not total cleanup time**. A timeout,
    /// owner cancellation, or direct task completion requests close for the
    /// whole region, then waits for the operation, all descendants, pending
    /// admissions, obligations, and finalizers. Cooperative cleanup can take
    /// longer than the duration. It is never replaced by forced destruction.
    ///
    /// The factory receives the actual admitted context. Work spawned through
    /// it belongs to the private subtree. Unlike ordinary race winners, a
    /// retained context from this subtree (including a nested race winner)
    /// cannot place new work outside the owned timeout subtree. A nested race
    /// inside an ordinary child region may still fall back within that child.
    /// Explicitly captured authority for an unrelated region remains unrelated
    /// authority; callers must use the supplied context for owned work.
    ///
    /// Cancellation observation is mask-agnostic, like [`Cx::cancelled`].
    /// It initiates child cleanup without acknowledging the owner's request or
    /// changing its mask. Cancellation wins a simultaneous deadline or task
    /// completion. During cleanup neither cancellation nor the elapsed timer
    /// can short-circuit the drain. The ordinary task policy still preserves
    /// values returned after that task acknowledges cancellation; inspect
    /// `stop`, `task`, and `close` independently.
    ///
    /// Only this context's authorized timer and runtime are used. Missing or
    /// denied time authority fails before submission or factory invocation.
    /// A zero duration or an already-cancelled owner starts no operation.
    /// Private admission retains strict spawn authorization and refuses user
    /// work when a distinct region cannot be minted (for example, when parent
    /// admission limits require work to stay in the parent).
    ///
    /// Dropping the future requests subtree close, including a close handed
    /// to admission that has not yet published its region. The runtime keeps
    /// owning the work; drop itself cannot wait for asynchronous cleanup.
    /// Returned values must not retain obligations whose release is required
    /// to close the operation region.
    ///
    /// # Errors
    ///
    /// Returns [`ScopedTimeoutError`] for timer or submission refusal. Later
    /// admission failures and cleanup failures remain separate report facts;
    /// a task value by itself does not certify successful region cleanup.
    ///
    /// ```
    /// use asupersync::Cx;
    /// use asupersync::cx::{ScopedTimeoutStop, ScopedTimeoutTask};
    /// use std::time::Duration;
    ///
    /// async fn example(cx: &Cx) {
    ///     let report = cx.timeout_scoped(Duration::from_secs(1), |body_cx| async move {
    ///         let mut child = body_cx.spawn(|_| async { 42_u32 }).expect("child admission");
    ///         child.join(&body_cx).await
    ///     }).await.expect("timeout admission");
    ///     assert!(matches!(report.stop, ScopedTimeoutStop::TaskFinished));
    ///     assert!(matches!(report.task, ScopedTimeoutTask::Joined(Ok(Ok(42)))));
    ///     assert!(report.close.expect("owned region").is_ok());
    /// }
    /// ```
    pub async fn timeout_scoped<T, F, Fut>(
        &self,
        duration: Duration,
        operation: F,
    ) -> Result<ScopedTimeoutReport<T>, ScopedTimeoutError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Capability preflight comes before region reservations or user code.
        let driver = self.timer_driver().ok_or(ScopedTimeoutError::TimerUnavailable)?;
        let gateway = self
            .spawn_gateway_handle()
            .ok_or(ScopedTimeoutError::Spawn(SpawnError::RuntimeUnavailable))?;
        let deadline = driver.now() + duration;
        if self.is_cancel_requested() {
            return Ok(not_started(
                ScopedTimeoutStop::Cancelled(owner_cancel_reason(self)),
                deadline,
            ));
        }
        if driver.now() >= deadline {
            return Ok(not_started(ScopedTimeoutStop::TimedOut, deadline));
        }

        let region = Arc::new(BranchRegionSlot::owned(&gateway));
        let mut owned = OwnedOperation {
            region: Arc::clone(&region),
            handle: None,
            armed: true,
        };
        let factory_region = Arc::clone(&region);
        let factory_owner = self.clone();
        let factory_driver = driver.clone();
        owned.handle = Some(
            self.spawn_owned_branch(Arc::clone(&region), move |body_cx| async move {
                // Existing races may fall back to the requested parent when a
                // sealed mint is refused. This owner never invokes user code
                // on that fallback path.
                if factory_region.get().is_none() {
                    return BodyResult::NotStarted(ScopedTimeoutStop::NotAdmitted);
                }
                if factory_owner.is_cancel_requested() {
                    return BodyResult::NotStarted(ScopedTimeoutStop::Cancelled(
                        owner_cancel_reason(&factory_owner),
                    ));
                }
                if factory_driver.now() >= deadline {
                    return BodyResult::NotStarted(ScopedTimeoutStop::TimedOut);
                }
                if factory_region.close_requested() || body_cx.is_cancel_requested() {
                    return BodyResult::NotStarted(ScopedTimeoutStop::NotAdmitted);
                }
                BodyResult::Value(operation(body_cx).await)
            })
            .map_err(ScopedTimeoutError::Spawn)?,
        );

        let (mut stop, mut result) = {
            // These registrations end before the unconditional cleanup phase.
            let mut cancelled = std::pin::pin!(self.cancelled());
            let mut timer = std::pin::pin!(Sleep::with_timer_driver(deadline, driver.clone()));
            poll_fn(|task| {
                if cancelled.as_mut().poll(task).is_ready() {
                    return Poll::Ready((
                        ScopedTimeoutStop::Cancelled(owner_cancel_reason(self)),
                        None,
                    ));
                }
                if driver.now() >= deadline {
                    return Poll::Ready((ScopedTimeoutStop::TimedOut, None));
                }
                if let Poll::Ready(result) = owned
                    .handle
                    .as_mut()
                    .expect("operation submitted")
                    .poll_join(task)
                {
                    return Poll::Ready((ScopedTimeoutStop::TaskFinished, Some(result)));
                }
                if timer.as_mut().poll_deadline(task).is_ready() {
                    // A coalesced timer wake can precede its exact deadline.
                    // Re-arm on a later poll, without looping inside this poll.
                    timer.as_mut().get_mut().reset(deadline);
                    task.waker().wake_by_ref();
                }
                Poll::Pending
            })
            .await
        };

        let reason = match &stop {
            ScopedTimeoutStop::TimedOut => CancelReason::timeout(),
            ScopedTimeoutStop::Cancelled(reason) => reason.clone(),
            ScopedTimeoutStop::TaskFinished | ScopedTimeoutStop::NotAdmitted => {
                CancelReason::user("scoped timeout operation completed")
            }
        };
        owned.request_stop(reason);

        // The whole-region request above precedes this join. A body waiting
        // on its own child can therefore finish once that child drains.
        if result.is_none() {
            result = Some(
                poll_fn(|task| owned.handle.as_mut().expect("operation submitted").poll_join(task))
                    .await,
            );
        }
        let task = match result.expect("operation joined") {
            Ok(BodyResult::Value(value)) => ScopedTimeoutTask::Joined(Ok(value)),
            Ok(BodyResult::NotStarted(refusal)) => {
                if matches!(stop, ScopedTimeoutStop::TaskFinished) {
                    stop = refusal;
                }
                ScopedTimeoutTask::NotStarted
            }
            Err(error) => ScopedTimeoutTask::Joined(Err(error)),
        };
        let (region_id, close) = if let Some(minted) = region.get() {
            let closed = RegionQuiescence::watch(minted.close_notify(), Some(gateway)).await;
            let outcome = closed.and_then(|()| {
                minted
                    .close_outcome()
                    .map(|receipt| ScopedTimeoutClose {
                        outcome: receipt.outcome,
                        cleanup_outcome: receipt.cleanup_outcome,
                        descendant_panic: receipt.descendant_panic,
                    })
                    .ok_or(ChildRegionError::RuntimeUnavailable)
            });
            (Some(minted.region_id), Some(outcome))
        } else {
            if matches!(stop, ScopedTimeoutStop::TaskFinished) {
                stop = ScopedTimeoutStop::NotAdmitted;
            }
            (None, None)
        };
        owned.armed = false;
        Ok(ScopedTimeoutReport { stop, task, region_id, close, deadline })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "scoped_timeout_inline_tests.rs"]
mod tests;
