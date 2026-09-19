//! Execute membership-protected work in a real, independently closed child region.

use super::{OwnedLeaseStatus, OwnedMembershipController, OwnedMembershipError, OwnedMembershipLease};
use crate::cx::{ChildRegionError, ChildRegionSpec, Cx};
use crate::error::Error;
use crate::remote::NodeId;
use crate::runtime::{JoinError, SpawnError};
use crate::time::Sleep;
use crate::types::{CancelReason, Outcome, RegionId, Time};
use std::fmt;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

/// Why the owner stopped waiting for ordinary task completion.
#[derive(Debug)]
pub enum MembershipWorkTrigger {
    /// A body result, panic, cancellation, or spawn refusal was observed.
    TaskFinished,
    /// Membership, the lease deadline, or controller closure invalidated the work.
    LeaseEnded(OwnedLeaseStatus),
    /// The calling task was cancelled; the parent context is not modified here.
    ParentCancelled(CancelReason),
    /// Local clock/expiry validation failed. The child is still closed.
    ControlFailed(OwnedMembershipError),
}

/// A body result is separate from the reason the region was stopped.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MembershipWorkTaskError {
    /// The lease/owner ended before the factory could be invoked.
    #[error("membership work was not started")]
    NotStarted,
    /// The child's ordinary spawn gateway refused admission.
    #[error(transparent)]
    Spawn(#[from] SpawnError),
    /// Preserve the actual task cancellation or panic, even after revocation.
    #[error(transparent)]
    Join(#[from] JoinError),
    /// A close failure or inconsistent terminal channel prevented observation.
    #[error("membership work has no observable terminal task result")]
    MissingResult,
}

/// Refusal before a child region was obtained. The lease, if any, is aborted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MembershipWorkError {
    /// Membership or checked runtime-obligation admission failed.
    #[error(transparent)]
    Lease(#[from] OwnedMembershipError),
    /// Opening a real child region failed; no body factory was invoked.
    #[error(transparent)]
    Open(#[from] ChildRegionError),
}

/// Actual retained child-region close receipt, including finalizer failures.
#[derive(Debug)]
pub struct MembershipWorkClose {
    /// The newly allocated child, never the parent region.
    pub region_id: RegionId,
    /// Aggregate task/subtree outcome retained by the runtime.
    pub outcome: Outcome<(), Error>,
    /// Separate cleanup/finalizer outcome, when the runtime produced one.
    pub cleanup_outcome: Option<Outcome<(), Error>>,
}

/// All independent execution outcomes; `Ok(report)` alone is NOT workload success.
///
/// A body can return a useful cancellation/cleanup value after its lease ended.
/// Such a value is retained in `task` but must not be accepted as lease-authorized
/// success. Inspect [`Self::is_success`] and the application-specific value. A
/// close error is never converted into a quiescence receipt. Debug redacts `T`.
pub struct MembershipWorkReport<T> {
    /// Observed stop cause, rechecked after drain and during final lease release.
    pub trigger: MembershipWorkTrigger,
    /// Actual body value or task failure, independently of the stop cause.
    pub task: Result<T, MembershipWorkTaskError>,
    /// Success here means the child actually reached Closed, including cleanup.
    pub close: Result<MembershipWorkClose, ChildRegionError>,
    /// `Released` only after checked commit won. Other statuses mean local abort;
    /// they do not certify remote termination or immediate arena projection.
    pub lease: Result<OwnedLeaseStatus, OwnedMembershipError>,
}

impl<T> fmt::Debug for MembershipWorkReport<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MembershipWorkReport")
            .field("trigger", &self.trigger)
            .field("task_returned", &self.task.is_ok())
            .field("close", &self.close)
            .field("lease", &self.lease)
            .finish_non_exhaustive()
    }
}

impl<T> MembershipWorkReport<T> {
    /// True only for completed work, successful subtree/cleanup, and a winning
    /// lease commit. Does not interpret application errors encoded inside `T`.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.trigger, MembershipWorkTrigger::TaskFinished)
            && self.task.is_ok()
            && clean_close(&self.close)
            && matches!(self.lease, Ok(OwnedLeaseStatus::Released))
    }
}

fn clean_close(close: &Result<MembershipWorkClose, ChildRegionError>) -> bool {
    close.as_ref().is_ok_and(|receipt| {
        matches!(receipt.outcome, Outcome::Ok(()))
            && receipt.cleanup_outcome.as_ref().is_none_or(|outcome| matches!(outcome, Outcome::Ok(())))
    })
}

fn stop(
    owner: &OwnedMembershipController, cx: &Cx, lease: &OwnedMembershipLease, deadline: Time,
) -> Option<MembershipWorkTrigger> {
    if cx.is_cancel_requested() {
        return Some(MembershipWorkTrigger::ParentCancelled(
            cx.cancel_reason().unwrap_or_else(|| CancelReason::user("membership work owner cancelled")),
        ));
    }
    if owner.shared.clock.now() >= deadline {
        if let Err(error) = owner.expire() {
            return Some(MembershipWorkTrigger::ControlFailed(error));
        }
    }
    let status = lease.status();
    (status != OwnedLeaseStatus::Active).then_some(MembershipWorkTrigger::LeaseEnded(status))
}

impl OwnedMembershipController {
    /// Run one factory in a real child region while retaining its checked lease
    /// in the calling task. The finite lease starts BEFORE region admission.
    ///
    /// Revocation, supersession, expiry, controller close or caller cancellation
    /// stop waiting for normal completion and close ONLY the child subtree. Close
    /// cancels remaining work and awaits actual runtime quiescence/finalizers.
    /// A returned body value never bypasses that close or the final lease check.
    /// The body receives the child's admitted Cx; tasks spawned through it remain
    /// in that subtree. Factory and future panics use normal TaskHandle semantics.
    ///
    /// The runner drives its own fixed-duration expiry; a separate controller
    /// driver is not required. There is no automatic renewal, retry or spawn on
    /// the parent. The factory is checked again at its first task poll, but no
    /// cooperative API can preempt a concurrent synchronous factory/poll.
    ///
    /// `Ok(report)` means execution reached the reporting phase, not that every
    /// component succeeded. Use `report.is_success()` before accepting its value
    /// as authorized completion, and additionally check any application result.
    /// Body panics and cleanup failures remain visible even when revocation wins.
    /// A lease ending during drain prevents clean commit. Failure never rolls
    /// back already-performed effects or proves remote quiescence.
    ///
    /// Continue polling through shutdown to receive a close receipt. External
    /// drop/unwind requests region close via ChildRegion ownership and aborts the
    /// lease, but cannot synchronously await drain. The parent runtime retains
    /// that subtree. A stuck synchronous poll or blocking worker can delay drain;
    /// no universal wall-clock shutdown bound is promised.
    pub async fn run_scoped<T, F, Fut>(
        &self, cx: &Cx, node: &NodeId, incarnation: u64, duration: Duration,
        spec: ChildRegionSpec, factory: F,
    ) -> Result<MembershipWorkReport<T>, MembershipWorkError>
    where
        T: Send + 'static,
        F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        let lease = self.try_grant(cx, node, incarnation, duration)?;
        let deadline = {
            let state = self.shared.state.lock();
            state.entries.get(&lease.id).map(|entry| entry.deadline)
                .ok_or_else(|| OwnedMembershipError::Ended(lease.status()))?
        };
        let child = cx.open_child_region(spec).await?;
        let region_id = child.region_id();
        let mut trigger = stop(self, cx, &lease, deadline);
        let mut result = None;
        let mut handle = None;
        if trigger.is_none() {
            let signal = Arc::clone(&lease.signal);
            let clock = self.shared.clock.clone();
            match child.cx().spawn(move |body_cx| async move {
                // Admission can be delayed after the owner last checked. Never
                // invoke a user factory after observing a terminal lease here.
                if signal.status() != OwnedLeaseStatus::Active
                    || clock.now() >= deadline || body_cx.is_cancel_requested()
                { return Err(MembershipWorkTaskError::NotStarted); }
                Ok(factory(body_cx).await)
            }) {
                Ok(task) => handle = Some(task),
                Err(error) => {
                    result = Some(Err(MembershipWorkTaskError::Spawn(error)));
                    trigger = Some(MembershipWorkTrigger::TaskFinished);
                }
            }
        }
        if trigger.is_none() {
            let task = handle.as_mut().expect("admitted body");
            let mut ended = std::pin::pin!(lease.ended());
            let mut cancelled = std::pin::pin!(cx.cancelled());
            let mut sleep = std::pin::pin!(Sleep::with_timer_driver(deadline, self.shared.clock.clone()));
            let (cause, observed) = poll_fn(|poll_cx| {
                // Retirement/deadline wins a tie with an already-ready body.
                if let Some(cause) = stop(self, cx, &lease, deadline) {
                    return Poll::Ready((cause, None));
                }
                if cancelled.as_mut().poll(poll_cx).is_ready()
                    || ended.as_mut().poll(poll_cx).is_ready()
                    || sleep.as_mut().poll(poll_cx).is_ready()
                {
                    if let Some(cause) = stop(self, cx, &lease, deadline) {
                        return Poll::Ready((cause, None));
                    }
                }
                task.poll_join(poll_cx).map(|terminal| {
                    (MembershipWorkTrigger::TaskFinished, Some(terminal.map_err(MembershipWorkTaskError::Join).and_then(|value| value)))
                })
            }).await;
            trigger = Some(cause);
            result = observed;
        }
        // Close owns cancellation, descendant drain and finalization on every
        // path after opening, including spawn refusal and a returned body value.
        let close = child.close_with_outcome().await.map(|receipt| MembershipWorkClose {
            region_id, outcome: receipt.outcome, cleanup_outcome: receipt.cleanup_outcome,
        });
        if result.is_none() {
            result = Some(match handle.as_mut().map(|task| task.try_join()) {
                Some(Ok(Some(value))) => value,
                Some(Err(error)) => Err(MembershipWorkTaskError::Join(error)),
                Some(Ok(None)) => Err(MembershipWorkTaskError::MissingResult),
                None => Err(MembershipWorkTaskError::NotStarted),
            });
        }
        // Preserve the first stop cause. If completion won initially, a later
        // lease or caller failure during drain still prevents authorized success.
        if matches!(trigger, Some(MembershipWorkTrigger::TaskFinished)) {
            if let Some(cause) = stop(self, cx, &lease, deadline) { trigger = Some(cause); }
        }
        let mut trigger = trigger.expect("terminal cause");
        let task = result.expect("body observation");
        let signal = Arc::clone(&lease.signal);
        let settlement = if matches!(trigger, MembershipWorkTrigger::TaskFinished)
            && task.is_ok() && clean_close(&close)
        {
            match lease.release() {
                Ok(()) => Ok(OwnedLeaseStatus::Released),
                Err(error) => {
                    let status = signal.status();
                    if status != OwnedLeaseStatus::Active && status != OwnedLeaseStatus::Released {
                        trigger = MembershipWorkTrigger::LeaseEnded(status);
                    }
                    Err(error)
                }
            }
        } else {
            drop(lease);
            Ok(signal.status())
        };
        drop(handle);
        Ok(MembershipWorkReport { trigger, task, close, lease: settlement })
    }
}

use std::sync::Arc;

#[cfg(test)]
mod tests;
