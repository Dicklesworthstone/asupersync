//! Checked, child-region ownership for one ordinary `RemoteRuntime` invocation.
//!
//! This additive entry point uses the existing `spawn_remote` / `RemoteHandle`
//! protocol. It does not replace a runtime, invent a result on transport loss,
//! or change V1-V3 messages. The remote proxy lives in an actual child task; its
//! checked lease is retained until that proxy has collected the terminal result
//! (or the existing runtime has reported failure) and destroyed its handle.

use crate::cx::{ChildRegionError, ChildRegionSpec, Cx};
use crate::error::Error;
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::remote::{
    ComputationName, NodeId, RemoteError, RemoteHandle, RemoteInput, RemoteOutcome,
    RemoteTaskId, spawn_remote,
};
use crate::runtime::obligation_mailbox::{ObligationAdmissionError, ObligationToken};
use crate::runtime::{JoinError, SpawnError};
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::{CancelReason, Outcome, RegionId, Time};
use std::fmt;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

/// Explicit admission-to-cancellation budget and child-region constraints.
/// There is deliberately no unbounded/default policy.
#[derive(Debug, Clone)]
pub struct RemoteRunConfig {
    /// Starts before child-region admission. This initiates cancellation, not
    /// a deadline for remote termination or local uninterruptible drain.
    pub timeout: Duration,
    /// Existing region budgets/capability attenuation; never relaxed here.
    pub child: ChildRegionSpec,
}

/// Refusal before the child region was obtained. No remote dispatch occurred.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteRunError {
    /// An absent remote capability never acquires ambient network authority.
    #[error("owned remote work requires a remote capability")]
    NoCapability,
    /// Unlike the legacy API, this path never runs a simulated remote fallback.
    #[error("owned remote work requires an attached remote runtime")]
    NoRemoteRuntime,
    /// No explicit timer was attached to the calling context.
    #[error("owned remote work requires a context timer driver")]
    NoTimer,
    /// Zero timeout or a saturated clock leaves no usable execution interval.
    #[error("owned remote work requires a positive remaining clock interval")]
    Timeout,
    /// The caller was already cancelled before admission.
    #[error("owned remote work caller is cancelled")]
    Cancelled,
    /// Existing region admission failed.
    #[error(transparent)]
    Open(#[from] ChildRegionError),
}

/// Failure in the local proxy, independently of remote protocol outcomes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteRunTaskError {
    /// Cancellation or deadline was observed before invoking `spawn_remote`.
    #[error("owned remote work was not dispatched")]
    NotStarted,
    /// The admitted child does not retain the required remote capability/runtime.
    #[error("owned remote child has no attached remote capability")]
    NoRemoteRuntime,
    /// Untracked contexts cannot silently create a successful proxy.
    #[error("owned remote child has no checked obligation gateway")]
    NoObligationRuntime,
    /// Checked region/holder/quota admission refused before remote registration.
    #[error(transparent)]
    Admission(#[from] ObligationAdmissionError),
    /// Synchronous remote registration/dispatch failed.
    #[error(transparent)]
    Dispatch(#[from] RemoteError),
    /// The local child-task spawn gateway refused.
    #[error(transparent)]
    Spawn(#[from] SpawnError),
    /// Preserve the actual proxy-task panic or cancellation.
    #[error(transparent)]
    Join(#[from] JoinError),
    /// No terminal task result was available after a failed/inconsistent close.
    #[error("owned remote proxy has no observable terminal result")]
    MissingResult,
}

/// Local observation which initiated final child-region close.
#[derive(Debug, Clone)]
pub enum RemoteRunTrigger {
    /// The proxy produced a result, error, or panic.
    Finished,
    /// The explicit invocation deadline was reached.
    Deadline,
    /// The caller requested cancellation. This API does not modify its parent.
    Cancelled(CancelReason),
}

/// Outcome of choosing a terminal on the checked local lease token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteLeaseSettlement {
    /// A remote Success was collected while the proxy was not cancelled.
    Committed,
    /// Failure, cancellation, or a non-success remote outcome chose local abort.
    Aborted,
    /// Runtime retirement/holder completion already won the token's terminal.
    Lost,
}

/// Actual protocol result plus local cancellation and accounting facts.
/// Debug never exposes result bytes or remote diagnostic strings.
pub struct RemoteRunReply {
    /// Original ID allocated by `spawn_remote`; never derived from an arena ID.
    pub remote_task_id: RemoteTaskId,
    /// Exact result returned by the existing join/close implementation.
    /// A closed channel, transport failure, or lease expiry is NOT remote success.
    pub outcome: Outcome<RemoteOutcome, RemoteError>,
    /// Cancellation observed by the proxy, including while collecting a result.
    pub cancellation: Option<CancelReason>,
    /// Local checked settlement, not proof of remote-work quiescence.
    pub settlement: RemoteLeaseSettlement,
}

impl fmt::Debug for RemoteRunReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteRunReply")
            .field("remote_task_id", &self.remote_task_id)
            .field("remote_success", &matches!(self.outcome, Outcome::Ok(RemoteOutcome::Success(_))))
            .field("cancelled", &self.cancellation.is_some())
            .field("settlement", &self.settlement)
            .finish_non_exhaustive()
    }
}

/// Actual retained close receipt for the local invocation subtree.
#[derive(Debug)]
pub struct RemoteRunClose {
    /// Independent child region, not the calling region.
    pub region_id: RegionId,
    /// Runtime aggregate task/subtree outcome.
    pub outcome: Outcome<(), Error>,
    /// Retained finalizer/cleanup outcome, if any.
    pub cleanup_outcome: Option<Outcome<(), Error>>,
}

/// Keep local execution, cancellation, and quiescence separate from remote success.
/// `Ok(report)` means reporting was reached, not that the remote operation succeeded.
pub struct RemoteRunReport {
    /// Why the owner started closing its child region.
    pub trigger: RemoteRunTrigger,
    /// Result of the actual runtime-owned proxy task.
    pub task: Result<RemoteRunReply, RemoteRunTaskError>,
    /// Child close is always attempted, including after task-spawn refusal.
    pub close: Result<RemoteRunClose, ChildRegionError>,
    /// A failed explicit cancellation enqueue is retained, never ignored.
    pub cancel_error: Option<ChildRegionError>,
}

impl fmt::Debug for RemoteRunReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteRunReport")
            .field("trigger", &self.trigger)
            .field("proxy_returned", &self.task.is_ok())
            .field("child_closed", &self.close.is_ok())
            .field("cancel_enqueue_failed", &self.cancel_error.is_some())
            .finish_non_exhaustive()
    }
}

impl RemoteRunReport {
    /// Success requires a timely remote Success, a winning checked commit,
    /// and successful local subtree/finalizer close. Application payloads are opaque.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.trigger, RemoteRunTrigger::Finished)
            && self.cancel_error.is_none()
            && self.task.as_ref().is_ok_and(|reply| {
                reply.cancellation.is_none()
                    && reply.settlement == RemoteLeaseSettlement::Committed
                    && matches!(reply.outcome, Outcome::Ok(RemoteOutcome::Success(_)))
            })
            && self.close.as_ref().is_ok_and(|close| {
                matches!(close.outcome, Outcome::Ok(()))
                    && close.cleanup_outcome.as_ref().is_none_or(|value| matches!(value, Outcome::Ok(())))
            })
    }
}

// Drop ordering is intentional: the remote handle requests cancellation before
// the fallback checked abort. Every ordinary error/unwind owns both backstops.
struct CheckedLease(Option<ObligationToken>);
impl CheckedLease {
    fn settle(mut self, success: bool) -> RemoteLeaseSettlement {
        let token = self.0.take().expect("unsettled checked lease");
        let accepted = if success { token.commit() } else { token.abort(ObligationAbortReason::Cancel) };
        if !accepted { RemoteLeaseSettlement::Lost }
        else if success { RemoteLeaseSettlement::Committed }
        else { RemoteLeaseSettlement::Aborted }
    }
}
impl Drop for CheckedLease {
    fn drop(&mut self) {
        if let Some(token) = self.0.take() { token.abort(ObligationAbortReason::Cancel); }
    }
}
struct Exchange { remote: RemoteHandle, lease: CheckedLease }

// Field drop order retires the complete proxy future (including remote handle
// and checked token) before its share of outbound admission. The calling scope
// independently retains the other share through child-region close.
#[pin_project::pin_project]
struct AdmittedProxy<F> {
    #[pin]
    future: F,
    _admission: Option<admission::Permit>,
}

impl<F: Future> Future for AdmittedProxy<F> {
    type Output = F::Output;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.project().future.poll(cx)
    }
}

async fn execute(
    cx: Cx, node: NodeId, computation: ComputationName, input: RemoteInput,
    clock: TimerDriverHandle, deadline: Time,
) -> Result<RemoteRunReply, RemoteRunTaskError> {
    if cx.checkpoint().is_err() || clock.now() >= deadline { return Err(RemoteRunTaskError::NotStarted); }
    if cx.remote().is_none_or(|cap| cap.runtime().is_none()) { return Err(RemoteRunTaskError::NoRemoteRuntime); }
    let lease = CheckedLease(Some(cx.try_register_obligation_checked(ObligationKind::Lease, cx.task_id())?
        .ok_or(RemoteRunTaskError::NoObligationRuntime)?));
    // Runtime admission can invoke a notifier. Recheck before its side effects.
    if cx.checkpoint().is_err() || clock.now() >= deadline { return Err(RemoteRunTaskError::NotStarted); }
    let mut exchange = Exchange { remote: spawn_remote(&cx, node, computation, input)?, lease };
    let remote_task_id = exchange.remote.remote_task_id();
    let mut outcome = exchange.remote.join(&cx).await;
    if matches!(outcome, Outcome::Err(RemoteError::Cancelled(_))) {
        // is_finished() means buffered OR consumed, so it cannot distinguish
        // cancellation winning recv from a genuine consumed Cancelled result.
        // Probe consumption explicitly before deciding whether close is needed.
        match exchange.remote.try_join() {
            Ok(Some(reply)) => outcome = Outcome::Ok(reply),
            Ok(None) => outcome = exchange.remote.close(&cx).await,
            Err(RemoteError::PolledAfterCompletion) => {} // Preserve consumed result.
            Err(error) => outcome = Outcome::Err(error),
        }
    }
    let cancellation = cx.is_cancel_requested().then(|| {
        cx.cancel_reason().unwrap_or_else(CancelReason::parent_cancelled)
    });
    // Freeze outcome before destroying the proxy. Settlement cannot precede its
    // unregister/cancel callbacks, including their panic boundary.
    drop(exchange.remote);
    let success = cancellation.is_none() && matches!(outcome, Outcome::Ok(RemoteOutcome::Success(_)));
    let settlement = exchange.lease.settle(success);
    // Preserve a typed cleanup report through ordinary Cx spawn's acknowledged-
    // cancellation policy. Outer combinators retain their own cancellation rules.
    let _ = cx.checkpoint();
    Ok(RemoteRunReply { remote_task_id, outcome, cancellation, settlement })
}

fn stopped(cx: &Cx, clock: &TimerDriverHandle, deadline: Time) -> Option<RemoteRunTrigger> {
    if cx.is_cancel_requested() {
        Some(RemoteRunTrigger::Cancelled(cx.cancel_reason().unwrap_or_else(CancelReason::parent_cancelled)))
    } else if clock.now() >= deadline { Some(RemoteRunTrigger::Deadline) } else { None }
}

/// Execute one named remote invocation through its existing capability/runtime,
/// with checked ownership, cancellation forwarding and local child-region drain.
///
/// The checked Lease is registered by the admitted proxy task BEFORE any remote
/// registration or send. No task/obligation identity is forged and no runtime or
/// route is acquired implicitly. Old `spawn_remote` signatures/semantics stay intact.
///
/// Timeout or caller cancellation cancels ONLY this invocation's child region.
/// Its proxy continues through `RemoteHandle::close`, retaining the lease until
/// the existing runtime classifies terminal collection. A custom RemoteRuntime
/// that never publishes a terminal can therefore delay drain indefinitely. The
/// configured timeout initiates cancellation; it never manufactures remote
/// quiescence, kills a remote process, or hides ambiguous transport failure.
/// Region opening itself requires scheduler progress and is not preempted here.
///
/// Continue polling through close for its receipt. Dropping this future requests
/// child close; the parent runtime retains the task and its checked obligation.
/// Runtime shutdown/cleanup budgets and pathological synchronous callbacks can
/// still prevent graceful completion. No cleanup is spawned outside the region.
///
/// `report.is_success()` must pass before accepting the result as successful.
/// Remote business failures/panics remain in the exact protocol outcome; local
/// panics and close failures remain separate. No retry or wire change is added.
pub async fn run_remote(
    cx: &Cx, node: NodeId, computation: ComputationName, input: RemoteInput,
    config: RemoteRunConfig,
) -> Result<RemoteRunReport, RemoteRunError> {
    run_admitted(cx, node, computation, input, config, None).await
}

async fn run_admitted(
    cx: &Cx, node: NodeId, computation: ComputationName, input: RemoteInput,
    config: RemoteRunConfig, admission: Option<admission::Permit>,
) -> Result<RemoteRunReport, RemoteRunError> {
    if cx.is_cancel_requested() { return Err(RemoteRunError::Cancelled); }
    let cap = cx.remote().ok_or(RemoteRunError::NoCapability)?;
    if cap.runtime().is_none() { return Err(RemoteRunError::NoRemoteRuntime); }
    let clock = cx.timer_driver().ok_or(RemoteRunError::NoTimer)?;
    let now = clock.now();
    let deadline = now + config.timeout;
    if config.timeout.is_zero() || deadline <= now { return Err(RemoteRunError::Timeout); }
    let child = cx.open_child_region(config.child).await?;
    let region_id = child.region_id();
    let mut handle = None;
    let mut result = None;
    let mut trigger = stopped(cx, &clock, deadline);
    if trigger.is_none() {
        let timer = clock.clone();
        let proxy_admission = admission.clone();
        match child.cx().spawn(move |task| AdmittedProxy {
            future: execute(task, node, computation, input, timer, deadline),
            _admission: proxy_admission,
        }) {
            Ok(task) => handle = Some(task),
            Err(error) => {
                result = Some(Err(RemoteRunTaskError::Spawn(error)));
                trigger = Some(RemoteRunTrigger::Finished);
            }
        }
    } else { result = Some(Err(RemoteRunTaskError::NotStarted)); }
    if trigger.is_none() {
        let mut cancelled = std::pin::pin!(cx.cancelled());
        let mut timer = std::pin::pin!(Sleep::with_timer_driver(deadline, clock.clone()));
        trigger = Some(poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready() {
                return Poll::Ready(RemoteRunTrigger::Cancelled(
                    cx.cancel_reason().unwrap_or_else(CancelReason::parent_cancelled)));
            }
            if clock.now() >= deadline || timer.as_mut().poll(task).is_ready() {
                return Poll::Ready(RemoteRunTrigger::Deadline);
            }
            if let Poll::Ready(value) = handle.as_mut().expect("admitted proxy").poll_join(task) {
                result = Some(value.map_err(RemoteRunTaskError::Join).and_then(|value| value));
                return Poll::Ready(RemoteRunTrigger::Finished);
            }
            Poll::Pending
        }).await);
    }
    let mut trigger = trigger.expect("selected stop cause");
    let cancel_error = match &trigger {
        RemoteRunTrigger::Finished => None,
        RemoteRunTrigger::Deadline => child.cancel(CancelReason::timeout()).err(),
        RemoteRunTrigger::Cancelled(reason) => child.cancel(reason.clone()).err(),
    };
    let close = child.close_with_outcome().await.map(|receipt| RemoteRunClose {
        region_id, outcome: receipt.outcome, cleanup_outcome: receipt.cleanup_outcome,
    });
    if result.is_none() {
        result = Some(match handle.as_mut().expect("retained proxy").try_join() {
            Ok(Some(value)) => value,
            Err(error) => Err(RemoteRunTaskError::Join(error)),
            Ok(None) => Err(RemoteRunTaskError::MissingResult),
        });
    }
    // A result already collected must not bypass a caller deadline/cancellation
    // that became visible while local descendants/finalizers were draining.
    if matches!(trigger, RemoteRunTrigger::Finished) {
        if let Some(stop) = stopped(cx, &clock, deadline) { trigger = stop; }
    }
    let report = RemoteRunReport { trigger, task: result.expect("terminal classification"), close, cancel_error };
    drop(admission);
    Ok(report)
}

mod admission;
pub use admission::{
    RemoteAdmissionError, RemoteAdmissionLimits, RemoteAdmissionUsage, RemoteExecutor,
    RemoteExecutorError, RemotePeerLimits,
};

#[cfg(test)]
mod tests;
