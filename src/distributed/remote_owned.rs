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
use crate::runtime::{JoinError, SpawnError, TaskHandle};
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::{CancelReason, Outcome, RegionId, TaskId, Time};
use std::fmt;
use std::future::{Future, poll_fn};
use std::task::{Context, Poll};
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

/// Admission or observation failure for a spawned owned remote invocation.
/// Remote protocol outcomes remain inside [`RemoteRunReport`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteRunHandleError {
    /// The invocation could not obtain its required authority or child region.
    #[error(transparent)]
    Run(#[from] RemoteRunError),
    /// The owner task could not be submitted to the calling region.
    #[error(transparent)]
    Spawn(#[from] SpawnError),
    /// The owner task panicked, was refused or cancelled before starting, or
    /// its terminal report was already consumed.
    #[error(transparent)]
    Join(#[from] JoinError),
}

/// A remotely executing invocation whose local owner runs independently of
/// result polling and remains part of the caller's region.
///
/// The owner drives the same checked lease, protocol cancellation, and child
/// close as [`run_remote`]. Dropping this handle requests cancellation; the
/// runtime retains the owner until that cleanup finishes. Dropping only a
/// [`join`](Self::join) future leaves the invocation running and permits a later
/// join. Neither operation creates detached cleanup work.
///
/// [`abort`](Self::abort) and the invocation deadline initiate cancellation.
/// They do not prove remote quiescence. The native remote runtime bounds silent
/// peers by its lease and drain policy; a custom [`crate::remote::RemoteRuntime`]
/// must supply its own eventual terminal result or drain can remain pending.
#[must_use = "dropping the owned remote handle requests cancellation"]
pub struct RemoteRunHandle {
    task: TaskHandle<Result<RemoteRunReport, RemoteRunError>>,
    deadline: Time,
}

impl fmt::Debug for RemoteRunHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteRunHandle")
            .field("local_task_id", &self.task.task_id())
            .field("deadline", &self.deadline)
            .field("finished", &self.task.is_finished())
            .finish_non_exhaustive()
    }
}

impl RemoteRunHandle {
    /// Returns the local owner task, which retains the invocation's child
    /// region until its close receipt has been collected. Before admission the
    /// ID is provisional, just as for [`TaskHandle::task_id`].
    #[must_use]
    pub fn local_task_id(&self) -> TaskId {
        self.task.task_id()
    }

    /// Returns the cancellation deadline captured when the invocation was
    /// submitted, before local task admission or any result polling.
    #[must_use]
    pub fn deadline(&self) -> Time {
        self.deadline
    }

    /// Whether the owner has retired and its terminal report can be observed.
    /// A failed admission is also terminal; inspect the join result for success.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Requests cancellation of this invocation without waiting for cleanup.
    /// Join or close it to obtain the actual terminal and child-close report.
    pub fn abort(&self) {
        self.abort_with_reason(CancelReason::user("owned remote handle abort"));
    }

    /// Requests cancellation with the supplied attribution. Repeated requests
    /// follow the runtime's ordinary reason-strengthening rules.
    pub fn abort_with_reason(&self, reason: CancelReason) {
        if !self.task.terminal_published() {
            self.task.abort_with_reason(reason);
        }
    }

    /// Observes the owner without consuming a pending result or changing its
    /// cancellation state.
    ///
    /// # Errors
    /// Returns the exact owner admission, invocation, or join failure. Repeated
    /// observation after consuming a terminal returns
    /// [`JoinError::PolledAfterCompletion`].
    pub fn try_join(&mut self) -> Result<Option<RemoteRunReport>, RemoteRunHandleError> {
        match self.task.try_join()? {
            Some(report) => report.map(Some).map_err(RemoteRunHandleError::Run),
            None => Ok(None),
        }
    }

    /// Polls the owner report without cancelling if the caller stops polling.
    /// The wake registration stays on this handle until terminal observation
    /// or handle drop, as with [`TaskHandle::poll_join`].
    ///
    /// # Errors
    /// Returns the same errors as [`try_join`](Self::try_join).
    pub fn poll_join(
        &mut self,
        task: &mut Context<'_>,
    ) -> Poll<Result<RemoteRunReport, RemoteRunHandleError>> {
        self.task.poll_join(task).map(|result| {
            result
                .map_err(RemoteRunHandleError::Join)
                .and_then(|report| report.map_err(RemoteRunHandleError::Run))
        })
    }

    /// Waits for the exact invocation and local child-close report.
    ///
    /// This is an uninterruptible observation: cancellation of the observing
    /// context does not erase cleanup or its result. Use [`abort`](Self::abort)
    /// or [`close`](Self::close) to cancel the invocation itself. Dropping this
    /// waiting future preserves the handle and its pending report.
    ///
    /// # Errors
    /// Returns the same errors as [`try_join`](Self::try_join).
    pub async fn join(&mut self, _cx: &Cx) -> Result<RemoteRunReport, RemoteRunHandleError> {
        poll_fn(|task| self.poll_join(task)).await
    }

    /// Requests cancellation and waits for the protocol and child-region
    /// cleanup report. Caller cancellation cannot truncate that observation.
    ///
    /// # Errors
    /// Returns the same errors as [`try_join`](Self::try_join).
    pub async fn close(&mut self, cx: &Cx) -> Result<RemoteRunReport, RemoteRunHandleError> {
        self.abort_with_reason(
            cx.cancel_reason()
                .unwrap_or_else(|| CancelReason::user("owned remote handle close")),
        );
        self.join(cx).await
    }
}

impl Drop for RemoteRunHandle {
    fn drop(&mut self) {
        self.abort_with_reason(CancelReason::user("owned remote handle dropped"));
    }
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

/// Starts a named remote invocation as owned background work in the caller's
/// region and immediately returns its cancellation and result handle.
///
/// Unlike constructing a [`run_remote`] future, successful submission starts
/// the owner independently of whether its handle is ever polled. It opens an
/// invocation child region and uses the same checked Lease and protocol driver
/// as `run_remote`; no remote request is sent before local proxy and lease
/// admission. The timeout starts at this call and includes owner-task admission
/// delay. If that interval elapses before the owner starts, no remote work is
/// dispatched.
///
/// Parent cancellation reaches the owner and invocation subtree. Parent close
/// waits for that subtree even if the handle has never been joined or has been
/// dropped. An abort after the invocation starts preserves its typed report
/// through the owner task's acknowledged-cancellation boundary.
///
/// Remote success still requires [`RemoteRunReport::is_success`]. A native
/// runtime's lease/drain limits bound a silent peer; custom remote runtimes keep
/// the terminal-delivery requirement documented on [`run_remote`].
///
/// # Errors
/// Rejects missing remote or timer authority, prior cancellation, and an unusable
/// timeout before submitting the owner. A missing local spawn gateway returns
/// [`RemoteRunHandleError::Spawn`]. Later task or child-region admission failures
/// are returned by the handle, with no remote dispatch.
pub fn spawn_remote_owned(
    cx: &Cx,
    node: NodeId,
    computation: ComputationName,
    input: RemoteInput,
    config: RemoteRunConfig,
) -> Result<RemoteRunHandle, RemoteRunHandleError> {
    let (clock, deadline) = prepare_run(cx, &config)?;
    let task = cx.spawn(move |owner| async move {
        let result = if clock.now() >= deadline {
            Err(RemoteRunError::Timeout)
        } else {
            run_prepared(
                &owner,
                node,
                computation,
                input,
                config.child,
                (clock, deadline),
                None,
            )
            .await
        };
        // The report is terminal bookkeeping. Preserve it even when the
        // operation's cancellation arrived during child-region close.
        let _ = owner.checkpoint();
        result
    })?;
    Ok(RemoteRunHandle { task, deadline })
}

fn prepare_run(
    cx: &Cx,
    config: &RemoteRunConfig,
) -> Result<(TimerDriverHandle, Time), RemoteRunError> {
    if cx.is_cancel_requested() {
        return Err(RemoteRunError::Cancelled);
    }
    let cap = cx.remote().ok_or(RemoteRunError::NoCapability)?;
    if cap.runtime().is_none() {
        return Err(RemoteRunError::NoRemoteRuntime);
    }
    let clock = cx.timer_driver().ok_or(RemoteRunError::NoTimer)?;
    let now = clock.now();
    let deadline = now + config.timeout;
    if config.timeout.is_zero() || deadline <= now {
        return Err(RemoteRunError::Timeout);
    }
    Ok((clock, deadline))
}

async fn run_admitted(
    cx: &Cx, node: NodeId, computation: ComputationName, input: RemoteInput,
    config: RemoteRunConfig, admission: Option<admission::Permit>,
) -> Result<RemoteRunReport, RemoteRunError> {
    let timing = prepare_run(cx, &config)?;
    run_prepared(cx, node, computation, input, config.child, timing, admission).await
}

async fn run_prepared(
    cx: &Cx,
    node: NodeId,
    computation: ComputationName,
    input: RemoteInput,
    child_spec: ChildRegionSpec,
    timing: (TimerDriverHandle, Time),
    admission: Option<admission::Permit>,
) -> Result<RemoteRunReport, RemoteRunError> {
    let (clock, deadline) = timing;
    let child = cx.open_child_region(child_spec).await?;
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
            // This operation belongs to the explicit Cx. Cancellation of an
            // unrelated ambient polling task must not look like elapsed time.
            if clock.now() >= deadline || timer.as_mut().poll_deadline(task).is_ready() {
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
        // Closed means the proxy is terminal, but its join result becomes
        // visible only when the scheduler opens its retirement barrier, after
        // the lock that closed the region. On another worker this closer can
        // get here first, where try_join would still report Ok(None).
        let proxy = handle.as_mut().expect("retained proxy");
        result = Some(match poll_fn(|task| proxy.poll_join(task)).await {
            Ok(value) => value,
            Err(error) => Err(RemoteRunTaskError::Join(error)),
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
    RemoteExecutorError, RemotePeerLimits, RemoteServiceAdmission,
    RemoteQueueLimits, RemoteQueueUsage, RemoteReservation, RemoteReserveError,
    RemotePriority, RemotePriorityPolicy,
};

#[cfg(test)]
mod tests;
