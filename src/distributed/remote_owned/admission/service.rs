//! Inbound admission for authenticated named computations, retained through drain.
//!
//! This is an opt-in registration adapter, not a new listener or wire protocol.
//! The session's admitted peer selects the quota; request origin fields do not.
//! A runtime-owned coordinator holds the charge while a child region executes
//! the handler and drains its descendants. Dropping the dispatch waiter requests
//! coordinator cancellation rather than making its admission immediately reusable.

use super::{RemoteAdmissionError, RemoteAdmissionLimits, RemoteAdmissionUsage, RemoteExecutor,
    RemotePeerLimits, RemotePriority, RemotePriorityPolicy, RemoteQueueLimits, RemoteQueueUsage, RemoteReserveError};
use crate::cx::{ChildRegionSpec, Cx};
use crate::distributed::{ComputationSchemaRegistryError, HasSchema};
use crate::remote::{NodeId, RemoteComputationInvocation, RemoteComputationRegistry, RemoteError, RemoteOutcome};
use crate::runtime::{JoinError, TaskHandle};
use crate::types::{CancelReason, Outcome};
use std::fmt;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

/// Shared inbound execution and original-input-byte limits for registered handlers.
///
/// Uses the same atomic quota accounting as the outbound executor, but owns an
/// independent budget. Clones, registry clones, and every computation registered
/// through this object share that one budget. Separate constructors do not.
///
/// Admission happens after session authentication, framing and registry dispatch,
/// but BEFORE the user factory, its decoding/copies, and its child-region work.
/// Existing listener connection/frame and retained-idempotency limits still apply.
/// Input charges exclude earlier frame copies, outputs, TLS buffers, task metadata
/// and arbitrary application allocations. This is not an exact RSS ceiling.
///
/// The registered computation runs in an explicit child region. Completion waits
/// for descendant/finalizer close. Cancellation or dropping a dispatch waiter
/// requests cancellation of its coordinator; that region-owned task retains the
/// charge through cleanup. Work deliberately spawned outside the supplied child
/// Cx is not owned by this adapter. Forced runtime teardown is not remote drain.
#[derive(Clone)]
pub struct RemoteServiceAdmission {
    budget: RemoteExecutor,
}

impl fmt::Debug for RemoteServiceAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteServiceAdmission")
            .field("usage", &self.usage())
            .finish_non_exhaustive()
    }
}

impl RemoteServiceAdmission {
    /// Provision fixed authenticated logical peers without granting network access.
    /// `RemotePeerLimits` now applies to the inbound session peer, not a destination.
    /// Zero denies the corresponding dimension; aliases have independent quotas.
    pub fn new<I>(limits: RemoteAdmissionLimits, peers: I) -> Result<Self, RemoteAdmissionError>
    where
        I: IntoIterator<Item = (NodeId, RemotePeerLimits)>,
    {
        Ok(Self { budget: RemoteExecutor::new(limits, peers)? })
    }

    /// Explicitly enable bounded waiting. All immediate and waiting registrations
    /// share active counters; only register_waiting uses the bounded wait queue.
    pub fn new_queued<I>(limits: RemoteAdmissionLimits, peers: I, queue: RemoteQueueLimits)
        -> Result<Self, RemoteAdmissionError>
    where I: IntoIterator<Item = (NodeId, RemotePeerLimits)>,
    {
        Ok(Self { budget: RemoteExecutor::new_queued(limits, peers, queue)? })
    }

    /// Enable locally assigned application priorities with bounded-bypass promotion.
    /// Every registered class shares the same global/per-peer active and waiting
    /// ceilings. This changes no TLS grants, wire schemas or lifecycle-control lane.
    pub fn new_prioritized<I>(limits: RemoteAdmissionLimits, peers: I,
        queue: RemoteQueueLimits, priority: RemotePriorityPolicy,
    ) -> Result<Self, RemoteAdmissionError>
    where I: IntoIterator<Item = (NodeId, RemotePeerLimits)>,
    {
        Ok(Self { budget: RemoteExecutor::new_prioritized(limits, peers, queue, priority)? })
    }

    /// Current waiting charges, separate from active execution usage.
    #[must_use]
    pub fn queue_usage(&self) -> RemoteQueueUsage { self.budget.queue_usage() }

    /// Waiting charges selected by the authenticated peer, never request origin.
    #[must_use]
    pub fn peer_queue_usage(&self, peer: &NodeId) -> Option<RemoteQueueUsage> {
        self.budget.peer_queue_usage(peer)
    }

    /// Execution charges, including admitted work whose network waiter disappeared.
    #[must_use]
    pub fn usage(&self) -> RemoteAdmissionUsage { self.budget.usage() }

    /// Current charges for an authenticated logical peer, not request origin_node.
    #[must_use]
    pub fn peer_usage(&self, peer: &NodeId) -> Option<RemoteAdmissionUsage> {
        self.budget.peer_usage(peer)
    }

    /// Permanently refuse new executions through all registrations and clones.
    /// Existing tasks still drain and control/terminal traffic takes no new credit.
    pub fn close_admission(&self) -> bool { self.budget.close_admission() }

    /// Register a bounded handler with its original name and input/output schemas.
    ///
    /// Build the normal certificate-bound policy from the resulting registry.
    /// This does not authenticate a string, grant a capability, change a receipt,
    /// or replace the server's V1/V2/V3 lifecycle and idempotency implementation.
    /// Retained duplicate replies are not new executions and acquire no charge.
    /// A capacity refusal is an ordinary Failed outcome: V2/V3 may retain that
    /// outcome under their existing idempotency policy. No retry is introduced.
    ///
    /// Saturation, unknown peers and payload limits refuse before user code runs.
    /// A detached context or failed task/region admission refuses without inline
    /// fallback. The factory is checked again when its real child task starts.
    /// Panics use native TaskHandle isolation, including factory/destructor panics.
    ///
    /// The body value is not exposed until child close succeeds. Parent or subtree
    /// cancellation cannot become Success merely because a handler returned late.
    /// A body/descendant panic remains Panicked; cleanup failures never become
    /// Success. Original returned application outcomes/errors are otherwise kept.
    /// Panics observed only through task/close machinery use payload-free messages.
    ///
    /// An ordinary caller must poll through completion for a drain receipt. If it
    /// drops the dispatch future, owned cleanup requests coordinator cancellation;
    /// the runtime still owns the cleanup. Cancellation cannot preempt synchronous
    /// user polls or stuck blocking work. No bounded wall-clock drain is promised.
    pub fn register<I, O, F, Fut>(
        &self, registry: &mut RemoteComputationRegistry, name: impl Into<String>,
        child: ChildRegionSpec, handler: F,
    ) -> Result<(), ComputationSchemaRegistryError>
    where
        I: HasSchema,
        O: HasSchema,
        F: Fn(Cx, RemoteComputationInvocation) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RemoteOutcome, RemoteError>> + Send + 'static,
    {
        self.register_policy::<I, O, F, Fut>(registry, name, child, None, handler)
    }

    /// Register a handler with explicit cancellation-aware bounded backpressure.
    ///
    /// Requires new_queued and a positive wait interval plus context timer. A
    /// queued invocation retains its original input charge but invokes no user
    /// factory and creates no extra coordinator. Cancellation, disconnect/drop,
    /// closure or wait expiry removes it without execution. Once admitted it uses
    /// the SAME coordinator and retains active quota through subtree cleanup.
    ///
    /// Ordinary queues use FIFO per authenticated peer and oldest feasible heads
    /// globally. Priority-enabled queues assign this handler Normal. V3 renewal/
    /// cancel and cached replies bypass
    /// execution admission as before. Queue refusals/timeouts are Failed outcomes
    /// and may be retained by V2/V3 idempotency; no retry policy changes. Queue wait
    /// is separate from, and cannot extend, the service's original lease/deadlines.
    pub fn register_waiting<I, O, F, Fut>(
        &self, registry: &mut RemoteComputationRegistry, name: impl Into<String>,
        child: ChildRegionSpec, wait_timeout: Duration, handler: F,
    ) -> Result<(), ComputationSchemaRegistryError>
    where
        I: HasSchema,
        O: HasSchema,
        F: Fn(Cx, RemoteComputationInvocation) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RemoteOutcome, RemoteError>> + Send + 'static,
    {
        self.register_policy::<I, O, F, Fut>(registry, name, child,
            Some((wait_timeout, RemotePriority::Normal)), handler)
    }

    /// Register a computation with an operator-selected application priority.
    ///
    /// The class is captured at registration, never read from the request, its
    /// asserted origin or the client's payload. Only an authenticated peer granted
    /// this computation can reach its class. Non-normal classes require an
    /// explicitly priority-enabled constructor; otherwise dispatch refuses before
    /// invoking the factory. This is scheduling policy, not extra capacity or a
    /// protocol-control capability. Running handlers are never preempted.
    ///
    /// All classes share the same counters/coordinator/drain path. FIFO holds
    /// within each authenticated peer/class; promoted feasible heads outrank all
    /// ordinary classes. Cancellation and the original lease/queue deadline remain
    /// dominant. Existing V2/V3 idempotency may retain admission refusals as before.
    pub fn register_waiting_with_priority<I, O, F, Fut>(
        &self, registry: &mut RemoteComputationRegistry, name: impl Into<String>,
        child: ChildRegionSpec, wait_timeout: Duration, priority: RemotePriority, handler: F,
    ) -> Result<(), ComputationSchemaRegistryError>
    where
        I: HasSchema,
        O: HasSchema,
        F: Fn(Cx, RemoteComputationInvocation) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RemoteOutcome, RemoteError>> + Send + 'static,
    {
        self.register_policy::<I, O, F, Fut>(registry, name, child, Some((wait_timeout, priority)), handler)
    }

    fn register_policy<I, O, F, Fut>(
        &self, registry: &mut RemoteComputationRegistry, name: impl Into<String>,
        child: ChildRegionSpec, wait: Option<(Duration, RemotePriority)>, handler: F,
    ) -> Result<(), ComputationSchemaRegistryError>
    where
        I: HasSchema,
        O: HasSchema,
        F: Fn(Cx, RemoteComputationInvocation) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RemoteOutcome, RemoteError>> + Send + 'static,
    {
        let budget = self.budget.clone();
        let handler = Arc::new(handler);
        registry.register::<I, O, _, _>(name, move |cx, invocation| {
            let budget = budget.clone();
            let handler = Arc::clone(&handler);
            let spec = child.clone();
            async move {
                if cx.checkpoint().is_err() { return Ok(cancelled(&cx)); }
                let permit = if let Some((timeout, priority)) = wait {
                    match budget.reserve_with_priority(&cx, invocation.peer_node(),
                        invocation.request().input.len(), timeout, priority).await {
                        Ok(reservation) => reservation.permit,
                        Err(RemoteReserveError::Cancelled) => return Ok(cancelled(&cx)),
                        Err(error) => return Ok(RemoteOutcome::Failed(format!("remote service admission refused: {error}"))),
                    }
                } else {
                    match budget.acquire(invocation.peer_node(), invocation.request().input.len()) {
                        Ok(permit) => permit,
                        Err(error) => return Ok(RemoteOutcome::Failed(format!("remote service admission refused: {error}"))),
                    }
                };
                // The complete coordinator future is destroyed before its charge.
                // Dropping the waiter aborts the coordinator, whose own
                // cancellation path awaits the actual child-region close.
                let task = cx.spawn(move |owner| crate::distributed::remote_owned::AdmittedProxy {
                    future: execute(owner, invocation, spec, handler),
                    _admission: Some(permit),
                }).map_err(|_| setup_error("remote service coordinator admission refused"))?;
                let mut coordinator = Coordinator { task, cx: &cx };
                let mut cancel = std::pin::pin!(cx.cancelled());
                let first = poll_fn(|context| {
                    if cancel.as_mut().poll(context).is_ready() { return Poll::Ready(None); }
                    coordinator.task.poll_join(context).map(Some)
                }).await;
                let result = match first {
                    Some(result) => result,
                    None => {
                        let _ = cx.checkpoint(); // Acknowledge before asynchronous drain.
                        coordinator.cancel();
                        let result = coordinator.task.join(&cx).await;
                        let _ = cx.checkpoint();
                        result
                    }
                };
                match result {
                    Ok(result) => result,
                    Err(error) => Ok(join_outcome(error)),
                }
            }
        })
    }
}

// poll_join preserves wake registration but has no cancellation-on-drop future.
// This owner supplies that backstop even before the first parked join poll.
struct Coordinator<'a, T> { task: TaskHandle<T>, cx: &'a Cx }
impl<T> Coordinator<'_, T> {
    fn cancel(&self) {
        if !self.task.is_finished() {
            self.task.abort_with_reason(self.cx.cancel_reason()
                .unwrap_or_else(|| CancelReason::user("remote service dispatch dropped")));
        }
    }
}
impl<T> Drop for Coordinator<'_, T> { fn drop(&mut self) { self.cancel(); } }

fn setup_error(message: &str) -> RemoteError { RemoteError::TransportError(message.to_owned()) }
fn cancelled(cx: &Cx) -> RemoteOutcome {
    RemoteOutcome::Cancelled(cx.cancel_reason().unwrap_or_else(CancelReason::parent_cancelled))
}
fn join_outcome(error: JoinError) -> RemoteOutcome {
    match error {
        JoinError::Cancelled(reason) => RemoteOutcome::Cancelled(reason),
        JoinError::Panicked(_) => RemoteOutcome::Panicked("remote admitted task panicked".to_owned()),
        JoinError::PolledAfterCompletion => RemoteOutcome::Failed("remote admitted task result was already consumed".to_owned()),
    }
}

async fn execute<F, Fut>(
    cx: Cx, invocation: RemoteComputationInvocation, spec: ChildRegionSpec, handler: Arc<F>,
) -> Result<RemoteOutcome, RemoteError>
where
    F: Fn(Cx, RemoteComputationInvocation) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<RemoteOutcome, RemoteError>> + Send + 'static,
{
    if cx.checkpoint().is_err() { return Ok(cancelled(&cx)); }
    let child = cx.open_child_region(spec).await
        .map_err(|_| setup_error("remote service child-region admission refused"))?;
    let mut task = None;
    let mut result = if cx.checkpoint().is_err() {
        Some(Ok(cancelled(&cx)))
    } else {
        match child.cx().spawn(move |body| async move {
            if body.checkpoint().is_err() { return Ok(cancelled(&body)); }
            handler(body, invocation).await
        }) {
            Ok(handle) => { task = Some(handle); None }
            Err(_) => Some(Err(setup_error("remote service handler admission refused"))),
        }
    };
    if let Some(task) = task.as_mut() {
        let mut stop = std::pin::pin!(cx.cancelled());
        poll_fn(|context| {
            if stop.as_mut().poll(context).is_ready() { return Poll::Ready(()); }
            if let Poll::Ready(value) = task.poll_join(context) {
                result = Some(value.unwrap_or_else(|error| Ok(join_outcome(error))));
                return Poll::Ready(());
            }
            Poll::Pending
        }).await;
    }
    // Cancellation is independent of the parent; close also cancels remaining
    // descendants after ordinary body completion. Neither path detaches cleanup.
    let cancel_error = if cx.is_cancel_requested() {
        let _ = cx.checkpoint(); // Cleanup may legitimately cross further Pending polls.
        child.cancel(cx.cancel_reason().unwrap_or_else(CancelReason::parent_cancelled)).err()
    } else { None };
    let close = child.close_with_outcome().await;
    if result.is_none() {
        result = Some(match task.as_mut().expect("started handler").try_join() {
            Ok(Some(value)) => value,
            Err(error) => Ok(join_outcome(error)),
            Ok(None) => Err(setup_error("remote service handler has no terminal result after close")),
        });
    }
    drop(task);
    // Preserve a typed cancellation result through the ordinary Cx-spawn policy.
    let _ = cx.checkpoint();
    let result = result.expect("handler result or setup refusal");
    let close = close.map_err(|_| setup_error("remote service child-region close failed"))?;
    if matches!(&result, Ok(RemoteOutcome::Panicked(_))) { return result; }
    let outcomes = [Some(&close.outcome), close.cleanup_outcome.as_ref()];
    if outcomes.iter().flatten().any(|outcome| matches!(outcome, Outcome::Panicked(_))) {
        return Ok(RemoteOutcome::Panicked("remote admitted subtree or cleanup panicked".to_owned()));
    }
    if cancel_error.is_some() { return Err(setup_error("remote service child cancellation enqueue failed")); }
    if cx.is_cancel_requested() { return Ok(cancelled(&cx)); }
    for outcome in outcomes.iter().flatten() {
        if let Outcome::Cancelled(reason) = outcome { return Ok(RemoteOutcome::Cancelled(reason.clone())); }
    }
    if outcomes.iter().flatten().any(|outcome| matches!(outcome, Outcome::Err(_))) {
        return Ok(RemoteOutcome::Failed("remote admitted subtree or cleanup failed".to_owned()));
    }
    result
}

#[cfg(test)]
mod tests;
