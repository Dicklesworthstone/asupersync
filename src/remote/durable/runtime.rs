//! Explicit, caller-owned execution over a durable idempotency journal.

use super::{
    DurableRemoteAdmission, DurableRemoteError, DurableRemoteJournal,
    DurableRemoteJournalStatus, DurableRemoteLimits, DurableRemoteReconciliation,
};
use crate::cx::Cx;
use crate::distributed::{ComputationRegistryFingerprint, ComputationSchemaRegistry, HasSchema};
use crate::remote::{
    RemoteComputationInvocation, RemoteComputationRegistry, RemoteError, RemoteOutcome,
};
use parking_lot::Mutex;
use std::fmt;
use std::future::Future;
use std::sync::Arc;

/// Opt-in restart-durable execution for one named computation and application version.
///
/// Construct this from an authenticated, exclusively owned journal before
/// exposing the service. The caller supplies a trusted clock in milliseconds
/// from a consistent epoch across restarts; never use a peer timestamp or a new
/// runtime's relative clock. A backward clock refuses work. Wall-clock jumps
/// forward can expire completed results, so the clock's trust and continuity
/// are part of the application's retention policy.
///
/// Exactly one invocation owns this journal at a time, across all registrations
/// and clones. Additional calls refuse `Busy` without a hidden waiter queue.
/// The owner retains the journal through the reservation write, application
/// future, terminal write, and any queued/running blocking job retirement.
/// All disk work uses the context's drained blocking pool, outside the slot
/// mutex. A non-preemptible filesystem operation can delay region drain.
///
/// A synced reservation precedes application execution. A synced terminal
/// result precedes a successful return, and retries replay that result during
/// its retention window. Dropping, panicking, or failing to persist after a
/// reservation leaves an **in-doubt fence**, including after restart. Such a
/// fence never expires automatically: arbitrary application side effects cannot
/// be committed atomically with this journal. Reconcile them at the application
/// boundary; do not change the key to turn uncertainty into an automatic retry.
/// [`Self::reconcile`] can persist a result independently established by an
/// application after fencing the original external operation. It never executes
/// the original handler or treats an unknown effect as a successful rollback.
/// This adapter does not restore futures or promise cross-system exactly-once
/// effects. Existing remote clients retain their conservative retry policy.
pub struct DurableRemoteComputation {
    journal: Mutex<Option<DurableRemoteJournal>>,
    computation: String,
    schema: ComputationRegistryFingerprint,
    limits: DurableRemoteLimits,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl fmt::Debug for DurableRemoteComputation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DurableRemoteComputation")
            .field("computation", &self.computation)
            .field("in_flight", &self.in_flight())
            .finish_non_exhaustive()
    }
}

impl DurableRemoteComputation {
    /// Own an already created or reopened journal and an explicit trusted clock.
    ///
    /// This performs no I/O, spawns no task, and acquires no ambient authority.
    /// The journal's application version and schemas must describe the handler
    /// that will be registered, including changes in effect semantics that keep
    /// the same input/output shape.
    pub fn new(
        journal: DurableRemoteJournal,
        clock: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Self {
        Self {
            computation: journal.computation().to_owned(),
            schema: journal.schema_fingerprint(),
            limits: journal.limits(),
            journal: Mutex::new(Some(journal)),
            clock: Arc::new(clock),
        }
    }

    /// Whether an invocation or a queued/running disk job owns the journal.
    #[must_use]
    pub fn in_flight(&self) -> bool {
        self.journal.try_lock().is_none_or(|slot| slot.is_none())
    }

    /// Append posture without waiting behind an invocation or doing disk I/O.
    /// `None` means the journal currently has an invocation owner.
    #[must_use]
    pub fn journal_status(&self) -> Option<DurableRemoteJournalStatus> {
        self.journal
            .try_lock()
            .and_then(|slot| slot.as_ref().map(DurableRemoteJournal::status))
    }

    /// Register this computation through the existing schema and peer-admission APIs.
    ///
    /// Input/output schemas must match the journal's independently provisioned
    /// identity. The handler explicitly returns a terminal [`RemoteOutcome`].
    /// Any persistence/admission error becomes the existing remote execution
    /// failure; it is not a successful outcome or evidence of rollback. V1--V3
    /// wire formats and framework idempotency remain unchanged. A wire response
    /// does not attest which storage backend the operator configured.
    pub fn register<I, O, F, Fut>(
        self: &Arc<Self>,
        registry: &mut RemoteComputationRegistry,
        handler: F,
    ) -> Result<(), DurableRemoteError>
    where
        I: HasSchema,
        O: HasSchema,
        F: Fn(Cx, RemoteComputationInvocation) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = RemoteOutcome> + Send + 'static,
    {
        let mut schemas = ComputationSchemaRegistry::new();
        schemas
            .register_typed::<I, O>(self.computation.clone())
            .map_err(|_| DurableRemoteError::Configuration)?;
        if schemas.fingerprint() != self.schema {
            return Err(DurableRemoteError::Configuration);
        }
        let owner = Arc::clone(self);
        let handler = Arc::new(handler);
        registry
            .register::<I, O, _, _>(self.computation.clone(), move |cx, invocation| {
                let owner = Arc::clone(&owner);
                let handler = Arc::clone(&handler);
                async move {
                    owner
                        .call(&cx, invocation, move |cx, invocation| handler(cx, invocation))
                        .await
                        .map_err(|error| RemoteError::TransportError(error.to_string()))
                }
            })
            .map_err(|_| DurableRemoteError::Configuration)
    }

    /// Execute or replay one invocation already admitted by the remote registry.
    ///
    /// This is the same path used by [`Self::register`], exposed for applications
    /// that compose their own registered handler. The invocation's authenticated
    /// peer, key, and input determine replay; caller-supplied origin metadata,
    /// task IDs, budgets and leases cannot change the durable identity.
    ///
    /// The application future is awaited inline, never detached. Cancellation
    /// before a queued reservation starts performs no journal write. Once its
    /// reservation is synced, cancellation or handler drop can leave an in-doubt
    /// fence even if the handler had not yet performed an effect. Failure to
    /// admit or finish a terminal write likewise does not authorize re-execution.
    pub async fn call<F, Fut>(
        self: &Arc<Self>,
        cx: &Cx,
        invocation: RemoteComputationInvocation,
        handler: F,
    ) -> Result<RemoteOutcome, DurableRemoteError>
    where
        F: FnOnce(Cx, RemoteComputationInvocation) -> Fut + Send + 'static,
        Fut: Future<Output = RemoteOutcome> + Send + 'static,
    {
        if cx.checkpoint().is_err() || cx.blocking_pool_handle().is_none() {
            return Err(DurableRemoteError::Unavailable);
        }
        if invocation.request().computation.as_str() != self.computation {
            return Err(DurableRemoteError::Configuration);
        }
        if invocation.request().input.len() > self.limits.max_input_bytes {
            return Err(DurableRemoteError::Limit);
        }
        let mut job = self.take_journal()?;
        // Move the existing invocation into the worker: admission creates no
        // second input buffer, and the job already owns the single service slot.
        let mut admission = cx
            .spawn_blocking_drained(move |worker| {
                if worker.checkpoint().is_err() {
                    return Err(DurableRemoteError::Unavailable);
                }
                let now = (job.owner.clock)();
                let decision = job.journal_mut().admit(
                    invocation.peer_node(),
                    invocation.request().idempotency_key,
                    invocation.request().input.data(),
                    now,
                )?;
                Ok((job, invocation, decision))
            })
            .map_err(|_| DurableRemoteError::Unavailable)?;
        let (mut job, invocation, decision) = admission
            .join()
            .await
            .map_err(|_| DurableRemoteError::Unavailable)??;
        let reservation = match decision {
            DurableRemoteAdmission::Replay(outcome) => {
                // Preserve the durable receipt through an enclosing native
                // task's completion policy as well as this independent join.
                // Observing late cancellation acknowledges it without making
                // an already committed result disappear.
                if cx.is_cancel_requested() {
                    let _ = cx.checkpoint();
                }
                return Ok(outcome);
            }
            DurableRemoteAdmission::Execute(reservation) => reservation,
        };
        if cx.checkpoint().is_err() {
            return Err(DurableRemoteError::Unavailable);
        }
        let outcome = handler(cx.clone(), invocation).await;
        // A started terminal append is a commit boundary. Do not add a worker
        // checkpoint or discard its result because cancellation arrived later.
        // If the runtime cannot admit this job, the persisted reservation fences
        // the ambiguous effect instead of fabricating a replayable result.
        let mut completion = cx
            .spawn_blocking_drained(move |_worker| {
                let now = (job.owner.clock)();
                job.journal_mut().complete(reservation, outcome, now)
            })
            .map_err(|_| DurableRemoteError::Unavailable)?;
        let result = completion
            .join()
            .await
            .map_err(|_| DurableRemoteError::Unavailable)?;
        if cx.is_cancel_requested() {
            let _ = cx.checkpoint();
        }
        result
    }

    /// Resolve an uncertain request from authoritative application state.
    ///
    /// This is an explicit local recovery operation, not part of automatic
    /// execution or the remote retry protocol. The invocation must have passed
    /// the same authenticated registry boundary as [`Self::call`]. A matching
    /// saved outcome replays without calling `resolve`. Missing, expired,
    /// conflicting or actively owned reservations refuse before that callback.
    ///
    /// Before returning `Some(outcome)`, the callback must fence or drain the
    /// original external operation and independently establish its actual
    /// terminal result. Return `None` when it cannot do so; the original durable
    /// reservation remains in doubt. This API provides neither automatic effect
    /// discovery nor permission to execute the original handler again.
    ///
    /// The resolver is awaited inline with the journal exclusively owned. Before
    /// it supplies `Some(outcome)`, cancellation, panic or abandonment leaves the
    /// pending fence unchanged. Failed terminal-job admission or cancellation
    /// before the pool claims that job also leaves the fence intact. After claim,
    /// the terminal write has no cancellation checkpoint and may persist despite
    /// later cancellation. The job retains the owner through actual retirement,
    /// and a successfully persisted result wins over late cancellation just as
    /// in [`Self::call`].
    pub async fn reconcile<F, Fut>(
        self: &Arc<Self>,
        cx: &Cx,
        invocation: RemoteComputationInvocation,
        resolve: F,
    ) -> Result<RemoteOutcome, DurableRemoteError>
    where
        F: FnOnce(Cx, RemoteComputationInvocation) -> Fut + Send + 'static,
        Fut: Future<Output = Option<RemoteOutcome>> + Send + 'static,
    {
        if cx.checkpoint().is_err() || cx.blocking_pool_handle().is_none() {
            return Err(DurableRemoteError::Unavailable);
        }
        if invocation.request().computation.as_str() != self.computation {
            return Err(DurableRemoteError::Configuration);
        }
        if invocation.request().input.len() > self.limits.max_input_bytes {
            return Err(DurableRemoteError::Limit);
        }
        let mut job = self.take_journal()?;
        let mut preparation = cx
            .spawn_blocking_drained(move |worker| {
                if worker.checkpoint().is_err() {
                    return Err(DurableRemoteError::Unavailable);
                }
                let now = (job.owner.clock)();
                let decision = job.journal_mut().prepare_reconciliation(
                    invocation.peer_node(),
                    invocation.request().idempotency_key,
                    invocation.request().input.data(),
                    now,
                )?;
                Ok((job, invocation, decision))
            })
            .map_err(|_| DurableRemoteError::Unavailable)?;
        let (mut job, invocation, decision) = preparation
            .join()
            .await
            .map_err(|_| DurableRemoteError::Unavailable)??;
        let permit = match decision {
            DurableRemoteReconciliation::Replay(outcome) => {
                if cx.is_cancel_requested() {
                    let _ = cx.checkpoint();
                }
                return Ok(outcome);
            }
            DurableRemoteReconciliation::Pending(permit) => permit,
        };
        if cx.checkpoint().is_err() {
            return Err(DurableRemoteError::Unavailable);
        }
        let Some(outcome) = resolve(cx.clone(), invocation).await else {
            return Err(DurableRemoteError::InDoubt);
        };
        let mut completion = cx
            .spawn_blocking_drained(move |_worker| {
                let now = (job.owner.clock)();
                job.journal_mut().complete_reconciliation(permit, outcome, now)
            })
            .map_err(|_| DurableRemoteError::Unavailable)?;
        let result = completion
            .join()
            .await
            .map_err(|_| DurableRemoteError::Unavailable)?;
        if cx.is_cancel_requested() {
            let _ = cx.checkpoint();
        }
        result
    }

    fn take_journal(self: &Arc<Self>) -> Result<InvocationOwner, DurableRemoteError> {
        let journal = self
            .journal
            .try_lock()
            .ok_or(DurableRemoteError::Busy)?
            .take()
            .ok_or(DurableRemoteError::Busy)?;
        Ok(InvocationOwner {
            owner: Arc::clone(self),
            journal: Some(journal),
        })
    }
}

// Also travels in the drained worker's result. Dropping an unclaimed result
// returns the journal only after the actual worker has retired its captures.
struct InvocationOwner {
    owner: Arc<DurableRemoteComputation>,
    journal: Option<DurableRemoteJournal>,
}

impl InvocationOwner {
    fn journal_mut(&mut self) -> &mut DurableRemoteJournal {
        self.journal.as_mut().expect("one admitted journal owner")
    }
}

impl Drop for InvocationOwner {
    fn drop(&mut self) {
        if let Some(journal) = self.journal.take() {
            let mut slot = self.owner.journal.lock();
            debug_assert!(slot.is_none(), "one invocation owns the journal");
            *slot = Some(journal);
        }
    }
}

#[cfg(test)]
mod tests;
