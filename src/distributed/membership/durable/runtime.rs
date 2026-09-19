//! Persist-before-publish authority admission for checked runtime-owned leases.

use super::{MembershipJournal, MembershipJournalError, MembershipJournalStatus};
use crate::cx::{ChildRegionSpec, Cx};
use crate::distributed::membership::authority::{
    MAX_MEMBERSHIP_UPDATE_BYTES, MembershipApplied, MembershipControlError, MembershipStamp,
};
use crate::distributed::membership::owned::{
    MembershipWorkError, MembershipWorkReport, OwnedMembershipController, OwnedMembershipError,
    OwnedMembershipLease,
};
use crate::distributed::membership::service::MEMBERSHIP_SERVICE_COMPUTATION;
use crate::distributed::{ComputationSchemaRegistryError, HasSchema, SchemaDescriptor};
use crate::remote::{NodeId, RemoteComputationRegistry, RemoteOutcome};
use crate::time::TimerDriverHandle;
use parking_lot::Mutex;
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use zeroize::Zeroizing;

/// Persistence or checked-runtime projection could not be completed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PersistentMembershipError {
    /// Authenticated journal validation/append failed.
    #[error(transparent)]
    Journal(#[from] MembershipJournalError),
    /// Checked local lease admission or projection failed.
    #[error(transparent)]
    Owned(#[from] OwnedMembershipError),
    /// One queued/running update already owns the file; no hidden queue exists.
    #[error("persistent membership update is busy")]
    Busy,
    /// Closed after explicit shutdown, an uncertain append, or projection failure.
    #[error("persistent membership controller is closed")]
    Closed,
}

/// A journal plus its private, checked-runtime membership projection.
///
/// Build from a successfully opened journal before exposing the service. Restore
/// its authenticated decisions BEFORE permitting grants, but never restore old
/// runtime tokens or child tasks. Every new decision reaches sync_all before the
/// owned controller changes or a successful wire receipt is produced.
///
/// Exactly one queued/running update owns the journal across all registrations
/// and Arc clones. The journal is taken out of the mutex while working: disk I/O
/// and arbitrary lease-waker callbacks cannot run under that mutex or the same
/// controller lock. Reentrant updates refuse Busy. Any uncertain write or failed
/// in-memory projection closes admission and aborts existing local leases.
///
/// A synchronous commit is not preemptible. Continue draining its runtime-owned
/// blocking worker on cancellation; a stuck filesystem can delay that drain.
/// This proves neither remote termination nor rollback of accepted decisions.
pub struct PersistentMembershipController {
    owner: OwnedMembershipController,
    authority: NodeId,
    journal: Mutex<Option<MembershipJournal>>,
    closed: AtomicBool,
    driver_started: AtomicBool,
}
impl fmt::Debug for PersistentMembershipController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistentMembershipController")
            .field("closed", &self.closed.load(Ordering::Acquire))
            .field("update_in_flight", &self.update_in_flight()).finish_non_exhaustive()
    }
}
impl PersistentMembershipController {
    /// Consume a verified/synced journal and reconstruct the private live policy.
    /// Call off the async executor during startup. Initial floors, epoch and keys
    /// were already checked by journal open. No lease is revived by this method.
    pub fn new(journal: MembershipJournal, clock: TimerDriverHandle) -> Result<Self, PersistentMembershipError> {
        if journal.status() == MembershipJournalStatus::Poisoned {
            return Err(MembershipJournalError::NotWritable(journal.status()).into());
        }
        let config = &journal.core.config;
        let owner = OwnedMembershipController::new(config.authority.clone(), config.epoch,
            config.statement_key.clone(), config.floors.clone(), config.controller_limits, clock)?;
        for bytes in journal.core.latest.values() { owner.apply_authenticated(&config.authority, bytes)?; }
        Ok(Self { authority: config.authority.clone(), owner,
            journal: Mutex::new(Some(journal)), closed: AtomicBool::new(false), driver_started: AtomicBool::new(false) })
    }
    /// The last durably admitted decision, once projected to the owned controller.
    pub fn stamp(&self, node: &NodeId) -> Option<MembershipStamp> { self.owner.stamp(node) }
    /// Owned guards and pending checked runtime registrations.
    pub fn live_leases(&self) -> usize { self.owner.live_leases() }
    /// Whether another update owns the journal, including a queued blocking job.
    pub fn update_in_flight(&self) -> bool {
        self.journal.try_lock().is_none_or(|slot| slot.is_none())
    }
    /// No I/O: None means an update currently owns the journal or mutex.
    pub fn journal_status(&self) -> Option<MembershipJournalStatus> {
        self.journal.try_lock().and_then(|slot| slot.as_ref().map(MembershipJournal::status))
    }
    /// Checked lease admission under only already-persisted decisions.
    pub fn try_grant(&self, cx: &Cx, node: &NodeId, incarnation: u64, duration: Duration)
        -> Result<OwnedMembershipLease, OwnedMembershipError>
    {
        if self.closed.load(Ordering::Acquire) { return Err(OwnedMembershipError::Closed); }
        self.owner.try_grant(cx, node, incarnation, duration)
    }
    /// Existing child-region execution/drain behavior, with durable grant policy.
    pub async fn run_scoped<T, F, Fut>(&self, cx: &Cx, node: &NodeId, incarnation: u64,
        duration: Duration, spec: ChildRegionSpec, factory: F)
        -> Result<MembershipWorkReport<T>, MembershipWorkError>
    where T: Send + 'static, F: FnOnce(Cx) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        if self.closed.load(Ordering::Acquire) { return Err(OwnedMembershipError::Closed.into()); }
        self.owner.run_scoped(cx, node, incarnation, duration, spec, factory).await
    }
    /// Drive the existing expiry loop in a caller-owned task. This adds no task.
    pub async fn run(&self, cx: &Cx) -> Result<(), OwnedMembershipError> {
        if self.closed.load(Ordering::Acquire) { return Err(OwnedMembershipError::Closed); }
        if self.driver_started.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Err(OwnedMembershipError::DriverRunning);
        }
        struct Driver<'a>(&'a PersistentMembershipController);
        impl Drop for Driver<'_> { fn drop(&mut self) { self.0.close(); } }
        let _driver = Driver(self);
        self.owner.run(cx).await
    }
    /// Explicit expiry for embeddings with their own timer driver.
    pub fn expire(&self) -> Result<usize, OwnedMembershipError> { self.owner.expire() }
    /// Close local admission and abort guards. Does not cancel a started disk
    /// syscall, erase its possibly committed decision, or persist a new statement.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.owner.close();
    }
    /// Synchronous local adapter. Peer identity is caller authority, not a proof
    /// from a string; network users should register the certificate-bound service.
    /// Use a blocking worker, never an async executor thread. No retry is added.
    pub fn apply_blocking(self: &Arc<Self>, peer: &NodeId, bytes: &[u8])
        -> Result<MembershipApplied, PersistentMembershipError>
    {
        self.prepare(peer, bytes)?.execute()
    }
    fn prepare(self: &Arc<Self>, peer: &NodeId, bytes: &[u8]) -> Result<UpdateJob, PersistentMembershipError> {
        if self.closed.load(Ordering::Acquire) { return Err(PersistentMembershipError::Closed); }
        if peer != &self.authority {
            return Err(MembershipJournalError::Control(MembershipControlError::Authority).into());
        }
        if !(73..=MAX_MEMBERSHIP_UPDATE_BYTES).contains(&bytes.len()) {
            return Err(MembershipJournalError::Control(MembershipControlError::Format).into());
        }
        let journal = self.journal.try_lock().ok_or(PersistentMembershipError::Busy)?
            .take().ok_or(PersistentMembershipError::Busy)?;
        let mut job = UpdateJob { controller: Arc::clone(self), journal: Some(journal),
            bytes: Zeroizing::new(Vec::new()), projecting: false };
        job.bytes.try_reserve_exact(bytes.len()).map_err(|_| MembershipJournalError::Allocation)?;
        job.bytes.extend_from_slice(bytes);
        Ok(job)
    }
    fn return_journal(&self, journal: MembershipJournal) {
        let mut slot = self.journal.lock();
        assert!(slot.is_none(), "one journal owner per controller");
        *slot = Some(journal);
    }
}
impl Drop for PersistentMembershipController {
    fn drop(&mut self) { self.owner.close(); }
}

// Ownership exists before request copying/spawn. A cancelled unstarted closure
// simply returns the untouched journal. A started failure closes grants first.
struct UpdateJob {
    controller: Arc<PersistentMembershipController>,
    journal: Option<MembershipJournal>,
    bytes: Zeroizing<Vec<u8>>,
    projecting: bool,
}
impl UpdateJob {
    fn execute(mut self) -> Result<MembershipApplied, PersistentMembershipError> {
        if self.controller.closed.load(Ordering::Acquire) { return Err(PersistentMembershipError::Closed); }
        self.journal.as_mut().expect("admitted journal").append(&self.bytes)?;
        // A crash now replays the synced decision. A projection refusal/panic
        // instead closes this live owner so it cannot continue under stale policy.
        self.projecting = true;
        let applied = self.controller.owner.apply_authenticated(&self.controller.authority, &self.bytes)?;
        self.projecting = false;
        Ok(applied)
    }
}
impl Drop for UpdateJob {
    fn drop(&mut self) {
        let Some(journal) = self.journal.take() else { return; };
        let must_close = self.projecting || journal.status() == MembershipJournalStatus::Poisoned;
        // Return even when a close notifier unwinds, but only AFTER local closure
        // and sensitive request retirement. No callback runs with the slot locked.
        struct Return<'a> { controller: &'a PersistentMembershipController, journal: Option<MembershipJournal> }
        impl Drop for Return<'_> {
            fn drop(&mut self) { self.controller.return_journal(self.journal.take().expect("return once")); }
        }
        let _return = Return { controller: &self.controller, journal: Some(journal) };
        drop(std::mem::replace(&mut self.bytes, Zeroizing::new(Vec::new())));
        if must_close { self.controller.close(); }
    }
}

// Same canonical descriptors as the existing V1 membership service, not a new
// negotiated wire contract or a receipt that third parties can prove is durable.
struct Request;
struct Response;
impl HasSchema for Request {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("asupersync.membership-authority.signed-statement.v1") }
}
impl HasSchema for Response {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("asupersync.membership-authority.accepted-statement-echo.v1") }
}
fn cancelled(cx: &Cx) -> RemoteOutcome {
    cx.cancel_reason().map_or_else(|| RemoteOutcome::Failed("persistent membership worker refused".to_owned()), RemoteOutcome::Cancelled)
}

/// Alternative backend for the existing V1 capability and submission client.
///
/// Grant only the certificate-bound authority via the normal peer policy. The
/// private controller additionally checks that identity and the statement MAC.
/// Require an explicit context blocking pool; no inline disk-I/O fallback exists.
/// One controller-wide admission is taken BEFORE copies/spawn and is retained if
/// its network waiter drops. The worker checks cancellation before starting,
/// then completes a synchronous append/projection without pretending to roll it
/// back. An exact success echo follows sync and checked local revocation posts;
/// it does not certify child drain, peer liveness or persistent runtime tokens.
/// V1 avoids replaying framework-cached lifecycle receipts after backend restart.
pub fn register_persistent_membership_service(registry: &mut RemoteComputationRegistry,
    controller: Arc<PersistentMembershipController>) -> Result<(), ComputationSchemaRegistryError>
{
    registry.register::<Request, Response, _, _>(MEMBERSHIP_SERVICE_COMPUTATION, move |cx, invocation| {
        let controller = Arc::clone(&controller);
        async move {
            if cx.checkpoint().is_err() { return Ok(cancelled(&cx)); }
            if cx.blocking_pool_handle().is_none() {
                return Ok(RemoteOutcome::Failed("persistent membership requires a context blocking pool".to_owned()));
            }
            let job = match controller.prepare(invocation.peer_node(), invocation.request().input.data()) {
                Ok(job) => job, Err(error) => return Ok(RemoteOutcome::Failed(error.to_string())),
            };
            let receipt = job.bytes.to_vec();
            let mut worker = match cx.spawn_blocking(move |worker| {
                if worker.checkpoint().is_err() { return cancelled(&worker); }
                match job.execute() {
                    Ok(_) => RemoteOutcome::Success(receipt),
                    Err(error) => RemoteOutcome::Failed(error.to_string()),
                }
            }) {
                Ok(worker) => worker,
                Err(_) => return Ok(RemoteOutcome::Failed("persistent membership worker admission refused".to_owned())),
            };
            match worker.join(&cx).await {
                Ok(outcome) if !cx.is_cancel_requested() => Ok(outcome),
                _ => Ok(cancelled(&cx)),
            }
        }
    })
}

#[cfg(test)]
mod tests;
