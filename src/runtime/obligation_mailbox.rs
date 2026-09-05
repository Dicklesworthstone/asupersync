//! Obligation mailbox: how a primitive holding only a `&Cx` mints and
//! resolves a runtime-tracked obligation (br-asupersync-bi2462.13).
//!
//! # Why a mailbox
//!
//! Every reserved permit is meant to be a tracked obligation, so region close
//! can prove "no leaked permits" and the lab's obligation-leak oracle sees it.
//! The obligation table lives inside [`RuntimeState`]: in Unified mode it is
//! embedded (`RuntimeState::obligations`), the production runtime reaches it
//! only through `Arc<Mutex<RuntimeState>>`, and the [`LabRuntime`] owns its
//! state by value and polls task futures from inside its own step. A future
//! being polled therefore has no path to `&mut RuntimeState`, and neither has
//! a `Cx`. The spawn path solves exactly this with the
//! [`SpawnGateway`](crate::runtime::spawn_mailbox::SpawnGateway) mailbox that
//! the runtime drains at step start; obligations use the same shape.
//!
//! # Shape
//!
//! * [`ObligationGateway`] (crate-private, attached to every task `Cx` by the
//!   runtime) posts [`ObligationPost`] messages onto an unbounded lock-free
//!   FIFO ([`ObligationMailbox`]). Checked posts also carry their owned credit.
//! * [`Cx::try_register_obligation`](crate::cx::Cx::try_register_obligation)
//!   mints a ticket, reserves one credit on the region's pending-post counter
//!   (so `is_quiescent` / drain gating see the reservation BEFORE the runtime
//!   drains it, the way `PendingSpawnCounter` works for spawns), posts
//!   `Reserve`, and returns an [`ObligationToken`].
//! * [`ObligationToken::commit`] / [`ObligationToken::abort`] post the
//!   resolution; dropping an unresolved token posts `Leak` (never panics).
//! * The runtime drains the mailbox where it drains spawn admissions
//!   ([`apply_obligation_posts`]): `Reserve` -> `RuntimeState::create_obligation`
//!   (holder / region checks, region accounting, trace event, oracle hooks),
//!   `Commit` / `Abort` -> the matching `RuntimeState` method through the
//!   ticket table, `Leak` -> `RuntimeState::report_obligation_leak`, the same
//!   leak policy a completion-time audit runs (leak count, `LeakEscalation`,
//!   `Recover` auto-abort). Drain order is post order, so a resolution never
//!   overtakes its reservation. Everything visible to the oracle flows through
//!   the one authoritative implementation in `RuntimeState`.
//!
//! # Allocation and checked admission
//!
//! Queue segments, drain batches, and ticket maps can allocate. Checked
//! admission additionally owns an `Arc` credit before publication; its live
//! count shares RegionRecord's quota with direct RuntimeState admission.
//! Resolution releases that quota synchronously, while a separate unapplied
//! barrier keeps close waiting for the terminal arena projection. This is not
//! an allocation-free path or immediate arena visibility guarantee.
//!
//! # Not covered (no-claim)
//!
//! Channel send permits (D2) and semaphore permits (D3) use the seam; remote
//! leases (D4) do not yet. A `Cx` built without a runtime (`Cx::new`,
//! `Cx::for_testing`) has no gateway and `try_register_obligation` returns
//! `None`, preserving today's untracked behaviour — which is also why
//! `Semaphore::try_acquire`, whose signature carries no `Cx`, registers only
//! when a task-local one happens to be current.

use crate::record::{ObligationAbortReason, ObligationKind, ObligationResolution};
use crate::runtime::scheduler::global_queue::GlobalFifoQueue;
use crate::runtime::state::RuntimeState;
use crate::types::{ObligationId, RegionId, TaskId};
use crate::util::det_hash::DetHashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// Refusal before a checked obligation token becomes observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ObligationAdmissionError {
    /// The runtime no longer accepts effects.
    #[error("obligation runtime is unavailable")]
    RuntimeUnavailable,
    /// The region was closed or removed.
    #[error("obligation region is closed")]
    RegionClosed,
    /// The original task generation no longer accepts new obligations.
    #[error("obligation holder is no longer live")]
    HolderNotLive,
    /// The requested holder is not the task represented by the context.
    #[error("obligation holder does not match the context")]
    HolderMismatch,
    /// Live direct and checked reservations exhausted the same region quota.
    #[error("obligation limit {limit} reached with {live} live obligations")]
    LimitReached {
        /// Configured region quota.
        limit: usize,
        /// Authoritative live count at refusal.
        live: usize,
    },
    /// An identity or accounting counter cannot grow without wrapping.
    #[error("obligation admission capacity exhausted")]
    CapacityExhausted,
}

/// Owned, preaccepted admission; the arena is its delayed lifecycle projection.
#[derive(Debug)]
pub(crate) struct AdmittedObligation {
    handle: Arc<crate::record::region::ObligationAdmissionHandle>,
    mailbox: Weak<ObligationMailbox>,
    ticket: u64,
    active: AtomicBool,
    resolution: Mutex<Option<ObligationResolution>>,
    application_finished: AtomicBool,
}

impl AdmittedObligation {
    fn resolve(&self, resolution: ObligationResolution, publish: impl FnOnce()) -> bool {
        if !self.active.load(Ordering::Acquire) {
            return false;
        }
        self.handle.settle(|| {
            let mut terminal = self
                .resolution
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if terminal.is_some() {
                return false;
            }
            *terminal = Some(resolution);
            publish();
            true
        })
    }

    pub(crate) fn claim_resolution(
        &self,
        resolution: ObligationResolution,
    ) -> ObligationResolution {
        self.resolve(resolution, || {});
        self.resolution
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expect("an active admitted obligation has one terminal decision")
    }

    pub(crate) fn finish_application(&self) {
        if !self.application_finished.swap(true, Ordering::AcqRel) {
            self.handle.finish_application();
            if let Some(mailbox) = self.mailbox.upgrade() {
                mailbox
                    .tickets
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&self.ticket);
            }
        }
    }
}

#[derive(Debug)]
struct QueuedObligationPost {
    post: ObligationPost,
    admission: Option<Arc<AdmittedObligation>>,
}

/// What a post asks the runtime to do with an obligation ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationOp {
    /// Mint the obligation record (`RuntimeState::create_obligation`).
    Reserve,
    /// Resolve it successfully (`RuntimeState::commit_obligation`).
    Commit,
    /// Resolve it as aborted (`RuntimeState::abort_obligation`).
    Abort,
    /// The token was dropped unresolved (`RuntimeState::report_obligation_leak`:
    /// the runtime's leak policy, so it counts, escalates, or auto-recovers).
    Leak,
}

/// One Copy-sized message on the obligation mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObligationPost {
    /// The operation.
    pub op: ObligationOp,
    /// Ticket minted by the gateway; the drainer maps it to the
    /// [`ObligationId`] the `Reserve` produced.
    pub ticket: u64,
    /// Obligation kind (only meaningful on `Reserve`).
    pub kind: ObligationKind,
    /// Holder task.
    pub holder: TaskId,
    /// Owning region.
    pub region: RegionId,
    /// Abort reason (only meaningful on `Abort`).
    pub abort_reason: ObligationAbortReason,
}

/// Counters the drainer keeps so tests and diagnostics can prove every post
/// was applied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObligationMailboxStats {
    /// Posts pushed by gateways.
    pub posted: u64,
    /// Posts the runtime applied.
    pub applied: u64,
    /// `Reserve` posts that produced an obligation record.
    pub reserved: u64,
    /// `Commit` posts applied.
    pub committed: u64,
    /// `Abort` posts applied.
    pub aborted: u64,
    /// `Leak` posts applied.
    pub leaked: u64,
    /// Posts the runtime could not apply.
    ///
    /// A `Reserve` the state refused (closed region, admission limit) or a
    /// resolution whose ticket had no record. Each is counted, never dropped
    /// silently.
    pub refused: u64,
}

/// The unbounded lock-free FIFO of obligation posts plus the drainer's
/// ticket table.
#[derive(Debug, Default)]
pub struct ObligationMailbox {
    queue: GlobalFifoQueue<QueuedObligationPost>,
    next_ticket: AtomicU64,
    posted: AtomicU64,
    applied: AtomicU64,
    reserved: AtomicU64,
    committed: AtomicU64,
    aborted: AtomicU64,
    leaked: AtomicU64,
    refused: AtomicU64,
    /// ticket -> obligation id for reservations the runtime has applied and
    /// not yet resolved. Only the drainer touches it (under the state lock),
    /// so an uncontended mutex is enough.
    tickets: Mutex<DetHashMap<u64, ObligationId>>,
}

impl ObligationMailbox {
    /// A new, empty mailbox.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn mint_ticket(&self) -> Option<u64> {
        let mut ticket = self.next_ticket.load(Ordering::Relaxed);
        loop {
            let next = ticket.checked_add(1)?;
            match self.next_ticket.compare_exchange_weak(
                ticket,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(ticket),
                Err(observed) => ticket = observed,
            }
        }
    }

    fn push(&self, post: ObligationPost) {
        self.push_admitted(post, None);
    }

    fn push_admitted(&self, post: ObligationPost, admission: Option<Arc<AdmittedObligation>>) {
        // Count before publishing so observers see posted >= applied.
        self.posted.fetch_add(1, Ordering::Relaxed);
        self.queue.push(QueuedObligationPost { post, admission });
    }

    /// Whether no post is waiting to be applied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Posts waiting to be applied.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Snapshot of the counters.
    #[must_use]
    pub fn stats(&self) -> ObligationMailboxStats {
        ObligationMailboxStats {
            posted: self.posted.load(Ordering::Relaxed),
            applied: self.applied.load(Ordering::Relaxed),
            reserved: self.reserved.load(Ordering::Relaxed),
            committed: self.committed.load(Ordering::Relaxed),
            aborted: self.aborted.load(Ordering::Relaxed),
            leaked: self.leaked.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
        }
    }

    /// Reservations applied and not yet resolved.
    #[must_use]
    pub fn open_tickets(&self) -> usize {
        self.tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

/// Producer-side handle attached to every task `Cx` built by a runtime
/// (mirrors [`SpawnGateway`](crate::runtime::spawn_mailbox::SpawnGateway)).
pub struct ObligationGateway {
    mailbox: Arc<ObligationMailbox>,
    notify: Arc<dyn Fn() + Send + Sync>,
    runtime_liveness: Weak<()>,
}

impl std::fmt::Debug for ObligationGateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObligationGateway")
            .field("pending_posts", &self.mailbox.len())
            .field("runtime_available", &self.is_runtime_available())
            .finish_non_exhaustive()
    }
}

impl ObligationGateway {
    /// A gateway over `mailbox`; `notify` wakes the runtime's drain loop and
    /// `runtime_liveness` is the same liveness token the spawn gateway uses.
    #[must_use]
    pub(crate) fn new(
        mailbox: Arc<ObligationMailbox>,
        notify: Arc<dyn Fn() + Send + Sync>,
        runtime_liveness: Weak<()>,
    ) -> Self {
        Self {
            mailbox,
            notify,
            runtime_liveness,
        }
    }

    /// The mailbox this gateway posts to.
    #[must_use]
    pub fn mailbox(&self) -> &Arc<ObligationMailbox> {
        &self.mailbox
    }

    /// Whether the owning runtime is still alive.
    #[must_use]
    pub fn is_runtime_available(&self) -> bool {
        self.runtime_liveness.upgrade().is_some()
    }

    /// Post one message and wake the drain loop. Returns `false` (and posts
    /// nothing) once the runtime is gone.
    fn post(&self, post: ObligationPost) -> bool {
        if !self.post_deferred(post) {
            return false;
        }
        self.notify();
        true
    }

    fn post_deferred(&self, post: ObligationPost) -> bool {
        let Some(_liveness) = self.runtime_liveness.upgrade() else {
            return false;
        };
        self.mailbox.push(post);
        true
    }

    /// Invoke only after any primitive/adapter locks have been released.
    pub(crate) fn notify(&self) {
        (self.notify)();
    }

    /// Mint a ticket and post its reservation.
    ///
    /// `pending` is the owning region's pending-post counter, reserved for
    /// the token's lifetime so drain gating sees the obligation before the
    /// runtime applies it.
    pub(crate) fn register(
        self: &Arc<Self>,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        pending: Option<&Arc<crate::record::region::PendingSpawnCounter>>,
    ) -> Option<ObligationToken> {
        let ticket = self.mailbox.mint_ticket()?;
        let pending = pending.map(crate::record::region::PendingSpawnCounter::reserve);
        let posted = self.post(ObligationPost {
            op: ObligationOp::Reserve,
            ticket,
            kind,
            holder,
            region,
            abort_reason: ObligationAbortReason::Explicit,
        });
        if !posted {
            return None;
        }
        Some(ObligationToken {
            ticket,
            kind,
            holder,
            region,
            gateway: Arc::downgrade(self),
            _pending: pending,
            resolved: false,
            admission: None,
            abort_on_drop: false,
        })
    }

    pub(crate) fn register_checked(
        self: &Arc<Self>,
        kind: ObligationKind,
        holder: TaskId,
        region: RegionId,
        handle: &Arc<crate::record::region::ObligationAdmissionHandle>,
    ) -> Result<ObligationToken, ObligationAdmissionError> {
        let _liveness = self
            .runtime_liveness
            .upgrade()
            .ok_or(ObligationAdmissionError::RuntimeUnavailable)?;
        let ticket = self
            .mailbox
            .mint_ticket()
            .ok_or(ObligationAdmissionError::CapacityExhausted)?;
        let admission = Arc::new(AdmittedObligation {
            handle: Arc::clone(handle),
            mailbox: Arc::downgrade(&self.mailbox),
            ticket,
            active: AtomicBool::new(false),
            resolution: Mutex::new(None),
            application_finished: AtomicBool::new(false),
        });
        // Ownership is installed before publication and before arbitrary notify.
        let mut token = ObligationToken {
            ticket,
            kind,
            holder,
            region,
            gateway: Arc::downgrade(self),
            _pending: None,
            resolved: false,
            admission: Some(Arc::clone(&admission)),
            abort_on_drop: true,
        };
        handle.admit(holder, region, || {
            admission.active.store(true, Ordering::Release);
            self.mailbox.push_admitted(
                ObligationPost {
                    op: ObligationOp::Reserve,
                    ticket,
                    kind,
                    holder,
                    region,
                    abort_reason: ObligationAbortReason::Explicit,
                },
                Some(Arc::clone(&admission)),
            );
        })?;
        (self.notify)();
        token.abort_on_drop = false;
        Ok(token)
    }
}

/// A runtime-tracked obligation minted through the obligation mailbox.
///
/// Created by
/// [`Cx::try_register_obligation`](crate::cx::Cx::try_register_obligation).
/// Resolve it with [`commit`](Self::commit) or [`abort`](Self::abort);
/// dropping it unresolved posts a leak, which the runtime records through its
/// obligation-leak policy (and the lab's obligation-leak oracle reports). The
/// token keeps one pending-post credit on its region for as long as it lives,
/// so region close and `is_quiescent` never observe a window in which the
/// reservation is neither posted nor applied.
#[must_use = "an unresolved ObligationToken is reported as a leak when dropped"]
#[derive(Debug)]
pub struct ObligationToken {
    ticket: u64,
    kind: ObligationKind,
    holder: TaskId,
    region: RegionId,
    gateway: Weak<ObligationGateway>,
    _pending: Option<crate::record::region::PendingSpawnReservation>,
    resolved: bool,
    admission: Option<Arc<AdmittedObligation>>,
    abort_on_drop: bool,
}

impl ObligationToken {
    /// The gateway ticket (stable for the token's life; the drainer maps it
    /// to the runtime's [`ObligationId`]).
    #[must_use]
    pub fn ticket(&self) -> u64 {
        self.ticket
    }

    /// The obligation kind.
    #[must_use]
    pub fn kind(&self) -> ObligationKind {
        self.kind
    }

    /// The holder task.
    #[must_use]
    pub fn holder(&self) -> TaskId {
        self.holder
    }

    /// The owning region.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.region
    }

    fn resolve_deferred(
        mut self,
        op: ObligationOp,
        abort_reason: ObligationAbortReason,
    ) -> (bool, Option<Arc<ObligationGateway>>) {
        self.resolved = true;
        let post = ObligationPost {
            op,
            ticket: self.ticket,
            kind: self.kind,
            holder: self.holder,
            region: self.region,
            abort_reason,
        };
        if let Some(admission) = &self.admission {
            return self.resolve_checked_deferred(admission, post);
        }
        let gateway = self
            .gateway
            .upgrade()
            .filter(|gateway| gateway.post_deferred(post));
        (gateway.is_some(), gateway)
    }

    fn resolve_checked_deferred(
        &self,
        admission: &Arc<AdmittedObligation>,
        post: ObligationPost,
    ) -> (bool, Option<Arc<ObligationGateway>>) {
        let resolution = match post.op {
            ObligationOp::Commit => ObligationResolution::Commit,
            ObligationOp::Abort => ObligationResolution::Abort(post.abort_reason),
            ObligationOp::Leak => ObligationResolution::Leak,
            ObligationOp::Reserve => unreachable!("resolution cannot reserve"),
        };
        let gateway = self
            .gateway
            .upgrade()
            .filter(|gateway| gateway.is_runtime_available());
        let won = admission.resolve(resolution, || {
            if let Some(gateway) = &gateway {
                gateway
                    .mailbox
                    .push_admitted(post, Some(Arc::clone(admission)));
            }
        });
        if gateway.is_none() && admission.active.load(Ordering::Acquire) {
            admission.finish_application();
        }
        let accepted = won && gateway.is_some();
        let notification = if won && !std::thread::panicking() {
            gateway
        } else {
            None
        };
        (accepted, notification)
    }

    /// Settle and publish without running a notification callback.
    pub(crate) fn commit_deferred(self) -> (bool, Option<Arc<ObligationGateway>>) {
        self.resolve_deferred(ObligationOp::Commit, ObligationAbortReason::Explicit)
    }

    /// Settle and publish without running a notification callback.
    pub(crate) fn abort_deferred(
        self,
        reason: ObligationAbortReason,
    ) -> (bool, Option<Arc<ObligationGateway>>) {
        self.resolve_deferred(ObligationOp::Abort, reason)
    }

    /// Resolve the obligation as committed. Returns `false` when the runtime
    /// is already gone (nothing is tracked any more).
    pub fn commit(self) -> bool {
        let (accepted, notification) = self.commit_deferred();
        if let Some(gateway) = notification {
            gateway.notify();
        }
        accepted
    }

    /// Resolve the obligation as aborted for `reason`.
    pub fn abort(self, reason: ObligationAbortReason) -> bool {
        let (accepted, notification) = self.abort_deferred(reason);
        if let Some(gateway) = notification {
            gateway.notify();
        }
        accepted
    }
}

impl Drop for ObligationToken {
    fn drop(&mut self) {
        if self.resolved {
            return;
        }
        self.resolved = true;
        let post = ObligationPost {
            op: if self.abort_on_drop {
                ObligationOp::Abort
            } else {
                ObligationOp::Leak
            },
            ticket: self.ticket,
            kind: self.kind,
            holder: self.holder,
            region: self.region,
            abort_reason: if self.abort_on_drop {
                ObligationAbortReason::Error
            } else {
                ObligationAbortReason::Explicit
            },
        };
        if let Some(admission) = &self.admission {
            let (_, notification) = self.resolve_checked_deferred(admission, post);
            if let Some(gateway) = notification {
                gateway.notify();
            }
            return;
        }
        if let Some(gateway) = self.gateway.upgrade() {
            let _ = gateway.post(post);
        }
    }
}

/// Apply up to `max` waiting posts to `state` in post order.
///
/// Called by the runtime where it drains spawn admissions (under the state
/// lock). Returns how many posts were applied.
pub(crate) fn apply_obligation_posts(
    state: &mut RuntimeState,
    mailbox: &ObligationMailbox,
    max: usize,
) -> usize {
    apply_obligation_posts_with_task_table(state, mailbox, max, None)
}

pub(crate) fn apply_obligation_posts_with_task_table(
    state: &mut RuntimeState,
    mailbox: &ObligationMailbox,
    max: usize,
    dispatch_tasks: Option<&Arc<crate::sync::ContendedMutex<crate::runtime::TaskTable>>>,
) -> usize {
    if mailbox.is_empty() {
        return 0;
    }
    let mut posts = Vec::with_capacity(max.min(64));
    let drained = mailbox.queue.pop_batch_into(max, &mut posts);
    if drained == 0 {
        return 0;
    }
    for queued in posts {
        let QueuedObligationPost { post, admission } = queued;
        // A completion audit can apply the shared terminal decision before a
        // late queued receipt reaches this bounded drain. It is not a refusal.
        if admission
            .as_ref()
            .is_some_and(|credit| credit.application_finished.load(Ordering::Acquire))
        {
            mailbox.applied.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let ticket_id = mailbox
            .tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&post.ticket)
            .copied();
        let apply = |state: &mut RuntimeState, id: Option<ObligationId>| {
            if dispatch_tasks.is_some() || admission.is_some() || post.op == ObligationOp::Reserve {
                return state.apply_obligation_post_from_dispatch_table(
                    post,
                    id,
                    dispatch_tasks,
                    admission.clone(),
                );
            }
            match post.op {
                ObligationOp::Reserve => state
                    .create_obligation(post.kind, post.holder, post.region, None)
                    .map(Some),
                ObligationOp::Commit | ObligationOp::Abort | ObligationOp::Leak => {
                    let id = id.ok_or_else(|| {
                        crate::error::Error::new(crate::error::ErrorKind::ObligationAlreadyResolved)
                    })?;
                    match post.op {
                        ObligationOp::Commit => state.commit_obligation(id).map(|_| None),
                        ObligationOp::Abort => {
                            state.abort_obligation(id, post.abort_reason).map(|_| None)
                        }
                        ObligationOp::Leak => state.report_obligation_leak(id).map(|()| None),
                        ObligationOp::Reserve => unreachable!("handled reserve above"),
                    }
                }
            }
        };
        match post.op {
            ObligationOp::Reserve => match apply(state, None) {
                Ok(Some(id)) => {
                    mailbox
                        .tickets
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(post.ticket, id);
                    mailbox.reserved.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    mailbox.refused.fetch_add(1, Ordering::Relaxed);
                }
            },
            ObligationOp::Commit => match ticket_id {
                Some(id) if apply(state, Some(id)).is_ok() => {
                    mailbox.committed.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    mailbox.refused.fetch_add(1, Ordering::Relaxed);
                }
            },
            ObligationOp::Abort => match ticket_id {
                Some(id) if apply(state, Some(id)).is_ok() => {
                    mailbox.aborted.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    mailbox.refused.fetch_add(1, Ordering::Relaxed);
                }
            },
            ObligationOp::Leak => match ticket_id {
                Some(id) if apply(state, Some(id)).is_ok() => {
                    mailbox.leaked.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    mailbox.refused.fetch_add(1, Ordering::Relaxed);
                }
            },
        }
        if post.op != ObligationOp::Reserve {
            mailbox
                .tickets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&post.ticket);
        }
        mailbox.applied.fetch_add(1, Ordering::Relaxed);
    }
    drained
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::lab::{LabConfig, LabRuntime};
    use crate::runtime::config::{LeakEscalation, ObligationLeakResponse};
    use crate::trace::TraceEventKind;
    use crate::types::Budget;
    use std::sync::atomic::AtomicUsize;

    fn lab() -> LabRuntime {
        let mut runtime = LabRuntime::new(LabConfig::new(0xD1_0001).max_steps(4_096));
        runtime
            .state
            .set_obligation_leak_response(ObligationLeakResponse::Silent);
        runtime
    }

    fn mailbox_of(runtime: &LabRuntime) -> Arc<ObligationMailbox> {
        Arc::clone(
            runtime
                .state
                .obligation_gateway()
                .expect("lab runtime installs an obligation gateway")
                .mailbox(),
        )
    }

    fn checked_holder(limit: usize) -> (LabRuntime, RegionId, TaskId, Cx) {
        let mut runtime = lab();
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (holder, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, std::future::pending::<()>())
            .expect("live holder");
        let record = runtime.state.region(region).unwrap();
        let mut limits = record.limits();
        limits.max_obligations = Some(limit);
        record.set_limits(limits);
        let cx = runtime.state.task(holder).unwrap().cx.clone().unwrap();
        (runtime, region, holder, cx)
    }

    #[test]
    fn checked_external_dispatch_admits_drains_and_retires_its_actual_holder() {
        use crate::runtime::scheduler::three_lane::ThreeLaneScheduler;
        use crate::runtime::state::{AdmissionRegionTarget, AdmissionTaskTarget};
        use crate::sync::ContendedMutex;
        use crate::trace::distributed::{LogicalClockMode, LogicalTime};

        for limit in [0, 1] {
            let state = Arc::new(ContendedMutex::new(
                "checked_external_state",
                RuntimeState::new(),
            ));
            // This is the external-only dispatch shape: no ShardedState is
            // installed, and the embedded task table stays empty throughout.
            let tasks = Arc::new(ContendedMutex::new(
                "checked_external_tasks",
                crate::runtime::TaskTable::new(),
            ));
            let mailbox = Arc::new(ObligationMailbox::new());
            let liveness = Arc::new(());
            let polls = Arc::new(AtomicUsize::new(0));
            let observed_polls = Arc::clone(&polls);
            let (region, holder, mut handle, spawn_effects) = {
                let mut runtime = state.lock().unwrap();
                runtime.set_logical_clock_mode(LogicalClockMode::Lamport);
                runtime.set_obligation_leak_response(ObligationLeakResponse::Log);
                runtime.set_obligation_gateway(Arc::new(ObligationGateway::new(
                    Arc::clone(&mailbox),
                    Arc::new(|| {}),
                    Arc::downgrade(&liveness),
                )));
                let region = runtime.create_root_region(Budget::INFINITE);
                assert!(runtime.set_region_limits(
                    region,
                    crate::record::region::RegionLimits {
                        max_obligations: Some(limit),
                        ..crate::record::region::RegionLimits::UNLIMITED
                    }
                ));
                let mut held = None;
                let future = std::future::poll_fn(move |context| {
                    let cx = Cx::current().expect("native worker installs the external holder Cx");
                    assert_eq!(cx.region_id(), region);
                    if observed_polls.fetch_add(1, Ordering::SeqCst) == 0 {
                        for _ in 0..17 {
                            let _ = cx.logical_tick();
                        }
                        if limit == 1 {
                            let token = cx
                                .try_register_obligation_checked(
                                    ObligationKind::SendPermit,
                                    cx.task_id(),
                                )
                                .unwrap()
                                .expect("external holder has authoritative admission");
                            assert_eq!(token.holder(), cx.task_id());
                            assert_eq!(token.region(), region);
                            held = Some(token);
                        }
                        assert!(matches!(cx.try_register_obligation_checked(
                            ObligationKind::SendPermit, cx.task_id(),
                        ), Err(ObligationAdmissionError::LimitReached { limit: quota, live })
                            if quota == limit && live == limit));
                        context.waker().wake_by_ref();
                        return std::task::Poll::Pending;
                    }
                    if let Some(token) = held.take() {
                        assert!(token.commit());
                        // The first Commit is still queued. The same external
                        // holder must nevertheless be able to reuse its quota.
                        let next = cx
                            .try_register_obligation_checked(ObligationKind::Lease, cx.task_id())
                            .unwrap()
                            .expect("same-poll external quota reuse");
                        assert!(next.abort(ObligationAbortReason::Explicit));
                    }
                    std::task::Poll::Ready(83_u32)
                });
                let mut target = AdmissionTaskTarget::External(tasks.lock().unwrap());
                let (holder, handle, spawn_effects) = runtime
                    .create_task_with_deferred_spawn_effects_in(
                        region,
                        Budget::INFINITE,
                        future,
                        &mut target,
                        &AdmissionRegionTarget::Embedded,
                    )
                    .expect("mint a real holder directly into the dispatch table");
                assert!(runtime.tasks.is_empty());
                assert_eq!(runtime.tasks.stored_future_count(), 0);
                (region, holder, handle, spawn_effects)
            };
            let cx = tasks
                .lock()
                .unwrap()
                .task(holder)
                .unwrap()
                .cx
                .clone()
                .unwrap();
            let mut scheduler = ThreeLaneScheduler::new_with_options_and_task_table(
                1,
                &state,
                Some(Arc::clone(&tasks)),
                16,
                false,
                32,
            );
            let mut worker = scheduler.take_workers().remove(0);
            scheduler.inject_ready(holder, 0);
            spawn_effects.dispatch();
            let worker_state = Arc::clone(&state);
            let worker_tasks = Arc::clone(&tasks);
            let worker_mailbox = Arc::clone(&mailbox);
            let (completed_tx, completed_rx) = std::sync::mpsc::sync_channel(1);
            let worker_thread = std::thread::spawn(move || {
                assert_eq!(worker.next_task(), Some(holder));
                worker.execute(holder);
                assert_eq!(worker_mailbox.stats().posted, limit as u64);
                assert_eq!(worker_mailbox.stats().applied, 0);
                assert_eq!(worker_mailbox.open_tickets(), 0);
                {
                    let runtime = worker_state.lock().unwrap();
                    assert!(runtime.tasks.is_empty());
                    assert!(worker_tasks.lock().unwrap().task(holder).is_some());
                    assert_eq!(runtime.region(region).unwrap().pending_obligations(), limit);
                }
                // The ordinary native selection path must drain against the
                // selected external table while the holder is still live.
                assert_eq!(worker.next_task(), Some(holder));
                assert_eq!(worker_mailbox.stats().reserved, limit as u64);
                assert_eq!(worker_mailbox.stats().applied, limit as u64);
                assert_eq!(worker_mailbox.stats().refused, 0);
                assert_eq!(worker_mailbox.open_tickets(), limit);
                {
                    let runtime = worker_state.lock().unwrap();
                    assert!(runtime.tasks.is_empty());
                    assert!(worker_tasks.lock().unwrap().task(holder).is_some());
                    assert_eq!(runtime.pending_obligation_count(), limit);
                    for (_, record) in runtime.obligations.iter() {
                        assert_eq!(record.holder, holder);
                        assert_eq!(record.region, region);
                    }
                }
                worker.execute(holder);
                drop(worker);
                completed_tx
                    .send(())
                    .expect("completion receiver remains alive");
            });
            // A dispatch or lock regression must fail within a bounded wait.
            // The owned JoinHandle detaches on timeout; no scoped join can
            // block this test's unwind waiting for the stuck worker.
            completed_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap_or_else(|error| {
                    panic!("external native worker completion limit={limit}: {error}");
                });
            worker_thread
                .join()
                .expect("external native worker completes without panic");
            assert_eq!(polls.load(Ordering::SeqCst), 2);
            assert_eq!(handle.try_join().unwrap(), Some(83));
            assert!(matches!(
                cx.try_register_obligation_checked(ObligationKind::SendPermit, holder,),
                Err(ObligationAdmissionError::HolderNotLive)
            ));
            let runtime = state.lock().unwrap();
            assert!(runtime.tasks.is_empty());
            assert_eq!(runtime.tasks.stored_future_count(), 0);
            assert!(tasks.lock().unwrap().is_empty());
            assert_eq!(tasks.lock().unwrap().stored_future_count(), 0);
            assert_eq!(runtime.pending_obligation_count(), 0);
            assert_eq!(runtime.leak_count(), 0);
            let record = runtime.region(region).unwrap();
            assert_eq!(record.pending_obligations(), 0);
            assert_eq!(record.pending_obligation_post_count(), 0);
            assert_eq!(record.unapplied_obligation_count(), 0);
            assert!(matches!(
                record.close_outcome(),
                Some(crate::types::Outcome::Ok(()))
            ));
            let stats = mailbox.stats();
            assert_eq!(stats.posted, 4 * limit as u64);
            assert_eq!(stats.applied, stats.posted);
            assert_eq!(stats.reserved, 2 * limit as u64);
            assert_eq!(stats.committed, limit as u64);
            assert_eq!(stats.aborted, limit as u64);
            assert_eq!(stats.refused, 0);
            assert_eq!(stats.leaked, 0);
            assert!(mailbox.is_empty());
            assert_eq!(mailbox.open_tickets(), 0);
            let mut previous_tick = 17;
            let mut traced = 0;
            for event in runtime.trace_handle().snapshot() {
                if matches!(
                    event.kind,
                    TraceEventKind::ObligationReserve
                        | TraceEventKind::ObligationCommit
                        | TraceEventKind::ObligationAbort
                ) {
                    let Some(LogicalTime::Lamport(tick)) = event.logical_time else {
                        panic!("external holder attribution missing: {event:?}");
                    };
                    assert!(tick.raw() > previous_tick, "{event:?}");
                    previous_tick = tick.raw();
                    traced += 1;
                }
            }
            assert_eq!(traced, 4 * limit);
            eprintln!(
                "checked external-only dispatch limit={limit} holder={holder:?} region={region:?} polls=2 result=83 trace_events={traced} stats={stats:?}"
            );
        }
    }

    #[test]
    fn checked_admission_shares_zero_one_n_quota_before_any_drain() {
        for limit in [0, 1, 4] {
            let (mut runtime, region, holder, cx) = checked_holder(limit);
            let mailbox = mailbox_of(&runtime);
            let mut tokens = Vec::new();
            for live in 0..limit {
                tokens.push(
                    cx.try_register_obligation_checked(ObligationKind::SendPermit, holder)
                        .expect("quota available")
                        .expect("runtime tracked"),
                );
                assert_eq!(
                    runtime.state.region(region).unwrap().pending_obligations(),
                    live + 1
                );
            }
            assert!(
                matches!(cx.try_register_obligation_checked(ObligationKind::SendPermit, holder),
                Err(ObligationAdmissionError::LimitReached { limit: observed_limit, live })
                    if observed_limit == limit && live == limit)
            );
            assert!(
                runtime
                    .state
                    .create_obligation(ObligationKind::SendPermit, holder, region, None)
                    .is_err()
            );
            assert_eq!(mailbox.len(), limit);
            assert_eq!(
                runtime.state.pending_obligation_count(),
                0,
                "arena projection has not run"
            );
            for token in tokens {
                assert!(token.commit());
            }
            assert_eq!(
                runtime.state.region(region).unwrap().pending_obligations(),
                0
            );
            assert_eq!(
                runtime
                    .state
                    .region(region)
                    .unwrap()
                    .unapplied_obligation_count(),
                limit
            );
            assert_eq!(runtime.state.drain_obligation_posts(64), limit * 2);
            assert_eq!(runtime.state.pending_obligation_count(), 0);
            assert_eq!(
                runtime
                    .state
                    .region(region)
                    .unwrap()
                    .unapplied_obligation_count(),
                0
            );
            assert_eq!(mailbox.stats().reserved, limit as u64);
            assert_eq!(mailbox.stats().committed, limit as u64);
            assert_eq!(mailbox.stats().refused, 0);
            assert_eq!(mailbox.open_tickets(), 0);
            eprintln!(
                "checked quota limit={limit} region={region:?} holder={holder:?} stats={:?}",
                mailbox.stats()
            );
        }
    }

    #[test]
    fn checked_same_poll_settlement_and_direct_admission_conserve_one_credit() {
        let (mut runtime, region, holder, cx) = checked_holder(1);
        let mailbox = mailbox_of(&runtime);
        let direct = runtime
            .state
            .create_obligation(ObligationKind::Lease, holder, region, None)
            .unwrap();
        assert!(matches!(
            cx.try_register_obligation_checked(ObligationKind::SendPermit, holder),
            Err(ObligationAdmissionError::LimitReached { limit: 1, live: 1 })
        ));
        runtime.state.commit_obligation(direct).unwrap();
        for _ in 0..65 {
            let token = cx
                .try_register_obligation_checked(ObligationKind::SendPermit, holder)
                .unwrap()
                .unwrap();
            assert_eq!(
                runtime.state.region(region).unwrap().pending_obligations(),
                1
            );
            assert!(token.commit());
            assert_eq!(
                runtime.state.region(region).unwrap().pending_obligations(),
                0
            );
        }
        // All 130 posts remain unapplied, but their live quota is already free.
        assert_eq!(mailbox.len(), 130);
        let direct = runtime
            .state
            .create_obligation(ObligationKind::Lease, holder, region, None)
            .unwrap();
        assert_eq!(
            runtime.state.drain_obligation_posts_before_completion(None),
            130
        );
        assert_eq!(
            runtime.state.region(region).unwrap().pending_obligations(),
            1
        );
        assert_eq!(runtime.state.pending_obligation_count(), 1);
        runtime
            .state
            .abort_obligation(direct, ObligationAbortReason::Explicit)
            .unwrap();
        assert_eq!(
            runtime.state.region(region).unwrap().pending_obligations(),
            0
        );
        assert_eq!(
            runtime.state.region(region).unwrap().double_resolve_count(),
            0
        );
        assert_eq!(mailbox.stats().committed, 65);
        assert_eq!(mailbox.stats().refused, 0);
        assert_eq!(mailbox.open_tickets(), 0);
    }

    #[test]
    fn checked_publication_precedes_revoke_and_old_credit_still_resolves() {
        let (mut runtime, region, holder, cx) = checked_holder(1);
        let mailbox = mailbox_of(&runtime);
        let entered = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        let liveness = Arc::new(());
        let notifications = Arc::new(AtomicUsize::new(0));
        let notify = {
            let entered = Arc::clone(&entered);
            let resume = Arc::clone(&resume);
            let notifications = Arc::clone(&notifications);
            Arc::new(move || {
                if notifications.fetch_add(1, Ordering::SeqCst) == 0 {
                    entered.wait();
                    resume.wait();
                }
            })
        };
        let gateway = Arc::new(ObligationGateway::new(
            Arc::clone(&mailbox),
            notify,
            Arc::downgrade(&liveness),
        ));
        let producer = cx
            .clone()
            .with_obligation_gateway(Some(Arc::clone(&gateway)), None);
        let thread = std::thread::spawn(move || {
            producer.try_register_obligation_checked(ObligationKind::SendPermit, holder)
        });
        entered.wait();
        assert_eq!(
            mailbox.len(),
            1,
            "Reserve is published before arbitrary notification"
        );
        runtime
            .state
            .revoke_obligation_admission_before_completion(holder, None);
        assert!(matches!(
            cx.try_register_obligation_checked(ObligationKind::SendPermit, holder),
            Err(ObligationAdmissionError::HolderNotLive)
        ));
        assert!(
            runtime
                .state
                .create_obligation(ObligationKind::Lease, holder, region, None)
                .is_err()
        );
        assert_eq!(
            runtime.state.drain_obligation_posts_before_completion(None),
            1
        );
        assert_eq!(
            runtime.state.pending_obligation_count(),
            1,
            "accepted credit survives revocation"
        );
        resume.wait();
        let token = thread.join().unwrap().unwrap().unwrap();
        assert!(token.abort(ObligationAbortReason::Explicit));
        assert_eq!(
            runtime.state.region(region).unwrap().pending_obligations(),
            0
        );
        assert_eq!(runtime.state.drain_obligation_posts(64), 1);
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert_eq!(mailbox.stats().refused, 0);
        assert_eq!(mailbox.open_tickets(), 0);
    }

    #[test]
    fn checked_notify_panic_aborts_unreturned_credit_without_double_panic() {
        let (mut runtime, region, holder, cx) = checked_holder(1);
        let mailbox = mailbox_of(&runtime);
        let liveness = Arc::new(());
        let notifications = Arc::new(AtomicUsize::new(0));
        let notify = {
            let notifications = Arc::clone(&notifications);
            Arc::new(move || {
                notifications.fetch_add(1, Ordering::SeqCst);
                panic!("original checked admission notification panic");
            })
        };
        let gateway = Arc::new(ObligationGateway::new(
            Arc::clone(&mailbox),
            notify,
            Arc::downgrade(&liveness),
        ));
        let cx = cx.with_obligation_gateway(Some(gateway), None);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _token = cx.try_register_obligation_checked(ObligationKind::SendPermit, holder);
        }))
        .expect_err("notifier panic must propagate");
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"original checked admission notification panic")
        );
        assert_eq!(
            notifications.load(Ordering::SeqCst),
            1,
            "unwind cleanup must not notify again"
        );
        assert_eq!(
            runtime.state.region(region).unwrap().pending_obligations(),
            0
        );
        assert_eq!(
            runtime
                .state
                .region(region)
                .unwrap()
                .unapplied_obligation_count(),
            1
        );
        assert_eq!(runtime.state.drain_obligation_posts(64), 2);
        assert_eq!(mailbox.stats().reserved, 1);
        assert_eq!(mailbox.stats().aborted, 1);
        assert_eq!(mailbox.stats().leaked, 0);
        assert_eq!(mailbox.stats().refused, 0);
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert_eq!(
            runtime
                .state
                .region(region)
                .unwrap()
                .unapplied_obligation_count(),
            0
        );
        assert_eq!(mailbox.open_tickets(), 0);
    }

    #[test]
    fn checked_completion_and_late_resolve_choose_one_attributed_terminal() {
        for commit_before_audit in [false, true] {
            let (mut runtime, region, holder, cx) = checked_holder(1);
            let mailbox = mailbox_of(&runtime);
            let token = cx
                .try_register_obligation_checked(ObligationKind::SendPermit, holder)
                .unwrap()
                .unwrap();
            let ticket = token.ticket();
            assert_eq!(runtime.state.drain_obligation_posts(1), 1);
            let id = *mailbox.tickets.lock().unwrap().get(&ticket).unwrap();
            let mut retained = Some(token);
            runtime
                .state
                .revoke_obligation_admission_before_completion(holder, None);
            if commit_before_audit {
                assert!(retained.take().unwrap().commit());
            }
            let _ = runtime.state.update_task(holder, |record| {
                assert!(record.complete(crate::types::Outcome::Ok(())));
            });
            let _effects = runtime.state.task_completed(holder);
            let record = runtime.state.obligation(id).unwrap();
            assert_eq!(record.holder, holder);
            assert_eq!(record.region, region);
            assert_eq!(
                record.state,
                if commit_before_audit {
                    crate::record::ObligationState::Committed
                } else {
                    crate::record::ObligationState::Leaked
                }
            );
            if let Some(token) = retained {
                assert!(
                    !token.commit(),
                    "completion already terminalized the same credit"
                );
            }
            assert_eq!(
                runtime.state.drain_obligation_posts(64),
                usize::from(commit_before_audit)
            );
            assert_eq!(runtime.state.leak_count(), u64::from(!commit_before_audit));
            assert_eq!(
                runtime.state.region(region).unwrap().pending_obligations(),
                0
            );
            assert_eq!(
                runtime
                    .state
                    .region(region)
                    .unwrap()
                    .unapplied_obligation_count(),
                0
            );
            assert_eq!(mailbox.open_tickets(), 0);
            assert_eq!(mailbox.stats().refused, 0);
        }
    }

    #[test]
    fn checked_removed_generation_and_missing_runtime_cannot_fall_back_untracked() {
        let (mut runtime, region, holder, cx) = checked_holder(1);
        let stateless = Cx::for_testing();
        assert!(
            stateless
                .try_register_obligation_checked(ObligationKind::SendPermit, stateless.task_id())
                .unwrap()
                .is_none()
        );
        let unbound = cx.clone().with_obligation_gateway(None, None);
        assert!(matches!(
            unbound.try_register_obligation_checked(ObligationKind::SendPermit, holder),
            Err(ObligationAdmissionError::RuntimeUnavailable)
        ));
        let (other, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, std::future::pending::<()>())
            .unwrap();
        assert!(matches!(
            cx.try_register_obligation_checked(ObligationKind::SendPermit, other),
            Err(ObligationAdmissionError::HolderMismatch)
        ));
        let removed = runtime
            .state
            .remove_task(holder)
            .expect("remove original generation");
        assert!(matches!(
            cx.try_register_obligation_checked(ObligationKind::SendPermit, holder),
            Err(ObligationAdmissionError::HolderNotLive)
        ));
        let (replacement, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, std::future::pending::<()>())
            .unwrap();
        assert_ne!(replacement, holder);
        let replacement_cx = runtime.state.task(replacement).unwrap().cx.clone().unwrap();
        let token = replacement_cx
            .try_register_obligation_checked(ObligationKind::SendPermit, replacement)
            .unwrap()
            .unwrap();
        assert!(token.commit());
        assert_eq!(runtime.state.drain_obligation_posts(64), 2);
        assert_eq!(mailbox_of(&runtime).stats().refused, 0);
        assert_eq!(
            runtime.state.region(region).unwrap().pending_obligations(),
            0
        );
        drop(removed);
    }

    #[test]
    fn checked_close_waits_for_applied_terminal_after_live_quota_released() {
        let (mut runtime, region, holder, cx) = checked_holder(1);
        let token = cx
            .try_register_obligation_checked(ObligationKind::SendPermit, holder)
            .unwrap()
            .unwrap();
        assert!(token.commit());
        let record = runtime.state.region(region).unwrap();
        record.remove_task(holder);
        assert!(record.begin_close(None));
        assert!(record.begin_finalize());
        assert_eq!(record.pending_obligations(), 0);
        assert_eq!(record.unapplied_obligation_count(), 1);
        assert!(!record.is_quiescent());
        assert!(!record.ready_to_finalize(&|_| true));
        assert!(!record.complete_close());
        assert!(!runtime.state.can_region_complete_close(region));
        assert!(matches!(
            cx.try_register_obligation_checked(ObligationKind::SendPermit, holder),
            Err(ObligationAdmissionError::RegionClosed)
        ));
        assert_eq!(runtime.state.drain_obligation_posts(64), 2);
        assert_eq!(mailbox_of(&runtime).stats().reserved, 1);
        assert_eq!(mailbox_of(&runtime).stats().committed, 1);
        assert_eq!(mailbox_of(&runtime).stats().refused, 0);
        assert_eq!(
            runtime
                .state
                .region(region)
                .unwrap()
                .unapplied_obligation_count(),
            0
        );
        assert_eq!(
            runtime.state.region(region).unwrap().state(),
            crate::record::region::RegionState::Closed
        );
    }

    #[test]
    fn checked_runtime_teardown_releases_unmaterialized_credit_once() {
        let (mut runtime, region, holder, cx) = checked_holder(1);
        let mailbox = mailbox_of(&runtime);
        let liveness = Arc::new(());
        let gateway = Arc::new(ObligationGateway::new(
            Arc::clone(&mailbox),
            Arc::new(|| {}),
            Arc::downgrade(&liveness),
        ));
        let cx = cx.with_obligation_gateway(Some(gateway), None);
        let token = cx
            .try_register_obligation_checked(ObligationKind::SendPermit, holder)
            .unwrap()
            .unwrap();
        drop(liveness);
        assert!(!token.commit());
        assert!(matches!(
            cx.try_register_obligation_checked(ObligationKind::SendPermit, holder),
            Err(ObligationAdmissionError::RuntimeUnavailable)
        ));
        assert_eq!(
            runtime.state.region(region).unwrap().pending_obligations(),
            0
        );
        assert_eq!(
            runtime
                .state
                .region(region)
                .unwrap()
                .unapplied_obligation_count(),
            0
        );
        assert_eq!(runtime.state.drain_obligation_posts(64), 1);
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert_eq!(mailbox.open_tickets(), 0);
        assert_eq!(mailbox.stats().refused, 0);
    }

    #[test]
    fn checked_late_resolution_after_actual_lab_drop_retires_existing_ticket() {
        for materialized in [false, true] {
            for terminal in ["commit", "abort", "drop"] {
                let (mut runtime, _region, holder, cx) = checked_holder(1);
                let mailbox = mailbox_of(&runtime);
                let gateway = Arc::clone(runtime.state.obligation_gateway().unwrap());
                let token = cx
                    .try_register_obligation_checked(ObligationKind::SendPermit, holder)
                    .unwrap()
                    .expect("real Lab holder returns an accepted token");
                let credit = Arc::clone(token.admission.as_ref().unwrap());
                if materialized {
                    assert_eq!(runtime.state.drain_obligation_posts(1), 1);
                    assert_eq!(runtime.state.pending_obligation_count(), 1);
                    assert_eq!(mailbox.open_tickets(), 1);
                } else {
                    assert_eq!(runtime.state.pending_obligation_count(), 0);
                    assert_eq!(mailbox.open_tickets(), 0);
                }
                assert!(!credit.application_finished.load(Ordering::Acquire));
                let before = mailbox.stats();
                // Keep diagnostic mailbox/gateway handles and the token, but
                // destroy the actual runtime and its region/task ownership.
                // The earlier test only withdraws a replacement gateway's
                // liveness while leaving those runtime records intact.
                drop(runtime);
                assert!(!gateway.is_runtime_available());
                assert!(matches!(
                    cx.try_register_obligation_checked(ObligationKind::SendPermit, holder),
                    Err(ObligationAdmissionError::RuntimeUnavailable)
                ));
                match terminal {
                    "commit" => assert!(!token.commit()),
                    "abort" => assert!(!token.abort(ObligationAbortReason::Explicit)),
                    _ => drop(token),
                }
                assert!(credit.application_finished.load(Ordering::Acquire));
                assert_eq!(mailbox.open_tickets(), 0);
                assert_eq!(
                    mailbox.stats(),
                    before,
                    "no new post or fictitious runtime application"
                );
                assert_eq!(mailbox.len(), usize::from(!materialized));
                assert_eq!(before.reserved, u64::from(materialized));
                assert_eq!(before.refused, 0);
                assert_eq!(before.leaked, 0);
                eprintln!(
                    "checked actual Lab teardown materialized={materialized} late_terminal={terminal} open_tickets=0 no_new_posts=true prior_stats={before:?}"
                );
            }
        }
    }

    #[test]
    fn checked_runtime_request_and_cleanup_principals_are_not_stateless() {
        let runtime = crate::runtime::RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs its request context");
            assert!(matches!(
                cx.try_register_obligation_checked(ObligationKind::SendPermit, cx.task_id()),
                Err(ObligationAdmissionError::HolderNotLive)
            ));
        });
        let mut lab = lab();
        let region = lab.state.create_root_region(Budget::INFINITE);
        let observed = Arc::new(AtomicUsize::new(0));
        let finalizer_observed = Arc::clone(&observed);
        let record = lab.state.region(region).unwrap();
        record.add_finalizer(crate::record::finalizer::Finalizer::Async(Box::pin(
            async move {
                let cx =
                    Cx::current().expect("inline cleanup installs its restricted runtime context");
                assert!(matches!(
                    cx.try_register_obligation_checked(ObligationKind::SendPermit, cx.task_id()),
                    Err(ObligationAdmissionError::HolderNotLive)
                ));
                finalizer_observed.fetch_add(1, Ordering::SeqCst);
            },
        )));
        assert!(record.begin_close(None));
        assert!(record.begin_finalize());
        assert!(lab.state.drive_failed_start_async_finalizer_inline(region));
        assert_eq!(
            observed.load(Ordering::SeqCst),
            1,
            "actual cleanup future executed"
        );
        assert_eq!(lab.state.region(region).unwrap().pending_obligations(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(mailbox_of(&lab).len(), 0);
    }

    #[test]
    fn checked_deferred_resolution_releases_quota_without_invoking_notification() {
        let (mut runtime, region, holder, cx) = checked_holder(1);
        let mailbox = mailbox_of(&runtime);
        let liveness = Arc::new(());
        let notifications = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&notifications);
        let gateway = Arc::new(ObligationGateway::new(
            Arc::clone(&mailbox),
            Arc::new(move || {
                observed.fetch_add(1, Ordering::SeqCst);
            }),
            Arc::downgrade(&liveness),
        ));
        let cx = cx.with_obligation_gateway(Some(gateway), None);
        let token = cx
            .try_register_obligation_checked(ObligationKind::SendPermit, holder)
            .unwrap()
            .unwrap();
        assert_eq!(notifications.load(Ordering::SeqCst), 1);
        let (accepted, notification) = token.commit_deferred();
        assert!(accepted);
        assert_eq!(
            runtime.state.region(region).unwrap().pending_obligations(),
            0
        );
        assert_eq!(mailbox.len(), 2);
        assert_eq!(notifications.load(Ordering::SeqCst), 1);
        notification.unwrap().notify();
        assert_eq!(notifications.load(Ordering::SeqCst), 2);
        let token = cx
            .try_register_obligation_checked(ObligationKind::SendPermit, holder)
            .unwrap()
            .unwrap();
        let (accepted, discarded) = token.abort_deferred(ObligationAbortReason::Explicit);
        assert!(accepted);
        drop(discarded);
        assert_eq!(
            notifications.load(Ordering::SeqCst),
            3,
            "discarding deferred work invokes no callback"
        );
        assert_eq!(
            runtime.state.region(region).unwrap().pending_obligations(),
            0
        );
        assert_eq!(runtime.state.drain_obligation_posts(64), 4);
        assert_eq!(mailbox.stats().reserved, 2);
        assert_eq!(mailbox.stats().committed, 1);
        assert_eq!(mailbox.stats().aborted, 1);
        assert_eq!(mailbox.stats().refused, 0);
        assert_eq!(mailbox.open_tickets(), 0);
    }

    struct PostingDuringAdmissionMetrics {
        cx: Cx,
        remaining: AtomicUsize,
    }

    impl crate::observability::metrics::MetricsProvider for PostingDuringAdmissionMetrics {
        fn task_spawned(&self, _: RegionId, _: TaskId) {}
        fn task_completed(
            &self,
            _: TaskId,
            _: crate::observability::metrics::OutcomeKind,
            _: std::time::Duration,
        ) {
        }
        fn region_created(&self, _: RegionId, _: Option<RegionId>) {}
        fn region_closed(&self, _: RegionId, _: std::time::Duration) {}
        fn cancellation_requested(&self, _: RegionId, _: crate::types::CancelKind) {}
        fn drain_completed(&self, _: RegionId, _: std::time::Duration) {}
        fn deadline_set(&self, _: RegionId, _: std::time::Duration) {}
        fn deadline_exceeded(&self, _: RegionId) {}
        fn deadline_warning(&self, _: &str, _: &'static str, _: std::time::Duration) {}
        fn deadline_violation(&self, _: &str, _: std::time::Duration) {}
        fn deadline_remaining(&self, _: &str, _: std::time::Duration) {}
        fn checkpoint_interval(&self, _: &str, _: std::time::Duration) {}
        fn task_stuck_detected(&self, _: &str) {}
        fn obligation_created(&self, _: RegionId) {
            let mut remaining = self.remaining.load(Ordering::SeqCst);
            while remaining > 0 {
                if let Err(observed) = self.remaining.compare_exchange_weak(
                    remaining,
                    remaining - 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    remaining = observed;
                    continue;
                }
                let token = self
                    .cx
                    .try_register_obligation(ObligationKind::SendPermit, self.cx.task_id())
                    .expect("producer posts while the captured backlog is draining");
                assert!(token.commit());
                break;
            }
        }
        fn obligation_discharged(&self, _: RegionId) {}
        fn obligation_leaked(&self, _: RegionId) {}
        fn scheduler_tick(&self, _: usize, _: std::time::Duration) {}
    }

    #[test]
    fn completion_obligation_drain_captures_once_despite_new_publications() {
        let mut runtime = lab();
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (holder, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, std::future::pending::<()>())
            .expect("live holder");
        let cx = runtime.state.task(holder).unwrap().cx.clone().unwrap();
        let metrics = Arc::new(PostingDuringAdmissionMetrics {
            cx: cx.clone(),
            remaining: AtomicUsize::new(80),
        });
        runtime.state.set_metrics_provider(metrics.clone());
        let mailbox = mailbox_of(&runtime);
        assert!(
            cx.try_register_obligation(ObligationKind::SendPermit, holder)
                .unwrap()
                .commit()
        );
        assert_eq!(mailbox.len(), 2);

        // The first Reserve callback publishes another reserve+commit pair.
        // A reloading/unbounded drain would process 162 posts; the captured
        // prefix must stop after the original two, leaving the new pair live.
        let applied = runtime.state.drain_obligation_posts_before_completion(None);
        assert_eq!(applied, 2);
        assert_eq!(metrics.remaining.load(Ordering::SeqCst), 79);
        assert_eq!(mailbox.len(), 2);
        assert_eq!(mailbox.stats().posted, 4);
        assert_eq!(mailbox.stats().applied, 2);
        metrics.remaining.store(0, Ordering::SeqCst);
        assert_eq!(
            runtime.state.drain_obligation_posts_before_completion(None),
            2
        );
        let stats = mailbox.stats();
        assert_eq!(stats.reserved, 2);
        assert_eq!(stats.committed, 2);
        assert_eq!(stats.refused, 0);
        assert_eq!(mailbox.open_tickets(), 0);
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert!(mailbox.is_empty());
        eprintln!(
            "completion snapshot initial_posts=2 first_applied={applied} queued_after_first=2 final_stats={stats:?}"
        );
    }

    #[test]
    fn register_then_commit_is_applied_through_runtime_state() {
        let mut runtime = lab();
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let observed = Arc::new(AtomicUsize::new(0));
        let observed_in_task = Arc::clone(&observed);
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task has a current cx");
                let token = cx
                    .try_register_obligation(ObligationKind::SendPermit, cx.task_id())
                    .expect("runtime-built cx carries the gateway");
                assert_eq!(token.kind(), ObligationKind::SendPermit);
                assert!(token.commit());
                observed_in_task.fetch_add(1, Ordering::Relaxed);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        let mailbox = mailbox_of(&runtime);

        runtime.run_until_quiescent();

        assert_eq!(observed.load(Ordering::Relaxed), 1, "task body ran");
        let stats = mailbox.stats();
        assert_eq!(stats.posted, 2, "reserve + commit");
        assert_eq!(stats.applied, 2);
        assert_eq!(stats.reserved, 1);
        assert_eq!(stats.committed, 1);
        assert_eq!(stats.refused, 0);
        assert_eq!(mailbox.open_tickets(), 0);
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert!(runtime.is_quiescent());
        assert_eq!(runtime.state.leak_count(), 0);
    }

    #[test]
    fn register_then_abort_is_applied_with_the_reason() {
        let mut runtime = lab();
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task has a current cx");
                let token = cx
                    .try_register_obligation(ObligationKind::SemaphorePermit, cx.task_id())
                    .expect("gateway");
                assert!(token.abort(ObligationAbortReason::Cancel));
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        let mailbox = mailbox_of(&runtime);

        runtime.run_until_quiescent();

        let stats = mailbox.stats();
        assert_eq!(stats.reserved, 1);
        assert_eq!(stats.aborted, 1);
        assert_eq!(stats.refused, 0);
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert_eq!(runtime.state.leak_count(), 0);
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn dropping_an_unresolved_token_is_recorded_as_a_leak() {
        let mut runtime = lab();
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task has a current cx");
                let token = cx
                    .try_register_obligation(ObligationKind::SendPermit, cx.task_id())
                    .expect("gateway");
                // Forgotten on purpose: the drop must post a Leak, never panic.
                drop(token);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        let mailbox = mailbox_of(&runtime);

        runtime.run_until_quiescent();

        let stats = mailbox.stats();
        assert_eq!(stats.reserved, 1);
        assert_eq!(stats.leaked, 1, "{stats:?}");
        assert_eq!(stats.refused, 0, "{stats:?}");
        assert_eq!(
            runtime.state.leak_count(),
            1,
            "the runtime's leak policy counted the dropped token exactly once"
        );
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert_eq!(mailbox.open_tickets(), 0);
        let kinds: Vec<TraceEventKind> = runtime
            .state
            .trace_handle()
            .snapshot()
            .into_iter()
            .map(|event| event.kind)
            .filter(|kind| {
                matches!(
                    kind,
                    TraceEventKind::ObligationLeak | TraceEventKind::ObligationAbort
                )
            })
            .collect();
        assert_eq!(kinds, vec![TraceEventKind::ObligationLeak]);
    }

    #[test]
    fn a_dropped_token_is_auto_aborted_when_the_leak_policy_escalates_to_recover() {
        let mut runtime = lab();
        runtime.state.set_leak_escalation(Some(LeakEscalation::new(
            1,
            ObligationLeakResponse::Recover,
        )));
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task has a current cx");
                let token = cx
                    .try_register_obligation(ObligationKind::SendPermit, cx.task_id())
                    .expect("gateway");
                drop(token);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        let mailbox = mailbox_of(&runtime);

        runtime.run_until_quiescent();

        let stats = mailbox.stats();
        assert_eq!(stats.leaked, 1, "{stats:?}");
        assert_eq!(stats.refused, 0, "{stats:?}");
        assert_eq!(
            runtime.state.leak_count(),
            1,
            "the escalation threshold saw it"
        );
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        let kinds: Vec<TraceEventKind> = runtime
            .state
            .trace_handle()
            .snapshot()
            .into_iter()
            .map(|event| event.kind)
            .filter(|kind| {
                matches!(
                    kind,
                    TraceEventKind::ObligationLeak | TraceEventKind::ObligationAbort
                )
            })
            .collect();
        assert_eq!(
            kinds,
            vec![TraceEventKind::ObligationAbort],
            "Recover aborts the obligation instead of marking it leaked"
        );
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn semaphore_permits_register_and_resolve_runtime_obligations() {
        let mut runtime = lab();
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task has a current cx");
                let semaphore = crate::sync::Semaphore::new(4);

                // Released back to the semaphore: the obligation is discharged.
                let permit = semaphore.acquire(&cx, 1).await.expect("acquire");
                drop(permit);

                // Explicit commit is the same discharge on a different path.
                let permit = semaphore.acquire(&cx, 1).await.expect("acquire");
                permit.commit();

                // Forgotten on purpose: capacity is intentionally kept, which
                // is an abort, not a leak.
                let permit = semaphore.acquire(&cx, 1).await.expect("acquire");
                permit.forget();

                // Zero permits hold no capacity, so they mint nothing at all.
                let permit = semaphore.acquire(&cx, 0).await.expect("acquire zero");
                drop(permit);

                // try_acquire has no `Cx` in its signature; it picks the
                // current one up from the task-local.
                let permit = semaphore.try_acquire(1).expect("try_acquire");
                drop(permit);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        let mailbox = mailbox_of(&runtime);

        runtime.run_until_quiescent();

        let stats = mailbox.stats();
        assert_eq!(
            stats.reserved, 4,
            "three acquires plus try_acquire; the zero-permit acquire mints nothing: {stats:?}"
        );
        assert_eq!(
            stats.committed, 3,
            "drop, commit and the try_acquire drop all release capacity: {stats:?}"
        );
        assert_eq!(stats.aborted, 1, "forget keeps the capacity: {stats:?}");
        assert_eq!(stats.leaked, 0, "{stats:?}");
        assert_eq!(stats.refused, 0, "{stats:?}");
        assert_eq!(mailbox.open_tickets(), 0);
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert_eq!(runtime.state.leak_count(), 0);
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn a_cx_without_a_runtime_returns_none_and_tracks_nothing() {
        let cx = Cx::for_testing();
        assert!(
            cx.try_register_obligation(ObligationKind::SendPermit, cx.task_id())
                .is_none(),
            "hand-built Cx has no gateway: today's untracked behaviour is preserved"
        );
    }

    /// br-asupersync-bi2462.14: the stock channel permits go through the
    /// seam.
    ///
    /// mpsc reserve+send commits, reserve+abort aborts explicitly,
    /// reserve+drop aborts as a cancellation; oneshot reserve+send commits;
    /// broadcast reserve+send commits and reserve+drop aborts.
    #[test]
    fn channel_permits_register_and_resolve_runtime_obligations() {
        let mut runtime = lab();
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task has a current cx");

                let (tx, rx) = crate::channel::mpsc::channel::<u8>(4);
                let permit = tx.reserve(&cx).await.expect("mpsc reserve");
                let _ = permit.send(1);
                let permit = tx.reserve(&cx).await.expect("mpsc reserve");
                permit.abort();
                let permit = tx.reserve(&cx).await.expect("mpsc reserve");
                drop(permit);
                drop(rx);

                let (otx, orx) = crate::channel::oneshot::channel::<u8>();
                let permit = otx.reserve(&cx).expect("oneshot reserve");
                permit.send(7).expect("oneshot send");
                drop(orx);

                let (btx, brx) = crate::channel::broadcast::channel::<u8>(4);
                let permit = btx.reserve(&cx).expect("broadcast reserve");
                let _ = permit.send(3);
                let permit = btx.reserve(&cx).expect("broadcast reserve");
                drop(permit);
                drop(brx);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        let mailbox = mailbox_of(&runtime);

        runtime.run_until_quiescent();

        let stats = mailbox.stats();
        assert_eq!(stats.reserved, 6, "{stats:?}");
        assert_eq!(
            stats.committed, 3,
            "mpsc send, oneshot send, broadcast send: {stats:?}"
        );
        assert_eq!(
            stats.aborted, 3,
            "mpsc abort, mpsc drop, broadcast drop: {stats:?}"
        );
        assert_eq!(stats.leaked, 0, "{stats:?}");
        assert_eq!(stats.refused, 0, "{stats:?}");
        assert_eq!(mailbox.open_tickets(), 0);
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert_eq!(runtime.state.leak_count(), 0);
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn many_register_commit_rounds_apply_exactly_and_leave_nothing_pending() {
        const ROUNDS: u64 = 10_000;
        let mut runtime = lab();
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = runtime
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task has a current cx");
                for _ in 0..ROUNDS {
                    let token = cx
                        .try_register_obligation(ObligationKind::SendPermit, cx.task_id())
                        .expect("gateway");
                    assert!(token.commit());
                }
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        let mailbox = mailbox_of(&runtime);

        runtime.run_until_quiescent();

        let stats = mailbox.stats();
        assert_eq!(stats.posted, 2 * ROUNDS);
        assert_eq!(stats.applied, 2 * ROUNDS);
        assert_eq!(stats.reserved, ROUNDS);
        assert_eq!(stats.committed, ROUNDS);
        assert_eq!(stats.refused, 0);
        assert!(mailbox.is_empty());
        assert_eq!(
            mailbox.open_tickets(),
            0,
            "the ticket table does not grow per post"
        );
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert!(runtime.is_quiescent());
    }

    /// Completes once `flag` is set; parks its waker otherwise so the task
    /// stays parked (not re-scheduled) until the test wakes it.
    struct WaitForFlag {
        flag: Arc<std::sync::atomic::AtomicBool>,
        waker: Arc<parking_lot::Mutex<Option<std::task::Waker>>>,
    }

    impl std::future::Future for WaitForFlag {
        type Output = ();

        fn poll(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<()> {
            if self.flag.load(Ordering::Acquire) {
                std::task::Poll::Ready(())
            } else {
                *self.waker.lock() = Some(cx.waker().clone());
                std::task::Poll::Pending
            }
        }
    }

    #[test]
    fn a_posted_reservation_keeps_the_region_from_looking_quiescent_until_applied() {
        let mut runtime = lab();
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker: Arc<parking_lot::Mutex<Option<std::task::Waker>>> =
            Arc::new(parking_lot::Mutex::new(None));
        let (task, _handle) = {
            let flag = Arc::clone(&flag);
            let waker = Arc::clone(&waker);
            runtime
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().expect("lab task has a current cx");
                    let token = cx
                        .try_register_obligation(ObligationKind::SendPermit, cx.task_id())
                        .expect("gateway");
                    // Hold the token while parked, so the reservation is
                    // outstanding with no poll able to resolve it.
                    WaitForFlag { flag, waker }.await;
                    assert!(token.commit());
                })
                .expect("create task")
        };
        runtime.scheduler.lock().schedule(task, 0);
        let mailbox = mailbox_of(&runtime);
        let post_credits = |runtime: &LabRuntime| {
            runtime
                .state
                .region(root)
                .map_or(u32::MAX, |region| region.pending_obligation_post_count())
        };

        // The task polls once, posts Reserve, parks. The reservation is
        // visible as an undrained post, an applied pending obligation, or the
        // region's held credit; the runtime is NOT quiescent.
        runtime.run_until_idle();
        assert_eq!(post_credits(&runtime), 1, "the live token holds one credit");
        assert!(
            !mailbox.is_empty() || runtime.state.pending_obligation_count() >= 1,
            "reservation must be posted or applied while the token lives"
        );
        assert!(!runtime.is_quiescent());

        flag.store(true, Ordering::Release);
        if let Some(waker) = waker.lock().take() {
            waker.wake();
        }
        runtime.run_until_quiescent();
        assert_eq!(mailbox.stats().committed, 1);
        assert_eq!(runtime.state.pending_obligation_count(), 0);
        assert_eq!(post_credits(&runtime), 0, "credit released with the token");
        assert!(runtime.is_quiescent());
    }
}
