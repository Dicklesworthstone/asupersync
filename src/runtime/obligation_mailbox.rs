//! Obligation mailbox: how a primitive holding only a `&Cx` mints and
//! resolves a runtime-tracked obligation (br-asupersync-bi2462.13).
//!
//! # Why a mailbox
//!
//! Every reserved permit is meant to be a tracked obligation, so region close
//! can prove "no leaked permits" and the lab's obligation-leak oracle sees it.
//! The obligation table lives inside [`RuntimeState`]: in Unified mode it is
//! embedded (`RuntimeState::obligations`), the production runtime reaches it
//! only through `Arc<Mutex<RuntimeState>>`, and the [`LabRuntime`](crate::lab::LabRuntime) owns its
//! state by value and polls task futures from inside its own step. A future
//! being polled therefore has no path to `&mut RuntimeState`, and neither has
//! a `Cx`. The spawn path solves exactly this with the
//! [`SpawnGateway`](crate::runtime::spawn_mailbox::SpawnGateway) mailbox that
//! the runtime drains at step start; obligations use the same shape.
//!
//! # Shape
//!
//! * [`ObligationGateway`](crate::runtime::obligation_mailbox::ObligationGateway) (crate-private, attached to every task `Cx` by the
//!   runtime) posts [`ObligationPost`](crate::runtime::obligation_mailbox::ObligationPost) messages onto an unbounded lock-free
//!   FIFO ([`ObligationMailbox`](crate::runtime::obligation_mailbox::ObligationMailbox)). Checked posts also carry their owned credit.
//! * `Cx::try_register_obligation` (crate-private)
//!   mints a ticket, reserves one credit on the region's pending-post counter
//!   (so `is_quiescent` / drain gating see the reservation BEFORE the runtime
//!   drains it, the way `PendingSpawnCounter` works for spawns), posts
//!   `Reserve`, and returns an [`ObligationToken`](crate::runtime::obligation_mailbox::ObligationToken).
//! * [`ObligationToken::commit`](crate::runtime::obligation_mailbox::ObligationToken::commit) / [`ObligationToken::abort`](crate::runtime::obligation_mailbox::ObligationToken::abort) post the
//!   resolution; dropping an unresolved token posts `Leak` (never panics).
//! * The runtime drains the mailbox where it drains spawn admissions
//!   (`apply_obligation_posts`): `Reserve` -> `RuntimeState::create_obligation`
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

/// Why an explicit consuming handoff did not acquire destination ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ObligationTransferError {
    /// Legacy tokens retain their original holder's liability.
    #[error("only checked obligation tokens can be transferred")]
    SourceNotChecked,
    /// A terminal outcome already won the source credit.
    #[error("source obligation is already resolved")]
    SourceResolved,
    /// Direct-ID settlement closed admission before choosing its terminal.
    #[error("source obligation settlement has started")]
    SourceSettlementStarted,
    /// Completion revoked the source generation.
    #[error("source obligation holder is no longer live")]
    SourceHolderNotLive,
    /// Either runtime gateway is unavailable.
    #[error("obligation transfer runtime is unavailable")]
    RuntimeUnavailable,
    /// A handoff cannot cross runtime arenas.
    #[error("obligation transfer requires the same runtime")]
    DifferentRuntime,
    /// Ownership already belongs to this holder.
    #[error("obligation transfer requires a different holder")]
    SameHolder,
    /// The destination context has a cancellation request.
    #[error("obligation transfer destination is cancelled")]
    DestinationCancelled,
    /// Destination admission refused before either credit changed.
    #[error("obligation transfer destination refused admission: {0}")]
    Destination(ObligationAdmissionError),
}

/// A refused handoff retaining the original token for explicit recovery.
/// Dropping the failure retains the token's ordinary unresolved-drop behavior.
#[derive(Debug)]
pub struct ObligationTransferFailure {
    reason: ObligationTransferError,
    token: ObligationToken,
}

impl ObligationTransferFailure {
    /// The reason the handoff was refused.
    #[must_use]
    pub fn reason(&self) -> ObligationTransferError {
        self.reason
    }

    /// Recover the reason and original token, with its original ticket/holder.
    #[must_use]
    pub fn into_parts(self) -> (ObligationTransferError, ObligationToken) {
        (self.reason, self.token)
    }
}

impl std::fmt::Display for ObligationTransferFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.reason, f)
    }
}

impl std::error::Error for ObligationTransferFailure {}

#[derive(Debug)]
enum AdmissionDecision {
    Pending,
    Terminal(ObligationResolution),
    HandedOff(Arc<AdmittedObligation>),
}

/// Read under the owning region's admission gate by the projection checker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObligationCreditProjection {
    Pending,
    Terminal,
    HandedOff,
    Inactive,
}

/// Owned, preaccepted admission; the arena is its delayed lifecycle projection.
#[derive(Debug)]
pub(crate) struct AdmittedObligation {
    handle: Arc<crate::record::region::ObligationAdmissionHandle>,
    mailbox: Weak<ObligationMailbox>,
    ticket: u64,
    active: AtomicBool,
    resolution: Mutex<AdmissionDecision>,
    settlement_started: Arc<AtomicBool>,
    predecessor: Weak<AdmittedObligation>,
    application_finished: AtomicBool,
}

impl AdmittedObligation {
    pub(crate) fn fence_transfers(&self) {
        self.settlement_started.store(true, Ordering::SeqCst);
    }

    fn resolve(&self, resolution: ObligationResolution, publish: impl FnOnce()) -> bool {
        if !self.active.load(Ordering::Acquire) {
            return false;
        }
        self.handle.settle(|| {
            let mut terminal = self
                .resolution
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !matches!(*terminal, AdmissionDecision::Pending) {
                return false;
            }
            *terminal = AdmissionDecision::Terminal(resolution);
            publish();
            true
        })
    }

    pub(crate) fn claim_resolution(
        &self,
        resolution: ObligationResolution,
    ) -> Option<ObligationResolution> {
        self.resolve(resolution, || {});
        match &*self
            .resolution
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            AdmissionDecision::Terminal(resolution) => Some(*resolution),
            AdmissionDecision::HandedOff(_) => None,
            AdmissionDecision::Pending => unreachable!("active credit has a decision"),
        }
    }

    pub(crate) fn successor(&self) -> Option<Arc<Self>> {
        match &*self
            .resolution
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            AdmissionDecision::HandedOff(next) => Some(Arc::clone(next)),
            AdmissionDecision::Pending | AdmissionDecision::Terminal(_) => None,
        }
    }

    pub(crate) fn binding(&self) -> (u64, TaskId, RegionId) {
        (self.ticket, self.handle.holder(), self.handle.region())
    }

    pub(crate) fn projection_state(&self) -> ObligationCreditProjection {
        if !self.active.load(Ordering::Acquire) || self.application_finished.load(Ordering::Acquire)
        {
            return ObligationCreditProjection::Inactive;
        }
        match &*self
            .resolution
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            AdmissionDecision::Pending => ObligationCreditProjection::Pending,
            AdmissionDecision::Terminal(_) => ObligationCreditProjection::Terminal,
            AdmissionDecision::HandedOff(_) => ObligationCreditProjection::HandedOff,
        }
    }

    pub(crate) fn bind_ticket(&self, id: ObligationId) {
        if let Some(mailbox) = self.mailbox.upgrade() {
            mailbox
                .tickets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(self.ticket, id);
        }
    }

    fn finish_lineage_after_runtime_drop(&self) {
        self.finish_application();
        let mut previous = self.predecessor.upgrade();
        while let Some(credit) = previous {
            credit.finish_application();
            previous = credit.predecessor.upgrade();
        }
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

    fn take_successor_for_drop(&mut self) -> Option<Arc<Self>> {
        let decision = self
            .resolution
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match std::mem::replace(decision, AdmissionDecision::Pending) {
            AdmissionDecision::HandedOff(next) => Some(next),
            AdmissionDecision::Pending | AdmissionDecision::Terminal(_) => None,
        }
    }
}

impl Drop for AdmittedObligation {
    fn drop(&mut self) {
        let mut successor = self.take_successor_for_drop();
        while let Some(next) = successor {
            match Arc::into_inner(next) {
                Some(mut owned) => {
                    successor = owned.take_successor_for_drop();
                    // Its Drop now sees Pending, never the remaining chain.
                }
                // A shared decrement cannot drop the inner value here. With
                // try_unwrap, another owner could disappear before dropping
                // Err(shared), reentering this destructor recursively.
                None => break,
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum QueuedObligationPost {
    Operation {
        post: ObligationPost,
        admission: Option<Arc<AdmittedObligation>>,
    },
    Handoff {
        source: Arc<AdmittedObligation>,
    },
}

struct PendingReceipt<'a>(&'a AtomicU64);

impl Drop for PendingReceipt<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Counts one dequeued post as applied when its application ends, also when
/// it unwinds.
struct AppliedReceipt<'a>(&'a AtomicU64);

impl Drop for AppliedReceipt<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
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
    pending_handoffs: AtomicU64,
    pending_admissions: AtomicU64,
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
        if post.op == ObligationOp::Reserve && admission.is_some() {
            self.pending_admissions.fetch_add(1, Ordering::Release);
        }
        // Count before publishing so observers see posted >= applied.
        self.posted.fetch_add(1, Ordering::Relaxed);
        self.queue
            .push(QueuedObligationPost::Operation { post, admission });
    }

    pub(crate) fn has_pending_handoffs(&self) -> bool {
        self.pending_handoffs.load(Ordering::Acquire) != 0
    }

    pub(crate) fn has_pending_ownership_projection(&self) -> bool {
        self.has_pending_handoffs() || self.pending_admissions.load(Ordering::Acquire) != 0
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

    pub(crate) fn ticket_binding(&self, ticket: u64) -> Option<ObligationId> {
        self.tickets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&ticket)
            .copied()
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
            resolution: Mutex::new(AdmissionDecision::Pending),
            settlement_started: Arc::new(AtomicBool::new(false)),
            predecessor: Weak::new(),
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
/// `Cx::try_register_obligation` (crate-private).
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

    /// Transfer a checked obligation to another live holder in the same runtime.
    ///
    /// This consumes the old token, preserves its logical obligation identity
    /// and reservation age, and returns a new ticket bound to `destination`.
    /// A plain Rust move does not transfer holder liability. Same-region
    /// handoffs reuse live quota, including a region already at its limit.
    ///
    /// # Errors
    /// Refusal returns the original token inside [`ObligationTransferFailure`].
    /// A completion which already resolved that credit is not undone.
    /// A panicking notification aborts the accepted, unreturned destination
    /// credit; it cannot restore ownership to the consumed source.
    #[allow(clippy::result_large_err)]
    pub fn try_transfer<Caps>(
        mut self,
        destination: &crate::cx::Cx<Caps>,
    ) -> Result<Self, ObligationTransferFailure> {
        match self.prepare_transfer(destination) {
            Err(reason) => Err(ObligationTransferFailure {
                reason,
                token: self,
            }),
            Ok((mut next, gateway)) => {
                self.resolved = true;
                gateway.notify();
                next.abort_on_drop = false;
                Ok(next)
            }
        }
    }

    fn prepare_transfer<Caps>(
        &self,
        destination: &crate::cx::Cx<Caps>,
    ) -> Result<(Self, Arc<ObligationGateway>), ObligationTransferError> {
        use ObligationTransferError as Error;
        let source = self.admission.as_ref().ok_or(Error::SourceNotChecked)?;
        let source_gateway = self.gateway.upgrade().ok_or(Error::RuntimeUnavailable)?;
        let _source_liveness = source_gateway
            .runtime_liveness
            .upgrade()
            .ok_or(Error::RuntimeUnavailable)?;
        let (gateway, handle) = destination
            .obligation_transfer_destination()
            .map_err(Error::Destination)?;
        let _destination_liveness = gateway
            .runtime_liveness
            .upgrade()
            .ok_or(Error::RuntimeUnavailable)?;
        if !Arc::ptr_eq(&source_gateway.mailbox, &gateway.mailbox) {
            return Err(Error::DifferentRuntime);
        }
        if self.holder == handle.holder() {
            return Err(Error::SameHolder);
        }
        if destination.is_cancel_requested() {
            return Err(Error::DestinationCancelled);
        }
        let ticket = gateway.mailbox.mint_ticket().ok_or(Error::Destination(
            ObligationAdmissionError::CapacityExhausted,
        ))?;
        let admission = Arc::new(AdmittedObligation {
            handle: Arc::clone(handle),
            mailbox: Arc::downgrade(&gateway.mailbox),
            ticket,
            active: AtomicBool::new(false),
            resolution: Mutex::new(AdmissionDecision::Pending),
            settlement_started: Arc::clone(&source.settlement_started),
            predecessor: Arc::downgrade(source),
            application_finished: AtomicBool::new(false),
        });
        let next = Self {
            ticket,
            kind: self.kind,
            holder: handle.holder(),
            region: handle.region(),
            gateway: Arc::downgrade(gateway),
            _pending: None,
            resolved: false,
            admission: Some(Arc::clone(&admission)),
            abort_on_drop: true,
        };
        source.handle.transfer_to(
            handle,
            || {
                let mut decision = source
                    .resolution
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !matches!(*decision, AdmissionDecision::Pending) {
                    return Err(Error::SourceResolved);
                }
                if source.settlement_started.load(Ordering::SeqCst) {
                    return Err(Error::SourceSettlementStarted);
                }
                *decision = AdmissionDecision::HandedOff(Arc::clone(&admission));
                Ok(())
            },
            || {
                admission.active.store(true, Ordering::Release);
                gateway
                    .mailbox
                    .pending_handoffs
                    .fetch_add(1, Ordering::Release);
                gateway.mailbox.posted.fetch_add(1, Ordering::Relaxed);
                gateway.mailbox.queue.push(QueuedObligationPost::Handoff {
                    source: Arc::clone(source),
                });
            },
        )?;
        Ok((next, Arc::clone(gateway)))
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
            admission.finish_lineage_after_runtime_drop();
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
        state.check_obligation_conservation_after_drain(mailbox);
        return 0;
    }
    // One post at a time: a post whose application unwinds (a leak under the
    // Panic policy, a panicking metrics callback) leaves the posts behind it
    // queued for the next drain. A local batch dropped them, so a Reserve
    // behind it never created its record and its region could never close.
    let mut drained = 0;
    while drained < max {
        let Some(queued) = mailbox.queue.pop() else {
            break;
        };
        drained += 1;
        let _applied = AppliedReceipt(&mailbox.applied);
        let (post, admission) = match queued {
            QueuedObligationPost::Operation { post, admission } => (post, admission),
            QueuedObligationPost::Handoff { source } => {
                let _pending_receipt = PendingReceipt(&mailbox.pending_handoffs);
                if !source.application_finished.load(Ordering::Acquire) {
                    let id = mailbox
                        .tickets
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .get(&source.ticket)
                        .copied();
                    if state
                        .apply_obligation_post_from_dispatch_table(
                            QueuedObligationPost::Handoff { source },
                            id,
                            dispatch_tasks,
                        )
                        .is_err()
                    {
                        mailbox.refused.fetch_add(1, Ordering::Relaxed);
                    }
                }
                continue;
            }
        };
        let _pending_receipt = (post.op == ObligationOp::Reserve && admission.is_some())
            .then(|| PendingReceipt(&mailbox.pending_admissions));
        // A completion audit can apply the shared terminal decision before a
        // late queued receipt reaches this bounded drain. It is not a refusal.
        if admission
            .as_ref()
            .is_some_and(|credit| credit.application_finished.load(Ordering::Acquire))
        {
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
                    QueuedObligationPost::Operation {
                        post,
                        admission: admission.clone(),
                    },
                    id,
                    dispatch_tasks,
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
    }
    // Ticket insertion/removal and receipt barriers are complete here. Checking
    // inside an individual apply would observe those legitimate partial writes.
    state.check_obligation_conservation_after_drain(mailbox);
    drained
}

#[cfg(test)]
#[path = "obligation_mailbox_inline_tests.rs"]
mod tests;
