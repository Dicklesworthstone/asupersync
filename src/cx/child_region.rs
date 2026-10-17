//! Owned child regions derived from an ambient [`Cx`](crate::cx::Cx)
//! (bd-asupersync-ambient-child-region-0fm8l).
//!
//! Server-style callers (request handlers, connection pumps) hold only
//! `&Cx`; the legacy `Scope::region` family cannot serve them because it
//! borrows `RuntimeState` exclusively for the child's whole lifetime. This
//! module adds the missing surface: derive an owned child region from the
//! ambient context, spawn its body through the standard gateway path, and
//! request independent cancellation or quiescent close — all without ever
//! holding runtime state outside the scheduler.
//!
//! # Semantics
//!
//! - **Structured ownership:** the child region is minted under the ambient
//!   context's region, so parent cancellation propagates through the normal
//!   region-tree protocol and every spawned task stays region-owned.
//! - **Independent cancellation:** [`ChildRegion::cancel`] drives the same
//!   request→drain→finalize protocol for this subtree only.
//! - **Close = quiescence:** [`ChildRegion::close`] begins the close
//!   protocol (cancel remaining children, run finalizers) and resolves only
//!   when the region reaches `Closed` — no live children, finalizers done.
//!   Dropping the handle requests the same close best-effort.
//! - **Bounded close:** [`ChildRegion::close_within`] begins the same close
//!   but waits at most a bound on the runtime's clock. On timeout it reports
//!   the tasks still running instead of waiting forever for one that never
//!   observes cancellation. Those tasks stay owned by the closing region.
//! - **No ambient authority:** everything flows through the caller's `Cx`
//!   capability wiring. A detached Cx without a runtime gateway fails closed
//!   with [`ChildRegionError::NoRuntimeGateway`].
//!
//! The mint itself is command-driven: the producer enqueues a plain-data
//! region command through the spawn gateway's liveness guard, the scheduler
//! performs the authoritative record transitions at its existing dispatch
//! point, and the outcome is published into a caller-shared slot after the
//! runtime lock drops.

use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use parking_lot::Mutex;

use crate::record::region::RegionCloseState;
use crate::runtime::region_table::RegionCreateError;
use crate::runtime::resource_monitor::RegionPriority;
use crate::runtime::spawn_mailbox::{
    AdmittedRegionSlot, RegionCommand, RegionLiveTasksQuery, SpawnGateway, TeardownWake,
};
use crate::types::{
    Budget, CancelReason, CapabilityBudget, CapabilityBudgetRequirements, RegionId, TaskId,
};

/// Admission envelope for [`Cx::open_child_region`](crate::cx::Cx::open_child_region).
///
/// Every field is optional; omitted dimensions inherit the ambient context's
/// values, and the effective scheduler budget is always the meet of parent
/// and request, so a child can never relax its parent's constraints.
#[derive(Debug, Clone)]
pub struct ChildRegionSpec {
    /// Requested scheduler budget (`None` inherits the ambient budget).
    pub budget: Option<Budget>,
    /// Requested capability budget (`None` inherits).
    pub capability_budget: Option<CapabilityBudget>,
    /// Required capability dimensions (admission fails closed when neither
    /// parent nor child supplies a non-exhausted envelope).
    pub requirements: CapabilityBudgetRequirements,
    /// Resource-pressure admission priority.
    pub priority: RegionPriority,
}

impl ChildRegionSpec {
    /// Inherits every dimension from the ambient context.
    #[must_use]
    pub const fn inherit() -> Self {
        Self {
            budget: None,
            capability_budget: None,
            requirements: CapabilityBudgetRequirements::NONE,
            priority: RegionPriority::Normal,
        }
    }

    /// Overrides the requested scheduler budget.
    #[must_use]
    pub const fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Overrides the resource-pressure admission priority.
    #[must_use]
    pub const fn with_priority(mut self, priority: RegionPriority) -> Self {
        self.priority = priority;
        self
    }
}

/// Failure modes of deriving an owned child region from an ambient `&Cx`.
#[derive(Debug)]
pub enum ChildRegionError {
    /// The context was built without runtime wiring (detached/ad-hoc Cx).
    /// There is no gateway to carry the mint command, so derivation fails
    /// closed instead of inventing ambient authority.
    NoRuntimeGateway,
    /// The owning runtime shut down before or while the mint was pending,
    /// or the caller's runtime capability mask forbids region spawning.
    RuntimeUnavailable,
    /// The authoritative mint rejected the child region (parent closed,
    /// missing, at capacity, or under resource pressure).
    Create(RegionCreateError),
}

impl std::fmt::Display for ChildRegionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRuntimeGateway => {
                write!(f, "context has no runtime gateway for region derivation")
            }
            Self::RuntimeUnavailable => write!(f, "owning runtime is no longer available"),
            Self::Create(error) => write!(f, "child region mint failed: {error}"),
        }
    }
}

impl std::error::Error for ChildRegionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Create(error) => Some(error),
            _ => None,
        }
    }
}

/// How a [`ChildRegion::close_within`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChildRegionCloseOutcome {
    /// The region reached `Closed` within the bound: its tasks and child
    /// regions finished and its finalizers ran.
    Quiescent,
    /// The bound elapsed first. The region keeps closing. Its unfinished
    /// tasks stay owned by it, and an ancestor's close or the root drain
    /// finishes them. Nothing is force-dropped.
    TimedOut,
}

/// What a [`ChildRegion::close_within`] observed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChildRegionCloseReport {
    /// Whether the region closed within the bound.
    pub outcome: ChildRegionCloseOutcome,
    /// Time from the close request until the region closed or the bound
    /// elapsed, on the runtime's clock (virtual time under the lab runtime).
    pub elapsed: Duration,
    /// Tasks of the region and its descendant regions that had not finished
    /// when the bound elapsed, in depth-first region order. Empty when
    /// quiescent. A straggler that finishes between the timeout and this
    /// snapshot is not listed.
    pub stragglers: Vec<TaskId>,
}

impl From<RegionCreateError> for ChildRegionError {
    fn from(error: RegionCreateError) -> Self {
        Self::Create(error)
    }
}

/// Future resolving to an owned [`ChildRegion`] once the scheduler mints it.
///
/// Polling registers the waker on the shared slot; publication wakes the
/// opener directly. Derivation failures — including a detached context with
/// no runtime gateway and a runtime that vanished while pending — resolve as
/// [`ChildRegionError`] instead of panicking or hanging.
///
/// Dropping an opening before it resolves (a timeout, a lost race, an aborted
/// task) closes the region it would have opened, so the region never stays
/// open without an owner and a parent's close never waits for it.
///
/// `Caps` is the opener's compile-time capability set. The child's principal
/// context carries the same set, so opening a region cannot widen a restricted
/// context back to `cap::All` (asupersync-cwxavr).
#[must_use = "an opening that is never awaited never observes its mint outcome"]
pub struct ChildRegionOpening<Caps = crate::cx::cap::All> {
    pending: Option<(Arc<AdmittedRegionSlot>, Weak<()>)>,
    failure: Option<ChildRegionError>,
    parent_mask: crate::cx::cap::CapMask,
    parent_remote: Option<Arc<crate::remote::RemoteCap>>,
    caps: PhantomData<fn() -> Caps>,
}

impl<Caps> ChildRegionOpening<Caps> {
    pub(crate) fn new(
        slot: Arc<AdmittedRegionSlot>,
        liveness: Weak<()>,
        parent_mask: crate::cx::cap::CapMask,
        parent_remote: Option<Arc<crate::remote::RemoteCap>>,
    ) -> Self {
        Self {
            pending: Some((slot, liveness)),
            failure: None,
            parent_mask,
            parent_remote,
            caps: PhantomData,
        }
    }

    pub(crate) fn failed(error: ChildRegionError) -> Self {
        Self {
            pending: None,
            failure: Some(error),
            parent_mask: crate::cx::cap::CapMask::none(),
            parent_remote: None,
            caps: PhantomData,
        }
    }
}

impl<Caps> Future for ChildRegionOpening<Caps> {
    type Output = Result<ChildRegion<Caps>, ChildRegionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(error) = this.failure.take() {
            return Poll::Ready(Err(error));
        }
        let Some((slot, liveness)) = this.pending.as_ref() else {
            return Poll::Ready(Err(ChildRegionError::RuntimeUnavailable));
        };
        if let Some(outcome) = slot.take() {
            this.pending = None;
            return Poll::Ready(match outcome {
                Ok(mut admitted) => {
                    // The scheduler mints the principal with runtime wiring.
                    // Publication must not restore capabilities that the
                    // opener's ambient context had already relinquished.
                    admitted.cx.runtime_mask = admitted.cx.runtime_mask.intersect(this.parent_mask);
                    // The scheduler cannot recover handles attached to this
                    // particular caller from the region record. Inherit the
                    // explicit remote handle without widening the mask or
                    // replacing the freshly minted identity and gateways.
                    admitted.cx = admitted.cx.with_remote_cap_handle(this.parent_remote.take());
                    Ok(ChildRegion::from_admitted(admitted))
                }
                Err(error) => Err(ChildRegionError::Create(error)),
            });
        }
        // Fail closed when the runtime vanished before publication; a live
        // runtime keeps the registration until the worker publishes. The
        // waker is registered first: teardown drops the liveness token and
        // only then wakes registered waiters, so a teardown racing this poll
        // is either seen here or wakes this registration.
        slot.register(cx.waker().clone());
        if liveness.upgrade().is_none() {
            this.pending = None;
            return Poll::Ready(Err(ChildRegionError::RuntimeUnavailable));
        }
        Poll::Pending
    }
}

impl<Caps> Drop for ChildRegionOpening<Caps> {
    fn drop(&mut self) {
        // The Create command is already queued. A region minted for an opening
        // that nobody awaits any more must still close: the slot closes one
        // minted later, and one minted already but never taken closes here
        // through the handle's drop backstop.
        if let Some((slot, _)) = self.pending.take()
            && let Some(Ok(admitted)) = slot.abandon()
        {
            drop(ChildRegion::<Caps>::from_admitted(admitted));
        }
    }
}

/// An owned child region derived from an ambient `&Cx`.
///
/// The principal context ([`ChildRegion::cx`]) carries the child region's
/// identity, effective (met) budget, and pending-spawn credits, so body work
/// spawned through it rides the standard admission path. Handlers that need
/// checkpoint-observable cancellation should run as spawned tasks — each
/// gets its own admission-built context wired to a real record.
///
/// `Caps` is the opener's compile-time capability set (`cap::All` for an
/// unrestricted opener), so [`ChildRegion::cx`] never exceeds it.
pub struct ChildRegion<Caps = crate::cx::cap::All> {
    region_id: RegionId,
    cx: crate::cx::Cx<Caps>,
    close_notify: Arc<Mutex<RegionCloseState>>,
    close_receipt: Arc<Mutex<Option<crate::record::region::RegionCloseOutcome>>>,
    gateway: Option<Arc<SpawnGateway>>,
    /// Set once a structured close has been requested for this handle
    /// ([`Self::close`]); defuses the [`Drop`] backstop so a completed close
    /// never enqueues a second, redundant Close command for a region that is
    /// already closing or closed.
    closed: bool,
}

impl<Caps> std::fmt::Debug for ChildRegion<Caps> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildRegion")
            .field("region_id", &self.region_id)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl<Caps> ChildRegion<Caps> {
    pub(crate) fn from_admitted(admitted: crate::runtime::spawn_mailbox::AdmittedRegion) -> Self {
        let handles = admitted.cx.spawn_gateway_handle();
        Self {
            region_id: admitted.region_id,
            // The scheduler mints a Cx<All>. Re-type it to the opener's
            // compile-time set; the runtime mask was already met with the
            // opener's in ChildRegionOpening::poll.
            cx: admitted.cx.retype(),
            close_notify: admitted.close_notify,
            close_receipt: admitted.close_receipt,
            gateway: handles,
            closed: false,
        }
    }

    /// The child region's identity.
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        self.region_id
    }

    /// Principal capability context for spawning body work into this region.
    #[must_use]
    pub fn cx(&self) -> &crate::cx::Cx<Caps> {
        &self.cx
    }

    /// Attach an owned value to real finalizer work before admitting a body.
    /// The acknowledgment prevents a caller from exposing the value before
    /// the runtime accepted its lifetime. Register this before user finalizers
    /// so LIFO cleanup retains it through their completion.
    pub(crate) async fn retain_until_finalized<T: Send + 'static>(
        &self,
        retained: T,
    ) -> Result<(), ChildRegionError> {
        let (complete, mut completed) = crate::channel::oneshot::channel();
        let request = crate::runtime::spawn_mailbox::RegisterRegionFinalizer::new(
            self.region_id,
            move || drop(retained),
            complete,
        );
        self.enqueue(RegionCommand::RegisterFinalizer(request))?;
        completed
            .recv_uninterruptible()
            .await
            .map_err(|_| ChildRegionError::RuntimeUnavailable)?
            .map_err(ChildRegionError::Create)
    }

    fn enqueue(&self, command: RegionCommand) -> Result<(), ChildRegionError> {
        let gateway = self
            .gateway
            .as_ref()
            .ok_or(ChildRegionError::NoRuntimeGateway)?;
        gateway
            .enqueue_region_command(command)
            .map_err(|_| ChildRegionError::RuntimeUnavailable)
    }

    /// Requests independent cancellation for this subtree.
    ///
    /// Drives the same request→drain→finalize protocol a parent would:
    /// every live task record in the region observes cancellation, finalizers
    /// run during close, and awaiting quiescence afterwards resolves. Unknown
    /// regions are tolerated so a late cancel after close never fails.
    ///
    /// # Errors
    ///
    /// Fails closed when no runtime gateway is wired or the owning runtime
    /// is gone.
    pub fn cancel(&self, reason: CancelReason) -> Result<(), ChildRegionError> {
        self.enqueue(RegionCommand::Cancel {
            region_id: self.region_id,
            reason,
        })
    }

    pub(crate) fn cancel_with_budget(
        &self,
        reason: CancelReason,
        shutdown_budget: Budget,
    ) -> Result<(), ChildRegionError> {
        self.enqueue(RegionCommand::CancelWithBudget {
            region_id: self.region_id,
            reason,
            shutdown_budget,
        })
    }

    /// Await actual quiescence and retain both child and cleanup outcomes.
    pub(crate) async fn close_with_outcome(
        mut self,
    ) -> Result<crate::record::region::RegionCloseOutcome, ChildRegionError> {
        self.closed = true;
        self.enqueue(RegionCommand::Close {
            region_id: self.region_id,
        })?;
        self.quiescence().await?;
        self.close_receipt
            .lock()
            .clone()
            .ok_or(ChildRegionError::RuntimeUnavailable)
    }

    /// Begins the close protocol and awaits quiescence.
    ///
    /// Resolves only after the region reaches `Closed`: body work finished,
    /// remaining children cancelled and drained, finalizers complete.
    ///
    /// # Errors
    ///
    /// Fails closed when no runtime gateway is wired or the owning runtime
    /// is gone before the close command could be enqueued.
    pub async fn close(mut self) -> Result<(), ChildRegionError> {
        // Defuse the Drop backstop FIRST: this structured close is the close
        // the backstop exists to request, so a completed close() must never
        // enqueue a second Close for an already-closing region.
        self.closed = true;
        self.enqueue(RegionCommand::Close {
            region_id: self.region_id,
        })?;
        self.quiescence().await
    }

    /// Begins the close protocol like [`ChildRegion::close`], but waits at
    /// most `bound` on the runtime's clock (virtual time under the lab
    /// runtime) for the region to reach `Closed`.
    ///
    /// Cancellation is cooperative, so `close` waits forever for a task that
    /// never reaches a checkpoint or a cancel-aware await. `close_within`
    /// instead reports [`ChildRegionCloseOutcome::TimedOut`] together with
    /// the tasks still running in the region and its descendants. Those
    /// stragglers are not dropped or detached: the region keeps closing and
    /// still owns them, so an ancestor's close or the root drain finishes
    /// them (br-asupersync-issue65-criticisms-kpmoy5.2.4).
    ///
    /// # Errors
    ///
    /// Fails closed like [`ChildRegion::close`] when no runtime gateway is
    /// wired or the owning runtime is gone before a command could be
    /// enqueued or answered.
    pub async fn close_within(
        mut self,
        bound: Duration,
    ) -> Result<ChildRegionCloseReport, ChildRegionError>
    where
        Caps: crate::cx::cap::HasTime,
    {
        // As in close(): this is the close the Drop backstop exists for.
        self.closed = true;
        let started = self.cx.now();
        self.enqueue(RegionCommand::Close {
            region_id: self.region_id,
        })?;
        let quiescent = match crate::time::timeout(started, bound, self.quiescence()).await {
            Ok(closed) => {
                closed?;
                true
            }
            // The timeout checks its deadline before polling the region, so
            // a region that reached Closed in time, but was polled late,
            // would still read as timed out.
            Err(_elapsed) => self.close_notify.lock().closed,
        };
        let elapsed = Duration::from_nanos(self.cx.now().duration_since(started));
        let (outcome, stragglers) = if quiescent {
            (ChildRegionCloseOutcome::Quiescent, Vec::new())
        } else {
            (ChildRegionCloseOutcome::TimedOut, self.live_tasks().await?)
        };
        Ok(ChildRegionCloseReport {
            outcome,
            elapsed,
            stragglers,
        })
    }

    /// Waits for this region to reach `Closed`. Runtime teardown wakes the
    /// wait, which then fails closed instead of pending forever when it is
    /// awaited outside the runtime (the werypv shape for monitors).
    fn quiescence(&self) -> RegionQuiescence {
        if let Some(gateway) = &self.gateway {
            let watch = Arc::downgrade(&self.close_notify);
            gateway.mailbox().register_teardown_wake(watch);
        }
        RegionQuiescence {
            state: Arc::clone(&self.close_notify),
            gateway: self.gateway.clone(),
        }
    }

    /// The live tasks of this region and its descendants, as the runtime
    /// sees them now.
    async fn live_tasks(&self) -> Result<Vec<TaskId>, ChildRegionError> {
        let (reply, mut replied) = crate::channel::oneshot::channel();
        self.enqueue(RegionCommand::LiveTasks(RegionLiveTasksQuery::new(
            self.region_id,
            reply,
        )))?;
        replied
            .recv_uninterruptible()
            .await
            .map_err(|_| ChildRegionError::RuntimeUnavailable)
    }
}

impl<Caps> Drop for ChildRegion<Caps> {
    fn drop(&mut self) {
        // Best-effort structured-close backstop: an abandoned handle must not
        // leak live children. Enqueue failures are swallowed because Drop can
        // neither block nor panic (same boundary as handle-cancel enqueue).
        if !self.closed {
            let _ = self.enqueue(RegionCommand::Close {
                region_id: self.region_id,
            });
        }
    }
}

/// Resolves once the observed region reaches terminal `Closed`, or fails
/// closed once the runtime that owns it is gone.
pub(crate) struct RegionQuiescence {
    state: Arc<Mutex<RegionCloseState>>,
    gateway: Option<Arc<SpawnGateway>>,
}

impl RegionQuiescence {
    /// Waits for the region whose close state is `state`, registered for the
    /// runtime teardown wake like [`ChildRegion::close`]'s wait. Used by the
    /// race engine to drain a losing branch's region
    /// (br-asupersync-issue65-criticisms-kpmoy5.2.2).
    pub(crate) fn watch(
        state: &Arc<Mutex<RegionCloseState>>,
        gateway: Option<Arc<SpawnGateway>>,
    ) -> Self {
        if let Some(gateway) = &gateway {
            let watch = Arc::downgrade(state);
            gateway.mailbox().register_teardown_wake(watch);
        }
        Self {
            state: Arc::clone(state),
            gateway,
        }
    }
}

impl Future for RegionQuiescence {
    type Output = Result<(), ChildRegionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.state.lock();
        if state.closed {
            return Poll::Ready(Ok(()));
        }
        if !state
            .waiters
            .iter()
            .any(|waker| waker.will_wake(cx.waker()))
        {
            state.waiters.push(cx.waker().clone());
        }
        drop(state);
        // Checked after registering: teardown drops the liveness token and
        // then wakes this state's waiters, so a teardown racing this poll is
        // either seen here or wakes the registration above.
        if self
            .gateway
            .as_ref()
            .is_some_and(|gateway| gateway.liveness_guard().is_none())
        {
            return Poll::Ready(Err(ChildRegionError::RuntimeUnavailable));
        }
        Poll::Pending
    }
}

impl TeardownWake for Mutex<RegionCloseState> {
    fn wake_for_teardown(&self) {
        let waiters = std::mem::take(&mut self.lock().waiters);
        for waker in waiters {
            waker.wake();
        }
    }
}
#[cfg(test)]
#[path = "child_region_inline_tests.rs"]
mod tests;
