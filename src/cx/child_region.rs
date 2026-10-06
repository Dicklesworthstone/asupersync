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
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::runtime::RuntimeBuilder;
    use crate::types::Budget;

    /// A budget whose deadline is `secs` seconds from now on the runtime
    /// clock. That clock's zero is the first time the process reads it, so an
    /// absolute deadline such as `with_deadline_at_secs(10)` has usually
    /// passed by the time a test in a full lib run gets here, and budget
    /// deadlines are enforced by a timer (br-asupersync-pev2xi): work spawned
    /// under a passed deadline is cancelled (br-asupersync-r7vhmw).
    fn deadline_budget_in(secs: u64) -> Budget {
        let deadline = crate::time::wall_now() + std::time::Duration::from_secs(secs);
        Budget::with_deadline_at_ns(deadline.as_nanos())
    }

    #[test]
    fn inherit_spec_has_no_budget_override() {
        let spec = ChildRegionSpec::inherit();
        assert!(spec.budget.is_none());
        assert!(spec.capability_budget.is_none());
        assert_eq!(spec.requirements, CapabilityBudgetRequirements::NONE);
    }

    #[test]
    fn display_names_each_failure_mode() {
        assert!(
            ChildRegionError::NoRuntimeGateway
                .to_string()
                .contains("no runtime gateway")
        );
        assert!(
            ChildRegionError::RuntimeUnavailable
                .to_string()
                .contains("no longer")
        );
    }

    #[test]
    fn detached_context_fails_closed_without_runtime_gateway() {
        let cx = Cx::detached_cancel_context();
        let mut opening = cx.open_child_region(ChildRegionSpec::inherit());
        let waker = std::task::Waker::noop();
        let mut task_context = std::task::Context::from_waker(waker);
        match std::pin::Pin::new(&mut opening).poll(&mut task_context) {
            std::task::Poll::Ready(Err(ChildRegionError::NoRuntimeGateway)) => {}
            other => panic!("expected NoRuntimeGateway, got {other:?}"),
        }
    }

    /// A restricted opener's child keeps the opener's compile-time capability
    /// set (asupersync-cwxavr). The type annotations are the assertion: before
    /// the fix, the child's context was always `Cx<cap::All>`.
    #[test]
    fn a_restricted_opener_keeps_its_capability_set_in_the_child() {
        use crate::cx::cap;
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime builds");
        let parent = runtime.request_cx_with_budget(deadline_budget_in(600));
        let restricted: Cx<cap::None> = parent.restrict();
        runtime.block_on_with_cx(parent.clone(), async move {
            let opening: ChildRegionOpening<cap::None> =
                restricted.open_child_region(ChildRegionSpec::inherit());
            let child: ChildRegion<cap::None> = opening
                .await
                .expect("a restricted context still mints a child region");
            let child_cx: &Cx<cap::None> = child.cx();
            assert_eq!(child_cx.region_id(), child.region_id());
            assert!(
                restricted.runtime_mask.contains(child_cx.runtime_mask),
                "the child's runtime mask never exceeds the opener's"
            );
            child.close().await.expect("child region closes");
        });
    }

    /// Yields until the scheduler has published the slot's mint outcome.
    async fn await_publication(slot: &AdmittedRegionSlot) {
        for _ in 0..10_000 {
            if !slot.is_pending() {
                return;
            }
            crate::runtime::yield_now().await;
        }
        panic!("the scheduler never minted the region");
    }

    /// An opening dropped before it resolves (a timeout, a lost race, an
    /// aborted task) must not leave the region the scheduler mints for it
    /// open with no owner until some ancestor closes. That holds whether the
    /// opening is dropped before the region is minted or after it was
    /// published but never taken: either way the slot ends up empty because
    /// the region was handed to its close backstop.
    #[test]
    fn a_dropped_opening_never_leaves_its_minted_region_to_nobody() {
        for published_before_drop in [false, true] {
            let runtime = RuntimeBuilder::current_thread()
                .build()
                .expect("current-thread runtime builds");
            let parent = runtime.request_cx_with_budget(deadline_budget_in(600));
            runtime.block_on_with_cx(parent.clone(), async move {
                let owner = parent
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .expect("the owner region opens");
                // Queue the Create command, keeping a view of its slot.
                let opening = owner.cx().open_child_region(ChildRegionSpec::inherit());
                let slot = Arc::clone(&opening.pending.as_ref().expect("a queued opening").0);
                if published_before_drop {
                    // Minted and published, but never polled or taken.
                    await_publication(&slot).await;
                }
                drop(opening);
                await_publication(&slot).await;
                assert!(
                    slot.take().is_none(),
                    "published_before_drop={published_before_drop}: \
                     the minted region was left in the slot for nobody"
                );
                owner.close().await.expect("the owner region closes");
            });
        }
    }

    #[test]
    fn open_child_region_mints_distinct_region_and_spawns_body() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime builds");
        let parent = runtime.request_cx_with_budget(deadline_budget_in(600));
        let parent_region = parent.region_id();
        runtime.block_on_with_cx(parent.clone(), async move {
            let child = parent
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .expect("ambient Cx mints an owned child region");
            assert_ne!(
                child.region_id(),
                parent_region,
                "child must be minted as a distinct region"
            );
            assert_eq!(child.cx().region_id(), child.region_id());

            let mut body = child
                .cx()
                .spawn(|_task_cx| async move { 7_u32 })
                .expect("child principal context spawns through the gateway");
            let value = body.join(child.cx()).await.expect("body joins");
            assert_eq!(value, 7);

            child.close().await.expect("close reaches quiescence");
        });
    }

    #[test]
    fn child_region_preserves_caller_budget_attenuation_on_native_workers() {
        for workers in [1, 4] {
            let runtime = if workers == 1 {
                RuntimeBuilder::current_thread().build().unwrap()
            } else {
                RuntimeBuilder::new()
                    .worker_threads(workers)
                    .build()
                    .unwrap()
            };
            let parent_budget = deadline_budget_in(600)
                .with_poll_quota(4096)
                .with_cost_quota(512);
            // Request contexts share the runtime root region. Their private
            // limits are deliberately stricter than that region's record.
            let parent = runtime.request_cx_with_budget(parent_budget);
            let envelope = CapabilityBudget::new()
                .with_io_bytes(128)
                .with_memory_bytes(256)
                .with_cpu_units(64)
                .with_artifact_bytes(32)
                .with_cleanup_budget(Budget::new().with_poll_quota(128));
            parent
                .apply_child_capability_budget(envelope, CapabilityBudgetRequirements::NONE)
                .unwrap();
            runtime.block_on_with_cx(parent.clone(), async move {
                let mut relaxed = ChildRegionSpec::inherit().with_budget(Budget::INFINITE);
                relaxed.capability_budget = Some(
                    CapabilityBudget::new()
                        .with_io_bytes(4096)
                        .with_memory_bytes(8192)
                        .with_cpu_units(4096)
                        .with_artifact_bytes(4096)
                        .with_cleanup_budget(Budget::INFINITE),
                );
                for spec in [ChildRegionSpec::inherit(), relaxed] {
                    let child = parent.open_child_region(spec).await.unwrap();
                    assert_eq!(child.cx().budget(), parent_budget);
                    assert_eq!(child.cx().capability_budget(), envelope);
                    let mut body = child
                        .cx()
                        .spawn(move |cx| async move {
                            assert_eq!(cx.capability_budget(), envelope);
                            assert_eq!(cx.budget().deadline, parent_budget.deadline);
                            assert_eq!(cx.budget().cost_quota, parent_budget.cost_quota);
                            assert!(cx.budget().poll_quota <= parent_budget.poll_quota);
                            crate::runtime::yield_now().await;
                            assert_eq!(cx.capability_budget(), envelope);
                            let ambient = Cx::current().expect("native task context");
                            assert_eq!(ambient.capability_budget(), envelope);
                            7_u32
                        })
                        .unwrap();
                    assert_eq!(body.join(child.cx()).await.unwrap(), 7);
                    child.close().await.unwrap();
                    assert_eq!(parent.capability_budget(), envelope);
                    assert_eq!(parent.budget(), parent_budget);
                }
                let tighter_budget = deadline_budget_in(300)
                    .with_poll_quota(2048)
                    .with_cost_quota(256);
                assert!(tighter_budget.deadline < parent_budget.deadline);
                let mut tighter = ChildRegionSpec::inherit().with_budget(tighter_budget);
                tighter.capability_budget = Some(CapabilityBudget::new().with_io_bytes(64));
                let child = parent.open_child_region(tighter).await.unwrap();
                assert_eq!(child.cx().budget().deadline, tighter_budget.deadline);
                assert_eq!(child.cx().budget().poll_quota, 2048);
                assert_eq!(child.cx().budget().cost_quota, Some(256));
                assert_eq!(child.cx().capability_budget(), envelope.with_io_bytes(64));
                child.close().await.unwrap();
                assert_eq!(parent.capability_budget(), envelope);
            });
            assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(3)));
        }
    }

    #[test]
    fn child_region_cannot_replenish_an_exhausted_caller_envelope() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let parent = runtime.request_cx_with_budget(Budget::INFINITE);
        parent
            .apply_child_capability_budget(
                CapabilityBudget::new().with_io_bytes(0),
                CapabilityBudgetRequirements::NONE,
            )
            .unwrap();
        runtime.block_on_with_cx(parent.clone(), async move {
            let mut spec = ChildRegionSpec::inherit();
            spec.capability_budget = Some(CapabilityBudget::new().with_io_bytes(4096));
            spec.requirements = CapabilityBudgetRequirements::NONE.require_io_bytes();
            assert!(matches!(
                parent.open_child_region(spec).await,
                Err(ChildRegionError::Create(
                    RegionCreateError::CapabilityBudgetRefused {
                        reason: crate::types::CapabilityBudgetRefusal::Exhausted(
                            crate::types::CapabilityBudgetDimension::IoBytes
                        ),
                        ..
                    }
                ))
            ));
            // A refusal must not poison the parent or silently replenish it.
            let child = parent
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .unwrap();
            assert_eq!(child.cx().capability_budget().io_bytes, Some(0));
            child.close().await.unwrap();
            assert_eq!(parent.capability_budget().io_bytes, Some(0));
        });
        assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(3)));
    }

    #[test]
    fn child_region_work_runs_under_the_planned_capability_budget() {
        // asupersync-mkybj0: the region record carried the planned envelope
        // but its principal (and so every task spawned through it) did not.
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime builds");
        let parent = runtime.request_cx_with_budget(deadline_budget_in(600));
        runtime.block_on_with_cx(parent.clone(), async move {
            let mut planned = CapabilityBudget::UNSPECIFIED;
            planned.io_bytes = Some(128);
            planned.memory_bytes = Some(256);
            let mut spec = ChildRegionSpec::inherit();
            spec.capability_budget = Some(planned);
            let child = parent
                .open_child_region(spec)
                .await
                .expect("owned child region mints");
            assert_eq!(child.cx().capability_budget(), planned);

            let mut body = child
                .cx()
                .spawn(|task_cx| async move { task_cx.capability_budget() })
                .expect("child principal context spawns through the gateway");
            let seen = body.join(child.cx()).await.expect("body joins");
            assert_eq!(seen, planned, "spawned work must run under the envelope");

            // A nested request can only tighten: a looser ask stays clamped.
            let mut looser = CapabilityBudget::UNSPECIFIED;
            looser.io_bytes = Some(512);
            looser.memory_bytes = Some(64);
            let mut nested_spec = ChildRegionSpec::inherit();
            nested_spec.capability_budget = Some(looser);
            let nested = child
                .cx()
                .open_child_region(nested_spec)
                .await
                .expect("nested child region mints");
            let mut nested_body = nested
                .cx()
                .spawn(|task_cx| async move { task_cx.capability_budget() })
                .expect("nested principal spawns");
            let nested_seen = nested_body
                .join(nested.cx())
                .await
                .expect("nested body joins");
            assert_eq!(nested_seen.io_bytes, Some(128));
            assert_eq!(nested_seen.memory_bytes, Some(64));

            nested.close().await.expect("nested close reaches quiescence");
            child.close().await.expect("close reaches quiescence");
        });
    }

    #[test]
    fn close_resolves_only_at_true_quiescence_draining_an_oblivious_body() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime builds");
        let parent = runtime.request_cx_with_budget(deadline_budget_in(600));
        runtime.block_on_with_cx(parent.clone(), async move {
            let child = parent
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .expect("owned child region mints");
            let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let body_done = std::sync::Arc::clone(&done);
            // Deliberately cancellation-oblivious: no checkpoints. The close
            // protocol MAY cancel this work; what this test pins is that
            // close() cannot RESOLVE until the region truly reaches Closed —
            // an in-flight body is drained, never silently dropped, and the
            // waiter observes completion of whatever the body actually ran.
            let body = child
                .cx()
                .spawn(move |_task_cx| async move {
                    for _ in 0..64 {
                        crate::runtime::yield_now().await;
                    }
                    body_done.store(true, std::sync::atomic::Ordering::Release);
                })
                .expect("body spawns into the child");

            child.close().await.expect("quiescent close resolves");
            assert!(
                done.load(std::sync::atomic::Ordering::Acquire),
                "close resolved before the drained body finished its stores"
            );
            let _ = body;
        });
    }

    #[test]
    fn early_close_cancels_checkpoint_aware_body_and_still_quiesces() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime builds");
        let parent = runtime.request_cx_with_budget(deadline_budget_in(600));
        runtime.block_on_with_cx(parent.clone(), async move {
            let child = parent
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .expect("owned child region mints");
            let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            // The handle stays bound (underscore-prefixed) so the body task
            // is not dropped mid-test; quiescence, not the handle, ends it.
            let _body = child
                .cx()
                .spawn(move |task_cx| async move {
                    loop {
                        task_cx.checkpoint()?;
                        crate::runtime::yield_now().await;
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), crate::error::Error>(())
                })
                .expect("aware body spawns");

            // Close while the body is still looping: the documented contract
            // is that remaining children are CANCELLED, so the aware body
            // must abort without ever setting done — and the close must then
            // still reach true quiescence (which implies every task, this
            // body included, reached a terminal state before close resolved).
            child.close().await.expect("close reaches quiescence");
            assert!(
                !done.load(std::sync::atomic::Ordering::Acquire),
                "an aborted checkpoint-aware body must not run to completion"
            );
        });
    }

    #[test]
    fn independent_cancel_stops_child_body_and_parent_keeps_working() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime builds");
        let parent = runtime.request_cx_with_budget(deadline_budget_in(600));
        runtime.block_on_with_cx(parent.clone(), async move {
            let child = parent
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .expect("owned child region mints");
            let mut body = child
                .cx()
                .spawn(|task_cx| async move {
                    loop {
                        task_cx.checkpoint()?;
                        crate::runtime::yield_now().await;
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), crate::error::Error>(())
                })
                .expect("cancellable body spawns");
            child
                .cancel(CancelReason::user("independent cancel"))
                .expect("cancel enqueues while the runtime is live");
            assert!(
                body.join(child.cx()).await.is_err(),
                "the cancelled child body must not complete successfully"
            );

            // The parent context remains fully operational afterwards.
            let mut sibling = parent
                .spawn(|_task_cx| async move { 11_u16 })
                .expect("parent still spawns after child cancel");
            assert_eq!(
                sibling.join(&parent).await.expect("sibling joins"),
                11,
                "independent child cancellation must not disturb the parent"
            );

            child
                .close()
                .await
                .expect("post-cancel close still reaches quiescence");
        });
    }

    #[test]
    fn lab_runtime_drains_region_commands_deterministically() {
        let _report = crate::lab::run_async_under_lab(0x5EED_u64, |root_cx: Cx| async move {
            let child = root_cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .expect("lab runtime drains the mint command");
            let mut body = child
                .cx()
                .spawn(|_task_cx| async move { 3_u8 })
                .expect("child spawn works under lab admission");
            assert_eq!(body.join(child.cx()).await.expect("body joins"), 3);
            child.close().await.expect("lab quiescence reached");
        });
    }

    /// Parks until released and ignores cancellation: a task that never
    /// reaches a checkpoint or a cancel-aware await.
    struct Released(
        Arc<(
            std::sync::atomic::AtomicBool,
            Mutex<Option<std::task::Waker>>,
        )>,
    );

    impl Future for Released {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            let (released, waker) = &*self.0;
            *waker.lock() = Some(cx.waker().clone());
            if released.load(std::sync::atomic::Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    #[test]
    fn close_within_times_out_on_lab_time_and_names_the_straggler() {
        use crate::lab::{LabConfig, LabRuntime};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        let bound = Duration::from_millis(50);
        let mut observed = Vec::new();
        for seed in [0x34_C400_u64, 0x34_C401, 0x34_C402] {
            let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(100_000));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let result = Arc::new(Mutex::new(None));
            let result_slot = Arc::clone(&result);
            let (owner, _join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().expect("lab task cx");
                    let child = cx
                        .open_child_region(ChildRegionSpec::inherit())
                        .await
                        .expect("child region");
                    let gate = Arc::new((AtomicBool::new(false), Mutex::new(None)));
                    let gate_for_task = Arc::clone(&gate);
                    let started = Arc::new(AtomicBool::new(false));
                    let started_flag = Arc::clone(&started);
                    let straggler_id = Arc::new(Mutex::new(None));
                    let id_slot = Arc::clone(&straggler_id);
                    let mut straggler = child
                        .cx()
                        .spawn(move |task_cx| async move {
                            *id_slot.lock() = Some(task_cx.task_id());
                            started_flag.store(true, Ordering::SeqCst);
                            Released(gate_for_task).await;
                        })
                        .expect("spawn straggler");
                    while !started.load(Ordering::SeqCst) {
                        crate::runtime::yield_now().await;
                    }
                    let report = child.close_within(bound).await.expect("close report");
                    let named = report.stragglers == vec![(*straggler_id.lock()).expect("ran")];
                    // Still owned by the closing region: releasing it lets
                    // the region close normally.
                    gate.0.store(true, Ordering::SeqCst);
                    if let Some(waker) = gate.1.lock().take() {
                        waker.wake();
                    }
                    // It ignored the cancellation, so it joins as Cancelled.
                    let _ = straggler.join(&cx).await;
                    *result_slot.lock() = Some((report.outcome, report.elapsed, named));
                })
                .expect("create owner");
            lab.scheduler.lock().schedule(owner, 0);
            let run = lab.run_with_auto_advance();
            let (outcome, elapsed, named) = result
                .lock()
                .take()
                .unwrap_or_else(|| panic!("seed {seed:#x}: the owner did not finish ({run:?})"));
            assert_eq!(outcome, ChildRegionCloseOutcome::TimedOut, "seed {seed:#x}");
            assert!(
                named,
                "seed {seed:#x}: the report names exactly the straggler"
            );
            assert!(
                elapsed >= bound,
                "seed {seed:#x}: elapsed {elapsed:?} < {bound:?}"
            );
            assert_eq!(lab.state.live_task_count(), 0, "seed {seed:#x}");
            observed.push(elapsed);
        }
        assert!(
            observed.windows(2).all(|pair| pair[0] == pair[1]),
            "virtual-time elapsed differs across seeds: {observed:?}"
        );
    }

    struct CountWakes(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for CountWakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// A close awaited outside the runtime is woken by the runtime's teardown
    /// and fails closed, instead of pending forever on a region that can no
    /// longer finish closing (the monitor-watch teardown shape, werypv).
    #[test]
    fn teardown_wakes_a_close_awaited_outside_the_runtime() {
        use crate::lab::{LabConfig, LabRuntime};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut lab = LabRuntime::new(LabConfig::new(0x0C1_05E0).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let slot = Arc::new(Mutex::new(None));
        let slot_for_owner = Arc::clone(&slot);
        let (owner, _join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab task cx");
                let child = cx
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .expect("child region");
                // Never finishes, so the region cannot reach Closed.
                let _parked = child
                    .cx()
                    .spawn(|_task_cx| std::future::pending::<()>())
                    .expect("spawn parked task");
                *slot_for_owner.lock() = Some(child);
            })
            .expect("create owner");
        lab.scheduler.lock().schedule(owner, 0);
        lab.run_until_idle();
        let child = slot
            .lock()
            .take()
            .expect("the owner opened the child region");

        let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(Arc::clone(&wakes));
        let mut context = Context::from_waker(&waker);
        let mut closing = Box::pin(child.close());
        assert!(closing.as_mut().poll(&mut context).is_pending());
        lab.run_until_idle();
        assert!(
            closing.as_mut().poll(&mut context).is_pending(),
            "the parked task keeps the region closing"
        );
        let before = wakes.0.load(Ordering::SeqCst);

        drop(lab);
        assert!(
            wakes.0.load(Ordering::SeqCst) > before,
            "teardown wakes the waiting close"
        );
        assert!(matches!(
            closing.as_mut().poll(&mut context),
            Poll::Ready(Err(ChildRegionError::RuntimeUnavailable))
        ));
    }

    /// `close_within` reports a region that reached `Closed` before its bound
    /// as quiescent, even when it is first polled after the deadline: the
    /// timeout checks the deadline before it polls the region.
    #[test]
    fn close_within_reports_an_already_closed_region_as_quiescent() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        runtime.block_on(async {
            let cx = Cx::current().expect("root cx");
            let child = cx
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .expect("child region");
            // An empty region closes as soon as the cancel is applied.
            child
                .cancel(CancelReason::user("closed before the bounded close"))
                .expect("cancel");
            let close_state = Arc::clone(&child.close_notify);
            let mut turns = 0_u32;
            while !close_state.lock().closed {
                turns += 1;
                assert!(turns < 100_000, "the cancelled region never closed");
                crate::runtime::yield_now().await;
            }

            let report = child
                .close_within(Duration::ZERO)
                .await
                .expect("close report");
            assert_eq!(
                report.outcome,
                ChildRegionCloseOutcome::Quiescent,
                "{report:?}"
            );
            assert!(report.stragglers.is_empty(), "{report:?}");
        });
    }

    /// The runtime owns this future, including its retirement. Counting actual
    /// polls and Drop distinguishes refusal from silently skipping cleanup.
    struct ShutdownProbe {
        polls: Arc<std::sync::atomic::AtomicUsize>,
        drops: Arc<std::sync::atomic::AtomicUsize>,
        wake_again: bool,
    }

    impl Future for ShutdownProbe {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            self.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.wake_again {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }

    impl Drop for ShutdownProbe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn managed_shutdown_enforces_actual_finalizers_and_retains_reclaimed_receipts() {
        use crate::error::ErrorKind;
        use crate::lab::{LabConfig, LabRuntime};
        use crate::types::{Outcome, Time};
        use std::sync::atomic::{AtomicUsize, Ordering};

        // First two cases enforce exact zero/two polls. Third uses a real timer
        // to wake cleanup that never wakes itself. Fourth activates an expired
        // ceiling after legacy cleanup has already parked without a timer.
        for case in 0..4 {
            let mut lab = LabRuntime::new(LabConfig::new(0x34_C100 + case).max_steps(4096));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let opened = Arc::new(Mutex::new(None));
            let child_slot = Arc::clone(&opened);
            let result = Arc::new(Mutex::new(None));
            let result_slot = Arc::clone(&result);
            let (release, mut wait) = crate::channel::oneshot::channel();
            let (begin_legacy, mut legacy_wait) = crate::channel::oneshot::channel();
            let budget = match case {
                0 => Budget::INFINITE.with_poll_quota(0),
                1 => Budget::INFINITE.with_poll_quota(2),
                2 => Budget::INFINITE.with_deadline(Time::from_nanos(100)),
                _ => Budget::INFINITE.with_deadline(Time::ZERO),
            };
            let (owner, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().expect("registered owner");
                    let child = cx
                        .open_child_region(ChildRegionSpec::inherit())
                        .await
                        .unwrap();
                    *child_slot.lock() = Some(child.region_id());
                    if case == 3 {
                        legacy_wait.recv_uninterruptible().await.unwrap();
                        child
                            .cancel(CancelReason::user("legacy close first"))
                            .unwrap();
                    }
                    wait.recv_uninterruptible().await.unwrap();
                    child
                        .cancel_with_budget(CancelReason::user("bounded cleanup test"), budget)
                        .unwrap();
                    *result_slot.lock() = Some(child.close_with_outcome().await.unwrap());
                })
                .unwrap();
            lab.scheduler.lock().schedule(owner, 0);
            lab.run_until_idle();
            let child = opened.lock().expect("actual child region opened");
            let receipt = lab.state.region(child).unwrap().close_receipt_handle();
            let polls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            assert!(lab.state.register_async_finalizer(
                child,
                ShutdownProbe {
                    polls: Arc::clone(&polls),
                    drops: Arc::clone(&drops),
                    wake_again: case == 1,
                }
            ));
            let owner_cx = lab.state.task(owner).unwrap().cx.clone().unwrap();
            if case == 3 {
                // Drive the real registered owner's command. Mutating state
                // directly while the scheduler is idle does not admit a
                // finalizer task through run_until_idle.
                begin_legacy.send(&owner_cx, ()).unwrap();
                lab.run_until_idle();
                assert_eq!(polls.load(Ordering::SeqCst), 1);
                assert_eq!(drops.load(Ordering::SeqCst), 0);
                assert!(lab.state.region(child).unwrap().shutdown_budget().is_none());
                assert!(receipt.lock().is_none());
            }
            release.send(&owner_cx, ()).unwrap();
            lab.run_until_idle();
            if case == 2 {
                assert_eq!(polls.load(Ordering::SeqCst), 1);
                assert_eq!(drops.load(Ordering::SeqCst), 0);
                assert!(result.lock().is_none());
                assert!(join.try_join().unwrap().is_none());
                assert!(receipt.lock().is_none());
                assert_eq!(lab.advance_to_next_timer(), 1);
                lab.run_until_idle();
            }
            assert!(
                join.try_join().unwrap().is_some(),
                "case {case} owner awaits real close"
            );
            let outcome = result
                .lock()
                .take()
                .expect("actual close receipt published");
            let expected = if case < 2 {
                ErrorKind::PollQuotaExhausted
            } else {
                ErrorKind::DeadlineExceeded
            };
            assert!(
                matches!(&outcome.cleanup_outcome, Some(Outcome::Err(error)) if error.kind() == expected)
            );
            if case == 3 {
                assert!(matches!(outcome.outcome, Outcome::Cancelled(ref reason)
                    if *reason == CancelReason::user("bounded cleanup test")));
            } else {
                assert!(
                    outcome.outcome.is_err(),
                    "canonical scheduler error remains unit-derived"
                );
            }
            assert_eq!(polls.load(Ordering::SeqCst), [0, 2, 1, 1][case as usize]);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(
                lab.state.region(child).is_none(),
                "close reclaims original generation"
            );
            assert!(
                matches!(&receipt.lock().as_ref().unwrap().cleanup_outcome, Some(Outcome::Err(error)) if error.kind() == expected)
            );
            assert_eq!(lab.state.live_task_count(), 0);
            assert_eq!(lab.state.pending_obligation_count(), 0);
            assert!(lab.run_until_quiescent_with_report().lab_test_passed());
            lab.state
                .close_region_command(root, &CancelReason::user("test complete"));
            lab.run_until_idle();
            assert!(lab.state.region(root).is_none());
            assert!(lab.run_until_quiescent_with_report().lab_test_passed());
        }
    }

    #[test]
    fn ordinary_ancestor_cancel_preserves_descendant_shutdown_ceiling_and_unbounded_sibling() {
        use crate::error::ErrorKind;
        use crate::lab::{LabConfig, LabRuntime};
        use crate::types::Outcome;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        struct CleanupRetirement(Arc<AtomicUsize>);

        impl Drop for CleanupRetirement {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        // br-asupersync-jrdfmh: None at the cancellation root must not hide
        // a descendant's existing ceiling from that descendant's children.
        let mut lab = LabRuntime::new(LabConfig::new(0x34_C300).max_steps(4096));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let opened = Arc::new(Mutex::new(None));
        let opened_slot = Arc::clone(&opened);
        let result = Arc::new(Mutex::new(None));
        let result_slot = Arc::clone(&result);
        let (begin_cancel, mut wait_cancel) = crate::channel::oneshot::channel();
        let reason = CancelReason::user("ordinary ancestor cancellation");
        let owner_reason = reason.clone();
        let (owner, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let ancestor = cx
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                let bounded = ancestor
                    .cx()
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                let grandchild = bounded
                    .cx()
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                let sibling = ancestor
                    .cx()
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                *opened_slot.lock() = Some((
                    ancestor.region_id(),
                    bounded.region_id(),
                    grandchild.region_id(),
                    sibling.region_id(),
                ));
                wait_cancel.recv_uninterruptible().await.unwrap();
                ancestor.cancel(owner_reason).unwrap();
                *result_slot.lock() = Some(ancestor.close_with_outcome().await.unwrap());
                drop((bounded, grandchild, sibling));
            })
            .unwrap();
        lab.scheduler.lock().schedule(owner, 0);
        lab.run_until_idle();
        let (ancestor, bounded, grandchild, sibling) = opened.lock().unwrap();
        let budgets = [ancestor, bounded, grandchild, sibling].map(|region| {
            let record = lab.state.region(region).unwrap();
            assert!(record.shutdown_budget().is_none());
            record.shutdown_budget_handle()
        });
        let receipts = [bounded, grandchild, sibling]
            .map(|region| lab.state.region(region).unwrap().close_receipt_handle());
        let ceiling = Budget::INFINITE.with_poll_quota(2);
        assert!(
            lab.state
                .region(bounded)
                .unwrap()
                .tighten_shutdown_budget(ceiling)
        );
        assert!(budgets[2].read().is_none());

        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        assert!(lab.state.register_async_finalizer(
            grandchild,
            ShutdownProbe {
                polls: Arc::clone(&polls),
                drops: Arc::clone(&drops),
                wake_again: true,
            }
        ));
        let sibling_started = Arc::new(AtomicBool::new(false));
        let started = Arc::clone(&sibling_started);
        let sibling_drops = Arc::new(AtomicUsize::new(0));
        let retired = Arc::clone(&sibling_drops);
        let (finish_sibling, mut wait_sibling) = crate::channel::oneshot::channel();
        assert!(lab.state.register_async_finalizer(sibling, async move {
            let _retirement = CleanupRetirement(retired);
            started.store(true, Ordering::SeqCst);
            wait_sibling.recv_uninterruptible().await.unwrap();
        }));

        let owner_cx = lab.state.task(owner).unwrap().cx.clone().unwrap();
        begin_cancel.send(&owner_cx, ()).unwrap();
        lab.run_until_idle();
        assert_eq!(*budgets[1].read(), Some(ceiling));
        assert_eq!(*budgets[2].read(), Some(ceiling));
        assert!(budgets[0].read().is_none());
        assert!(budgets[3].read().is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        for receipt in &receipts[..2] {
            assert!(matches!(
                receipt.lock().as_ref().unwrap().cleanup_outcome,
                Some(Outcome::Err(ref error)) if error.kind() == ErrorKind::PollQuotaExhausted
            ));
        }
        // The lab admits finalizer tasks after draining both lifecycle commands.
        // Their scheduler outcomes retain the unit-error mapping; the separate
        // cleanup receipts above preserve the exact exhausted quota.
        {
            let grandchild_receipt = receipts[1].lock();
            let outcome = &grandchild_receipt.as_ref().unwrap().outcome;
            assert!(
                matches!(outcome, Outcome::Err(error) if error.kind() == ErrorKind::Internal),
                "canonical grandchild outcome: {outcome:?}"
            );
        }
        assert!(lab.state.region(bounded).is_none());
        assert!(lab.state.region(grandchild).is_none());
        assert!(sibling_started.load(Ordering::SeqCst));
        assert_eq!(sibling_drops.load(Ordering::SeqCst), 0);
        assert!(receipts[2].lock().is_none());
        assert!(result.lock().is_none());
        assert!(join.try_join().unwrap().is_none());

        // The sibling completes through its real wake and success path, without
        // ever receiving an explicit ceiling to make it retire.
        finish_sibling.send(&owner_cx, ()).unwrap();
        lab.run_until_idle();
        assert!(join.try_join().unwrap().is_some());
        assert_eq!(sibling_drops.load(Ordering::SeqCst), 1);
        assert!(budgets[3].read().is_none());
        {
            let sibling_receipt = receipts[2].lock();
            let sibling_receipt = sibling_receipt.as_ref().unwrap();
            assert!(
                matches!(&sibling_receipt.outcome, Outcome::Ok(())),
                "canonical sibling outcome: {:?}",
                sibling_receipt.outcome
            );
            assert!(matches!(
                sibling_receipt.cleanup_outcome,
                Some(Outcome::Ok(()))
            ));
        }
        let outcome = result.lock().take().unwrap();
        assert!(matches!(outcome.outcome, Outcome::Cancelled(ref actual) if *actual == reason));
        assert!(matches!(
            outcome.cleanup_outcome,
            Some(Outcome::Err(ref error)) if error.kind() == ErrorKind::PollQuotaExhausted
        ));
        assert!(lab.state.region(ancestor).is_none());
        assert!(lab.state.region(sibling).is_none());
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert!(lab.run_until_quiescent_with_report().lab_test_passed());
        lab.state
            .close_region_command(root, &CancelReason::user("test complete"));
        lab.run_until_idle();
        assert!(lab.state.region(root).is_none());
        assert!(lab.run_until_quiescent_with_report().lab_test_passed());
    }

    #[test]
    fn managed_close_distinguishes_cancelled_body_from_descendant_cleanup_failure() {
        use crate::lab::{LabConfig, LabRuntime};
        use crate::types::Outcome;

        for failing_cleanup in [false, true] {
            let mut lab = LabRuntime::new(LabConfig::new(0x34_C200).max_steps(4096));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let opened = Arc::new(Mutex::new(None));
            let opened_slot = Arc::clone(&opened);
            let result = Arc::new(Mutex::new(None));
            let result_slot = Arc::clone(&result);
            let (release, mut wait) = crate::channel::oneshot::channel();
            let (owner, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    let child = cx
                        .open_child_region(ChildRegionSpec::inherit())
                        .await
                        .unwrap();
                    let grandchild = child
                        .cx()
                        .open_child_region(ChildRegionSpec::inherit())
                        .await
                        .unwrap();
                    let mut body = child
                        .cx()
                        .spawn(|body_cx| async move {
                            loop {
                                if body_cx.is_cancel_requested() {
                                    return;
                                }
                                crate::runtime::yield_now().await;
                            }
                        })
                        .unwrap();
                    *opened_slot.lock() = Some((child.region_id(), grandchild.region_id()));
                    wait.recv_uninterruptible().await.unwrap();
                    child
                        .cancel_with_budget(
                            CancelReason::user("subtree cleanup"),
                            Budget::INFINITE.with_poll_quota(2),
                        )
                        .unwrap();
                    // Observe real task cancellation; its terminal must not enter
                    // the separate cleanup-failure field.
                    let _ = body.join(&cx).await;
                    *result_slot.lock() = Some(child.close_with_outcome().await.unwrap());
                    drop(grandchild);
                })
                .unwrap();
            lab.scheduler.lock().schedule(owner, 0);
            // The body yields continuously: use a bounded scheduler prefix to
            // obtain the actual admitted subtree, then request cancellation.
            for _ in 0..256 {
                if opened.lock().is_some() {
                    break;
                }
                lab.step_for_test();
            }
            let (child, grandchild) = opened.lock().expect("actual subtree admitted");
            assert!(lab.state.register_sync_finalizer(grandchild, move || {
                assert!(!failing_cleanup, "actual descendant cleanup panic");
            }));
            let owner_cx = lab.state.task(owner).unwrap().cx.clone().unwrap();
            release.send(&owner_cx, ()).unwrap();
            lab.run_until_idle();
            assert!(join.try_join().unwrap().is_some());
            let outcome = result.lock().take().unwrap();
            assert!(
                outcome.outcome.is_cancelled(),
                "legacy canonical child outcome preserved"
            );
            if failing_cleanup {
                assert!(
                    matches!(outcome.cleanup_outcome, Some(Outcome::Panicked(ref payload)) if payload.message() == "actual descendant cleanup panic")
                );
            } else {
                assert!(matches!(outcome.cleanup_outcome, Some(Outcome::Ok(()))));
            }
            assert!(lab.state.region(child).is_none());
            assert!(lab.state.region(grandchild).is_none());
            assert_eq!(lab.state.live_task_count(), 0);
            assert!(lab.run_until_quiescent_with_report().lab_test_passed());
            lab.state
                .close_region_command(root, &CancelReason::user("test complete"));
            lab.run_until_idle();
            assert!(lab.state.region(root).is_none());
        }
    }
}
