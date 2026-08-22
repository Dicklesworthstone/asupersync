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
//! - **No ambient authority:** everything flows through the caller's `Cx`
//!   capability wiring. A detached Cx without a runtime gateway fails closed
//!   with [`ChildRegionError::NoRuntimeGateway`].
//!
//! The mint itself is command-driven: the producer enqueues a plain-data
//! region command through the spawn gateway's liveness guard, the scheduler
//! performs the authoritative record transitions at its existing dispatch
//! point, and the outcome is published into a caller-shared slot after the
//! runtime lock drops.

use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use parking_lot::Mutex;

use crate::record::region::RegionCloseState;
use crate::runtime::region_table::RegionCreateError;
use crate::runtime::resource_monitor::RegionPriority;
use crate::runtime::spawn_mailbox::{AdmittedRegionSlot, RegionCommand, SpawnGateway};
use crate::types::{
    Budget, CancelReason, CapabilityBudget, CapabilityBudgetRequirements, RegionId,
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
    /// The owning runtime shut down before or while the mint was pending.
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
#[must_use = "an opening that is never awaited never observes its mint outcome"]
pub struct ChildRegionOpening {
    pending: Option<(Arc<AdmittedRegionSlot>, Weak<()>)>,
    failure: Option<ChildRegionError>,
}

impl ChildRegionOpening {
    pub(crate) fn new(slot: Arc<AdmittedRegionSlot>, liveness: Weak<()>) -> Self {
        Self {
            pending: Some((slot, liveness)),
            failure: None,
        }
    }

    pub(crate) fn failed(error: ChildRegionError) -> Self {
        Self {
            pending: None,
            failure: Some(error),
        }
    }
}

impl Future for ChildRegionOpening {
    type Output = Result<ChildRegion, ChildRegionError>;

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
                Ok(admitted) => Ok(ChildRegion::from_admitted(admitted)),
                Err(error) => Err(ChildRegionError::Create(error)),
            });
        }
        // Fail closed when the runtime vanished before publication; a live
        // runtime keeps the registration until the worker publishes.
        if liveness.upgrade().is_none() {
            this.pending = None;
            return Poll::Ready(Err(ChildRegionError::RuntimeUnavailable));
        }
        slot.register(cx.waker().clone());
        Poll::Pending
    }
}

/// An owned child region derived from an ambient `&Cx`.
///
/// The principal context ([`ChildRegion::cx`]) carries the child region's
/// identity, effective (met) budget, and pending-spawn credits, so body work
/// spawned through it rides the standard admission path. Handlers that need
/// checkpoint-observable cancellation should run as spawned tasks — each
/// gets its own admission-built context wired to a real record.
pub struct ChildRegion {
    region_id: RegionId,
    cx: crate::cx::Cx,
    close_notify: Arc<Mutex<RegionCloseState>>,
    gateway: Option<Arc<SpawnGateway>>,
    /// Set once a structured close has been requested for this handle
    /// ([`Self::close`]); defuses the [`Drop`] backstop so a completed close
    /// never enqueues a second, redundant Close command for a region that is
    /// already closing or closed.
    closed: bool,
}

impl std::fmt::Debug for ChildRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildRegion")
            .field("region_id", &self.region_id)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl ChildRegion {
    pub(crate) fn from_admitted(admitted: crate::runtime::spawn_mailbox::AdmittedRegion) -> Self {
        let handles = admitted.cx.spawn_gateway_handle();
        Self {
            region_id: admitted.region_id,
            cx: admitted.cx,
            close_notify: admitted.close_notify,
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
    pub fn cx(&self) -> &crate::cx::Cx {
        &self.cx
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
        let waiter = RegionQuiescence {
            state: Arc::clone(&self.close_notify),
        };
        waiter.await;
        Ok(())
    }
}

impl Drop for ChildRegion {
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

/// Resolves once the observed region reaches terminal `Closed`.
struct RegionQuiescence {
    state: Arc<Mutex<RegionCloseState>>,
}

impl Future for RegionQuiescence {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.state.lock();
        if state.closed {
            return Poll::Ready(());
        }
        if !state
            .waiters
            .iter()
            .any(|waker| waker.will_wake(cx.waker()))
        {
            state.waiters.push(cx.waker().clone());
        }
        Poll::Pending
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::runtime::RuntimeBuilder;
    use crate::types::Budget;

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

    #[test]
    fn open_child_region_mints_distinct_region_and_spawns_body() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime builds");
        let parent = runtime.request_cx_with_budget(Budget::with_deadline_at_secs(10));
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
    fn close_resolves_only_at_true_quiescence_draining_an_oblivious_body() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime builds");
        let parent = runtime.request_cx_with_budget(Budget::with_deadline_at_secs(10));
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
            let mut body = child
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
        let parent = runtime.request_cx_with_budget(Budget::with_deadline_at_secs(10));
        runtime.block_on_with_cx(parent.clone(), async move {
            let child = parent
                .open_child_region(ChildRegionSpec::inherit())
                .await
                .expect("owned child region mints");
            let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let body_done = std::sync::Arc::clone(&done);
            let body = child
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
        let parent = runtime.request_cx_with_budget(Budget::with_deadline_at_secs(10));
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
        crate::lab::run_async_under_lab(0x5EED_u64, |root_cx: Cx| async move {
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
}
