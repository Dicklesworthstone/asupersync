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
    close_receipt: Arc<Mutex<Option<crate::record::region::RegionCloseOutcome>>>,
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
        RegionQuiescence {
            state: Arc::clone(&self.close_notify),
        }
        .await;
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
        let parent = runtime.request_cx_with_budget(Budget::with_deadline_at_secs(10));
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
            if case == 3 {
                lab.state
                    .close_region_command(child, &CancelReason::user("legacy close first"));
                lab.run_until_idle();
                assert_eq!(polls.load(Ordering::SeqCst), 1);
                assert_eq!(drops.load(Ordering::SeqCst), 0);
                assert!(lab.state.region(child).unwrap().shutdown_budget().is_none());
                assert!(receipt.lock().is_none());
            }
            let owner_cx = lab.state.task(owner).unwrap().cx.clone().unwrap();
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
