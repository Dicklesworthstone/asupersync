//! Two-phase, runtime-accounted name publication.

use super::{Admission, TrackedNameError, TrackedNameLease, TrackedNameRegistry, validate_owner};
use crate::cx::{CancelWakerToken, Cx};
use crate::cx::registry::{NameLeaseError, NamePermit};
use crate::record::ObligationAbortReason;
use crate::runtime::obligation_mailbox::{ObligationAdmissionError, ObligationToken};
use crate::types::{RegionId, TaskId, Time};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::atomic::Ordering;
use std::task::Poll;

impl TrackedNameRegistry {
    /// Reserves an invisible name and its checked runtime obligation.
    ///
    /// Setup can await while holding the returned permit. Until `commit`,
    /// `whereis` returns `None`, but a competing registration cannot take the
    /// reserved name. Setup failure, cancellation/drop, and explicit abort
    /// remove the reservation and return quota. Commit transfers the SAME
    /// runtime credit to the visible lease; it neither settles that obligation
    /// nor requests a second credit. Keep the permit within its original task.
    pub fn reserve<'a>(
        &self,
        cx: &'a Cx,
        name: impl Into<String>,
    ) -> Result<TrackedNamePermit<'a>, TrackedNameError> {
        let name = name.into();
        let mut admission = Admission::new(cx)?;
        let now = cx.now();
        cx.checkpoint().map_err(|_| TrackedNameError::Cancelled)?;
        let token = admission.token.as_ref().expect("admitted name credit");
        validate_owner(cx, token)?;
        self.bind_runtime(cx)?;
        let result = {
            self.inner
                .lock()
                .reserve(name, token.holder(), token.region(), now)
        };
        let permit = result.map_err(TrackedNameError::Registry)?;
        Ok(TrackedNamePermit {
            registry: self.clone(),
            cx,
            permit: Some(permit),
            obligation: admission.token.take(),
        })
    }

    /// Waits for a name without holding runtime quota while it is occupied.
    ///
    /// Release, abort, and dropped ownership wake this name's contenders; no
    /// polling timer or background task is used. Cancellation is independently
    /// wake-driven and respects checkpoint masks. A finite context deadline is
    /// driven by its explicit timer capability, never an ambient fallback.
    ///
    /// Once the name is free, checked admission must succeed before a permit is
    /// returned. Quota refusal is an error, not an indefinite wait for credits.
    /// Competing waiters race to reserve the name; FIFO/starvation freedom is
    /// not promised. Dropping this future removes its subscriptions and any
    /// partially acquired reservation, without changing the current owner.
    pub async fn reserve_wait<'a>(
        &self,
        cx: &'a Cx,
        name: impl Into<String>,
    ) -> Result<TrackedNamePermit<'a>, TrackedNameError> {
        self.reserve_wait_inner(cx, name.into(), None).await
    }

    /// Like [`Self::reserve_wait`], with an additional absolute wait deadline.
    ///
    /// An expired wait returns `Registry(WaitBudgetExceeded)` before acquiring
    /// the name. An inherited context deadline can end the wait sooner.
    pub async fn reserve_wait_until<'a>(
        &self,
        cx: &'a Cx,
        name: impl Into<String>,
        deadline: Time,
    ) -> Result<TrackedNamePermit<'a>, TrackedNameError> {
        self.reserve_wait_inner(cx, name.into(), Some(deadline)).await
    }

    async fn reserve_wait_inner<'a>(
        &self,
        cx: &'a Cx,
        name: String,
        deadline: Option<Time>,
    ) -> Result<TrackedNamePermit<'a>, TrackedNameError> {
        cx.checkpoint().map_err(|_| TrackedNameError::Cancelled)?;
        wait_identity(cx)?;
        self.bind_runtime(cx)?;
        let interest = self.subscribe(&name);
        let mut retries = 0usize;
        loop {
            // Sample BEFORE testing the condition. Notify::notified() captures
            // broadcasts at first poll, not construction; wait_until plus this
            // persistent epoch also catches release before waiter registration.
            let epoch = interest.signal.epoch.load(Ordering::Acquire);
            let now = cx.now();
            cx.checkpoint().map_err(|_| TrackedNameError::Cancelled)?;
            if deadline.is_some_and(|until| now >= until) {
                return Err(wait_expired(&name));
            }
            let (holder, region) = wait_identity(cx)?;
            let raw = { self.inner.lock().reserve(name.clone(), holder, region, now) };
            match raw {
                Ok(raw) => {
                    // Physical rollback is owned before checked admission can
                    // invoke user callbacks. This provisional permit never
                    // crosses an await or becomes observable to the caller.
                    let mut permit = TrackedNamePermit {
                        registry: self.clone(), cx, permit: Some(raw), obligation: None,
                    };
                    let mut admission = Admission::new(cx)?;
                    let admitted_at = cx.now();
                    cx.checkpoint().map_err(|_| TrackedNameError::Cancelled)?;
                    if deadline.is_some_and(|until| admitted_at >= until) {
                        return Err(wait_expired(&name));
                    }
                    validate_owner(cx, admission.token.as_ref().expect("admitted name credit"))?;
                    permit.obligation = admission.token.take();
                    return Ok(permit);
                }
                Err(NameLeaseError::NameTaken { .. }) => {}
                Err(error) => return Err(TrackedNameError::Registry(error)),
            }

            let inherited = cx.budget().deadline;
            let wake_at = match (deadline, inherited) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            let sleep = match wake_at {
                Some(at) => Some(crate::time::Sleep::with_timer_driver(
                    at, cx.timer_driver().ok_or(TrackedNameError::TimerRequired)?,
                )),
                None => None,
            };
            let mut sleep = pin!(sleep);
            let mut changed = pin!(interest.changed(epoch));
            let mut cancellation = WaitCancellation { cx, token: None };
            poll_fn(|task| {
                cancellation.token = Some(cx.refresh_cancel_waker(cancellation.token, task.waker()));
                if cx.checkpoint().is_err() {
                    return Poll::Ready(Err(TrackedNameError::Cancelled));
                }
                if let Err(error) = wait_identity(cx) {
                    return Poll::Ready(Err(error));
                }
                if let Some(timer) = sleep.as_mut().as_pin_mut() {
                    // A timer completing early for an ambient owner's cancel
                    // must never be mistaken for this operation's deadline.
                    if timer.poll_deadline(task).is_ready() {
                        return Poll::Ready(Err(wait_expired(&name)));
                    }
                }
                changed.as_mut().poll(task).map(|()| Ok(()))
            }).await?;
            retries += 1;
            if retries == 32 {
                retries = 0;
                crate::runtime::yield_now().await;
            }
        }
    }
}

// Validate without reserving quota: the existing owner may hold the region's
// last credit, and sleeping with a second credit would create a quota deadlock.
fn wait_identity(cx: &Cx) -> Result<(TaskId, RegionId), TrackedNameError> {
    let (gateway, holder) = cx.obligation_transfer_destination().map_err(TrackedNameError::Admission)?;
    if !gateway.is_runtime_available() {
        return Err(TrackedNameError::Admission(ObligationAdmissionError::RuntimeUnavailable));
    }
    if !holder.is_live() {
        return Err(TrackedNameError::Admission(ObligationAdmissionError::HolderNotLive));
    }
    if holder.holder() != cx.task_id() || holder.region() != cx.region_id() {
        return Err(TrackedNameError::Admission(ObligationAdmissionError::HolderMismatch));
    }
    if holder.region().as_u64() == 0 {
        return Err(TrackedNameError::UnscopedRegion);
    }
    Ok((holder.holder(), holder.region()))
}

fn wait_expired(name: &str) -> TrackedNameError {
    TrackedNameError::Registry(NameLeaseError::WaitBudgetExceeded { name: name.to_owned() })
}

struct WaitCancellation<'a> {
    cx: &'a Cx,
    token: Option<CancelWakerToken>,
}

impl Drop for WaitCancellation<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

/// Invisible name reservation that remains accountable during async setup.
///
/// `commit` checks cancellation and rejects a retired original holder or
/// unavailable runtime before publishing. A move is not a transfer of holder
/// liability. Validation does not extend the original task's lifetime; callers
/// must still resolve the guard within that lifetime. Forgetting a permit is
/// ledger-visible but cannot reclaim the name. No raw mutation handle is exposed.
#[derive(Debug)]
#[must_use = "dropping the permit cancels the invisible name reservation"]
pub struct TrackedNamePermit<'a> {
    registry: TrackedNameRegistry,
    cx: &'a Cx,
    permit: Option<NamePermit>,
    obligation: Option<ObligationToken>,
}

impl TrackedNamePermit<'_> {
    /// The reserved, not yet published name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.permit.as_ref().expect("live name permit").name()
    }

    /// The original holder of the checked obligation.
    #[must_use]
    pub fn holder(&self) -> TaskId {
        self.permit.as_ref().expect("live name permit").holder()
    }

    /// The region accountable for both reservation and published lease.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.permit.as_ref().expect("live name permit").region()
    }

    /// Reservation time from the original context's clock.
    #[must_use]
    pub fn reserved_at(&self) -> Time {
        self.permit.as_ref().expect("live name permit").reserved_at()
    }

    /// The same ticket will be carried by the committed lease.
    #[must_use]
    pub fn obligation_ticket(&self) -> u64 {
        self.obligation.as_ref().expect("live name obligation").ticket()
    }

    /// Publishes discovery without releasing or reacquiring runtime quota.
    ///
    /// Cancellation observed at the checkpoint aborts the still-invisible
    /// reservation. As with other two-phase primitives, a cancellation racing
    /// after that checkpoint does not undo an already committed publication.
    pub fn commit(mut self) -> Result<TrackedNameLease, TrackedNameError> {
        validate_owner(self.cx, self.obligation.as_ref().expect("live name obligation"))?;
        self.cx.checkpoint().map_err(|_| TrackedNameError::Cancelled)?;
        validate_owner(self.cx, self.obligation.as_ref().expect("live name obligation"))?;
        let name = self.name().to_owned();
        let permit = self.permit.take().expect("live name permit");
        let result = { self.registry.inner.lock().commit_permit(permit) };
        match result {
            Ok(lease) => Ok(TrackedNameLease {
                registry: self.registry.clone(),
                lease: Some(lease),
                obligation: self.obligation.take(),
            }),
            Err(error) => {
                // commit_permit defuses a refused raw permit. Retire its runtime
                // credit too, outside the registry lock, without fabricating a leak.
                let _changed = self.registry.publish_availability(&name);
                let _ = self.abort_inner(ObligationAbortReason::Error);
                Err(TrackedNameError::Registry(error))
            }
        }
    }

    /// Cancels setup and returns its name reservation and quota immediately.
    pub fn abort(mut self) -> Result<(), TrackedNameError> {
        self.abort_inner(ObligationAbortReason::Explicit)
    }

    fn abort_inner(&mut self, reason: ObligationAbortReason) -> Result<(), TrackedNameError> {
        let mut _changed = None;
        let token = self.obligation.take();
        let (removed, accepted, notification) = if let Some(permit) = self.permit.take() {
            // This private registry has no raw waiters. Reuse the recorded time
            // rather than calling an arbitrary clock driver during unwinding.
            let at = permit.reserved_at();
            let name = permit.name().to_owned();
            let (removed, accepted, notification) = {
                let mut inner = self.registry.inner.lock();
                let removed = inner
                    .abort_permit(permit, at)
                    .map(|_| ())
                    .map_err(TrackedNameError::Registry);
                // Settle before the lock that freed the name is released, so
                // a contender that finds it free also finds the quota returned
                // (br-asupersync-xphg21). No callback runs here.
                let (accepted, notification) = settle_deferred(token, reason, removed.is_ok());
                (removed, accepted, notification)
            };
            if removed.is_ok() {
                _changed = self.registry.publish_availability(&name);
            }
            (removed, accepted, notification)
        } else {
            let (accepted, notification) = settle_deferred(token, reason, true);
            (Ok(()), accepted, notification)
        };
        if let Some(gateway) = notification {
            gateway.notify();
        }
        removed?;
        if accepted { Ok(()) } else { Err(TrackedNameError::SettlementRejected) }
    }
}

impl Drop for TrackedNamePermit<'_> {
    fn drop(&mut self) {
        let _ = self.abort_inner(ObligationAbortReason::Cancel);
    }
}

/// Aborts a permit's credit without running the gateway notification (the
/// caller runs it once no registry lock is held). Returns whether the runtime
/// accepted the settlement; no token means nothing to settle.
fn settle_deferred(
    token: Option<ObligationToken>,
    reason: ObligationAbortReason,
    removed: bool,
) -> (
    bool,
    Option<std::sync::Arc<crate::runtime::obligation_mailbox::ObligationGateway>>,
) {
    match token {
        Some(token) => token.abort_deferred(if removed {
            reason
        } else {
            ObligationAbortReason::Error
        }),
        None => (true, None),
    }
}

#[cfg(test)]
#[path = "permit_tests.rs"]
mod tests;

#[cfg(test)]
mod wait_tests {
    #![allow(clippy::pedantic, clippy::nursery)]

    use super::*;
    use super::super::tests::{finish, fixture, flush};
    use crate::runtime::obligation_mailbox::ObligationGateway;
    use crate::types::{Budget, CancelKind};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Wake, Waker};

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) { self.wake_by_ref(); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }

    fn counter() -> (Arc<WakeCount>, Waker) {
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        (count, waker)
    }

    fn poll<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(waker))
    }

    fn ready<T>(result: Poll<Result<T, TrackedNameError>>) -> T {
        match result {
            Poll::Ready(Ok(value)) => value,
            Poll::Ready(Err(error)) => panic!("unexpected name refusal: {error}"),
            Poll::Pending => panic!("name should be ready"),
        }
    }

    #[test]
    fn immediate_wait_returns_an_invisible_accounted_permit() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
        let permit = ready(poll(wait.as_mut(), Waker::noop()));
        assert_eq!(names.whereis("worker"), None);
        assert!(names.waiters.lock().is_empty());
        let ticket = permit.obligation_ticket();
        let lease = permit.commit().unwrap();
        assert_eq!(lease.obligation_ticket(), ticket);
        lease.release().unwrap();
        drop(wait);
        finish(lab, &cx, handle, 1);
    }

    #[test]
    fn sleeping_contender_does_not_hold_the_owners_only_quota_credit() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let (count, waker) = counter();
        let before = lab.state.obligation_gateway().unwrap().mailbox().stats().posted;
        let mut wait = Box::pin(names.register_wait(&cx, "worker"));
        assert!(poll(wait.as_mut(), &waker).is_pending());
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        assert_eq!(lab.state.obligation_gateway().unwrap().mailbox().stats().posted, before);
        owner.release().unwrap();
        assert!(count.0.load(Ordering::SeqCst) > 0);
        let lease = ready(poll(wait.as_mut(), &waker));
        assert_eq!(names.whereis("worker"), Some(cx.task_id()));
        lease.release().unwrap();
        drop(wait);
        assert!(names.waiters.lock().is_empty());
        finish(lab, &cx, handle, 2);
    }

    #[test]
    fn aborting_or_dropping_unpublished_ownership_wakes_contenders() {
        for explicit in [false, true] {
            let (lab, cx, handle) = fixture(1);
            let names = TrackedNameRegistry::new();
            let owner = names.reserve(&cx, "worker").unwrap();
            let (count, waker) = counter();
            let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
            assert!(poll(wait.as_mut(), &waker).is_pending());
            if explicit { owner.abort().unwrap(); } else { drop(owner); }
            assert!(count.0.load(Ordering::SeqCst) > 0);
            let next = ready(poll(wait.as_mut(), &waker));
            assert_eq!(names.whereis("worker"), None);
            next.abort().unwrap();
            drop(wait);
            finish(lab, &cx, handle, 2);
        }
    }

    #[test]
    fn cancellation_alone_wakes_wait_and_preserves_the_current_owner() {
        let (mut lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let (count, waker) = counter();
        let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
        assert!(poll(wait.as_mut(), &waker).is_pending());
        cx.cancel_fast(CancelKind::User);
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(poll(wait.as_mut(), &waker), Poll::Ready(Err(TrackedNameError::Cancelled))));
        assert_eq!(names.whereis("worker"), Some(owner.holder()));
        assert!(names.waiters.lock().is_empty());
        assert_eq!(Arc::strong_count(&count), 2);
        drop(wait);
        owner.release().unwrap();
        flush(&mut lab);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.leak_count(), 0);
        drop(handle);
    }

    #[test]
    fn dropping_wait_removes_both_subscriptions_and_name_metadata() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let (count, waker) = counter();
        let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
        assert!(poll(wait.as_mut(), &waker).is_pending());
        drop(wait);
        assert!(names.waiters.lock().is_empty());
        assert_eq!(Arc::strong_count(&count), 2);
        owner.release().unwrap();
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        finish(lab, &cx, handle, 1);
    }

    #[test]
    fn unrelated_name_release_does_not_wake_the_waiter() {
        let (lab, cx, handle) = fixture(2);
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let unrelated = names.register(&cx, "unrelated").unwrap();
        let (count, waker) = counter();
        let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
        assert!(poll(wait.as_mut(), &waker).is_pending());
        unrelated.release().unwrap();
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        owner.release().unwrap();
        assert!(count.0.load(Ordering::SeqCst) > 0);
        ready(poll(wait.as_mut(), &waker)).abort().unwrap();
        drop(wait);
        finish(lab, &cx, handle, 3);
    }

    #[test]
    fn same_waker_waiters_have_independent_subscription_ownership() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let (count, waker) = counter();
        let mut first = Box::pin(names.reserve_wait(&cx, "worker"));
        let mut second = Box::pin(names.reserve_wait(&cx, "worker"));
        assert!(poll(first.as_mut(), &waker).is_pending());
        assert!(poll(second.as_mut(), &waker).is_pending());
        drop(first);
        assert_eq!(names.waiters.lock().get("worker").unwrap().users, 1);
        owner.release().unwrap();
        assert!(count.0.load(Ordering::SeqCst) > 0);
        ready(poll(second.as_mut(), &waker)).abort().unwrap();
        drop(second);
        assert!(names.waiters.lock().is_empty());
        assert_eq!(Arc::strong_count(&count), 2);
        finish(lab, &cx, handle, 2);
    }

    #[test]
    fn migrated_wait_retires_the_old_executor_waker() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let (old_count, old_waker) = counter();
        let (new_count, new_waker) = counter();
        let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
        assert!(poll(wait.as_mut(), &old_waker).is_pending());
        assert!(poll(wait.as_mut(), &new_waker).is_pending());
        assert_eq!(Arc::strong_count(&old_count), 2);
        owner.release().unwrap();
        assert_eq!(old_count.0.load(Ordering::SeqCst), 0);
        assert!(new_count.0.load(Ordering::SeqCst) > 0);
        ready(poll(wait.as_mut(), &new_waker)).abort().unwrap();
        drop(wait);
        finish(lab, &cx, handle, 2);
    }

    #[test]
    fn release_between_condition_check_and_first_poll_is_not_lost() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let interest = names.subscribe("worker");
        let epoch = interest.signal.epoch.load(Ordering::Acquire);
        assert!(matches!(names.inner.lock().reserve("worker", cx.task_id(), cx.region_id(), cx.now()),
            Err(NameLeaseError::NameTaken { .. })));
        assert_eq!(interest.signal.notify.waiter_count(), 0);
        owner.release().unwrap();
        // This is the same armed wait used by reserve_wait, first polled AFTER
        // the owner released with no Notify waker registered.
        let mut changed = Box::pin(interest.changed(epoch));
        assert!(poll(changed.as_mut(), Waker::noop()).is_ready());
        drop(changed);
        drop(interest);
        assert!(names.waiters.lock().is_empty());
        finish(lab, &cx, handle, 1);
    }

    #[test]
    fn quota_refusal_after_claim_returns_the_invisible_name() {
        let (mut lab, cx, handle) = fixture(0);
        let names = TrackedNameRegistry::new();
        let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
        assert!(matches!(poll(wait.as_mut(), Waker::noop()),
            Poll::Ready(Err(TrackedNameError::Admission(ObligationAdmissionError::LimitReached { limit: 0, live: 0 })))));
        drop(wait);
        assert!(names.waiters.lock().is_empty());
        assert_eq!(names.whereis("worker"), None);
        assert!(lab.state.set_region_limits(cx.region_id(), crate::record::region::RegionLimits {
            max_obligations: Some(1), ..crate::record::region::RegionLimits::UNLIMITED
        }));
        names.register(&cx, "worker").unwrap().release().unwrap();
        finish(lab, &cx, handle, 1);
    }

    #[test]
    fn elapsed_deadline_refuses_even_an_available_name() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let mut wait = Box::pin(names.reserve_wait_until(&cx, "worker", Time::ZERO));
        assert!(matches!(poll(wait.as_mut(), Waker::noop()),
            Poll::Ready(Err(TrackedNameError::Registry(NameLeaseError::WaitBudgetExceeded { .. })))));
        drop(wait);
        assert!(names.waiters.lock().is_empty());
        assert_eq!(names.whereis("worker"), None);
        finish(lab, &cx, handle, 0);
    }

    #[test]
    fn virtual_deadline_wakes_without_name_or_cancellation_activity() {
        use crate::lab::{LabConfig, LabRuntime};
        use crate::time::{TimerDriverHandle, VirtualClock};
        crate::test_utils::init_test_logging();
        let mut lab = LabRuntime::new(LabConfig::new(0x100_71ae).max_steps(512));
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        lab.state.set_timer_driver(timer.clone());
        let root = lab.state.create_root_region(Budget::INFINITE);
        let region = lab.state.create_child_region(root, Budget::INFINITE).unwrap();
        let (task, handle) = lab.state.create_task(region, Budget::INFINITE, async {}).unwrap();
        let cx = lab.state.task(task).unwrap().cx.clone().unwrap();
        let names = TrackedNameRegistry::new();
        let owner = names.register(&cx, "worker").unwrap();
        let (count, waker) = counter();
        let deadline = Time::from_secs(1);
        let mut wait = Box::pin(names.reserve_wait_until(&cx, "worker", deadline));
        assert!(poll(wait.as_mut(), &waker).is_pending());
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        clock.advance_to(deadline);
        let _ = timer.process_timers();
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(poll(wait.as_mut(), &waker),
            Poll::Ready(Err(TrackedNameError::Registry(NameLeaseError::WaitBudgetExceeded { .. })))));
        drop(wait);
        assert_eq!(names.whereis("worker"), Some(owner.holder()));
        assert!(names.waiters.lock().is_empty());
        owner.release().unwrap();
        finish(lab, &cx, handle, 1);
    }

    #[test]
    fn settlement_notifier_panic_still_wakes_after_returning_quota() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let liveness = Arc::new(());
        let gateway = Arc::new(ObligationGateway::new(
            Arc::clone(lab.state.obligation_gateway().unwrap().mailbox()),
            Arc::new(move || {
                if observed.fetch_add(1, Ordering::SeqCst) == 1 {
                    panic!("planted name settlement failure");
                }
            }),
            Arc::downgrade(&liveness),
        ));
        let owner_cx = cx.clone().with_obligation_gateway(Some(gateway), None);
        let owner = names.register(&owner_cx, "worker").unwrap();
        let (count, waker) = counter();
        let mut wait = Box::pin(names.reserve_wait(&cx, "worker"));
        assert!(poll(wait.as_mut(), &waker).is_pending());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.release()));
        assert!(result.is_err());
        assert!(count.0.load(Ordering::SeqCst) > 0);
        ready(poll(wait.as_mut(), &waker)).abort().unwrap();
        drop(wait);
        finish(lab, &cx, handle, 2);
    }
}
