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
#[path = "permit_wait_tests_inline_tests.rs"]
mod wait_tests;
