//! Authenticated membership recovery hints for an existing one-source worker.

use super::{SymbolRepairRequest, SymbolRepairWorker, SymbolRepairWorkerHandle};
use crate::cx::{CancelWakerToken, Cx};
use crate::distributed::membership::MembershipKind;
use crate::distributed::membership::authority::MembershipStamp;
use crate::distributed::membership::owned::{
    OwnedMembershipController, OwnedMembershipError, OwnedMembershipObservation,
    OwnedMembershipObserver,
};
use crate::remote::NodeId;
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::{CancelReason, Time};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Why the caller-owned membership trigger stopped.
///
/// Stopping this trigger does not cancel a repair round, close membership, or
/// stop the separately owned repair worker. Continue to own and drain those
/// services through their existing APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SymbolRepairMembershipStop {
    /// The authenticated membership controller permanently closed.
    ControllerClosed,
    /// Repair request admission was sealed, including a worker still draining.
    WorkerClosed,
    /// The explicit owner, original poller, or current poller was cancelled.
    Cancelled(CancelReason),
}

/// Bounded terminal trigger receipt, not a completed-repair or drain receipt.
///
/// Use the repair worker's round reports to determine whether data was repaired.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SymbolRepairMembershipReport {
    /// Exact source already provisioned in the repair worker.
    pub source: NodeId,
    /// Observed terminal cause.
    pub stop: SymbolRepairMembershipStop,
    /// Hints which filled the worker's one pending request slot.
    pub scheduled: u64,
    /// Hints covered by a request that was already pending.
    pub coalesced: u64,
    /// Last authenticated Alive transition which produced an accepted hint.
    pub last_trigger: Option<MembershipStamp>,
}

/// Caller-driven link from authenticated source recovery to bounded repair.
///
/// The worker constructs this object from its own source identity. It has no
/// free destination, authority key, route, credential, task or transport. Run it
/// in an existing owned task; no task is spawned by construction or polling.
///
/// Only a fresh authenticated transition into Alive requests repair. Repeated
/// Alive heartbeats, duplicates, rejected statements and other members do not.
/// The retained transition also detects Alive -> Suspect -> Alive bursts between
/// polls. The source must still be Alive when the hint is checked.
///
/// Membership can change immediately after that check. A hint is never a lease
/// or grant and cannot authorize ongoing work: the worker's existing transport
/// identity, origin, grant, timeout and byte limits continue to govern each
/// round. The trigger does not elect a source, publish catalogs, cancel an
/// existing round on suspicion, or claim remote quiescence.
#[derive(Debug)]
pub struct SymbolRepairMembership {
    observer: OwnedMembershipObserver,
    worker: SymbolRepairWorkerHandle,
    baseline: OwnedMembershipObservation,
    initial_repair: bool,
    scheduled: u64,
    coalesced: u64,
    last_trigger: Option<MembershipStamp>,
}

impl SymbolRepairWorker {
    /// Link this worker's exact source to its authenticated membership observer.
    ///
    /// The source must already be provisioned in the controller, although its
    /// first authenticated statement may arrive later. Construction performs no
    /// I/O or repair request. Recovery after construction remains visible even
    /// if this object is not polled until after the transition.
    ///
    /// By default an already-Alive source causes no additional initial hint.
    /// Use the returned trigger's initial-repair option if desired. The worker's
    /// own initial/periodic repair configuration remains independently active.
    pub fn membership_trigger(
        &self,
        controller: &OwnedMembershipController,
    ) -> Result<SymbolRepairMembership, OwnedMembershipError> {
        let observer = controller.observe_member(&self.client.source)?;
        let baseline = observer.snapshot();
        Ok(SymbolRepairMembership {
            observer,
            worker: self.handle(),
            baseline,
            initial_repair: false,
            scheduled: 0,
            coalesced: 0,
            last_trigger: None,
        })
    }
}

impl SymbolRepairMembership {
    /// Also request one round when first polled if the source is already Alive.
    #[must_use]
    pub fn with_initial_repair(mut self, enabled: bool) -> Self {
        self.initial_repair = enabled;
        self
    }

    /// The repair worker's exact provisioned source.
    #[must_use]
    pub fn source(&self) -> &NodeId {
        self.observer.node()
    }

    /// Drive authenticated recovery hints until closure or cancellation.
    ///
    /// The explicit owner, original polling context and current polling context
    /// can cancel or shorten this wait. All polling and destruction of observer
    /// waits and repair notifications run under the explicit owner. Dropping the
    /// future unregisters its waits, without changing either service's state.
    /// No repair completion or remote drain is implied by this method's return.
    pub async fn run(mut self, cx: &Cx) -> SymbolRepairMembershipReport {
        let mut control = Control::new(cx);
        let stop = {
            let mut inner = std::pin::pin!(cx.with_ambient(self.run_inner()));
            poll_fn(|task| {
                if let Some(reason) = control.check(task) {
                    return Poll::Ready(SymbolRepairMembershipStop::Cancelled(reason));
                }
                inner.as_mut().poll(task)
            }).await
        };
        SymbolRepairMembershipReport {
            source: self.observer.node().clone(),
            stop,
            scheduled: self.scheduled,
            coalesced: self.coalesced,
            last_trigger: self.last_trigger,
        }
    }

    async fn run_inner(&mut self) -> SymbolRepairMembershipStop {
        let mut previous = self.baseline;
        let mut initial = self.initial_repair;
        loop {
            let current = self.observer.snapshot();
            if current.closed {
                return SymbolRepairMembershipStop::ControllerClosed;
            }
            if worker_closed(&self.worker) {
                return SymbolRepairMembershipStop::WorkerClosed;
            }
            let recovered = current.last_alive_transition != previous.last_alive_transition;
            if current.stamp.is_some_and(|stamp| stamp.kind == MembershipKind::Alive)
                && (initial || recovered)
            {
                // Check again immediately before publishing a hint. Concurrent
                // changes can still race after this read; the hint is not an
                // authority claim and all worker-side checks remain necessary.
                if self.observer.snapshot() != current {
                    crate::runtime::yield_now().await;
                    continue;
                }
                match self.worker.request() {
                    SymbolRepairRequest::Scheduled => {
                        self.scheduled = self.scheduled.saturating_add(1);
                    }
                    SymbolRepairRequest::Coalesced => {
                        self.coalesced = self.coalesced.saturating_add(1);
                    }
                    SymbolRepairRequest::Closed => return SymbolRepairMembershipStop::WorkerClosed,
                }
                self.last_trigger = current.last_alive_transition;
            }
            previous = current;
            initial = false;
            let closed = {
                let mut membership = std::pin::pin!(self.observer.changed(current));
                // changed(rounds_finished) deliberately ignores Stopping. Here
                // admission closure must wake even while a round still drains.
                let mut worker = std::pin::pin!(self.worker.shared.changed.wait_until(|| {
                    worker_closed(&self.worker)
                }));
                poll_fn(|task| {
                    if worker.as_mut().poll(task).is_ready() {
                        return Poll::Ready(true);
                    }
                    if membership.as_mut().poll(task).is_ready() {
                        return Poll::Ready(false);
                    }
                    Poll::Pending
                }).await
            };
            if closed {
                return SymbolRepairMembershipStop::WorkerClosed;
            }
            // A rapidly publishing authority cannot monopolize a native poll.
            crate::runtime::yield_now().await;
        }
    }
}

fn worker_closed(worker: &SymbolRepairWorkerHandle) -> bool {
    let state = worker.shared.state.lock();
    state.stop || state.snapshot.status.is_terminal()
}

struct Cancellation {
    cx: Cx,
    token: Option<CancelWakerToken>,
}

impl Cancellation {
    fn new(cx: Cx) -> Self {
        Self { cx, token: None }
    }

    fn register(&mut self, task: &Context<'_>) {
        self.token = Some(self.cx.refresh_cancel_waker(self.token, task.waker()));
    }
}

impl Drop for Cancellation {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

// Keep one timer and a fixed number of cancellation registrations. Deadline
// values from other clocks contribute their remaining duration, never their
// raw epoch, and cannot replace the explicit owner's captured clock.
struct Control {
    owner: Cancellation,
    initial: Option<Cancellation>,
    poller: Option<Cancellation>,
    clock: Option<TimerDriverHandle>,
    deadline: Option<Time>,
    sleep: Option<Sleep>,
}

impl Control {
    fn new(cx: &Cx) -> Self {
        Self {
            owner: Cancellation::new(cx.clone()),
            initial: Cx::current().map(Cancellation::new),
            poller: None,
            clock: cx.timer_driver(),
            deadline: None,
            sleep: None,
        }
    }

    fn now(&self) -> Time {
        self.clock.as_ref().map_or_else(crate::time::wall_now, TimerDriverHandle::now)
    }

    fn tighten(&mut self, cx: &Cx) {
        let Some(deadline) = cx.budget().deadline else { return; };
        let source_clock = cx.timer_driver();
        let same_clock = match (&self.clock, &source_clock) {
            (Some(owner), Some(source)) => owner.ptr_eq(source),
            (None, None) => true,
            _ => false,
        };
        let translated = if same_clock {
            // An absolute deadline already in the captured domain never moves.
            deadline
        } else {
            // Sample the destination clock first: a preemption between reads
            // may shorten a foreign deadline, but must never extend it.
            let owner_now = self.now();
            let source_now = source_clock.as_ref()
                .map_or_else(crate::time::wall_now, TimerDriverHandle::now);
            owner_now.saturating_add_nanos(
                deadline.as_nanos().saturating_sub(source_now.as_nanos()),
            )
        };
        if self.deadline.is_none_or(|current| translated < current) {
            self.deadline = Some(translated);
            match &mut self.sleep {
                Some(sleep) => sleep.reset(translated),
                None => self.sleep = Some(self.clock.as_ref().map_or_else(
                    || Sleep::new(translated),
                    |clock| Sleep::with_timer_driver(translated, clock.clone()),
                )),
            }
        }
    }

    fn check(&mut self, task: &mut Context<'_>) -> Option<CancelReason> {
        let current = Cx::current().filter(|current| {
            !Arc::ptr_eq(&current.inner, &self.owner.cx.inner)
                && !self.initial.as_ref().is_some_and(|initial| {
                    Arc::ptr_eq(&current.inner, &initial.cx.inner)
                })
        });
        if current.as_ref().is_none_or(|current| self.poller.as_ref().is_none_or(|previous| {
            !Arc::ptr_eq(&previous.cx.inner, &current.inner)
        })) {
            self.poller = current.map(Cancellation::new);
        }
        self.owner.register(task);
        if let Some(initial) = &mut self.initial { initial.register(task); }
        if let Some(poller) = &mut self.poller { poller.register(task); }
        let contexts = [
            Some(self.owner.cx.clone()),
            self.initial.as_ref().map(|guard| guard.cx.clone()),
            self.poller.as_ref().map(|guard| guard.cx.clone()),
        ];
        for cx in contexts.iter().flatten() {
            self.tighten(cx);
        }
        if self.deadline.is_some_and(|deadline| self.now() >= deadline) {
            return Some(CancelReason::deadline());
        }
        {
            let _ambient = self.owner.cx.clone().set_current_restricted();
            if self.sleep.as_mut().is_some_and(|sleep| {
                Pin::new(sleep).poll_deadline(task).is_ready()
            }) {
                return Some(CancelReason::deadline());
            }
        }
        for cx in contexts.iter().flatten() {
            if cx.checkpoint().is_err() {
                return Some(cx.cancel_reason().unwrap_or_else(|| {
                    CancelReason::user("membership repair trigger cancelled")
                }));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests;
