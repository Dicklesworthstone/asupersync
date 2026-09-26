//! Runtime-tracked membership leases with explicit owner-driven expiry.
//!
//! Unlike the metadata-only controller, every accepted guard owns a checked
//! `Cx` obligation. No arena ID is fabricated from a mailbox ticket. The runtime
//! accounts for admission before its arena projection catches up. Settlement
//! posts the existing commit/abort operation; it does not certify remote drain.
//! Keep each guard within its admitting task: a Rust move is not a runtime
//! obligation handoff. Closing or dropping the expiry driver aborts local leases.

use super::authority::{
    MembershipApplied, MembershipControlError, MembershipControllerLimits,
    MembershipFloor, MembershipLeaseController, MembershipStamp,
};
use super::MembershipKind;
use crate::cx::Cx;
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::remote::NodeId;
use crate::runtime::obligation_mailbox::{
    ObligationAdmissionError, ObligationGateway, ObligationToken,
};
use crate::security::AuthKey;
use crate::sync::Notify;
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::Time;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::Poll;
use std::time::Duration;

/// Local guard state, not a remote cancellation or arena-application receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OwnedLeaseStatus {
    /// Admitted and not yet retired by local membership ownership.
    Active,
    /// The owner requested clean release.
    Released,
    /// The guard was dropped without clean release.
    Dropped,
    /// The local clock reached its deadline.
    Expired,
    /// The authority marked its incarnation Dead or Left.
    Revoked,
    /// A newer incarnation replaced the guard's incarnation.
    Superseded,
    /// The controller or its expiry driver closed.
    Closed,
}

/// Admission/settlement refusal; no untracked compatibility fallback is used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OwnedMembershipError {
    /// Existing authenticated policy or clock validation refused the operation.
    #[error(transparent)]
    Control(#[from] MembershipControlError),
    /// Checked runtime reservation failed before a guard was exposed.
    #[error(transparent)]
    Admission(#[from] ObligationAdmissionError),
    /// An untracked context cannot create an owned lease.
    #[error("membership leases require a runtime obligation gateway")]
    NoRuntime,
    /// Another local operation currently holds the membership state.
    #[error("owned membership controller is busy")]
    Busy,
    /// The caller requested cancellation.
    #[error("membership lease owner is cancelled")]
    Cancelled,
    /// Closing is terminal for this controller instance.
    #[error("owned membership controller is closed")]
    Closed,
    /// Another task already owns the expiry loop.
    #[error("owned membership controller already has an expiry driver")]
    DriverRunning,
    /// A terminal guard cannot be renewed or committed again.
    #[error("membership lease has ended: {0:?}")]
    Ended(OwnedLeaseStatus),
    /// Holder completion or runtime retirement already won settlement.
    #[error("runtime obligation settlement was not accepted")]
    SettlementLost,
}

struct Signal { status: AtomicU8, changed: Notify }
impl Signal {
    fn status(&self) -> OwnedLeaseStatus {
        match self.status.load(Ordering::Acquire) {
            0 => OwnedLeaseStatus::Active, 1 => OwnedLeaseStatus::Released,
            2 => OwnedLeaseStatus::Dropped, 3 => OwnedLeaseStatus::Expired,
            4 => OwnedLeaseStatus::Revoked, 5 => OwnedLeaseStatus::Superseded,
            _ => OwnedLeaseStatus::Closed,
        }
    }
}
struct Entry {
    node: NodeId,
    incarnation: u64,
    deadline: Time,
    token: Option<ObligationToken>,
    signal: Arc<Signal>,
    notification: Option<Arc<ObligationGateway>>,
    settlement_accepted: bool,
}
struct State {
    policy: MembershipLeaseController,
    entries: BTreeMap<u64, Entry>,
    next: u64,
    accepted: usize,
    pending: usize,
    limit: usize,
    now: Time,
    closed: bool,
    running: bool,
}
struct Shared { state: Mutex<State>, clock: TimerDriverHandle, changed: Notify }

/// An opt-in controller whose guards reserve real runtime lease obligations.
///
/// Clones share admission and policy. `max_lease_ids` bounds lifetime successful
/// grants plus simultaneous pending registrations, not just currently live ones.
/// Use `run` in an owned task for automatic expiry, or explicitly call `expire`.
/// Dead/Left and newer-incarnation updates settle affected local obligations
/// immediately. Expiry and controller shutdown do not affect the parent Cx.
#[derive(Clone)]
pub struct OwnedMembershipController { shared: Arc<Shared> }
impl fmt::Debug for OwnedMembershipController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.shared.state.lock();
        f.debug_struct("OwnedMembershipController")
            .field("active", &state.entries.len()).field("pending", &state.pending)
            .field("closed", &state.closed).finish_non_exhaustive()
    }
}

/// One non-cloneable local lease owner. Drop explicitly aborts, never leaks.
///
/// The guard must remain within the lifetime of its admitting task. Completing
/// that task while retaining its guard elsewhere is still an obligation leak;
/// this API does not transfer holder liability. `status` describes membership,
/// not arbitrary remote work. Settlement uses the token's original runtime.
pub struct OwnedMembershipLease {
    shared: Arc<Shared>, id: u64, signal: Arc<Signal>, ticket: u64,
}
impl fmt::Debug for OwnedMembershipLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedMembershipLease").field("status", &self.status()).finish_non_exhaustive()
    }
}

fn observe(state: &mut State, now: Time) -> Result<(), OwnedMembershipError> {
    if now < state.now { return Err(MembershipControlError::Clock.into()); }
    state.now = now;
    Ok(())
}
fn alive(state: &State, node: &NodeId, incarnation: u64) -> bool {
    state.policy.stamp(node).is_some_and(|s| s.incarnation == incarnation && s.kind == MembershipKind::Alive)
}
fn remove(state: &mut State, id: u64, status: OwnedLeaseStatus) -> Option<Entry> {
    let entry = state.entries.remove(&id)?;
    Some(retire(entry, status))
}
fn retire(mut entry: Entry, status: OwnedLeaseStatus) -> Entry {
    // Choose the checked terminal BEFORE publishing local invalidation. A holder
    // may observe status without waiting for a wake and immediately complete.
    // Deferred settlement runs no callback and is safe under the owner lock.
    let token = entry.token.take().expect("owned unsettled token");
    let (accepted, notification) = if status == OwnedLeaseStatus::Released { token.commit_deferred() }
        else { token.abort_deferred(ObligationAbortReason::Cancel) };
    entry.settlement_accepted = accepted;
    entry.notification = notification;
    entry.signal.status.store(status as u8, Ordering::Release);
    entry
}

// All decisions/posts precede all callbacks. One hostile notifier must not
// prevent other already-retired owners from posting or waking their waiters.
fn finish(shared: &Shared, entries: Vec<Entry>) -> usize {
    let accepted = entries.iter().filter(|entry| entry.settlement_accepted).count();
    let mut panic = None;
    for entry in &entries {
        for callback in [false, true] {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if callback { entry.signal.changed.notify_waiters(); }
                else if let Some(gateway) = &entry.notification { gateway.notify(); }
            }));
            if let Err(payload) = result { if panic.is_none() { panic = Some(payload); } }
        }
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| shared.changed.notify_waiters()));
    if let Err(payload) = result { if panic.is_none() { panic = Some(payload); } }
    if !std::thread::panicking() { if let Some(payload) = panic { std::panic::resume_unwind(payload); } }
    accepted
}

// Reserving before calling the runtime avoids callbacks under the policy mutex.
// Revalidation after runtime admission closes the concurrent revoke/close race.
struct Registration { shared: Arc<Shared>, pending: bool, token: Option<ObligationToken> }
impl Drop for Registration {
    fn drop(&mut self) {
        if self.pending { self.shared.state.lock().pending -= 1; }
        if let Some(token) = self.token.take() {
            let (_, notification) = token.abort_deferred(ObligationAbortReason::Error);
            if let Some(gateway) = notification { gateway.notify(); }
        }
    }
}

impl OwnedMembershipController {
    /// Provision independent membership authority and an explicit expiry clock.
    /// No runtime obligation, task, route or peer authority is acquired here.
    pub fn new(
        authority: NodeId, epoch: u64, key: AuthKey, floors: Vec<MembershipFloor>,
        limits: MembershipControllerLimits, clock: TimerDriverHandle,
    ) -> Result<Self, OwnedMembershipError> {
        let policy = MembershipLeaseController::new(authority, epoch, key, floors, limits)?;
        Ok(Self { shared: Arc::new(Shared { state: Mutex::new(State {
            policy, entries: BTreeMap::new(), next: 0, accepted: 0, pending: 0,
            limit: limits.max_lease_ids, now: Time::ZERO, closed: false, running: false,
        }), clock, changed: Notify::new() }) })
    }

    /// Last authenticated membership stamp, without granting new authority.
    pub fn stamp(&self, node: &NodeId) -> Option<MembershipStamp> { self.shared.state.lock().policy.stamp(node) }
    /// Live guards plus registrations currently crossing runtime admission.
    pub fn live_leases(&self) -> usize {
        let state = self.shared.state.lock(); state.entries.len() + state.pending
    }

    /// Apply an authenticated decision from the separately authenticated peer.
    /// This requires both authority identity and statement MAC. Retired local
    /// tokens post abort before return; arena projection and remote drain may lag.
    pub fn apply_authenticated(&self, peer: &NodeId, bytes: &[u8]) -> Result<MembershipApplied, OwnedMembershipError> {
        let mut state = self.shared.state.try_lock().ok_or(OwnedMembershipError::Busy)?;
        if state.closed { return Err(OwnedMembershipError::Closed); }
        if peer != state.policy.authority() { return Err(MembershipControlError::Authority.into()); }
        // Allocate before changing the policy or detaching any owned tokens.
        let mut retired = Vec::with_capacity(state.entries.len());
        let mut ids = Vec::with_capacity(state.entries.len());
        let result = state.policy.apply_authenticated(bytes)?;
        for (&id, entry) in &state.entries {
            if let Some(stamp) = state.policy.stamp(&entry.node) {
                let reason = if stamp.incarnation != entry.incarnation { Some(OwnedLeaseStatus::Superseded) }
                    else if matches!(stamp.kind, MembershipKind::Dead | MembershipKind::Left) { Some(OwnedLeaseStatus::Revoked) }
                    else { None };
                if let Some(reason) = reason { ids.push((id, reason)); }
            }
        }
        for (id, reason) in ids { retired.push(remove(&mut state, id, reason).expect("selected lease")); }
        let count = retired.len();
        drop(state);
        finish(&self.shared, retired);
        Ok(match result { MembershipApplied::Applied { .. } => MembershipApplied::Applied { revoked: count }, MembershipApplied::Duplicate => MembershipApplied::Duplicate })
    }

    /// Reserve a checked runtime obligation only for an accepted Alive incarnation.
    /// Missing runtime, quota/cancellation failure, or a concurrent revocation
    /// refuses without returning a guard. The runtime callback runs outside locks.
    pub fn try_grant(&self, cx: &Cx, node: &NodeId, incarnation: u64, duration: Duration) -> Result<OwnedMembershipLease, OwnedMembershipError> {
        if cx.is_cancel_requested() { return Err(OwnedMembershipError::Cancelled); }
        let now = self.shared.clock.now();
        let deadline = now + duration;
        if duration.is_zero() || deadline <= now { return Err(MembershipControlError::GrantDenied.into()); }
        let mut state = self.shared.state.lock();
        observe(&mut state, now)?;
        if state.closed { return Err(OwnedMembershipError::Closed); }
        if !alive(&state, node, incarnation) { return Err(MembershipControlError::GrantDenied.into()); }
        if state.accepted.checked_add(state.pending).is_none_or(|n| n >= state.limit) {
            return Err(MembershipControlError::Capacity.into());
        }
        let id = state.next.checked_add(1).ok_or(MembershipControlError::Capacity)?;
        state.next = id; state.pending += 1;
        drop(state);
        let mut registration = Registration { shared: Arc::clone(&self.shared), pending: true, token: None };
        registration.token = Some(cx.try_register_obligation_checked(ObligationKind::Lease, cx.task_id())?
            .ok_or(OwnedMembershipError::NoRuntime)?);
        let now = self.shared.clock.now();
        let signal = Arc::new(Signal { status: AtomicU8::new(0), changed: Notify::new() });
        let mut state = self.shared.state.lock();
        observe(&mut state, now)?;
        if state.closed { return Err(OwnedMembershipError::Closed); }
        if cx.is_cancel_requested() { return Err(OwnedMembershipError::Cancelled); }
        if now >= deadline || !alive(&state, node, incarnation) { return Err(MembershipControlError::GrantDenied.into()); }
        let ticket = registration.token.as_ref().expect("registered token").ticket();
        state.entries.insert(id, Entry { node: node.clone(), incarnation, deadline,
            token: registration.token.take(), signal: Arc::clone(&signal), notification: None, settlement_accepted: false });
        state.pending -= 1; state.accepted += 1; registration.pending = false;
        drop(state);
        let lease = OwnedMembershipLease { shared: Arc::clone(&self.shared), id, signal, ticket };
        self.shared.changed.notify_waiters();
        Ok(lease)
    }

    /// Abort all locally due tokens. Return the number of guards retired, not a
    /// synchronous arena-drain count. Deadline ties expire rather than renew.
    pub fn expire(&self) -> Result<usize, OwnedMembershipError> {
        let now = self.shared.clock.now();
        let mut state = self.shared.state.lock(); observe(&mut state, now)?;
        let ids: Vec<_> = state.entries.iter().filter(|(_, entry)| now >= entry.deadline).map(|(&id, _)| id).collect();
        let mut retired = Vec::with_capacity(ids.len());
        for id in ids { retired.push(remove(&mut state, id, OwnedLeaseStatus::Expired).expect("due lease")); }
        let count = retired.len(); drop(state);
        if count != 0 { finish(&self.shared, retired); }
        Ok(count)
    }

    /// Permanently close admission and abort every current local guard. A pending
    /// registration rechecks closure and aborts before becoming observable.
    pub fn close(&self) {
        let mut state = self.shared.state.lock();
        let mut retired = Vec::with_capacity(state.entries.len());
        state.closed = true;
        for (_, entry) in std::mem::take(&mut state.entries) {
            retired.push(retire(entry, OwnedLeaseStatus::Closed));
        }
        drop(state); finish(&self.shared, retired);
    }

    /// Drive real expiry timers in the calling task, without spawning work.
    /// Cancellation, external future drop and clock failure close local admission
    /// and abort guards. Only one driver is allowed. `close` wakes an idle driver.
    /// This does not abort the holder tasks or wait for remote computations.
    pub async fn run(&self, cx: &Cx) -> Result<(), OwnedMembershipError> {
        {
            let mut state = self.shared.state.lock();
            if state.running { return Err(OwnedMembershipError::DriverRunning); }
            if state.closed { return Err(OwnedMembershipError::Closed); }
            state.running = true;
        }
        struct Driver<'a>(&'a OwnedMembershipController);
        impl Drop for Driver<'_> { fn drop(&mut self) { self.0.close(); } }
        let _driver = Driver(self);
        let mut cancelled = std::pin::pin!(cx.cancelled());
        loop {
            self.expire()?;
            let deadline = {
                let state = self.shared.state.lock();
                if state.closed { return Ok(()); }
                state.entries.values().map(|entry| entry.deadline).min()
            };
            // Notify::notified captures generation on first poll, NOT creation.
            // Its predicate-aware API closes the snapshot-to-registration race.
            let mut changed = std::pin::pin!(self.shared.changed.wait_until(|| {
                let state = self.shared.state.lock();
                state.closed || state.entries.values().map(|entry| entry.deadline).min() != deadline
            }));
            let mut sleep = deadline.map(|at| Box::pin(Sleep::with_timer_driver(at, self.shared.clock.clone())));
            poll_fn(|task| {
                if cancelled.as_mut().poll(task).is_ready() { return Poll::Ready(Err(OwnedMembershipError::Cancelled)); }
                if changed.as_mut().poll(task).is_ready() { return Poll::Ready(Ok(())); }
                // Only the explicit owner's cancellation above can stop this
                // driver. Ambient cancellation must not turn every future
                // deadline into a ready timer and spin this expiry loop.
                if sleep.as_mut().is_some_and(|timer| timer.as_mut().poll_deadline(task).is_ready()) { return Poll::Ready(Ok(())); }
                Poll::Pending
            }).await?;
        }
    }
}

impl OwnedMembershipLease {
    /// Original checked mailbox ticket; it is NOT a fabricated ObligationId.
    pub fn ticket(&self) -> u64 { self.ticket }
    /// Local membership state, not proof that remote work has stopped.
    pub fn status(&self) -> OwnedLeaseStatus { self.signal.status() }
    /// Wait for local retirement; cancel-safe and independent of parent cancellation.
    pub async fn ended(&self) -> OwnedLeaseStatus {
        self.signal.changed.wait_until(|| self.status() != OwnedLeaseStatus::Active).await;
        self.status()
    }
    /// Renew this exact guard while unexpired. Suspicion only pauses new grants.
    pub fn renew(&self, duration: Duration) -> Result<(), OwnedMembershipError> {
        let now = self.shared.clock.now();
        let mut state = self.shared.state.lock(); observe(&mut state, now)?;
        let Some(entry) = state.entries.get_mut(&self.id) else { return Err(OwnedMembershipError::Ended(self.status())); };
        if now >= entry.deadline {
            let retired = vec![remove(&mut state, self.id, OwnedLeaseStatus::Expired).expect("expired")];
            drop(state); finish(&self.shared, retired);
            return Err(OwnedMembershipError::Ended(OwnedLeaseStatus::Expired));
        }
        if duration.is_zero() || now + duration <= now { return Err(MembershipControlError::GrantDenied.into()); }
        entry.deadline = now + duration;
        drop(state); self.shared.changed.notify_waiters(); Ok(())
    }
    /// Release consumes the guard and requires the real checked commit to win.
    /// A due/revoked guard cannot be turned back into a successful release.
    pub fn release(self) -> Result<(), OwnedMembershipError> {
        let now = self.shared.clock.now();
        let mut state = self.shared.state.lock(); observe(&mut state, now)?;
        let Some(entry) = state.entries.get(&self.id) else { return Err(OwnedMembershipError::Ended(self.status())); };
        let expired = now >= entry.deadline;
        let status = if expired { OwnedLeaseStatus::Expired } else { OwnedLeaseStatus::Released };
        let retired = vec![remove(&mut state, self.id, status).expect("released")];
        drop(state);
        let won = finish(&self.shared, retired);
        if expired { Err(OwnedMembershipError::Ended(status)) }
        else if won == 1 { Ok(()) } else { Err(OwnedMembershipError::SettlementLost) }
    }
}
impl Drop for OwnedMembershipLease {
    fn drop(&mut self) {
        let mut state = self.shared.state.lock();
        let mut retired = Vec::with_capacity(1);
        if let Some(entry) = remove(&mut state, self.id, OwnedLeaseStatus::Dropped) { retired.push(entry); }
        drop(state);
        if !retired.is_empty() { finish(&self.shared, retired); }
    }
}

#[cfg(test)]
mod tests;

/// Execute protected work with independent subtree cancellation and drain receipts.
pub mod work;

// br-asupersync-l1ekl5: re-export the work types that consumers import via the
// `owned::` path (durable/runtime.rs). The work-submodule split in 8fb795b7e
// moved these here but omitted the re-export, breaking the default lib build.
pub use work::{MembershipWorkError, MembershipWorkReport};
