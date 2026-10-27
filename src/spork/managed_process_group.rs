//! Live node-local process groups with bounded admission and checked leases.
//!
//! One region-owned controller monitors actual member tasks. It owns the
//! leases because a member's terminal obligation audit precedes DOWN delivery.
//! Moving a membership guard never changes the original member identity.
//!
//! Broadcast is a sequence of checked two-phase commits, not atomic multicast.
//! Returned reports retain partial delivery. Abandoning a broadcast can leave
//! its delivered prefix; no old incarnation is ever routed into a replacement.

use super::process_group::{
    BroadcastBackpressurePolicy, GroupEvent, GroupEventBatch, GroupEventCursor,
    GroupMember, GroupMemberId, GroupName, GroupSnapshot, ProcessGroupError, ProcessGroupState,
};
use crate::channel::mpsc;
use crate::cx::{CancelWakerToken, ChildRegion, ChildRegionError, ChildRegionSpec, Cx,
    TrackedNameError, TrackedNameLease, TrackedNameRegistry};
use crate::monitor::{DownReason, Monitor, MonitorOpening, WatchError};
use crate::record::task::TaskOutcome;
use crate::remote::NodeId;
use crate::runtime::obligation_mailbox::{ObligationAdmissionError, ObligationMailbox};
use crate::runtime::{JoinError, SpawnError, TaskHandle};
use crate::types::{CancelReason, PanicPayload, RegionId};
use parking_lot::Mutex;
use std::collections::{BTreeMap, VecDeque};
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Waker};

const SCAN_QUANTUM: usize = 64;

/// Explicit bounds for all work retained by the controller.
#[derive(Debug, Clone)]
pub struct ManagedProcessGroupConfig {
    /// Active memberships, including unclaimed join receipts.
    pub max_members: usize,
    /// Messages per incarnation; must be nonzero.
    pub mailbox_capacity: usize,
    /// Queued/unclaimed join receipts plus broadcasts and event waits; nonzero.
    /// An unclaimed receipt retains credit even after its member departs, until
    /// the caller reads or drops that future. Its member lease is already settled.
    /// Receive, leave and shutdown bypass this limit so they can release capacity.
    pub max_requests: usize,
    /// Retained membership events; must be nonzero.
    pub event_capacity: usize,
    /// Actual region envelope, met with the caller's existing authority.
    pub region: ChildRegionSpec,
}
impl ManagedProcessGroupConfig {
    /// Construct explicit bounds and inherit the caller's region envelope.
    #[must_use]
    pub const fn new(max_members: usize, mailbox_capacity: usize, max_requests: usize, event_capacity: usize) -> Self {
        Self { max_members, mailbox_capacity, max_requests, event_capacity, region: ChildRegionSpec::inherit() }
    }
}

/// Admission or lifecycle refusal; no variant asserts quiescence.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ManagedGroupError {
    /// Invalid capacities or a name/node exceeding 255 bytes.
    InvalidConfig,
    /// All retained member slots are occupied.
    Capacity,
    /// All outstanding request slots are occupied.
    Busy,
    /// This actual task already has a live incarnation.
    DuplicateMember(GroupMemberId),
    /// A runtime-wired, still-live task context is required.
    RuntimeRequired,
    /// Another runtime's numeric task IDs cannot address this group.
    DifferentRuntime,
    /// The caller acknowledged cancellation.
    Cancelled(CancelReason),
    /// The controller is stopping or unavailable.
    Closed,
    /// Actual member-monitor establishment failed.
    Watch(WatchError),
    /// Checked lease admission or settlement failed.
    Lease(TrackedNameError),
    /// Canonical membership sequencing refused a transition.
    State(ProcessGroupError),
    /// Actual child-region admission failed.
    Region(Arc<ChildRegionError>),
    /// Actual controller submission failed.
    Spawn(Arc<SpawnError>),
}
impl std::fmt::Display for ManagedGroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("invalid process-group limits or identity"),
            Self::Capacity => f.write_str("process-group member capacity exhausted"),
            Self::Busy => f.write_str("process-group request capacity exhausted"),
            Self::DuplicateMember(id) => write!(f, "task already joined process group: {id}"),
            Self::RuntimeRequired => f.write_str("process group requires a live runtime context"),
            Self::DifferentRuntime => f.write_str("process group belongs to a different runtime"),
            Self::Cancelled(_) => f.write_str("process-group operation cancelled"),
            Self::Closed => f.write_str("process group is closed"),
            Self::Watch(error) => write!(f, "process-group monitor: {error}"),
            Self::Lease(error) => write!(f, "process-group lease: {error}"),
            Self::State(error) => write!(f, "process-group state: {error}"),
            Self::Region(error) => write!(f, "process-group region: {error}"),
            Self::Spawn(error) => write!(f, "process-group controller: {error}"),
        }
    }
}
impl std::error::Error for ManagedGroupError {}

/// Bounded replay with explicit loss of older history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedGroupEventBatch {
    /// Existing canonical events and cursor.
    pub batch: GroupEventBatch,
    /// Earlier events this cursor missed.
    pub skipped: u64,
    /// Oldest retained event, or next sequence when the ring is empty.
    pub first_retained: GroupEventCursor,
    /// No further events can arrive from this owner.
    pub closed: bool,
}

/// Delivery result for one captured incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedGroupRecipientStatus {
    /// Checked two-phase commit accepted the cloned message.
    Delivered,
    /// Skip policy observed a full mailbox.
    Skipped,
    /// Error policy observed a full mailbox and stopped traversal.
    Backpressured,
    /// This incarnation left, died or lost its receiver.
    Departed,
    /// Runtime obligation admission refused before moving a message.
    AdmissionRefused(ObligationAdmissionError),
    /// Cancellation stopped this recipient.
    Cancelled,
    /// An earlier refusal or cancellation stopped traversal.
    NotAttempted,
}
/// An actual member and its join-generation delivery result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedGroupRecipient {
    /// Actual task and configured node identity.
    pub member: GroupMemberId,
    /// Canonical monotonically increasing join sequence.
    pub generation: u64,
    /// Exact delivery classification.
    pub status: ManagedGroupRecipientStatus,
}
/// Complete accounting for a broadcast that returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedGroupBroadcastReport {
    /// Target group.
    pub group: GroupName,
    /// Selected slow-member policy.
    pub policy: BroadcastBackpressurePolicy,
    /// Every captured incarnation in canonical join order.
    pub recipients: Vec<ManagedGroupRecipient>,
    /// Cancellation without discarding any delivered prefix.
    pub cancellation: Option<CancelReason>,
}
impl ManagedGroupBroadcastReport {
    /// Whether every captured incarnation accepted a message.
    #[must_use]
    pub fn is_all_delivered(&self) -> bool {
        self.cancellation.is_none() && self.recipients.iter().all(|r| r.status == ManagedGroupRecipientStatus::Delivered)
    }
}

/// Receive cancellation or actual membership departure.
#[derive(Debug, Clone)]
pub enum ManagedGroupRecvError {
    /// The caller acknowledged cancellation.
    Cancelled(CancelReason),
    /// This incarnation was withdrawn.
    Departed(GroupEvent),
    /// Controller disappearance without a canonical terminal event.
    Closed,
}
impl std::fmt::Display for ManagedGroupRecvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Cancelled(_) => "process-group receive cancelled",
            Self::Departed(_) => "process-group membership departed",
            Self::Closed => "process-group mailbox closed",
        })
    }
}
impl std::error::Error for ManagedGroupRecvError {}

/// Controller accounting published after its leases settle.
#[derive(Debug, Default)]
pub struct ManagedGroupReport {
    /// Published incarnations.
    pub joined: u64,
    /// Explicit or abandoned-guard leaves.
    pub left: u64,
    /// Task-death or shutdown departures.
    pub down: u64,
    /// Refused settlements; nonzero is not successful cleanup.
    pub settlement_failures: u64,
    /// Finite canonical sequence exhaustion, if encountered.
    pub state_error: Option<ProcessGroupError>,
}
/// Actual enclosing-region close receipt.
#[derive(Debug)]
pub struct ManagedGroupClose {
    /// Aggregate result, possibly ordinary shutdown cancellation.
    pub outcome: TaskOutcome,
    /// Explicit finalizer outcome when present.
    pub cleanup_outcome: Option<TaskOutcome>,
    /// Descendant panic retained by the runtime.
    pub descendant_panic: Option<PanicPayload>,
}
/// Controller retirement and enclosing-region quiescence.
#[derive(Debug)]
pub struct ManagedProcessGroupExit {
    /// Actual controller result; a panic is not a successful report.
    pub task_outcome: Result<ManagedGroupReport, JoinError>,
    /// Actual descendant/finalizer closure.
    pub close: Result<ManagedGroupClose, ChildRegionError>,
}

#[derive(Default)]
struct WakeSlot(Mutex<Option<Waker>>);
impl WakeSlot {
    fn register(&self, waker: &Waker) {
        let incoming = waker.clone();
        let retired = self.0.lock().replace(incoming);
        callback(|| drop(retired));
    }
    fn notify(&self) {
        let waker = self.0.lock().take();
        callback(|| { if let Some(waker) = waker { waker.wake(); } });
    }
}
impl Drop for WakeSlot {
    fn drop(&mut self) {
        let retired = self.0.get_mut().take();
        callback(|| drop(retired));
    }
}
#[derive(Default)]
struct WaitHub(Mutex<Vec<Weak<WakeSlot>>>);
impl WaitHub {
    fn subscribe(&self) -> Arc<WakeSlot> {
        let slot = Arc::new(WakeSlot::default());
        let mut slots = self.0.lock();
        slots.retain(|entry| entry.strong_count() != 0);
        slots.push(Arc::downgrade(&slot));
        slot
    }
    fn notify(&self) {
        let slots: Vec<_> = self.0.lock().iter().filter_map(Weak::upgrade).collect();
        for slot in slots { slot.notify(); }
    }
}
#[derive(Default)]
struct Signal { wake: WakeSlot, stopping: AtomicBool, abort_leases: AtomicBool, abort_on_down: AtomicBool }
impl Signal {
    fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.wake.notify();
    }
}
struct Credits { used: AtomicUsize, limit: usize }
struct Credit(Arc<Credits>);
impl Credit {
    fn acquire(credits: &Arc<Credits>) -> Result<Self, ManagedGroupError> {
        let mut used = credits.used.load(Ordering::Relaxed);
        loop {
            if used >= credits.limit { return Err(ManagedGroupError::Busy); }
            match credits.used.compare_exchange_weak(used, used + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Ok(Self(Arc::clone(credits))),
                Err(actual) => used = actual,
            }
        }
    }
}
impl Drop for Credit {
    fn drop(&mut self) { self.0.used.fetch_sub(1, Ordering::AcqRel); }
}
struct CancelRegistration<'a> { cx: &'a Cx, token: Option<CancelWakerToken> }
impl<'a> CancelRegistration<'a> {
    fn new(cx: &'a Cx) -> Self { Self { cx, token: None } }
    fn poll(&mut self, waker: &Waker) {
        self.token = Some(self.cx.refresh_cancel_waker(self.token, waker));
    }
}
impl Drop for CancelRegistration<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() { callback(|| self.cx.clear_cancel_waker(token)); }
    }
}
struct MemberTerminal {
    leave: AtomicBool,
    active: AtomicBool,
    outcome: Mutex<Option<Result<GroupEvent, ManagedGroupError>>>,
    signal: Arc<Signal>,
    waiters: Arc<WaitHub>,
}
impl MemberTerminal {
    fn request_leave(&self) {
        self.leave.store(true, Ordering::Release);
        self.signal.wake.notify();
        self.waiters.notify();
    }
    fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire) && !self.leave.load(Ordering::Acquire)
    }
    fn result(&self) -> Option<Result<GroupEvent, ManagedGroupError>> { self.outcome.lock().clone() }
    fn finish(&self, result: Result<GroupEvent, ManagedGroupError>) {
        {
            let mut current = self.outcome.lock();
            if current.is_none() { *current = Some(result); }
        }
        self.active.store(false, Ordering::Release);
        self.waiters.notify();
    }
}
struct Route<M> { member: GroupMember, sender: mpsc::Sender<M>, terminal: Arc<MemberTerminal> }
impl<M> Clone for Route<M> {
    fn clone(&self) -> Self {
        Self { member: self.member.clone(), sender: self.sender.clone(), terminal: Arc::clone(&self.terminal) }
    }
}
struct Joined<M> {
    member: GroupMember,
    event: GroupEvent,
    receiver: mpsc::Receiver<M>,
    terminal: Arc<MemberTerminal>,
}
struct Reply<M> {
    value: Option<Result<Joined<M>, ManagedGroupError>>,
    abandoned: bool,
    received: bool,
    credit: Option<Credit>,
}
struct JoinRequest<M> {
    member: GroupMemberId,
    reply: Mutex<Reply<M>>,
    wake: WakeSlot,
    signal: Arc<Signal>,
}
impl<M> JoinRequest<M> {
    fn disposition(&self) -> (bool, bool) {
        let reply = self.reply.lock();
        (reply.abandoned, reply.received)
    }
    fn finish(&self, value: Result<Joined<M>, ManagedGroupError>) {
        let mut unused = Some(value);
        {
            let mut reply = self.reply.lock();
            if !reply.abandoned && !reply.received && reply.value.is_none() {
                reply.value = unused.take();
            }
        }
        // A receiver may contain arbitrary M destructors.
        drop(unused);
        self.wake.notify();
    }
}
struct JoinWait<'a, M> {
    request: Arc<JoinRequest<M>>,
    cancel: CancelRegistration<'a>,
    finished: bool,
}
impl<M> Future for JoinWait<'_, M> {
    type Output = Result<Joined<M>, ManagedGroupError>;
    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.cancel.poll(task.waker());
        this.request.wake.register(task.waker());
        if this.cancel.cx.checkpoint().is_err() {
            return Poll::Ready(Err(cancelled(this.cancel.cx)));
        }
        let (value, credit) = {
            let mut reply = this.request.reply.lock();
            let value = reply.value.take();
            if value.is_some() { reply.received = true; }
            let credit = if value.is_some() { reply.credit.take() } else { None };
            (value, credit)
        };
        drop(credit);
        if let Some(value) = value {
            this.request.signal.wake.notify();
            this.finished = true;
            Poll::Ready(value)
        } else { Poll::Pending }
    }
}
impl<M> Drop for JoinWait<'_, M> {
    fn drop(&mut self) {
        if !self.finished { self.request.reply.lock().abandoned = true; }
        self.request.signal.wake.notify();
    }
}
struct SharedState<M> {
    queue: VecDeque<Arc<JoinRequest<M>>>,
    requests: Vec<Weak<JoinRequest<M>>>,
    routes: BTreeMap<GroupMemberId, Route<M>>,
    events: VecDeque<GroupEvent>,
    next_event: u64,
    closed: bool,
    ready: Option<Result<(), ManagedGroupError>>,
}
struct Shared<M> {
    name: GroupName,
    node: NodeId,
    config: ManagedProcessGroupConfig,
    runtime: Weak<ObligationMailbox>,
    state: Mutex<SharedState<M>>,
    signal: Arc<Signal>,
    waiters: Arc<WaitHub>,
    credits: Arc<Credits>,
}
impl<M> Shared<M> {
    fn validate(&self, cx: &Cx) -> Result<(), ManagedGroupError> {
        let identity = runtime_identity(cx)?;
        if !Weak::ptr_eq(&self.runtime, &identity) {
            return Err(ManagedGroupError::DifferentRuntime);
        }
        Ok(())
    }
    fn publish(&self, event: GroupEvent) {
        let retired = {
            let mut state = self.state.lock();
            state.next_event = event.sequence().saturating_add(1);
            let retired = if state.events.len() == self.config.event_capacity { state.events.pop_front() } else { None };
            state.events.push_back(event);
            retired
        };
        drop(retired);
        self.waiters.notify();
    }
    fn events(&self, cursor: GroupEventCursor) -> ManagedGroupEventBatch {
        let state = self.state.lock();
        let first = state.events.front().map_or(state.next_event, GroupEvent::sequence);
        let events = state.events.iter().filter(|event| event.sequence() >= cursor.next_sequence()).cloned().collect();
        ManagedGroupEventBatch {
            batch: GroupEventBatch::new(events, GroupEventCursor::from_next_sequence(state.next_event.max(cursor.next_sequence()))),
            skipped: first.saturating_sub(cursor.next_sequence()),
            first_retained: GroupEventCursor::from_next_sequence(first),
            closed: state.closed,
        }
    }
    fn close(&self) {
        self.signal.stopping.store(true, Ordering::Release);
        let (queued, requests, routes) = {
            let mut state = self.state.lock();
            state.closed = true;
            if state.ready.is_none() { state.ready = Some(Err(ManagedGroupError::Closed)); }
            let requests: Vec<_> = state.requests.iter().filter_map(Weak::upgrade).collect();
            (std::mem::take(&mut state.queue), requests, std::mem::take(&mut state.routes))
        };
        for route in routes.into_values() {
            route.terminal.finish(Err(ManagedGroupError::Closed));
            callback(|| route.sender.close_receiver());
            callback(|| drop(route));
        }
        for request in requests {
            callback(|| request.finish(Err(ManagedGroupError::Closed)));
            callback(|| drop(request));
        }
        for request in queued { callback(|| drop(request)); }
        self.waiters.notify();
        self.signal.wake.notify();
    }
}

/// Cloneable group capability; the owner handle controls its lifetime.
pub struct ProcessGroupClient<M> { shared: Arc<Shared<M>> }
impl<M> Clone for ProcessGroupClient<M> {
    fn clone(&self) -> Self { Self { shared: Arc::clone(&self.shared) } }
}
impl<M> std::fmt::Debug for ProcessGroupClient<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessGroupClient").field("group", &self.shared.name)
            .field("outstanding_requests", &self.outstanding_requests()).finish_non_exhaustive()
    }
}
impl<M> ProcessGroupClient<M> {
    /// Queued/unclaimed joins plus admitted broadcasts and event waits.
    #[must_use]
    pub fn outstanding_requests(&self) -> usize { self.shared.credits.used.load(Ordering::Acquire) }
    /// Snapshot of published members in canonical join order.
    pub fn members(&self, cx: &Cx) -> Result<GroupSnapshot, ManagedGroupError> {
        self.shared.validate(cx)?;
        let members = self.shared.state.lock().routes.values().map(|route| route.member.clone()).collect();
        Ok(GroupSnapshot::new(self.shared.name.clone(), members))
    }
    /// Replay retained events without advancing the caller's cursor.
    pub fn events(&self, cx: &Cx, cursor: GroupEventCursor) -> Result<ManagedGroupEventBatch, ManagedGroupError> {
        self.shared.validate(cx)?;
        Ok(self.shared.events(cursor))
    }
    /// Wait for events, an explicit history gap, or controller closure.
    pub async fn next_events(&self, cx: &Cx, cursor: GroupEventCursor) -> Result<ManagedGroupEventBatch, ManagedGroupError> {
        self.shared.validate(cx)?;
        let _credit = Credit::acquire(&self.shared.credits)?;
        let wake = self.shared.waiters.subscribe();
        let mut cancel = CancelRegistration::new(cx);
        poll_fn(|task| {
            wake.register(task.waker());
            cancel.poll(task.waker());
            if cx.checkpoint().is_err() { return Poll::Ready(Err(cancelled(cx))); }
            let batch = self.shared.events(cursor);
            if !batch.batch.is_empty() || batch.skipped != 0 || batch.closed { Poll::Ready(Ok(batch)) }
            else { Poll::Pending }
        }).await
    }
    /// Join as the actual calling task after its monitor and checked lease exist.
    /// Moving the guard never changes that identity. An abandoned join is removed
    /// before its request credit is reused.
    pub async fn join(&self, cx: &Cx) -> Result<ManagedGroupMembership<M>, ManagedGroupError> {
        self.shared.validate(cx)?;
        let credit = Credit::acquire(&self.shared.credits)?;
        let request = Arc::new(JoinRequest {
            member: GroupMemberId::new(self.shared.node.clone(), cx.task_id()),
            reply: Mutex::new(Reply { value: None, abandoned: false, received: false, credit: Some(credit) }),
            wake: WakeSlot::default(), signal: Arc::clone(&self.shared.signal),
        });
        {
            let mut state = self.shared.state.lock();
            if state.closed || self.shared.signal.stopping.load(Ordering::Acquire) { return Err(ManagedGroupError::Closed); }
            state.requests.retain(|request| request.strong_count() != 0);
            state.requests.push(Arc::downgrade(&request));
            state.queue.push_back(Arc::clone(&request));
        }
        let wait = JoinWait { request, cancel: CancelRegistration::new(cx), finished: false };
        self.shared.signal.wake.notify();
        let joined = wait.await?;
        Ok(ManagedGroupMembership { shared: Arc::clone(&self.shared), joined })
    }
}

/// One member's receive capability and generation-specific leave guard.
/// A guard retained elsewhere is revoked when its original task retires.
pub struct ManagedGroupMembership<M> { shared: Arc<Shared<M>>, joined: Joined<M> }
impl<M> std::fmt::Debug for ManagedGroupMembership<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedGroupMembership").field("member", self.id())
            .field("generation", &self.generation()).field("active", &self.is_active()).finish_non_exhaustive()
    }
}
impl<M> ManagedGroupMembership<M> {
    /// Actual member identity.
    #[must_use]
    pub fn id(&self) -> &GroupMemberId { self.joined.member.id() }
    /// Monotone canonical join sequence.
    #[must_use]
    pub fn generation(&self) -> u64 { self.joined.member.join_sequence() }
    /// Canonical joined event.
    #[must_use]
    pub fn joined_event(&self) -> &GroupEvent { &self.joined.event }
    /// Whether leave/death has not yet been observed or requested.
    #[must_use]
    pub fn is_active(&self) -> bool { self.joined.terminal.is_active() }
    /// Out-of-band idempotent leave, independent of request credit.
    pub fn request_leave(&self) { self.joined.terminal.request_leave(); }
    /// Withdraw and await its terminal event and lease settlement. Abandoning
    /// this wait does not undo leave; repeated waits return the same result.
    pub async fn leave(&mut self, cx: &Cx) -> Result<GroupEvent, ManagedGroupError> {
        self.shared.validate(cx)?;
        self.request_leave();
        let wake = self.shared.waiters.subscribe();
        let mut cancel = CancelRegistration::new(cx);
        poll_fn(|task| {
            wake.register(task.waker());
            cancel.poll(task.waker());
            if let Some(result) = self.joined.terminal.result() {
                let _ = cx.checkpoint();
                return Poll::Ready(result);
            }
            // A controller panic after removing this record can close shared
            // state before it publishes a per-member terminal result.
            if self.shared.state.lock().closed {
                return Poll::Ready(Err(ManagedGroupError::Closed));
            }
            if cx.checkpoint().is_err() { return Poll::Ready(Err(cancelled(cx))); }
            Poll::Pending
        }).await
    }
    /// Receive within this incarnation. Departure wakes a parked receive even
    /// when another task retains the guard. Queued values are never rerouted.
    pub async fn recv(&mut self, cx: &Cx) -> Result<M, ManagedGroupRecvError> {
        self.shared.validate(cx).map_err(|error| match error {
            ManagedGroupError::Cancelled(reason) => ManagedGroupRecvError::Cancelled(reason),
            _ => ManagedGroupRecvError::Closed,
        })?;
        let wake = self.shared.waiters.subscribe();
        let mut cancel = CancelRegistration::new(cx);
        let terminal = Arc::clone(&self.joined.terminal);
        poll_fn(|task| {
            wake.register(task.waker());
            cancel.poll(task.waker());
            if let Some(result) = terminal.result() {
                let _ = cx.checkpoint();
                return Poll::Ready(Err(match result {
                    Ok(event) => ManagedGroupRecvError::Departed(event),
                    Err(_) => ManagedGroupRecvError::Closed,
                }));
            }
            if self.shared.state.lock().closed {
                return Poll::Ready(Err(ManagedGroupRecvError::Closed));
            }
            if cx.checkpoint().is_err() { return Poll::Ready(Err(ManagedGroupRecvError::Cancelled(cancel_reason(cx)))); }
            if !terminal.is_active() { return Poll::Pending; }
            match self.joined.receiver.poll_recv(cx, task) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(value)) => Poll::Ready(Ok(value)),
                Poll::Ready(Err(mpsc::RecvError::Cancelled)) => Poll::Ready(Err(ManagedGroupRecvError::Cancelled(cancel_reason(cx)))),
                Poll::Ready(Err(_)) => Poll::Ready(Err(ManagedGroupRecvError::Closed)),
            }
        }).await
    }
}
impl<M> Drop for ManagedGroupMembership<M> {
    fn drop(&mut self) { self.request_leave(); }
}

fn runtime_identity(cx: &Cx) -> Result<Weak<ObligationMailbox>, ManagedGroupError> {
    cx.checkpoint().map_err(|_| cancelled(cx))?;
    let (gateway, holder) = cx.obligation_transfer_destination().map_err(|_| ManagedGroupError::RuntimeRequired)?;
    if !gateway.is_runtime_available() || !holder.is_live()
        || holder.holder() != cx.task_id() || holder.region() != cx.region_id()
    { return Err(ManagedGroupError::RuntimeRequired); }
    Ok(Arc::downgrade(gateway.mailbox()))
}
fn cancel_reason(cx: &Cx) -> CancelReason {
    cx.cancel_reason().unwrap_or_else(|| CancelReason::user("process-group caller cancelled"))
}
fn cancelled(cx: &Cx) -> ManagedGroupError { ManagedGroupError::Cancelled(cancel_reason(cx)) }
fn callback(action: impl FnOnce()) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(action)) {
        // An adversarial panic payload can itself panic in Drop. Containment
        // must remain usable while settling all other controller obligations.
        std::mem::forget(payload);
    }
}

impl<M: Clone + Send + Sync> ProcessGroupClient<M> {
    /// Send to the captured incarnations in canonical join order.
    ///
    /// Every recipient first owns physical capacity and a checked runtime
    /// SendPermit. Only then is the caller's message cloned. Wait parks this
    /// caller, leaving the controller free to revoke dead or departing members.
    /// Skip continues past full mailboxes; Error stops at the first full mailbox.
    /// Runtime admission refusal stops either policy. Cancellation returns the
    /// delivered prefix and marks the untouched suffix as NotAttempted.
    ///
    /// Dropping this future abandons its remaining work, not already committed
    /// messages. Concurrent broadcasts may interleave; this is not multicast
    /// atomicity. A departed incarnation is never replaced within a snapshot.
    pub async fn broadcast(
        &self, cx: &Cx, message: &M, policy: BroadcastBackpressurePolicy,
    ) -> Result<ManagedGroupBroadcastReport, ManagedGroupError> {
        self.shared.validate(cx)?;
        let _credit = Credit::acquire(&self.shared.credits)?;
        let mut routes: Vec<_> = {
            let state = self.shared.state.lock();
            if state.closed || self.shared.signal.stopping.load(Ordering::Acquire) {
                return Err(ManagedGroupError::Closed);
            }
            state.routes.values().cloned().collect()
        };
        routes.sort_by_key(|route| route.member.join_sequence());
        let mut report = ManagedGroupBroadcastReport {
            group: self.shared.name.clone(), policy, cancellation: None,
            recipients: routes.iter().map(|route| ManagedGroupRecipient {
                member: route.member.id().clone(),
                generation: route.member.join_sequence(),
                status: ManagedGroupRecipientStatus::NotAttempted,
            }).collect(),
        };
        let wake = self.shared.waiters.subscribe();
        let mut cancel = CancelRegistration::new(cx);
        for (index, route) in routes.iter().enumerate() {
            if index != 0 && index % SCAN_QUANTUM == 0 { yield_once().await; }
            let reserved = if cx.checkpoint().is_err() {
                Err(ManagedGroupRecipientStatus::Cancelled)
            } else if !route.terminal.is_active() || self.shared.signal.stopping.load(Ordering::Acquire) {
                Err(ManagedGroupRecipientStatus::Departed)
            } else if policy == BroadcastBackpressurePolicy::Wait {
                let mut reserve = std::pin::pin!(route.sender.reserve_checked(cx));
                poll_fn(|task| {
                    wake.register(task.waker());
                    cancel.poll(task.waker());
                    if cx.checkpoint().is_err() {
                        return Poll::Ready(Err(ManagedGroupRecipientStatus::Cancelled));
                    }
                    if !route.terminal.is_active() || self.shared.signal.stopping.load(Ordering::Acquire) {
                        return Poll::Ready(Err(ManagedGroupRecipientStatus::Departed));
                    }
                    match reserve.as_mut().poll(task) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Ok(permit)) => Poll::Ready(Ok(permit)),
                        Poll::Ready(Err(error)) => Poll::Ready(Err(reservation_status(error, policy))),
                    }
                }).await
            } else {
                route.sender.try_reserve_checked(cx).map_err(|error| reservation_status(error, policy))
            };
            let status = match reserved {
                Err(status) => status,
                Ok(permit) => {
                    // User cloning, value destruction and receiver callbacks
                    // all run without any group mutex held.
                    let value = message.clone();
                    if cx.checkpoint().is_err() {
                        drop(permit);
                        drop(value);
                        ManagedGroupRecipientStatus::Cancelled
                    } else if !route.terminal.is_active() || self.shared.signal.stopping.load(Ordering::Acquire) {
                        drop(permit);
                        drop(value);
                        ManagedGroupRecipientStatus::Departed
                    } else {
                        let (sent, wake) = permit.try_send_deferred_wake(value);
                        let status = match sent {
                            Ok(()) => ManagedGroupRecipientStatus::Delivered,
                            Err(mpsc::SendError::Disconnected(value)) => {
                                drop(value);
                                ManagedGroupRecipientStatus::Departed
                            }
                            Err(mpsc::SendError::Cancelled(value)) => {
                                drop(value);
                                let _ = cx.checkpoint();
                                ManagedGroupRecipientStatus::Cancelled
                            }
                            Err(mpsc::SendError::Full(value)) => {
                                drop(value);
                                ManagedGroupRecipientStatus::Backpressured
                            }
                        };
                        // Publication and obligation settlement precede arbitrary
                        // receiver callbacks; a broken waker cannot erase it.
                        callback(|| wake.wake());
                        status
                    }
                }
            };
            report.recipients[index].status = status;
            match status {
                ManagedGroupRecipientStatus::Cancelled => {
                    report.cancellation = Some(cancel_reason(cx));
                    break;
                }
                ManagedGroupRecipientStatus::Backpressured | ManagedGroupRecipientStatus::AdmissionRefused(_) => break,
                _ => {}
            }
        }
        // Preserve typed prefix accounting even when the final commit's wake
        // requested cancellation; the normal task wrapper sees acknowledgement.
        if cx.checkpoint().is_err() { report.cancellation = Some(cancel_reason(cx)); }
        Ok(report)
    }
}

fn reservation_status(
    error: mpsc::CheckedSendError<()>, policy: BroadcastBackpressurePolicy,
) -> ManagedGroupRecipientStatus {
    match error {
        mpsc::CheckedSendError::Admission { error, .. } => ManagedGroupRecipientStatus::AdmissionRefused(error),
        mpsc::CheckedSendError::Channel(mpsc::SendError::Disconnected(())) => ManagedGroupRecipientStatus::Departed,
        mpsc::CheckedSendError::Channel(mpsc::SendError::Cancelled(())) => ManagedGroupRecipientStatus::Cancelled,
        mpsc::CheckedSendError::Channel(mpsc::SendError::Full(())) => {
            if policy == BroadcastBackpressurePolicy::Skip { ManagedGroupRecipientStatus::Skipped }
            else { ManagedGroupRecipientStatus::Backpressured }
        }
    }
}

async fn yield_once() {
    let mut yielded = false;
    poll_fn(|task| {
        if yielded { Poll::Ready(()) }
        else {
            yielded = true;
            task.waker().wake_by_ref();
            Poll::Pending
        }
    }).await;
}

/// Sole owner of a region-owned process-group controller.
/// Client clones do not keep its service detached after this handle is dropped.
pub struct ManagedProcessGroup<M> {
    shared: Arc<Shared<M>>,
    region: Option<ChildRegion>,
    task: Option<TaskHandle<ManagedGroupReport>>,
    region_id: RegionId,
}
impl<M> std::fmt::Debug for ManagedProcessGroup<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedProcessGroup").field("group", &self.shared.name)
            .field("region", &self.region_id).finish_non_exhaustive()
    }
}
impl<M: Send + 'static> ManagedProcessGroup<M> {
    /// Open an actual child region and wait until its controller is running.
    ///
    /// The node identifies this local owner; no remote discovery or transport
    /// is implied. All clients remain permanently bound to this runtime.
    pub async fn open(
        cx: &Cx, name: GroupName, node: NodeId, config: ManagedProcessGroupConfig,
    ) -> Result<Self, ManagedGroupError> {
        if config.mailbox_capacity == 0 || config.max_requests == 0 || config.event_capacity == 0
            || name.as_str().len() > 255 || node.as_str().is_empty() || node.as_str().len() > 255
        { return Err(ManagedGroupError::InvalidConfig); }
        let runtime = runtime_identity(cx)?;
        let region = cx.open_child_region(config.region.clone()).await
            .map_err(|error| ManagedGroupError::Region(Arc::new(error)))?;
        let region_id = region.region_id();
        let shared = Arc::new(Shared {
            name, node,
            credits: Arc::new(Credits { used: AtomicUsize::new(0), limit: config.max_requests }),
            config, runtime,
            state: Mutex::new(SharedState {
                queue: VecDeque::new(), requests: Vec::new(), routes: BTreeMap::new(),
                events: VecDeque::new(), next_event: 0, closed: false, ready: None,
            }),
            signal: Arc::new(Signal::default()), waiters: Arc::new(WaitHub::default()),
        });
        // Construct before submission: denial or cancellation before the first
        // controller poll must also close every queued join/ready waiter.
        let lifetime = Lifetime(Arc::clone(&shared));
        let task = region.cx().spawn(move |controller_cx| async move {
            let lifetime = lifetime;
            let report = run_controller(&controller_cx, &lifetime.0).await;
            drop(lifetime);
            report
        }).map_err(|error| ManagedGroupError::Spawn(Arc::new(error)))?;
        let owner = Self { shared, region: Some(region), task: Some(task), region_id };
        let wake = owner.shared.waiters.subscribe();
        let mut cancel = CancelRegistration::new(cx);
        poll_fn(|task| {
            wake.register(task.waker());
            cancel.poll(task.waker());
            if cx.checkpoint().is_err() { return Poll::Ready(Err(cancelled(cx))); }
            let ready = owner.shared.state.lock().ready.clone();
            match ready { Some(result) => Poll::Ready(result), None => Poll::Pending }
        }).await?;
        Ok(owner)
    }
}
impl<M> ManagedProcessGroup<M> {
    /// Clone a group capability without transferring lifetime ownership.
    #[must_use]
    pub fn client(&self) -> ProcessGroupClient<M> { ProcessGroupClient { shared: Arc::clone(&self.shared) } }
    /// The actual region containing the sole controller.
    #[must_use]
    pub const fn region_id(&self) -> RegionId { self.region_id }
    /// Out-of-band graceful stop, independent of outstanding request credit.
    pub fn request_shutdown(&self) {
        self.shared.signal.stop();
        self.shared.waiters.notify();
    }
    /// Await controller retirement and the actual region finalizer barrier.
    /// Dropping this future leaves its child region owned by the close protocol.
    pub async fn join(mut self) -> ManagedProcessGroupExit {
        let task_outcome = poll_fn(|task| self.task.as_mut().expect("owned group controller").poll_join(task)).await;
        let close = self.region.take().expect("owned group region").close_with_outcome().await
            .map(|close| ManagedGroupClose {
                outcome: close.outcome, cleanup_outcome: close.cleanup_outcome,
                descendant_panic: close.descendant_panic,
            });
        ManagedProcessGroupExit { task_outcome, close }
    }
    /// Seal admission, revoke all memberships, settle leases, and await close.
    pub async fn shutdown(self) -> ManagedProcessGroupExit {
        self.request_shutdown();
        self.join().await
    }

    // Configure before publishing clients: actual member DOWN then aborts the
    // tracked name obligation at the controller's original retirement boundary.
    pub(crate) fn abort_on_member_down(&self) {
        self.shared.signal.abort_on_down.store(true, Ordering::Release);
    }

    // Opt-in revocation for global-name ownership. Ordinary process-group
    // shutdown retains its existing successful-release settlement semantics.
    pub(crate) fn request_abort(&self) {
        self.shared.signal.abort_leases.store(true, Ordering::Release);
        self.request_shutdown();
    }

    // The controller still reports its actual settlement and region closure.
    // This does not bypass cleanup by aborting its task handle.
    pub(crate) async fn abort(self) -> ManagedProcessGroupExit {
        self.request_abort();
        self.join().await
    }
}
impl<M> Drop for ManagedProcessGroup<M> {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Some(task) = &self.task { callback(|| task.abort()); }
        // ChildRegion's Drop arms the real close barrier. No synchronous drop
        // path claims that controller retirement or finalization has completed.
    }
}
struct Lifetime<M>(Arc<Shared<M>>);
impl<M> Drop for Lifetime<M> {
    fn drop(&mut self) { self.0.close(); }
}

struct LiveRecord<M> {
    member: GroupMember,
    monitor: Monitor,
    lease: Option<TrackedNameLease>,
    terminal: Arc<MemberTerminal>,
    publication: Option<Arc<JoinRequest<M>>>,
}
struct Admission<M> { request: Arc<JoinRequest<M>>, opening: MonitorOpening }
enum Work<M> {
    Start(Arc<JoinRequest<M>>),
    Admit(Arc<JoinRequest<M>>, Result<Monitor, WatchError>),
    Discard(Admission<M>),
    Remove(GroupMemberId, Option<DownReason>),
    Stop,
}
struct Controller<M> {
    shared: Arc<Shared<M>>,
    records: BTreeMap<GroupMemberId, LiveRecord<M>>,
    state: ProcessGroupState,
    registry: TrackedNameRegistry,
    pending: Option<Admission<M>>,
    report: ManagedGroupReport,
}
impl<M> Drop for Controller<M> {
    fn drop(&mut self) {
        // FIRST settle every lease. An unclaimed receiver can contain arbitrary
        // messages after publication, and one destructor must not prevent other
        // memberships' obligations from settling before this task retires.
        for record in self.records.values_mut() {
            if let Some(lease) = record.lease.take() { callback(|| drop(lease)); }
        }
        self.shared.close();
        if let Some(pending) = self.pending.take() { callback(|| drop(pending)); }
        for (_, record) in std::mem::take(&mut self.records) {
            callback(|| drop(record));
        }
    }
}

impl<M> Controller<M> {
    fn poll(
        &mut self, cx: &Cx, cancel: &mut CancelRegistration<'_>, task: &mut Context<'_>,
    ) -> Poll<Work<M>> {
        self.shared.signal.wake.register(task.waker());
        cancel.poll(task.waker());
        if cx.checkpoint().is_err() || self.shared.signal.stopping.load(Ordering::Acquire) {
            return Poll::Ready(Work::Stop);
        }
        // Every poll scans the configured, bounded member set before parking.
        // Splitting a scan across polls would consume a coalesced wake for an
        // earlier member while only revisiting the later slice.
        let keys: Vec<_> = self.records.keys().cloned().collect();
        for id in &keys {
            let record = self.records.get_mut(id).expect("retained scan member");
            if let Some(request) = &record.publication {
                let (abandoned, received) = request.disposition();
                if abandoned { return Poll::Ready(Work::Remove(id.clone(), None)); }
                if received {
                    let request = record.publication.take();
                    callback(|| drop(request));
                }
            }
            if record.terminal.leave.load(Ordering::Acquire) {
                return Poll::Ready(Work::Remove(id.clone(), None));
            }
            let result = {
                let mut down = std::pin::pin!(record.monitor.down(cx));
                down.as_mut().poll(task)
            };
            match result {
                Poll::Pending => {}
                Poll::Ready(Ok(down)) => {
                    debug_assert_eq!(down.monitored, id.task());
                    return Poll::Ready(Work::Remove(id.clone(), Some(down.reason)));
                }
                Poll::Ready(Err(_)) => {
                    // Loss of the controller's watch authority is shutdown,
                    // never a fabricated member DOWN notification.
                    let _ = cx.checkpoint();
                    self.shared.signal.stop();
                    return Poll::Ready(Work::Stop);
                }
            }
        }
        if let Some(admission) = self.pending.as_mut() {
            if admission.request.disposition().0 {
                return Poll::Ready(Work::Discard(self.pending.take().expect("pending admission")));
            }
            if let Poll::Ready(result) = Pin::new(&mut admission.opening).poll(task) {
                let admission = self.pending.take().expect("completed admission");
                return Poll::Ready(Work::Admit(admission.request, result));
            }
        }
        if self.pending.is_none() {
            let request = self.shared.state.lock().queue.pop_front();
            if let Some(request) = request { return Poll::Ready(Work::Start(request)); }
        }
        Poll::Pending
    }

    fn start(&mut self, cx: &Cx, request: Arc<JoinRequest<M>>) {
        if request.disposition().0 { return; }
        let refusal = if self.records.contains_key(&request.member) {
            Some(ManagedGroupError::DuplicateMember(request.member.clone()))
        } else if self.records.len() >= self.shared.config.max_members {
            Some(ManagedGroupError::Capacity)
        } else { None };
        if let Some(error) = refusal {
            callback(|| request.finish(Err(error)));
            return;
        }
        let opening = cx.monitor(request.member.task());
        self.pending = Some(Admission { request, opening });
    }

    fn admit(&mut self, cx: &Cx, request: Arc<JoinRequest<M>>, monitor: Result<Monitor, WatchError>) {
        let monitor = match monitor {
            Ok(monitor) => monitor,
            Err(error) => { callback(|| request.finish(Err(ManagedGroupError::Watch(error)))); return; }
        };
        if request.disposition().0 { callback(|| drop(monitor)); return; }
        if cx.checkpoint().is_err() || self.shared.signal.stopping.load(Ordering::Acquire) {
            callback(|| drop(monitor));
            callback(|| request.finish(Err(ManagedGroupError::Closed)));
            return;
        }
        if monitor.try_down().is_some() {
            callback(|| drop(monitor));
            callback(|| request.finish(Err(ManagedGroupError::Watch(WatchError::NotFound))));
            return;
        }
        // This private registry has one lease per retained incarnation. The
        // holder is the controller, while the watch retains the actual member.
        let lease = match self.registry.register(cx, format!("member/{}", self.state.next_join_sequence())) {
            Ok(lease) => lease,
            Err(error) => {
                callback(|| drop(monitor));
                callback(|| request.finish(Err(ManagedGroupError::Lease(error))));
                return;
            }
        };
        // Checked admission can notify the runtime. Recheck abandonment, death
        // and cancellation before exposing a mailbox after that boundary.
        if request.disposition().0 || monitor.try_down().is_some()
            || cx.checkpoint().is_err() || self.shared.signal.stopping.load(Ordering::Acquire)
        {
            let _ = self.settle(lease, false);
            callback(|| drop(monitor));
            callback(|| request.finish(Err(ManagedGroupError::Closed)));
            return;
        }
        let event = match self.state.join(request.member.clone(), cx.now()) {
            Ok(event) => event,
            Err(error) => {
                let _ = self.settle(lease, false);
                self.report.state_error = Some(error.clone());
                self.shared.signal.stop();
                callback(|| drop(monitor));
                callback(|| request.finish(Err(ManagedGroupError::State(error))));
                return;
            }
        };
        self.state.discard_managed_events();
        let member = self.state.member(&request.member).expect("joined canonical member").clone();
        let terminal = Arc::new(MemberTerminal {
            leave: AtomicBool::new(false), active: AtomicBool::new(true), outcome: Mutex::new(None),
            signal: Arc::clone(&self.shared.signal), waiters: Arc::clone(&self.shared.waiters),
        });
        let (sender, receiver) = mpsc::channel(self.shared.config.mailbox_capacity);
        let record = LiveRecord {
            member: member.clone(), monitor, lease: Some(lease),
            terminal: Arc::clone(&terminal), publication: Some(Arc::clone(&request)),
        };
        let replaced = self.records.insert(request.member.clone(), record);
        debug_assert!(replaced.is_none(), "canonical join excludes duplicate records");
        callback(|| drop(replaced));
        let route = Route { member: member.clone(), sender, terminal: Arc::clone(&terminal) };
        let retired = self.shared.state.lock().routes.insert(request.member.clone(), route);
        debug_assert!(retired.is_none(), "canonical join excludes duplicate routes");
        callback(|| drop(retired));
        self.report.joined = self.report.joined.saturating_add(1);
        self.shared.publish(event.clone());
        // The record owns both the lease and the unclaimed request before any
        // caller can receive or abandon the guard, including through a wake.
        callback(|| request.finish(Ok(Joined { member, event, receiver, terminal })));
    }

    fn settle(&mut self, lease: TrackedNameLease, down: bool) -> Result<(), TrackedNameError> {
        let abort = self.shared.signal.abort_leases.load(Ordering::Acquire)
            || (down && self.shared.signal.abort_on_down.load(Ordering::Acquire));
        let result = match catch_unwind(AssertUnwindSafe(|| {
            if abort { lease.abort() } else { lease.release() }
        })) {
            Ok(result) => result,
            Err(payload) => {
                std::mem::forget(payload);
                Err(TrackedNameError::SettlementRejected)
            }
        };
        if result.is_err() {
            self.report.settlement_failures = self.report.settlement_failures.saturating_add(1);
            self.shared.signal.stop();
        }
        result
    }

    fn remove(&mut self, cx: &Cx, id: &GroupMemberId, reason: Option<DownReason>) {
        let Some(mut record) = self.records.remove(id) else { return; };
        // Departure must be visible before channel closure or event publication
        // can wake a broadcaster or observer on another worker.
        record.terminal.active.store(false, Ordering::Release);
        let route = {
            let mut state = self.shared.state.lock();
            if state.routes.get(id).is_some_and(|route| route.member.join_sequence() == record.member.join_sequence()) {
                state.routes.remove(id)
            } else { None }
        };
        // Snapshot senders may outlive this record and a forgotten receiver.
        // Seal the channel itself, waking all pending checked reservations.
        if let Some(route) = &route { callback(|| route.sender.close_receiver()); }
        let settlement = record.lease.take().map_or(Ok(()), |lease| self.settle(lease, reason.is_some()));
        let result = if let Err(error) = settlement {
            Err(ManagedGroupError::Lease(error))
        } else {
            let down = reason.is_some();
            let transition = match reason {
                Some(reason) => self.state.mark_down(id, reason, cx.now()),
                None => self.state.leave(id, cx.now()),
            };
            match transition {
                Ok(event) => {
                    self.state.discard_managed_events();
                    if down { self.report.down = self.report.down.saturating_add(1); }
                    else { self.report.left = self.report.left.saturating_add(1); }
                    self.shared.publish(event.clone());
                    Ok(event)
                }
                Err(error) => {
                    self.report.state_error = Some(error.clone());
                    self.shared.signal.stop();
                    Err(ManagedGroupError::State(error))
                }
            }
        };
        record.terminal.finish(result);
        callback(|| drop(route));
        callback(|| drop(record));
    }

    fn shutdown(&mut self, cx: &Cx) {
        self.shared.signal.stop();
        if let Some(admission) = self.pending.take() {
            callback(|| admission.request.finish(Err(ManagedGroupError::Closed)));
            callback(|| drop(admission));
        }
        let reason = cx.cancel_reason().unwrap_or_else(|| CancelReason::user("process-group owner shutdown"));
        while let Some(id) = self.records.keys().next().cloned() {
            self.remove(cx, &id, Some(DownReason::Cancelled(reason.clone())));
        }
        self.shared.close();
    }
}

async fn run_controller<M: Send + 'static>(cx: &Cx, shared: &Arc<Shared<M>>) -> ManagedGroupReport {
    let mut controller = Controller {
        shared: Arc::clone(shared), records: BTreeMap::new(),
        state: ProcessGroupState::new(shared.name.clone()), registry: TrackedNameRegistry::new(),
        pending: None, report: ManagedGroupReport::default(),
    };
    let ready = shared.validate(cx);
    let refused = ready.is_err();
    shared.state.lock().ready = Some(ready);
    shared.waiters.notify();
    if !refused {
        let mut cancel = CancelRegistration::new(cx);
        let mut work = 0usize;
        loop {
            match poll_fn(|task| controller.poll(cx, &mut cancel, task)).await {
                Work::Start(request) => controller.start(cx, request),
                Work::Admit(request, monitor) => controller.admit(cx, request, monitor),
                Work::Discard(admission) => callback(|| drop(admission)),
                Work::Remove(id, reason) => controller.remove(cx, &id, reason),
                Work::Stop => break,
            }
            work += 1;
            if work == SCAN_QUANTUM { work = 0; yield_once().await; }
        }
    }
    // No await or task-result publication after taking leases out of ownership.
    // All records settle while this actual controller task is still live.
    controller.shutdown(cx);
    std::mem::take(&mut controller.report)
}

// `spork.rs` loads this file through `#[path]`, which makes a bare `mod tests;`
// resolve to `src/spork/tests.rs`; name the sibling directory explicitly.
#[cfg(test)]
#[path = "managed_process_group/tests.rs"]
mod tests;
