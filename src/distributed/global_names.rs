//! Live, bounded, lease-backed names for an explicitly provisioned cluster.
//!
//! A caller-owned driver opens one monitored process group per admitted local
//! name. Its child regions and checked leases belong to the driver, while each
//! membership monitors the actual registering task. Moving or forgetting the
//! public handle therefore cannot keep a dead actor registered. The driver must
//! run in a separate owned task from actors whose lifetime it monitors.
//!
//! Full authenticated owner catalogs converge by sequence and deterministic
//! node/incarnation order. These are local observations: neither SWIM suspicion,
//! a reachable peer, nor an owner round trip proves a quorum or global exclusive
//! ownership. Partitions can preserve conflicting claims. Suspect owners remain
//! visible with an explicit flag; Dead/Left or a newer authenticated incarnation
//! invalidate their previous claims. No finite gossip convergence is promised.
//!
//! A target names an existing remote computation explicitly selected by its
//! registering actor. It is not a serialized TaskId, remote mailbox capability,
//! invocation fence, or atomic lookup-and-call reservation. Use the existing
//! named-computation admission policy for every eventual invocation.

use crate::cx::Cx;
use crate::distributed::membership::{MembershipKind, owned::OwnedMembershipController};
use crate::remote::NodeId;
use crate::runtime::obligation_mailbox::ObligationMailbox;
use crate::spork::process_group::{
    GroupName, ManagedGroupError, ManagedGroupMembership, ManagedProcessGroup,
    ManagedProcessGroupConfig, ManagedProcessGroupExit, ProcessGroupClient,
};
use crate::sync::Notify;
use crate::time::{Sleep, TimerDriverHandle};
use crate::types::{TaskId, Time};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::task::Poll;
use std::time::Duration;

pub mod service;
pub mod wire;
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
pub mod native;

/// Finite catalog, admission, and maintenance bounds.
#[derive(Debug, Clone)]
pub struct GlobalNameConfig {
    max_local_names: usize,
    max_names_per_peer: usize,
    maintenance_interval: Duration,
    registration_timeout: Duration,
}
impl GlobalNameConfig {
    /// Limit names to 1..=1024 per owner and maintenance to (0, 60s].
    /// Pending registrations and draining groups consume local capacity too.
    pub fn new(
        max_local_names: usize, max_names_per_peer: usize, maintenance_interval: Duration,
    ) -> Result<Self, GlobalNameError> {
        if !(1..=wire::MAX_NAMES).contains(&max_local_names)
            || !(1..=wire::MAX_NAMES).contains(&max_names_per_peer)
            || maintenance_interval.is_zero() || maintenance_interval > Duration::from_secs(60)
        { return Err(GlobalNameError::Configuration); }
        Ok(Self { max_local_names, max_names_per_peer, maintenance_interval,
            registration_timeout: Duration::from_secs(30) })
    }

    /// Set the maximum time a not-yet-published registration may retain credit.
    /// The driver observes expiry at its bounded maintenance interval.
    pub fn with_registration_timeout(mut self, timeout: Duration) -> Result<Self, GlobalNameError> {
        if timeout.is_zero() || timeout > Duration::from_secs(300) { return Err(GlobalNameError::Configuration); }
        self.registration_timeout = timeout;
        Ok(self)
    }
}

/// Exact owner incarnation, local registration generation, and computation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GlobalNameTarget {
    node: NodeId,
    incarnation: u64,
    registration: u64,
    computation: String,
}
impl GlobalNameTarget {
    /// Direct authenticated owner.
    pub fn node(&self) -> &NodeId { &self.node }
    /// Independently authorized owner incarnation.
    pub const fn incarnation(&self) -> u64 { self.incarnation }
    /// Non-reused registration identity within this incarnation.
    pub const fn registration(&self) -> u64 { self.registration }
    /// Explicitly chosen named computation; its own admission remains required.
    pub fn computation(&self) -> &str { &self.computation }
}

/// A possibly stale local observation, never a global exclusivity certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalNameView {
    /// Deterministic winner among this observer's currently permitted catalogs.
    pub target: GlobalNameTarget,
    /// Last accepted full owner-catalog sequence.
    pub owner_sequence: u64,
    /// Local receipt time, not a lease deadline or synchronized owner clock.
    pub observed_at: Time,
    /// Whether this observer also owns the actual local monitor.
    pub local_owner: bool,
    /// The independently authenticated membership view currently says Suspect.
    /// False still does not prove reachability, a majority, or fresh ownership.
    pub owner_suspect: bool,
}

/// Exact in-memory snapshot admission receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalNameSnapshotReceipt {
    /// The directly authenticated sender, not an owner supplied in the payload.
    pub owner: NodeId,
    /// Owner incarnation admitted by membership authority.
    pub incarnation: u64,
    /// Accepted sequence, including an identical retry.
    pub sequence: u64,
    /// Digest of every byte of the accepted canonical catalog.
    pub digest: [u8; 32],
}

/// Typed reason for withdrawal of this exact local registration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GlobalNameEndReason {
    /// Explicit release, handle drop, or abandoned registration.
    Released,
    /// The original task's real monitor observed its departure.
    OwnerDown,
    /// Dead/Left, controller closure, or a different authorized incarnation.
    MembershipLost,
    /// A lower-ranked authenticated claim was observed.
    Conflict(GlobalNameTarget),
    /// Driver shutdown or acknowledged cancellation.
    Shutdown,
    /// A pending registration did not finish within its configured deadline.
    AdmissionExpired,
    /// Group creation or joining could not produce an active local lease.
    AdmissionFailed,
    /// The caller abandoned the driver without awaiting its drain.
    DriverDropped,
}

/// Actual local-controller termination, including any cleanup failure.
#[derive(Debug)]
pub struct GlobalNameRetirement {
    /// Why this registration was withdrawn.
    pub reason: GlobalNameEndReason,
    /// None means no successful controller/region-close receipt was obtained.
    /// Dropped owners still arm the runtime's real close barrier.
    pub exit: Option<ManagedProcessGroupExit>,
}
impl GlobalNameRetirement {
    /// The controller reported settled leases and its region reached closure.
    /// Consult the retained close outcome for cleanup cancellation or panic.
    pub fn is_drained(&self) -> bool {
        self.exit.as_ref().is_some_and(|exit| {
            exit.close.is_ok() && exit.task_outcome.as_ref().is_ok_and(|report| {
                report.settlement_failures == 0 && report.state_error.is_none()
            })
        })
    }
}

/// Driver-observed lifecycle of one exact registration.
#[derive(Debug, Clone)]
pub enum GlobalNameLeaseStatus {
    /// Last observed active state; lookup still checks current membership.
    Active,
    /// Withdrawn from lookup, with actual child-region closure still pending.
    Retiring(GlobalNameEndReason),
    /// Final result, including an explicit absent receipt on abandoned drivers.
    Retired(Arc<GlobalNameRetirement>),
}

/// Payload-free refusals plus typed deterministic conflict identity.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum GlobalNameError {
    /// Invalid explicit bounds or identities.
    #[error("invalid global-name configuration")]
    Configuration,
    /// The context is detached, belongs to another runtime, or has no clock.
    #[error("global names require the owning live runtime context")]
    Runtime,
    /// Start and await the driver before admission.
    #[error("global-name driver is not running")]
    NotRunning,
    /// An invalidated published claim awaits its sequence-advancing retirement.
    #[error("global-name snapshot awaits local retirement")]
    PendingRetirement,
    /// Only one driver can own controller regions.
    #[error("global-name driver is already running")]
    DriverRunning,
    /// Shutdown and driver abandonment permanently seal this instance.
    #[error("global-name registry is closed")]
    Closed,
    /// Caller cancellation was acknowledged.
    #[error("global-name operation cancelled")]
    Cancelled,
    /// Retained local names, pending requests, or finite generations are full.
    #[error("global-name capacity exhausted")]
    Capacity,
    /// Invalid bounded canonical payload.
    #[error("invalid global-name payload")]
    Format,
    /// Peer identity or independently authenticated incarnation is inadmissible.
    #[error("global-name owner authority refused")]
    Authority,
    /// An older owner incarnation or sequence cannot replace an accepted one.
    #[error("global-name snapshot is stale")]
    Stale,
    /// Identical owner/incarnation/sequence carried different bytes.
    #[error("global-name sequence was reused with different contents")]
    SequenceConflict,
    /// This observer already knows a competing claim.
    #[error("global name has a competing owner")]
    Conflict(GlobalNameTarget),
    /// A response did not bind the exact submitted request.
    #[error("global-name response did not match the request")]
    Receipt,
    /// The bounded admission window elapsed before publication.
    #[error("global-name registration expired")]
    AdmissionExpired,
    /// A driver cannot register its own task and then wait for its own DOWN.
    #[error("global-name driver cannot register itself")]
    DriverIsOwner,
    /// Actual monitored process-group admission failed.
    #[error("global-name local lease failed: {0}")]
    Group(#[from] ManagedGroupError),
}

struct Signal {
    release: AtomicBool,
    status: Mutex<GlobalNameLeaseStatus>,
    changed: Notify,
}
impl Signal {
    fn new() -> Self {
        Self { release: AtomicBool::new(false), status: Mutex::new(GlobalNameLeaseStatus::Active), changed: Notify::new() }
    }
    fn retiring(&self, reason: GlobalNameEndReason) {
        *self.status.lock() = GlobalNameLeaseStatus::Retiring(reason);
        wake(&self.changed);
    }
    fn finish(&self, retirement: Arc<GlobalNameRetirement>) {
        *self.status.lock() = GlobalNameLeaseStatus::Retired(retirement);
        wake(&self.changed);
    }
}

struct Reply {
    value: Option<Result<ProcessGroupClient<()>, GlobalNameError>>,
    received: bool,
}
struct Request {
    reply: Mutex<Reply>,
    changed: Notify,
}
impl Request {
    fn finish(&self, value: Result<ProcessGroupClient<()>, GlobalNameError>) {
        {
            let mut reply = self.reply.lock();
            if !reply.received { reply.value = Some(value); }
        }
        wake(&self.changed);
    }
}

struct Local {
    target: GlobalNameTarget,
    signal: Arc<Signal>,
    request: Arc<Request>,
    group: Option<ManagedProcessGroup<()>>,
    member: Option<ManagedGroupMembership<()>>,
    opening: bool,
    deadline: Time,
    published_at: Time,
    finalized: bool,
}
impl Local {
    fn published(&self) -> bool { self.member.is_some() }
}
impl Drop for Local {
    fn drop(&mut self) {
        if !self.finalized {
            if let Some(group) = &self.group { group.request_abort(); }
            let reason = match &*self.signal.status.lock() {
                GlobalNameLeaseStatus::Retiring(reason) => reason.clone(),
                _ => GlobalNameEndReason::DriverDropped,
            };
            self.signal.finish(Arc::new(GlobalNameRetirement { reason, exit: None }));
            self.request.finish(Err(GlobalNameError::Closed));
        }
        // The actual group owner is dropped outside registry locks. Its Drop
        // requests cancellation and arms the runtime child-region close barrier.
    }
}

struct Remote {
    snapshot: wire::Snapshot,
    observed_at: Time,
}
struct State {
    running: bool,
    closed: bool,
    driver_task: Option<TaskId>,
    runtime: Option<Weak<ObligationMailbox>>,
    clock: Option<TimerDriverHandle>,
    next_registration: u64,
    sequence: u64,
    locals: BTreeMap<String, Local>,
    draining: usize,
    remotes: BTreeMap<NodeId, Remote>,
}
struct Shared {
    node: NodeId,
    incarnation: u64,
    peers: Vec<NodeId>,
    membership: OwnedMembershipController,
    config: GlobalNameConfig,
    state: Mutex<State>,
    changed: Notify,
}

/// Cloneable capability; run its single driver in an explicitly owned task.
#[derive(Clone)]
pub struct GlobalNameRegistry { shared: Arc<Shared> }
impl fmt::Debug for GlobalNameRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.shared.state.lock();
        f.debug_struct("GlobalNameRegistry").field("node", &self.shared.node)
            .field("incarnation", &self.shared.incarnation).field("local_names", &state.locals.len())
            .field("draining", &state.draining).field("running", &state.running)
            .field("closed", &state.closed).finish_non_exhaustive()
    }
}

/// Generation-specific release and typed conflict notification capability.
/// Moving this handle does not move the original actor or its monitored identity.
pub struct GlobalNameLease {
    name: String,
    target: GlobalNameTarget,
    signal: Arc<Signal>,
    shared: Arc<Shared>,
}
impl fmt::Debug for GlobalNameLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GlobalNameLease").field("name", &self.name)
            .field("target", &self.target).field("status", &self.status()).finish()
    }
}

/// Actual owner-driven retirement totals, not remote convergence evidence.
#[derive(Debug, Default)]
pub struct GlobalNameRunReport {
    /// Controllers or pending entries withdrawn.
    pub retired: usize,
    /// Deterministic conflicts that withdrew a local claim.
    pub conflicts: usize,
    /// Observed original-task departures.
    pub owner_down: usize,
    /// Entries with an admitted controller but no successful drain receipt.
    pub close_failures: usize,
}

fn wake(notify: &Notify) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| notify.notify_waiters())) {
        std::mem::forget(payload);
    }
}

fn runtime(cx: &Cx) -> Result<Weak<ObligationMailbox>, GlobalNameError> {
    if cx.checkpoint().is_err() { return Err(GlobalNameError::Cancelled); }
    let (gateway, holder) = cx.obligation_transfer_destination().map_err(|_| GlobalNameError::Runtime)?;
    if !gateway.is_runtime_available() || !holder.is_live()
        || holder.holder() != cx.task_id() || holder.region() != cx.region_id()
    { return Err(GlobalNameError::Runtime); }
    Ok(Arc::downgrade(gateway.mailbox()))
}

struct Admission {
    shared: Arc<Shared>,
    signal: Arc<Signal>,
    complete: bool,
}
impl Drop for Admission {
    fn drop(&mut self) {
        if !self.complete {
            self.signal.release.store(true, Ordering::Release);
            wake(&self.shared.changed);
        }
    }
}

struct Driver<'a>(&'a GlobalNameRegistry);
impl Drop for Driver<'_> {
    fn drop(&mut self) {
        let locals = {
            let mut state = self.0.shared.state.lock();
            state.closed = true;
            state.running = false;
            std::mem::take(&mut state.locals)
        };
        // No group destructor, user waker, or checked settlement under the mutex.
        drop(locals);
        wake(&self.0.shared.changed);
    }
}

struct Draining(Arc<Shared>);
impl Drop for Draining {
    fn drop(&mut self) {
        self.0.state.lock().draining -= 1;
        wake(&self.0.changed);
    }
}

impl GlobalNameRegistry {
    /// Provision immutable direct peers and a separately authenticated membership
    /// controller. This creates no task, lease, listener, or ambient authority.
    /// Restarted owners must restore a fresh trusted incarnation before serving;
    /// in-memory catalog high-water marks are not crash-persistent storage.
    pub fn new(
        node: NodeId, incarnation: u64, peers: impl IntoIterator<Item = NodeId>,
        membership: OwnedMembershipController, config: GlobalNameConfig,
    ) -> Result<Self, GlobalNameError> {
        wire::label(node.as_str()).map_err(|_| GlobalNameError::Configuration)?;
        if incarnation == 0 { return Err(GlobalNameError::Configuration); }
        let mut accepted = Vec::new();
        for peer in peers {
            if accepted.len() == wire::MAX_PEERS || peer == node
                || accepted.contains(&peer) || wire::label(peer.as_str()).is_err()
            { return Err(GlobalNameError::Configuration); }
            accepted.push(peer);
        }
        accepted.sort();
        Ok(Self { shared: Arc::new(Shared {
            node, incarnation, peers: accepted, membership, config,
            state: Mutex::new(State {
                running: false, closed: false, driver_task: None, runtime: None, clock: None,
                next_registration: 0, sequence: 1, locals: BTreeMap::new(),
                draining: 0, remotes: BTreeMap::new(),
            }),
            changed: Notify::new(),
        }) })
    }

    /// Immutable direct owner identity.
    pub fn local_node(&self) -> &NodeId { &self.shared.node }
    /// Independently authorized local incarnation.
    pub fn incarnation(&self) -> u64 { self.shared.incarnation }
    /// Fixed allowlist; catalogs never add peers or routes.
    pub fn peers(&self) -> impl Iterator<Item = &NodeId> { self.shared.peers.iter() }
    /// Whether the driver has bound its actual runtime and still admits work.
    pub fn is_running(&self) -> bool {
        let state = self.shared.state.lock();
        state.running && !state.closed
    }

    fn validate(&self, cx: &Cx) -> Result<(), GlobalNameError> {
        let identity = runtime(cx)?;
        let state = self.shared.state.lock();
        if state.closed { return Err(GlobalNameError::Closed); }
        if !state.running { return Err(GlobalNameError::NotRunning); }
        if state.runtime.as_ref().is_none_or(|bound| !Weak::ptr_eq(bound, &identity)) {
            return Err(GlobalNameError::Runtime);
        }
        Ok(())
    }

    fn suspect(&self, node: &NodeId) -> bool {
        self.shared.membership.stamp(node).is_some_and(|stamp| stamp.kind == MembershipKind::Suspect)
    }

    fn local_permitted(&self) -> bool {
        self.shared.membership.permits_name_observation(&self.shared.node, self.shared.incarnation)
    }

    fn remote_winner(&self, state: &State, name: &str) -> Option<GlobalNameView> {
        state.remotes.iter().filter_map(|(node, remote)| {
            if !self.shared.membership.permits_name_observation(node, remote.snapshot.incarnation) {
                return None;
            }
            remote.snapshot.names.get(name).map(|target| GlobalNameView {
                target: target.clone(), owner_sequence: remote.snapshot.sequence,
                observed_at: remote.observed_at, local_owner: false, owner_suspect: self.suspect(node),
            })
        }).min_by(|left, right| left.target.cmp(&right.target))
    }

    fn winner(&self, state: &State, name: &str) -> Option<GlobalNameView> {
        let remote = self.remote_winner(state, name);
        let local = state.locals.get(name).filter(|entry| {
            !entry.signal.release.load(Ordering::Acquire)
                && entry.member.as_ref().is_some_and(ManagedGroupMembership::is_active)
                && self.local_permitted()
        }).map(|entry| GlobalNameView {
            target: entry.target.clone(), owner_sequence: state.sequence,
            observed_at: entry.published_at, local_owner: true,
            owner_suspect: self.suspect(&self.shared.node),
        });
        match (local, remote) {
            (Some(local), Some(remote)) => Some(if local.target <= remote.target { local } else { remote }),
            (local, remote) => local.or(remote),
        }
    }

    fn retirement_reason(&self, state: &State, name: &str, entry: &Local, now: Time) -> Option<GlobalNameEndReason> {
        if state.closed { return Some(GlobalNameEndReason::Shutdown); }
        if entry.signal.release.load(Ordering::Acquire) { return Some(GlobalNameEndReason::Released); }
        if !entry.published() && now >= entry.deadline { return Some(GlobalNameEndReason::AdmissionExpired); }
        if entry.member.as_ref().is_some_and(|member| !member.is_active()) { return Some(GlobalNameEndReason::OwnerDown); }
        if !self.local_permitted() { return Some(GlobalNameEndReason::MembershipLost); }
        if let Some(winner) = self.remote_winner(state, name) {
            if winner.target < entry.target { return Some(GlobalNameEndReason::Conflict(winner.target)); }
        }
        None
    }

    /// Wait for the separately spawned driver, without creating any work.
    pub async fn wait_running(&self, cx: &Cx) -> Result<(), GlobalNameError> {
        let _ = runtime(cx)?;
        let mut changed = std::pin::pin!(self.shared.changed.wait_until(|| {
            let state = self.shared.state.lock();
            state.running || state.closed
        }));
        let mut cancelled = std::pin::pin!(cx.cancelled());
        poll_fn(|task| {
            if cancelled.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() { return Poll::Ready(Err(GlobalNameError::Cancelled)); }
            if changed.as_mut().poll(task).is_ready() { return Poll::Ready(Ok(())); }
            Poll::Pending
        }).await?;
        self.validate(cx)
    }

    /// Reserve a bounded admission slot and join using the actual actor's Cx.
    ///
    /// The driver opens and owns the controller's child region. A name becomes
    /// visible only after its real task monitor and checked local name lease are
    /// installed. Cancellation or future abandonment releases the admission;
    /// forgotten pending futures expire on the explicit driver's clock.
    pub async fn register_global(
        &self, cx: &Cx, name: impl Into<String>, computation: impl Into<String>,
    ) -> Result<GlobalNameLease, GlobalNameError> {
        self.validate(cx)?;
        let name = name.into();
        let computation = computation.into();
        wire::label(&name)?;
        let _ = GroupName::new(name.clone()).map_err(|_| GlobalNameError::Format)?;
        wire::label(&computation)?;
        let signal = Arc::new(Signal::new());
        let request = Arc::new(Request {
            reply: Mutex::new(Reply { value: None, received: false }), changed: Notify::new(),
        });
        let target = {
            let mut state = self.shared.state.lock();
            if state.closed { return Err(GlobalNameError::Closed); }
            if state.driver_task == Some(cx.task_id()) { return Err(GlobalNameError::DriverIsOwner); }
            if !self.shared.membership.permits_native_route(&self.shared.node, self.shared.incarnation) {
                return Err(GlobalNameError::Authority);
            }
            if state.locals.len().saturating_add(state.draining) >= self.shared.config.max_local_names {
                return Err(GlobalNameError::Capacity);
            }
            if let Some(current) = state.locals.get(&name) { return Err(GlobalNameError::Conflict(current.target.clone())); }
            let registration = state.next_registration.checked_add(1).ok_or(GlobalNameError::Capacity)?;
            let target = GlobalNameTarget {
                node: self.shared.node.clone(), incarnation: self.shared.incarnation, registration, computation,
            };
            if let Some(winner) = self.remote_winner(&state, &name) {
                if winner.target < target { return Err(GlobalNameError::Conflict(winner.target)); }
            }
            let now = state.clock.as_ref().ok_or(GlobalNameError::Runtime)?.now();
            let deadline = now + self.shared.config.registration_timeout;
            if deadline <= now { return Err(GlobalNameError::Capacity); }
            state.next_registration = registration;
            state.locals.insert(name.clone(), Local {
                target: target.clone(), signal: Arc::clone(&signal), request: Arc::clone(&request),
                group: None, member: None, opening: false, deadline, published_at: now, finalized: false,
            });
            target
        };
        let mut admission = Admission { shared: Arc::clone(&self.shared), signal: Arc::clone(&signal), complete: false };
        wake(&self.shared.changed);
        let client = {
            let mut ready = std::pin::pin!(request.changed.wait_until(|| request.reply.lock().value.is_some()));
            let mut cancelled = std::pin::pin!(cx.cancelled());
            poll_fn(|task| {
                if cancelled.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() { return Poll::Ready(Err(GlobalNameError::Cancelled)); }
                if ready.as_mut().poll(task).is_ready() {
                    let mut reply = request.reply.lock();
                    if let Some(value) = reply.value.take() {
                        reply.received = true;
                        return Poll::Ready(value);
                    }
                }
                Poll::Pending
            }).await?
        };
        let mut member = Some(client.join(cx).await?);
        if cx.checkpoint().is_err() { return Err(GlobalNameError::Cancelled); }
        let publication = {
            let mut state = self.shared.state.lock();
            (|| {
                if state.closed { return Err(GlobalNameError::Closed); }
                if !self.shared.membership.permits_native_route(&self.shared.node, self.shared.incarnation) {
                    return Err(GlobalNameError::Authority);
                }
                if let Some(winner) = self.remote_winner(&state, &name) {
                    if winner.target < target { return Err(GlobalNameError::Conflict(winner.target)); }
                }
                let now = state.clock.as_ref().ok_or(GlobalNameError::Runtime)?.now();
                let sequence = state.sequence.checked_add(1).ok_or(GlobalNameError::Capacity)?;
                let entry = state.locals.get_mut(&name).ok_or(GlobalNameError::Closed)?;
                if entry.target.registration != target.registration || entry.signal.release.load(Ordering::Acquire) {
                    return Err(GlobalNameError::Closed);
                }
                if now >= entry.deadline { return Err(GlobalNameError::AdmissionExpired); }
                if !member.as_ref().is_some_and(ManagedGroupMembership::is_active) { return Err(GlobalNameError::Closed); }
                entry.member = member.take();
                entry.published_at = now;
                state.sequence = sequence;
                Ok(())
            })()
        };
        publication?;
        if cx.checkpoint().is_err() { return Err(GlobalNameError::Cancelled); }
        admission.complete = true;
        wake(&self.shared.changed);
        Ok(GlobalNameLease { name, target, signal, shared: Arc::clone(&self.shared) })
    }

    /// Return this observer's deterministic winner, including explicit suspicion.
    /// None is local absence, not a cluster-wide negative lookup. A partition can
    /// leave this result stale indefinitely; use an exact-owner round trip when
    /// a fresh observation at the selected owner is required.
    pub fn whereis_global(&self, cx: &Cx, name: &str) -> Result<Option<GlobalNameView>, GlobalNameError> {
        self.validate(cx)?;
        wire::label(name)?;
        let state = self.shared.state.lock();
        if state.closed { return Err(GlobalNameError::Closed); }
        Ok(self.winner(&state, name))
    }

    /// Encode this node's complete published catalog only.
    ///
    /// A withdrawn claim must first advance the sequence in the driver. Refusal
    /// during that interval prevents different bytes at the same sequence.
    pub fn snapshot(&self, cx: &Cx) -> Result<Vec<u8>, GlobalNameError> {
        self.validate(cx)?;
        let state = self.shared.state.lock();
        if state.closed { return Err(GlobalNameError::Closed); }
        if !self.local_permitted() { return Err(GlobalNameError::Authority); }
        let now = state.clock.as_ref().ok_or(GlobalNameError::Runtime)?.now();
        let mut names = BTreeMap::new();
        for (name, entry) in &state.locals {
            if entry.published() {
                if self.retirement_reason(&state, name, entry, now).is_some() { return Err(GlobalNameError::PendingRetirement); }
                names.insert(name.clone(), entry.target.clone());
            }
        }
        wire::encode_snapshot(self.shared.incarnation, state.sequence, &names)
    }

    /// Apply a full catalog from its direct authenticated owner.
    ///
    /// No third-party relaying or serialized owner identity is accepted. Exact
    /// retries are idempotent; older snapshots and sequence equivocation refuse.
    /// Accepted high-water marks survive member death for this registry lifetime.
    pub fn apply_authenticated_snapshot(
        &self, cx: &Cx, peer: &NodeId, bytes: &[u8],
    ) -> Result<GlobalNameSnapshotReceipt, GlobalNameError> {
        self.validate(cx)?;
        if !self.shared.peers.contains(peer) { return Err(GlobalNameError::Authority); }
        let snapshot = wire::decode_snapshot(peer, bytes, self.shared.config.max_names_per_peer)?;
        let receipt = GlobalNameSnapshotReceipt {
            owner: peer.clone(), incarnation: snapshot.incarnation, sequence: snapshot.sequence, digest: snapshot.digest,
        };
        {
            let mut state = self.shared.state.lock();
            if state.closed { return Err(GlobalNameError::Closed); }
            if !self.local_permitted() || !self.shared.membership.permits_native_route(peer, snapshot.incarnation) {
                return Err(GlobalNameError::Authority);
            }
            if let Some(previous) = state.remotes.get(peer) {
                let old = &previous.snapshot;
                if (snapshot.incarnation, snapshot.sequence) < (old.incarnation, old.sequence) { return Err(GlobalNameError::Stale); }
                if snapshot.incarnation == old.incarnation && snapshot.sequence == old.sequence && snapshot.digest != old.digest {
                    return Err(GlobalNameError::SequenceConflict);
                }
            }
            let observed_at = state.clock.as_ref().ok_or(GlobalNameError::Runtime)?.now();
            state.remotes.insert(peer.clone(), Remote { snapshot, observed_at });
        }
        wake(&self.shared.changed);
        Ok(receipt)
    }

    /// Answer an exact-incarnation round trip using only this owner's live claim.
    /// A remote cached winner is never represented as this node's authoritative
    /// answer. Suspect is still only local authority, not majority authority.
    pub fn authoritative_reply(&self, cx: &Cx, name: &str, incarnation: u64) -> Result<Vec<u8>, GlobalNameError> {
        self.validate(cx)?;
        wire::label(name)?;
        let state = self.shared.state.lock();
        if state.closed { return Err(GlobalNameError::Closed); }
        if incarnation != self.shared.incarnation || !self.local_permitted() { return Err(GlobalNameError::Authority); }
        if let Some(entry) = state.locals.get(name) {
            let now = state.clock.as_ref().ok_or(GlobalNameError::Runtime)?.now();
            if entry.published() && self.retirement_reason(&state, name, entry, now).is_some() {
                return Err(GlobalNameError::PendingRetirement);
            }
        }
        let local = self.winner(&state, name).filter(|view| view.local_owner);
        wire::lookup_reply(incarnation, state.sequence, name, local.as_ref().map(|view| &view.target))
    }

    /// Permanently seal admission and wake the caller-owned drain loop.
    pub fn request_shutdown(&self) {
        self.shared.state.lock().closed = true;
        wake(&self.shared.changed);
    }

    /// Own all local controller regions and drain them on shutdown/cancellation.
    ///
    /// This future creates no detached work. Each opened group is a real child
    /// region of this driver task, never a child of its monitored actor. The
    /// per-name controller owns the checked local registry lease and monitor.
    /// Dropping the driver requests actual child-region cleanup but cannot return
    /// a drain receipt; surviving leases explicitly report that absent receipt.
    pub async fn run(&self, cx: &Cx) -> Result<GlobalNameRunReport, GlobalNameError> {
        let identity = runtime(cx)?;
        let clock = cx.timer_driver().ok_or(GlobalNameError::Runtime)?;
        {
            let mut state = self.shared.state.lock();
            if state.closed { return Err(GlobalNameError::Closed); }
            if state.running { return Err(GlobalNameError::DriverRunning); }
            if !self.shared.membership.permits_native_route(&self.shared.node, self.shared.incarnation) {
                return Err(GlobalNameError::Authority);
            }
            state.running = true;
            state.runtime = Some(identity);
            state.clock = Some(clock.clone());
            state.driver_task = Some(cx.task_id());
        }
        let _driver = Driver(self);
        wake(&self.shared.changed);
        let mut report = GlobalNameRunReport::default();
        let mut cancelled = false;
        loop {
            if cx.checkpoint().is_err() {
                cancelled = true;
                self.request_shutdown();
            }
            enum Work {
                Retire(String, GlobalNameEndReason),
                Open(String, Arc<Request>),
                Wait,
                Done,
            }
            let work = {
                let mut state = self.shared.state.lock();
                let now = clock.now();
                let retirement = state.locals.iter().find_map(|(name, entry)| {
                    self.retirement_reason(&state, name, entry, now).map(|reason| Work::Retire(name.clone(), reason))
                });
                if let Some(retirement) = retirement { retirement }
                else if state.closed && state.locals.is_empty() { Work::Done }
                else if let Some((name, entry)) = state.locals.iter_mut().find(|(_, entry)| !entry.opening && entry.group.is_none()) {
                    entry.opening = true;
                    Work::Open(name.clone(), Arc::clone(&entry.request))
                } else { Work::Wait }
            };
            match work {
                Work::Done => return if cancelled { Err(GlobalNameError::Cancelled) } else { Ok(report) },
                Work::Retire(name, reason) => {
                    let mut entry = {
                        let mut state = self.shared.state.lock();
                        let Some(entry) = state.locals.remove(&name) else { continue; };
                        if entry.published() {
                            if let Some(next) = state.sequence.checked_add(1) { state.sequence = next; }
                            else { state.closed = true; }
                        }
                        state.draining += 1;
                        entry
                    };
                    let _credit = Draining(Arc::clone(&self.shared));
                    entry.signal.retiring(reason.clone());
                    entry.request.finish(Err(match &reason {
                        GlobalNameEndReason::AdmissionExpired => GlobalNameError::AdmissionExpired,
                        GlobalNameEndReason::Conflict(target) => GlobalNameError::Conflict(target.clone()),
                        _ => GlobalNameError::Closed,
                    }));
                    let had_group = entry.group.is_some();
                    // Retain membership until shutdown has selected and settled
                    // the terminal. A conflict must abort the checked name lease.
                    let exit = if let Some(group) = entry.group.take() {
                        Some(if reason == GlobalNameEndReason::Released { group.shutdown().await } else { group.abort().await })
                    } else { None };
                    let retirement = Arc::new(GlobalNameRetirement { reason: reason.clone(), exit });
                    report.retired += 1;
                    if matches!(reason, GlobalNameEndReason::Conflict(_)) { report.conflicts += 1; }
                    if reason == GlobalNameEndReason::OwnerDown { report.owner_down += 1; }
                    if had_group && !retirement.is_drained() { report.close_failures += 1; }
                    drop(_credit);
                    entry.signal.finish(retirement);
                    entry.finalized = true;
                    drop(entry);
                    wake(&self.shared.changed);
                }
                Work::Open(name, request) => {
                    let group_name = GroupName::new(name.clone()).map_err(|_| GlobalNameError::Format)?;
                    let opened = ManagedProcessGroup::<()>::open(
                        cx, group_name, self.shared.node.clone(), ManagedProcessGroupConfig::new(1, 1, 1, 4),
                    ).await;
                    match opened {
                        Ok(group) => {
                            group.abort_on_member_down();
                            let client = group.client();
                            {
                                let mut state = self.shared.state.lock();
                                let entry = state.locals.get_mut(&name).expect("only driver removes local admissions");
                                entry.group = Some(group);
                            }
                            request.finish(Ok(client));
                        }
                        Err(error) => {
                            let entry = self.shared.state.lock().locals.remove(&name);
                            if let Some(mut entry) = entry {
                                entry.signal.finish(Arc::new(GlobalNameRetirement {
                                    reason: GlobalNameEndReason::AdmissionFailed, exit: None,
                                }));
                                entry.request.finish(Err(GlobalNameError::Group(error)));
                                entry.finalized = true;
                                drop(entry);
                            }
                            report.retired += 1;
                        }
                    }
                }
                Work::Wait => {
                    let deadline = clock.now() + self.shared.config.maintenance_interval;
                    let mut timer = std::pin::pin!(Sleep::with_timer_driver(deadline, clock.clone()));
                    let mut changed = std::pin::pin!(self.shared.changed.wait_until(|| {
                        let state = self.shared.state.lock();
                        state.closed || state.locals.iter().any(|(name, entry)| {
                            (!entry.opening && entry.group.is_none())
                                || self.retirement_reason(&state, name, entry, clock.now()).is_some()
                        })
                    }));
                    let mut cancellation = std::pin::pin!(cx.cancelled());
                    poll_fn(|task| {
                        if (cancellation.as_mut().poll(task).is_ready() && cx.checkpoint().is_err())
                            || changed.as_mut().poll(task).is_ready()
                            || timer.as_mut().poll_deadline(task).is_ready()
                        { Poll::Ready(()) } else { Poll::Pending }
                    }).await;
                }
            }
        }
    }
}

impl GlobalNameLease {
    /// Exact registered name.
    pub fn name(&self) -> &str { &self.name }
    /// Immutable target identity for this registration.
    pub fn target(&self) -> &GlobalNameTarget { &self.target }
    /// Driver-observed status, not permission to bypass invocation admission.
    pub fn status(&self) -> GlobalNameLeaseStatus { self.signal.status.lock().clone() }
    /// Withdraw this exact generation without waiting or acquiring admission.
    pub fn request_release(&self) {
        self.signal.release.store(true, Ordering::Release);
        wake(&self.shared.changed);
    }
    /// Wait for the actual retirement report; this wait itself ignores caller
    /// cancellation so it can be used during owned cleanup.
    pub async fn ended(&self) -> Arc<GlobalNameRetirement> {
        self.signal.changed.wait_until(|| matches!(*self.signal.status.lock(), GlobalNameLeaseStatus::Retired(_))).await;
        match &*self.signal.status.lock() {
            GlobalNameLeaseStatus::Retired(retirement) => Arc::clone(retirement),
            _ => unreachable!("terminal notification predicate"),
        }
    }
    /// Request release and await its receipt, with explicit caller cancellation.
    /// Cancellation abandons this wait; it does not undo the release request.
    pub async fn release(self, cx: &Cx) -> Result<Arc<GlobalNameRetirement>, GlobalNameError> {
        self.request_release();
        let mut ended = std::pin::pin!(self.ended());
        let mut cancelled = std::pin::pin!(cx.cancelled());
        poll_fn(|task| {
            if let Poll::Ready(retirement) = ended.as_mut().poll(task) {
                let _ = cx.checkpoint();
                return Poll::Ready(Ok(retirement));
            }
            if cancelled.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() { return Poll::Ready(Err(GlobalNameError::Cancelled)); }
            Poll::Pending
        }).await
    }
}
impl Drop for GlobalNameLease {
    fn drop(&mut self) { self.request_release(); }
}

#[cfg(test)]
#[path = "global_names/tests.rs"]
mod tests;
