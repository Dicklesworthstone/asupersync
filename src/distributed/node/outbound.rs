//! Explicit outbound authority and bounded remote owners for a native node.

use super::{Controls, NativeDistributedComponentResult, NativeDistributedNodeStopCause, StopPanics};
use crate::cx::Cx;
use crate::distributed::membership::owned::OwnedMembershipController;
use crate::distributed::membership::owned::remote::{MembershipRemoteError, MembershipRemoteReport};
use crate::distributed::remote_owned::{RemoteRunConfig, RemoteRunError, prepare_run};
use crate::remote::{
    ComputationName, NativeRemoteRoute, NativeRemoteRuntime, NativeRemoteRuntimeBuildError,
    NativeRemoteRuntimeConfig, NodeId, RemoteCap, RemoteComputationClientError, RemoteInput,
    RemoteRuntime,
};
use crate::runtime::{JoinError, RuntimeHandle, SpawnError, TaskHandle};
use crate::runtime::spawn_mailbox::RegionCommand;
use crate::types::{CancelReason, TaskId, Time};
use parking_lot::Mutex;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::future::poll_fn;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

mod discovery;
pub use discovery::{
    NativeDistributedDiscoveryHandle, NativeDistributedDiscoveryResult,
    NativeDistributedDiscoveryStartError,
};
mod typed;
pub use typed::{
    NativeDistributedTypedRemoteError, NativeDistributedTypedRemoteHandle,
    NativeDistributedTypedRemoteReport, NativeDistributedTypedRemoteResult,
};

/// Explicit transport authority and finite catalog/operation bounds.
///
/// Construction starts no task or connection. The supplied capability must be
/// unbound; its local identity, lease and budget are retained when the node binds
/// its private native runtime. A bootstrap node may initially have no peers.
/// The runtime handle is explicit authority and must remain driven until close.
/// Its caller remains responsible for that runtime's own shutdown, including
/// driver task retirement if it belongs to a different runtime than the node.
pub struct NativeDistributedOutboundConfig {
    remote: Arc<NativeRemoteRuntime>,
    capability: RemoteCap,
    max_peers: usize,
    max_operations: usize,
}

impl fmt::Debug for NativeDistributedOutboundConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDistributedOutboundConfig")
            .field("local_node", self.remote.local_node())
            .field("max_peers", &self.max_peers)
            .field("max_operations", &self.max_operations)
            .finish_non_exhaustive()
    }
}

impl NativeDistributedOutboundConfig {
    /// Configure a fresh, node-owned V3 runtime with no ambient routes.
    ///
    /// `transport.max_in_flight()` additionally bounds owner tasks and retained
    /// result slots. Completed, unread handles continue holding that credit.
    /// Each retained input allocation and computation name is bounded by its
    /// admitted route's frame limit. Per-client frame and attempt limits still
    /// govern transport buffers; caller-owned inputs/results remain outside.
    pub fn new(
        runtime: RuntimeHandle,
        capability: RemoteCap,
        transport: NativeRemoteRuntimeConfig,
        max_peers: usize,
    ) -> Result<Self, NativeDistributedOutboundError> {
        if max_peers == 0 || capability.runtime().is_some() {
            return Err(NativeDistributedOutboundError::Configuration);
        }
        let remote = Arc::new(NativeRemoteRuntime::with_config(
            runtime, capability.local_node().clone(), [], transport,
        )?);
        let capability = capability.with_runtime(Arc::clone(&remote) as Arc<dyn RemoteRuntime>);
        Ok(Self { remote, capability, max_peers, max_operations: transport.max_in_flight() })
    }

    pub(super) fn bind(self, membership: OwnedMembershipController) -> Arc<Outbound> {
        Arc::new(Outbound {
            remote: self.remote,
            capability: self.capability,
            membership,
            peers: Mutex::new(BTreeMap::new()),
            closed: AtomicBool::new(false),
            region_retired: AtomicBool::new(false),
            operations: Mutex::new(Vec::new()),
            discoveries: Mutex::new(BTreeMap::new()),
            max_peers: self.max_peers,
            max_operations: self.max_operations,
        })
    }
}

/// Configuration, route publication, or local owner admission refusal.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeDistributedOutboundError {
    /// Peers must have finite nonzero capacity and the capability must be unbound.
    #[error("node outbound configuration requires nonzero peers and an unbound capability")]
    Configuration,
    /// Node shutdown is terminal for all client clones.
    #[error("node outbound admission is closed")]
    Closed,
    /// The candidate would exceed the configured logical-peer catalog bound.
    #[error("node peer catalog is full")]
    PeerCapacity,
    /// Exact Alive authority and an explicitly published route are required.
    #[error("node peer incarnation is not authorized and published")]
    Membership,
    /// Pending/running operations and unread reports fill the shared capacity.
    #[error("node remote owner capacity is full")]
    OperationCapacity,
    /// The input allocation or computation name exceeds its route's frame bound.
    #[error("node remote input exceeds the configured route frame limit")]
    RequestTooLarge,
    /// Missing capability/clock, cancellation or an unusable timeout.
    #[error(transparent)]
    Timing(#[from] RemoteRunError),
    /// Existing native route protocol/origin validation refused publication.
    #[error(transparent)]
    Routes(#[from] NativeRemoteRuntimeBuildError),
    /// A route lacks the required enforcing server SPKI identity.
    #[error(transparent)]
    Identity(#[from] RemoteComputationClientError),
    /// The node region's existing task gateway refused before publication.
    #[error(transparent)]
    Spawn(#[from] SpawnError),
}

/// Outbound transport drain accounting collected by node close.
#[derive(Debug)]
#[non_exhaustive]
pub struct NativeDistributedOutboundReport {
    /// True if native drain did not have to force-close remaining transports.
    /// This records local session terminal publication, without asserting
    /// remote success or retirement of tasks on the supplied driver runtime.
    pub graceful: bool,
    /// Local native driver sessions still present after their close barrier.
    pub active_sessions: usize,
    /// Last successfully published route catalog generation.
    pub route_generation: u64,
    /// Credits still held by unread public handles after node task retirement.
    /// An uncollected region close also retains any submission interrupted by
    /// a panic before its task handle could be published to the caller.
    pub retained_operations: usize,
    /// Discovery owners or unread discovery reports, bounded separately by the
    /// configured peer capacity. Actual node region close drains their tasks.
    pub retained_discoveries: usize,
}

pub(super) struct Outbound {
    remote: Arc<NativeRemoteRuntime>,
    capability: RemoteCap,
    membership: OwnedMembershipController,
    peers: Mutex<BTreeMap<NodeId, (NativeRemoteRoute, u64, Arc<()>)>>,
    closed: AtomicBool,
    region_retired: AtomicBool,
    operations: Mutex<Vec<Arc<Operation>>>,
    discoveries: Mutex<BTreeMap<NodeId, Arc<Operation<discovery::DiscoveryOutcome>>>>,
    max_peers: usize,
    max_operations: usize,
}

impl Outbound {
    pub(super) fn begin_close(&self, panics: &mut StopPanics) {
        self.seal();
        panics.run(|| { let _ = self.remote.begin_drain(); });
    }

    fn seal(&self) {
        // Publication holds this same catalog lock. Finish its atomic update
        // before sealing; release the lock before invoking any stop callbacks.
        let peers = self.peers.lock();
        self.closed.store(true, Ordering::Release);
        drop(peers);
    }

    pub(super) async fn close(&self, cx: Option<&Cx>) -> bool {
        // Before child admission no public client can exist and this private
        // runtime has no route or operation. There is nothing to drive then.
        if let Some(cx) = cx { cx.with_ambient(self.remote.close(cx)).await }
        else { self.remote.active_operations() == 0 }
    }

    pub(super) fn region_retired(&self) {
        self.region_retired.store(true, Ordering::Release);
    }

    pub(super) fn report(&self, graceful: bool) -> NativeDistributedOutboundReport {
        NativeDistributedOutboundReport {
            graceful,
            active_sessions: self.remote.active_operations(),
            route_generation: self.remote.route_generation(),
            retained_operations: self.retained_operations(),
            retained_discoveries: self.retained_discoveries(),
        }
    }

    fn check_open(&self) -> Result<(), NativeDistributedOutboundError> {
        if self.closed.load(Ordering::Acquire) { Err(NativeDistributedOutboundError::Closed) }
        else { Ok(()) }
    }

    fn retained_operations(&self) -> usize {
        let mut operations = self.operations.lock();
        let mut retired = Vec::new();
        let region_retired = self.region_retired.load(Ordering::Acquire);
        operations.retain(|operation| {
            if operation.reclaimable(region_retired) {
                // The last TaskHandle may drop a user waker. Keep another Arc
                // until the catalog lock is released before running that drop.
                retired.push(Arc::clone(operation));
                false
            } else { true }
        });
        let count = operations.len();
        drop(operations);
        drop(retired);
        count
    }

    fn reserve(&self) -> Result<Arc<Operation>, NativeDistributedOutboundError> {
        self.check_open()?;
        let _ = self.retained_operations();
        let mut operations = self.operations.lock();
        self.check_open()?;
        if operations.len() == self.max_operations {
            return Err(NativeDistributedOutboundError::OperationCapacity);
        }
        let operation = Arc::new(Operation {
            task: Mutex::new(None),
            outcome: Mutex::new(None),
            observed: AtomicBool::new(false),
            public: AtomicBool::new(true),
            stranded: AtomicBool::new(false),
        });
        operations.push(Arc::clone(&operation));
        Ok(operation)
    }
}

// Keep the real TaskHandle in a bounded slot after public handle drop. A task's
// future can drop before record retirement; only the handle's barrier may free
// that slot. Reaping happens on the next admission/observation or node close and
// requires no detached cleanup task. An unread public result retains the slot.
struct Operation<R = Result<MembershipRemoteReport, NativeDistributedRemoteError>> {
    task: Mutex<Option<TaskHandle<()>>>,
    outcome: Mutex<Option<R>>,
    observed: AtomicBool,
    public: AtomicBool,
    stranded: AtomicBool,
}

impl<R> Operation<R> {
    fn reclaimable(&self, region_retired: bool) -> bool {
        if self.stranded.load(Ordering::Acquire) { return region_retired; }
        self.observed.load(Ordering::Acquire)
            || (!self.public.load(Ordering::Acquire)
                && self.task.lock().as_ref().is_some_and(TaskHandle::is_finished))
    }
}

// A spawn callback may panic either before enqueue or after the request became
// visible to the runtime. Without its returned handle those cases cannot be
// distinguished. Retain the reservation until the owning region has closed;
// never manufacture a terminal observation or launch detached cleanup.
struct SubmissionGuard<'a, R = Result<MembershipRemoteReport, NativeDistributedRemoteError>> {
    client: &'a NativeDistributedClient,
    operation: Arc<Operation<R>>,
    armed: bool,
}

impl<R> Drop for SubmissionGuard<'_, R> {
    fn drop(&mut self) {
        if !self.armed { return; }
        self.operation.stranded.store(true, Ordering::Release);
        // Another closer may have won Controls' cause CAS without reaching its
        // outbound callback yet. Seal admission here before any cleanup action.
        self.client.shared.seal();
        let mut panics = StopPanics::new();
        self.client.controls.stop(NativeDistributedNodeStopCause::OwnerDropped, &mut panics);
        panics.run(|| {
            if let Some(gateway) = self.client.principal.spawn_gateway_handle() {
                let _ = gateway.enqueue_region_command(RegionCommand::Cancel {
                    region_id: self.client.principal.region_id(),
                    reason: CancelReason::user("node outbound submission unwound"),
                });
            }
        });
    }
}

// Abort/poll may invoke waker code. Temporarily take the handle so such callbacks
// never run under the slot mutex; an unwinding callback still restores it. The
// public handle is Send but not Sync, so it is the slot's sole accessing owner.
// Concurrent catalog reaping treats a taken handle as not yet reclaimable.
struct TaskAccess<'a> {
    slot: &'a Mutex<Option<TaskHandle<()>>>,
    task: Option<TaskHandle<()>>,
}

impl<'a> TaskAccess<'a> {
    fn new(slot: &'a Mutex<Option<TaskHandle<()>>>) -> Self {
        let task = slot.lock().take().expect("submitted owner");
        Self { slot, task: Some(task) }
    }
}
impl Deref for TaskAccess<'_> {
    type Target = TaskHandle<()>;
    fn deref(&self) -> &Self::Target { self.task.as_ref().expect("taken owner") }
}
impl DerefMut for TaskAccess<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target { self.task.as_mut().expect("taken owner") }
}
impl Drop for TaskAccess<'_> {
    fn drop(&mut self) { *self.slot.lock() = self.task.take(); }
}

/// Cloneable access to the node's bounded, explicitly authorized outbound work.
///
/// Clones cannot outlive the node's admission or create work outside its child
/// region. Publishing a route is local provisioning, not a network join proof.
/// Native submission verifies the mTLS identity and computation grant at use.
#[derive(Clone)]
pub struct NativeDistributedClient {
    controls: Arc<Controls>,
    shared: Arc<Outbound>,
    principal: Cx,
}

impl fmt::Debug for NativeDistributedClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let peers = self.shared.peers.lock().len();
        let retained_operations = self.retained_operations();
        f.debug_struct("NativeDistributedClient")
            .field("local_node", self.shared.remote.local_node())
            .field("peers", &peers)
            .field("retained_operations", &retained_operations)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl NativeDistributedClient {
    pub(super) fn new(controls: Arc<Controls>, principal: Cx) -> Self {
        let shared = Arc::clone(controls.outbound.as_ref().expect("configured outbound"));
        let principal = principal.with_remote_cap(shared.capability.clone());
        Self { controls, shared, principal }
    }

    /// Whether node close has permanently sealed this client and every clone.
    #[must_use]
    pub fn is_closed(&self) -> bool { self.shared.closed.load(Ordering::Acquire) }

    /// Current owner/result credits, including complete but unread handles.
    #[must_use]
    pub fn retained_operations(&self) -> usize { self.shared.retained_operations() }

    /// Active native driver sessions; owner/result credits are counted separately.
    #[must_use]
    pub fn active_sessions(&self) -> usize { self.shared.remote.active_operations() }

    /// Current validated catalog generation. Membership can veto it independently.
    #[must_use]
    pub fn route_generation(&self) -> u64 { self.shared.remote.route_generation() }

    /// Publish an explicitly provisioned route for the current Alive incarnation.
    ///
    /// Publication is atomic with respect to membership replacement and closure.
    /// It preserves route TLS credentials, endpoints, V3 registry identity and
    /// optional SWIM veto, and binds the node's own membership controller. A new
    /// incarnation requires a new explicit call; stale statements never rebind
    /// an old route. The returned generation records this publication, not a
    /// promise that later authority changes leave the route eligible.
    pub fn publish_peer(
        &self, route: NativeRemoteRoute, incarnation: u64,
    ) -> Result<u64, NativeDistributedOutboundError> {
        self.shared.check_open()?;
        let destination = route.destination().clone();
        let route = route.with_membership(self.shared.membership.clone(), incarnation)?;
        let mut peers = self.shared.peers.lock();
        self.shared.check_open()?;
        if !peers.contains_key(&destination) && peers.len() == self.shared.max_peers {
            return Err(NativeDistributedOutboundError::PeerCapacity);
        }
        let mut candidate = peers.clone();
        // Explicit provisioning ends any discovery owner captured from the old
        // route, even when a replacement keeps the same membership incarnation.
        candidate.insert(destination.clone(), (route, incarnation, Arc::new(())));
        let publication = self.shared.membership.publish_native_route(&destination, incarnation, || {
            self.shared.check_open()?;
            self.shared.remote.replace_routes(candidate.values().map(|(route, _, _)| route.clone()))
                .map_err(NativeDistributedOutboundError::Routes)
        }).unwrap_or(Err(NativeDistributedOutboundError::Membership));
        let generation = match publication {
            Ok(generation) => generation,
            Err(error) => { drop(peers); return Err(error); }
        };
        let old = std::mem::replace(&mut *peers, candidate);
        drop(peers);
        drop(old);
        Ok(generation)
    }

    /// Withdraw a route for future work. Already admitted work retains its client
    /// through cancellation/drain; use authenticated revocation to end its lease.
    pub fn remove_peer(&self, node: &NodeId) -> Result<u64, NativeDistributedOutboundError> {
        let mut peers = self.shared.peers.lock();
        self.shared.check_open()?;
        let mut candidate = peers.clone();
        candidate.remove(node);
        let generation = self.shared.remote.replace_routes(candidate.values().map(|(route, _, _)| route.clone()))?;
        let old = std::mem::replace(&mut *peers, candidate);
        drop(peers);
        drop(old);
        Ok(generation)
    }

    fn route_frame_limit(
        &self, node: &NodeId, incarnation: u64,
    ) -> Result<usize, NativeDistributedOutboundError> {
        self.shared.check_open()?;
        let peers = self.shared.peers.lock();
        let Some((route, current, _)) = peers.get(node) else {
            return Err(NativeDistributedOutboundError::Membership);
        };
        if *current != incarnation || !self.shared.membership.permits_native_route(node, incarnation) {
            return Err(NativeDistributedOutboundError::Membership);
        }
        Ok(route.client().config().wire_limits().max_frame_bytes())
    }

    /// Submit one membership-owned named computation in the node's child region.
    ///
    /// The owner runs independently of result polling. Its task Cx owns the
    /// checked membership lease; the client principal never impersonates that
    /// holder. Closing the node cancels and drains every such owner. Dropping
    /// the returned handle requests the same operation cancellation. No work is
    /// retried across rejoin and no simulated remote fallback is used.
    /// The timeout starts at submission; owner-queue delay is deducted before
    /// membership admission, and a deadline already reached dispatches no work.
    /// If runtime submission unwinds, the node seals admission and requests its
    /// child-region cancellation. Await node close to retire the unpublished
    /// owner and release its reserved credit.
    pub fn spawn_remote(
        &self, node: NodeId, incarnation: u64, computation: ComputationName,
        input: RemoteInput, mut config: RemoteRunConfig,
    ) -> Result<NativeDistributedRemoteHandle, NativeDistributedOutboundError> {
        let frame_limit = self.route_frame_limit(&node, incarnation)?;
        let input = input.into_data();
        if input.capacity() > frame_limit || computation.as_str().len() > frame_limit {
            return Err(NativeDistributedOutboundError::RequestTooLarge);
        }
        let input = RemoteInput::new(input);
        // Copy only the bounded logical name, not a caller's possibly oversized
        // spare String allocation. Input's actual allocation was checked above.
        let computation = ComputationName::new(computation.as_str());
        let (clock, deadline) = prepare_run(&self.principal, &config)?;
        let operation = self.shared.reserve()?;
        let mut admission = SubmissionGuard {
            client: self, operation: Arc::clone(&operation), armed: true,
        };
        let shared = Arc::clone(&self.shared);
        let returned = Arc::clone(&operation);
        let submitted = self.principal.spawn(move |body| async move {
            // Admission can be queued behind close. Do not begin a fresh remote
            // invocation after that seal, even before child cancellation arrives.
            let result = if shared.closed.load(Ordering::Acquire) {
                Err(NativeDistributedRemoteError::Closed)
            } else if clock.now() >= deadline {
                Err(NativeDistributedRemoteError::Timing(RemoteRunError::Timeout))
            } else {
                config.timeout = Duration::from_nanos(deadline.duration_since(clock.now()));
                shared.membership.run_remote(&body, node, incarnation, computation, input, config)
                    .await.map_err(NativeDistributedRemoteError::Membership)
            };
            *returned.outcome.lock() = Some(result);
            let _ = body.checkpoint();
        });
        match submitted {
            Ok(task) => {
                *operation.task.lock() = Some(task);
                let handle = NativeDistributedRemoteHandle { operation, deadline, not_sync: PhantomData };
                admission.armed = false;
                Ok(handle)
            }
            Err(error) => {
                operation.observed.store(true, Ordering::Release);
                admission.armed = false;
                Err(error.into())
            }
        }
    }
}

/// Actual invocation refusal, independent of its owner task's retirement.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeDistributedRemoteError {
    /// Node close won after local submission but before body execution.
    #[error("node closed before remote work started")]
    Closed,
    /// The submission budget expired before actual membership admission.
    #[error(transparent)]
    Timing(#[from] RemoteRunError),
    /// Preserve the checked membership/remote runner's complete error.
    #[error(transparent)]
    Membership(#[from] MembershipRemoteError),
}

/// Actual operation result and independent local owner retirement.
pub type NativeDistributedRemoteResult = NativeDistributedComponentResult<
    Result<MembershipRemoteReport, NativeDistributedRemoteError>,
>;

/// One bounded result owner. Drop requests cancellation; no cleanup task is born.
#[must_use = "join or close to collect the actual remote and retirement results"]
pub struct NativeDistributedRemoteHandle {
    operation: Arc<Operation>,
    deadline: Time,
    not_sync: PhantomData<Cell<()>>,
}

impl fmt::Debug for NativeDistributedRemoteHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDistributedRemoteHandle")
            .field("task_id", &self.task_id())
            .field("finished", &self.is_finished()).finish_non_exhaustive()
    }
}

impl NativeDistributedRemoteHandle {
    /// Cancellation deadline captured before submitting the local owner task.
    #[must_use]
    pub const fn deadline(&self) -> Time { self.deadline }

    /// The real local owner task, provisional until its spawn is admitted.
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.operation.task.lock().as_ref().expect("submitted owner").task_id()
    }

    /// True only after the runtime has opened the owner retirement barrier.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.operation.task.lock().as_ref().expect("submitted owner").is_finished()
    }

    /// Request operation cancellation without erasing its eventual report.
    pub fn abort(&self) {
        let task = TaskAccess::new(&self.operation.task);
        if !task.terminal_published() {
            task.abort_with_reason(CancelReason::user("node remote owner abort"));
        }
    }

    /// Wait for actual task retirement, retaining any independently returned
    /// protocol/cleanup result. Dropping this wait leaves the handle usable.
    /// A repeated observation has no outcome and reports PolledAfterCompletion.
    pub async fn join(&mut self) -> NativeDistributedRemoteResult {
        poll_fn(|cx| self.poll_join(cx)).await
    }

    /// Cancellation-independent observation of the owner retirement barrier.
    pub fn poll_join(&mut self, cx: &mut Context<'_>) -> Poll<NativeDistributedRemoteResult> {
        if self.operation.observed.load(Ordering::Acquire) {
            return Poll::Ready(NativeDistributedComponentResult {
                outcome: None, retirement: Err(JoinError::PolledAfterCompletion),
            });
        }
        let terminal = TaskAccess::new(&self.operation.task).poll_join(cx);
        terminal.map(|retirement| {
            let outcome = self.operation.outcome.lock().take();
            self.operation.observed.store(true, Ordering::Release);
            NativeDistributedComponentResult { outcome, retirement }
        })
    }

    /// Request cancellation and await its actual protocol and local drain report.
    pub async fn close(&mut self) -> NativeDistributedRemoteResult {
        self.abort();
        self.join().await
    }
}

impl Drop for NativeDistributedRemoteHandle {
    fn drop(&mut self) {
        self.operation.public.store(false, Ordering::Release);
        self.abort();
    }
}
