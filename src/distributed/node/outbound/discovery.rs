//! Owned endpoint refresh without changing a peer's provisioned authority.

use super::{
    NativeDistributedClient, NativeDistributedComponentResult, NativeDistributedOutboundError,
    Operation, Outbound, SubmissionGuard, TaskAccess,
};
use crate::cx::Cx;
use crate::distributed::remote_owned::RemoteRunError;
use crate::remote::{
    NativeRemoteDiscoveryBuildError, NativeRemoteDiscoveryConfig, NativeRemoteDiscoveryDriver,
    NativeRemoteDiscoveryError, NativeRemoteDiscoveryReport, NativeRemoteDiscoveryRoutes,
    NativeRemoteDiscoveryStop, NativeRemoteRouteRefresh, NativeRemoteRouteRefreshError,
    NodeId, RemoteComputationClientError,
};
use crate::runtime::JoinError;
use crate::service::Discover;
use crate::types::{CancelReason, TaskId};
use parking_lot::Mutex;
use std::cell::Cell;
use std::fmt;
use std::future::poll_fn;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

pub(super) type DiscoveryOutcome = Result<NativeRemoteDiscoveryReport, NativeRemoteDiscoveryError>;

/// Refusal before a node-owned discovery task was published.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeDistributedDiscoveryStartError {
    /// Existing node authority, exact membership, or task admission refused.
    #[error(transparent)]
    Outbound(#[from] NativeDistributedOutboundError),
    /// Existing discovery timing or retry settings are invalid.
    #[error(transparent)]
    Configuration(#[from] NativeRemoteDiscoveryBuildError),
    /// Each discovered snapshot must have a finite nonzero endpoint bound.
    #[error("node discovery requires a nonzero endpoint bound")]
    ZeroEndpointLimit,
    /// A previous owner or its unread result still occupies this peer's slot.
    #[error("node peer already has a retained discovery owner")]
    PeerOccupied,
    /// Running owners and unread reports fill the configured peer capacity.
    #[error("node discovery owner capacity is full")]
    Capacity,
    /// Source polling requires the node principal's enabled blocking pool.
    #[error("node discovery requires blocking-pool authority")]
    BlockingPoolUnavailable,
}

/// Actual discovery report and independent retirement of the node-owned task.
pub type NativeDistributedDiscoveryResult = NativeDistributedComponentResult<
    Result<NativeRemoteDiscoveryReport, NativeRemoteDiscoveryError>,
>;

impl Outbound {
    pub(super) fn retained_discoveries(&self) -> usize {
        let mut discoveries = self.discoveries.lock();
        let mut retired = Vec::new();
        let region_retired = self.region_retired.load(Ordering::Acquire);
        discoveries.retain(|_, operation| {
            if operation.reclaimable(region_retired) {
                retired.push(Arc::clone(operation));
                false
            } else { true }
        });
        let count = discoveries.len();
        drop(discoveries);
        // The last TaskHandle can drop a user waker. As for computation owners,
        // this destruction must happen outside the bounded catalog lock.
        drop(retired);
        count
    }

    fn reserve_discovery(
        &self, node: &NodeId,
    ) -> Result<Arc<Operation<DiscoveryOutcome>>, NativeDistributedDiscoveryStartError> {
        self.check_open()?;
        let _ = self.retained_discoveries();
        let mut discoveries = self.discoveries.lock();
        self.check_open()?;
        if discoveries.contains_key(node) {
            return Err(NativeDistributedDiscoveryStartError::PeerOccupied);
        }
        if discoveries.len() >= self.max_peers {
            return Err(NativeDistributedDiscoveryStartError::Capacity);
        }
        let operation = Arc::new(Operation {
            task: Mutex::new(None),
            outcome: Mutex::new(None),
            observed: AtomicBool::new(false),
            public: AtomicBool::new(true),
            stranded: AtomicBool::new(false),
        });
        discoveries.insert(node.clone(), Arc::clone(&operation));
        Ok(operation)
    }
}

// A provisioning token changes on every explicit publish, including replacement
// at the same membership incarnation. Discovery changes endpoints only and keeps
// that token. An unrelated peer publication cannot invalidate this owner.
struct NodeDiscoveryRoutes {
    shared: Arc<Outbound>,
    owner: Cx,
    incarnation: u64,
    provisioning: Arc<()>,
    max_endpoints: usize,
}

impl NodeDiscoveryRoutes {
    fn stopped(&self) -> bool {
        self.owner.is_cancel_requested() || self.shared.closed.load(Ordering::Acquire)
    }
}

impl NativeRemoteDiscoveryRoutes for NodeDiscoveryRoutes {
    fn route_generation(&self) -> u64 { self.shared.remote.route_generation() }

    fn stop_reason(&self, destination: &NodeId) -> Option<NativeRemoteDiscoveryStop> {
        if self.stopped() { return Some(NativeRemoteDiscoveryStop::Cancelled); }
        let peers = self.shared.peers.lock();
        if self.stopped() { return Some(NativeRemoteDiscoveryStop::Cancelled); }
        let current = peers.get(destination);
        if current.is_none_or(|(_, incarnation, token)| {
            *incarnation != self.incarnation || !Arc::ptr_eq(token, &self.provisioning)
        }) || !self.shared.membership.permits_native_route(destination, self.incarnation) {
            return Some(NativeRemoteDiscoveryStop::DestinationRemoved);
        }
        None
    }

    fn refresh_discovered_route(
        &self, destination: &NodeId, endpoints: Vec<SocketAddr>,
    ) -> Result<NativeRemoteRouteRefresh, NativeRemoteRouteRefreshError> {
        let mut peers = self.shared.peers.lock();
        if self.stopped() { return Err(NativeRemoteRouteRefreshError::Stopped); }
        let Some((route, incarnation, token)) = peers.get(destination) else {
            return Err(NativeRemoteRouteRefreshError::DestinationRemoved);
        };
        if *incarnation != self.incarnation || !Arc::ptr_eq(token, &self.provisioning) {
            return Err(NativeRemoteRouteRefreshError::DestinationRemoved);
        }
        if endpoints.len() > self.max_endpoints {
            return Err(NativeRemoteRouteRefreshError::InvalidSnapshot(
                RemoteComputationClientError::InvalidConfig("node discovery endpoint bound exceeded"),
            ));
        }
        // A source owns its transient allocations. Retain only its bounded
        // endpoint values, never a large spare capacity in a returned Vec.
        let endpoints = endpoints.into_boxed_slice().into_vec();
        let replacement = route.with_bootstrap_endpoints(endpoints)
            .map_err(NativeRemoteRouteRefreshError::InvalidSnapshot)?;
        if replacement.client().bootstrap_endpoints() == route.client().bootstrap_endpoints() {
            let result = self.shared.membership.publish_native_route(destination, self.incarnation, || {
                if self.stopped() { return Err(NativeRemoteRouteRefreshError::Stopped); }
                Ok(NativeRemoteRouteRefresh::Unchanged(self.shared.remote.route_generation()))
            }).unwrap_or(Err(NativeRemoteRouteRefreshError::DestinationRemoved));
            drop(peers);
            drop(replacement);
            return result;
        }
        let mut candidate = peers.clone();
        candidate.insert(destination.clone(), (replacement, self.incarnation, Arc::clone(&self.provisioning)));
        let publication = self.shared.membership.publish_native_route(destination, self.incarnation, || {
            if self.stopped() { return Err(NativeRemoteRouteRefreshError::Stopped); }
            self.shared.remote.replace_routes(candidate.values().map(|(route, _, _)| route.clone()))
                .map_err(NativeRemoteRouteRefreshError::Publication)
        }).unwrap_or(Err(NativeRemoteRouteRefreshError::DestinationRemoved));
        let generation = match publication {
            Ok(generation) => generation,
            Err(error) => { drop(peers); return Err(error); }
        };
        let old = std::mem::replace(&mut *peers, candidate);
        drop(peers);
        drop(old);
        Ok(NativeRemoteRouteRefresh::Published(generation))
    }
}

impl NativeDistributedClient {
    /// Discovery owners and unread reports retained separately from computation
    /// credits. At most one slot per peer and `max_peers` total can be retained.
    #[must_use]
    pub fn retained_discoveries(&self) -> usize { self.shared.retained_discoveries() }

    /// Start periodic endpoint discovery owned by this node's child region.
    ///
    /// The exact Alive incarnation and an explicitly provisioned route must
    /// already exist. Discovery can only replace that route's ordered endpoints;
    /// it preserves TLS identity/pins, grants, V3 hello, client limits, membership
    /// and any SWIM veto. It neither creates a peer nor authenticates a rejoin.
    /// Every explicit route replacement/removal ends the old discovery owner,
    /// even at the same incarnation. Changes to unrelated peers are independent.
    ///
    /// Source callbacks run on the node task's blocking pool without node locks.
    /// A running callback is always awaited before task retirement or node close,
    /// so sources must bound their own poll operation. `max_endpoints` bounds a
    /// retained discovered snapshot; allocations inside source callbacks remain
    /// source-owned. Empty, duplicate or excessive snapshots retain the last
    /// good route and use the existing bounded retry policy. Late snapshots after
    /// cancellation, close, revocation or reprovisioning cannot be published.
    ///
    /// Discovery has at most `max_peers` retained owners, one per peer, separate
    /// from computation capacity. An unread terminal report retains its slot;
    /// join it or drop the handle and allow actual retirement before restarting.
    /// Dropping a handle requests cancellation. Dropping only a join future
    /// leaves the handle usable. Submission unwind uses the same seal and
    /// region-cancellation backstop as named computation submission.
    pub fn spawn_peer_discovery<D>(
        &self, node: NodeId, incarnation: u64, discovery: Arc<D>,
        config: NativeRemoteDiscoveryConfig, max_endpoints: usize,
    ) -> Result<NativeDistributedDiscoveryHandle, NativeDistributedDiscoveryStartError>
    where
        D: Discover<Key = SocketAddr> + Send + Sync + 'static,
    {
        self.shared.check_open()?;
        config.validate()?;
        if max_endpoints == 0 { return Err(NativeDistributedDiscoveryStartError::ZeroEndpointLimit); }
        if self.principal.is_cancel_requested() {
            return Err(NativeDistributedOutboundError::Timing(RemoteRunError::Cancelled).into());
        }
        if self.principal.remote().is_none() {
            return Err(NativeDistributedOutboundError::Timing(RemoteRunError::NoCapability).into());
        }
        if self.principal.timer_driver().is_none() {
            return Err(NativeDistributedOutboundError::Timing(RemoteRunError::NoTimer).into());
        }
        if self.principal.blocking_pool_handle().is_none_or(|pool| pool.forbids_blocking()) {
            return Err(NativeDistributedDiscoveryStartError::BlockingPoolUnavailable);
        }
        let provisioning = {
            let peers = self.shared.peers.lock();
            let Some((_, current, token)) = peers.get(&node) else {
                return Err(NativeDistributedOutboundError::Membership.into());
            };
            if *current != incarnation || !self.shared.membership.permits_native_route(&node, incarnation) {
                return Err(NativeDistributedOutboundError::Membership.into());
            }
            Arc::clone(token)
        };
        let node = NodeId::new(node.as_str());
        let operation = self.shared.reserve_discovery(&node)?;
        let mut admission = SubmissionGuard {
            client: self, operation: Arc::clone(&operation), armed: true,
        };
        let destination = node.clone();
        let shared = Arc::clone(&self.shared);
        let returned = Arc::clone(&operation);
        let submitted = self.principal.spawn(move |body| async move {
            let routes = Arc::new(NodeDiscoveryRoutes {
                shared, owner: body.clone(), incarnation, provisioning, max_endpoints,
            });
            let driver = NativeRemoteDiscoveryDriver::with_routes(routes, node, discovery, config)
                .expect("discovery configuration validated before owner admission");
            let result = body.with_ambient(driver.run(&body)).await;
            *returned.outcome.lock() = Some(result);
            let _ = body.checkpoint();
        });
        match submitted {
            Ok(task) => {
                *operation.task.lock() = Some(task);
                let handle = NativeDistributedDiscoveryHandle {
                    operation, destination, incarnation, not_sync: PhantomData,
                };
                admission.armed = false;
                Ok(handle)
            }
            Err(error) => {
                operation.observed.store(true, Ordering::Release);
                admission.armed = false;
                Err(NativeDistributedOutboundError::Spawn(error).into())
            }
        }
    }
}

/// Bounded observation of a node-owned discovery task and its real retirement.
#[must_use = "join or close discovery to collect its actual report and retirement"]
pub struct NativeDistributedDiscoveryHandle {
    operation: Arc<Operation<DiscoveryOutcome>>,
    destination: NodeId,
    incarnation: u64,
    not_sync: PhantomData<Cell<()>>,
}

impl fmt::Debug for NativeDistributedDiscoveryHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDistributedDiscoveryHandle")
            .field("destination", &self.destination)
            .field("incarnation", &self.incarnation)
            .field("task_id", &self.task_id())
            .field("finished", &self.is_finished())
            .finish_non_exhaustive()
    }
}

impl NativeDistributedDiscoveryHandle {
    /// Logical peer whose explicitly provisioned endpoints this owner may refresh.
    #[must_use]
    pub fn destination(&self) -> &NodeId { &self.destination }

    /// Authenticated membership incarnation captured before submission.
    #[must_use]
    pub const fn incarnation(&self) -> u64 { self.incarnation }

    /// Actual node-owned task, provisional until spawn admission completes.
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.operation.task.lock().as_ref().expect("submitted discovery owner").task_id()
    }

    /// True only once the runtime has opened the owner retirement barrier.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.operation.task.lock().as_ref().expect("submitted discovery owner").is_finished()
    }

    /// Request cancellation; a currently executing source poll must still retire.
    pub fn abort(&self) {
        let task = TaskAccess::new(&self.operation.task);
        if !task.terminal_published() {
            task.abort_with_reason(CancelReason::user("node discovery owner abort"));
        }
    }

    /// Collect the actual source/refresh report after owner retirement.
    pub async fn join(&mut self) -> NativeDistributedDiscoveryResult {
        poll_fn(|cx| self.poll_join(cx)).await
    }

    /// Cancellation-independent observation. A completed result is consumed once.
    pub fn poll_join(&mut self, cx: &mut Context<'_>) -> Poll<NativeDistributedDiscoveryResult> {
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

    /// Request cancellation and await both source completion and task retirement.
    pub async fn close(&mut self) -> NativeDistributedDiscoveryResult {
        self.abort();
        self.join().await
    }
}

impl Drop for NativeDistributedDiscoveryHandle {
    fn drop(&mut self) {
        self.operation.public.store(false, Ordering::Release);
        self.abort();
    }
}
