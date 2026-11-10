//! Bounded authenticated symbol transfers owned by the node's actual region.

use super::{Controls, NativeDistributedNode, NativeDistributedNodeStopCause, StopPanics};
use crate::cx::Cx;
use crate::distributed::distribution::{DistributorTransport, ReplicaAck, ReplicaFailure};
use crate::distributed::membership::owned::OwnedLeaseStatus;
use crate::distributed::membership::owned::work::{
    MembershipWorkError, MembershipWorkReport, MembershipWorkTrigger,
};
use crate::distributed::remote_owned::{RemoteRunConfig, RemoteRunError, prepare_owned_timing};
use crate::distributed::symbol_service::{
    RemoteSymbolError, RemoteSymbolTransport, SymbolBatchKey, SymbolBatchLimits,
};
use crate::error::ErrorKind;
use crate::remote::{NativeRemoteRoute, NodeId, RemoteComputationClient, RemotePeerHello};
use crate::runtime::spawn_mailbox::RegionCommand;
use crate::runtime::{JoinError, SpawnError, TaskHandle};
use crate::security::{AuthKey, AuthenticatedSymbol};
use crate::time::TimerDriverHandle;
use crate::types::{CancelReason, Symbol, Time};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Finite route/owner bounds and a fixed operation lifetime.
#[derive(Debug, Clone)]
pub struct NativeDistributedSymbolConfig {
    /// Maximum explicitly provisioned logical replicas; must be nonzero.
    pub max_routes: usize,
    /// Shared running/unobserved owner slots; zero denies all operations.
    pub max_in_flight: usize,
    /// Admission-to-lease deadline and the existing child-region policy.
    pub work: RemoteRunConfig,
    /// Optional bounded multi-frame transfer, requiring its separate service grant.
    pub max_chunk_bytes: Option<usize>,
}

/// An explicit replica-to-member binding, with separately provisioned TLS identity.
#[derive(Debug, Clone)]
pub struct NativeDistributedSymbolRoute {
    /// Exact replica identity used in authenticated storage receipts.
    pub replica_id: String,
    /// Logical member whose current Alive statement authorizes this route.
    pub node: NodeId,
    /// Exact incarnation; later membership statements never silently rebind it.
    pub incarnation: u64,
    /// Existing finite mTLS client with one enforcing server SPKI pin.
    pub client: RemoteComputationClient,
}

/// Local construction/admission failures, separate from the retained work report.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeDistributedSymbolError {
    /// Invalid finite bounds, duplicate routes, or oversized retained input.
    #[error("invalid node symbol transport configuration or input")]
    Configuration,
    /// The node has permanently sealed admission.
    #[error("node symbol admission is closed")]
    Closed,
    /// The node principal cannot exercise remote authority.
    #[error("node symbol transport requires remote permission")]
    MissingRemote,
    /// The requested replica was not explicitly provisioned.
    #[error("node symbol replica is not configured")]
    UnknownReplica,
    /// The configured member is not Alive at the exact provisioned incarnation.
    #[error("node symbol membership binding is not active")]
    Membership,
    /// Running work or unread results fill the clone-shared capacity.
    #[error("node symbol owner capacity is full")]
    Capacity,
    /// Missing clock, cancellation, or unusable timeout.
    #[error(transparent)]
    Timing(#[from] RemoteRunError),
    /// Existing transport, codec, or TLS identity validation failed.
    #[error(transparent)]
    Symbol(#[from] RemoteSymbolError),
    /// The actual node region refused task admission.
    #[error(transparent)]
    Spawn(#[from] SpawnError),
    /// Checked lease or child-region admission failed.
    #[error(transparent)]
    Work(#[from] MembershipWorkError),
}

/// Storage outcome, checked membership settlement and actual owner retirement.
///
/// A returned storage receipt can coexist with a subsequent revocation or local
/// cancellation. Only `is_success()` accepts all three layers as successful.
/// V1 acknowledges the serving store's current retention, not crash durability,
/// consensus, rollback, or remote quiescence after a lost response.
#[non_exhaustive]
pub struct NativeDistributedSymbolReport<T> {
    /// Actual work result, absent if the owner never returned one.
    pub work: Option<
        Result<MembershipWorkReport<Result<T, RemoteSymbolError>>, NativeDistributedSymbolError>,
    >,
    /// Runtime retirement barrier, independently preserved after work returns.
    pub retirement: Result<(), JoinError>,
}

impl<T> fmt::Debug for NativeDistributedSymbolReport<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDistributedSymbolReport")
            .field("work", &self.work)
            .field("retirement", &self.retirement)
            .finish()
    }
}

impl<T> NativeDistributedSymbolReport<T> {
    /// Require a verified transport result, clean child close, winning lease
    /// release, and successful retirement of the node-owned supervisor task.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.retirement.is_ok()
            && self.work.as_ref().is_some_and(|work| {
                work.as_ref().is_ok_and(|work| {
                    work.is_success() && matches!(&work.task, Ok(Ok(_)))
                })
            })
    }
}

struct Slot {
    task: Mutex<Option<TaskHandle<()>>>,
    observed: AtomicBool,
    dropped: AtomicBool,
}

struct Shared {
    controls: Arc<Controls>,
    principal: Cx,
    transport: RemoteSymbolTransport,
    routes: BTreeMap<String, (NodeId, u64)>,
    limits: SymbolBatchLimits,
    config: NativeDistributedSymbolConfig,
    slots: Mutex<Vec<Arc<Slot>>>,
}

impl Shared {
    fn check_open(&self) -> Result<(), NativeDistributedSymbolError> {
        if self.controls.cause().is_some() {
            Err(NativeDistributedSymbolError::Closed)
        } else {
            Ok(())
        }
    }

    fn retained(&self) -> usize {
        let mut slots = self.slots.lock();
        let mut retired = Vec::new();
        slots.retain(|slot| {
            let finished = slot.observed.load(Ordering::Acquire)
                || (slot.dropped.load(Ordering::Acquire)
                    && slot.task.lock().as_ref().is_some_and(TaskHandle::is_finished));
            if finished {
                retired.push(Arc::clone(slot));
            }
            !finished
        });
        let count = slots.len();
        drop(slots);
        // TaskHandle drop can invoke user waker destructors.
        drop(retired);
        count
    }

    fn reserve(self: &Arc<Self>) -> Result<Reservation, NativeDistributedSymbolError> {
        self.check_open()?;
        let _ = self.retained();
        let mut slots = self.slots.lock();
        self.check_open()?;
        if slots.len() >= self.config.max_in_flight {
            return Err(NativeDistributedSymbolError::Capacity);
        }
        let slot = Arc::new(Slot {
            task: Mutex::new(None),
            observed: AtomicBool::new(false),
            dropped: AtomicBool::new(false),
        });
        slots.push(Arc::clone(&slot));
        Ok(Reservation {
            shared: Arc::clone(self),
            slot,
            phase: Phase::Reserved,
        })
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Reserved,
    Submitting,
    Submitted,
    Observed,
}

struct Reservation {
    shared: Arc<Shared>,
    slot: Arc<Slot>,
    phase: Phase,
}

// Poll/abort may call arbitrary waker code. Keep the actual task outside the
// mutex for those calls, restoring it even when a callback unwinds.
struct TaskAccess<'a> {
    slot: &'a Mutex<Option<TaskHandle<()>>>,
    task: Option<TaskHandle<()>>,
}

impl<'a> TaskAccess<'a> {
    fn new(slot: &'a Mutex<Option<TaskHandle<()>>>) -> Self {
        Self {
            slot,
            task: Some(slot.lock().take().expect("submitted symbol owner")),
        }
    }
}

impl Deref for TaskAccess<'_> {
    type Target = TaskHandle<()>;

    fn deref(&self) -> &Self::Target {
        self.task.as_ref().expect("taken symbol owner")
    }
}

impl DerefMut for TaskAccess<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.task.as_mut().expect("taken symbol owner")
    }
}

impl Drop for TaskAccess<'_> {
    fn drop(&mut self) {
        *self.slot.lock() = self.task.take();
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.slot.dropped.store(true, Ordering::Release);
        let mut panics = StopPanics::new();
        match self.phase {
            Phase::Reserved | Phase::Observed => {
                self.slot.observed.store(true, Ordering::Release);
            }
            Phase::Submitted => panics.run(|| {
                let task = TaskAccess::new(&self.slot.task);
                if !task.terminal_published() {
                    task.abort_with_reason(CancelReason::user("node symbol caller dropped"));
                }
            }),
            Phase::Submitting => {
                // Submission may have become visible before a callback panic.
                // Retain the unknown slot and seal the entire owner, never
                // misreporting an unobserved task as retired.
                self.shared.controls.stop(
                    NativeDistributedNodeStopCause::OwnerDropped, &mut panics,
                );
                panics.run(|| {
                    if let Some(gateway) = self.shared.principal.spawn_gateway_handle() {
                        let _ = gateway.enqueue_region_command(RegionCommand::Cancel {
                            region_id: self.shared.principal.region_id(),
                            reason: CancelReason::user("node symbol submission unwound"),
                        });
                    }
                });
            }
        }
    }
}

/// Cloneable bounded V1 symbol transport whose tasks belong to one native node.
///
/// Every transfer holds an exact-incarnation checked lease and runs in a real
/// child of the node region. Revocation, timeout and node close cancel and drain
/// that subtree. Dropping a borrowing operation future requests cancellation;
/// its slot remains occupied until actual task retirement. No helper task is
/// detached. Per-transport bounds are shared across all its clones.
#[derive(Clone)]
pub struct NativeDistributedSymbolTransport {
    shared: Arc<Shared>,
}

impl fmt::Debug for NativeDistributedSymbolTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDistributedSymbolTransport")
            .field("routes", &self.shared.routes.len())
            .field("retained_operations", &self.retained_operations())
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl NativeDistributedNode {
    /// Bind an explicit V1 snapshot transport to this node's owner and authority.
    ///
    /// Construction performs no I/O. The node's capability mask, exact Alive
    /// incarnation and single enforcing server SPKI pin are required. Pin-to-
    /// logical-node provisioning remains the operator's responsibility. V3
    /// retained outcomes cannot prove a restarted store still holds a snapshot,
    /// so the underlying symbol protocol continues to reject V2/V3 hellos.
    /// A separate call creates a separate bounded transport; clones share limits.
    pub fn symbol_transport(
        &self,
        hello: RemotePeerHello,
        routes: impl IntoIterator<Item = NativeDistributedSymbolRoute>,
        auth_key: Arc<AuthKey>,
        limits: SymbolBatchLimits,
        config: NativeDistributedSymbolConfig,
    ) -> Result<NativeDistributedSymbolTransport, NativeDistributedSymbolError> {
        if self.controls.cause().is_some() {
            return Err(NativeDistributedSymbolError::Closed);
        }
        let principal = self.principal.as_ref().ok_or(NativeDistributedSymbolError::Closed)?;
        if !principal.capabilities().remote {
            return Err(NativeDistributedSymbolError::MissingRemote);
        }
        let _ = prepare_owned_timing(principal, &config.work)?;
        if config.max_routes == 0 {
            return Err(NativeDistributedSymbolError::Configuration);
        }
        let mut bindings = BTreeMap::new();
        let mut clients = Vec::new();
        for route in routes {
            if bindings.len() == config.max_routes
                || route.replica_id.is_empty()
                || route.replica_id.len() > 255
                || route.node.as_str().is_empty()
                || route.node.as_str().len() > 255
                || bindings.contains_key(&route.replica_id)
            {
                return Err(NativeDistributedSymbolError::Configuration);
            }
            if !self.controls.membership.permits_native_route(&route.node, route.incarnation) {
                return Err(NativeDistributedSymbolError::Membership);
            }
            // Reuse the canonical explicit identity-binding validator without
            // creating a V3 runtime or changing the symbol service's protocol.
            NativeRemoteRoute::new(route.node.clone(), hello.clone(), route.client.clone())
                .with_membership(self.controls.membership.clone(), route.incarnation)
                .map_err(|error| {
                    NativeDistributedSymbolError::Symbol(RemoteSymbolError::Client(error))
                })?;
            let label = route.replica_id.into_boxed_str().into_string();
            bindings.insert(label.clone(), (NodeId::new(route.node.as_str()), route.incarnation));
            clients.push((label, route.client));
        }
        let transport = if let Some(chunk) = config.max_chunk_bytes {
            RemoteSymbolTransport::new_chunked_bounded(
                principal.clone(), hello, clients, auth_key, limits, config.max_in_flight, chunk,
            )?
        } else {
            RemoteSymbolTransport::new_bounded(
                principal.clone(), hello, clients, auth_key, limits, config.max_in_flight,
            )?
        };
        Ok(NativeDistributedSymbolTransport {
            shared: Arc::new(Shared {
                controls: Arc::clone(&self.controls),
                principal: principal.clone(),
                transport,
                routes: bindings,
                limits,
                config,
                slots: Mutex::new(Vec::new()),
            }),
        })
    }
}

impl NativeDistributedSymbolTransport {
    /// Whether node close or component failure permanently sealed admission.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.shared.controls.cause().is_some()
    }

    /// Running and completed-but-unobserved work, shared across all clones.
    /// Dropped calls retain credit until their actual runtime retirement.
    /// A submission callback panic without a published task handle seals the
    /// node and conservatively retains that slot until this adapter is dropped.
    #[must_use]
    pub fn retained_operations(&self) -> usize {
        self.shared.retained()
    }

    fn peer(&self, replica: &str) -> Result<(NodeId, u64), NativeDistributedSymbolError> {
        self.shared.check_open()?;
        let peer = self.shared.routes.get(replica)
            .ok_or(NativeDistributedSymbolError::UnknownReplica)?;
        if !self.shared.controls.membership.permits_native_route(&peer.0, peer.1) {
            return Err(NativeDistributedSymbolError::Membership);
        }
        Ok(peer.clone())
    }

    async fn run<T, F, Fut>(
        &self,
        mut reservation: Reservation,
        peer: (NodeId, u64),
        timing: (TimerDriverHandle, Time),
        factory: F,
    ) -> Result<NativeDistributedSymbolReport<T>, NativeDistributedSymbolError>
    where
        T: Send + 'static,
        F: FnOnce(RemoteSymbolTransport) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, RemoteSymbolError>> + Send + 'static,
    {
        let shared = Arc::clone(&self.shared);
        let outcome = Arc::new(Mutex::new(None));
        let retained = Arc::clone(&outcome);
        reservation.phase = Phase::Submitting;
        let spawned = self.shared.principal.spawn(move |owner| async move {
            let (clock, deadline) = timing;
            let now = clock.now();
            let result = if let Err(error) = shared.check_open() {
                Err(error)
            } else if now >= deadline {
                Err(NativeDistributedSymbolError::Timing(RemoteRunError::Timeout))
            } else {
                let transport = shared.transport.clone();
                shared.controls.membership.run_scoped(
                    &owner,
                    &peer.0,
                    peer.1,
                    Duration::from_nanos(deadline.as_nanos().saturating_sub(now.as_nanos())),
                    shared.config.work.child.clone(),
                    move |body| async move {
                        let result = factory(transport.for_owner(body.clone())).await;
                        let _ = body.checkpoint();
                        result
                    },
                )
                .await
                .map_err(NativeDistributedSymbolError::Work)
            };
            // Preserve a useful receipt independently of late cancellation.
            *retained.lock() = Some(result);
            let _ = owner.checkpoint();
        });
        match spawned {
            Ok(task) => {
                *reservation.slot.task.lock() = Some(task);
                reservation.phase = Phase::Submitted;
            }
            Err(error) => {
                reservation.phase = Phase::Reserved;
                return Err(error.into());
            }
        }
        let retirement = poll_fn(|task| {
            TaskAccess::new(&reservation.slot.task).poll_join(task)
        }).await;
        let work = outcome.lock().take();
        reservation.phase = Phase::Observed;
        Ok(NativeDistributedSymbolReport { work, retirement })
    }

    /// Store a bounded authenticated batch and retain the complete ownership receipt.
    /// Successful local cancellation cannot undo remote retention already performed.
    pub async fn store_symbols(
        &self,
        replica: &str,
        symbols: Vec<AuthenticatedSymbol>,
    ) -> Result<NativeDistributedSymbolReport<ReplicaAck>, NativeDistributedSymbolError> {
        let peer = self.peer(replica)?;
        let timing = prepare_owned_timing(&self.shared.principal, &self.shared.config.work)?;
        let reservation = self.shared.reserve()?;
        let symbols = compact_symbols(symbols, self.shared.limits)?;
        let replica = replica.to_owned();
        self.run(reservation, peer, timing, move |transport| async move {
            transport.send(&replica, symbols).await
        })
        .await
    }

    /// Fetch exactly one authenticated origin/object/digest for snapshot recovery.
    /// Every returned symbol is reverified by the existing native batch decoder.
    pub async fn fetch_symbols(
        &self,
        replica: &str,
        key: SymbolBatchKey,
    ) -> Result<NativeDistributedSymbolReport<Vec<AuthenticatedSymbol>>, NativeDistributedSymbolError> {
        let peer = self.peer(replica)?;
        let timing = prepare_owned_timing(&self.shared.principal, &self.shared.config.work)?;
        let reservation = self.shared.reserve()?;
        let replica = replica.to_owned();
        self.run(reservation, peer, timing, move |transport| async move {
            transport.fetch_symbols(&replica, key).await
        })
        .await
    }
}

// Bound allocations retained in a runtime task, including caller-provided spare
// capacity. Codec/authentication checks still run before network dispatch.
fn compact_symbols(
    symbols: Vec<AuthenticatedSymbol>,
    limits: SymbolBatchLimits,
) -> Result<Vec<AuthenticatedSymbol>, NativeDistributedSymbolError> {
    if symbols.is_empty() || symbols.len() > limits.max_symbols {
        return Err(NativeDistributedSymbolError::Configuration);
    }
    let mut total = 0usize;
    for symbol in &symbols {
        let size = symbol.symbol().data().len();
        total = total.checked_add(size).ok_or(NativeDistributedSymbolError::Configuration)?;
        if total > limits.max_payload_bytes {
            return Err(NativeDistributedSymbolError::Configuration);
        }
    }
    let storage = symbols.len().checked_mul(std::mem::size_of::<AuthenticatedSymbol>())
        .and_then(|overhead| overhead.checked_add(total))
        .ok_or(NativeDistributedSymbolError::Configuration)?;
    if storage > limits.max_decoded_bytes {
        return Err(NativeDistributedSymbolError::Configuration);
    }
    let mut bounded = Vec::new();
    bounded.try_reserve_exact(symbols.len())
        .map_err(|_| NativeDistributedSymbolError::Configuration)?;
    for symbol in symbols {
        let tag = *symbol.tag();
        let symbol = symbol.into_symbol();
        let id = symbol.id();
        let kind = symbol.kind();
        let payload = symbol.into_data().into_boxed_slice().into_vec();
        bounded.push(AuthenticatedSymbol::from_parts(Symbol::new(id, payload, kind), tag));
    }
    Ok(bounded)
}

impl DistributorTransport for NativeDistributedSymbolTransport {
    async fn send_symbols(
        &self,
        replica_id: &str,
        symbols: Vec<AuthenticatedSymbol>,
    ) -> Result<ReplicaAck, ReplicaFailure> {
        let failure = |error_kind| ReplicaFailure {
            replica_id: replica_id.to_owned(),
            error: "node-owned symbol transfer did not complete with valid membership and storage receipts".into(),
            error_kind,
        };
        let report = self.store_symbols(replica_id, symbols).await
            .map_err(|error| failure(admission_error_kind(&error)))?;
        let error_kind = report_error_kind(&report);
        if report.is_success() {
            if let Some(Ok(work)) = report.work {
                if let Ok(Ok(receipt)) = work.task {
                    return Ok(receipt);
                }
            }
        }
        Err(failure(error_kind))
    }
}

fn admission_error_kind(error: &NativeDistributedSymbolError) -> ErrorKind {
    match error {
        NativeDistributedSymbolError::Configuration => ErrorKind::ConfigError,
        NativeDistributedSymbolError::UnknownReplica => ErrorKind::NodeUnavailable,
        NativeDistributedSymbolError::Closed
        | NativeDistributedSymbolError::Timing(RemoteRunError::Cancelled) => ErrorKind::Cancelled,
        NativeDistributedSymbolError::Timing(RemoteRunError::Timeout) => ErrorKind::DeadlineExceeded,
        NativeDistributedSymbolError::Symbol(error) => symbol_error_kind(error),
        _ => ErrorKind::AdmissionDenied,
    }
}

fn symbol_error_kind(error: &RemoteSymbolError) -> ErrorKind {
    match error {
        RemoteSymbolError::Configuration => ErrorKind::ConfigError,
        RemoteSymbolError::UnknownReplica => ErrorKind::NodeUnavailable,
        RemoteSymbolError::Cancelled => ErrorKind::Cancelled,
        RemoteSymbolError::Deadline => ErrorKind::DeadlineExceeded,
        RemoteSymbolError::Batch(_) => ErrorKind::ProtocolError,
        RemoteSymbolError::Client(_) => ErrorKind::ConnectionLost,
        RemoteSymbolError::Refused | RemoteSymbolError::Admission => ErrorKind::AdmissionDenied,
    }
}

fn report_error_kind<T>(report: &NativeDistributedSymbolReport<T>) -> ErrorKind {
    match &report.retirement {
        Err(JoinError::Cancelled(_)) => return ErrorKind::Cancelled,
        Err(_) => return ErrorKind::Internal,
        Ok(()) => {}
    }
    match &report.work {
        Some(Err(error)) => admission_error_kind(error),
        Some(Ok(work)) => match &work.trigger {
            MembershipWorkTrigger::ParentCancelled(_) => ErrorKind::Cancelled,
            MembershipWorkTrigger::LeaseEnded(OwnedLeaseStatus::Expired) => ErrorKind::DeadlineExceeded,
            MembershipWorkTrigger::LeaseEnded(_) => ErrorKind::AdmissionDenied,
            MembershipWorkTrigger::ControlFailed(_) => ErrorKind::Internal,
            MembershipWorkTrigger::TaskFinished => match &work.task {
                Ok(Err(error)) => symbol_error_kind(error),
                _ => ErrorKind::Internal,
            },
        },
        None => ErrorKind::Internal,
    }
}
