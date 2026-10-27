//! Caller-owned, bounded mTLS propagation for global names.
//!
//! Full-owner snapshots and exact-owner lookups use the existing authenticated
//! computation service. Neither successful propagation nor a direct lookup
//! establishes cluster-wide uniqueness or consensus. Run the registry lifetime
//! driver and this transport driver as separately owned tasks.

use super::service::GLOBAL_NAME_SERVICE_COMPUTATION;
use super::wire::{self, MAX_GLOBAL_NAME_MESSAGE_BYTES};
use super::{GlobalNameError, GlobalNameRegistry, GlobalNameTarget};
use crate::cx::Cx;
use crate::remote::{
    ComputationName, IdempotencyKey, NodeId, RemoteComputationClient,
    RemoteComputationClientError, RemoteInput, RemotePeerHello, RemoteProtocolVersion,
    RemoteServiceWireOutcome, RemoteServiceWireRequest, RemoteServiceWireResponse,
    RemoteTaskId, SpawnRequest,
};
use crate::sync::Semaphore;
use crate::sync::semaphore::SemaphorePermit;
use crate::time::Sleep;
use crate::types::Time;
use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

const MAX_NATIVE_PEERS: usize = 256;
const MAX_NATIVE_IN_FLIGHT: usize = 256;
const MAX_NATIVE_FRAME_BYTES: usize = 8 * MAX_GLOBAL_NAME_MESSAGE_BYTES;

/// Validated finite native propagation policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeGlobalNameConfig {
    max_in_flight: usize,
    refresh_interval: Duration,
}

impl NativeGlobalNameConfig {
    /// Bound simultaneous exchanges across clones and delay between full rounds.
    ///
    /// There is no admission queue. Capacity must be in 1..=256; the interval
    /// must be nonzero and representable by the runtime's nanosecond clock.
    pub fn new(
        max_in_flight: usize,
        refresh_interval: Duration,
    ) -> Result<Self, NativeGlobalNameError> {
        if max_in_flight == 0
            || max_in_flight > MAX_NATIVE_IN_FLIGHT
            || refresh_interval.is_zero()
            || refresh_interval.as_nanos() > u128::from(u64::MAX)
        {
            return Err(NativeGlobalNameError::Configuration);
        }
        Ok(Self { max_in_flight, refresh_interval })
    }

    /// Maximum number of live native exchanges across clones.
    #[must_use]
    pub const fn max_in_flight(self) -> usize {
        self.max_in_flight
    }

    /// Delay measured from the end of one round to the next.
    #[must_use]
    pub const fn refresh_interval(self) -> Duration {
        self.refresh_interval
    }
}

/// Local refusal or authenticated remote exchange failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeGlobalNameError {
    /// Route, protocol, frame, timer, or capacity policy is invalid.
    #[error("invalid native global-name configuration")]
    Configuration,
    /// The requested owner has no explicitly configured route.
    #[error("global-name owner route is not configured")]
    UnknownPeer,
    /// Shared exchange capacity was unavailable; no request was dispatched.
    #[error("global-name transport admission limit reached")]
    Admission,
    /// A full-snapshot round is already active on a clone.
    #[error("global-name propagation round is already running")]
    RoundRunning,
    /// A periodic driver is already active on a clone.
    #[error("global-name propagation driver is already running")]
    DriverRunning,
    /// The caller's context observed cancellation.
    #[error("global-name transport owner cancelled")]
    Cancelled,
    /// The caller's deadline elapsed.
    #[error("global-name transport owner deadline elapsed")]
    Deadline,
    /// The registry refused a snapshot, reply, or local lifecycle state.
    #[error(transparent)]
    Registry(#[from] GlobalNameError),
    /// The configured client failed; remote application is not rolled back.
    #[error("global-name native exchange failed")]
    Client(#[source] RemoteComputationClientError),
    /// The service returned a non-success or oversized outcome.
    #[error("global-name service refused the request")]
    Refused,
}

/// One configured peer's exact-snapshot acknowledgement or failure.
#[derive(Debug)]
pub struct GlobalNamePeerResult {
    /// Explicit destination.
    pub peer: NodeId,
    /// Success means this peer acknowledged precisely the snapshot sent.
    pub result: Result<(), NativeGlobalNameError>,
}

/// Bounded outcomes for one completed propagation round.
#[derive(Debug)]
pub struct GlobalNameRoundReport {
    /// One outcome per configured peer, in deterministic node order.
    pub peers: Vec<GlobalNamePeerResult>,
}

impl GlobalNameRoundReport {
    /// Count of verified acknowledgements.
    #[must_use]
    pub fn acknowledged(&self) -> usize {
        self.peers.iter().filter(|peer| peer.result.is_ok()).count()
    }

    /// Whether all configured peers acknowledged, including an empty set.
    #[must_use]
    pub fn all_acknowledged(&self) -> bool {
        self.peers.iter().all(|peer| peer.result.is_ok())
    }
}

/// Reply obtained directly from one specified authenticated owner.
///
/// This is authoritative for that owner's catalog at its returned sequence.
/// Another owner may concurrently claim the same name. It is neither a
/// linearizable cluster lookup nor proof that the actor remains alive.
#[derive(Debug)]
pub struct GlobalNameOwnerLookup {
    /// Exact owner selected by the caller.
    pub owner: NodeId,
    /// Exact expected incarnation, verified in the reply.
    pub incarnation: u64,
    /// Owner catalog sequence at lookup.
    pub sequence: u64,
    /// Registered target or the owner's authoritative absence.
    pub target: Option<GlobalNameTarget>,
    /// Local runtime time when the reply was verified.
    pub observed_at: Time,
}

/// Structured reason a propagation driver stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GlobalNamePropagationStop {
    /// Caller cancelled; all local exchange futures have been retired.
    Cancelled,
    /// The caller's deadline elapsed.
    Deadline,
    /// The registry sealed admission and closed.
    RegistryClosed,
}

/// Bounded terminal observations; counters saturate rather than wrap.
#[derive(Debug)]
pub struct GlobalNamePropagationReport {
    /// Fully completed rounds, including rounds with peer failures.
    pub completed_rounds: u64,
    /// Rounds refused before network exchange due to transient local state.
    pub skipped_rounds: u64,
    /// Verified acknowledgements in completed rounds.
    pub acknowledgements: u64,
    /// Failed exchanges in completed rounds.
    pub failed_exchanges: u64,
    /// Most recent completed round only.
    pub last_round: Option<GlobalNameRoundReport>,
    /// Most recent transient pre-round refusal; cleared after a complete round.
    pub last_round_error: Option<NativeGlobalNameError>,
    /// Structured stop cause.
    pub stop: GlobalNamePropagationStop,
}

/// Immutable authenticated routes and clone-shared exchange admission.
///
/// Routes must exactly match the registry peer allowlist, with at most 256
/// entries. The caller binds each route's logical node to its client's TLS
/// trust, server name, client certificate, and enforcing pins as appropriate.
/// The remote service must grant the versioned name computation to the
/// caller's certificate-bound identity. No discovery or membership authority
/// is derived from these application messages or from transport failures.
///
/// V1 retains the existing client's finite pre-delivery-only retry policy.
/// Ambiguous delivery remains a failure. Later rounds publish the current
/// full snapshot; registry incarnation/sequence checks reject stale or
/// conflicting versions and make an identical version idempotent.
///
/// Only one full round and one periodic driver may run across clones. A round
/// keeps one bounded snapshot and polls finite batches of owned futures.
/// Direct lookups share the same no-wait exchange semaphore. Credit remains
/// held until the associated socket future is destroyed, including on drop.
#[derive(Clone)]
pub struct NativeGlobalNameTransport {
    registry: GlobalNameRegistry,
    hello: RemotePeerHello,
    routes: Arc<BTreeMap<NodeId, RemoteComputationClient>>,
    config: NativeGlobalNameConfig,
    exchanges: Arc<Semaphore>,
    round_active: Arc<AtomicBool>,
    driver_active: Arc<AtomicBool>,
}

impl fmt::Debug for NativeGlobalNameTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeGlobalNameTransport")
            .field("local_node", self.registry.local_node())
            .field("peers", &self.routes.len())
            .field("config", &self.config)
            .field("in_flight", &self.in_flight())
            .finish_non_exhaustive()
    }
}

impl NativeGlobalNameTransport {
    /// Validate routes without performing I/O or starting tasks.
    ///
    /// Hello must identify this registry and use V1. Client frame limits must
    /// be finite and no larger than 8 MiB. Smaller configured limits remain
    /// enforced and may refuse a large valid snapshot before delivery.
    pub fn new(
        registry: GlobalNameRegistry,
        hello: RemotePeerHello,
        routes: impl IntoIterator<Item = (NodeId, RemoteComputationClient)>,
        config: NativeGlobalNameConfig,
    ) -> Result<Self, NativeGlobalNameError> {
        if hello.peer_node() != registry.local_node()
            || hello.protocol_version() != RemoteProtocolVersion::V1
        {
            return Err(NativeGlobalNameError::Configuration);
        }
        let mut configured = BTreeMap::new();
        for (peer, client) in routes {
            let policy = client.config();
            if configured.len() >= MAX_NATIVE_PEERS
                || configured.contains_key(&peer)
                || &peer == registry.local_node()
                || policy.attempt_timeout().is_zero()
                || policy.connect_timeout().is_zero()
                || policy.max_attempts() == 0
                || policy.wire_limits().max_frame_bytes() == 0
                || policy.wire_limits().max_frame_bytes() > MAX_NATIVE_FRAME_BYTES
            {
                return Err(NativeGlobalNameError::Configuration);
            }
            configured.insert(peer, client);
        }
        let expected: Vec<_> = registry.peers().collect();
        if expected.len() != configured.len()
            || expected.iter().any(|peer| !configured.contains_key(*peer))
        {
            return Err(NativeGlobalNameError::Configuration);
        }
        Ok(Self {
            registry,
            hello,
            routes: Arc::new(configured),
            config,
            exchanges: Arc::new(Semaphore::new(config.max_in_flight)),
            round_active: Arc::new(AtomicBool::new(false)),
            driver_active: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Occupied exchange credits across all clones.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.config.max_in_flight.saturating_sub(self.exchanges.available_permits())
    }

    /// Finite immutable transport policy.
    #[must_use]
    pub const fn config(&self) -> NativeGlobalNameConfig {
        self.config
    }

    /// Publish one captured full-owner snapshot to all configured peers.
    ///
    /// Complete-round peer failures are retained without being interpreted as
    /// membership death. Caller cancellation or deadline drops all pending
    /// exchanges and returns an error. Some peers may already have applied the
    /// snapshot; interruption does not undo their updates.
    pub async fn propagate_once(
        &self,
        cx: &Cx,
    ) -> Result<GlobalNameRoundReport, NativeGlobalNameError> {
        check_owner(cx)?;
        let _round = ActiveGuard::acquire(&self.round_active)
            .ok_or(NativeGlobalNameError::RoundRunning)?;
        let snapshot = self.registry.snapshot(cx)?;
        if snapshot.len() > MAX_GLOBAL_NAME_MESSAGE_BYTES {
            return Err(NativeGlobalNameError::Refused);
        }
        let peers: Vec<_> = self.routes.keys().collect();
        let mut report = GlobalNameRoundReport { peers: Vec::with_capacity(peers.len()) };
        for batch in peers.chunks(self.config.max_in_flight) {
            let mut calls = batch.iter().map(|peer| {
                Some(Box::pin(self.send_snapshot(cx, peer, &snapshot)))
            }).collect::<Vec<_>>();
            let mut results = (0..calls.len()).map(|_| None).collect::<Vec<_>>();
            let joined = poll_fn(|task| {
                for (index, call) in calls.iter_mut().enumerate() {
                    if let Some(future) = call.as_mut() {
                        if let Poll::Ready(result) = future.as_mut().poll(task) {
                            *call = None;
                            results[index] = Some(result);
                        }
                    }
                }
                if calls.iter().all(Option::is_none) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            });
            let outcome = with_owner(cx, joined).await;
            // Retire every socket before releasing the enclosing round guard.
            drop(calls);
            outcome?;
            for (peer, result) in batch.iter().zip(results) {
                report.peers.push(GlobalNamePeerResult {
                    peer: (*peer).clone(),
                    result: result.ok_or(NativeGlobalNameError::Refused)?,
                });
            }
        }
        check_owner(cx)?;
        Ok(report)
    }

    /// Query exactly one owner and incarnation through its configured client.
    ///
    /// A cached value or different owner is never substituted after failure.
    /// The answer does not update replicated catalogs or confer authority.
    pub async fn lookup_owner(
        &self,
        cx: &Cx,
        owner: &NodeId,
        incarnation: u64,
        name: &str,
    ) -> Result<GlobalNameOwnerLookup, NativeGlobalNameError> {
        check_owner(cx)?;
        if !self.routes.contains_key(owner) {
            return Err(NativeGlobalNameError::UnknownPeer);
        }
        let permit = self.exchanges.try_acquire_checked(cx, 1)
            .map_err(|_| NativeGlobalNameError::Admission)?;
        let operation = async {
            let request = wire::lookup_request(name, incarnation)?;
            let reply = self.call(cx, owner, request).await?;
            let (sequence, target) = wire::decode_lookup_reply(owner, incarnation, name, &reply)?;
            Ok(GlobalNameOwnerLookup {
                owner: owner.clone(),
                incarnation,
                sequence,
                target,
                observed_at: cx.now(),
            })
        };
        with_owner(cx, AdmittedExchange { future: Box::pin(operation), _permit: permit }).await?
    }

    async fn send_snapshot(
        &self,
        cx: &Cx,
        peer: &NodeId,
        snapshot: &[u8],
    ) -> Result<(), NativeGlobalNameError> {
        check_owner(cx)?;
        let permit = self.exchanges.try_acquire_checked(cx, 1)
            .map_err(|_| NativeGlobalNameError::Admission)?;
        let operation = async {
            let reply = self.call(cx, peer, snapshot.to_vec()).await?;
            wire::verify_snapshot_receipt(&reply, snapshot)?;
            Ok(())
        };
        with_owner(cx, AdmittedExchange { future: Box::pin(operation), _permit: permit }).await?
    }

    async fn call(
        &self,
        cx: &Cx,
        peer: &NodeId,
        input: Vec<u8>,
    ) -> Result<Vec<u8>, NativeGlobalNameError> {
        check_owner(cx)?;
        if input.len() > MAX_GLOBAL_NAME_MESSAGE_BYTES {
            return Err(NativeGlobalNameError::Refused);
        }
        let client = self.routes.get(peer).ok_or(NativeGlobalNameError::UnknownPeer)?;
        let task = RemoteTaskId::next();
        let request = SpawnRequest {
            remote_task_id: task,
            computation: ComputationName::new(GLOBAL_NAME_SERVICE_COMPUTATION),
            input: RemoteInput::new(input),
            lease: client.config().attempt_timeout(),
            idempotency_key: IdempotencyKey::from_raw(u128::from(task.raw())),
            budget: None,
            origin_node: self.hello.peer_node().clone(),
            origin_region: cx.region_id(),
            origin_task: cx.task_id(),
        };
        let wire = RemoteServiceWireRequest::from_spawn_request(self.hello.clone(), &request)
            .map_err(|_| NativeGlobalNameError::Configuration)?;
        drop(request);
        match client.call(cx, &wire).await.map_err(NativeGlobalNameError::Client)? {
            RemoteServiceWireResponse::Outcome {
                outcome: RemoteServiceWireOutcome::Success(bytes), ..
            } if bytes.len() <= MAX_GLOBAL_NAME_MESSAGE_BYTES => Ok(bytes),
            _ => Err(NativeGlobalNameError::Refused),
        }
    }

    /// Propagate immediately and periodically until a structured stop.
    ///
    /// Poll in an owned task. Drop closes active local sockets and releases
    /// guards; it cannot undo remote application. Cancellation has no final
    /// network flush. Core actor retirement/receipts remain the registry
    /// driver's responsibility. Failed peers and pending local retirement
    /// are retried at the next bounded interval without changing membership.
    pub async fn run(
        &self,
        cx: &Cx,
    ) -> Result<GlobalNamePropagationReport, NativeGlobalNameError> {
        let _driver = ActiveGuard::acquire(&self.driver_active)
            .ok_or(NativeGlobalNameError::DriverRunning)?;
        let mut report = GlobalNamePropagationReport {
            completed_rounds: 0,
            skipped_rounds: 0,
            acknowledgements: 0,
            failed_exchanges: 0,
            last_round: None,
            last_round_error: None,
            stop: GlobalNamePropagationStop::Cancelled,
        };
        loop {
            match self.propagate_once(cx).await {
                Ok(round) => {
                    let acknowledged = round.acknowledged();
                    report.completed_rounds = report.completed_rounds.saturating_add(1);
                    report.acknowledgements = report.acknowledgements
                        .saturating_add(acknowledged as u64);
                    report.failed_exchanges = report.failed_exchanges
                        .saturating_add((round.peers.len() - acknowledged) as u64);
                    report.last_round = Some(round);
                    report.last_round_error = None;
                }
                Err(NativeGlobalNameError::Cancelled) => return Ok(report),
                Err(NativeGlobalNameError::Deadline) => {
                    report.stop = GlobalNamePropagationStop::Deadline;
                    return Ok(report);
                }
                Err(NativeGlobalNameError::Registry(GlobalNameError::Closed)) => {
                    report.stop = GlobalNamePropagationStop::RegistryClosed;
                    return Ok(report);
                }
                Err(error @ NativeGlobalNameError::RoundRunning)
                | Err(error @ NativeGlobalNameError::Registry(GlobalNameError::PendingRetirement)) => {
                    report.skipped_rounds = report.skipped_rounds.saturating_add(1);
                    report.last_round_error = Some(error);
                }
                Err(error) => return Err(error),
            }
            let clock = cx.timer_driver().ok_or(NativeGlobalNameError::Configuration)?;
            let nanos = u64::try_from(self.config.refresh_interval.as_nanos())
                .map_err(|_| NativeGlobalNameError::Configuration)?;
            let deadline = Time::from_nanos(cx.now().as_nanos().checked_add(nanos)
                .ok_or(NativeGlobalNameError::Deadline)?);
            let mut sleep = std::pin::pin!(Sleep::with_timer_driver(deadline, clock));
            let delay = poll_fn(|task| sleep.as_mut().poll_deadline(task));
            match with_owner(cx, delay).await {
                Ok(()) => {}
                Err(NativeGlobalNameError::Cancelled) => return Ok(report),
                Err(NativeGlobalNameError::Deadline) => {
                    report.stop = GlobalNamePropagationStop::Deadline;
                    return Ok(report);
                }
                Err(error) => return Err(error),
            }
        }
    }
}

// Declaration order destroys I/O before releasing its runtime-visible credit,
// including when an outer future is abandoned or unwinds.
struct AdmittedExchange<'a, F> {
    future: Pin<Box<F>>,
    _permit: SemaphorePermit<'a>,
}

impl<F: Future> Future for AdmittedExchange<'_, F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().future.as_mut().poll(task)
    }
}

struct ActiveGuard<'a>(&'a AtomicBool);

impl<'a> ActiveGuard<'a> {
    fn acquire(active: &'a AtomicBool) -> Option<Self> {
        active.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok().map(|_| Self(active))
    }
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn owner_cancel_error(cx: &Cx) -> NativeGlobalNameError {
    match cx.cancel_reason().map(|reason| reason.kind) {
        Some(crate::types::CancelKind::Deadline | crate::types::CancelKind::Timeout) => {
            NativeGlobalNameError::Deadline
        }
        _ => NativeGlobalNameError::Cancelled,
    }
}

fn check_owner(cx: &Cx) -> Result<(), NativeGlobalNameError> {
    cx.checkpoint().map_err(|_| owner_cancel_error(cx))?;
    if !cx.capabilities().io || cx.io_driver_handle().is_none() || cx.timer_driver().is_none() {
        return Err(NativeGlobalNameError::Configuration);
    }
    if cx.budget().deadline.is_some_and(|deadline| cx.now() >= deadline) {
        return Err(NativeGlobalNameError::Deadline);
    }
    Ok(())
}

async fn with_owner<F: Future>(
    cx: &Cx,
    operation: F,
) -> Result<F::Output, NativeGlobalNameError> {
    check_owner(cx)?;
    let timer = cx.budget().deadline.map(|deadline| {
        cx.timer_driver().map(|clock| Sleep::with_timer_driver(deadline, clock))
            .ok_or(NativeGlobalNameError::Configuration)
    }).transpose()?;
    let mut deadline = std::pin::pin!(timer);
    let mut cancelled = std::pin::pin!(cx.cancelled());
    let mut operation = std::pin::pin!(cx.with_ambient(operation));
    poll_fn(|task| {
        if cancelled.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() {
            return Poll::Ready(Err(owner_cancel_error(cx)));
        }
        if deadline.as_mut().as_pin_mut()
            .is_some_and(|timer| timer.poll_deadline(task).is_ready())
        {
            // Preserve the typed terminal result if the runtime has also
            // delivered this deadline as task cancellation.
            let _ = cx.checkpoint();
            return Poll::Ready(Err(NativeGlobalNameError::Deadline));
        }
        match operation.as_mut().poll(task) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(value) => match check_owner(cx) {
                Ok(()) => Poll::Ready(Ok(value)),
                Err(error) => Poll::Ready(Err(error)),
            },
        }
    }).await
}
