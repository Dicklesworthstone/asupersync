//! Shared-port routing for retained, mutually authenticated resume sessions.
//!
//! Every connection authenticates before its certificate/nonce key is looked
//! up. Only one worker owns a session at a time, including uncollected joins.
//! Reconnects reuse the original sink, partial epoch, and application receipt.
//! A factory runs once per new key, never on reconnect or after a failed spawn.
//!
//! The service reserves its resident-session budget before binding. Connection,
//! resident-session, per-client, and lifetime key limits are independent. Retire
//! idle sessions explicitly to release their sinks; their keys remain tombstoned
//! until service shutdown, so a late reconnect cannot recreate committed effects.
//! There is no automatic eviction, process-crash recovery, or hidden retry.

#[cfg(test)]
use super::Credit;
use super::{
    RESUMABLE_LIVE_ALPN, ResumeError, ResumeReport,
    decode_offer, peer_certificate, validate_attempts,
};
use super::super::super::{
    Cancellation, LiveStreamError, LiveStreamPrefix, LiveStreamReceipt,
    LiveStreamReceiver, Permit, Wire, authorize, bounded, expect,
};
use super::super::super::super::NativeClientCertificateId;
use crate::cx::{Cx, Scope};
use crate::net::atp::protocol::frames::FrameType;
use crate::net::{TcpListener, TcpStream};
use crate::runtime::{JoinError, SpawnError, TaskHandle};
use crate::tls::{TlsAcceptor, TlsStream};
use crate::types::{CancelReason, Policy};
use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

#[path = "restoration.rs"]
mod restoration;
pub use restoration::ResumeSessionInit;
use restoration::ServiceReceiver;

/// Exact client identity plus stream continuity identifier. A nonce is not authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResumeSessionKey {
    /// SHA-256 of the full WebPKI-verified client certificate.
    pub client: NativeClientCertificateId,
    /// Original sender nonce, never interpreted as a path or permission grant.
    pub nonce: [u8; 32],
}

/// Resource policy for a shared reconnect endpoint.
#[derive(Debug, Clone, Copy)]
pub struct ResumeServiceConfig {
    /// Bound on simultaneous handshakes, transfers, and uncollected worker results.
    pub max_connections: usize,
    /// Retained sinks, including idle and completed sessions. Reserved from SDK admission.
    pub max_sessions: usize,
    /// Resident sessions admitted for any one authenticated client certificate.
    pub max_sessions_per_client: usize,
    /// Lifetime distinct keys, including retired/failed tombstones; at most 65,536.
    pub max_session_keys: usize,
    /// Authenticated routed attempts per session, including protocol failures.
    /// Invalid TLS/hellos cannot charge a session they have not identified.
    pub max_attempts_per_session: u32,
}

impl ResumeServiceConfig {
    fn validate(self, capacity: usize) -> Result<(), LiveStreamError> {
        validate_attempts(self.max_attempts_per_session)?;
        if self.max_connections == 0 || self.max_connections > self.max_sessions
            || self.max_sessions == 0 || self.max_sessions > capacity
            || self.max_sessions > 1024 || self.max_sessions_per_client == 0
            || self.max_sessions_per_client > self.max_sessions
            || self.max_session_keys < self.max_sessions || self.max_session_keys > 65_536
        {
            return Err(LiveStreamError::Configuration("invalid shared resume limits"));
        }
        Ok(())
    }
}

/// Metadata retained when an idle sink is retired; no source or sink bytes escape.
#[derive(Debug, Clone)]
pub struct ResumeSessionSnapshot {
    /// Last receiver-flushed prefix, not necessarily observed by the sender.
    pub prefix: Option<LiveStreamPrefix>,
    /// Application commit retained independently of Proof transmission.
    pub completed: Option<LiveStreamReceipt>,
    /// Admitted, authenticated attempts for this key.
    pub attempts: u32,
    /// Successful sink-write bytes, including an incomplete epoch.
    pub sink_written_bytes: u64,
    /// Whether a local sink failure prevents continuation.
    pub failed: bool,
}

/// Registry state. Active includes a worker whose join has not yet been collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeSessionStatus {
    /// A worker exclusively owns initialization or continuation.
    Active,
    /// Retained and available for another authenticated connection.
    Idle,
    /// Sink retired or lost to a failed factory/spawn/join; key cannot be recreated.
    Retired,
}

/// Refusal of one accepted connection, without terminating unrelated sessions.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResumeServiceRejection {
    /// TLS, ALPN, or bounded initial hello validation failed.
    #[error(transparent)]
    Connection(#[from] ResumeError),
    /// Another connection still owns the exact same session.
    #[error("resume session is already active")]
    Busy,
    /// This key is a retained tombstone, never a new-session request.
    #[error("resume session has been retired")]
    Retired,
    /// Resident, per-client, or lifetime key admission was refused.
    #[error("shared resume {0} capacity exhausted")]
    Capacity(&'static str),
    /// No more authenticated attempts are allowed for this session.
    #[error("resume session attempt budget exhausted")]
    AttemptsExhausted,
    /// Factory failed or was interrupted; its key is tombstoned, not retried.
    #[error("resume sink creation failed: {0}")]
    Factory(LiveStreamError),
    /// Runtime refused the continuation worker; the key is tombstoned.
    #[error("resume worker admission failed: {0:?}")]
    Spawn(SpawnError),
    /// Admission closed before a handshake could become a new transfer.
    #[error("shared resume service is stopping")]
    Stopping,
}

/// An actual child result, not an indication that a socket was merely accepted.
#[derive(Debug)]
pub enum ResumeServiceOutcome {
    /// A routed transfer returned its complete continuation/commit report.
    Transfer(ResumeReport),
    /// This connection was refused; other admitted workers are retained.
    Rejected(ResumeServiceRejection),
    /// Canonical runtime cancellation or panic, without a fabricated domain result.
    JoinFailed(JoinError),
}

/// One terminal connection result. The session may remain idle for reconnection.
#[derive(Debug)]
#[must_use = "inspect transfer, rejection, and runtime outcomes separately"]
pub struct ResumeServiceCompletion {
    /// Monotonic local connection number; never reused within this service.
    pub connection: u64,
    /// Actual TCP peer address, diagnostic only.
    pub address: SocketAddr,
    /// Present only after authenticated hello routing.
    pub session: Option<ResumeSessionKey>,
    /// Exact worker result or refusal.
    pub outcome: ResumeServiceOutcome,
}

/// Explicit retirement refusal. Active sinks cannot be removed from their worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResumeRetireError {
    /// No admitted session with that certificate/nonce exists.
    #[error("unknown resume session")]
    Unknown,
    /// Collect the current worker's terminal result before retiring its sink.
    #[error("resume session is active")]
    Active,
}

struct Entry<W> {
    receiver: Option<ServiceReceiver<W>>,
    status: ResumeSessionStatus,
    snapshot: Option<ResumeSessionSnapshot>,
}

pub(super) struct Capacity { _permits: Vec<Permit> }
struct Authenticated {
    key: ResumeSessionKey,
    wire: Wire<TlsStream<TcpStream>>,
    offered: Vec<u8>,
    // A completed handshake can wait uncollected while its socket is still live.
    _capacity: Arc<Capacity>,
}

type WorkerResult<W> = Result<(ServiceReceiver<W>, ResumeReport), ResumeServiceRejection>;
enum JobKind<W> {
    Handshake(TaskHandle<Result<Authenticated, ResumeError>>),
    Transfer { key: ResumeSessionKey, task: TaskHandle<WorkerResult<W>> },
}
struct Job<W> { connection: u64, address: SocketAddr, kind: JobKind<W> }
enum FinishedKind<W> {
    Handshake(Result<Result<Authenticated, ResumeError>, JoinError>),
    Transfer { key: ResumeSessionKey, result: Result<WorkerResult<W>, JoinError> },
}
struct Finished<W> { connection: u64, address: SocketAddr, kind: FinishedKind<W> }

/// Shared listener and bounded registry, driven by its owning task.
///
/// Keep polling next to accept and collect results. A dropped Pending wait keeps
/// all jobs and sessions here. Stop/cancel, then call drain_next until None.
/// No idle-key timeout or metadata eviction occurs: max_session_keys is a finite
/// lifetime budget. A durable registry is needed to reclaim it across restarts
/// without forgetting earlier application effects.
#[must_use = "drive next and then drain_next until None"]
pub struct ResumableService<W> {
    listener: Option<TcpListener>,
    address: SocketAddr,
    receiver: LiveStreamReceiver,
    acceptor: TlsAcceptor,
    config: ResumeServiceConfig,
    capacity: Option<Arc<Capacity>>,
    entries: BTreeMap<ResumeSessionKey, Entry<W>>,
    residents: usize,
    clients: BTreeMap<NativeClientCertificateId, usize>,
    jobs: Vec<Job<W>>,
    next_connection: Option<u64>,
}

impl<W> fmt::Debug for ResumableService<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResumableService").field("address", &self.address)
            .field("connections", &self.jobs.len()).field("resident_sessions", &self.residents)
            .field("retained_keys", &self.entries.len()).finish_non_exhaustive()
    }
}

impl LiveStreamReceiver {
    /// Bind one mutually authenticated reconnect port for multiple retained sinks.
    ///
    /// Reserves max_sessions SDK credits before creating a socket. No sink factory
    /// runs until a verified client and valid resume hello have passed admission.
    pub async fn bind_resumable_service<W: super::LiveStreamCommitSink + Unpin>(
        &self, cx: &Cx, address: SocketAddr, config: ResumeServiceConfig,
    ) -> Result<ResumableService<W>, LiveStreamError> {
        authorize(cx)?;
        config.validate(self.admission.capacity)?;
        let mut permits = Vec::new();
        permits.try_reserve_exact(config.max_sessions).map_err(|_| allocation())?;
        let mut jobs = Vec::new();
        jobs.try_reserve_exact(config.max_connections).map_err(|_| allocation())?;
        for _ in 0..config.max_sessions { permits.push(self.admission.reserve()?); }
        let mut tls = (**self.acceptor.config()).clone();
        tls.alpn_protocols = vec![RESUMABLE_LIVE_ALPN.to_vec()];
        let listener = bounded(cx, self.config.operation_timeout, "shared resume bind", TcpListener::bind(address)).await?;
        let address = listener.local_addr()?;
        Ok(ResumableService {
            listener: Some(listener), address, receiver: self.clone(), acceptor: TlsAcceptor::new(tls),
            config, capacity: Some(Arc::new(Capacity { _permits: permits })),
            entries: BTreeMap::new(), residents: 0, clients: BTreeMap::new(), jobs,
            next_connection: Some(0),
        })
    }
}

fn allocation() -> LiveStreamError { io::Error::from(io::ErrorKind::OutOfMemory).into() }

impl<W> ResumableService<W> {
    /// Address of the actual retained listener, including an OS-assigned port.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr { self.address }

    /// Handshakes/transfers and uncollected connection results currently owned.
    #[must_use]
    pub fn in_flight(&self) -> usize { self.jobs.len() }

    /// Resident sinks, including completed sinks awaiting explicit retirement.
    #[must_use]
    pub const fn resident_sessions(&self) -> usize { self.residents }

    /// Admitted lifetime keys, including failed and explicitly retired tombstones.
    #[must_use]
    pub fn retained_keys(&self) -> usize { self.entries.len() }

    /// Current state for a known key; no socket address participates in lookup.
    #[must_use]
    pub fn session_status(&self, key: &ResumeSessionKey) -> Option<ResumeSessionStatus> {
        self.entries.get(key).map(|entry| entry.status)
    }

    /// Last collected snapshot; an active worker may have progressed beyond it.
    #[must_use]
    pub fn session_snapshot(&self, key: &ResumeSessionKey) -> Option<&ResumeSessionSnapshot> {
        self.entries.get(key).and_then(|entry| entry.snapshot.as_ref())
    }

    /// Drop an idle sink while retaining a refusal tombstone and its last metadata.
    ///
    /// Idempotent for a retired key. This never aborts active work, deletes a file,
    /// refunds storage charges, or permits a factory to run again for this key.
    pub fn retire(&mut self, key: &ResumeSessionKey) -> Result<Option<ResumeSessionSnapshot>, ResumeRetireError> {
        let entry = self.entries.get_mut(key).ok_or(ResumeRetireError::Unknown)?;
        if entry.status == ResumeSessionStatus::Active { return Err(ResumeRetireError::Active); }
        let retired = entry.receiver.take();
        let was_resident = entry.status == ResumeSessionStatus::Idle;
        entry.status = ResumeSessionStatus::Retired;
        let snapshot = entry.snapshot.clone();
        if was_resident { self.release_resident(key.client); }
        drop(retired);
        Ok(snapshot)
    }

    /// Close the actual listener now; already routed workers can finish.
    /// Authenticated but not yet routed handshakes are refused during drain.
    pub fn stop_accepting(&mut self) {
        drop(self.listener.take());
        self.release_if_drained();
    }

    /// Close admission and request cancellation; drain_next observes real results.
    pub fn cancel(&mut self, reason: CancelReason) {
        drop(self.listener.take());
        for job in &self.jobs {
            match &job.kind {
                JobKind::Handshake(task) => task.abort_with_reason(reason.clone()),
                JobKind::Transfer { task, .. } => task.abort_with_reason(reason.clone()),
            }
        }
        self.release_if_drained();
    }

    /// True only when admission is closed, every worker joined, and sinks released.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.listener.is_none() && self.jobs.is_empty() && self.capacity.is_none()
    }

    fn release_resident(&mut self, client: NativeClientCertificateId) {
        self.residents -= 1;
        let count = self.clients.get_mut(&client).expect("resident client count");
        *count -= 1;
        if *count == 0 { self.clients.remove(&client); }
    }

    fn release_if_drained(&mut self) {
        if self.listener.is_none() && self.jobs.is_empty() {
            self.entries.clear();
            self.clients.clear();
            self.residents = 0;
            drop(self.capacity.take());
        }
    }

    fn poll_finished(&mut self, ctx: &mut Context<'_>) -> Poll<Finished<W>> {
        for index in 0..self.jobs.len() {
            let kind = match &mut self.jobs[index].kind {
                JobKind::Handshake(task) => match task.poll_join(ctx) {
                    Poll::Pending => continue,
                    Poll::Ready(result) => FinishedKind::Handshake(result),
                },
                JobKind::Transfer { key, task } => match task.poll_join(ctx) {
                    Poll::Pending => continue,
                    Poll::Ready(result) => FinishedKind::Transfer { key: *key, result },
                },
            };
            let job = self.jobs.swap_remove(index);
            return Poll::Ready(Finished { connection: job.connection, address: job.address, kind });
        }
        Poll::Pending
    }

    fn completed_transfer(&mut self, key: ResumeSessionKey, result: Result<WorkerResult<W>, JoinError>) -> ResumeServiceOutcome {
        let entry = self.entries.get_mut(&key).expect("admitted resume key");
        let outcome = match result {
            Ok(Ok((receiver, report))) => {
                entry.snapshot = Some(ResumeSessionSnapshot {
                    prefix: report.prefix.clone(), completed: report.completed.clone(),
                    attempts: report.attempts, sink_written_bytes: report.sink_written_bytes,
                    failed: receiver.failed(),
                });
                // Keep even failed sinks until explicit retirement: their destructor
                // may own application cleanup, and snapshots must not imply rollback.
                entry.receiver = Some(receiver);
                entry.status = ResumeSessionStatus::Idle;
                ResumeServiceOutcome::Transfer(report)
            }
            result => {
                entry.status = ResumeSessionStatus::Retired;
                self.release_resident(key.client);
                match result {
                    Ok(Err(error)) => ResumeServiceOutcome::Rejected(error),
                    Err(error) => ResumeServiceOutcome::JoinFailed(error),
                    Ok(Ok(_)) => unreachable!("successful transfer handled above"),
                }
            }
        };
        self.release_if_drained();
        outcome
    }

    /// Stop admission and collect one result, independent of a cancelled manager Cx.
    ///
    /// Repeat until None. A dropped Pending wait loses no jobs or terminal reports.
    /// When drained, all idle sinks and tombstones are dropped without file deletion.
    pub async fn drain_next(&mut self) -> Option<ResumeServiceCompletion> {
        self.stop_accepting();
        poll_fn(|ctx| {
            if let Poll::Ready(finished) = self.poll_finished(ctx) {
                let (session, outcome) = match finished.kind {
                    FinishedKind::Transfer { key, result } => (Some(key), self.completed_transfer(key, result)),
                    FinishedKind::Handshake(result) => match result {
                        Ok(Ok(auth)) => (Some(auth.key), ResumeServiceOutcome::Rejected(ResumeServiceRejection::Stopping)),
                        Ok(Err(error)) => (None, ResumeServiceOutcome::Rejected(error.into())),
                        Err(error) => (None, ResumeServiceOutcome::JoinFailed(error)),
                    },
                };
                self.release_if_drained();
                return Poll::Ready(Some(ResumeServiceCompletion {
                    connection: finished.connection, address: finished.address, session, outcome,
                }));
            }
            self.release_if_drained();
            if self.jobs.is_empty() { Poll::Ready(None) } else { Poll::Pending }
        }).await
    }
}

impl<W: super::LiveStreamCommitSink + Unpin + Send + 'static> ResumableService<W> {
    /// Accept and route one terminal result while owning all intervening workers.
    ///
    /// Factories run in child contexts only after TLS, hello, and registry admission.
    /// Reconnects never invoke the factory. Pass the same application factory policy
    /// on successive calls; existing sessions keep their original sink. Idle listening
    /// has no deadline; pending TLS, hello, factory and transfers use operation limits.
    /// Manager cancellation requests child cancellation; drain_next must still run.
    pub async fn next<P, F, Fut>(
        &mut self, cx: &Cx, scope: &Scope<'_, P>, make_sink: F,
    ) -> Result<Option<ResumeServiceCompletion>, LiveStreamError>
    where
        P: Policy,
        F: Fn(Cx, ResumeSessionKey) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = io::Result<W>> + Send + 'static,
    {
        self.next_restoring(cx, scope, move |child, key| {
            let future = make_sink(child, key);
            async move { future.await.map(ResumeSessionInit::Fresh) }
        }).await
    }

    /// Route either a new sink or an application-validated historical receipt.
    ///
    /// The factory executes once after fresh mTLS and bounded key admission,
    /// under the same operation deadline as sink creation. Committed decisions
    /// restore only final-Proof exchange: no epoch, sink write or commit runs.
    /// The application must validate protected history before returning one.
    /// Unresolved claims must remain errors, not fresh or completed sessions.
    /// Recovered reports mark receipt_reused and record zero new sink writes.
    /// All connection, resident, per-client, key, attempt and drain limits apply.
    /// Changing the factory cannot resurrect an already retired or failed key.
    pub async fn next_restoring<P, F, Fut>(
        &mut self, cx: &Cx, scope: &Scope<'_, P>, make_sink: F,
    ) -> Result<Option<ResumeServiceCompletion>, LiveStreamError>
    where
        P: Policy,
        F: Fn(Cx, ResumeSessionKey) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = io::Result<ResumeSessionInit<W>>> + Send + 'static,
    {
        let mut cancellation = Cancellation { cx, token: None };
        poll_fn(|ctx| {
            cancellation.token = Some(cx.refresh_cancel_waker(cancellation.token.take(), ctx.waker()));
            if let Err(error) = authorize(cx) {
                self.cancel(cx.cancel_reason().unwrap_or_else(|| CancelReason::user("shared resume authority ended")));
                return Poll::Ready(Err(error));
            }
            if let Poll::Ready(finished) = self.poll_finished(ctx) {
                let (session, outcome) = match finished.kind {
                    FinishedKind::Transfer { key, result } => (Some(key), self.completed_transfer(key, result)),
                    FinishedKind::Handshake(Err(error)) => (None, ResumeServiceOutcome::JoinFailed(error)),
                    FinishedKind::Handshake(Ok(Err(error))) => (None, ResumeServiceOutcome::Rejected(error.into())),
                    FinishedKind::Handshake(Ok(Ok(auth))) => {
                        let key = auth.key;
                        match self.route(cx, scope, finished.connection, finished.address, auth, make_sink.clone()) {
                            Ok(()) => { ctx.waker().wake_by_ref(); return Poll::Pending; }
                            Err(error) => (Some(key), ResumeServiceOutcome::Rejected(error)),
                        }
                    }
                };
                self.release_if_drained();
                return Poll::Ready(Ok(Some(ResumeServiceCompletion {
                    connection: finished.connection, address: finished.address, session, outcome,
                })));
            }
            self.release_if_drained();
            let Some(listener) = &self.listener else {
                return if self.jobs.is_empty() { Poll::Ready(Ok(None)) } else { Poll::Pending };
            };
            if self.jobs.len() >= self.config.max_connections { return Poll::Pending; }
            let Some(connection) = self.next_connection else {
                self.stop_accepting();
                return Poll::Ready(Err(LiveStreamError::Configuration("shared resume connection IDs exhausted")));
            };
            let (tcp, address) = match listener.poll_accept(ctx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => { self.stop_accepting(); return Poll::Ready(Err(error.into())); }
                Poll::Ready(Ok(pair)) => pair,
            };
            self.next_connection = connection.checked_add(1);
            let acceptor = self.acceptor.clone();
            let timeout = self.receiver.config.operation_timeout;
            let capacity = Arc::clone(self.capacity.as_ref().expect("open service capacity"));
            let task = cx.spawn_in(scope, move |child| {
                let future: Pin<Box<dyn Future<Output = Result<Authenticated, ResumeError>> + Send>> = Box::pin(async move {
                    let _capacity = capacity;
                    authorize(&child)?;
                    let tls = bounded(&child, timeout, "shared resume TLS", acceptor.accept(tcp)).await?;
                    let client = NativeClientCertificateId::from_sha256(peer_certificate(&tls)?);
                    let mut wire = Wire::new(tls);
                    let frame = bounded(&child, timeout, "shared resume hello", wire.receive()).await?;
                    let offered = expect(&frame, FrameType::Handshake)?;
                    let hello = decode_offer(offered)?;
                    Ok(Authenticated { key: ResumeSessionKey { client, nonce: hello.nonce }, wire, offered: offered.to_vec(), _capacity })
                });
                future
            });
            match task {
                Ok(task) => self.jobs.push(Job { connection, address, kind: JobKind::Handshake(task) }),
                Err(error) => { self.stop_accepting(); return Poll::Ready(Err(LiveStreamError::Spawn(error))); }
            }
            ctx.waker().wake_by_ref();
            Poll::Pending
        }).await
    }

    fn route<P, F, Fut>(
        &mut self, cx: &Cx, scope: &Scope<'_, P>, connection: u64, address: SocketAddr,
        auth: Authenticated, factory: F,
    ) -> Result<(), ResumeServiceRejection>
    where
        P: Policy,
        F: Fn(Cx, ResumeSessionKey) -> Fut + Send + 'static,
        Fut: Future<Output = io::Result<ResumeSessionInit<W>>> + Send + 'static,
    {
        if self.listener.is_none() { return Err(ResumeServiceRejection::Stopping); }
        let key = auth.key;
        let existing = if let Some(entry) = self.entries.get_mut(&key) {
            match entry.status {
                ResumeSessionStatus::Active => return Err(ResumeServiceRejection::Busy),
                ResumeSessionStatus::Retired => return Err(ResumeServiceRejection::Retired),
                ResumeSessionStatus::Idle => {}
            }
            let receiver = entry.receiver.as_mut().expect("idle session owner");
            if receiver.failed() { return Err(ResumeServiceRejection::Connection(ResumeError::LocalFailure)); }
            if !receiver.has_attempts() { return Err(ResumeServiceRejection::AttemptsExhausted); }
            entry.status = ResumeSessionStatus::Active;
            entry.receiver.take()
        } else {
            if self.entries.len() >= self.config.max_session_keys { return Err(ResumeServiceRejection::Capacity("lifetime key")); }
            if self.residents >= self.config.max_sessions { return Err(ResumeServiceRejection::Capacity("resident session")); }
            let clients = self.clients.entry(key.client).or_default();
            if *clients >= self.config.max_sessions_per_client { return Err(ResumeServiceRejection::Capacity("per-client session")); }
            *clients += 1;
            self.residents += 1;
            self.entries.insert(key, Entry { receiver: None, status: ResumeSessionStatus::Active, snapshot: None });
            None
        };
        let capacity = Arc::clone(self.capacity.as_ref().expect("open service capacity"));
        let acceptor = self.acceptor.clone();
        let config = self.receiver.config.clone();
        let maximum = self.config.max_attempts_per_session;
        let task = cx.spawn_in(scope, move |child| {
            let future: Pin<Box<dyn Future<Output = WorkerResult<W>> + Send>> = Box::pin(async move {
                let _capacity = capacity;
                let mut receiver = match existing {
                    Some(receiver) => receiver,
                    None => {
                        authorize(&child).map_err(ResumeServiceRejection::Factory)?;
                        let initialized = bounded(&child, config.operation_timeout, "resume sink creation", factory(child.clone(), key))
                            .await.map_err(ResumeServiceRejection::Factory)?;
                        ServiceReceiver::new(initialized, key, acceptor, config, maximum, Arc::clone(&_capacity))
                            .map_err(ResumeServiceRejection::Factory)?
                    }
                };
                let mut auth = auth;
                let report = receiver.attempt(&child, &mut auth.wire, &auth.offered).await;
                Ok((receiver, report))
            });
            future
        });
        match task {
            Ok(task) => { self.jobs.push(Job { connection, address, kind: JobKind::Transfer { key, task } }); Ok(()) }
            Err(error) => {
                self.entries.get_mut(&key).expect("reserved key").status = ResumeSessionStatus::Retired;
                self.release_resident(key.client);
                self.stop_accepting();
                Err(ResumeServiceRejection::Spawn(error))
            }
        }
    }
}

impl<W> Drop for ResumableService<W> {
    fn drop(&mut self) {
        self.cancel(CancelReason::user("shared resume service dropped"));
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
