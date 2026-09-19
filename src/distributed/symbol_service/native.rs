//! Native production transport using the existing bounded mTLS computation client.

use super::{SymbolBatchKey, SymbolBatchLimits, SymbolStoreError, decode_symbol_batch, encode_symbol_batch};
use super::service::{SYMBOL_SERVICE_COMPUTATION, fetch_request, put_request, validate_receipt};
use crate::cx::Cx;
use crate::distributed::distribution::{DistributorTransport, ReplicaAck, ReplicaFailure};
use crate::error::ErrorKind;
use crate::remote::{
    ComputationName, IdempotencyKey, RemoteComputationClient, RemoteComputationClientError,
    RemoteInput, RemotePeerHello, RemoteProtocolVersion, RemoteServiceWireOutcome,
    RemoteServiceWireRequest, RemoteServiceWireResponse, RemoteTaskId, SpawnRequest,
};
use crate::security::{AuthKey, AuthenticatedSymbol};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

mod admission;
use admission::Admission;

/// Transport refusal. Untrusted remote diagnostics/payloads are not echoed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RemoteSymbolError {
    /// Invalid route or unsupported service protocol configuration.
    #[error("invalid symbol transport configuration")]
    Configuration,
    /// The requested replica has no explicitly configured authenticated client.
    #[error("symbol replica route is not configured")]
    UnknownReplica,
    /// Batch structure, authentication, or receipt identity failed.
    #[error(transparent)]
    Batch(#[from] SymbolStoreError),
    /// Existing mTLS client failed or refused an ambiguous delivery.
    #[error("symbol transport remote call failed")]
    Client(#[source] RemoteComputationClientError),
    /// Authenticated service refused the request or returned a non-success outcome.
    #[error("remote symbol service refused the request")]
    Refused,
    /// The caller's context observed cancellation before dispatch.
    #[error("symbol transport context is cancelled")]
    Cancelled,
    /// Clone-shared send/fetch capacity is exhausted; no request was dispatched.
    #[error("symbol transport admission limit reached")]
    Admission,
}

/// Explicit native replica routes plus the owner context and symbol-verification key.
///
/// Implements the existing `DistributorTransport`: no custom raw TCP protocol,
/// unverified acknowledgement, detached task, ambient resolver or automatic retry
/// is added. Each client retains its configured TLS trust/name/pins, client cert,
/// finite deadlines and pre-delivery-only retry policy. Configure each logical
/// replica's client for that replica's authenticated server identity.
///
/// This adapter deliberately uses protocol V1 one-shot calls: storage is inline,
/// immutable and independently idempotent. V2/V3 retained lifecycle replies must
/// not acknowledge a store that has since restarted, so those modes are refused
/// here rather than silently claiming durable deduplication. Whole batches must
/// fit BOTH binary batch limits and the clients/listener's JSON frame limits.
///
/// Construct with the same owning Cx used by the distributor. Clones share that
/// context and routes. Local timeout/drop closes the connection, but cannot roll
/// back a batch already retained by a remote store. Fetch returns authenticated
/// symbols for the existing recovery pipeline, not reconstructed task futures.
#[derive(Clone)]
pub struct RemoteSymbolTransport {
    cx: Cx,
    hello: RemotePeerHello,
    routes: Arc<BTreeMap<String, RemoteComputationClient>>,
    auth_key: Arc<AuthKey>,
    limits: SymbolBatchLimits,
    admission: Arc<Admission>,
}

impl fmt::Debug for RemoteSymbolTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteSymbolTransport").field("routes", &self.routes.len())
            .field("in_flight", &self.in_flight())
            .field("max_in_flight", &self.max_in_flight()).finish_non_exhaustive()
    }
}

impl RemoteSymbolTransport {
    /// Bind explicitly authorized replica clients and a V1 registry hello to an owner.
    /// Route labels must be unique, nonempty, and at most 255 bytes; no I/O occurs.
    pub fn new(
        cx: Cx, hello: RemotePeerHello,
        routes: impl IntoIterator<Item = (String, RemoteComputationClient)>,
        auth_key: Arc<AuthKey>, limits: SymbolBatchLimits,
    ) -> Result<Self, RemoteSymbolError> {
        if hello.protocol_version() != RemoteProtocolVersion::V1 || !super::valid_identity(hello.peer_node().as_str()) {
            return Err(RemoteSymbolError::Configuration);
        }
        let mut map = BTreeMap::new();
        for (replica, client) in routes {
            if !super::valid_identity(&replica) || map.contains_key(&replica) {
                return Err(RemoteSymbolError::Configuration);
            }
            map.insert(replica, client);
        }
        if map.is_empty() { return Err(RemoteSymbolError::Configuration); }
        Ok(Self { cx, hello, routes: Arc::new(map), auth_key, limits,
            admission: Arc::new(Admission::new(usize::MAX)) })
    }

    /// Bind routes with one explicit send/fetch ceiling shared by every clone.
    ///
    /// Admission occurs on first poll, BEFORE request allocation, sorting, hashing,
    /// task-ID allocation or network dispatch. Saturation refuses without queuing;
    /// zero is a deny-all configuration. The credit spans response verification
    /// and destruction of the inner future, including timeout, drop and unwind.
    /// Caller-owned inputs, returned symbols and the service's retained storage
    /// are outside this in-flight bound. Per-frame/decode/client limits still apply.
    /// `new` retains its existing effectively-unbounded admission behavior.
    pub fn new_bounded(
        cx: Cx, hello: RemotePeerHello,
        routes: impl IntoIterator<Item = (String, RemoteComputationClient)>,
        auth_key: Arc<AuthKey>, limits: SymbolBatchLimits, max_in_flight: usize,
    ) -> Result<Self, RemoteSymbolError> {
        let mut transport = Self::new(cx, hello, routes, auth_key, limits)?;
        transport.admission = Arc::new(Admission::new(max_in_flight));
        Ok(transport)
    }

    /// Admitted send and fetch operations across this transport and its clones.
    #[must_use]
    pub fn in_flight(&self) -> usize { self.admission.active() }

    /// Shared admission ceiling (`usize::MAX` for the compatibility constructor).
    #[must_use]
    pub fn max_in_flight(&self) -> usize { self.admission.limit() }

    async fn call(&self, replica: &str, input: Vec<u8>) -> Result<Vec<u8>, RemoteSymbolError> {
        if self.cx.is_cancel_requested() { return Err(RemoteSymbolError::Cancelled); }
        let client = self.routes.get(replica).ok_or(RemoteSymbolError::UnknownReplica)?;
        let task = RemoteTaskId::next();
        let request = SpawnRequest {
            remote_task_id: task,
            computation: ComputationName::new(SYMBOL_SERVICE_COMPUTATION),
            input: RemoteInput::new(input),
            lease: client.config().attempt_timeout(), // V1 does not establish a renewable lease.
            idempotency_key: IdempotencyKey::from_raw(u128::from(task.raw())),
            budget: None,
            origin_node: self.hello.peer_node().clone(),
            origin_region: self.cx.region_id(),
            origin_task: self.cx.task_id(),
        };
        let wire = RemoteServiceWireRequest::from_spawn_request(self.hello.clone(), &request)
            .map_err(|_| RemoteSymbolError::Configuration)?;
        drop(request);
        match client.call(&self.cx, &wire).await.map_err(RemoteSymbolError::Client)? {
            RemoteServiceWireResponse::Outcome { outcome: RemoteServiceWireOutcome::Success(bytes), .. } => Ok(bytes),
            _ => Err(RemoteSymbolError::Refused),
        }
    }

    /// Retrieve only the requested origin/object/digest and reverify all symbol tags.
    /// No different version of an object, partial result, or live fallback is accepted.
    pub async fn fetch_symbols(
        &self, replica: &str, key: SymbolBatchKey,
    ) -> Result<Vec<AuthenticatedSymbol>, RemoteSymbolError> {
        if self.cx.is_cancel_requested() { return Err(RemoteSymbolError::Cancelled); }
        if !self.routes.contains_key(replica) { return Err(RemoteSymbolError::UnknownReplica); }
        self.admission.run(|| async {
            let bytes = self.call(replica, fetch_request(replica, key)?).await?;
            let symbols = decode_symbol_batch(&bytes, &self.auth_key, self.limits)?;
            let actual = super::batch::key(symbols[0].symbol().id().object_id(), &bytes);
            if actual != key { return Err(SymbolStoreError::Identity.into()); }
            Ok(symbols)
        }).await
    }

    async fn send(&self, replica: &str, symbols: Vec<AuthenticatedSymbol>) -> Result<ReplicaAck, RemoteSymbolError> {
        // Check authority/cancellation before sorting, hashing, or making an input copy.
        if self.cx.is_cancel_requested() { return Err(RemoteSymbolError::Cancelled); }
        if !self.routes.contains_key(replica) { return Err(RemoteSymbolError::UnknownReplica); }
        self.admission.run(|| async move {
            let encoded = encode_symbol_batch(&symbols, self.limits)?;
            drop(symbols);
            let response = self.call(replica, put_request(replica, encoded.as_ref())?).await?;
            Ok(validate_receipt(&response, replica, encoded.key(), encoded.symbol_count())?)
        }).await
    }
}

impl DistributorTransport for RemoteSymbolTransport {
    async fn send_symbols(
        &self, replica_id: &str, symbols: Vec<AuthenticatedSymbol>,
    ) -> Result<ReplicaAck, ReplicaFailure> {
        self.send(replica_id, symbols).await.map_err(|error| {
            let error_kind = match &error {
                RemoteSymbolError::Configuration => ErrorKind::ConfigError,
                RemoteSymbolError::UnknownReplica => ErrorKind::NodeUnavailable,
                RemoteSymbolError::Cancelled => ErrorKind::Cancelled,
                RemoteSymbolError::Batch(_) => ErrorKind::ProtocolError,
                RemoteSymbolError::Client(_) => ErrorKind::ConnectionLost,
                RemoteSymbolError::Refused | RemoteSymbolError::Admission => ErrorKind::AdmissionDenied,
            };
            ReplicaFailure { replica_id: replica_id.to_owned(), error: error.to_string(), error_kind }
        })
    }
}

/// Bounded replica collection and authenticated snapshot reconstruction.
pub mod recovery;
