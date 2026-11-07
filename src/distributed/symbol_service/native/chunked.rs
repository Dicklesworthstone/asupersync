//! Native multi-frame adapter sharing the original transport's admission domain.

use super::{RemoteSymbolError, RemoteSymbolTransport};
use crate::cx::Cx;
use crate::distributed::distribution::ReplicaAck;
use crate::distributed::symbol_service::service::chunked::{
    ABORT, BEGIN, CHUNK, COMMIT, SYMBOL_CHUNKED_SERVICE_COMPUTATION, Upload,
    range_request, read_progress, read_range, request, upload_body,
};
use crate::distributed::symbol_service::service::validate_receipt;
use crate::distributed::symbol_service::{EncodedSymbolBatch, SymbolBatchKey, SymbolBatchLimits, SymbolStoreError, decode_symbol_batch, encode_symbol_batch};
use crate::remote::{
    ComputationName, IdempotencyKey, NodeId, RemoteComputationClient, RemoteInput, RemotePeerHello,
    RemoteServiceWireOutcome, RemoteServiceWireRequest, RemoteServiceWireResponse, RemoteTaskId,
    SpawnRequest,
};
use crate::security::{AuthKey, AuthenticatedSymbol};
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Exact identity of one caller-managed chunked upload, without its payload.
///
/// Obtain this from [`RemoteSymbolTransport::chunked_upload_identity`] before
/// sending with [`RemoteSymbolTransport::send_symbols_with_attempt`]. Retain it
/// if a later authorized owner may need to release an incomplete remote stage.
/// It binds the origin, replica, attempt, canonical batch digest, byte length
/// and symbol count; no public field can substitute another upload's metadata.
///
/// This is correlation metadata, not a capability or proof of delivery. The
/// cleanup transport must independently authenticate the same origin and hold
/// the replica's chunked-service grant. Callers sharing that origin must still
/// reserve distinct attempt IDs and never reuse one for unrelated work.
#[derive(Clone, PartialEq, Eq)]
pub struct SymbolUploadIdentity {
    origin: NodeId,
    replica: String,
    upload: Upload,
}

impl std::fmt::Debug for SymbolUploadIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymbolUploadIdentity")
            .field("attempt", &self.upload.attempt)
            .field("symbols", &self.upload.count)
            .field("encoded_bytes", &self.upload.total)
            .finish_non_exhaustive()
    }
}

impl SymbolUploadIdentity {
    /// Authenticated origin whose staging namespace contains the attempt.
    #[must_use]
    pub fn origin(&self) -> &NodeId { &self.origin }

    /// Configured replica route associated with this attempt.
    #[must_use]
    pub fn replica(&self) -> &str { &self.replica }

    /// Exact canonical batch identity; its digest grants no authority.
    #[must_use]
    pub const fn key(&self) -> SymbolBatchKey { self.upload.key }

    /// Caller-reserved attempt ID in the authenticated origin's namespace.
    #[must_use]
    pub const fn attempt(&self) -> u64 { self.upload.attempt }

    /// Complete canonical encoded length, excluding service envelopes.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize { self.upload.total }

    /// Number of symbols bound to this exact upload.
    #[must_use]
    pub const fn symbol_count(&self) -> u32 { self.upload.count }
}

impl RemoteSymbolTransport {
    /// Use a separately granted chunked symbol capability with finite shared admission.
    ///
    /// The complete canonical batch may exceed the client's JSON frame limit.
    /// Every request/response payload is bounded by `max_chunk_bytes` plus fixed
    /// metadata; construction counts the actual empty JSON envelopes and admits
    /// worst-case byte-array expansion BEFORE allocating/copying batch payloads.
    /// The receiver has independent staging, chunk, batch, and frame policies.
    /// Its smaller advertised chunk limit is honored without changing identity.
    ///
    /// One credit covers encoding, all frames, final verification and destruction.
    /// Each RPC retains the client's bounded connection/retry/attempt policy.
    /// An owner Cx deadline bounds the whole transfer; without one, the explicit
    /// batch size and per-RPC limits bound its finite sequence of calls. There is
    /// no automatic replay after ambiguous delivery and no implicit resume token.
    /// Dropping/cancelling closes local work but incomplete remote staging remains
    /// charged until the receiver's fixed expiry/reap. A lost commit receipt can
    /// follow successful publication; a subsequent identical send is idempotent.
    /// Caller-managed attempts can instead request explicit staging cleanup with
    /// [`Self::abort_symbol_upload`] from a live, independently authorized owner.
    #[allow(clippy::too_many_arguments)]
    pub fn new_chunked_bounded(
        cx: Cx, hello: RemotePeerHello,
        routes: impl IntoIterator<Item = (String, RemoteComputationClient)>,
        auth_key: Arc<AuthKey>, limits: SymbolBatchLimits,
        max_in_flight: usize, max_chunk_bytes: usize,
    ) -> Result<Self, RemoteSymbolError> {
        if max_chunk_bytes == 0 || u32::try_from(max_chunk_bytes).is_err() {
            return Err(RemoteSymbolError::Configuration);
        }
        let mut transport = Self::new_bounded(cx, hello, routes, auth_key, limits, max_in_flight)?;
        for (replica, client) in transport.routes.iter() {
            transport.check_chunk_frame_budget(replica, client, max_chunk_bytes)?;
        }
        transport.chunk_bytes = Some(max_chunk_bytes);
        Ok(transport)
    }

    /// Send or reconcile a chunked upload using a caller-owned attempt identity.
    ///
    /// The caller must persist `attempt` before first dispatch and reserve it for
    /// this exact canonical signed batch in the authenticated origin's namespace.
    /// Do not reuse it for an unrelated upload, including work submitted through
    /// a different transport or the compatibility `send_symbols` entry point.
    /// After a publisher restart, supplying the same attempt and exact batch
    /// continues the receiver's retained prefix; an already retained batch yields
    /// a newly verified commit receipt. An attempt with different batch metadata
    /// is refused while its original stage is present.
    ///
    /// This is explicit caller-driven reconciliation, not automatic retry.
    /// Receiver expiry, abort, or restart can remove an incomplete stage, in which
    /// case the exact upload starts again. A lost commit reply can follow a
    /// successful publication. This API does not persist caller intent, add
    /// receiver durability, guarantee remote rollback, or establish exactly-once
    /// execution. Cancellation/drop retains the existing remote staging policy.
    ///
    /// Only transports constructed with `new_chunked_bounded` support this
    /// operation; whole-batch transports return `Configuration` before dispatch.
    /// The clone-shared credit, complete owner deadline, frame bounds and
    /// authenticated receipt checks are the same as ordinary chunked sends.
    pub async fn send_symbols_with_attempt(
        &self, replica: &str, symbols: Vec<AuthenticatedSymbol>, attempt: u64,
    ) -> Result<ReplicaAck, RemoteSymbolError> {
        if self.cx.is_cancel_requested() { return Err(RemoteSymbolError::Cancelled); }
        let maximum = self.chunk_bytes.ok_or(RemoteSymbolError::Configuration)?;
        if !self.routes.contains_key(replica) { return Err(RemoteSymbolError::UnknownReplica); }
        self.admission.run(|| {
            self.with_owner_deadline(self.send_chunked_attempt(replica, symbols, maximum, Some(attempt)))
        }).await
    }

    /// Describe an exact caller-managed upload for later explicit cleanup.
    ///
    /// No I/O, admission credit, payload copy or authority grant occurs here.
    /// This can describe an upload even after this transport's owner is cancelled;
    /// aborting it requires a live transport with the same authenticated origin.
    /// Persist the attempt and source intent before dispatch, as required by
    /// [`Self::send_symbols_with_attempt`]. After a restart, the same canonical
    /// batch and attempt reconstruct the same identity; no checkpoint storage is
    /// provided by this method.
    ///
    /// Whole-batch transports, unconfigured routes and metadata beyond this
    /// transport's batch byte/symbol limits are refused before allocation.
    pub fn chunked_upload_identity(
        &self, replica: &str, batch: &EncodedSymbolBatch, attempt: u64,
    ) -> Result<SymbolUploadIdentity, RemoteSymbolError> {
        if self.chunk_bytes.is_none() { return Err(RemoteSymbolError::Configuration); }
        if !self.routes.contains_key(replica) { return Err(RemoteSymbolError::UnknownReplica); }
        let upload = Upload { key: batch.key(), attempt,
            total: batch.as_ref().len(), count: batch.symbol_count() };
        self.check_upload_bounds(upload)?;
        Ok(SymbolUploadIdentity {
            origin: self.hello.peer_node().clone(), replica: replica.to_owned(), upload,
        })
    }

    /// Release only an exact upload's incomplete receiver staging reservation.
    ///
    /// This explicit authenticated ABORT uses the existing chunked capability,
    /// clone-shared admission, owner cancellation/deadline and bounded RPC path.
    /// A different origin, unconfigured replica, whole-batch transport or upload
    /// beyond the cleanup transport's byte/symbol limits is refused locally.
    /// The receiver also matches the digest, attempt, encoded length and count;
    /// a conflicting live stage is left intact. Success requires its exact
    /// correlated zero-progress acknowledgement. No batch payload is resent.
    ///
    /// Repeating an abort when the stage is absent is idempotent. An in-progress
    /// COMMIT finishes before the receiver processes ABORT, and an already
    /// committed batch is never removed. Thus success means staging was absent
    /// at that receiver operation, not that publication was rolled back. Stop
    /// dispatching this attempt first: ABORT is not a fence against a later BEGIN.
    /// A lost, cancelled or timed-out reply does not prove whether cleanup ran;
    /// retry explicitly with the same identity or let the receiver's TTL expire.
    ///
    /// After the original owner is cancelled, construct a new chunked transport
    /// from a live authorized Cx, the same origin and authenticated replica route,
    /// then pass the retained identity here. Cloning a cancelled transport does
    /// not revive it. Dropping a send or this future never starts background I/O.
    pub async fn abort_symbol_upload(
        &self, identity: &SymbolUploadIdentity,
    ) -> Result<(), RemoteSymbolError> {
        if self.cx.is_cancel_requested() { return Err(RemoteSymbolError::Cancelled); }
        if self.chunk_bytes.is_none() || identity.origin != *self.hello.peer_node() {
            return Err(RemoteSymbolError::Configuration);
        }
        if !self.routes.contains_key(&identity.replica) { return Err(RemoteSymbolError::UnknownReplica); }
        self.check_upload_bounds(identity.upload)?;
        self.admission.run(|| self.with_owner_deadline(async {
            let response = self.call_named(&identity.replica, SYMBOL_CHUNKED_SERVICE_COMPUTATION,
                request(ABORT, &identity.replica, &upload_body(identity.upload))?).await?;
            validate_abort_progress(&response, identity.upload)?;
            Ok(())
        })).await
    }

    fn check_upload_bounds(&self, upload: Upload) -> Result<(), RemoteSymbolError> {
        if upload.total > self.limits.max_encoded_bytes || upload.count as usize > self.limits.max_symbols {
            return Err(SymbolStoreError::Limit("batch bytes or symbols").into());
        }
        Ok(())
    }

    fn check_chunk_frame_budget(
        &self, replica: &str, client: &RemoteComputationClient, maximum: usize,
    ) -> Result<(), RemoteSymbolError> {
        // Maximal correlation IDs keep this bound valid for every later frame.
        let spawn = SpawnRequest {
            remote_task_id: RemoteTaskId::from_raw(u64::MAX),
            computation: ComputationName::new(SYMBOL_CHUNKED_SERVICE_COMPUTATION),
            input: RemoteInput::new(Vec::new()), lease: client.config().attempt_timeout(),
            idempotency_key: IdempotencyKey::from_raw(u128::MAX), budget: None,
            origin_node: self.hello.peer_node().clone(), origin_region: self.cx.region_id(), origin_task: self.cx.task_id(),
        };
        let wire = RemoteServiceWireRequest::from_spawn_request(self.hello.clone(), &spawn)
            .map_err(|_| RemoteSymbolError::Configuration)?;
        let response = RemoteServiceWireResponse::Outcome {
            remote_task_id: u64::MAX, outcome: RemoteServiceWireOutcome::Success(Vec::new()),
        };
        // Request: 14-byte prefix + replica + 68-byte upload + 8-byte offset + chunk.
        // Response: range header + chunk, progress (92), or attempt + receipt.
        let request_bytes = maximum.checked_add(90 + replica.len()).ok_or(RemoteSymbolError::Configuration)?;
        let response_bytes = maximum.checked_add(80).ok_or(RemoteSymbolError::Configuration)?.max(82 + replica.len()).max(92);
        let ceiling = client.config().wire_limits().max_frame_bytes();
        for (base, bytes) in [(encoded_size(&wire)?, request_bytes), (encoded_size(&response)?, response_bytes)] {
            let total = bytes.checked_mul(4).and_then(|expanded| base.checked_add(expanded))
                .ok_or(RemoteSymbolError::Configuration)?;
            if total > ceiling { return Err(RemoteSymbolError::Configuration); }
        }
        Ok(())
    }

    fn check_chunk_context(&self) -> Result<(), RemoteSymbolError> {
        if self.cx.is_cancel_requested() {
            let _ = self.cx.checkpoint();
            return Err(RemoteSymbolError::Cancelled);
        }
        if self.cx.budget().deadline.is_some_and(|deadline| self.cx.now() >= deadline) {
            return Err(RemoteSymbolError::Deadline);
        }
        Ok(())
    }

    pub(super) async fn with_owner_deadline<T>(
        &self, future: impl Future<Output = Result<T, RemoteSymbolError>>,
    ) -> Result<T, RemoteSymbolError> {
        let operation = async {
            self.check_chunk_context()?;
            let result = if let Some(deadline) = self.cx.budget().deadline {
                if self.cx.timer_driver().is_none() { return Err(RemoteSymbolError::Configuration); }
                crate::time::timeout_at(deadline, future).await.map_err(|_| RemoteSymbolError::Deadline)?
            } else { future.await };
            self.check_chunk_context()?;
            result
        };
        let mut operation = std::pin::pin!(operation);
        poll_fn(|task| {
            // Sleep and the existing client's per-RPC timeout obtain their clock
            // from the ambient context. Bind the complete poll to this transport's
            // owner even when a different task/context polls the borrowed future.
            // The guard is destroyed before Pending crosses an await boundary.
            let _owner = Cx::set_current(Some(self.cx.clone()));
            operation.as_mut().poll(task)
        }).await
    }

    pub(super) async fn send_chunked(
        &self, replica: &str, symbols: Vec<AuthenticatedSymbol>, maximum: usize,
    ) -> Result<ReplicaAck, RemoteSymbolError> {
        self.send_chunked_attempt(replica, symbols, maximum, None).await
    }

    async fn send_chunked_attempt(
        &self, replica: &str, symbols: Vec<AuthenticatedSymbol>, maximum: usize, attempt: Option<u64>,
    ) -> Result<ReplicaAck, RemoteSymbolError> {
        self.check_chunk_context()?;
        let batch = encode_symbol_batch(&symbols, self.limits)?;
        drop(symbols);
        self.check_chunk_context()?;
        let upload = Upload { key: batch.key(), attempt: attempt.unwrap_or_else(|| RemoteTaskId::next().raw()),
            total: batch.as_ref().len(), count: batch.symbol_count() };
        let response = self.call_named(replica, SYMBOL_CHUNKED_SERVICE_COMPUTATION,
            request(BEGIN, replica, &upload_body(upload))?).await?;
        let (mut offset, accepted) = read_progress(&response, upload)?;
        drop(response);
        let chunk = maximum.min(accepted);
        while offset < upload.total {
            self.check_chunk_context()?;
            let end = offset + chunk.min(upload.total - offset);
            let mut body = Zeroizing::new(upload_body(upload));
            body.try_reserve_exact(8 + end - offset).map_err(|_| SymbolStoreError::Allocation)?;
            body.extend_from_slice(&(offset as u64).to_le_bytes());
            body.extend_from_slice(&batch.as_ref()[offset..end]);
            let input = request(CHUNK, replica, &body)?;
            drop(body);
            let response = self.call_named(replica, SYMBOL_CHUNKED_SERVICE_COMPUTATION, input).await?;
            let (received, limit) = read_progress(&response, upload)?;
            if received != end || limit != accepted { return Err(SymbolStoreError::Identity.into()); }
            offset = received;
        }
        self.check_chunk_context()?;
        let response = self.call_named(replica, SYMBOL_CHUNKED_SERVICE_COMPUTATION,
            request(COMMIT, replica, &upload_body(upload))?).await?;
        if response.get(..8) != Some(upload.attempt.to_le_bytes().as_slice()) {
            return Err(SymbolStoreError::Identity.into());
        }
        Ok(validate_receipt(&response[8..], replica, upload.key, upload.count)?)
    }

    pub(super) async fn fetch_chunked(
        &self, replica: &str, key: SymbolBatchKey, maximum: usize,
    ) -> Result<Vec<AuthenticatedSymbol>, RemoteSymbolError> {
        let mut bytes = Zeroizing::new(Vec::new());
        let mut expected = None;
        loop {
            self.check_chunk_context()?;
            let response = self.call_named(replica, SYMBOL_CHUNKED_SERVICE_COMPUTATION,
                range_request(replica, key, bytes.len(), maximum)?).await?;
            let (total, count, chunk) = read_range(&response, key, bytes.len(), maximum)?;
            if total > self.limits.max_encoded_bytes || count as usize > self.limits.max_symbols {
                return Err(SymbolStoreError::Limit("fetched bytes or symbols").into());
            }
            if let Some(metadata) = expected {
                if metadata != (total, count) { return Err(SymbolStoreError::Identity.into()); }
            } else {
                bytes.try_reserve_exact(total).map_err(|_| SymbolStoreError::Allocation)?;
                expected = Some((total, count));
            }
            bytes.extend_from_slice(chunk);
            if bytes.len() == total { break; }
        }
        self.check_chunk_context()?;
        if super::super::batch::key(key.object_id, &bytes) != key { return Err(SymbolStoreError::Identity.into()); }
        let symbols = decode_symbol_batch(&bytes, &self.auth_key, self.limits)?;
        if symbols[0].symbol().id().object_id() != key.object_id
            || expected != Some((bytes.len(), symbols.len() as u32))
        { return Err(SymbolStoreError::Identity.into()); }
        self.check_chunk_context()?;
        Ok(symbols)
    }
}

fn validate_abort_progress(bytes: &[u8], upload: Upload) -> Result<(), SymbolStoreError> {
    let (received, _) = read_progress(bytes, upload)?;
    if received != 0 { return Err(SymbolStoreError::Identity); }
    Ok(())
}

struct CountWriter(usize);
impl Write for CountWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.checked_add(bytes.len()).ok_or_else(|| io::Error::other("frame size overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn encoded_size(value: &impl serde::Serialize) -> Result<usize, RemoteSymbolError> {
    let mut writer = CountWriter(0);
    serde_json::to_writer(&mut writer, value).map_err(|_| RemoteSymbolError::Configuration)?;
    Ok(writer.0)
}

#[cfg(test)]
#[path = "chunked_inline_tests.rs"]
mod tests;
