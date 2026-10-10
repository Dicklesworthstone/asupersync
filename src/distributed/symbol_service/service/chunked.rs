//! Bounded multi-frame transfer inside the existing authenticated V1 service.

use super::{put_key, read_key, receipt};
use crate::distributed::symbol_service::{SymbolBatchKey, SymbolReplicaStore, SymbolStoreError};
use crate::distributed::{ComputationSchemaRegistryError, HasSchema, SchemaDescriptor};
use crate::remote::{NodeId, RemoteComputationRegistry, RemoteOutcome};
use crate::types::Time;
use parking_lot::{Condvar, Mutex};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// Separate capability; registering the original symbol service does not grant this one.
pub const SYMBOL_CHUNKED_SERVICE_COMPUTATION: &str = "asupersync.distributed.symbol-store.chunked.v1";
const MAGIC: &[u8; 8] = b"ASUPCHN\0";
pub(crate) const BEGIN: u8 = 1;
pub(crate) const CHUNK: u8 = 2;
pub(crate) const COMMIT: u8 = 3;
pub(crate) const ABORT: u8 = 4;
pub(crate) const READ: u8 = 5;
const PROGRESS: &[u8; 8] = b"ASUPPRG\0";
const RANGE: &[u8; 8] = b"ASUPRNG\0";

/// Logical staging limits, independent of retained storage and JSON frame limits.
///
/// A full declared upload length is reserved before accepting its first byte.
/// Allocator overhead, incoming service frames and final verification buffers
/// remain separately bounded by service connection/frame and batch policies.
#[derive(Debug, Clone, Copy)]
pub struct SymbolChunkedLimits {
    max_chunk_bytes: usize,
    max_uploads: usize,
    max_reserved_bytes: usize,
    max_uploads_per_peer: usize,
    max_reserved_bytes_per_peer: usize,
    ttl_nanos: u64,
}

impl SymbolChunkedLimits {
    /// Zero staging counts/bytes deny new uploads. Chunks and expiry must be nonzero.
    pub fn new(
        max_chunk_bytes: usize, max_uploads: usize, max_reserved_bytes: usize,
        max_uploads_per_peer: usize, max_reserved_bytes_per_peer: usize,
        upload_ttl: Duration,
    ) -> Result<Self, SymbolStoreError> {
        if max_chunk_bytes == 0 || u32::try_from(max_chunk_bytes).is_err() {
            return Err(SymbolStoreError::Limit("chunk bytes"));
        }
        let ttl_nanos = u64::try_from(upload_ttl.as_nanos()).map_err(|_| SymbolStoreError::Overflow)?;
        if ttl_nanos == 0 { return Err(SymbolStoreError::Limit("upload lifetime")); }
        Ok(Self { max_chunk_bytes, max_uploads, max_reserved_bytes,
            max_uploads_per_peer, max_reserved_bytes_per_peer, ttl_nanos })
    }

    /// Maximum binary payload in one upload chunk or range response.
    #[must_use]
    pub const fn max_chunk_bytes(self) -> usize { self.max_chunk_bytes }
}

/// Staged bytes only; successful immutable batches belong to the backing store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolStagingStats {
    /// Uncommitted uploads across authenticated origins.
    pub uploads: usize,
    /// Sum of complete declared lengths, including bytes not yet received.
    pub reserved_bytes: usize,
    /// Actual accepted bytes currently held by uncommitted uploads.
    pub received_bytes: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Upload {
    pub(crate) key: SymbolBatchKey,
    pub(crate) attempt: u64,
    pub(crate) total: usize,
    pub(crate) count: u32,
}

struct Stage {
    upload: Upload,
    expires: Time,
    bytes: Zeroizing<Vec<u8>>,
    commit: Option<Arc<CommitCompletion>>,
}

impl Stage {
    fn received_bytes(&self) -> usize {
        if self.commit.is_some() { self.upload.total } else { self.bytes.len() }
    }
}

#[derive(Default)]
struct CommitCompletion {
    done: Mutex<bool>,
    changed: Condvar,
}

impl CommitCompletion {
    fn wait(&self) {
        let mut done = self.done.lock();
        while !*done { self.changed.wait(&mut done); }
    }

    fn finish(&self) {
        *self.done.lock() = true;
        self.changed.notify_all();
    }
}

#[derive(Default)]
struct Staging {
    entries: BTreeMap<(NodeId, u64), Stage>,
    reserved: usize,
}

impl Staging {
    fn reap(&mut self, now: Time) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, stage| stage.commit.is_some() || now < stage.expires);
        self.reserved = self.entries.values().map(|stage| stage.upload.total).sum();
        before - self.entries.len()
    }

    fn remove(&mut self, id: &(NodeId, u64)) {
        if let Some(stage) = self.entries.remove(id) { self.reserved -= stage.upload.total; }
    }
}

// The map retains the full count/byte charge, but hashing and authentication own
// their payload outside its mutex. The completion identity protects removal even
// during unwind; another request cannot reap, abort, or replace this marker.
struct StagedCommit<'a> {
    staging: &'a Mutex<Staging>,
    id: (NodeId, u64),
    completion: Arc<CommitCompletion>,
    bytes: Option<Zeroizing<Vec<u8>>>,
}

impl StagedCommit<'_> {
    fn bytes(&self) -> &[u8] {
        self.bytes.as_ref().expect("commit owns its staged bytes").as_slice()
    }
}

impl Drop for StagedCommit<'_> {
    fn drop(&mut self) {
        // Zeroization can touch a complete large batch. Do it outside the shared
        // mutex and before any request can spend the reservation again.
        drop(self.bytes.take());
        {
            let mut state = self.staging.lock();
            if state.entries.get(&self.id).is_some_and(|stage| {
                stage.commit.as_ref().is_some_and(|commit| Arc::ptr_eq(commit, &self.completion))
            }) {
                state.remove(&self.id);
            }
        }
        self.completion.finish();
    }
}

/// Authenticated-origin staging followed by atomic, fully verified publication.
///
/// Uploads have a fixed lifetime from BEGIN; replaying or appending cannot renew
/// it. Every request reaps expired uploads. Operators may also call
/// `reap_expired` from their own clock-driven task. There is no hidden background
/// task: idle expired allocations persist until a request, explicit reap, or
/// final service drop. All are still charged against the configured hard quota.
/// An admitted COMMIT keeps its full charge until verification and publication
/// retire, even if the upload expires meanwhile. Other attempts can progress
/// during verification; requests for that same attempt wait for its completion.
///
/// A completed receipt means the backing IN-MEMORY store retained the exact
/// authenticated batch. Cancellation/disconnection can leave an incomplete
/// remote stage until expiry, or an already committed batch. It does not imply
/// remote quiescence, disk durability, rollback, or exactly-once delivery.
pub struct ChunkedSymbolService {
    store: Arc<SymbolReplicaStore>,
    limits: SymbolChunkedLimits,
    staging: Mutex<Staging>,
    #[cfg(test)]
    commit_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl std::fmt::Debug for ChunkedSymbolService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkedSymbolService").field("stats", &self.stats()).finish_non_exhaustive()
    }
}

impl ChunkedSymbolService {
    /// Wrap existing immutable storage without I/O or spawning tasks.
    #[must_use]
    pub fn new(store: Arc<SymbolReplicaStore>, limits: SymbolChunkedLimits) -> Self {
        Self { store, limits, staging: Mutex::new(Staging::default()),
            #[cfg(test)]
            commit_hook: Mutex::new(None),
        }
    }

    /// Current charged staging, including expired uploads not yet reaped.
    #[must_use]
    pub fn stats(&self) -> SymbolStagingStats {
        let state = self.staging.lock();
        SymbolStagingStats { uploads: state.entries.len(), reserved_bytes: state.reserved,
            received_bytes: state.entries.values().map(Stage::received_bytes).sum() }
    }

    /// Retire expired allocations using the same clock as the registered handler.
    /// Returns the number removed. Retained immutable batches are unaffected.
    pub fn reap_expired(&self, now: Time) -> usize { self.staging.lock().reap(now) }

    fn handle(&self, peer: &NodeId, now: Time, input: &[u8]) -> Result<Vec<u8>, SymbolStoreError> {
        if !super::super::valid_identity(peer.as_str()) { return Err(SymbolStoreError::InvalidIdentity); }
        let (operation, body) = split_request(input, self.store.replica_id())?;
        let mut state = self.staging.lock();
        state.reap(now);
        if operation == READ {
            drop(state);
            return self.read(peer, body);
        }
        if body.len() < 68 { return Err(SymbolStoreError::Truncated); }
        let upload = read_upload(&body[..68])?;
        let id = (peer.clone(), upload.attempt);
        loop {
            if let Some(completion) = state.entries.get(&id).and_then(|stage| stage.commit.clone()) {
                // Preserve the original per-attempt ordering without holding up
                // every origin. The owner is bounded synchronous in-memory work,
                // not a task that can suspend on I/O; unwind also wakes us.
                drop(state);
                completion.wait();
                state = self.staging.lock();
                state.reap(now);
                continue;
            }
            return match operation {
                BEGIN => {
                    if body.len() != 68 { return Err(SymbolStoreError::TrailingData); }
                    self.validate_upload(upload)?;
                    if let Some(stage) = state.entries.get(&id) {
                        if stage.upload != upload { return Err(SymbolStoreError::Conflict); }
                        return progress(upload, stage.bytes.len(), self.limits.max_chunk_bytes);
                    }
                    if let Ok(batch) = self.store.get(peer, upload.key) {
                        if batch.as_ref().as_ref().len() != upload.total || batch.symbol_count() != upload.count {
                            return Err(SymbolStoreError::Identity);
                        }
                        return progress(upload, upload.total, self.limits.max_chunk_bytes);
                    }
                    if state.entries.len() >= self.limits.max_uploads { return Err(SymbolStoreError::Limit("staged uploads")); }
                    let reserved = state.reserved.checked_add(upload.total).ok_or(SymbolStoreError::Overflow)?;
                    if reserved > self.limits.max_reserved_bytes { return Err(SymbolStoreError::Limit("staged bytes")); }
                    let (count, bytes) = state.entries.iter().filter(|((origin, _), _)| origin == peer)
                        .fold((0usize, 0usize), |(count, bytes), (_, stage)| (count + 1, bytes + stage.upload.total));
                    if count >= self.limits.max_uploads_per_peer { return Err(SymbolStoreError::Limit("peer staged uploads")); }
                    if bytes.checked_add(upload.total).ok_or(SymbolStoreError::Overflow)? > self.limits.max_reserved_bytes_per_peer {
                        return Err(SymbolStoreError::Limit("peer staged bytes"));
                    }
                    let expires = now.as_nanos().checked_add(self.limits.ttl_nanos).ok_or(SymbolStoreError::Overflow)?;
                    state.entries.insert(id, Stage { upload, expires: Time::from_nanos(expires),
                        bytes: Zeroizing::new(Vec::new()), commit: None });
                    state.reserved = reserved;
                    progress(upload, 0, self.limits.max_chunk_bytes)
                }
                CHUNK => {
                    if body.len() < 77 { return Err(SymbolStoreError::Truncated); }
                    let offset = read_usize(&body[68..76])?;
                    let bytes = &body[76..];
                    if bytes.len() > self.limits.max_chunk_bytes { return Err(SymbolStoreError::Limit("chunk bytes")); }
                    let stage = state.entries.get_mut(&id).ok_or(SymbolStoreError::NotFound)?;
                    if stage.upload != upload { return Err(SymbolStoreError::Identity); }
                    let end = offset.checked_add(bytes.len()).ok_or(SymbolStoreError::Overflow)?;
                    if end > upload.total { return Err(SymbolStoreError::Limit("declared upload bytes")); }
                    if offset == stage.bytes.len() {
                        // Allocate the whole declared upload once (BEGIN already charged it to the
                        // staging quota). Growing by each chunk let small chunks copy everything
                        // staged so far under the shared lock, and left unzeroed copies behind.
                        let missing = upload.total - stage.bytes.len();
                        if stage.bytes.capacity() < upload.total {
                            let reserved = stage.bytes.try_reserve_exact(missing);
                            reserved.map_err(|_| SymbolStoreError::Allocation)?;
                        }
                        stage.bytes.extend_from_slice(bytes);
                    } else if stage.bytes.get(offset..end) != Some(bytes) {
                        return Err(SymbolStoreError::Conflict);
                    }
                    progress(upload, stage.bytes.len(), self.limits.max_chunk_bytes)
                }
                COMMIT => {
                    if body.len() != 68 { return Err(SymbolStoreError::TrailingData); }
                    let result = if let Some(stage) = state.entries.get_mut(&id) {
                        if stage.upload != upload { return Err(SymbolStoreError::Identity); }
                        if stage.bytes.len() != upload.total { return Err(SymbolStoreError::Truncated); }
                        let completion = Arc::new(CommitCompletion::default());
                        let staged = StagedCommit {
                            staging: &self.staging, id, completion: Arc::clone(&completion),
                            bytes: Some(std::mem::take(&mut stage.bytes)),
                        };
                        stage.commit = Some(completion);
                        drop(state);
                        #[cfg(test)]
                        {
                            let hook = self.commit_hook.lock().clone();
                            if let Some(hook) = hook { hook(); }
                        }
                        let bytes = staged.bytes();
                        if bytes.get(12..28) != Some(upload.key.object_id.as_u128().to_le_bytes().as_slice())
                            || bytes.get(28..32) != Some(upload.count.to_le_bytes().as_slice())
                            || super::super::batch::key(upload.key.object_id, bytes) != upload.key
                        {
                            Err(SymbolStoreError::Identity)
                        } else {
                            self.store.put(peer, bytes)
                        }
                        // StagedCommit destroys its payload and retires its exact
                        // charge before receipt publication, including on error.
                    } else {
                        drop(state);
                        self.store.get(peer, upload.key).and_then(|batch| {
                            if batch.as_ref().as_ref().len() != upload.total || batch.symbol_count() != upload.count {
                                return Err(SymbolStoreError::Identity);
                            }
                            Ok(batch)
                        })
                    };
                    let batch = result?;
                    let mut bytes = upload.attempt.to_le_bytes().to_vec();
                    bytes.extend_from_slice(&receipt(self.store.replica_id(), &batch, now));
                    Ok(bytes)
                }
                ABORT => {
                    if body.len() != 68 { return Err(SymbolStoreError::TrailingData); }
                    if state.entries.get(&id).is_some_and(|stage| stage.upload != upload) { return Err(SymbolStoreError::Identity); }
                    state.remove(&id);
                    progress(upload, 0, self.limits.max_chunk_bytes)
                }
                _ => Err(SymbolStoreError::Format),
            };
        }
    }

    fn validate_upload(&self, upload: Upload) -> Result<(), SymbolStoreError> {
        if upload.count == 0 { return Err(SymbolStoreError::Empty); }
        if upload.total > self.store.batch_limits.max_encoded_bytes || upload.count as usize > self.store.batch_limits.max_symbols {
            return Err(SymbolStoreError::Limit("batch bytes or symbols"));
        }
        let minimum = (upload.count as usize).checked_mul(42).and_then(|bytes| bytes.checked_add(32))
            .ok_or(SymbolStoreError::Overflow)?;
        if upload.total < minimum { return Err(SymbolStoreError::Format); }
        Ok(())
    }

    fn read(&self, peer: &NodeId, body: &[u8]) -> Result<Vec<u8>, SymbolStoreError> {
        if body.len() != 60 { return Err(SymbolStoreError::Format); }
        let key = read_key(&body[..48])?;
        let offset = read_usize(&body[48..56])?;
        let requested = u32::from_le_bytes(body[56..60].try_into().expect("range bytes")) as usize;
        if requested == 0 { return Err(SymbolStoreError::Limit("range bytes")); }
        let batch = self.store.get(peer, key)?;
        let source = batch.as_ref().as_ref();
        if offset >= source.len() { return Err(SymbolStoreError::Format); }
        let length = requested.min(self.limits.max_chunk_bytes).min(source.len() - offset);
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(80usize.checked_add(length).ok_or(SymbolStoreError::Overflow)?)
            .map_err(|_| SymbolStoreError::Allocation)?;
        bytes.extend_from_slice(RANGE);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        put_key(&mut bytes, key);
        bytes.extend_from_slice(&(source.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&batch.symbol_count().to_le_bytes());
        bytes.extend_from_slice(&(offset as u64).to_le_bytes());
        bytes.extend_from_slice(&source[offset..offset + length]);
        Ok(bytes)
    }
}

struct RequestSchema;
struct ResponseSchema;
impl HasSchema for RequestSchema {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("asupersync.symbol-service.chunked.request.v1") }
}
impl HasSchema for ResponseSchema {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("asupersync.symbol-service.chunked.response.v1") }
}

/// Register a separately granted multi-frame capability in the existing V1 mTLS service.
/// The peer namespace is supplied only by authenticated invocation admission.
pub fn register_chunked_symbol_service(
    registry: &mut RemoteComputationRegistry, service: Arc<ChunkedSymbolService>,
) -> Result<(), ComputationSchemaRegistryError> {
    registry.register::<RequestSchema, ResponseSchema, _, _>(SYMBOL_CHUNKED_SERVICE_COMPUTATION, move |cx, invocation| {
        let service = Arc::clone(&service);
        async move {
            if cx.checkpoint().is_err() {
                return Ok(cx.cancel_reason().map_or_else(
                    || RemoteOutcome::Failed("chunked symbol checkpoint refused".to_owned()), RemoteOutcome::Cancelled,
                ));
            }
            Ok(match service.handle(invocation.peer_node(), cx.now(), invocation.request().input.data()) {
                Ok(bytes) => RemoteOutcome::Success(bytes),
                Err(error) => RemoteOutcome::Failed(error.to_string()),
            })
        }
    })
}

fn split_request<'a>(bytes: &'a [u8], replica: &str) -> Result<(u8, &'a [u8]), SymbolStoreError> {
    if bytes.len() < 14 || &bytes[..8] != MAGIC || bytes[8..12] != 1_u32.to_le_bytes() {
        return Err(SymbolStoreError::Format);
    }
    let n = usize::from(bytes[13]);
    if n == 0 || bytes.len() < 14 + n { return Err(SymbolStoreError::Truncated); }
    if &bytes[14..14+n] != replica.as_bytes() { return Err(SymbolStoreError::Identity); }
    Ok((bytes[12], &bytes[14+n..]))
}

#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
pub(crate) fn request(operation: u8, replica: &str, body: &[u8]) -> Result<Vec<u8>, SymbolStoreError> {
    if !super::super::valid_identity(replica) { return Err(SymbolStoreError::InvalidIdentity); }
    let size = body.len().checked_add(14 + replica.len()).ok_or(SymbolStoreError::Overflow)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| SymbolStoreError::Allocation)?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.push(operation);
    bytes.push(replica.len() as u8);
    bytes.extend_from_slice(replica.as_bytes());
    bytes.extend_from_slice(body);
    Ok(bytes)
}

pub(crate) fn upload_body(upload: Upload) -> Vec<u8> {
    let mut body = Vec::with_capacity(68);
    put_key(&mut body, upload.key);
    body.extend_from_slice(&upload.attempt.to_le_bytes());
    body.extend_from_slice(&(upload.total as u64).to_le_bytes());
    body.extend_from_slice(&upload.count.to_le_bytes());
    body
}

fn read_upload(bytes: &[u8]) -> Result<Upload, SymbolStoreError> {
    if bytes.len() != 68 { return Err(SymbolStoreError::Format); }
    Ok(Upload { key: read_key(&bytes[..48])?, attempt: u64::from_le_bytes(bytes[48..56].try_into().expect("attempt bytes")),
        total: read_usize(&bytes[56..64])?, count: u32::from_le_bytes(bytes[64..68].try_into().expect("count bytes")) })
}

pub(crate) fn read_usize(bytes: &[u8]) -> Result<usize, SymbolStoreError> {
    let value = u64::from_le_bytes(bytes.try_into().map_err(|_| SymbolStoreError::Format)?);
    usize::try_from(value).map_err(|_| SymbolStoreError::Overflow)
}

fn progress(upload: Upload, received: usize, maximum: usize) -> Result<Vec<u8>, SymbolStoreError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(92).map_err(|_| SymbolStoreError::Allocation)?;
    bytes.extend_from_slice(PROGRESS);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&upload_body(upload));
    bytes.extend_from_slice(&(received as u64).to_le_bytes());
    bytes.extend_from_slice(&(maximum as u32).to_le_bytes());
    Ok(bytes)
}

#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
pub(crate) fn read_progress(bytes: &[u8], upload: Upload) -> Result<(usize, usize), SymbolStoreError> {
    if bytes.len() != 92 || &bytes[..8] != PROGRESS || bytes[8..12] != 1_u32.to_le_bytes() {
        return Err(SymbolStoreError::Format);
    }
    if read_upload(&bytes[12..80])? != upload { return Err(SymbolStoreError::Identity); }
    let received = read_usize(&bytes[80..88])?;
    let maximum = u32::from_le_bytes(bytes[88..92].try_into().expect("chunk limit bytes")) as usize;
    if received > upload.total || maximum == 0 { return Err(SymbolStoreError::Format); }
    Ok((received, maximum))
}

#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
pub(crate) fn range_request(replica: &str, key: SymbolBatchKey, offset: usize, maximum: usize) -> Result<Vec<u8>, SymbolStoreError> {
    let mut body = Vec::with_capacity(60);
    put_key(&mut body, key);
    body.extend_from_slice(&(offset as u64).to_le_bytes());
    body.extend_from_slice(&u32::try_from(maximum).map_err(|_| SymbolStoreError::Overflow)?.to_le_bytes());
    request(READ, replica, &body)
}

#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
pub(crate) fn read_range(
    bytes: &[u8], key: SymbolBatchKey, offset: usize, maximum: usize,
) -> Result<(usize, u32, &[u8]), SymbolStoreError> {
    if bytes.len() <= 80 || &bytes[..8] != RANGE || bytes[8..12] != 1_u32.to_le_bytes() {
        return Err(SymbolStoreError::Format);
    }
    if read_key(&bytes[12..60])? != key || read_usize(&bytes[72..80])? != offset {
        return Err(SymbolStoreError::Identity);
    }
    let total = read_usize(&bytes[60..68])?;
    let count = u32::from_le_bytes(bytes[68..72].try_into().expect("count bytes"));
    let data = &bytes[80..];
    if data.len() > maximum || offset.checked_add(data.len()).is_none_or(|end| end > total) || count == 0 {
        return Err(SymbolStoreError::Format);
    }
    Ok((total, count, data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed::symbol_service::{EncodedSymbolBatch, SymbolBatchLimits, SymbolStoreLimits, encode_symbol_batch};
    use crate::security::{AuthKey, SecurityContext};
    use crate::types::symbol::{ObjectId, Symbol};

    fn fixture(seed: u64) -> EncodedSymbolBatch {
        let security = SecurityContext::new(AuthKey::from_seed(seed));
        let symbols = (0..3).map(|esi| security.sign_symbol(&Symbol::new_for_test(71, 0, esi, &[esi as u8; 128])))
            .collect::<Vec<_>>();
        encode_symbol_batch(&symbols, batch_limits()).unwrap()
    }

    fn batch_limits() -> SymbolBatchLimits {
        SymbolBatchLimits { max_encoded_bytes: 4096, max_symbols: 16, max_payload_bytes: 2048, max_decoded_bytes: 8192 }
    }

    fn make_service(max_uploads: usize, total: usize, per_peer: usize) -> ChunkedSymbolService {
        let store = Arc::new(SymbolReplicaStore::new("replica", AuthKey::from_seed(42), batch_limits(),
            SymbolStoreLimits { max_batches: 4, max_bytes: 16384, max_batches_per_peer: 2, max_bytes_per_peer: 8192 }).unwrap());
        ChunkedSymbolService::new(store,
            SymbolChunkedLimits::new(128, max_uploads, total, per_peer, total, Duration::from_nanos(100)).unwrap())
    }

    fn make_upload(batch: &EncodedSymbolBatch, attempt: u64) -> Upload {
        Upload { key: batch.key(), attempt, total: batch.as_ref().len(), count: batch.symbol_count() }
    }

    fn command(service: &ChunkedSymbolService, peer: &NodeId, now: u64, operation: u8, upload: Upload) -> Result<Vec<u8>, SymbolStoreError> {
        service.handle(peer, Time::from_nanos(now), &request(operation, "replica", &upload_body(upload)).unwrap())
    }

    fn piece(service: &ChunkedSymbolService, peer: &NodeId, now: u64, upload: Upload, offset: usize, data: &[u8]) -> Result<Vec<u8>, SymbolStoreError> {
        let mut body = upload_body(upload);
        body.extend_from_slice(&(offset as u64).to_le_bytes());
        body.extend_from_slice(data);
        service.handle(peer, Time::from_nanos(now), &request(CHUNK, "replica", &body).unwrap())
    }

    fn stage(service: &ChunkedSymbolService, peer: &NodeId, batch: &EncodedSymbolBatch, upload: Upload) {
        command(service, peer, 0, BEGIN, upload).unwrap();
        for (index, chunk) in batch.as_ref().chunks(128).enumerate() {
            piece(service, peer, 1, upload, index * 128, chunk).unwrap();
        }
    }


    struct CommitRelease(Option<std::sync::mpsc::Sender<()>>);

    impl CommitRelease {
        fn release(&mut self) {
            if let Some(sender) = self.0.take() { let _ = sender.send(()); }
        }
    }

    impl Drop for CommitRelease {
        fn drop(&mut self) { self.release(); }
    }

    fn pause_commit(
        service: &ChunkedSymbolService, panic_after_release: bool,
    ) -> (std::sync::mpsc::Receiver<()>, CommitRelease) {
        let (entered, reached) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let released = Mutex::new(released);
        *service.commit_hook.lock() = Some(Arc::new(move || {
            entered.send(()).expect("commit pause observer");
            released.lock().recv_timeout(Duration::from_secs(5)).expect("commit pause release");
            assert!(!panic_after_release, "injected commit verification panic");
        }));
        (reached, CommitRelease(Some(release)))
    }

    #[test]
    fn committing_upload_keeps_credit_without_blocking_other_peers() {
        let batch = fixture(42);
        let upload = make_upload(&batch, 1);
        let service = make_service(3, 3 * upload.total, 1);
        let alice = NodeId::new("alice");
        let bob = NodeId::new("bob");
        let expired = NodeId::new("expired");
        let reader = NodeId::new("reader");
        service.store.put(&reader, batch.as_ref()).unwrap();
        stage(&service, &alice, &batch, upload);
        command(&service, &expired, 0, BEGIN, upload).unwrap();
        command(&service, &bob, 50, BEGIN, upload).unwrap();

        std::thread::scope(|scope| {
            // This release guard lives inside the scope: a failed progress
            // assertion releases the owner before scoped threads are joined.
            let (reached, mut release) = pause_commit(&service, false);
            let service = &service;
            let alice = &alice;
            let bob = &bob;
            let reader = &reader;
            let batch = &batch;
            let commit = scope.spawn(move || command(service, alice, 2, COMMIT, upload));
            reached.recv_timeout(Duration::from_secs(5)).expect("commit reached verification");
            let (progressed, progress) = std::sync::mpsc::channel();
            let other = scope.spawn(move || {
                assert_eq!(service.stats(), SymbolStagingStats {
                    uploads: 3, reserved_bytes: 3 * upload.total, received_bytes: upload.total,
                });
                // Expiry must remove only the abandoned upload. The committing
                // allocation is still owned even after its original deadline.
                assert_eq!(service.reap_expired(Time::from_nanos(120)), 1);
                assert_eq!(service.stats().uploads, 2);
                assert_eq!(service.stats().reserved_bytes, 2 * upload.total);
                let reply = piece(service, bob, 120, upload, 0, &batch.as_ref()[..128]).unwrap();
                assert_eq!(read_progress(&reply, upload).unwrap(), (128, 128));
                let replay = command(service, bob, 121, BEGIN, upload).unwrap();
                assert_eq!(read_progress(&replay, upload).unwrap(), (128, 128));
                let read = service.handle(reader, Time::from_nanos(121),
                    &range_request("replica", upload.key, 0, 128).unwrap()).unwrap();
                let (total, count, bytes) = read_range(&read, upload.key, 0, 128).unwrap();
                assert_eq!((total, count), (upload.total, upload.count));
                assert_eq!(bytes, &batch.as_ref()[..128]);
                assert_eq!(command(service, alice, 122, BEGIN, Upload { attempt: 2, ..upload }),
                    Err(SymbolStoreError::Limit("peer staged uploads")));
                command(service, &NodeId::new("charlie"), 122, BEGIN, upload).unwrap();
                assert_eq!(command(service, &NodeId::new("david"), 122, BEGIN, upload),
                    Err(SymbolStoreError::Limit("staged uploads")));
                assert_eq!(service.stats(), SymbolStagingStats {
                    uploads: 3, reserved_bytes: 3 * upload.total, received_bytes: upload.total + 128,
                });
                assert!(matches!(service.store.get(alice, upload.key), Err(SymbolStoreError::NotFound)));
                progressed.send(()).expect("peer progress observer");
            });
            progress.recv_timeout(Duration::from_secs(5))
                .expect("other peers must progress while commit verification is held");
            release.release();
            let receipt = commit.join().expect("committing thread").expect("verified commit");
            super::super::validate_receipt(&receipt[8..], "replica", upload.key, upload.count).unwrap();
            other.join().expect("independent peer requests");
        });
        assert_eq!(service.stats(), SymbolStagingStats {
            uploads: 2, reserved_bytes: 2 * upload.total, received_bytes: 128,
        });
        assert_eq!(service.store.stats().batches, 2);
        assert_eq!(service.reap_expired(Time::from_nanos(222)), 2);
        assert_eq!(service.stats(), SymbolStagingStats { uploads: 0, reserved_bytes: 0, received_bytes: 0 });
    }

    #[test]
    fn duplicate_commit_and_abort_wait_for_exact_owner_and_wake_on_failure_or_panic() {
        for case in 0..3 {
            let batch = fixture(if case == 1 { 43 } else { 42 });
            let upload = make_upload(&batch, 1);
            let service = make_service(1, upload.total, 1);
            let peer = NodeId::new("origin");
            stage(&service, &peer, &batch, upload);
            std::thread::scope(|scope| {
                let (reached, mut release) = pause_commit(&service, case == 2);
                let service = &service;
                let peer = &peer;
                let owner = scope.spawn(move || std::panic::catch_unwind(
                    std::panic::AssertUnwindSafe(|| command(service, peer, 2, COMMIT, upload)),
                ));
                reached.recv_timeout(Duration::from_secs(5)).expect("owner reached verification");
                let completion = {
                    let state = service.staging.lock();
                    Arc::clone(state.entries[&(peer.clone(), upload.attempt)].commit.as_ref().unwrap())
                };
                let duplicate = scope.spawn(move || command(service, peer, 3, COMMIT, upload));
                let abort = scope.spawn(move || command(service, peer, 3, ABORT, upload));
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                // Map + owner + this witness + both requests prove that the
                // duplicate and abort have reached the real per-attempt wait.
                while Arc::strong_count(&completion) < 5 {
                    assert!(std::time::Instant::now() < deadline, "same-attempt requests did not park");
                    std::thread::yield_now();
                }
                assert!(!*completion.done.lock());
                assert_eq!(service.reap_expired(Time::from_nanos(200)), 0);
                assert_eq!(service.stats(), SymbolStagingStats {
                    uploads: 1, reserved_bytes: upload.total, received_bytes: upload.total,
                });
                release.release();
                let result = owner.join().expect("owner thread catch-unwind");
                match case {
                    0 => { result.expect("successful owner").expect("verified publication"); }
                    1 => { assert_eq!(result.expect("authentication refusal"), Err(SymbolStoreError::Authentication)); }
                    _ => { assert!(result.is_err(), "injected owner panic must be observed"); }
                }
                let replay = duplicate.join().expect("duplicate commit thread");
                if case == 0 {
                    let receipt = replay.expect("duplicate committed receipt");
                    super::super::validate_receipt(&receipt[8..], "replica", upload.key, upload.count).unwrap();
                } else {
                    assert_eq!(replay, Err(SymbolStoreError::NotFound));
                }
                let aborted = abort.join().expect("abort thread").expect("idempotent abort");
                assert_eq!(read_progress(&aborted, upload).unwrap(), (0, 128));
                assert!(*completion.done.lock());
            });
            assert_eq!(service.stats(), SymbolStagingStats { uploads: 0, reserved_bytes: 0, received_bytes: 0 });
            assert_eq!(service.store.stats().batches, usize::from(case == 0));
            *service.commit_hook.lock() = None;
            let healthy = fixture(42);
            let next = make_upload(&healthy, 2);
            let healthy_peer = NodeId::new("healthy");
            stage(&service, &healthy_peer, &healthy, next);
            command(&service, &healthy_peer, 3, COMMIT, next).expect("retired credit is reusable");
            assert_eq!(service.stats().reserved_bytes, 0);
        }
    }

    #[test]
    fn incomplete_upload_is_invisible_and_exact_replays_publish_once() {
        let batch = fixture(42);
        let upload = make_upload(&batch, 1);
        let service = make_service(1, batch.as_ref().len(), 1);
        let peer = NodeId::new("origin");
        let begin = command(&service, &peer, 0, BEGIN, upload).unwrap();
        assert_eq!(read_progress(&begin, upload).unwrap(), (0, 128));
        assert_eq!(service.stats().reserved_bytes, upload.total);
        assert_eq!(service.stats().received_bytes, 0);
        piece(&service, &peer, 1, upload, 0, &batch.as_ref()[..128]).unwrap();
        assert_eq!(command(&service, &peer, 2, COMMIT, upload), Err(SymbolStoreError::Truncated));
        assert_eq!(service.store.stats().batches, 0);
        let replay = piece(&service, &peer, 3, upload, 0, &batch.as_ref()[..128]).unwrap();
        assert_eq!(read_progress(&replay, upload).unwrap(), (128, 128));
        assert_eq!(service.stats().received_bytes, 128);
        assert_eq!(piece(&service, &peer, 3, upload, 256, &batch.as_ref()[256..384]), Err(SymbolStoreError::Conflict));
        assert_eq!(piece(&service, &peer, 3, upload, 0, &[9; 128]), Err(SymbolStoreError::Conflict));
        for (index, bytes) in batch.as_ref()[128..].chunks(128).enumerate() {
            piece(&service, &peer, 4, upload, 128 + index * 128, bytes).unwrap();
        }
        let committed = command(&service, &peer, 5, COMMIT, upload).unwrap();
        assert_eq!(&committed[..8], &upload.attempt.to_le_bytes());
        super::super::validate_receipt(&committed[8..], "replica", upload.key, upload.count).unwrap();
        assert_eq!(service.stats(), SymbolStagingStats { uploads: 0, reserved_bytes: 0, received_bytes: 0 });
        assert_eq!(service.store.stats().batches, 1);
        // No tombstone is needed: immutable exact-key storage handles repeat sends.
        let repeated = Upload { attempt: 9, ..upload };
        let begin = command(&service, &peer, 6, BEGIN, repeated).unwrap();
        assert_eq!(read_progress(&begin, repeated).unwrap().0, upload.total);
        command(&service, &peer, 7, COMMIT, repeated).unwrap();
        command(&service, &peer, 8, ABORT, repeated).unwrap();
        assert_eq!(service.store.stats().batches, 1);
    }

    #[test]
    fn staged_upload_is_allocated_once_whatever_the_chunk_size() {
        let batch = fixture(42);
        let upload = make_upload(&batch, 1);
        let service = make_service(1, batch.as_ref().len(), 1);
        let peer = NodeId::new("origin");
        command(&service, &peer, 0, BEGIN, upload).unwrap();
        let mut staged_at = None;
        for (offset, byte) in batch.as_ref().iter().enumerate() {
            let chunk = std::slice::from_ref(byte);
            piece(&service, &peer, 1, upload, offset, chunk).unwrap();
            let state = service.staging.lock();
            let staged = &state.entries[&(peer.clone(), upload.attempt)].bytes;
            let capacity = staged.capacity();
            assert!(
                capacity >= upload.total,
                "chunk at {offset}: capacity {capacity}"
            );
            let at = staged.as_ptr();
            assert_eq!(
                *staged_at.get_or_insert(at),
                at,
                "chunk at {offset} moved the staged bytes"
            );
        }
        command(&service, &peer, 2, COMMIT, upload).unwrap();
        assert_eq!(service.store.stats().batches, 1);
    }

    #[test]
    fn reservation_limits_origin_isolation_and_fixed_expiry_cannot_be_renewed_by_replay() {
        let batch = fixture(42);
        let first = make_upload(&batch, 1);
        let second = Upload { attempt: 2, ..first };
        let service = make_service(2, 2 * first.total, 1);
        let alice = NodeId::new("alice");
        let bob = NodeId::new("bob");
        command(&service, &alice, 0, BEGIN, first).unwrap();
        assert_eq!(command(&service, &alice, 0, BEGIN, second), Err(SymbolStoreError::Limit("peer staged uploads")));
        command(&service, &bob, 0, BEGIN, first).unwrap();
        assert_eq!(service.stats().reserved_bytes, 2 * first.total);
        assert_eq!(command(&service, &NodeId::new("charlie"), 1, BEGIN, first), Err(SymbolStoreError::Limit("staged uploads")));
        piece(&service, &alice, 50, first, 0, &batch.as_ref()[..128]).unwrap();
        command(&service, &alice, 99, BEGIN, first).unwrap();
        assert_eq!(service.reap_expired(Time::from_nanos(99)), 0);
        assert_eq!(service.reap_expired(Time::from_nanos(100)), 2);
        assert_eq!(service.stats().reserved_bytes, 0);
        assert_eq!(piece(&service, &alice, 101, first, 128, &batch.as_ref()[128..256]), Err(SymbolStoreError::NotFound));
        command(&service, &alice, 101, BEGIN, second).unwrap();
        // A different authenticated origin cannot remove Alice's staging.
        command(&service, &bob, 101, ABORT, second).unwrap();
        assert_eq!(service.stats().uploads, 1);
        command(&service, &alice, 102, ABORT, second).unwrap();
        assert_eq!(service.stats().uploads, 0);
        let tiny = make_service(2, first.total - 1, 2);
        assert_eq!(command(&tiny, &alice, 0, BEGIN, first), Err(SymbolStoreError::Limit("staged bytes")));
    }

    #[test]
    fn invalid_declared_identity_digest_count_or_authentication_never_publishes() {
        for case in 0..4 {
            let batch = fixture(if case == 3 { 43 } else { 42 });
            let mut upload = make_upload(&batch, 1);
            match case {
                0 => {
                    upload.key.object_id = ObjectId::from_u128(999);
                    upload.key = super::super::super::batch::key(upload.key.object_id, batch.as_ref());
                }
                1 => upload.key.digest[0] ^= 1,
                2 => upload.count += 1,
                _ => {}
            }
            let service = make_service(1, 4096, 1);
            let peer = NodeId::new("origin");
            stage(&service, &peer, &batch, upload);
            let result = command(&service, &peer, 2, COMMIT, upload);
            assert_eq!(result, Err(if case == 3 { SymbolStoreError::Authentication } else { SymbolStoreError::Identity }));
            assert_eq!(service.store.stats().batches, 0);
            assert_eq!(service.stats().reserved_bytes, 0);
            // A failed complete upload cannot leave the sole slot unusable.
            let healthy = fixture(42);
            let next = make_upload(&healthy, 2);
            stage(&service, &peer, &healthy, next);
            command(&service, &peer, 3, COMMIT, next).unwrap();
            assert_eq!(service.store.stats().batches, 1);
        }
    }

    #[test]
    fn range_reads_bound_each_frame_and_refuse_cross_origin_or_wrong_identity() {
        let batch = fixture(42);
        let service = make_service(1, 4096, 1);
        let peer = NodeId::new("origin");
        service.store.put(&peer, batch.as_ref()).unwrap();
        let mut bytes = Vec::new();
        while bytes.len() < batch.as_ref().len() {
            let response = service.handle(&peer, Time::ZERO, &range_request("replica", batch.key(), bytes.len(), 1000).unwrap()).unwrap();
            let (total, count, part) = read_range(&response, batch.key(), bytes.len(), 128).unwrap();
            assert_eq!((total, count), (batch.as_ref().len(), batch.symbol_count()));
            assert!(part.len() <= 128);
            bytes.extend_from_slice(part);
        }
        assert_eq!(bytes, batch.as_ref());
        let request = range_request("replica", batch.key(), 0, 128).unwrap();
        assert_eq!(service.handle(&NodeId::new("other"), Time::ZERO, &request), Err(SymbolStoreError::NotFound));
        let mut wrong = batch.key(); wrong.digest[0] ^= 1;
        assert_eq!(service.handle(&peer, Time::ZERO, &range_request("replica", wrong, 0, 128).unwrap()), Err(SymbolStoreError::NotFound));
        assert_eq!(service.handle(&peer, Time::ZERO, &range_request("replica", batch.key(), bytes.len(), 128).unwrap()), Err(SymbolStoreError::Format));
        assert_eq!(service.stats().uploads, 0);
    }

    #[test]
    fn malformed_target_attempt_and_progress_cannot_mutate_or_satisfy_upload() {
        let batch = fixture(42);
        let upload = make_upload(&batch, 1);
        let service = make_service(1, 4096, 1);
        let peer = NodeId::new("origin");
        let wrong_target = request(BEGIN, "different", &upload_body(upload)).unwrap();
        assert_eq!(service.handle(&peer, Time::ZERO, &wrong_target), Err(SymbolStoreError::Identity));
        assert_eq!(service.stats().uploads, 0);
        let begun = command(&service, &peer, 0, BEGIN, upload).unwrap();
        let different = Upload { count: upload.count + 1, ..upload };
        assert_eq!(command(&service, &peer, 1, BEGIN, different), Err(SymbolStoreError::Conflict));
        assert_eq!(command(&service, &peer, 1, ABORT, different), Err(SymbolStoreError::Identity));
        assert_eq!(read_progress(&begun, Upload { attempt: 2, ..upload }), Err(SymbolStoreError::Identity));
        assert_eq!(piece(&service, &peer, 1, upload, 0, &[0; 129]), Err(SymbolStoreError::Limit("chunk bytes")));
        assert_eq!(service.stats().received_bytes, 0);
        assert!(SymbolChunkedLimits::new(0, 1, 1, 1, 1, Duration::from_secs(1)).is_err());
        assert!(SymbolChunkedLimits::new(1, 1, 1, 1, 1, Duration::ZERO).is_err());
    }
}
