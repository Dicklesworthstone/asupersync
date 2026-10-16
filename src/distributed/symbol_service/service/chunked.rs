//! Bounded multi-frame transfer inside the existing authenticated V1 service.

use super::{put_key, read_key, receipt};
use crate::distributed::symbol_service::{
    EncodedSymbolBatch, SymbolBatchKey, SymbolBatchLimits, SymbolReplicaStore, SymbolStoreError,
};
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

    #[cfg(not(target_arch = "wasm32"))]
    pub(super) const fn max_uploads(self) -> usize { self.max_uploads }
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
    // Identity changes whenever a commit marker retires. BEGIN retains an Arc
    // while looking outside the lock, so generation reuse/overflow cannot turn
    // a stale NotFound into permission to stage an already committed attempt.
    commit_generation: Arc<()>,
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
                state.commit_generation = Arc::new(());
            }
        }
        self.completion.finish();
    }
}

// A durable backend is only constructed by DurableChunkedSymbolService, whose
// registration dispatches every operation through a Cx-owned blocking worker.
// The public in-memory constructor and registration retain their existing path.
enum ChunkedBackend {
    Memory(Arc<SymbolReplicaStore>),
    #[cfg(not(target_arch = "wasm32"))]
    Durable(Arc<super::super::durable::DurableSymbolReplicaStore>),
}

impl ChunkedBackend {
    fn replica_id(&self) -> &str {
        match self {
            Self::Memory(store) => store.replica_id(),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Durable(store) => store.replica_id(),
        }
    }

    fn batch_limits(&self) -> SymbolBatchLimits {
        match self {
            Self::Memory(store) => store.batch_limits,
            #[cfg(not(target_arch = "wasm32"))]
            Self::Durable(store) => store.batch_limits(),
        }
    }

    fn get(&self, peer: &NodeId, key: SymbolBatchKey) -> Result<Arc<EncodedSymbolBatch>, SymbolStoreError> {
        match self {
            Self::Memory(store) => store.get(peer, key),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Durable(store) => {
                use super::super::durable::{DurableSymbolError, JournalStatus};
                match store.get(peer, key) {
                    Err(DurableSymbolError::Store(SymbolStoreError::NotFound))
                        if store.status() != JournalStatus::Writable =>
                    {
                        // Existing committed objects remain readable/replayable,
                        // but a partial-tail journal cannot admit a new upload.
                        Err(SymbolStoreError::StorageUnavailable)
                    }
                    result => result.map_err(durable_error),
                }
            }
        }
    }

    fn put(&self, peer: &NodeId, bytes: &[u8]) -> Result<Arc<EncodedSymbolBatch>, SymbolStoreError> {
        match self {
            Self::Memory(store) => store.put(peer, bytes),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Durable(store) => store.put(peer, bytes).map_err(durable_error),
        }
    }

    #[cfg(test)]
    fn stats(&self) -> super::super::SymbolStoreStats {
        match self {
            Self::Memory(store) => store.stats(),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Durable(store) => store.stats(),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn durable_error(error: super::super::durable::DurableSymbolError) -> SymbolStoreError {
    use super::super::durable::DurableSymbolError;
    match error {
        DurableSymbolError::Store(error) => error,
        DurableSymbolError::JournalLimit => SymbolStoreError::Limit("journal bytes"),
        _ => SymbolStoreError::StorageUnavailable,
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
    store: ChunkedBackend,
    limits: SymbolChunkedLimits,
    staging: Mutex<Staging>,
    #[cfg(test)]
    pub(super) commit_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    lookup_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
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
        Self::with_backend(ChunkedBackend::Memory(store), limits)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn new_durable(
        store: Arc<super::super::durable::DurableSymbolReplicaStore>, limits: SymbolChunkedLimits,
    ) -> Self {
        Self::with_backend(ChunkedBackend::Durable(store), limits)
    }

    fn with_backend(store: ChunkedBackend, limits: SymbolChunkedLimits) -> Self {
        Self { store, limits, staging: Mutex::new(Staging::default()),
            #[cfg(test)]
            commit_hook: Mutex::new(None),
            #[cfg(test)]
            lookup_hook: Mutex::new(None),
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

    // A legitimate CHUNK has the target header, 68-byte upload identity,
    // 8-byte offset, and at most the smaller chunk/batch allowance. BEGIN,
    // COMMIT, ABORT and READ are shorter. Saturation at the address-space
    // ceiling is conservative: no Rust slice can exceed that ceiling.
    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn request_byte_ceiling(&self) -> usize {
        14usize.saturating_add(self.store.replica_id().len())
            .saturating_add(76)
            .saturating_add(self.limits.max_chunk_bytes.min(self.store.batch_limits().max_encoded_bytes))
    }

    pub(super) fn handle(&self, peer: &NodeId, now: Time, input: &[u8]) -> Result<Vec<u8>, SymbolStoreError> {
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
        let mut committed = None;
        loop {
            if let Some(completion) = state.entries.get(&id).and_then(|stage| stage.commit.clone()) {
                // Preserve the original per-attempt ordering without holding up
                // every origin. In-memory owners are bounded synchronous work;
                // durable owners and their waiters run on blocking workers.
                // Unwinding also wakes every request for this exact owner.
                drop(state);
                completion.wait();
                state = self.staging.lock();
                state.reap(now);
                committed = None;
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
                    if committed.is_none() {
                        // A durable lookup can wait behind another writer's
                        // fsync. Never retain the staging mutex while waiting:
                        // independent chunks, aborts, stats and expiry must
                        // remain available. Recheck this exact attempt after
                        // reacquiring the lock; another BEGIN may have won.
                        let generation = Arc::clone(&state.commit_generation);
                        drop(state);
                        let found = self.store.get(peer, upload.key);
                        #[cfg(test)]
                        {
                            let hook = self.lookup_hook.lock().clone();
                            if let Some(hook) = hook { hook(); }
                        }
                        state = self.staging.lock();
                        state.reap(now);
                        if Arc::ptr_eq(&generation, &state.commit_generation) {
                            committed = Some(found);
                        }
                        continue;
                    }
                    match committed.take().expect("committed lookup precedes new staging") {
                        Ok(batch) => {
                            if batch.as_ref().as_ref().len() != upload.total || batch.symbol_count() != upload.count {
                                return Err(SymbolStoreError::Identity);
                            }
                            return progress(upload, upload.total, self.limits.max_chunk_bytes);
                        }
                        Err(SymbolStoreError::NotFound) => {}
                        Err(error) => return Err(error),
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
        let limits = self.store.batch_limits();
        if upload.total > limits.max_encoded_bytes || upload.count as usize > limits.max_symbols {
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

pub(super) struct RequestSchema;
pub(super) struct ResponseSchema;
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
#[path = "chunked_inline_tests.rs"]
mod tests;
