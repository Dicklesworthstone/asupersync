//! Authenticated, bounded immutable symbol batches for remote replica storage.
//!
//! This is storage of encoded symbols, not resurrection of Rust futures or proof
//! of durable storage. Entries are retained until the store is dropped: no silent
//! eviction, overwrite, or disk/network effect. Each authenticated origin owns a
//! separate object namespace. Remote adapters must obtain the origin from their
//! admitted session, never an origin string supplied inside the request payload.

mod batch;
pub use batch::{
    EncodedSymbolBatch, SymbolBatchKey, SymbolBatchLimits, SymbolStoreError,
    decode_symbol_batch, encode_symbol_batch,
};
use crate::remote::NodeId;
use crate::security::AuthKey;
use crate::types::symbol::ObjectId;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

/// Independent aggregate/per-origin storage bounds. Zero deliberately denies writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolStoreLimits {
    /// Total distinct (origin, object) batches retained.
    pub max_batches: usize,
    /// Sum of retained canonical encoded lengths.
    pub max_bytes: usize,
    /// Distinct objects retained for any one origin.
    pub max_batches_per_peer: usize,
    /// Encoded bytes retained for any one origin.
    pub max_bytes_per_peer: usize,
}

/// Retained storage only, not transient service frames, decoded reads, or allocator overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolStoreStats {
    /// Retained immutable batches.
    pub batches: usize,
    /// Retained encoded bytes.
    pub bytes: usize,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<(NodeId, ObjectId), Arc<EncodedSymbolBatch>>,
    bytes: usize,
}

/// Replica-local verified storage with atomic admission and immutable object keys.
///
/// Repeating identical bytes is idempotent even at full capacity. Reusing an
/// origin/object identity for different bytes fails; new snapshots require a new
/// object identity. No eviction API means a retained acknowledgement is not
/// silently invalidated by capacity pressure. This is IN-MEMORY retention, not a
/// durable receipt. Peer/object/map overhead is count-bounded; payloads are byte-
/// bounded. Concurrent verification and response buffers must additionally be
/// bounded by the owning service's connection/frame admission policy.
pub struct SymbolReplicaStore {
    replica: String,
    auth_key: AuthKey,
    batch_limits: SymbolBatchLimits,
    limits: SymbolStoreLimits,
    state: Mutex<State>,
}

impl fmt::Debug for SymbolReplicaStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolReplicaStore").field("stats", &self.stats()).finish_non_exhaustive()
    }
}

fn valid_identity(value: &str) -> bool { !value.is_empty() && value.len() <= 255 }

impl SymbolReplicaStore {
    /// Construct storage with explicit key and bounds. No ambient authority is acquired.
    pub fn new(
        replica: impl Into<String>, auth_key: AuthKey,
        batch_limits: SymbolBatchLimits, limits: SymbolStoreLimits,
    ) -> Result<Self, SymbolStoreError> {
        let replica = replica.into();
        if !valid_identity(&replica) { return Err(SymbolStoreError::InvalidIdentity); }
        Ok(Self { replica, auth_key, batch_limits, limits, state: Mutex::new(State::default()) })
    }

    /// Configured receiver identity used in its acknowledgements.
    #[must_use]
    pub fn replica_id(&self) -> &str { &self.replica }

    /// Retained storage at this instant. Read handles share, rather than copy, bytes.
    #[must_use]
    pub fn stats(&self) -> SymbolStoreStats {
        let state = self.state.lock();
        SymbolStoreStats { batches: state.entries.len(), bytes: state.bytes }
    }

    /// Verify and retain a complete batch in an already-authenticated origin namespace.
    ///
    /// `peer` is a local authority parameter; this method cannot authenticate a
    /// string. Network users must use certificate-bound remote-service admission.
    /// Every tag is verified outside the mutex. Publication, deduplication and
    /// both capacity checks are atomic; failed writes leave existing data intact.
    /// An allocation/verification buffer is per-call bounded, separately from the
    /// retained-storage ceilings. Dropping a failed call never removes old entries.
    pub fn put(&self, peer: &NodeId, bytes: &[u8]) -> Result<Arc<EncodedSymbolBatch>, SymbolStoreError> {
        if !valid_identity(peer.as_str()) { return Err(SymbolStoreError::InvalidIdentity); }
        let batch = batch::verified_bytes(bytes, &self.auth_key, self.batch_limits)?;
        let id = (peer.clone(), batch.key().object_id);
        let mut state = self.state.lock();
        if let Some(existing) = state.entries.get(&id) {
            return if existing.as_ref().as_ref() == bytes { Ok(Arc::clone(existing)) }
                else { Err(SymbolStoreError::Conflict) };
        }
        if state.entries.len() >= self.limits.max_batches { return Err(SymbolStoreError::Limit("batches")); }
        let total = state.bytes.checked_add(bytes.len()).ok_or(SymbolStoreError::Overflow)?;
        if total > self.limits.max_bytes { return Err(SymbolStoreError::Limit("stored bytes")); }
        let (peer_count, peer_bytes) = state.entries.iter()
            .filter(|((origin, _), _)| origin == peer)
            .fold((0usize, 0usize), |(count, size), (_, entry)| (count + 1, size + entry.as_ref().as_ref().len()));
        if peer_count >= self.limits.max_batches_per_peer { return Err(SymbolStoreError::Limit("peer batches")); }
        let peer_total = peer_bytes.checked_add(bytes.len()).ok_or(SymbolStoreError::Overflow)?;
        if peer_total > self.limits.max_bytes_per_peer { return Err(SymbolStoreError::Limit("peer bytes")); }
        let batch = Arc::new(batch);
        state.entries.insert(id, Arc::clone(&batch));
        state.bytes = total;
        Ok(batch)
    }

    /// Read an exact batch only from its authenticated origin's namespace.
    /// Returned owners keep bytes alive without duplicating the store allocation.
    pub fn get(&self, peer: &NodeId, key: SymbolBatchKey) -> Result<Arc<EncodedSymbolBatch>, SymbolStoreError> {
        if !valid_identity(peer.as_str()) { return Err(SymbolStoreError::InvalidIdentity); }
        let state = self.state.lock();
        state.entries.get(&(peer.clone(), key.object_id))
            .filter(|batch| batch.key() == key)
            .map(Arc::clone).ok_or(SymbolStoreError::NotFound)
    }
}

#[cfg(test)]
mod tests;

mod service;
pub use service::{SYMBOL_SERVICE_COMPUTATION, register_symbol_service};

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
mod native;
#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
pub use native::{RemoteSymbolError, RemoteSymbolTransport};

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
pub use native::recovery;

#[cfg(not(target_arch = "wasm32"))]
pub mod durable;

#[cfg(not(target_arch = "wasm32"))]
pub use service::{DurableSymbolServiceHandle, register_durable_symbol_service};

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
pub use native::checkpoint;
