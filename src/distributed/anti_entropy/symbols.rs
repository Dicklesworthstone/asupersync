//! Authenticated-origin catalogs of actually retained immutable symbol batches.

use super::catalog::{Catalog, CatalogEntry, CatalogError, CatalogLimits, add, label};
use super::wire;
use crate::distributed::{ComputationSchemaRegistryError, HasSchema, SchemaDescriptor};
use crate::distributed::symbol_service::{SymbolBatchKey, SymbolReplicaStore, SymbolStoreError};
use crate::remote::{NodeId, RemoteComputationRegistry, RemoteOutcome};
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

/// Separately granted, versioned application capability for catalog reads.
pub const SYMBOL_CATALOG_COMPUTATION: &str = "asupersync.distributed.symbol-catalog.v1";

/// Capture one atomic origin namespace from verified in-memory storage.
///
/// Batch values remain in the store; only object IDs, full content digests and
/// encoded lengths are copied. Later stores do not mutate this snapshot. The
/// temporary metadata cut is separately bounded by `max_entries` and by the
/// retained-byte ceiling; the resulting catalog applies all of its own limits.
pub fn capture_symbol_catalog(store: &SymbolReplicaStore, origin: NodeId, revision: u64,
    limits: CatalogLimits) -> Result<Catalog, CatalogError>
{
    let leaves = limits.validate()?;
    if limits.max_key_bytes < 16 || !label(origin.as_str()) { return Err(CatalogError::Configuration); }
    let tree_bytes = add((leaves + 1).checked_mul(std::mem::size_of::<usize>()).ok_or(CatalogError::Overflow)?,
        (leaves * 2).checked_mul(std::mem::size_of::<[u8; 32]>()).ok_or(CatalogError::Overflow)?)?;
    let entry_budget = limits.max_retained_bytes.checked_sub(tree_bytes).ok_or(CatalogError::Limit("retained bytes"))?;
    let maximum = limits.max_entries.min(limits.max_total_key_bytes / 16)
        .min(limits.max_retained_bytes / std::mem::size_of::<(SymbolBatchKey, usize)>())
        .min(entry_budget / (std::mem::size_of::<CatalogEntry>() + 16));
    let snapshot = store.catalog_entries(&origin, maximum).map_err(store_error)?;
    let mut entries = Vec::new();
    entries.try_reserve_exact(snapshot.len()).map_err(|_| CatalogError::Allocation)?;
    let mut retained = entries.capacity().checked_mul(std::mem::size_of::<CatalogEntry>()).ok_or(CatalogError::Overflow)?;
    if retained > entry_budget { return Err(CatalogError::Limit("retained bytes")); }
    for (key, bytes) in snapshot {
        if add(retained, 16)? > entry_budget { return Err(CatalogError::Limit("retained bytes")); }
        let mut object = Vec::new();
        object.try_reserve_exact(16).map_err(|_| CatalogError::Allocation)?;
        retained = add(retained, object.capacity())?;
        if retained > entry_budget { return Err(CatalogError::Limit("retained bytes")); }
        object.extend_from_slice(&key.object_id.as_u128().to_le_bytes());
        entries.push(CatalogEntry { key: object, value_hash: key.digest, value_bytes: bytes as u64 });
    }
    Catalog::new(origin, revision, entries, limits)
}

fn store_error(error: SymbolStoreError) -> CatalogError {
    match error {
        SymbolStoreError::Allocation => CatalogError::Allocation,
        SymbolStoreError::Overflow => CatalogError::Overflow,
        SymbolStoreError::Limit(_) => CatalogError::Limit("store catalog"),
        _ => CatalogError::Configuration,
    }
}

struct Catalogs { entries: BTreeMap<NodeId, Arc<Catalog>>, bytes: usize }

/// A bounded set of immutable catalogs behind authenticated remote admission.
///
/// Request payloads cannot select an origin. Only the admitted invocation peer
/// selects its catalog, even when another catalog's snapshot ID is known.
/// Publishing a newer local snapshot changes future reads atomically; readers
/// already encoding a page retain their immutable snapshot. Frame/connection
/// admission separately bounds those transient readers and response buffers.
pub struct SymbolCatalogService {
    replica: String,
    max_origins: usize,
    max_catalog_bytes: usize,
    catalogs: RwLock<Catalogs>,
}

impl fmt::Debug for SymbolCatalogService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.catalogs.read();
        f.debug_struct("SymbolCatalogService").field("origins", &state.entries.len())
            .field("catalog_bytes", &state.bytes).finish_non_exhaustive()
    }
}

impl SymbolCatalogService {
    /// Create empty publication slots. No peer grant, socket or I/O is acquired.
    pub fn new(replica: impl Into<String>, max_origins: usize, max_catalog_bytes: usize)
        -> Result<Self, CatalogError>
    {
        let replica = replica.into();
        if !label(&replica) { return Err(CatalogError::Configuration); }
        Ok(Self { replica, max_origins, max_catalog_bytes,
            catalogs: RwLock::new(Catalogs { entries: BTreeMap::new(), bytes: 0 }) })
    }

    /// Publish an independently captured catalog. An identical repeat is
    /// idempotent; replacing a snapshot requires a strictly larger revision.
    /// Limits apply to the currently published catalogs, excluding caller-held
    /// owners and the bounded transient readers described on this type.
    pub fn publish(&self, catalog: Arc<Catalog>) -> Result<(), CatalogError> {
        let mut state = self.catalogs.write();
        let previous = state.entries.get(catalog.origin());
        if let Some(previous) = previous {
            if previous.snapshot_id() == catalog.snapshot_id() { return Ok(()); }
            if catalog.revision() <= previous.revision() { return Err(CatalogError::SnapshotChanged); }
        } else if state.entries.len() >= self.max_origins { return Err(CatalogError::Limit("catalog origins")); }
        let old = previous.map_or(0, |previous| previous.retained_bytes());
        let bytes = add(state.bytes - old, catalog.retained_bytes())?;
        if bytes > self.max_catalog_bytes { return Err(CatalogError::Limit("catalog bytes")); }
        state.entries.insert(catalog.origin().clone(), catalog);
        state.bytes = bytes;
        Ok(())
    }

    fn handle(&self, peer: &NodeId, input: &[u8]) -> Result<Vec<u8>, CatalogError> {
        let catalog = self.catalogs.read().entries.get(peer).cloned().ok_or(CatalogError::Unauthorized)?;
        wire::serve(&catalog, &self.replica, input)
    }
}

struct CatalogRequest;
struct CatalogResponse;
impl HasSchema for CatalogRequest {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("asupersync.symbol-catalog.request.canonical-binary.v1") }
}
impl HasSchema for CatalogResponse {
    fn schema() -> SchemaDescriptor { SchemaDescriptor::primitive("asupersync.symbol-catalog.response.canonical-binary.v1") }
}

/// Install the catalog capability in an existing registry. Separately grant it
/// through certificate-bound service admission. No V1/V2/V3 envelope changes.
pub fn register_symbol_catalog_service(registry: &mut RemoteComputationRegistry,
    service: Arc<SymbolCatalogService>) -> Result<(), ComputationSchemaRegistryError>
{
    registry.register::<CatalogRequest, CatalogResponse, _, _>(SYMBOL_CATALOG_COMPUTATION,
        move |cx, invocation| {
            let service = Arc::clone(&service);
            async move {
                if cx.checkpoint().is_err() {
                    return Ok(cx.cancel_reason().map_or_else(
                        || RemoteOutcome::Failed("catalog checkpoint refused".to_owned()), RemoteOutcome::Cancelled));
                }
                Ok(match service.handle(invocation.peer_node(), invocation.request().input.data()) {
                    Ok(bytes) => RemoteOutcome::Success(bytes),
                    Err(error) => RemoteOutcome::Failed(error.to_string()),
                })
            }
        })
}

#[cfg(test)]
mod tests;
