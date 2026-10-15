//! Bounded native catalog traversal with verified repair into retained storage.
//!
//! Metadata runs through the caller's ordinary region-owned remote capability
//! (`NativeRemoteRuntime` in production). Values use the existing authenticated
//! symbol transport. Each step owns at most one remote call/fetch at a time.
//! Configure the native route's frame/session limits independently: catalog
//! bounds do not replace the remote transport's pre-decode admission policy.
//!
//! Publish an explicit `capture_symbol_catalog` cut in `SymbolCatalogService`,
//! register its separately granted computation, and provision a V3 metadata
//! route. The existing symbol adapter uses a V1 endpoint for validated values;
//! both endpoints must authenticate the original origin and identify the same
//! configured source. This adds application frames, not a new remote envelope.
//! Start one cursor and call `step` until its progress is complete. A changed
//! source snapshot requires a new cursor; completed immutable puts remain valid.
//!
//! A cursor retains one local catalog, one leaf page (each independently bounded
//! by the catalog retained-byte ceiling), and at most `depth + 1` frontier nodes.
//! RPC response and batch buffers have their separate frame/codec bounds. A step
//! borrowing an existing symbol transport observes both its own cancellation and
//! deadline and those of that transport's original owner.

use super::catalog::{Catalog, CatalogEntry, CatalogError, CatalogLimits, Hash, add, label};
use super::symbols::{SYMBOL_CATALOG_COMPUTATION, capture_symbol_catalog};
use super::wire::{self, Page, Root};
use crate::cx::{ChildRegionSpec, Cx};
use crate::distributed::remote_owned::{RemoteRunConfig, run_remote};
use crate::distributed::symbol_service::{RemoteSymbolError, RemoteSymbolTransport,
    SymbolBatchKey, SymbolReplicaStore, SymbolStoreError, encode_symbol_batch};
use crate::remote::{ComputationName, NodeId, RemoteInput, RemoteOutcome};
use crate::types::{Outcome, symbol::ObjectId};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// Immutable per-cursor resource policy; no unbounded defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolRepairLimits {
    /// Same exact tree/page policy used by the source catalog.
    pub catalog: CatalogLimits,
    /// ROOT refresh plus NODE calls per step; at least two.
    pub max_catalog_requests_per_step: usize,
    /// Examined pending values per step, including concurrently present values.
    pub max_repairs_per_step: usize,
    /// Sum of reserved canonical batch ceilings for fetches in one step. Each
    /// fetch reserves its transport's complete bound before dispatch, so an
    /// untruthful catalog length cannot spend another fetch's byte allowance.
    pub max_bytes_per_step: usize,
    /// Sum of successfully published canonical lengths across the whole cursor.
    pub max_total_repair_bytes: usize,
    /// Maximum one value. The supplied symbol transport's batch limit must fit.
    pub max_batch_bytes: usize,
    /// Deadline for each region-owned catalog invocation. Transport lease/drain
    /// policy still governs an unreachable peer and cancellation cleanup.
    pub request_timeout: Duration,
}

/// Refusal never implies rollback of earlier verified, idempotent publications.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SymbolRepairError {
    /// Catalog, cursor, identity or resource validation failed.
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    /// Both transports must use the configured original authenticated origin.
    #[error("symbol repair requires matching origin and remote authority")]
    Authority,
    /// The current step's owner requested cancellation. Retain the cursor and
    /// resume with a fresh authorized context/transport after draining this call.
    #[error("symbol repair owner cancelled")]
    Cancelled,
    /// The region-owned metadata invocation did not finish successfully.
    #[error("symbol catalog remote invocation refused")]
    Remote,
    /// Existing authenticated symbol fetch refused or failed.
    #[error(transparent)]
    Fetch(#[from] RemoteSymbolError),
    /// Existing immutable store refused the validated value.
    #[error(transparent)]
    Store(#[from] SymbolStoreError),
}

/// Cumulative progress for one exact source snapshot, not a claim of latest state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolRepairProgress {
    /// Origin/revision/limits-bound immutable source snapshot.
    pub source_snapshot: [u8; 32],
    /// Every divergent subtree and its missing values has been processed.
    pub complete: bool,
    /// Authenticated branch/leaf responses actually validated.
    pub visited_nodes: usize,
    /// Missing values fetched, validated and confirmed by `SymbolReplicaStore::put`.
    /// A concurrent identical insertion can make that put an idempotent repeat.
    pub repaired_batches: usize,
    /// Canonical bytes confirmed by those publications.
    pub repaired_bytes: usize,
    /// Individually examined values already present with the exact identity.
    /// Whole equal subtrees are skipped without enumerating their value count.
    pub already_present: usize,
}

/// Opaque, non-cloneable in-process continuation.
///
/// Contains only bounded metadata and one bounded pending leaf; no socket,
/// future, Cx or encoded value is retained. It is bound to its originating
/// client, namespace, source snapshot and limits.
pub struct SymbolRepairCursor {
    owner: Arc<()>,
    source: Root,
    local: Catalog,
    frontier: Vec<(u32, Hash)>,
    pending: Vec<CatalogEntry>,
    next: usize,
    seen_entries: usize,
    seen_key_bytes: usize,
    visited_nodes: usize,
    repaired_batches: usize,
    repaired_bytes: usize,
    already_present: usize,
}

impl fmt::Debug for SymbolRepairCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolRepairCursor").field("progress", &self.progress()).finish_non_exhaustive()
    }
}

impl SymbolRepairCursor {
    /// Read progress without advancing, consuming or resetting the continuation.
    #[must_use]
    pub fn progress(&self) -> SymbolRepairProgress {
        SymbolRepairProgress { source_snapshot: self.source.snapshot,
            complete: self.frontier.is_empty() && self.next == self.pending.len(),
            visited_nodes: self.visited_nodes, repaired_batches: self.repaired_batches,
            repaired_bytes: self.repaired_bytes, already_present: self.already_present }
    }
}

/// One-way repair from a provisioned source into an origin's local retained store.
///
/// Local-only values remain present; different content for one immutable object
/// refuses. This does not delete data, elect a source, trigger on partitions,
/// persist cursors, repair durable journals or claim distributed atomicity.
/// Clone this client to retain its identity; a separately constructed client
/// cannot consume its cursor even if labels and limits happen to match.
#[derive(Clone)]
pub struct SymbolRepairClient {
    identity: Arc<()>,
    origin: NodeId,
    source: NodeId,
    destination: Arc<SymbolReplicaStore>,
    limits: SymbolRepairLimits,
}

impl fmt::Debug for SymbolRepairClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolRepairClient").field("limits", &self.limits).finish_non_exhaustive()
    }
}

impl SymbolRepairClient {
    /// Bind labels, a local destination and finite work allowances. This grants
    /// no network capability and performs no I/O or catalog capture.
    pub fn new(origin: NodeId, source: NodeId, destination: Arc<SymbolReplicaStore>, limits: SymbolRepairLimits)
        -> Result<Self, SymbolRepairError>
    {
        limits.catalog.validate()?;
        if !label(origin.as_str()) || !label(source.as_str()) || limits.catalog.max_key_bytes < 16
            || limits.max_catalog_requests_per_step < 2 || limits.max_repairs_per_step == 0
            || limits.max_batch_bytes == 0 || limits.max_bytes_per_step < limits.max_batch_bytes
            || limits.request_timeout.is_zero()
        { return Err(CatalogError::Configuration.into()); }
        Ok(Self { identity: Arc::new(()), origin, source, destination, limits })
    }

    fn check_owner(&self, cx: &Cx) -> Result<(), SymbolRepairError> {
        if cx.checkpoint().is_err() { return Err(SymbolRepairError::Cancelled); }
        if cx.remote().is_none_or(|cap| cap.local_node() != &self.origin || cap.runtime().is_none()) {
            return Err(SymbolRepairError::Authority);
        }
        Ok(())
    }

    async fn query(&self, cx: &Cx, node: Option<(Hash, u32)>) -> Result<Vec<u8>, SymbolRepairError> {
        self.check_owner(cx)?;
        let input = wire::request(self.source.as_str(), node)?;
        let report = run_remote(cx, self.source.clone(), ComputationName::new(SYMBOL_CATALOG_COMPUTATION),
            RemoteInput::new(input), RemoteRunConfig { timeout: self.limits.request_timeout,
                child: ChildRegionSpec::inherit() }).await;
        self.check_owner(cx)?;
        let report = report.map_err(|_| SymbolRepairError::Remote)?;
        if !report.is_success() { return Err(SymbolRepairError::Remote); }
        let reply = report.task.map_err(|_| SymbolRepairError::Remote)?;
        match reply.outcome {
            Outcome::Ok(RemoteOutcome::Success(bytes)) => {
                if bytes.len() > self.limits.catalog.max_response_bytes {
                    return Err(CatalogError::Limit("response bytes").into());
                }
                Ok(bytes)
            }
            _ => Err(SymbolRepairError::Remote),
        }
    }

    /// Bind a source snapshot and capture one atomic destination metadata cut.
    /// The Cx must carry the original origin and an attached remote runtime.
    pub async fn start(&self, cx: &Cx) -> Result<SymbolRepairCursor, SymbolRepairError> {
        self.check_owner(cx)?;
        let bytes = self.query(cx, None).await?;
        let source = wire::root(&bytes, &self.origin, self.limits.catalog)?;
        drop(bytes);
        self.check_owner(cx)?;
        let local = capture_symbol_catalog(&self.destination, self.origin.clone(), 0, self.limits.catalog)?;
        let mut frontier = Vec::new();
        let maximum = usize::from(self.limits.catalog.depth) + 1;
        frontier.try_reserve_exact(maximum).map_err(|_| CatalogError::Allocation)?;
        if frontier.capacity() > maximum { return Err(CatalogError::Limit("frontier capacity").into()); }
        if local.root() != source.root { frontier.push((1, source.root)); }
        Ok(SymbolRepairCursor { owner: Arc::clone(&self.identity), source, local, frontier,
            pending: Vec::new(), next: 0, seen_entries: 0, seen_key_bytes: 0,
            visited_nodes: 0, repaired_batches: 0, repaired_bytes: 0, already_present: 0 })
    }

    /// Advance by finite metadata and value allowances. A partial successful
    /// return is resumable using the same cursor. Cancellation/drop while a
    /// network operation is pending leaves its item pending. Publication and
    /// cursor advancement contain no await: retry cannot lose a confirmed put.
    ///
    /// Each step checks current metadata and symbol-transport origin/source
    /// bindings before network work, then refreshes the immutable source ID.
    /// Source replacement refuses; already completed verified puts remain valid.
    /// Recheck each fetched value's exact digest and length before local put;
    /// a catalog assertion is never sufficient authority to publish raw bytes.
    pub async fn step(&self, cx: &Cx, symbols: &RemoteSymbolTransport, cursor: &mut SymbolRepairCursor)
        -> Result<SymbolRepairProgress, SymbolRepairError>
    {
        self.check_owner(cx)?;
        if !Arc::ptr_eq(&self.identity, &cursor.owner) { return Err(CatalogError::Cursor.into()); }
        let batch_limits = symbols.repair_binding(&self.origin, self.source.as_str(), self.limits.max_batch_bytes)
            .ok_or(SymbolRepairError::Authority)?;
        if cursor.progress().complete { return Ok(cursor.progress()); }
        let bytes = self.query(cx, None).await?;
        if wire::root(&bytes, &self.origin, self.limits.catalog)? != cursor.source {
            return Err(CatalogError::SnapshotChanged.into());
        }
        drop(bytes);
        let mut requests = 1usize;
        let mut values = 0usize;
        let mut value_bytes = 0usize;
        loop {
            self.check_owner(cx)?;
            if cursor.next < cursor.pending.len() {
                if values == self.limits.max_repairs_per_step { break; }
                let entry = &cursor.pending[cursor.next];
                let key = symbol_key(entry)?;
                let size = usize::try_from(entry.value_bytes).map_err(|_| CatalogError::Overflow)?;
                if size > self.limits.max_batch_bytes { return Err(CatalogError::Limit("batch bytes").into()); }
                match self.destination.get(&self.origin, key) {
                    Ok(existing) => {
                        if existing.as_ref().as_ref().len() != size { return Err(CatalogError::Integrity.into()); }
                        cursor.already_present = add(cursor.already_present, 1)?;
                        cursor.next += 1;
                        values += 1;
                        continue;
                    }
                    Err(SymbolStoreError::NotFound) => {}
                    Err(error) => return Err(error.into()),
                }
                let next_bytes = add(value_bytes, batch_limits.max_encoded_bytes)?;
                if next_bytes > self.limits.max_bytes_per_step { break; }
                let total_bytes = add(cursor.repaired_bytes, size)?;
                if total_bytes > self.limits.max_total_repair_bytes {
                    return Err(CatalogError::Limit("total repair bytes").into());
                }
                let repaired_batches = add(cursor.repaired_batches, 1)?;
                let fetched = symbols.fetch_symbols_for_repair(cx, self.source.as_str(), key).await;
                self.check_owner(cx)?;
                let fetched = fetched?;
                let encoded = encode_symbol_batch(&fetched, batch_limits)?;
                drop(fetched);
                if encoded.key() != key || encoded.as_ref().len() != size {
                    return Err(CatalogError::Integrity.into());
                }
                // All fallible accounting precedes the effect; no cancellation
                // boundary separates the idempotent publication from progress.
                self.destination.put(&self.origin, encoded.as_ref())?;
                cursor.repaired_batches = repaired_batches;
                cursor.repaired_bytes = total_bytes;
                cursor.next += 1;
                values += 1;
                value_bytes = next_bytes;
                continue;
            }
            cursor.pending = Vec::new();
            cursor.next = 0;
            let Some(&(index, expected)) = cursor.frontier.last() else { break; };
            if requests == self.limits.max_catalog_requests_per_step { break; }
            let bytes = self.query(cx, Some((cursor.source.snapshot, index))).await?;
            requests += 1;
            let page = wire::page(&bytes, cursor.source, self.limits.catalog, index, expected)?;
            drop(bytes);
            self.check_owner(cx)?;
            self.accept_page(cursor, index, page)?;
        }
        Ok(cursor.progress())
    }

    fn accept_page(&self, cursor: &mut SymbolRepairCursor, index: u32, page: Page)
        -> Result<(), CatalogError>
    {
        let visited = add(cursor.visited_nodes, 1)?;
        if visited >= (2usize << self.limits.catalog.depth) { return Err(CatalogError::Limit("visited nodes")); }
        match page {
            Page::Branch(left, right) => {
                let candidates = [(index * 2 + 1, right), (index * 2, left)];
                let added = candidates.iter().filter(|(child, hash)| cursor.local.node(*child) != Some(*hash)).count();
                if add(cursor.frontier.len() - 1, added)? > usize::from(self.limits.catalog.depth) + 1 {
                    return Err(CatalogError::Limit("frontier"));
                }
                cursor.frontier.pop();
                for (child, hash) in candidates {
                    if cursor.local.node(child) != Some(hash) { cursor.frontier.push((child, hash)); }
                }
            }
            Page::Leaf(mut entries) => {
                let seen_entries = add(cursor.seen_entries, entries.len())?;
                let key_bytes = entries.iter().try_fold(0, |total, entry| add(total, entry.key.len()))?;
                let seen_key_bytes = add(cursor.seen_key_bytes, key_bytes)?;
                if seen_entries > cursor.source.entries || seen_key_bytes > cursor.source.key_bytes {
                    return Err(CatalogError::Limit("source traversal"));
                }
                let mut present = 0usize;
                for entry in &entries {
                    symbol_key(entry)?;
                    if entry.value_bytes > self.limits.max_batch_bytes as u64 {
                        return Err(CatalogError::Limit("batch bytes"));
                    }
                    if let Some(local) = cursor.local.find(&entry.key) {
                        if local.value_hash != entry.value_hash || local.value_bytes != entry.value_bytes {
                            return Err(CatalogError::Conflict);
                        }
                        present += 1;
                    }
                }
                let present = add(cursor.already_present, present)?;
                entries.retain(|entry| cursor.local.find(&entry.key).is_none());
                cursor.frontier.pop();
                cursor.pending = entries;
                cursor.next = 0;
                cursor.seen_entries = seen_entries;
                cursor.seen_key_bytes = seen_key_bytes;
                cursor.already_present = present;
            }
        }
        cursor.visited_nodes = visited;
        Ok(())
    }
}

fn symbol_key(entry: &CatalogEntry) -> Result<SymbolBatchKey, CatalogError> {
    if entry.key.len() != 16 || entry.value_bytes == 0 { return Err(CatalogError::Format); }
    let object = u128::from_le_bytes(entry.key.as_slice().try_into().map_err(|_| CatalogError::Format)?);
    Ok(SymbolBatchKey { object_id: ObjectId::from_u128(object), digest: entry.value_hash })
}
