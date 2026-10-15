//! Immutable, bounded SHA-256 catalogs for network reconciliation.
//!
//! The older FNV tree remains a local comparison tool. Network equality and
//! subtree pruning use these domain-separated full SHA-256 digests instead.
//! Catalog authenticity comes from the authenticated service and independently
//! validated values; a digest does not prove a peer disclosed everything it owns.

use crate::remote::NodeId;
use sha2::{Digest, Sha256};
use std::fmt;

pub(crate) type Hash = [u8; 32];
pub(crate) const ROOT_BYTES: usize = 133;
pub(crate) const PAGE_HEADER: usize = 53;

/// Construction, retained metadata and complete binary-response limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogLimits {
    /// Fixed tree depth, between one and sixteen. Both catalogs must agree.
    pub depth: u8,
    /// Maximum entries in one immutable origin catalog.
    pub max_entries: usize,
    /// Maximum bytes in one nonempty key, at most `u16::MAX`.
    pub max_key_bytes: usize,
    /// Sum of key lengths; also bounds hashing and comparison input.
    pub max_total_key_bytes: usize,
    /// Maximum entries in one leaf page. An overfull bucket refuses construction.
    pub max_page_entries: usize,
    /// Entry-vector/key capacities, node digests and bucket-index capacities.
    /// Excludes fixed structs, short origin labels and allocator bookkeeping.
    pub max_retained_bytes: usize,
    /// Complete application response, before the remote transport's JSON framing.
    pub max_response_bytes: usize,
}

/// An ordered key and a strong content identity; no application value is retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    /// Exact nonempty key, without truncation or a lossy key fingerprint.
    pub key: Vec<u8>,
    /// SHA-256 content identity defined by the application's verified codec.
    pub value_hash: [u8; 32],
    /// Exact canonical value length, checked again before repair publication.
    pub value_bytes: u64,
}

/// Payload-free catalog and reconciliation refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CatalogError {
    /// Invalid bounds, dimensions, labels or symbol-catalog key structure.
    #[error("invalid reconciliation configuration")]
    Configuration,
    /// A count, byte, frame or work allowance was exceeded.
    #[error("reconciliation exceeds its {0} limit")]
    Limit(&'static str),
    /// Checked arithmetic cannot represent a configured quantity.
    #[error("reconciliation size overflow")]
    Overflow,
    /// A bounded allocation failed.
    #[error("reconciliation allocation failed")]
    Allocation,
    /// Duplicate keys or differing content for an immutable object.
    #[error("reconciliation immutable-key conflict")]
    Conflict,
    /// Invalid framing, order, dimensions or trailing data.
    #[error("invalid reconciliation response")]
    Format,
    /// A branch, leaf or snapshot digest did not validate.
    #[error("reconciliation digest mismatch")]
    Integrity,
    /// The source published another immutable snapshot or revision.
    #[error("reconciliation source snapshot changed")]
    SnapshotChanged,
    /// A cursor belongs to another client, origin, source or policy.
    #[error("reconciliation cursor belongs to another owner")]
    Cursor,
    /// An authenticated origin has no catalog or the target does not match.
    #[error("reconciliation origin or target is not authorized")]
    Unauthorized,
}

pub(crate) fn add(a: usize, b: usize) -> Result<usize, CatalogError> {
    a.checked_add(b).ok_or(CatalogError::Overflow)
}
pub(crate) fn label(value: &str) -> bool { !value.is_empty() && value.len() <= 255 }

impl CatalogLimits {
    pub(crate) fn validate(self) -> Result<usize, CatalogError> {
        if !(1..=16).contains(&self.depth) || self.max_key_bytes == 0
            || self.max_key_bytes > usize::from(u16::MAX) || self.max_page_entries == 0
            || self.max_entries > u32::MAX as usize || self.max_page_entries > u32::MAX as usize
            || self.max_response_bytes < ROOT_BYTES
        { return Err(CatalogError::Configuration); }
        Ok(1usize << self.depth)
    }

    pub(crate) fn fingerprint(self) -> Hash {
        let mut hash = Sha256::new();
        hash.update(b"asupersync.catalog.limits.v1");
        hash.update([self.depth]);
        for value in [self.max_entries, self.max_key_bytes, self.max_total_key_bytes,
            self.max_page_entries, self.max_retained_bytes, self.max_response_bytes]
        { hash.update((value as u64).to_le_bytes()); }
        hash.finalize().into()
    }
}

/// A complete immutable origin namespace at one caller-assigned revision.
///
/// Construction performs no I/O. Limits cover this owned catalog; caller-held
/// input and clones are separate owners. Revisions are not an anti-rollback
/// witness across restarts. Persist or independently provision expected revision
/// authority when that property is required.
pub struct Catalog {
    origin: NodeId,
    revision: u64,
    limits: CatalogLimits,
    entries: Vec<CatalogEntry>,
    offsets: Vec<usize>,
    nodes: Vec<Hash>,
    key_bytes: usize,
    retained_bytes: usize,
    snapshot: Hash,
}

impl fmt::Debug for Catalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Catalog").field("revision", &self.revision)
            .field("entries", &self.entries.len()).field("retained_bytes", &self.retained_bytes)
            .finish_non_exhaustive()
    }
}

pub(crate) fn bucket(depth: u8, key: &[u8]) -> usize {
    let hash = Sha256::digest(key);
    usize::from(u16::from_be_bytes([hash[0], hash[1]])) >> (16 - depth)
}

pub(crate) fn leaf_hash(depth: u8, index: u32, entries: &[CatalogEntry]) -> Hash {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.catalog.leaf.v1");
    hash.update([depth]);
    hash.update(index.to_le_bytes());
    hash.update((entries.len() as u64).to_le_bytes());
    for entry in entries {
        hash.update((entry.key.len() as u64).to_le_bytes());
        hash.update(&entry.key);
        hash.update(entry.value_hash);
        hash.update(entry.value_bytes.to_le_bytes());
    }
    hash.finalize().into()
}

pub(crate) fn branch_hash(depth: u8, index: u32, left: Hash, right: Hash) -> Hash {
    let mut hash = Sha256::new();
    hash.update(b"asupersync.catalog.branch.v1");
    hash.update([depth]);
    hash.update(index.to_le_bytes());
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

pub(crate) fn snapshot_hash(origin: &NodeId, revision: u64, limits: CatalogLimits,
    root: Hash, entries: usize, key_bytes: usize) -> Hash
{
    let mut hash = Sha256::new();
    hash.update(b"asupersync.catalog.snapshot.v1");
    hash.update([origin.as_str().len() as u8]);
    hash.update(origin.as_str().as_bytes());
    hash.update(revision.to_le_bytes());
    hash.update(limits.fingerprint());
    hash.update(root);
    hash.update((entries as u64).to_le_bytes());
    hash.update((key_bytes as u64).to_le_bytes());
    hash.finalize().into()
}

impl Catalog {
    /// Admit all metadata before building a tree. Duplicate keys refuse even
    /// when their hashes agree. Oversized leaf pages require another explicit
    /// depth/page policy; they never create an unbounded fallback response.
    pub fn new(origin: NodeId, revision: u64, mut entries: Vec<CatalogEntry>, limits: CatalogLimits)
        -> Result<Self, CatalogError>
    {
        let leaves = limits.validate()?;
        if !label(origin.as_str()) { return Err(CatalogError::Configuration); }
        if entries.len() > limits.max_entries { return Err(CatalogError::Limit("entries")); }
        let mut key_bytes = 0usize;
        let mut retained = entries.capacity().checked_mul(std::mem::size_of::<CatalogEntry>())
            .ok_or(CatalogError::Overflow)?;
        for entry in &entries {
            if entry.key.is_empty() || entry.key.len() > limits.max_key_bytes {
                return Err(CatalogError::Limit("key bytes"));
            }
            key_bytes = add(key_bytes, entry.key.len())?;
            retained = add(retained, entry.key.capacity())?;
        }
        if key_bytes > limits.max_total_key_bytes { return Err(CatalogError::Limit("total key bytes")); }
        let index_bytes = (leaves + 1).checked_mul(std::mem::size_of::<usize>()).ok_or(CatalogError::Overflow)?;
        let node_bytes = (leaves * 2).checked_mul(std::mem::size_of::<Hash>()).ok_or(CatalogError::Overflow)?;
        if add(retained, add(index_bytes, node_bytes)?)? > limits.max_retained_bytes {
            return Err(CatalogError::Limit("retained bytes"));
        }
        entries.sort_unstable_by(|a, b| bucket(limits.depth, &a.key).cmp(&bucket(limits.depth, &b.key))
            .then_with(|| a.key.cmp(&b.key)));
        if entries.windows(2).any(|pair| pair[0].key == pair[1].key) { return Err(CatalogError::Conflict); }
        let mut offsets = Vec::new();
        offsets.try_reserve_exact(leaves + 1).map_err(|_| CatalogError::Allocation)?;
        retained = add(retained, offsets.capacity().checked_mul(std::mem::size_of::<usize>()).ok_or(CatalogError::Overflow)?)?;
        if add(retained, node_bytes)? > limits.max_retained_bytes { return Err(CatalogError::Limit("retained bytes")); }
        offsets.resize(leaves + 1, 0usize);
        for entry in &entries { offsets[bucket(limits.depth, &entry.key) + 1] += 1; }
        for i in 1..=leaves { offsets[i] += offsets[i - 1]; }
        let mut nodes = Vec::new();
        nodes.try_reserve_exact(leaves * 2).map_err(|_| CatalogError::Allocation)?;
        retained = add(retained, nodes.capacity().checked_mul(std::mem::size_of::<Hash>()).ok_or(CatalogError::Overflow)?)?;
        if retained > limits.max_retained_bytes { return Err(CatalogError::Limit("retained bytes")); }
        nodes.resize(leaves * 2, [0; 32]);
        for i in 0..leaves {
            let page = &entries[offsets[i]..offsets[i + 1]];
            if page.len() > limits.max_page_entries { return Err(CatalogError::Limit("leaf entries")); }
            let encoded = page.iter().try_fold(PAGE_HEADER, |total, entry| add(total, add(42, entry.key.len())?))?;
            if encoded > limits.max_response_bytes { return Err(CatalogError::Limit("response bytes")); }
            nodes[leaves + i] = leaf_hash(limits.depth, (leaves + i) as u32, page);
        }
        for i in (1..leaves).rev() {
            nodes[i] = branch_hash(limits.depth, i as u32, nodes[i * 2], nodes[i * 2 + 1]);
        }
        let snapshot = snapshot_hash(&origin, revision, limits, nodes[1], entries.len(), key_bytes);
        Ok(Self { origin, revision, limits, entries, offsets, nodes, key_bytes,
            retained_bytes: retained, snapshot })
    }

    /// Authenticated namespace that this catalog is allowed to describe.
    #[must_use]
    pub fn origin(&self) -> &NodeId { &self.origin }
    /// Caller-assigned immutable revision.
    #[must_use]
    pub fn revision(&self) -> u64 { self.revision }
    /// Full strong digest of the ordered key/content tree.
    #[must_use]
    pub fn root(&self) -> [u8; 32] { self.nodes[1] }
    /// Origin/revision/policy/content-bound snapshot identity.
    #[must_use]
    pub fn snapshot_id(&self) -> [u8; 32] { self.snapshot }
    /// Construction and page bounds sealed into the snapshot identity.
    #[must_use]
    pub fn limits(&self) -> CatalogLimits { self.limits }
    /// Number of exact keys in this immutable catalog.
    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }
    /// Whether the origin catalog has no retained entries.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    /// Admitted metadata allocation capacities, as described by `CatalogLimits`.
    #[must_use]
    pub fn retained_bytes(&self) -> usize { self.retained_bytes }
    pub(crate) fn key_bytes(&self) -> usize { self.key_bytes }
    pub(crate) fn node(&self, index: u32) -> Option<Hash> { self.nodes.get(index as usize).copied().filter(|_| index != 0) }
    pub(crate) fn page(&self, index: u32) -> Option<&[CatalogEntry]> {
        let leaves = 1usize << self.limits.depth;
        let i = (index as usize).checked_sub(leaves)?;
        if i >= leaves { return None; }
        Some(&self.entries[self.offsets[i]..self.offsets[i + 1]])
    }
    #[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
    pub(crate) fn find(&self, key: &[u8]) -> Option<&CatalogEntry> {
        let page = self.page(((1usize << self.limits.depth) + bucket(self.limits.depth, key)) as u32)?;
        page.binary_search_by(|entry| entry.key.as_slice().cmp(key)).ok().map(|i| &page[i])
    }
}
