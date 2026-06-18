//! Content-addressed chunk store and Merkle manifest for delta ATP transfers.
//!
//! The B-8 delta path uses FastCDC to identify stable chunks, then records only
//! content addresses here. A chunk already present anywhere in the receiver CAS
//! is reusable without re-sending bytes; the Merkle manifest localizes changes
//! to leaf ranges while its commitments are persisted through the existing ATP
//! append journal.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::atp::journal::append_journal::JournalError;
use crate::atp::journal::{AppendJournal, JournalRecord};
use crate::security::AuthenticationTag;
use crate::types::outcome::Outcome;

use super::ChunkingProfileError;
use super::dedupe::CdcChunkData;

const MANIFEST_VERSION: u32 = 1;
const DOMAIN_ADDRESS: &[u8] = b"asupersync:atp:cas:chunk-address:v1";
const DOMAIN_LEAF: &[u8] = b"asupersync:atp:cas:manifest-leaf:v1";
const DOMAIN_NODE: &[u8] = b"asupersync:atp:cas:manifest-node:v1";
const DOMAIN_EMPTY: &[u8] = b"asupersync:atp:cas:manifest-empty:v1";
const DOMAIN_CANONICAL: &[u8] = b"asupersync:atp:cas:manifest-canonical:v1";
const PROOF_TYPE_ROOT: &str = "cas-merkle-root-v1";
const PROOF_TYPE_MANIFEST: &str = "cas-manifest-canonical-v1";

/// Stable content address for a chunk: SHA-256 plus byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkAddress {
    /// Plain SHA-256 over the chunk bytes.
    pub content_hash: [u8; 32],
    /// Chunk size in bytes.
    pub size_bytes: u64,
}

impl ChunkAddress {
    /// Build an address from chunk bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            content_hash: Sha256::digest(bytes).into(),
            size_bytes: bytes.len() as u64,
        }
    }

    /// Build an address from an already-hashed CDC chunk.
    #[must_use]
    pub const fn from_cdc(chunk: &CdcChunkData) -> Self {
        Self {
            content_hash: chunk.content_hash,
            size_bytes: chunk.size_bytes,
        }
    }

    /// Domain-separated digest of the address itself.
    #[must_use]
    pub fn address_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_ADDRESS);
        hasher.update(self.content_hash);
        hasher.update(self.size_bytes.to_be_bytes());
        hasher.finalize().into()
    }
}

/// Result of inserting bytes into the CAS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasInsertOutcome {
    /// Content address for the inserted chunk.
    pub address: ChunkAddress,
    /// Whether the store already held this chunk.
    pub dedup_hit: bool,
}

/// CAS utilization counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CasStoreStats {
    /// Number of unique chunks retained.
    pub unique_chunks: usize,
    /// Bytes retained for unique chunks only.
    pub unique_bytes: u64,
    /// Number of duplicate inserts suppressed by content address.
    pub dedup_hits: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CasStoredChunk {
    data: Vec<u8>,
    first_source: Option<String>,
}

/// In-memory content-addressed chunk store.
#[derive(Debug, Clone, Default)]
pub struct ContentAddressedChunkStore {
    chunks: BTreeMap<ChunkAddress, CasStoredChunk>,
    unique_bytes: u64,
    dedup_hits: u64,
}

impl ContentAddressedChunkStore {
    /// Create an empty CAS.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert bytes by content address, suppressing duplicate storage.
    pub fn insert_chunk(
        &mut self,
        bytes: &[u8],
        first_source: Option<String>,
    ) -> Result<CasInsertOutcome, ChunkingProfileError> {
        let address = ChunkAddress::from_bytes(bytes);
        if self.chunks.contains_key(&address) {
            self.dedup_hits = self.dedup_hits.saturating_add(1);
            return Ok(CasInsertOutcome {
                address,
                dedup_hit: true,
            });
        }

        self.unique_bytes = self.unique_bytes.saturating_add(address.size_bytes);
        self.chunks.insert(
            address,
            CasStoredChunk {
                data: bytes.to_vec(),
                first_source,
            },
        );
        Ok(CasInsertOutcome {
            address,
            dedup_hit: false,
        })
    }

    /// Return the stored bytes for an address.
    #[must_use]
    pub fn get(&self, address: &ChunkAddress) -> Option<&[u8]> {
        self.chunks.get(address).map(|chunk| chunk.data.as_slice())
    }

    /// Return whether the CAS can satisfy this address.
    #[must_use]
    pub fn contains(&self, address: &ChunkAddress) -> bool {
        self.chunks.contains_key(address)
    }

    /// Addresses absent from this store, deduplicated in manifest order.
    #[must_use]
    pub fn missing_from_manifest(&self, manifest: &CasMerkleManifest) -> Vec<ChunkAddress> {
        manifest
            .unique_addresses()
            .into_iter()
            .filter(|address| !self.contains(address))
            .collect()
    }

    /// Current CAS counters.
    #[must_use]
    pub fn stats(&self) -> CasStoreStats {
        CasStoreStats {
            unique_chunks: self.chunks.len(),
            unique_bytes: self.unique_bytes,
            dedup_hits: self.dedup_hits,
        }
    }
}

/// One chunk in a content-addressed tree manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasManifestChunk {
    /// Transfer-relative path.
    pub rel_path: String,
    /// Byte offset within that path.
    pub byte_offset: u64,
    /// Content address for the chunk.
    pub address: ChunkAddress,
}

impl CasManifestChunk {
    /// Convert a FastCDC chunk into a CAS manifest chunk.
    #[must_use]
    pub fn from_cdc(rel_path: impl Into<String>, chunk: &CdcChunkData) -> Self {
        Self {
            rel_path: rel_path.into(),
            byte_offset: chunk.byte_offset,
            address: ChunkAddress::from_cdc(chunk),
        }
    }
}

/// Stored manifest entry with its precomputed Merkle leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasManifestEntry {
    /// Transfer-relative path.
    pub rel_path: String,
    /// Byte offset within that path.
    pub byte_offset: u64,
    /// Content address for the chunk.
    pub address: ChunkAddress,
    /// Domain-separated Merkle leaf hash.
    pub leaf_hash: [u8; 32],
}

/// Changed leaf range identified by hierarchical Merkle descent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasSubtreeDiff {
    /// Inclusive start index in this manifest's sorted leaf list.
    pub start_index: usize,
    /// Exclusive end index in this manifest's sorted leaf list.
    pub end_index: usize,
}

/// Sender-vs-receiver delta summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasManifestDelta {
    /// Leaf ranges whose subtree hash differs.
    pub changed_ranges: Vec<CasSubtreeDiff>,
    /// Unique sender chunks absent from the receiver manifest.
    pub missing_chunks: Vec<ChunkAddress>,
    /// Bytes that must be sent if every missing chunk is transferred once.
    pub missing_bytes: u64,
}

/// Content-addressed per-tree manifest with deterministic Merkle root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasMerkleManifest {
    tree_id: String,
    entries: Vec<CasManifestEntry>,
    root: [u8; 32],
    total_bytes: u64,
}

impl CasMerkleManifest {
    /// Build a manifest from FastCDC-derived chunk addresses.
    pub fn from_chunks(
        tree_id: impl Into<String>,
        chunks: impl IntoIterator<Item = CasManifestChunk>,
    ) -> Result<Self, ChunkingProfileError> {
        let tree_id = tree_id.into();
        validate_tree_id(&tree_id)?;

        let mut chunks: Vec<CasManifestChunk> = chunks.into_iter().collect();
        chunks.sort_by(|a, b| {
            a.rel_path
                .cmp(&b.rel_path)
                .then_with(|| a.byte_offset.cmp(&b.byte_offset))
                .then_with(|| a.address.size_bytes.cmp(&b.address.size_bytes))
                .then_with(|| a.address.content_hash.cmp(&b.address.content_hash))
        });

        let mut entries = Vec::with_capacity(chunks.len());
        let mut total_bytes = 0u64;
        for chunk in chunks {
            validate_rel_path(&chunk.rel_path)?;
            total_bytes = total_bytes.saturating_add(chunk.address.size_bytes);
            let leaf_hash = leaf_hash(&tree_id, &chunk);
            entries.push(CasManifestEntry {
                rel_path: chunk.rel_path,
                byte_offset: chunk.byte_offset,
                address: chunk.address,
                leaf_hash,
            });
        }

        let leaf_hashes: Vec<[u8; 32]> = entries.iter().map(|entry| entry.leaf_hash).collect();
        let root = merkle_range_hash(&leaf_hashes, 0, leaf_hashes.len());
        Ok(Self {
            tree_id,
            entries,
            root,
            total_bytes,
        })
    }

    /// Stable tree identifier.
    #[must_use]
    pub fn tree_id(&self) -> &str {
        &self.tree_id
    }

    /// Sorted manifest entries.
    #[must_use]
    pub fn entries(&self) -> &[CasManifestEntry] {
        &self.entries
    }

    /// Merkle root over the sorted manifest leaves.
    #[must_use]
    pub const fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Total logical bytes represented by all entries.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Unique chunk addresses in deterministic order.
    #[must_use]
    pub fn unique_addresses(&self) -> Vec<ChunkAddress> {
        let mut seen = BTreeSet::new();
        self.entries
            .iter()
            .filter_map(|entry| {
                if seen.insert(entry.address) {
                    Some(entry.address)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Canonical bytes for persistence or proof hashing.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_bytes(&mut out, DOMAIN_CANONICAL);
        put_u32(&mut out, MANIFEST_VERSION);
        put_string(&mut out, &self.tree_id);
        put_u64(&mut out, self.total_bytes);
        put_u64(&mut out, self.entries.len() as u64);
        for entry in &self.entries {
            put_string(&mut out, &entry.rel_path);
            put_u64(&mut out, entry.byte_offset);
            put_u64(&mut out, entry.address.size_bytes);
            put_bytes(&mut out, &entry.address.content_hash);
            put_bytes(&mut out, &entry.leaf_hash);
        }
        put_bytes(&mut out, &self.root);
        out
    }

    /// SHA-256 over [`Self::to_canonical_bytes`].
    #[must_use]
    pub fn canonical_digest(&self) -> [u8; 32] {
        Sha256::digest(self.to_canonical_bytes()).into()
    }

    /// Journal records committing this manifest through the existing ATP journal.
    #[must_use]
    pub fn journal_commitment_records(
        &self,
        transfer_id: &str,
        timestamp: u64,
    ) -> Vec<JournalRecord> {
        vec![
            JournalRecord::ProofDigest {
                transfer_id: transfer_id.to_string(),
                proof_type: PROOF_TYPE_ROOT.to_string(),
                digest: self.root,
                timestamp,
                auth_tag: AuthenticationTag::zero(),
            },
            JournalRecord::ProofDigest {
                transfer_id: transfer_id.to_string(),
                proof_type: PROOF_TYPE_MANIFEST.to_string(),
                digest: self.canonical_digest(),
                timestamp,
                auth_tag: AuthenticationTag::zero(),
            },
        ]
    }

    /// Append manifest commitments to an existing append journal.
    pub fn append_commitments_to_journal(
        &self,
        journal: &mut AppendJournal,
        transfer_id: &str,
        timestamp: u64,
    ) -> Outcome<Vec<u64>, JournalError> {
        let mut sequences = Vec::new();
        for record in self.journal_commitment_records(transfer_id, timestamp) {
            match journal.append(record) {
                Outcome::Ok(sequence) => sequences.push(sequence),
                Outcome::Err(err) => return Outcome::Err(err),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }
        Outcome::Ok(sequences)
    }

    /// Hierarchically descend Merkle ranges and return changed leaf ranges.
    #[must_use]
    pub fn changed_subtree_ranges_against(&self, prior: &Self) -> Vec<CasSubtreeDiff> {
        if self.root == prior.root && self.entries.len() == prior.entries.len() {
            return Vec::new();
        }

        let current: Vec<[u8; 32]> = self.entries.iter().map(|entry| entry.leaf_hash).collect();
        let baseline: Vec<[u8; 32]> = prior.entries.iter().map(|entry| entry.leaf_hash).collect();
        let mut ranges = Vec::new();
        collect_changed_ranges(&current, &baseline, 0, current.len(), &mut ranges);
        ranges
    }

    /// Compute the CAS delta needed to update `receiver` to this manifest.
    #[must_use]
    pub fn delta_against(&self, receiver: &Self) -> CasManifestDelta {
        let receiver_addresses: BTreeSet<ChunkAddress> =
            receiver.entries.iter().map(|entry| entry.address).collect();
        let mut emitted = BTreeSet::new();
        let mut missing_chunks = Vec::new();
        let mut missing_bytes = 0u64;

        for entry in &self.entries {
            if receiver_addresses.contains(&entry.address) || !emitted.insert(entry.address) {
                continue;
            }
            missing_bytes = missing_bytes.saturating_add(entry.address.size_bytes);
            missing_chunks.push(entry.address);
        }

        CasManifestDelta {
            changed_ranges: self.changed_subtree_ranges_against(receiver),
            missing_chunks,
            missing_bytes,
        }
    }
}

fn validate_tree_id(tree_id: &str) -> Result<(), ChunkingProfileError> {
    if tree_id.is_empty() {
        return Err(ChunkingProfileError::InvalidChunkParameters(
            "CAS manifest tree id must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn validate_rel_path(rel_path: &str) -> Result<(), ChunkingProfileError> {
    if rel_path.is_empty() {
        return Err(ChunkingProfileError::InvalidChunkParameters(
            "CAS manifest relative path must not be empty".to_string(),
        ));
    }
    if rel_path.starts_with('/') || rel_path.contains("..") {
        return Err(ChunkingProfileError::InvalidChunkParameters(format!(
            "CAS manifest relative path is not normalized: {rel_path}"
        )));
    }
    Ok(())
}

fn leaf_hash(tree_id: &str, chunk: &CasManifestChunk) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_LEAF);
    put_string_hash(&mut hasher, tree_id);
    put_string_hash(&mut hasher, &chunk.rel_path);
    hasher.update(chunk.byte_offset.to_be_bytes());
    hasher.update(chunk.address.size_bytes.to_be_bytes());
    hasher.update(chunk.address.content_hash);
    hasher.finalize().into()
}

fn merkle_range_hash(leaves: &[[u8; 32]], start: usize, end: usize) -> [u8; 32] {
    if start >= end {
        return Sha256::digest(DOMAIN_EMPTY).into();
    }
    if end - start == 1 {
        return leaves[start];
    }
    let mid = start + (end - start) / 2;
    node_hash(
        &merkle_range_hash(leaves, start, mid),
        &merkle_range_hash(leaves, mid, end),
    )
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_NODE);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn collect_changed_ranges(
    current: &[[u8; 32]],
    baseline: &[[u8; 32]],
    start: usize,
    end: usize,
    out: &mut Vec<CasSubtreeDiff>,
) {
    if start >= end {
        return;
    }
    let current_hash = merkle_range_hash(current, start, end);
    let baseline_hash =
        merkle_range_hash(baseline, start.min(baseline.len()), end.min(baseline.len()));
    if current_hash == baseline_hash && end <= baseline.len() {
        return;
    }
    if end - start == 1 {
        out.push(CasSubtreeDiff {
            start_index: start,
            end_index: end,
        });
        return;
    }
    let mid = start + (end - start) / 2;
    collect_changed_ranges(current, baseline, start, mid, out);
    collect_changed_ranges(current, baseline, mid, end, out);
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn put_string(out: &mut Vec<u8>, value: &str) {
    put_bytes(out, value.as_bytes());
}

fn put_string_hash(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(path: &str, offset: u64, bytes: &[u8]) -> CasManifestChunk {
        CasManifestChunk {
            rel_path: path.to_string(),
            byte_offset: offset,
            address: ChunkAddress::from_bytes(bytes),
        }
    }

    #[test]
    fn cas_store_round_trips_and_deduplicates() {
        let mut store = ContentAddressedChunkStore::new();
        let first = store
            .insert_chunk(b"same chunk", Some("a".to_string()))
            .expect("first insert");
        let second = store
            .insert_chunk(b"same chunk", Some("b".to_string()))
            .expect("second insert");

        assert_eq!(first.address, second.address);
        assert!(!first.dedup_hit);
        assert!(second.dedup_hit);
        assert_eq!(store.get(&first.address), Some(b"same chunk".as_slice()));
        assert_eq!(
            store.stats(),
            CasStoreStats {
                unique_chunks: 1,
                unique_bytes: 10,
                dedup_hits: 1,
            }
        );
    }

    #[test]
    fn manifest_root_is_stable_across_input_order() {
        let a = CasMerkleManifest::from_chunks(
            "tree",
            [
                chunk("b.txt", 0, b"bravo"),
                chunk("a.txt", 0, b"alpha"),
                chunk("a.txt", 5, b"-tail"),
            ],
        )
        .expect("manifest a");
        let b = CasMerkleManifest::from_chunks(
            "tree",
            [
                chunk("a.txt", 5, b"-tail"),
                chunk("a.txt", 0, b"alpha"),
                chunk("b.txt", 0, b"bravo"),
            ],
        )
        .expect("manifest b");

        assert_eq!(a.root(), b.root());
        assert_eq!(a.to_canonical_bytes(), b.to_canonical_bytes());
    }

    #[test]
    fn subtree_delta_finds_changed_leaf_and_missing_chunk() {
        let old = CasMerkleManifest::from_chunks(
            "tree",
            [
                chunk("a", 0, b"a"),
                chunk("b", 0, b"b"),
                chunk("c", 0, b"c"),
                chunk("d", 0, b"d"),
            ],
        )
        .expect("old manifest");
        let new = CasMerkleManifest::from_chunks(
            "tree",
            [
                chunk("a", 0, b"a"),
                chunk("b", 0, b"b"),
                chunk("c", 0, b"C"),
                chunk("d", 0, b"d"),
            ],
        )
        .expect("new manifest");

        let delta = new.delta_against(&old);
        assert_eq!(
            delta.changed_ranges,
            vec![CasSubtreeDiff {
                start_index: 2,
                end_index: 3,
            }]
        );
        assert_eq!(delta.missing_chunks, vec![ChunkAddress::from_bytes(b"C")]);
        assert_eq!(delta.missing_bytes, 1);
    }

    #[test]
    fn journal_commitments_use_existing_proof_digest_records() {
        let manifest =
            CasMerkleManifest::from_chunks("tree", [chunk("a", 0, b"a")]).expect("manifest");
        let records = manifest.journal_commitment_records("transfer", 42);

        assert_eq!(records.len(), 2);
        assert!(matches!(
            &records[0],
            JournalRecord::ProofDigest {
                transfer_id,
                proof_type,
                digest,
                timestamp: 42,
                ..
            } if transfer_id == "transfer" && proof_type == PROOF_TYPE_ROOT && digest == &manifest.root()
        ));
        assert!(matches!(
            &records[1],
            JournalRecord::ProofDigest {
                transfer_id,
                proof_type,
                digest,
                timestamp: 42,
                ..
            } if transfer_id == "transfer"
                && proof_type == PROOF_TYPE_MANIFEST
                && digest == &manifest.canonical_digest()
        ));
    }
}
