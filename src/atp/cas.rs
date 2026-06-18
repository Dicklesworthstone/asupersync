//! Content-addressed chunk store (CAS) + per-tree Merkle manifest — B-8.2, the
//! tracking substrate for the rsync-killer incremental-resync delta path
//! (epic asupersync-...; builds on B-8.1 FastCDC chunking, bead asupersync-jktswz).
//!
//! Two pieces:
//!
//!   * [`ContentAddressedStore`] — a local store keyed by content id ([`ChunkId`]
//!     = [`ContentId`] over the chunk bytes). Dedup is intrinsic: a chunk present
//!     anywhere (in any file or any prior version) is stored exactly once and is
//!     never re-sent. This is what makes a re-sync transmit only genuinely new
//!     content.
//!   * [`TreeManifest`] / [`FileManifest`] — the receiver's persistent
//!     prior-state baseline for diffing. Each file is an ordered list of
//!     content-addressed [`ChunkRef`]s with a binary [`chunk_merkle_root`]; the
//!     tree has a Merkle root over its `(rel_path, file_root)` entries. Comparing
//!     roots localizes change hierarchically: equal tree roots ⇒ nothing changed
//!     (O(1)); otherwise only files whose roots differ are descended, and within
//!     a changed file only chunks the receiver lacks are transmitted
//!     ([`diff_trees`]) — O(log + delta), not O(total size).
//!
//! Persistence composes with the existing journal subsystem (`crate::atp::journal`)
//! rather than duplicating it: the manifest types derive `serde` so a caller can
//! checkpoint them through the journal's append/recovery machinery. This module
//! owns only the in-memory substrate + the deterministic Merkle/diff math.
//!
//! Determinism: all hashing is domain-separated SHA-256, leaves are taken in
//! file/chunk order (order-sensitive, as content layout is), and the tree root
//! iterates a `BTreeMap` (sorted by path), so identical inputs always yield
//! identical roots across machines/donors.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::atp::object::ContentId;

/// Content-addressed id of a chunk: a [`ContentId`] over the chunk's bytes. Two
/// byte-identical chunks share one id (the dedup key); different bytes ⇒
/// different id with cryptographic confidence.
pub type ChunkId = ContentId;

const MERKLE_LEAF_DOMAIN: &[u8] = b"asupersync.atp.cas.merkle.leaf.v1\0";
const MERKLE_NODE_DOMAIN: &[u8] = b"asupersync.atp.cas.merkle.node.v1\0";
const MERKLE_EMPTY_DOMAIN: &[u8] = b"asupersync.atp.cas.merkle.empty.v1\0";
const TREE_ROOT_DOMAIN: &[u8] = b"asupersync.atp.cas.tree.v1\0";

/// Content id for a chunk's bytes (the CAS / dedup key).
#[must_use]
pub fn chunk_id(bytes: &[u8]) -> ChunkId {
    ContentId::from_bytes(bytes)
}

/// Binary Merkle root over an ordered list of chunk ids.
///
/// Order-sensitive (a file's chunk layout is ordered), deterministic, and
/// hierarchical so subtree roots localize change. The last node is duplicated on
/// an odd level (standard). An empty list hashes to a fixed empty-root constant so
/// empty files have a stable, non-colliding id.
#[must_use]
pub fn chunk_merkle_root(ids: &[ChunkId]) -> ContentId {
    if ids.is_empty() {
        let mut h = Sha256::new();
        h.update(MERKLE_EMPTY_DOMAIN);
        return ContentId::new(h.finalize().into());
    }
    let mut level: Vec<[u8; 32]> = ids
        .iter()
        .map(|id| {
            let mut h = Sha256::new();
            h.update(MERKLE_LEAF_DOMAIN);
            h.update(id.hash());
            h.finalize().into()
        })
        .collect();
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = &pair[0];
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            let mut h = Sha256::new();
            h.update(MERKLE_NODE_DOMAIN);
            h.update(left);
            h.update(right);
            next.push(h.finalize().into());
        }
        level = next;
    }
    ContentId::new(level[0])
}

/// In-memory content-addressed chunk store. Dedups by [`ChunkId`]; a chunk is
/// stored once regardless of how many files/versions reference it.
#[derive(Debug, Default, Clone)]
pub struct ContentAddressedStore {
    chunks: HashMap<ChunkId, Vec<u8>>,
    dedup_hits: u64,
    bytes_stored: u64,
    bytes_deduped: u64,
}

impl ContentAddressedStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a chunk, returning its id and whether it was newly stored
    /// (`false` ⇒ a dedup hit; the bytes were already present and not re-stored).
    pub fn put(&mut self, bytes: &[u8]) -> (ChunkId, bool) {
        let id = chunk_id(bytes);
        let len = bytes.len() as u64;
        if self.chunks.contains_key(&id) {
            self.dedup_hits = self.dedup_hits.saturating_add(1);
            self.bytes_deduped = self.bytes_deduped.saturating_add(len);
            (id, false)
        } else {
            self.chunks.insert(id.clone(), bytes.to_vec());
            self.bytes_stored = self.bytes_stored.saturating_add(len);
            (id, true)
        }
    }

    /// Fetch a chunk's bytes by id.
    #[must_use]
    pub fn get(&self, id: &ChunkId) -> Option<&[u8]> {
        self.chunks.get(id).map(Vec::as_slice)
    }

    /// Whether the store already holds this chunk.
    #[must_use]
    pub fn contains(&self, id: &ChunkId) -> bool {
        self.chunks.contains_key(id)
    }

    /// Number of distinct chunks stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Count of `put` calls that hit an already-stored chunk (dedup hits).
    #[must_use]
    pub fn dedup_hits(&self) -> u64 {
        self.dedup_hits
    }

    /// Total distinct bytes actually stored.
    #[must_use]
    pub fn bytes_stored(&self) -> u64 {
        self.bytes_stored
    }

    /// Total bytes a naive (non-dedup) store would have re-stored — the bytes
    /// saved by content addressing.
    #[must_use]
    pub fn bytes_deduped(&self) -> u64 {
        self.bytes_deduped
    }
}

/// One chunk's placement within a file: its content id plus the byte range it
/// occupies. The file's content is the in-order concatenation of its chunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    /// Content-addressed id of the chunk (dedup / CAS key).
    pub id: ChunkId,
    /// Byte offset of this chunk within the file.
    pub offset: u64,
    /// Chunk length in bytes.
    pub len: u32,
}

/// Per-file manifest: the ordered content-addressed chunks plus a Merkle root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileManifest {
    /// Transfer-relative path (forward-slash separated).
    pub rel_path: String,
    /// Total file size in bytes.
    pub size: u64,
    /// Ordered chunk references.
    pub chunks: Vec<ChunkRef>,
    /// Merkle root over the chunk ids (the file's content fingerprint).
    pub merkle_root: ContentId,
}

impl FileManifest {
    /// Build a file manifest from ordered chunk refs, deriving size + Merkle root.
    #[must_use]
    pub fn from_chunks(rel_path: impl Into<String>, chunks: Vec<ChunkRef>) -> Self {
        let size = chunks.iter().map(|c| u64::from(c.len)).sum();
        let ids: Vec<ChunkId> = chunks.iter().map(|c| c.id.clone()).collect();
        let merkle_root = chunk_merkle_root(&ids);
        Self {
            rel_path: rel_path.into(),
            size,
            chunks,
            merkle_root,
        }
    }
}

/// Per-tree manifest: `rel_path -> FileManifest` plus a tree Merkle root. This is
/// the receiver's persistent prior-state baseline for delta diffing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeManifest {
    entries: BTreeMap<String, FileManifest>,
    root: ContentId,
}

impl Default for TreeManifest {
    fn default() -> Self {
        Self::new()
    }
}

impl TreeManifest {
    /// An empty tree manifest.
    #[must_use]
    pub fn new() -> Self {
        let entries = BTreeMap::new();
        let root = tree_root(&entries);
        Self { entries, root }
    }

    /// Build from a set of file manifests.
    #[must_use]
    pub fn from_files(files: impl IntoIterator<Item = FileManifest>) -> Self {
        let mut entries = BTreeMap::new();
        for file in files {
            entries.insert(file.rel_path.clone(), file);
        }
        let root = tree_root(&entries);
        Self { entries, root }
    }

    /// Insert/replace a file, recomputing the tree root.
    pub fn insert(&mut self, file: FileManifest) {
        self.entries.insert(file.rel_path.clone(), file);
        self.root = tree_root(&self.entries);
    }

    /// The tree's Merkle root (changes iff any file path or content changed).
    #[must_use]
    pub fn root(&self) -> &ContentId {
        &self.root
    }

    /// Look up a file manifest by path.
    #[must_use]
    pub fn file(&self, rel_path: &str) -> Option<&FileManifest> {
        self.entries.get(rel_path)
    }

    /// Number of files in the tree.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the tree has no files.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Merkle root over a tree's `(rel_path, file_root)` entries, in sorted path
/// order (the `BTreeMap` iterates sorted), so it is stable across machines.
fn tree_root(entries: &BTreeMap<String, FileManifest>) -> ContentId {
    let mut h = Sha256::new();
    h.update(TREE_ROOT_DOMAIN);
    h.update((entries.len() as u64).to_be_bytes());
    for (path, file) in entries {
        h.update((path.len() as u64).to_be_bytes());
        h.update(path.as_bytes());
        h.update(file.merkle_root.hash());
    }
    ContentId::new(h.finalize().into())
}

/// The delta a sender must transmit to bring a receiver from `prior` to
/// `current`, given the chunks the receiver already `have`s in its CAS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeDelta {
    /// Files that are new or whose content changed (root differs).
    pub changed_files: Vec<String>,
    /// Files present in `prior` but absent in `current`.
    pub removed_files: Vec<String>,
    /// Distinct chunk ids referenced by changed files that the receiver does NOT
    /// already hold — the only bytes that must actually be sent. Deduplicated and
    /// in first-seen order.
    pub new_chunks: Vec<ChunkId>,
}

impl TreeDelta {
    /// Whether the trees are identical (nothing to send).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changed_files.is_empty() && self.removed_files.is_empty() && self.new_chunks.is_empty()
    }
}

/// Diff `prior` → `current`, returning the minimal transmit set. Equal tree roots
/// short-circuit to an empty delta (O(1)); otherwise only files whose roots
/// differ are descended, and within them only chunks absent from `have` are
/// scheduled for transmission (content dedup). `have` is the receiver's CAS — a
/// chunk it already holds (from any file/version) is never re-sent.
#[must_use]
pub fn diff_trees(
    prior: &TreeManifest,
    current: &TreeManifest,
    have: &ContentAddressedStore,
) -> TreeDelta {
    let mut delta = TreeDelta::default();
    if prior.root == current.root {
        return delta; // hierarchical short-circuit: identical trees, send nothing.
    }

    let mut seen: HashSet<ChunkId> = HashSet::new();
    for (path, file) in &current.entries {
        let changed = match prior.entries.get(path) {
            Some(prev) => prev.merkle_root != file.merkle_root,
            None => true,
        };
        if !changed {
            continue; // subtree root matches: skip the whole file.
        }
        delta.changed_files.push(path.clone());
        for chunk in &file.chunks {
            if have.contains(&chunk.id) {
                continue; // receiver already holds this content.
            }
            if seen.insert(chunk.id.clone()) {
                delta.new_chunks.push(chunk.id.clone());
            }
        }
    }

    for path in prior.entries.keys() {
        if !current.entries.contains_key(path) {
            delta.removed_files.push(path.clone());
        }
    }

    delta
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refs_from(byte_chunks: &[&[u8]]) -> (Vec<ChunkRef>, Vec<Vec<u8>>) {
        let mut refs = Vec::new();
        let mut bytes = Vec::new();
        let mut offset = 0u64;
        for c in byte_chunks {
            refs.push(ChunkRef {
                id: chunk_id(c),
                offset,
                len: c.len() as u32,
            });
            offset += c.len() as u64;
            bytes.push(c.to_vec());
        }
        (refs, bytes)
    }

    #[test]
    fn cas_round_trip_and_dedup() {
        let mut cas = ContentAddressedStore::new();
        let (id1, new1) = cas.put(b"hello world");
        assert!(new1, "first insert is new");
        assert_eq!(cas.get(&id1), Some(b"hello world".as_slice()));
        assert_eq!(cas.len(), 1);

        // Re-inserting identical bytes is a dedup hit: not re-stored.
        let (id2, new2) = cas.put(b"hello world");
        assert_eq!(id1, id2, "identical bytes share one content id");
        assert!(!new2, "second insert is a dedup hit");
        assert_eq!(cas.len(), 1, "dedup hit must not grow the store");
        assert_eq!(cas.dedup_hits(), 1);
        assert_eq!(cas.bytes_deduped(), b"hello world".len() as u64);

        // Different bytes ⇒ different id, stored separately.
        let (id3, new3) = cas.put(b"goodbye");
        assert!(new3);
        assert_ne!(id1, id3);
        assert_eq!(cas.len(), 2);
        assert!(cas.contains(&id3));
    }

    #[test]
    fn merkle_root_is_stable_order_sensitive_and_distinct() {
        let a = chunk_id(b"a");
        let b = chunk_id(b"b");
        let c = chunk_id(b"c");

        // Stable: same inputs → same root.
        assert_eq!(
            chunk_merkle_root(&[a.clone(), b.clone(), c.clone()]),
            chunk_merkle_root(&[a.clone(), b.clone(), c.clone()])
        );
        // Order matters (file layout is ordered).
        assert_ne!(
            chunk_merkle_root(&[a.clone(), b.clone()]),
            chunk_merkle_root(&[b.clone(), a.clone()])
        );
        // Different content set → different root.
        assert_ne!(
            chunk_merkle_root(&[a.clone(), b.clone()]),
            chunk_merkle_root(&[a.clone(), c.clone()])
        );
        // Empty has a fixed, non-colliding root.
        assert_eq!(chunk_merkle_root(&[]), chunk_merkle_root(&[]));
        assert_ne!(chunk_merkle_root(&[]), chunk_merkle_root(&[a]));
    }

    #[test]
    fn tree_diff_skips_unchanged_localizes_change_and_dedups() {
        // Prior tree: two files.
        let (f1_refs, f1_bytes) = refs_from(&[b"alpha-0", b"alpha-1"]);
        let (f2_refs, f2_bytes) = refs_from(&[b"beta-0", b"beta-1"]);
        let prior = TreeManifest::from_files([
            FileManifest::from_chunks("dir/a.bin", f1_refs.clone()),
            FileManifest::from_chunks("dir/b.bin", f2_refs),
        ]);

        // Receiver already holds every prior chunk in its CAS.
        let mut have = ContentAddressedStore::new();
        for b in f1_bytes.iter().chain(f2_bytes.iter()) {
            have.put(b);
        }

        // Identical current tree ⇒ empty delta (root short-circuit).
        let same = diff_trees(&prior, &prior, &have);
        assert!(same.is_empty(), "identical trees transmit nothing");

        // Current: a.bin gains one NEW chunk; b.bin unchanged.
        let (mut f1b_refs, _) = refs_from(&[b"alpha-0", b"alpha-1"]);
        let new_chunk: &[u8] = b"alpha-2-NEW";
        f1b_refs.push(ChunkRef {
            id: chunk_id(new_chunk),
            offset: 14,
            len: new_chunk.len() as u32,
        });
        let current = TreeManifest::from_files([
            FileManifest::from_chunks("dir/a.bin", f1b_refs),
            FileManifest::from_chunks("dir/b.bin", f2_refs_clone()),
        ]);

        let delta = diff_trees(&prior, &current, &have);
        assert_eq!(delta.changed_files, vec!["dir/a.bin".to_string()], "only a.bin changed");
        assert!(delta.removed_files.is_empty());
        // Only the genuinely new chunk is scheduled; the two reused chunks are
        // dedup hits already in `have`.
        assert_eq!(delta.new_chunks, vec![chunk_id(new_chunk)]);
    }

    // Helper: rebuild b.bin's refs (same content) for the "current" tree.
    fn f2_refs_clone() -> Vec<ChunkRef> {
        refs_from(&[b"beta-0", b"beta-1"]).0
    }

    #[test]
    fn diff_reports_removed_files_and_new_file_chunks() {
        let prior = TreeManifest::from_files([
            FileManifest::from_chunks("keep.bin", refs_from(&[b"k0"]).0),
            FileManifest::from_chunks("gone.bin", refs_from(&[b"g0"]).0),
        ]);
        // Current: gone.bin removed, fresh.bin added (receiver lacks its chunk).
        let have = ContentAddressedStore::new();
        let current = TreeManifest::from_files([
            FileManifest::from_chunks("keep.bin", refs_from(&[b"k0"]).0),
            FileManifest::from_chunks("fresh.bin", refs_from(&[b"new!"]).0),
        ]);
        let delta = diff_trees(&prior, &current, &have);
        assert!(delta.changed_files.contains(&"fresh.bin".to_string()));
        assert!(delta.removed_files.contains(&"gone.bin".to_string()));
        // keep.bin chunk k0 is not in `have`, but keep.bin is UNCHANGED so it is
        // never descended → only fresh.bin's chunk is transmitted.
        assert_eq!(delta.new_chunks, vec![chunk_id(b"new!")]);
    }
}
