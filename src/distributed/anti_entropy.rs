//! Merkle-range anti-entropy: reconcile large key→hash stores by exchanging
//! `O(log n)` interval hashes and descending only into mismatched ranges
//! (bead `asupersync-dist-otp-completeness-8y37kz.6`).
//!
//! Distributed sagas and snapshots can diverge across a partition. Full-state
//! exchange to reconcile is `O(n)`; a Merkle tree over the keyspace lets two
//! replicas compare a root hash, then descend only the subtrees that differ,
//! exchanging `O(k log n)` hashes for `k` divergent keys (the Dynamo-lineage
//! breakthrough).
//!
//! This module is the pure tree + diff core. Keys are bucketed by the high bits
//! of a fixed FNV-1a-64 hash into a complete binary tree of `2^depth` leaves, so
//! two replicas build the *same* tree shape regardless of which keys each holds
//! (a key present on only one side simply makes its bucket's hash differ). The
//! hash is self-contained and deterministic — it does not depend on the
//! `det_hash` machinery (so it is independent of the `det_hash` reseed fix the
//! bead notes), and identical content yields identical roots across replicas.
//!
//! The anti-entropy *session* protocol (transport-agnostic state machine), the
//! saga/snapshot consumers, and the partition-heal trigger layer on top of this
//! core; the diff output feeds the existing repair / lattice-merge paths.

use std::collections::BTreeMap;

/// FNV-1a 64-bit hash (fixed constants → stable across builds and replicas).
fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Combines two child hashes into a parent hash (order-sensitive).
fn combine(left: u64, right: u64) -> u64 {
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&left.to_le_bytes());
    buf[8..16].copy_from_slice(&right.to_le_bytes());
    fnv1a64(&buf)
}

/// How a key differs between two replicas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    /// Present on the local replica only (absent on the remote). A key present
    /// on both with a differing content hash is [`DiffKind::HashDiffers`], not
    /// this variant.
    OnlyHere,
    /// Present on the remote replica only.
    OnlyThere,
    /// Present on both, but with differing content hashes.
    HashDiffers,
}

/// A single key-level divergence found by [`MerkleRangeTree::diff`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDiff {
    /// The divergent key.
    pub key: Vec<u8>,
    /// How it differs.
    pub kind: DiffKind,
}

/// The result of a diff: the key-level divergences plus the number of tree
/// nodes compared (the anti-entropy cost — should scale with the divergence,
/// not the keyspace).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffReport {
    /// Key-level divergences, in ascending key order.
    pub diffs: Vec<KeyDiff>,
    /// Tree nodes compared while descending (the `O(k log n)` cost witness).
    pub nodes_compared: usize,
}

/// A Merkle tree over a hashed keyspace for anti-entropy reconciliation.
#[derive(Debug, Clone)]
pub struct MerkleRangeTree {
    depth: u8,
    /// Per-leaf-bucket key → content-hash maps (sorted for deterministic hashing).
    buckets: Vec<BTreeMap<Vec<u8>, u64>>,
    /// Implicit complete binary tree of node hashes: `nodes[1]` is the root,
    /// node `i`'s children are `2i` and `2i+1`, leaves at `[2^depth, 2^(depth+1))`.
    nodes: Vec<u64>,
}

impl MerkleRangeTree {
    /// Creates an empty tree with `2^depth` leaf buckets. `depth` is clamped to
    /// `1..=24` (so the implicit node array stays sane).
    #[must_use]
    pub fn new(depth: u8) -> Self {
        let depth = depth.clamp(1, 24);
        let leaves = 1usize << depth;
        let mut tree = Self {
            depth,
            buckets: vec![BTreeMap::new(); leaves],
            nodes: vec![0u64; leaves * 2],
        };
        tree.recompute_all();
        tree
    }

    /// The tree depth (`2^depth` leaf buckets).
    #[must_use]
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// The root hash (identical across replicas with identical content).
    #[must_use]
    pub fn root(&self) -> u64 {
        self.nodes[1]
    }

    /// Inserts or updates `key`'s content hash, recomputing only the affected
    /// leaf and its path to the root (`O(depth)` — incremental, no full rebuild).
    pub fn insert(&mut self, key: Vec<u8>, content_hash: u64) {
        let bucket = self.bucket_of(&key);
        self.buckets[bucket].insert(key, content_hash);
        self.recompute_path(bucket);
    }

    /// Removes `key`, recomputing the affected path. No-op if absent.
    pub fn remove(&mut self, key: &[u8]) {
        let bucket = self.bucket_of(key);
        if self.buckets[bucket].remove(key).is_some() {
            self.recompute_path(bucket);
        }
    }

    /// Total keys stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buckets.iter().map(BTreeMap::len).sum()
    }

    /// Whether the tree holds no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(BTreeMap::is_empty)
    }

    /// Computes the key-level divergences against `other`, descending only the
    /// subtrees whose hashes differ. Both trees must share the same `depth`.
    #[must_use]
    pub fn diff(&self, other: &Self) -> DiffReport {
        assert_eq!(
            self.depth, other.depth,
            "anti-entropy requires equal tree depth"
        );
        let leaf_base = 1usize << self.depth;
        let mut diffs = Vec::new();
        let mut nodes_compared = 0usize;
        let mut stack = vec![1usize];
        while let Some(i) = stack.pop() {
            nodes_compared += 1;
            if self.nodes[i] == other.nodes[i] {
                continue; // identical subtree — prune
            }
            if i >= leaf_base {
                self.diff_bucket(other, i - leaf_base, &mut diffs);
            } else {
                stack.push(2 * i);
                stack.push(2 * i + 1);
            }
        }
        diffs.sort_by(|a, b| a.key.cmp(&b.key));
        DiffReport {
            diffs,
            nodes_compared,
        }
    }

    fn diff_bucket(&self, other: &Self, bucket: usize, diffs: &mut Vec<KeyDiff>) {
        let here = &self.buckets[bucket];
        let there = &other.buckets[bucket];
        for (key, hash) in here {
            match there.get(key) {
                None => diffs.push(KeyDiff {
                    key: key.clone(),
                    kind: DiffKind::OnlyHere,
                }),
                Some(other_hash) if other_hash != hash => diffs.push(KeyDiff {
                    key: key.clone(),
                    kind: DiffKind::HashDiffers,
                }),
                Some(_) => {}
            }
        }
        for key in there.keys() {
            if !here.contains_key(key) {
                diffs.push(KeyDiff {
                    key: key.clone(),
                    kind: DiffKind::OnlyThere,
                });
            }
        }
    }

    fn bucket_of(&self, key: &[u8]) -> usize {
        let hash = fnv1a64(key);
        // Top `depth` bits select the leaf bucket.
        (hash >> (64 - u32::from(self.depth))) as usize
    }

    fn leaf_hash(bucket: &BTreeMap<Vec<u8>, u64>) -> u64 {
        // Deterministic over the bucket's sorted (key, content-hash) pairs.
        let mut acc = fnv1a64(b"membrane-leaf");
        for (key, content) in bucket {
            acc = combine(acc, fnv1a64(key));
            acc = combine(acc, *content);
        }
        acc
    }

    fn recompute_path(&mut self, bucket: usize) {
        let leaf_base = 1usize << self.depth;
        let mut i = leaf_base + bucket;
        self.nodes[i] = Self::leaf_hash(&self.buckets[bucket]);
        while i > 1 {
            i /= 2;
            self.nodes[i] = combine(self.nodes[2 * i], self.nodes[2 * i + 1]);
        }
    }

    fn recompute_all(&mut self) {
        let leaf_base = 1usize << self.depth;
        for b in 0..self.buckets.len() {
            self.nodes[leaf_base + b] = Self::leaf_hash(&self.buckets[b]);
        }
        for i in (1..leaf_base).rev() {
            self.nodes[i] = combine(self.nodes[2 * i], self.nodes[2 * i + 1]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree_with(depth: u8, entries: &[(&str, u64)]) -> MerkleRangeTree {
        let mut t = MerkleRangeTree::new(depth);
        for (k, h) in entries {
            t.insert(k.as_bytes().to_vec(), *h);
        }
        t
    }

    #[test]
    fn identical_content_yields_identical_root_regardless_of_insert_order() {
        // AC1: deterministic roots across replicas with identical content.
        let a = tree_with(8, &[("alpha", 1), ("beta", 2), ("gamma", 3)]);
        let b = tree_with(8, &[("gamma", 3), ("alpha", 1), ("beta", 2)]);
        assert_eq!(a.root(), b.root());
        assert_eq!(a.diff(&b).diffs, vec![]);
    }

    #[test]
    fn incremental_update_equals_rebuild() {
        // AC1: incremental insert/remove path-recompute == a from-scratch build.
        let mut incremental = MerkleRangeTree::new(8);
        incremental.insert(b"k1".to_vec(), 10);
        incremental.insert(b"k2".to_vec(), 20);
        incremental.insert(b"k3".to_vec(), 30);
        incremental.insert(b"k2".to_vec(), 99); // update
        incremental.remove(b"k3");

        let rebuilt = tree_with(8, &[("k1", 10), ("k2", 99)]);
        assert_eq!(incremental.root(), rebuilt.root());
        assert_eq!(incremental.len(), 2);
    }

    #[test]
    fn diff_finds_exactly_the_divergent_keys() {
        let here = tree_with(8, &[("a", 1), ("b", 2), ("c", 3), ("d", 4)]);
        let there = tree_with(8, &[("a", 1), ("b", 999), ("d", 4), ("e", 5)]);
        let report = here.diff(&there);
        let kinds: Vec<(&[u8], DiffKind)> = report
            .diffs
            .iter()
            .map(|d| (d.key.as_slice(), d.kind))
            .collect();
        assert!(kinds.contains(&(b"b".as_slice(), DiffKind::HashDiffers)));
        assert!(kinds.contains(&(b"c".as_slice(), DiffKind::OnlyHere)));
        assert!(kinds.contains(&(b"e".as_slice(), DiffKind::OnlyThere)));
        assert_eq!(report.diffs.len(), 3);
        // "a" and "d" are identical and must not appear.
        assert!(!kinds.iter().any(|(k, _)| *k == b"a" || *k == b"d"));
    }

    #[test]
    fn diff_cost_scales_with_divergence_not_keyspace() {
        // AC2: many identical keys, a few differing -> few nodes compared.
        let depth = 10u8; // 1024 buckets, 2048 nodes
        let mut here = MerkleRangeTree::new(depth);
        let mut there = MerkleRangeTree::new(depth);
        for i in 0..2000u32 {
            let key = format!("key-{i}").into_bytes();
            here.insert(key.clone(), u64::from(i));
            there.insert(key, u64::from(i));
        }
        // Diverge exactly 3 keys.
        there.insert(b"key-100".to_vec(), 999_999);
        there.insert(b"key-500".to_vec(), 888_888);
        there.remove(b"key-1500");

        let report = here.diff(&there);
        assert_eq!(report.diffs.len(), 3);
        // Identical stores would compare just the root; with 3 divergent keys in
        // at most 3 buckets, far fewer than the full 2*1024 nodes are visited.
        let total_nodes = 2usize * (1usize << depth);
        assert!(
            report.nodes_compared < total_nodes / 4,
            "compared {} of {total_nodes} nodes — should scale with divergence",
            report.nodes_compared
        );
    }

    #[test]
    fn identical_trees_compare_only_the_root() {
        let a = tree_with(8, &[("x", 1), ("y", 2)]);
        let b = tree_with(8, &[("x", 1), ("y", 2)]);
        let report = a.diff(&b);
        assert!(report.diffs.is_empty());
        assert_eq!(
            report.nodes_compared, 1,
            "identical roots prune immediately"
        );
    }
}
