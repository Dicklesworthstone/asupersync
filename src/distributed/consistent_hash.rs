//! Deterministic consistent hashing ring with virtual nodes.
//!
//! Used for stable key-to-replica assignment with minimal remapping when
//! replicas are added or removed. For ephemeral routing decisions over a
//! transient candidate set, prefer the salted HRW helpers below so callers do
//! not pay to rebuild and sort a virtual-node ring on every lookup.

use crate::util::det_hash::DetHasher;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};

/// Errors returned by fallible HashRing constructors.
///
/// br-asupersync-un962v.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsistentHashError {
    /// `HashRing::try_new` was called with `vnodes_per_node == 0`. A
    /// ring with zero virtual nodes silently blackholes routing —
    /// every key returns `None` from `node_for_key`. The fallible
    /// constructor rejects this configuration up front so a misset
    /// config does not produce a healthy-looking ring with no
    /// reachable replicas.
    ZeroVnodes,
}

impl std::fmt::Display for ConsistentHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroVnodes => write!(
                f,
                "consistent-hash ring requires vnodes_per_node >= 1 \
                 (zero-vnode rings silently blackhole all routing; br-asupersync-un962v)"
            ),
        }
    }
}

impl std::error::Error for ConsistentHashError {}

/// A consistent hash ring with virtual nodes.
///
/// br-asupersync-rnybb1: vnode placement is salted with a per-ring
/// `seed`. Pre-fix the ring used `DetHasher::default()` (FNV-1a with
/// a publicly-known fixed seed) for both vnode placement and key
/// hashing — an attacker who could control any portion of the
/// hashed key space could compute keys that all hashed into the
/// same vnode bucket and pin the entire load to one replica
/// (load-pinning DoS). Post-fix, every hash is salted with the
/// `seed` field which production callers populate from
/// [`crate::util::OsEntropy`] (per-deployment random) and tests /
/// lab callers populate with a fixed value for replay determinism.
#[derive(Debug, Clone)]
pub struct HashRing {
    vnodes_per_node: usize,
    nodes: BTreeSet<String>,
    ring: Vec<VirtualNode>,
    /// br-asupersync-rnybb1: per-ring hash salt. Mixed into every
    /// `vnode_hash` and `hash_value` call so that an attacker who
    /// reverse-engineers the FNV-1a algorithm cannot pre-compute
    /// colliding keys without ALSO knowing this seed. Production
    /// rings should source it from `OsEntropy::next_u64()` at
    /// construction time; tests / lab use a fixed value.
    seed: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct VirtualNode {
    hash: u64,
    node_id: String,
    vnode: u32,
}

impl HashRing {
    /// Create a new hash ring with the given number of virtual nodes
    /// per node and an explicit hash salt.
    ///
    /// br-asupersync-rnybb1: `seed` SHOULD be unique per deployment
    /// (e.g., sourced from [`crate::util::OsEntropy::next_u64`] at
    /// startup) so that an attacker cannot pre-compute keys that
    /// collide on a known seed. Tests, lab runs, and any caller that
    /// requires byte-for-byte ring reproducibility should pass a
    /// fixed seed (e.g., `0`) — the security gate is only meaningful
    /// when keys are attacker-influenced.
    ///
    /// br-asupersync-un962v: `vnodes_per_node` is clamped to `>= 1`
    /// to avoid silently constructing a blackhole ring. A ring with
    /// zero virtual nodes accepts `add_node` calls but every key
    /// lookup returns `None` — a config-validation gap that any
    /// caller treating `node_count > 0` as healthy would silently
    /// route into. Callers that want to surface zero-vnode errors
    /// should use [`Self::try_new`] instead of clamping silently.
    #[must_use]
    pub fn new(vnodes_per_node: usize, seed: u64) -> Self {
        Self {
            // br-asupersync-un962v: clamp to at least 1 vnode so the
            // resulting ring is never a blackhole. Mirrors the
            // niczb3 worker_count clamp pattern in three_lane.rs.
            vnodes_per_node: vnodes_per_node.max(1),
            nodes: BTreeSet::new(),
            ring: Vec::new(),
            seed,
        }
    }

    /// br-asupersync-un962v: fallible constructor that rejects
    /// zero-vnode configurations up front with
    /// [`ConsistentHashError::ZeroVnodes`]. Use this from
    /// configuration-validation paths that want to surface
    /// misconfigured rings instead of accepting a silently-clamped
    /// fallback.
    pub fn try_new(vnodes_per_node: usize, seed: u64) -> Result<Self, ConsistentHashError> {
        if vnodes_per_node == 0 {
            return Err(ConsistentHashError::ZeroVnodes);
        }
        Ok(Self {
            vnodes_per_node,
            nodes: BTreeSet::new(),
            ring: Vec::new(),
            seed,
        })
    }

    /// Construct a HashRing seeded from OS entropy. Equivalent to
    /// `HashRing::new(vnodes_per_node, OsEntropy.next_u64())`.
    /// Production-grade default for new rings; tests should use
    /// `HashRing::new(vnodes_per_node, fixed_seed)` for determinism.
    ///
    /// br-asupersync-rnybb1.
    #[must_use]
    pub fn with_os_entropy(vnodes_per_node: usize) -> Self {
        use crate::util::EntropySource;
        let seed = crate::util::OsEntropy.next_u64();
        Self::new(vnodes_per_node, seed)
    }

    /// Returns the hash salt used by this ring. Exposed for diagnostics
    /// and replay-stability assertions; do not log this value
    /// alongside attacker-influenced keys.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Returns the number of registered nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the number of virtual nodes in the ring.
    #[must_use]
    pub fn vnode_count(&self) -> usize {
        self.ring.len()
    }

    /// Returns true if the ring has no virtual nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    /// Adds a node to the ring. Returns false if the node already exists.
    pub fn add_node(&mut self, node_id: impl Into<String>) -> bool {
        let node_id = node_id.into();
        if self.nodes.contains(&node_id) {
            return false;
        }
        self.nodes.insert(node_id.clone());

        if self.vnodes_per_node == 0 {
            return true;
        }

        for vnode in 0..self.vnodes_per_node {
            let hash = vnode_hash(self.seed, &node_id, vnode as u32);
            self.ring.push(VirtualNode {
                hash,
                node_id: node_id.clone(),
                vnode: vnode as u32,
            });
        }

        self.ring.sort_by(|a, b| {
            a.hash
                .cmp(&b.hash)
                .then_with(|| a.node_id.cmp(&b.node_id))
                .then_with(|| a.vnode.cmp(&b.vnode))
        });
        true
    }

    /// Removes a node and all its virtual nodes. Returns count of removed vnodes.
    pub fn remove_node(&mut self, node_id: &str) -> usize {
        if !self.nodes.remove(node_id) {
            return 0;
        }
        let before = self.ring.len();
        self.ring.retain(|vn| vn.node_id != node_id);
        before.saturating_sub(self.ring.len())
    }

    /// Returns the node responsible for a key, if any.
    #[must_use]
    pub fn node_for_key<K: Hash>(&self, key: &K) -> Option<&str> {
        if self.ring.is_empty() {
            return None;
        }
        let key_hash = hash_value(self.seed, key);
        let idx = self.ring.partition_point(|vn| vn.hash < key_hash);
        let idx = if idx == self.ring.len() { 0 } else { idx };
        Some(self.ring[idx].node_id.as_str())
    }

    /// Returns node identifiers in deterministic sorted order.
    pub fn nodes(&self) -> impl Iterator<Item = &str> {
        self.nodes.iter().map(String::as_str)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct HrwScore {
    score: f64,
    tie_break: u64,
}

impl Eq for HrwScore {}

impl PartialOrd for HrwScore {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HrwScore {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.score
            .total_cmp(&other.score)
            .then_with(|| self.tie_break.cmp(&other.tie_break))
    }
}

/// Salted Highest Random Weight (rendezvous) selection over a transient
/// candidate set.
///
/// This is the preferred hot-path scoring primitive when the membership set is
/// not persistent enough to justify materializing a [`HashRing`].
#[must_use]
pub(crate) fn select_hrw<'a, I, T, K, N, Node, Weight>(
    candidates: I,
    key: &K,
    seed: u64,
    node_id: Node,
    weight: Weight,
) -> Option<&'a T>
where
    I: IntoIterator<Item = &'a T>,
    K: Hash,
    N: Hash + ?Sized + 'a,
    Node: Fn(&'a T) -> &'a N,
    Weight: Fn(&T) -> u32,
{
    let mut best = None;
    for candidate in candidates {
        let candidate_node = node_id(candidate);
        let Some(score) = hrw_score(seed, key, candidate_node, weight(candidate)) else {
            continue;
        };
        if best.is_none_or(|(best_score, _)| score > best_score) {
            best = Some((score, candidate));
        }
    }
    best.map(|(_, candidate)| candidate)
}

/// Exact duplicate-free top-k HRW selection over a transient candidate set.
///
/// For the small `k` used in routing and placement policies, keeping a sorted
/// in-memory winner buffer avoids the old ring-build churn without introducing
/// heap traffic.
#[must_use]
#[allow(dead_code)]
pub(crate) fn select_top_k_hrw<'a, I, T, K, N, Node, Weight>(
    candidates: I,
    limit: usize,
    key: &K,
    seed: u64,
    node_id: Node,
    weight: Weight,
) -> Vec<&'a T>
where
    I: IntoIterator<Item = &'a T>,
    K: Hash,
    N: Hash + ?Sized + 'a,
    Node: Fn(&'a T) -> &'a N,
    Weight: Fn(&T) -> u32,
{
    if limit == 0 {
        return Vec::new();
    }

    let mut winners = Vec::with_capacity(limit);
    for candidate in candidates {
        let candidate_node = node_id(candidate);
        let Some(score) = hrw_score(seed, key, candidate_node, weight(candidate)) else {
            continue;
        };

        let insert_at = winners.partition_point(|(winner_score, _)| *winner_score > score);
        if insert_at >= limit {
            continue;
        }
        winners.insert(insert_at, (score, candidate));
        if winners.len() > limit {
            winners.pop();
        }
    }

    winners
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect()
}

/// br-asupersync-rnybb1: salted vnode placement hash. The `seed` is
/// hashed FIRST so that two HashRings with different seeds produce
/// disjoint vnode placements even for identical (node_id, vnode)
/// inputs. This defeats pre-computed collision attacks against the
/// known FNV-1a default seed.
fn vnode_hash(seed: u64, node_id: &str, vnode: u32) -> u64 {
    let mut hasher = DetHasher::default();
    seed.hash(&mut hasher);
    node_id.hash(&mut hasher);
    vnode.hash(&mut hasher);
    hasher.finish()
}

/// br-asupersync-rnybb1: salted key hash. Mirrors `vnode_hash` so
/// that key-to-vnode mapping uses the same salt domain.
fn hash_value<T: Hash>(seed: u64, value: &T) -> u64 {
    let mut hasher = DetHasher::default();
    seed.hash(&mut hasher);
    value.hash(&mut hasher);
    hasher.finish()
}

#[allow(clippy::cast_precision_loss)]
fn hrw_score<K: Hash, N: Hash + ?Sized>(
    seed: u64,
    key: &K,
    node_id: &N,
    weight: u32,
) -> Option<HrwScore> {
    if weight == 0 {
        return None;
    }

    let mut hasher = DetHasher::default();
    seed.hash(&mut hasher);
    "hrw-score".hash(&mut hasher);
    key.hash(&mut hasher);
    node_id.hash(&mut hasher);
    let hash = hasher.finish();

    let mut tie_break_hasher = DetHasher::default();
    seed.hash(&mut tie_break_hasher);
    "hrw-tie-break".hash(&mut tie_break_hasher);
    node_id.hash(&mut tie_break_hasher);
    let tie_break = tie_break_hasher.finish();

    let unit = (hash as f64 + 1.0) / (u64::MAX as f64 + 1.0);
    Some(HrwScore {
        score: f64::from(weight) / -unit.ln(),
        tie_break,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use serde_json::json;
    use std::hash::{Hash, Hasher};

    fn build_ring(node_count: usize, vnodes_per_node: usize) -> HashRing {
        // br-asupersync-rnybb1: tests use a fixed seed (0) for
        // deterministic ring placement; production callers should use
        // `HashRing::with_os_entropy` instead.
        let mut ring = HashRing::new(vnodes_per_node, 0);
        for i in 0..node_count {
            ring.add_node(format!("node-{i}"));
        }
        ring
    }

    fn canonical_fixed_seed_key_node_mapping_snapshot() -> serde_json::Value {
        let mut ring = HashRing::new(32, 0x5eed_cafe);
        for node in ["node-a", "node-b", "node-c", "node-d"] {
            assert!(ring.add_node(node), "fixture node should be unique");
        }

        let representative_keys = [
            "blob:deadbeef",
            "blob:cafebabe",
            "order:000001",
            "order:000128",
            "region:us-east-1",
            "region:eu-west-1",
            "route:/v1/health",
            "route:/v1/orders/42",
            "session:0001",
            "session:1042",
            "tenant:acme/invoices",
            "tenant:acme/orders/99",
            "tenant:globex/alerts",
            "user:alice",
            "user:bob",
            "user:zoe",
        ];

        json!({
            "seed": ring.seed(),
            "vnodes_per_node": 32,
            "nodes": ring.nodes().collect::<Vec<_>>(),
            "assignments": representative_keys
                .iter()
                .map(|key| {
                    json!({
                        "key": key,
                        "node": ring
                            .node_for_key(key)
                            .expect("fixture ring should assign representative key"),
                    })
                })
                .collect::<Vec<_>>(),
        })
    }

    fn reference_vnode_hash(seed: u64, node_id: &str, vnode: u32) -> u64 {
        let mut hasher = DetHasher::default();
        seed.hash(&mut hasher);
        node_id.hash(&mut hasher);
        vnode.hash(&mut hasher);
        hasher.finish()
    }

    fn reference_key_hash<K: Hash>(seed: u64, key: &K) -> u64 {
        let mut hasher = DetHasher::default();
        seed.hash(&mut hasher);
        key.hash(&mut hasher);
        hasher.finish()
    }

    fn reference_karger_mapping_bytes(
        seed: u64,
        vnodes_per_node: usize,
        nodes: &[String],
        keys: &[String],
    ) -> Vec<u8> {
        let mut ring = Vec::with_capacity(nodes.len() * vnodes_per_node);
        for node_id in nodes {
            for vnode in 0..vnodes_per_node {
                ring.push((
                    reference_vnode_hash(seed, node_id, vnode as u32),
                    node_id.clone(),
                    vnode as u32,
                ));
            }
        }
        ring.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.cmp(&b.1))
                .then_with(|| a.2.cmp(&b.2))
        });

        let assignments: Vec<(String, String)> = keys
            .iter()
            .map(|key| {
                let key_hash = reference_key_hash(seed, key);
                let idx = ring.partition_point(|(hash, _, _)| *hash < key_hash);
                let idx = if idx == ring.len() { 0 } else { idx };
                (key.clone(), ring[idx].1.clone())
            })
            .collect();
        serde_json::to_vec(&assignments).expect("serialize reference assignments")
    }

    fn ring_mapping_bytes(ring: &HashRing, keys: &[String]) -> Vec<u8> {
        let assignments: Vec<(String, String)> = keys
            .iter()
            .map(|key| {
                (
                    key.clone(),
                    ring.node_for_key(key)
                        .expect("ring should assign every key")
                        .to_owned(),
                )
            })
            .collect();
        serde_json::to_vec(&assignments).expect("serialize ring assignments")
    }

    #[test]
    fn ring_construction_orders_vnodes() {
        let ring = build_ring(4, 8);
        assert_eq!(ring.node_count(), 4);
        assert_eq!(ring.vnode_count(), 32);
        assert!(!ring.is_empty());

        for window in ring.ring.windows(2) {
            let a = &window[0];
            let b = &window[1];
            let ordered = (a.hash, &a.node_id, a.vnode) <= (b.hash, &b.node_id, b.vnode);
            assert!(ordered, "ring not sorted");
        }
    }

    #[test]
    fn vnode_distribution_per_node_is_exact() {
        let ring = build_ring(3, 16);
        let mut counts = std::collections::BTreeMap::new();
        for vn in &ring.ring {
            *counts.entry(vn.node_id.as_str()).or_insert(0usize) += 1;
        }
        assert_eq!(counts.len(), 3);
        for count in counts.values() {
            assert_eq!(*count, 16);
        }
    }

    #[test]
    fn key_lookup_returns_expected_node() {
        let mut ring = HashRing::new(8, 0);
        assert!(ring.node_for_key(&"alpha").is_none());
        ring.add_node("a");
        ring.add_node("b");
        ring.add_node("c");

        let first = ring.node_for_key(&"alpha");
        let second = ring.node_for_key(&"alpha");
        assert_eq!(first, second);
        assert!(matches!(first, Some("a" | "b" | "c")));
    }

    #[test]
    fn karger_reference_mapping_matches_hash_ring_for_1000_keys_and_100_nodes() {
        let seed = 0xC0DE_1000_u64;
        let replica_count = 64usize;
        let nodes: Vec<String> = (0..100).map(|idx| format!("node-{idx:03}")).collect();
        let keys: Vec<String> = (0..1000).map(|idx| format!("key-{idx:04}")).collect();

        let mut ring = HashRing::new(replica_count, seed);
        for node in &nodes {
            assert!(ring.add_node(node.clone()), "fixture node should be unique");
        }

        let actual = ring_mapping_bytes(&ring, &keys);
        let reference = reference_karger_mapping_bytes(seed, replica_count, &nodes, &keys);

        assert_eq!(
            actual, reference,
            "HashRing mapping must match the Karger-style reference implementation byte-for-byte"
        );
    }

    #[test]
    fn add_node_minimal_remap() {
        let mut ring = build_ring(5, 64);
        let keys: Vec<u64> = (0..10_000u64).collect();

        let before: Vec<String> = keys
            .iter()
            .map(|k| ring.node_for_key(k).unwrap().to_owned()) // ubs:ignore - test helper
            .collect();

        ring.add_node("node-new");

        let after: Vec<String> = keys
            .iter()
            .map(|k| ring.node_for_key(k).unwrap().to_owned()) // ubs:ignore - test helper
            .collect();

        let changed = before
            .iter()
            .zip(after.iter())
            .filter(|(a, b)| a != b)
            .count();
        let changed_f = f64::from(u32::try_from(changed).expect("changed fits u32"));
        let keys_len_f = f64::from(u32::try_from(keys.len()).expect("keys len fits u32"));
        let ratio = changed_f / keys_len_f;

        // Expected ~1/(n+1) for n=5; allow conservative headroom.
        assert!(ratio <= 0.30, "remap ratio too high: {ratio}");
    }

    #[test]
    fn remove_node_remaps_only_that_node() {
        let mut ring = build_ring(4, 64);
        let keys: Vec<u64> = (0..10_000u64).collect();

        let before: Vec<String> = keys
            .iter()
            .map(|k| ring.node_for_key(k).unwrap().to_owned()) // ubs:ignore - test helper
            .collect();

        let removed = "node-2";
        ring.remove_node(removed);

        let after: Vec<String> = keys
            .iter()
            .map(|k| ring.node_for_key(k).unwrap().to_owned()) // ubs:ignore - test helper
            .collect();

        let changed = before
            .iter()
            .zip(after.iter())
            .filter(|(a, b)| a != b)
            .count();
        let removed_count = before.iter().filter(|n| n.as_str() == removed).count();
        assert_eq!(changed, removed_count);
    }

    #[test]
    fn uniformity_chi_squared_is_reasonable() {
        let ring = build_ring(5, 128);
        let keys: Vec<u64> = (0..20_000u64).collect();

        let mut counts = std::collections::BTreeMap::new();
        for key in keys {
            let node = ring.node_for_key(&key).expect("node");
            *counts.entry(node).or_insert(0usize) += 1;
        }

        let total = counts.values().sum::<usize>();
        #[allow(clippy::cast_precision_loss)]
        let total_f = total as f64;
        #[allow(clippy::cast_precision_loss)]
        let count_len_f = counts.len() as f64;
        let expected = total_f / count_len_f;
        let chi_sq: f64 = counts
            .values()
            .map(|&obs| {
                #[allow(clippy::cast_precision_loss)]
                let obs_f = obs as f64;
                let diff = obs_f - expected;
                diff * diff / expected
            })
            .sum();

        let max_dev = counts
            .values()
            .map(|&obs| {
                #[allow(clippy::cast_precision_loss)]
                let obs_f = obs as f64;
                (obs_f - expected).abs() / expected
            })
            .fold(0.0, f64::max);

        assert!(max_dev <= 0.25, "distribution skew too high: {max_dev}");
        // With DetHasher on sequential u64 keys, distribution variance is higher
        // than with cryptographic hashes. Threshold accommodates observed behavior.
        assert!(chi_sq < 500.0, "chi-square too high: {chi_sq}");
    }

    #[test]
    fn remove_nonexistent_node_is_noop() {
        let mut ring = build_ring(3, 8);
        let removed = ring.remove_node("missing");
        assert_eq!(removed, 0);
        assert_eq!(ring.node_count(), 3);
    }

    #[test]
    fn zero_vnodes_constructor_clamps_to_single_vnode_until_removed() {
        let mut ring = HashRing::new(0, 0);
        ring.add_node("a");
        assert_eq!(ring.vnode_count(), 1);
        for key in ["alpha", "beta", "gamma"] {
            assert_eq!(ring.node_for_key(&key), Some("a"));
        }
        assert_eq!(ring.remove_node("a"), 1);
        assert!(ring.node_for_key(&"key").is_none());
    }

    /// Invariant: adding a duplicate node is idempotent — node_count and
    /// vnode_count must not change on the second add.
    #[test]
    fn duplicate_add_node_is_idempotent() {
        let mut ring = HashRing::new(16, 0);
        assert!(ring.add_node("a"));
        assert_eq!(ring.node_count(), 1);
        assert_eq!(ring.vnode_count(), 16);

        // Second add returns false and state is unchanged.
        assert!(!ring.add_node("a"));
        assert_eq!(ring.node_count(), 1);
        assert_eq!(ring.vnode_count(), 16);
    }

    /// Invariant: single-node ring, add then remove leaves an empty ring
    /// where node_for_key returns None.
    #[test]
    fn single_node_add_remove_leaves_empty_ring() {
        let mut ring = HashRing::new(8, 0);
        ring.add_node("only-node");
        assert_eq!(ring.node_count(), 1);
        assert!(ring.node_for_key(&42u64).is_some());

        let removed = ring.remove_node("only-node");
        assert_eq!(removed, 8);
        assert_eq!(ring.node_count(), 0);
        assert_eq!(ring.vnode_count(), 0);
        assert!(ring.is_empty());
        assert!(
            ring.node_for_key(&42u64).is_none(),
            "empty ring must return None for any key"
        );
    }

    /// Invariant: key assignment is deterministic across identical ring builds.
    #[test]
    fn deterministic_assignment_across_builds() {
        let build = || {
            let mut ring = HashRing::new(32, 0);
            for name in &["alpha", "beta", "gamma"] {
                ring.add_node(*name);
            }
            ring
        };

        let r1 = build();
        let r2 = build();

        for key in 0..1000u64 {
            assert_eq!(
                r1.node_for_key(&key),
                r2.node_for_key(&key),
                "key {key} assigned differently across builds"
            );
        }
    }

    #[test]
    fn canonical_fixed_seed_key_node_mapping() {
        assert_eq!(
            canonical_fixed_seed_key_node_mapping_snapshot(),
            json!({
                "assignments": [
                    { "key": "blob:deadbeef", "node": "node-b" },
                    { "key": "blob:cafebabe", "node": "node-a" },
                    { "key": "order:000001", "node": "node-a" },
                    { "key": "order:000128", "node": "node-a" },
                    { "key": "region:us-east-1", "node": "node-d" },
                    { "key": "region:eu-west-1", "node": "node-c" },
                    { "key": "route:/v1/health", "node": "node-c" },
                    { "key": "route:/v1/orders/42", "node": "node-b" },
                    { "key": "session:0001", "node": "node-c" },
                    { "key": "session:1042", "node": "node-d" },
                    { "key": "tenant:acme/invoices", "node": "node-c" },
                    { "key": "tenant:acme/orders/99", "node": "node-b" },
                    { "key": "tenant:globex/alerts", "node": "node-d" },
                    { "key": "user:alice", "node": "node-c" },
                    { "key": "user:bob", "node": "node-d" },
                    { "key": "user:zoe", "node": "node-a" },
                ],
                "nodes": ["node-a", "node-b", "node-c", "node-d"],
                "seed": 1_592_642_302_u64,
                "vnodes_per_node": 32,
            })
        );
    }

    /// Metamorphic relation: permuting node insertion order must not change
    /// key assignment when the final node set is identical.
    #[test]
    fn mr_key_assignment_invariant_to_node_insertion_order() {
        let keys: Vec<u64> = (0..2048u64).collect();
        let insertion_orders = [
            ["alpha", "beta", "gamma", "delta"],
            ["delta", "beta", "alpha", "gamma"],
            ["gamma", "alpha", "delta", "beta"],
            ["beta", "delta", "gamma", "alpha"],
        ];

        let assignments_for = |order: &[&str; 4]| {
            let mut ring = HashRing::new(32, 0);
            for node in order {
                assert!(ring.add_node(*node), "duplicate node in MR fixture");
            }
            keys.iter()
                .map(|key| ring.node_for_key(key).expect("ring should assign key"))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };

        let baseline = assignments_for(&insertion_orders[0]);
        for order in insertion_orders.iter().skip(1) {
            assert_eq!(
                assignments_for(order),
                baseline,
                "assignment drifted after insertion order permutation: {order:?}"
            );
        }
    }

    /// Metamorphic relation: removing a node and then re-adding the same node
    /// must restore the original key assignment when seed, vnode count, and
    /// final membership are unchanged.
    #[test]
    fn mr_key_assignment_restored_after_remove_readd() {
        let keys: Vec<u64> = (0..2048u64).collect();
        let mut ring = HashRing::new(32, 0x5eed_cafe);
        for node in ["alpha", "beta", "gamma", "delta"] {
            assert!(ring.add_node(node), "fixture node should be unique");
        }

        let assignments = |ring: &HashRing| {
            keys.iter()
                .map(|key| ring.node_for_key(key).expect("ring should assign key"))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };

        let baseline = assignments(&ring);
        assert_eq!(ring.remove_node("gamma"), 32);
        assert!(ring.add_node("gamma"));

        assert_eq!(
            assignments(&ring),
            baseline,
            "remove/readd of the same node changed assignments despite identical final membership"
        );
    }

    /// Metamorphic relation: duplicate adds and missing-node removals are
    /// semantic no-ops. They must not perturb membership, vnode placement, or
    /// key assignment for an already-built ring.
    #[test]
    fn mr_noop_membership_mutations_preserve_assignments() {
        let keys: Vec<u64> = (0..2048u64).collect();
        let mut ring = HashRing::new(32, 0x5eed_cafe);
        for node in ["alpha", "beta", "gamma", "delta"] {
            assert!(ring.add_node(node), "fixture node should be unique");
        }

        let assignments = |ring: &HashRing| {
            keys.iter()
                .map(|key| ring.node_for_key(key).expect("ring should assign key"))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };

        let baseline_nodes = ring.nodes().map(str::to_owned).collect::<Vec<_>>();
        let baseline_vnode_count = ring.vnode_count();
        let baseline_assignments = assignments(&ring);

        assert!(!ring.add_node("alpha"));
        assert_eq!(ring.remove_node("missing"), 0);
        assert!(!ring.add_node("delta"));
        assert_eq!(ring.remove_node("absent"), 0);

        assert_eq!(
            ring.nodes().map(str::to_owned).collect::<Vec<_>>(),
            baseline_nodes
        );
        assert_eq!(ring.vnode_count(), baseline_vnode_count);
        assert_eq!(
            assignments(&ring),
            baseline_assignments,
            "no-op membership mutations changed consistent-hash assignments"
        );
    }

    #[test]
    fn nodes_iterator_is_sorted() {
        let mut ring = HashRing::new(8, 0);
        ring.add_node("node-z");
        ring.add_node("node-a");
        ring.add_node("node-m");

        let nodes: Vec<&str> = ring.nodes().collect();
        assert_eq!(nodes, vec!["node-a", "node-m", "node-z"]);
    }

    // ================================================================
    // br-asupersync-un962v — zero-vnode rejection
    // ================================================================

    /// `try_new(0, _)` rejects zero-vnode rings up front with
    /// `ConsistentHashError::ZeroVnodes`. Use this from
    /// configuration-validation paths where misconfigured rings must
    /// be surfaced rather than silently clamped.
    #[test]
    fn try_new_rejects_zero_vnodes() {
        match HashRing::try_new(0, 0) {
            Err(ConsistentHashError::ZeroVnodes) => {}
            other => panic!("expected ZeroVnodes error, got {other:?}"), // ubs:ignore - test helper
        }
    }

    /// `try_new(N, _)` for N > 0 succeeds.
    #[test]
    fn try_new_accepts_nonzero_vnodes() {
        let ring = HashRing::try_new(8, 42).expect("non-zero vnodes accepted");
        assert_eq!(ring.seed(), 42);
        // No nodes registered yet → ring is empty.
        assert!(ring.is_empty());
    }

    /// The infallible `new(0, _)` clamps to vnodes_per_node = 1
    /// (silent fallback) so existing callers do not break when a
    /// config typo lands. Callers that want to surface the typo
    /// should use `try_new` instead.
    #[test]
    fn new_clamps_zero_vnodes_to_one() {
        let mut ring = HashRing::new(0, 0);
        ring.add_node("node-a");
        // Pre-fix this would have left vnode_count == 0 (silent
        // blackhole). With the clamp the ring has 1 vnode for the
        // single registered node and lookups succeed.
        assert!(ring.vnode_count() >= 1);
        assert!(ring.node_for_key(&"key").is_some());
    }

    #[test]
    fn hrw_is_deterministic_for_fixed_seed() {
        let nodes = [("node-a", 1_u32), ("node-b", 1), ("node-c", 1)];
        let first = select_hrw(
            nodes.iter(),
            &"alpha",
            42,
            |candidate| &candidate.0,
            |candidate| candidate.1,
        )
        .expect("winner");
        let second = select_hrw(
            nodes.iter(),
            &"alpha",
            42,
            |candidate| &candidate.0,
            |candidate| candidate.1,
        )
        .expect("winner");
        assert_eq!(first.0, second.0);
    }

    #[test]
    fn hrw_add_node_minimal_remap() {
        let keys: Vec<u64> = (0..10_000u64).collect();
        let mut nodes: Vec<(String, u32)> = (0..5).map(|i| (format!("node-{i}"), 1)).collect();

        let before: Vec<String> = keys
            .iter()
            .map(|key| {
                select_hrw(
                    nodes.iter(),
                    key,
                    7,
                    |candidate| candidate.0.as_str(),
                    |candidate| candidate.1,
                )
                .expect("winner")
                .0
                .clone()
            })
            .collect();

        nodes.push(("node-new".to_owned(), 1));
        let after: Vec<String> = keys
            .iter()
            .map(|key| {
                select_hrw(
                    nodes.iter(),
                    key,
                    7,
                    |candidate| candidate.0.as_str(),
                    |candidate| candidate.1,
                )
                .expect("winner")
                .0
                .clone()
            })
            .collect();

        let changed = before
            .iter()
            .zip(after.iter())
            .filter(|(left, right)| left != right)
            .count();
        let ratio = changed as f64 / keys.len() as f64;
        assert!(ratio <= 0.30, "remap ratio too high: {ratio}");
    }

    #[test]
    fn hrw_top_k_is_unique_and_weighted() {
        let nodes = [("light", 1_u32), ("heavy", 4_u32), ("medium", 2_u32)];
        let winners = select_top_k_hrw(
            nodes.iter(),
            3,
            &"orders.created",
            17,
            |candidate| &candidate.0,
            |candidate| candidate.1,
        );
        let unique = winners
            .iter()
            .map(|candidate| candidate.0)
            .collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), winners.len());

        let heavy_wins = (0..4096_u64)
            .filter(|key| {
                select_hrw(
                    nodes.iter(),
                    key,
                    17,
                    |candidate| &candidate.0,
                    |candidate| candidate.1,
                )
                .expect("winner")
                .0 == "heavy"
            })
            .count();
        let light_wins = (0..4096_u64)
            .filter(|key| {
                select_hrw(
                    nodes.iter(),
                    key,
                    17,
                    |candidate| &candidate.0,
                    |candidate| candidate.1,
                )
                .expect("winner")
                .0 == "light"
            })
            .count();
        assert!(
            heavy_wins > light_wins,
            "weights must influence HRW selection"
        );
    }

    #[test]
    fn mr_hrw_selection_is_invariant_to_zero_weight_candidates() {
        let positive = [("node-a", 1_u32), ("node-b", 3), ("node-c", 2)];
        let with_zero = [
            ("node-a", 1_u32),
            ("zero-a", 0),
            ("node-b", 3),
            ("zero-b", 0),
            ("node-c", 2),
        ];

        let single_for = |candidates: &[(&str, u32)]| {
            select_hrw(
                candidates.iter(),
                &"tenant:acme/orders/zero-weight",
                0x5eed_f00d,
                |candidate| &candidate.0,
                |candidate| candidate.1,
            )
            .expect("positive-weight candidates should yield a winner")
            .0
            .to_owned()
        };
        assert_eq!(
            single_for(&with_zero),
            single_for(&positive),
            "zero-weight candidates must not perturb the single HRW winner"
        );

        let top_for = |candidates: &[(&str, u32)], limit| {
            select_top_k_hrw(
                candidates.iter(),
                limit,
                &"tenant:acme/orders/zero-weight",
                0x5eed_f00d,
                |candidate| &candidate.0,
                |candidate| candidate.1,
            )
            .into_iter()
            .map(|candidate| candidate.0.to_owned())
            .collect::<Vec<_>>()
        };
        assert_eq!(
            top_for(&with_zero, with_zero.len()),
            top_for(&positive, positive.len()),
            "zero-weight candidates must not perturb positive HRW top-k ordering"
        );
    }

    #[test]
    fn mr_top_k_hrw_prefix_is_invariant_to_candidate_order() {
        let orders = [
            [
                ("node-a", 1_u32),
                ("node-b", 3),
                ("node-c", 2),
                ("node-d", 5),
                ("zero-weight", 0),
            ],
            [
                ("zero-weight", 0_u32),
                ("node-d", 5),
                ("node-b", 3),
                ("node-a", 1),
                ("node-c", 2),
            ],
            [
                ("node-c", 2_u32),
                ("node-a", 1),
                ("node-d", 5),
                ("zero-weight", 0),
                ("node-b", 3),
            ],
        ];

        let top3_for = |order: &[(&str, u32)]| {
            select_top_k_hrw(
                order.iter(),
                3,
                &"tenant:acme/orders/42",
                0x5eed_f00d,
                |candidate| &candidate.0,
                |candidate| candidate.1,
            )
            .into_iter()
            .map(|candidate| candidate.0.to_string())
            .collect::<Vec<_>>()
        };

        let baseline = top3_for(&orders[0]);
        for order in orders.iter().skip(1) {
            assert_eq!(
                top3_for(order),
                baseline,
                "HRW top-k winner order changed after candidate-order permutation"
            );
        }

        let top1 = select_top_k_hrw(
            orders[0].iter(),
            1,
            &"tenant:acme/orders/42",
            0x5eed_f00d,
            |candidate| &candidate.0,
            |candidate| candidate.1,
        )
        .into_iter()
        .map(|candidate| candidate.0)
        .collect::<Vec<_>>();
        let single_winner = select_hrw(
            orders[0].iter(),
            &"tenant:acme/orders/42",
            0x5eed_f00d,
            |candidate| &candidate.0,
            |candidate| candidate.1,
        )
        .expect("positive-weight candidates should yield a winner")
        .0;
        assert_eq!(top1, vec![single_winner]);

        let all_positive = select_top_k_hrw(
            orders[0].iter(),
            10,
            &"tenant:acme/orders/42",
            0x5eed_f00d,
            |candidate| &candidate.0,
            |candidate| candidate.1,
        );
        assert_eq!(all_positive.len(), 4);
        assert!(
            all_positive
                .iter()
                .all(|candidate| candidate.0 != "zero-weight"),
            "zero-weight candidates must remain excluded even when limit exceeds positive candidates"
        );
    }

    #[test]
    fn mr_top_k_hrw_limit_expansion_preserves_prefix() {
        let candidates = [
            ("node-a", 1_u32),
            ("node-b", 3),
            ("node-c", 2),
            ("node-d", 5),
            ("node-e", 4),
            ("zero-weight", 0),
        ];

        let winners_for = |limit: usize| {
            select_top_k_hrw(
                candidates.iter(),
                limit,
                &"tenant:acme/orders/prefix-stability",
                0x5eed_f00d,
                |candidate| &candidate.0,
                |candidate| candidate.1,
            )
            .into_iter()
            .map(|candidate| candidate.0)
            .collect::<Vec<_>>()
        };

        let all_winners = winners_for(candidates.len());
        assert_eq!(
            all_winners.len(),
            5,
            "fixture should include only positive-weight HRW winners"
        );
        assert!(
            all_winners.iter().all(|node| *node != "zero-weight"),
            "zero-weight candidate must not appear in the complete HRW ranking"
        );
        assert!(
            winners_for(0).is_empty(),
            "zero limit must return no HRW winners"
        );

        for limit in 1..=all_winners.len() {
            assert_eq!(
                winners_for(limit),
                all_winners[..limit].to_vec(),
                "expanding HRW top-k limit must preserve the previous winner prefix"
            );
        }

        assert_eq!(
            winners_for(candidates.len() + 4),
            all_winners,
            "limits above positive candidate count must return the complete positive ranking"
        );
    }

    /// Metamorphic relation: adding a node to a HashRing should cause minimal
    /// key reassignment, preserving the core consistent hashing property of
    /// minimal disruption.
    ///
    /// **Property**: When a new node is added to an existing ring, the majority
    /// of keys should remain assigned to their original nodes.
    ///
    /// **Transformation**: HashRing with N nodes → HashRing with N+1 nodes
    /// **Relation**: |keys_reassigned| / |total_keys| should be minimal (≤ 1/N ideally)
    /// **Detects**: Bugs in virtual node placement, hash distribution issues,
    /// incorrect ring reconstruction after node addition.
    #[test]
    fn mr_node_addition_minimal_disruption() {
        let keys: Vec<u64> = (0..4096u64).collect(); // Large key space for statistical validity
        let initial_nodes = ["node-a", "node-b", "node-c", "node-d"];

        // Build initial ring with fixed seed for determinism
        let mut ring = HashRing::new(64, 0); // More vnodes for better distribution
        for node in &initial_nodes {
            ring.add_node(*node);
        }

        // Record initial key-to-node assignments
        let initial_assignments: Vec<String> = keys
            .iter()
            .map(|key| {
                ring.node_for_key(key)
                    .expect("ring should assign key")
                    .to_owned()
            })
            .collect();

        // Add a new node
        ring.add_node("node-new");

        // Record assignments after adding the new node
        let final_assignments: Vec<String> = keys
            .iter()
            .map(|key| {
                ring.node_for_key(key)
                    .expect("ring should assign key")
                    .to_owned()
            })
            .collect();

        // Count how many keys were reassigned
        let reassigned_count = initial_assignments
            .iter()
            .zip(final_assignments.iter())
            .filter(|(before, after)| before != after)
            .count();

        let disruption_ratio = reassigned_count as f64 / keys.len() as f64;

        // Theoretical minimum: with N nodes initially, adding 1 node should ideally
        // reassign ~1/(N+1) of keys to the new node. We use a slightly more generous
        // threshold to account for hash distribution variance.
        let max_acceptable_disruption = 0.30; // 30% threshold, same as HRW test

        assert!(
            disruption_ratio <= max_acceptable_disruption,
            "Node addition caused excessive disruption: {:.2}% of keys reassigned \
             (expected ≤ {:.0}%). This violates the consistent hashing minimal \
             disruption property. Initial nodes: {:?}, Keys reassigned: {}/{}",
            disruption_ratio * 100.0,
            max_acceptable_disruption * 100.0,
            initial_nodes,
            reassigned_count,
            keys.len()
        );

        // Additional check: the new node should receive some keys (not zero)
        let new_node_assignments = final_assignments
            .iter()
            .filter(|node| *node == "node-new")
            .count();
        assert!(
            new_node_assignments > 0,
            "New node received zero key assignments, indicating a placement bug"
        );

        // Additional check: all original nodes should still have some keys
        // (unless the new node completely displaced one, which shouldn't happen
        // with good consistent hashing)
        for original_node in &initial_nodes {
            let remaining_assignments = final_assignments
                .iter()
                .filter(|node| node == original_node)
                .count();
            assert!(
                remaining_assignments > 0,
                "Original node '{}' lost all key assignments after adding new node, \
                 indicating poor hash distribution",
                original_node
            );
        }
    }
}
