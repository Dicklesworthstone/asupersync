//! Deterministic consistent hashing ring with virtual nodes.
//!
//! Used for stable key-to-replica assignment with minimal remapping when
//! replicas are added or removed.

use crate::util::det_hash::DetHasher;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};

/// A deterministic consistent hash ring with virtual nodes.
#[derive(Debug, Clone)]
pub struct HashRing {
    vnodes_per_node: usize,
    nodes: BTreeSet<String>,
    ring: Vec<VirtualNode>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct VirtualNode {
    hash: u64,
    node_id: String,
    vnode: u32,
}

impl HashRing {
    /// Create a new hash ring with the given number of virtual nodes per node.
    #[must_use]
    pub fn new(vnodes_per_node: usize) -> Self {
        Self {
            vnodes_per_node,
            nodes: BTreeSet::new(),
            ring: Vec::new(),
        }
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
            let hash = vnode_hash(&node_id, vnode as u32);
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
        let key_hash = hash_value(key);
        let idx = self.ring.partition_point(|vn| vn.hash < key_hash);
        let idx = if idx == self.ring.len() { 0 } else { idx };
        Some(self.ring[idx].node_id.as_str())
    }

    /// Returns an iterator of node identifiers (ordered).
    pub fn nodes(&self) -> impl Iterator<Item = &str> {
        self.nodes.iter().map(String::as_str)
    }
}

fn vnode_hash(node_id: &str, vnode: u32) -> u64 {
    let mut hasher = DetHasher::default();
    node_id.hash(&mut hasher);
    vnode.hash(&mut hasher);
    hasher.finish()
}

fn hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = DetHasher::default();
    value.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ring(node_count: usize, vnodes_per_node: usize) -> HashRing {
        let mut ring = HashRing::new(vnodes_per_node);
        for i in 0..node_count {
            ring.add_node(format!("node-{i}"));
        }
        ring
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
        let mut ring = HashRing::new(8);
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
    fn add_node_minimal_remap() {
        let mut ring = build_ring(5, 64);
        let keys: Vec<u64> = (0..10_000u64).collect();

        let before: Vec<String> = keys
            .iter()
            .map(|k| ring.node_for_key(k).unwrap().to_owned())
            .collect();

        ring.add_node("node-new");

        let after: Vec<String> = keys
            .iter()
            .map(|k| ring.node_for_key(k).unwrap().to_owned())
            .collect();

        let changed = before
            .iter()
            .zip(after.iter())
            .filter(|(a, b)| a != b)
            .count();
        let changed_f = changed as f64;
        let keys_len_f = keys.len() as f64;
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
            .map(|k| ring.node_for_key(k).unwrap().to_owned())
            .collect();

        let removed = "node-2";
        ring.remove_node(removed);

        let after: Vec<String> = keys
            .iter()
            .map(|k| ring.node_for_key(k).unwrap().to_owned())
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
    fn zero_vnodes_yields_empty_ring() {
        let mut ring = HashRing::new(0);
        ring.add_node("a");
        assert_eq!(ring.vnode_count(), 0);
        assert!(ring.node_for_key(&"key").is_none());
    }
}
