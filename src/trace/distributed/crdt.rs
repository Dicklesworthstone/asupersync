//! Convergent Replicated Data Types (CRDTs) for distributed coordination.
//!
//! Each type satisfies the three algebraic laws of a join-semilattice:
//!
//! - **Commutativity:** `a.merge(b) == b.merge(a)`
//! - **Associativity:** `a.merge(b).merge(c) == a.merge(b.merge(c))`
//! - **Idempotence:** `a.merge(a) == a`
//!
//! Types provided:
//!
//! - [`GCounter`]: Grow-only counter (increment per replica).
//! - [`PNCounter`]: Positive-negative counter (increment and decrement).
//! - [`LWWRegister`]: Last-writer-wins register keyed by a logical timestamp.
//! - [`ORSet`]: Observed-remove set with unique tags per addition.
//! - [`MVRegister`]: Multi-value register preserving concurrent writes.

use crate::remote::NodeId;
use std::collections::{BTreeMap, BTreeSet};

// ─── Merge trait ─────────────────────────────────────────────────────────────

/// A join-semilattice merge operation.
///
/// Implementors must guarantee commutativity, associativity, and idempotence.
pub trait Merge {
    /// Merge another replica's state into `self`.
    fn merge(&mut self, other: &Self);
}

// ─── GCounter ────────────────────────────────────────────────────────────────

/// Grow-only counter.
///
/// Each replica maintains its own monotonically increasing count.
/// The global value is the sum across all replicas.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GCounter {
    counts: BTreeMap<NodeId, u64>,
}

impl GCounter {
    /// Creates a new empty counter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increments the counter for the given replica by `amount`.
    pub fn increment(&mut self, node: &NodeId, amount: u64) {
        if let Some(v) = self.counts.get_mut(node) {
            *v = v.saturating_add(amount);
        } else {
            self.counts.insert(node.clone(), amount);
        }
    }

    /// Returns the global counter value (sum of all replicas).
    #[must_use]
    pub fn value(&self) -> u64 {
        self.counts
            .values()
            .fold(0u64, |acc, &v| acc.saturating_add(v))
    }

    /// Returns the count attributed to a specific replica.
    #[must_use]
    pub fn get(&self, node: &NodeId) -> u64 {
        self.counts.get(node).copied().unwrap_or(0)
    }
}

impl Merge for GCounter {
    fn merge(&mut self, other: &Self) {
        for (node, &count) in &other.counts {
            if let Some(v) = self.counts.get_mut(node) {
                *v = (*v).max(count);
            } else {
                self.counts.insert(node.clone(), count);
            }
        }
    }
}

// ─── PNCounter ───────────────────────────────────────────────────────────────

/// Positive-negative counter.
///
/// Supports both increment and decrement by maintaining two [`GCounter`]s
/// internally: one for increments and one for decrements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PNCounter {
    positive: GCounter,
    negative: GCounter,
}

impl PNCounter {
    /// Creates a new counter at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increments the counter for the given replica.
    pub fn increment(&mut self, node: &NodeId, amount: u64) {
        self.positive.increment(node, amount);
    }

    /// Decrements the counter for the given replica.
    pub fn decrement(&mut self, node: &NodeId, amount: u64) {
        self.negative.increment(node, amount);
    }

    /// Returns the net value (positive − negative). May be negative.
    #[must_use]
    pub fn value(&self) -> i128 {
        i128::from(self.positive.value()) - i128::from(self.negative.value())
    }
}

impl Merge for PNCounter {
    fn merge(&mut self, other: &Self) {
        self.positive.merge(&other.positive);
        self.negative.merge(&other.negative);
    }
}

// ─── LWWRegister ─────────────────────────────────────────────────────────────

/// Last-writer-wins register.
///
/// Stores a single value with a logical timestamp. On merge, the value with
/// the higher timestamp wins. Ties are broken by comparing values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LWWRegister<V: Ord + Clone> {
    value: V,
    timestamp: u64,
    node: NodeId,
}

impl<V: Ord + Clone> LWWRegister<V> {
    /// Creates a register with an initial value.
    #[must_use]
    pub fn new(value: V, timestamp: u64, node: NodeId) -> Self {
        Self {
            value,
            timestamp,
            node,
        }
    }

    /// Sets a new value at the given timestamp.
    ///
    /// The update is only applied if `timestamp` is strictly greater than
    /// the current timestamp (or equal with a greater node id for tie-breaking).
    pub fn set(&mut self, value: V, timestamp: u64, node: NodeId) {
        if timestamp > self.timestamp || (timestamp == self.timestamp && node > self.node) {
            self.value = value;
            self.timestamp = timestamp;
            self.node = node;
        }
    }

    /// Returns the current value.
    #[must_use]
    pub fn value(&self) -> &V {
        &self.value
    }

    /// Returns the current timestamp.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

impl<V: Ord + Clone> Merge for LWWRegister<V> {
    fn merge(&mut self, other: &Self) {
        if other.timestamp > self.timestamp
            || (other.timestamp == self.timestamp && other.node > self.node)
        {
            self.value = other.value.clone();
            self.timestamp = other.timestamp;
            self.node = other.node.clone();
        }
    }
}

// ─── ORSet ───────────────────────────────────────────────────────────────────

/// A unique tag identifying a specific add operation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Tag {
    node: NodeId,
    seq: u64,
}

/// Observed-remove set.
///
/// Each addition is tagged with a unique (node, sequence) pair. Removal
/// only deletes the tags observed at remove time, so concurrent adds of the
/// same element survive removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ORSet<V: Ord + Clone> {
    /// Maps each value to the set of tags that added it.
    entries: BTreeMap<V, BTreeSet<Tag>>,
    /// Set of tags that have been observed and removed.
    tombstones: BTreeSet<Tag>,
    /// Per-node sequence counter for generating unique tags.
    sequences: BTreeMap<NodeId, u64>,
}

impl<V: Ord + Clone> ORSet<V> {
    /// Creates a new empty set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            tombstones: BTreeSet::new(),
            sequences: BTreeMap::new(),
        }
    }

    /// Adds a value, tagging the addition with the given node.
    pub fn add(&mut self, value: V, node: &NodeId) {
        let seq = if let Some(s) = self.sequences.get_mut(node) {
            *s = s.checked_add(1).expect("ORSet sequence counter overflow");
            *s
        } else {
            self.sequences.insert(node.clone(), 1);
            1
        };
        let tag = Tag {
            node: node.clone(),
            seq,
        };
        self.entries.entry(value).or_default().insert(tag);
    }

    /// Removes a value by moving all currently observed tags to tombstones.
    ///
    /// Concurrent adds (with tags not yet observed) will survive.
    pub fn remove(&mut self, value: &V) {
        if let Some(tags) = self.entries.remove(value) {
            for tag in tags {
                self.tombstones.insert(tag);
            }
        }
    }

    /// Returns `true` if the value is present (has at least one live tag).
    #[must_use]
    pub fn contains(&self, value: &V) -> bool {
        self.entries.get(value).is_some_and(|tags| !tags.is_empty())
    }

    /// Returns an iterator over the current elements.
    pub fn elements(&self) -> impl Iterator<Item = &V> {
        self.entries
            .iter()
            .filter(|(_, tags)| !tags.is_empty())
            .map(|(v, _)| v)
    }

    /// Returns the number of distinct elements in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .iter()
            .filter(|(_, tags)| !tags.is_empty())
            .count()
    }

    /// Returns `true` if the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<V: Ord + Clone> Default for ORSet<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Ord + Clone> Merge for ORSet<V> {
    fn merge(&mut self, other: &Self) {
        // Merge tombstones.
        for tag in &other.tombstones {
            self.tombstones.insert(tag.clone());
        }

        for (value, other_tags) in &other.entries {
            let tags = self.entries.entry(value.clone()).or_default();
            for tag in other_tags {
                if !self.tombstones.contains(tag) {
                    tags.insert(tag.clone());
                }
            }
        }

        // Clean up our own entries that are in the merged tombstones, and
        // remove values whose tag sets are now empty to prevent unbounded
        // memory growth from accumulated phantom entries.
        self.entries.retain(|_, tags| {
            tags.retain(|tag| !self.tombstones.contains(tag));
            !tags.is_empty()
        });

        // Merge sequence counters (take max per node).
        for (node, &seq) in &other.sequences {
            if let Some(v) = self.sequences.get_mut(node) {
                *v = (*v).max(seq);
            } else {
                self.sequences.insert(node.clone(), seq);
            }
        }
    }
}

// ─── MVRegister ──────────────────────────────────────────────────────────────

/// Multi-value register.
///
/// Tracks concurrent writes using vector-clock-style versioning. On merge,
/// values that are causally superseded are dropped; concurrent values are
/// all retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MVRegister<V: Ord + Clone> {
    /// Each entry is a (value, version-vector) pair.
    entries: BTreeSet<(V, BTreeMap<NodeId, u64>)>,
    /// Per-node version counter.
    versions: BTreeMap<NodeId, u64>,
}

impl<V: Ord + Clone> MVRegister<V> {
    /// Creates an empty register.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeSet::new(),
            versions: BTreeMap::new(),
        }
    }

    /// Sets a new value from the given node.
    ///
    /// This causally supersedes all currently held values.
    pub fn set(&mut self, value: V, node: &NodeId) {
        if let Some(v) = self.versions.get_mut(node) {
            *v = v.saturating_add(1);
        } else {
            self.versions.insert(node.clone(), 1);
        }
        let version_snapshot = self.versions.clone();
        self.entries.clear();
        self.entries.insert((value, version_snapshot));
    }

    /// Returns all concurrently held values.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(v, _)| v)
    }

    /// Returns the number of concurrent values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no value has been set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<V: Ord + Clone> Default for MVRegister<V> {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true if `a` dominates `b` (a >= b componentwise, a != b).
fn dominates(a: &BTreeMap<NodeId, u64>, b: &BTreeMap<NodeId, u64>) -> bool {
    let mut dominated = false;
    // Every key in b must be <= a's value.
    for (node, &b_ver) in b {
        let a_ver = a.get(node).copied().unwrap_or(0);
        if a_ver < b_ver {
            return false;
        }
        if a_ver > b_ver {
            dominated = true;
        }
    }
    // If a has keys not in b, those also contribute to dominance.
    if !dominated {
        for (node, &a_ver) in a {
            if a_ver > 0 && !b.contains_key(node) {
                dominated = true;
                break;
            }
        }
    }
    dominated
}

impl<V: Ord + Clone> Merge for MVRegister<V> {
    fn merge(&mut self, other: &Self) {
        // Collect all entries from both sides, then remove dominated ones.
        let mut combined: Vec<(V, BTreeMap<NodeId, u64>)> = self.entries.iter().cloned().collect();
        combined.extend(other.entries.iter().cloned());

        // Remove entries dominated by any other entry.
        let mut kept = BTreeSet::new();
        for (i, (v_i, ver_i)) in combined.iter().enumerate() {
            let is_dominated = combined
                .iter()
                .enumerate()
                .any(|(j, (_, ver_j))| i != j && dominates(ver_j, ver_i));
            if !is_dominated {
                kept.insert((v_i.clone(), ver_i.clone()));
            }
        }

        self.entries = kept;

        // Merge version counters.
        for (node, &ver) in &other.versions {
            if let Some(v) = self.versions.get_mut(node) {
                *v = (*v).max(ver);
            } else {
                self.versions.insert(node.clone(), ver);
            }
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "crdt_inline_tests.rs"]
mod tests;
