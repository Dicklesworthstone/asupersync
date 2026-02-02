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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GCounter {
    counts: BTreeMap<NodeId, u64>,
}

impl GCounter {
    /// Creates a new empty counter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            counts: BTreeMap::new(),
        }
    }

    /// Increments the counter for the given replica by `amount`.
    pub fn increment(&mut self, node: &NodeId, amount: u64) {
        *self.counts.entry(node.clone()).or_insert(0) += amount;
    }

    /// Returns the global counter value (sum of all replicas).
    #[must_use]
    pub fn value(&self) -> u64 {
        self.counts.values().sum()
    }

    /// Returns the count attributed to a specific replica.
    #[must_use]
    pub fn get(&self, node: &NodeId) -> u64 {
        self.counts.get(node).copied().unwrap_or(0)
    }
}

impl Default for GCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl Merge for GCounter {
    fn merge(&mut self, other: &Self) {
        for (node, &count) in &other.counts {
            let entry = self.counts.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(count);
        }
    }
}

// ─── PNCounter ───────────────────────────────────────────────────────────────

/// Positive-negative counter.
///
/// Supports both increment and decrement by maintaining two [`GCounter`]s
/// internally: one for increments and one for decrements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PNCounter {
    positive: GCounter,
    negative: GCounter,
}

impl PNCounter {
    /// Creates a new counter at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            positive: GCounter::new(),
            negative: GCounter::new(),
        }
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
    #[allow(clippy::cast_possible_wrap)]
    pub fn value(&self) -> i64 {
        self.positive.value() as i64 - self.negative.value() as i64
    }
}

impl Default for PNCounter {
    fn default() -> Self {
        Self::new()
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
    /// Per-node sequence counter for generating unique tags.
    sequences: BTreeMap<NodeId, u64>,
}

impl<V: Ord + Clone> ORSet<V> {
    /// Creates a new empty set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            sequences: BTreeMap::new(),
        }
    }

    /// Adds a value, tagging the addition with the given node.
    pub fn add(&mut self, value: V, node: &NodeId) {
        let seq = self.sequences.entry(node.clone()).or_insert(0);
        *seq += 1;
        let tag = Tag {
            node: node.clone(),
            seq: *seq,
        };
        self.entries.entry(value).or_default().insert(tag);
    }

    /// Removes a value by clearing all currently observed tags.
    ///
    /// Concurrent adds (with tags not yet observed) will survive.
    pub fn remove(&mut self, value: &V) {
        self.entries.remove(value);
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
        for (value, other_tags) in &other.entries {
            let tags = self.entries.entry(value.clone()).or_default();
            for tag in other_tags {
                tags.insert(tag.clone());
            }
        }
        // Merge sequence counters (take max per node).
        for (node, &seq) in &other.sequences {
            let entry = self.sequences.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(seq);
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
        let ver = self.versions.entry(node.clone()).or_insert(0);
        *ver += 1;
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
        for entry in &other.entries {
            combined.push(entry.clone());
        }

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
            let entry = self.versions.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(ver);
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str) -> NodeId {
        NodeId::new(name)
    }

    /// Helper: verify the three semilattice laws for a CRDT.
    fn assert_semilattice_laws<T: Merge + Clone + PartialEq + std::fmt::Debug>(
        a: &T,
        b: &T,
        c: &T,
    ) {
        // Commutativity: a ⊔ b = b ⊔ a
        let mut ab = a.clone();
        ab.merge(b);
        let mut ba = b.clone();
        ba.merge(a);
        assert_eq!(ab, ba, "commutativity violated");

        // Associativity: (a ⊔ b) ⊔ c = a ⊔ (b ⊔ c)
        let mut ab_c = a.clone();
        ab_c.merge(b);
        ab_c.merge(c);
        let mut bc = b.clone();
        bc.merge(c);
        let mut a_bc = a.clone();
        a_bc.merge(&bc);
        assert_eq!(ab_c, a_bc, "associativity violated");

        // Idempotence: a ⊔ a = a
        let mut aa = a.clone();
        aa.merge(a);
        assert_eq!(aa, *a, "idempotence violated for a");

        let mut bb = b.clone();
        bb.merge(b);
        assert_eq!(bb, *b, "idempotence violated for b");

        let mut cc = c.clone();
        cc.merge(c);
        assert_eq!(cc, *c, "idempotence violated for c");
    }

    // ── GCounter ─────────────────────────────────────────────────────────

    #[test]
    fn gcounter_increment_and_value() {
        let mut g = GCounter::new();
        g.increment(&node("a"), 3);
        g.increment(&node("b"), 5);
        g.increment(&node("a"), 2);
        assert_eq!(g.value(), 10);
        assert_eq!(g.get(&node("a")), 5);
        assert_eq!(g.get(&node("b")), 5);
    }

    #[test]
    fn gcounter_merge_takes_max() {
        let mut g1 = GCounter::new();
        g1.increment(&node("a"), 3);
        g1.increment(&node("b"), 1);

        let mut g2 = GCounter::new();
        g2.increment(&node("a"), 1);
        g2.increment(&node("b"), 5);

        g1.merge(&g2);
        assert_eq!(g1.get(&node("a")), 3);
        assert_eq!(g1.get(&node("b")), 5);
        assert_eq!(g1.value(), 8);
    }

    #[test]
    fn gcounter_semilattice_laws() {
        let mut a = GCounter::new();
        a.increment(&node("x"), 3);

        let mut b = GCounter::new();
        b.increment(&node("y"), 7);

        let mut c = GCounter::new();
        c.increment(&node("x"), 5);
        c.increment(&node("z"), 2);

        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn gcounter_semilattice_laws_overlapping() {
        let mut a = GCounter::new();
        a.increment(&node("n1"), 10);
        a.increment(&node("n2"), 3);

        let mut b = GCounter::new();
        b.increment(&node("n1"), 5);
        b.increment(&node("n2"), 8);
        b.increment(&node("n3"), 1);

        let mut c = GCounter::new();
        c.increment(&node("n2"), 6);
        c.increment(&node("n3"), 4);

        assert_semilattice_laws(&a, &b, &c);
    }

    // ── PNCounter ────────────────────────────────────────────────────────

    #[test]
    fn pncounter_increment_decrement() {
        let mut pn = PNCounter::new();
        pn.increment(&node("a"), 10);
        pn.decrement(&node("b"), 3);
        assert_eq!(pn.value(), 7);
    }

    #[test]
    fn pncounter_negative_value() {
        let mut pn = PNCounter::new();
        pn.decrement(&node("a"), 5);
        assert_eq!(pn.value(), -5);
    }

    #[test]
    fn pncounter_merge() {
        let mut pn1 = PNCounter::new();
        pn1.increment(&node("a"), 10);
        pn1.decrement(&node("b"), 2);

        let mut pn2 = PNCounter::new();
        pn2.increment(&node("a"), 5);
        pn2.decrement(&node("b"), 7);

        pn1.merge(&pn2);
        // positive: max(10,5)=10, negative: max(2,7)=7
        assert_eq!(pn1.value(), 3);
    }

    #[test]
    fn pncounter_semilattice_laws() {
        let mut a = PNCounter::new();
        a.increment(&node("x"), 5);
        a.decrement(&node("y"), 2);

        let mut b = PNCounter::new();
        b.increment(&node("y"), 3);
        b.decrement(&node("x"), 1);

        let mut c = PNCounter::new();
        c.increment(&node("x"), 8);
        c.increment(&node("z"), 1);

        assert_semilattice_laws(&a, &b, &c);
    }

    // ── LWWRegister ──────────────────────────────────────────────────────

    #[test]
    fn lww_set_higher_timestamp_wins() {
        let mut r = LWWRegister::new("old".to_string(), 1, node("a"));
        r.set("new".to_string(), 2, node("a"));
        assert_eq!(r.value(), "new");
    }

    #[test]
    fn lww_set_lower_timestamp_ignored() {
        let mut r = LWWRegister::new("current".to_string(), 5, node("a"));
        r.set("stale".to_string(), 3, node("a"));
        assert_eq!(r.value(), "current");
    }

    #[test]
    fn lww_merge_higher_timestamp_wins() {
        let r1 = LWWRegister::new("v1".to_string(), 3, node("a"));
        let r2 = LWWRegister::new("v2".to_string(), 5, node("b"));

        let mut merged = r1;
        merged.merge(&r2);
        assert_eq!(merged.value(), "v2");
    }

    #[test]
    fn lww_tie_broken_by_node_id() {
        let r1 = LWWRegister::new("from_a".to_string(), 1, node("a"));
        let r2 = LWWRegister::new("from_b".to_string(), 1, node("b"));

        let mut m1 = r1.clone();
        m1.merge(&r2);
        let mut m2 = r2.clone();
        m2.merge(&r1);
        // "b" > "a", so "from_b" wins in both directions.
        assert_eq!(m1.value(), "from_b");
        assert_eq!(m2.value(), "from_b");
    }

    #[test]
    fn lww_semilattice_laws() {
        let a = LWWRegister::new("a".to_string(), 1, node("n1"));
        let b = LWWRegister::new("b".to_string(), 2, node("n2"));
        let c = LWWRegister::new("c".to_string(), 3, node("n3"));
        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn lww_semilattice_laws_same_timestamp() {
        let a = LWWRegister::new("a".to_string(), 5, node("n1"));
        let b = LWWRegister::new("b".to_string(), 5, node("n2"));
        let c = LWWRegister::new("c".to_string(), 5, node("n3"));
        assert_semilattice_laws(&a, &b, &c);
    }

    // ── ORSet ────────────────────────────────────────────────────────────

    #[test]
    fn orset_add_remove_contains() {
        let mut s = ORSet::new();
        s.add("x", &node("a"));
        assert!(s.contains(&"x"));
        s.remove(&"x");
        assert!(!s.contains(&"x"));
    }

    #[test]
    fn orset_concurrent_add_survives_remove() {
        let mut s1 = ORSet::new();
        s1.add("x", &node("a"));

        // s2 forks from s1.
        let mut s2 = s1.clone();

        // s1 removes x.
        s1.remove(&"x");
        assert!(!s1.contains(&"x"));

        // s2 concurrently re-adds x.
        s2.add("x", &node("b"));

        // Merge: the concurrent add survives the remove.
        s1.merge(&s2);
        assert!(s1.contains(&"x"));
    }

    #[test]
    fn orset_semilattice_laws() {
        let mut a = ORSet::new();
        a.add("x", &node("n1"));
        a.add("y", &node("n1"));

        let mut b = ORSet::new();
        b.add("y", &node("n2"));
        b.add("z", &node("n2"));

        let mut c = ORSet::new();
        c.add("x", &node("n3"));
        c.add("z", &node("n3"));
        c.add("w", &node("n3"));

        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn orset_len_and_elements() {
        let mut s = ORSet::new();
        assert!(s.is_empty());
        s.add(1, &node("a"));
        s.add(2, &node("a"));
        s.add(1, &node("b")); // duplicate value, different tag
        assert_eq!(s.len(), 2);
        let elems: Vec<_> = s.elements().copied().collect();
        assert_eq!(elems, vec![1, 2]);
    }

    // ── MVRegister ───────────────────────────────────────────────────────

    #[test]
    fn mvregister_single_writer() {
        let mut r = MVRegister::new();
        r.set("v1", &node("a"));
        r.set("v2", &node("a"));
        let vals: Vec<_> = r.values().collect();
        assert_eq!(vals, vec![&"v2"]);
    }

    #[test]
    fn mvregister_concurrent_writes_preserved() {
        let mut r1 = MVRegister::new();
        r1.set("from_a", &node("a"));

        let mut r2 = MVRegister::new();
        r2.set("from_b", &node("b"));

        r1.merge(&r2);
        // Both concurrent values preserved.
        assert_eq!(r1.len(), 2);
        let mut vals: Vec<_> = r1.values().copied().collect();
        vals.sort_unstable();
        assert_eq!(vals, vec!["from_a", "from_b"]);
    }

    #[test]
    fn mvregister_causal_supersedes() {
        let mut r1 = MVRegister::new();
        r1.set("v1", &node("a"));

        // r2 sees r1's state, then overwrites.
        let mut r2 = r1.clone();
        r2.set("v2", &node("b"));

        // Merge: v2 dominates v1 because r2's version vector ≥ r1's.
        r1.merge(&r2);
        let vals: Vec<_> = r1.values().collect();
        assert_eq!(vals, vec![&"v2"]);
    }

    #[test]
    fn mvregister_semilattice_laws() {
        // Three independent concurrent writes.
        let mut a = MVRegister::new();
        a.set("a", &node("n1"));

        let mut b = MVRegister::new();
        b.set("b", &node("n2"));

        let mut c = MVRegister::new();
        c.set("c", &node("n3"));

        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn mvregister_semilattice_laws_with_causal_chain() {
        let mut a = MVRegister::new();
        a.set("a1", &node("n1"));

        let mut b = a.clone();
        b.set("b1", &node("n2"));

        let mut c = b.clone();
        c.set("c1", &node("n3"));

        assert_semilattice_laws(&a, &b, &c);
    }

    // ── Cross-type integration ───────────────────────────────────────────

    #[test]
    fn gcounter_empty_merge() {
        let a = GCounter::new();
        let b = GCounter::new();
        let c = GCounter::new();
        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn pncounter_empty_merge() {
        let a = PNCounter::new();
        let b = PNCounter::new();
        let c = PNCounter::new();
        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn orset_empty_merge() {
        let a: ORSet<String> = ORSet::new();
        let b: ORSet<String> = ORSet::new();
        let c: ORSet<String> = ORSet::new();
        assert_semilattice_laws(&a, &b, &c);
    }

    #[test]
    fn mvregister_empty_merge() {
        let a: MVRegister<String> = MVRegister::new();
        let b: MVRegister<String> = MVRegister::new();
        let c: MVRegister<String> = MVRegister::new();
        assert_semilattice_laws(&a, &b, &c);
    }
}
