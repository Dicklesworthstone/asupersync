//! Vector clocks for causal ordering of distributed trace events.
//!
//! A vector clock maps each node in the system to a logical counter. It captures
//! the causal partial order: events are either causally ordered (happens-before)
//! or concurrent. This avoids imposing a false total order on distributed events.
//!
//! # Usage
//!
//! ```rust
//! use asupersync::trace::distributed::vclock::{VectorClock, CausalOrder};
//! use asupersync::remote::NodeId;
//!
//! let mut vc_a = VectorClock::new();
//! let node_a = NodeId::new("node-a");
//! let node_b = NodeId::new("node-b");
//!
//! vc_a.increment(&node_a);
//! vc_a.increment(&node_a);
//!
//! let mut vc_b = VectorClock::new();
//! vc_b.increment(&node_b);
//!
//! // These are concurrent — neither happened before the other.
//! assert_eq!(vc_a.partial_cmp(&vc_b), None);
//!
//! // Merge to get the join (componentwise max).
//! let merged = vc_a.merge(&vc_b);
//! assert!(merged.get(&node_a) == 2);
//! assert!(merged.get(&node_b) == 1);
//! ```

use crate::remote::NodeId;
use std::collections::BTreeMap;
use std::fmt;

/// A vector clock for causal ordering in a distributed system.
///
/// Maps `NodeId → u64` counters. The partial order is:
/// - `a ≤ b` iff `∀ node: a[node] ≤ b[node]`
/// - `a < b` (happens-before) iff `a ≤ b` and `a ≠ b`
/// - `a ∥ b` (concurrent) iff `¬(a ≤ b)` and `¬(b ≤ a)`
#[derive(Clone, PartialEq, Eq)]
pub struct VectorClock {
    /// BTreeMap for deterministic iteration order.
    entries: BTreeMap<NodeId, u64>,
}

impl VectorClock {
    /// Creates an empty vector clock (all components zero).
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Creates a vector clock with a single node initialized to 1.
    #[must_use]
    pub fn for_node(node: &NodeId) -> Self {
        let mut vc = Self::new();
        vc.entries.insert(node.clone(), 1);
        vc
    }

    /// Returns the counter for the given node (0 if absent).
    #[must_use]
    pub fn get(&self, node: &NodeId) -> u64 {
        self.entries.get(node).copied().unwrap_or(0)
    }

    /// Increments the counter for the given node and returns the new value.
    pub fn increment(&mut self, node: &NodeId) -> u64 {
        let entry = self.entries.entry(node.clone()).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Sets the counter for a node to a specific value.
    ///
    /// Used when receiving a message: update local clock to be at least
    /// as large as the sender's value for each node.
    pub fn set(&mut self, node: &NodeId, value: u64) {
        if value == 0 {
            return;
        }
        self.entries.insert(node.clone(), value);
    }

    /// Returns the merge (join / componentwise max) of two vector clocks.
    ///
    /// This is the least upper bound in the partial order.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (node, &value) in &other.entries {
            let entry = result.entries.entry(node.clone()).or_insert(0);
            if value > *entry {
                *entry = value;
            }
        }
        result
    }

    /// Merges another vector clock into `self` in place.
    pub fn merge_in(&mut self, other: &Self) {
        for (node, &value) in &other.entries {
            let entry = self.entries.entry(node.clone()).or_insert(0);
            if value > *entry {
                *entry = value;
            }
        }
    }

    /// Increments the local node and merges the remote clock.
    ///
    /// This is the standard "on receive" operation:
    /// 1. Merge the incoming clock
    /// 2. Increment the local counter
    pub fn receive(&mut self, local_node: &NodeId, remote_clock: &Self) {
        self.merge_in(remote_clock);
        self.increment(local_node);
    }

    /// Compares two vector clocks for causal ordering.
    #[must_use]
    pub fn causal_order(&self, other: &Self) -> CausalOrder {
        let mut self_leq_other = true;
        let mut other_leq_self = true;

        // Check all nodes present in either clock.
        let all_nodes: std::collections::BTreeSet<&NodeId> =
            self.entries.keys().chain(other.entries.keys()).collect();

        for node in all_nodes {
            let a = self.get(node);
            let b = other.get(node);
            if a > b {
                self_leq_other = false;
            }
            if b > a {
                other_leq_self = false;
            }
            if !self_leq_other && !other_leq_self {
                return CausalOrder::Concurrent;
            }
        }

        match (self_leq_other, other_leq_self) {
            (true, true) => CausalOrder::Equal,
            (true, false) => CausalOrder::Before,
            (false, true) => CausalOrder::After,
            (false, false) => CausalOrder::Concurrent,
        }
    }

    /// Returns true if `self` happens-before `other`.
    #[must_use]
    pub fn happens_before(&self, other: &Self) -> bool {
        self.causal_order(other) == CausalOrder::Before
    }

    /// Returns true if `self` and `other` are concurrent.
    #[must_use]
    pub fn is_concurrent_with(&self, other: &Self) -> bool {
        self.causal_order(other) == CausalOrder::Concurrent
    }

    /// Returns the number of nodes tracked by this clock.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if all counters are zero (empty clock).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an iterator over (node, counter) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&NodeId, &u64)> {
        self.entries.iter()
    }
}

impl Default for VectorClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Implements the partial order for vector clocks.
///
/// Returns `None` when the clocks are concurrent (incomparable).
impl PartialOrd for VectorClock {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.causal_order(other) {
            CausalOrder::Before => Some(std::cmp::Ordering::Less),
            CausalOrder::After => Some(std::cmp::Ordering::Greater),
            CausalOrder::Equal => Some(std::cmp::Ordering::Equal),
            CausalOrder::Concurrent => None,
        }
    }
}

impl fmt::Debug for VectorClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VC{{")?;
        for (i, (node, value)) in self.entries.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}:{}", node.as_str(), value)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for VectorClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (i, (node, value)) in self.entries.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}={}", node.as_str(), value)?;
        }
        write!(f, "]")
    }
}

/// Result of comparing two vector clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CausalOrder {
    /// `self` happened strictly before `other`.
    Before,
    /// `self` happened strictly after `other`.
    After,
    /// `self` and `other` are exactly equal.
    Equal,
    /// `self` and `other` are concurrent (neither happened before the other).
    Concurrent,
}

/// A trace event annotated with causal metadata.
///
/// Wraps any event with the vector clock at the time the event was recorded,
/// plus the originating node.
#[derive(Clone, Debug)]
pub struct CausalEvent<T> {
    /// The originating node.
    pub origin: NodeId,
    /// The vector clock at event creation time.
    pub clock: VectorClock,
    /// The wrapped event.
    pub event: T,
}

impl<T> CausalEvent<T> {
    /// Creates a new causal event.
    pub fn new(origin: NodeId, clock: VectorClock, event: T) -> Self {
        Self {
            origin,
            clock,
            event,
        }
    }

    /// Returns true if this event causally precedes `other`.
    pub fn happens_before<U>(&self, other: &CausalEvent<U>) -> bool {
        self.clock.happens_before(&other.clock)
    }

    /// Returns true if this event is concurrent with `other`.
    pub fn is_concurrent_with<U>(&self, other: &CausalEvent<U>) -> bool {
        self.clock.is_concurrent_with(&other.clock)
    }
}

/// A causal history tracker for a single node.
///
/// Manages the local vector clock, incrementing on local events and
/// merging on message receive.
#[derive(Clone, Debug)]
pub struct CausalTracker {
    /// The local node.
    node: NodeId,
    /// The current vector clock.
    clock: VectorClock,
}

impl CausalTracker {
    /// Creates a new tracker for the given node.
    #[must_use]
    pub fn new(node: NodeId) -> Self {
        Self {
            node,
            clock: VectorClock::new(),
        }
    }

    /// Records a local event, incrementing the local counter.
    ///
    /// Returns the vector clock at the time of the event.
    pub fn record_local_event(&mut self) -> VectorClock {
        self.clock.increment(&self.node);
        self.clock.clone()
    }

    /// Records a local event, wrapping it with causal metadata.
    pub fn record<T>(&mut self, event: T) -> CausalEvent<T> {
        let clock = self.record_local_event();
        CausalEvent::new(self.node.clone(), clock, event)
    }

    /// Records a message send. Increments the local clock and returns
    /// the clock to attach to the outgoing message.
    pub fn on_send(&mut self) -> VectorClock {
        self.record_local_event()
    }

    /// Records a message receive. Merges the incoming clock and
    /// increments the local counter.
    pub fn on_receive(&mut self, remote_clock: &VectorClock) {
        self.clock.receive(&self.node, remote_clock);
    }

    /// Returns the current vector clock (snapshot).
    #[must_use]
    pub fn current_clock(&self) -> &VectorClock {
        &self.clock
    }

    /// Returns the local node ID.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str) -> NodeId {
        NodeId::new(name)
    }

    #[test]
    fn empty_clocks_are_equal() {
        let a = VectorClock::new();
        let b = VectorClock::new();
        assert_eq!(a.causal_order(&b), CausalOrder::Equal);
        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Equal));
    }

    #[test]
    fn increment_creates_happens_before() {
        let n = node("A");
        let mut a = VectorClock::new();
        let b = a.clone();
        a.increment(&n);
        assert_eq!(b.causal_order(&a), CausalOrder::Before);
        assert!(b.happens_before(&a));
    }

    #[test]
    fn concurrent_detection() {
        let na = node("A");
        let nb = node("B");
        let mut a = VectorClock::new();
        let mut b = VectorClock::new();
        a.increment(&na);
        b.increment(&nb);
        assert_eq!(a.causal_order(&b), CausalOrder::Concurrent);
        assert!(a.is_concurrent_with(&b));
        assert_eq!(a.partial_cmp(&b), None);
    }

    #[test]
    fn merge_is_least_upper_bound() {
        let na = node("A");
        let nb = node("B");
        let mut a = VectorClock::new();
        a.increment(&na);
        a.increment(&na);
        let mut b = VectorClock::new();
        b.increment(&nb);
        b.increment(&nb);
        b.increment(&nb);

        let merged = a.merge(&b);
        assert_eq!(merged.get(&na), 2);
        assert_eq!(merged.get(&nb), 3);
        // Both original clocks happen-before the merge
        assert!(a.happens_before(&merged));
        assert!(b.happens_before(&merged));
    }

    #[test]
    fn merge_is_commutative() {
        let na = node("A");
        let nb = node("B");
        let mut a = VectorClock::new();
        a.increment(&na);
        let mut b = VectorClock::new();
        b.increment(&nb);

        assert_eq!(a.merge(&b), b.merge(&a));
    }

    #[test]
    fn merge_is_associative() {
        let na = node("A");
        let nb = node("B");
        let nc = node("C");
        let mut a = VectorClock::new();
        a.increment(&na);
        let mut b = VectorClock::new();
        b.increment(&nb);
        let mut c = VectorClock::new();
        c.increment(&nc);

        let ab_c = a.merge(&b).merge(&c);
        let a_bc = a.merge(&b.merge(&c));
        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn merge_is_idempotent() {
        let na = node("A");
        let mut a = VectorClock::new();
        a.increment(&na);
        assert_eq!(a.merge(&a), a);
    }

    #[test]
    fn receive_merges_and_increments() {
        let na = node("A");
        let nb = node("B");
        let mut a = VectorClock::new();
        a.increment(&na); // A: {A:1}

        let mut b = VectorClock::new();
        b.increment(&nb); // B: {B:1}
        b.increment(&nb); // B: {B:2}

        // A receives a message with B's clock
        a.receive(&na, &b); // merge → {A:1, B:2}, then increment → {A:2, B:2}
        assert_eq!(a.get(&na), 2);
        assert_eq!(a.get(&nb), 2);
    }

    #[test]
    fn for_node_initializes_to_one() {
        let n = node("X");
        let vc = VectorClock::for_node(&n);
        assert_eq!(vc.get(&n), 1);
        assert_eq!(vc.node_count(), 1);
    }

    #[test]
    fn causal_tracker_send_receive_protocol() {
        let na = node("A");
        let nb = node("B");
        let mut tracker_a = CausalTracker::new(na.clone());
        let mut tracker_b = CausalTracker::new(nb.clone());

        // A does local work
        tracker_a.record_local_event(); // A: {A:1}

        // A sends message to B
        let msg_clock = tracker_a.on_send(); // A: {A:2}
        assert_eq!(msg_clock.get(&na), 2);

        // B receives message from A
        tracker_b.on_receive(&msg_clock); // B: merge({}, {A:2}) → {A:2}, incr → {A:2, B:1}
        assert_eq!(tracker_b.current_clock().get(&na), 2);
        assert_eq!(tracker_b.current_clock().get(&nb), 1);

        // B does more work
        tracker_b.record_local_event(); // B: {A:2, B:2}

        // B's events happen after A's send
        assert!(msg_clock.happens_before(tracker_b.current_clock()));
    }

    #[test]
    fn causal_event_ordering() {
        let na = node("A");
        let nb = node("B");
        let mut tracker_a = CausalTracker::new(na);
        let mut tracker_b = CausalTracker::new(nb);

        let e1 = tracker_a.record("event-1");
        let e2 = tracker_b.record("event-2");

        // Independent events are concurrent
        assert!(e1.is_concurrent_with(&e2));
        assert!(!e1.happens_before(&e2));
    }

    #[test]
    fn display_formatting() {
        let na = node("A");
        let nb = node("B");
        let mut vc = VectorClock::new();
        vc.increment(&na);
        vc.increment(&nb);
        vc.increment(&nb);
        let display = format!("{vc}");
        assert!(display.contains("A=1"));
        assert!(display.contains("B=2"));
    }

    #[test]
    fn partial_order_after() {
        let na = node("A");
        let mut a = VectorClock::new();
        a.increment(&na);
        let b = VectorClock::new();
        assert_eq!(a.causal_order(&b), CausalOrder::After);
        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Greater));
    }

    #[test]
    fn three_node_diamond() {
        // Classic diamond:
        //   A sends to B and C independently
        //   B and C are concurrent
        //   D receives from both B and C
        let na = node("A");
        let nb = node("B");
        let nc = node("C");
        let nd = node("D");

        let mut ta = CausalTracker::new(na);
        let mut tb = CausalTracker::new(nb);
        let mut tc = CausalTracker::new(nc);
        let mut td = CausalTracker::new(nd);

        // A sends to B and C
        let msg_to_b = ta.on_send();
        let msg_to_c = ta.on_send();

        tb.on_receive(&msg_to_b);
        tc.on_receive(&msg_to_c);

        // B and C do independent work
        let b_clock = tb.on_send();
        let c_clock = tc.on_send();

        // B and C are concurrent
        assert!(b_clock.is_concurrent_with(&c_clock));

        // D receives from B then C
        td.on_receive(&b_clock);
        td.on_receive(&c_clock);

        // D happens after both B and C
        assert!(b_clock.happens_before(td.current_clock()));
        assert!(c_clock.happens_before(td.current_clock()));
    }
}
