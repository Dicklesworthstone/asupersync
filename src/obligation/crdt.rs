//! Convergent obligation ledger for distributed runtimes.
//!
//! This module provides a CRDT-based obligation ledger that converges across
//! distributed nodes while preserving the linearity invariant: each obligation
//! is resolved exactly once, and resolved obligations cannot be resurrected.
//!
//! # Design
//!
//! The ledger combines two convergent structures:
//!
//! 1. **State lattice** (from [`crate::trace::distributed::lattice::LatticeState`]):
//!    Each obligation's lifecycle state forms a join-semilattice where
//!    `Unknown < Reserved < {Committed, Aborted} < Conflict`.
//!
//! 2. **Per-node counters** (GCounter-style): Track how many times each node
//!    has observed an acquire or resolve event, enabling linearity violation
//!    detection across replicas.
//!
//! # Linearity Preservation
//!
//! The CRDT enforces that:
//! - Terminal states (`Committed`, `Aborted`, `Conflict`) are absorbing: once
//!   reached, no merge can revert them to `Reserved` or `Unknown`.
//! - The join-semilattice structure makes this automatic: `Committed ⊔ Reserved = Committed`.
//! - Multiple conflicting resolutions (commit on node A, abort on node B) are
//!   detected as `Conflict` and flagged for operator intervention.
//!
//! # Merge Semantics
//!
//! Merging two replicas performs componentwise join of each obligation entry:
//! - State: `LatticeState::join`
//! - Witnesses: union of per-node observations
//! - Counters: componentwise max (GCounter semantics)
//!
//! This satisfies commutativity, associativity, and idempotence.

use crate::record::ObligationKind;
use crate::remote::NodeId;
use crate::trace::distributed::crdt::Merge;
use crate::trace::distributed::lattice::LatticeState;
use crate::types::ObligationId;
use std::collections::BTreeMap;
use std::fmt;

// ─── Per-obligation CRDT entry ──────────────────────────────────────────────

/// A single obligation's convergent state across the cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrdtObligationEntry {
    /// Current lattice state (join of all observations).
    pub state: LatticeState,
    /// Which node reported which state (provenance).
    pub witnesses: BTreeMap<NodeId, LatticeState>,
    /// Obligation kind (informational, set on first observe).
    pub kind: Option<ObligationKind>,
    /// Per-node acquire count (GCounter). Linearity requires global sum == 1.
    acquire_counts: BTreeMap<NodeId, u64>,
    /// Per-node resolve count (GCounter). Linearity requires global sum == 1.
    resolve_counts: BTreeMap<NodeId, u64>,
}

impl CrdtObligationEntry {
    fn new() -> Self {
        Self {
            state: LatticeState::Unknown,
            witnesses: BTreeMap::new(),
            kind: None,
            acquire_counts: BTreeMap::new(),
            resolve_counts: BTreeMap::new(),
        }
    }

    /// Total acquires observed across all nodes.
    #[must_use]
    pub fn total_acquires(&self) -> u64 {
        self.acquire_counts.values().sum()
    }

    /// Total resolves observed across all nodes.
    #[must_use]
    pub fn total_resolves(&self) -> u64 {
        self.resolve_counts.values().sum()
    }

    /// Returns true if the linearity invariant is satisfied:
    /// at most one acquire and at most one resolve.
    #[must_use]
    pub fn is_linear(&self) -> bool {
        self.total_acquires() <= 1 && self.total_resolves() <= 1
    }

    /// Returns true if the obligation is in a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Returns true if the obligation is in conflict.
    #[must_use]
    pub fn is_conflict(&self) -> bool {
        self.state.is_conflict()
    }

    fn merge_entry(&mut self, other: &Self) {
        self.state = self.state.join(other.state);
        for (node, &state) in &other.witnesses {
            self.witnesses.insert(node.clone(), state);
        }
        if self.kind.is_none() {
            self.kind = other.kind;
        }
        for (node, &count) in &other.acquire_counts {
            let entry = self.acquire_counts.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(count);
        }
        for (node, &count) in &other.resolve_counts {
            let entry = self.resolve_counts.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(count);
        }
    }
}

// ─── CRDT Obligation Ledger ─────────────────────────────────────────────────

/// A convergent obligation ledger for distributed runtimes.
///
/// Each node maintains a local `CrdtObligationLedger`. Periodic or
/// event-driven merges bring replicas into agreement without coordination.
///
/// # Invariants maintained across merges
///
/// - Terminal states are absorbing (lattice join guarantees this).
/// - Per-obligation acquire/resolve counts use GCounter semantics (max per node).
/// - Linearity violations (multiple acquires or resolves) are detectable via counters.
/// - `Committed ⊔ Aborted = Conflict` flags protocol bugs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrdtObligationLedger {
    /// The node that owns this replica.
    local_node: NodeId,
    /// Per-obligation convergent state.
    entries: BTreeMap<ObligationId, CrdtObligationEntry>,
}

impl CrdtObligationLedger {
    /// Creates a new ledger replica for the given node.
    #[must_use]
    pub fn new(local_node: NodeId) -> Self {
        Self {
            local_node,
            entries: BTreeMap::new(),
        }
    }

    /// Records an obligation acquire on this node.
    pub fn record_acquire(&mut self, id: ObligationId, kind: ObligationKind) -> LatticeState {
        let entry = self
            .entries
            .entry(id)
            .or_insert_with(CrdtObligationEntry::new);
        entry.kind = Some(kind);
        entry.state = entry.state.join(LatticeState::Reserved);
        entry
            .witnesses
            .insert(self.local_node.clone(), LatticeState::Reserved);
        *entry
            .acquire_counts
            .entry(self.local_node.clone())
            .or_insert(0) += 1;
        entry.state
    }

    /// Records an obligation commit on this node.
    pub fn record_commit(&mut self, id: ObligationId) -> LatticeState {
        self.record_resolve(id, LatticeState::Committed)
    }

    /// Records an obligation abort on this node.
    pub fn record_abort(&mut self, id: ObligationId) -> LatticeState {
        self.record_resolve(id, LatticeState::Aborted)
    }

    /// Forces an obligation into an aborted, linear state.
    ///
    /// This is a recovery-only repair that collapses conflicts or linearity
    /// violations by resetting counters and witnesses to a single abort.
    pub fn force_abort_repair(&mut self, id: ObligationId) {
        let entry = self
            .entries
            .entry(id)
            .or_insert_with(CrdtObligationEntry::new);
        entry.state = LatticeState::Aborted;
        entry.witnesses.clear();
        entry
            .witnesses
            .insert(self.local_node.clone(), LatticeState::Aborted);
        entry.acquire_counts.clear();
        entry.resolve_counts.clear();
        entry.acquire_counts.insert(self.local_node.clone(), 1);
        entry.resolve_counts.insert(self.local_node.clone(), 1);
    }

    fn record_resolve(&mut self, id: ObligationId, terminal: LatticeState) -> LatticeState {
        let entry = self
            .entries
            .entry(id)
            .or_insert_with(CrdtObligationEntry::new);
        entry.state = entry.state.join(terminal);
        entry.witnesses.insert(self.local_node.clone(), terminal);
        *entry
            .resolve_counts
            .entry(self.local_node.clone())
            .or_insert(0) += 1;
        entry.state
    }

    /// Returns the current state of an obligation.
    #[must_use]
    pub fn get(&self, id: &ObligationId) -> LatticeState {
        self.entries
            .get(id)
            .map_or(LatticeState::Unknown, |e| e.state)
    }

    /// Returns the full entry for an obligation.
    #[must_use]
    pub fn get_entry(&self, id: &ObligationId) -> Option<&CrdtObligationEntry> {
        self.entries.get(id)
    }

    /// Returns the node ID of this replica.
    #[must_use]
    pub fn local_node(&self) -> &NodeId {
        &self.local_node
    }

    /// Returns the number of tracked obligations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if no obligations are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns all obligations currently pending (Reserved, not terminal).
    #[must_use]
    pub fn pending(&self) -> Vec<ObligationId> {
        self.entries
            .iter()
            .filter(|(_, e)| e.state == LatticeState::Reserved)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Returns all obligations in conflict.
    #[must_use]
    pub fn conflicts(&self) -> Vec<(ObligationId, &CrdtObligationEntry)> {
        self.entries
            .iter()
            .filter(|(_, e)| e.state.is_conflict())
            .map(|(id, e)| (*id, e))
            .collect()
    }

    /// Returns all obligations with linearity violations
    /// (acquired or resolved more than once across the cluster).
    #[must_use]
    pub fn linearity_violations(&self) -> Vec<LinearityViolation> {
        self.entries
            .iter()
            .filter(|(_, e)| !e.is_linear())
            .map(|(id, e)| LinearityViolation {
                id: *id,
                total_acquires: e.total_acquires(),
                total_resolves: e.total_resolves(),
                witnesses: e.witnesses.clone(),
            })
            .collect()
    }

    /// Returns true if no obligation has a linearity violation or conflict.
    #[must_use]
    pub fn is_sound(&self) -> bool {
        self.entries
            .values()
            .all(|e| e.is_linear() && !e.is_conflict())
    }

    /// Compacts the ledger by removing fully resolved obligations whose
    /// state is terminal and linear. This is safe because terminal states
    /// are absorbing — any future merge with a stale replica will re-join
    /// to the same terminal, and the counter invariant is already satisfied.
    ///
    /// Returns the number of entries compacted.
    pub fn compact(&mut self) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, e| !(e.is_terminal() && e.is_linear() && !e.is_conflict()));
        before - self.entries.len()
    }

    /// Returns a diagnostic snapshot of the ledger.
    #[must_use]
    pub fn snapshot(&self) -> LedgerSnapshot {
        let total = self.entries.len();
        let pending = self
            .entries
            .values()
            .filter(|e| e.state == LatticeState::Reserved)
            .count();
        let committed = self
            .entries
            .values()
            .filter(|e| e.state == LatticeState::Committed)
            .count();
        let aborted = self
            .entries
            .values()
            .filter(|e| e.state == LatticeState::Aborted)
            .count();
        let conflicts = self.entries.values().filter(|e| e.is_conflict()).count();
        let linearity_violations = self.entries.values().filter(|e| !e.is_linear()).count();

        LedgerSnapshot {
            node: self.local_node.clone(),
            total,
            pending,
            committed,
            aborted,
            conflicts,
            linearity_violations,
        }
    }
}

impl Merge for CrdtObligationLedger {
    fn merge(&mut self, other: &Self) {
        for (id, other_entry) in &other.entries {
            let entry = self
                .entries
                .entry(*id)
                .or_insert_with(CrdtObligationEntry::new);
            entry.merge_entry(other_entry);
        }
    }
}

// ─── Diagnostic types ───────────────────────────────────────────────────────

/// A linearity violation detected in the CRDT ledger.
#[derive(Debug, Clone)]
pub struct LinearityViolation {
    /// The obligation with the violation.
    pub id: ObligationId,
    /// Total acquires across all nodes (should be exactly 1).
    pub total_acquires: u64,
    /// Total resolves across all nodes (should be at most 1).
    pub total_resolves: u64,
    /// Node-level provenance.
    pub witnesses: BTreeMap<NodeId, LatticeState>,
}

impl fmt::Display for LinearityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "obligation {:?}: acquires={}, resolves={}, witnesses={:?}",
            self.id, self.total_acquires, self.total_resolves, self.witnesses
        )
    }
}

/// Diagnostic snapshot of a CRDT ledger replica.
#[derive(Debug, Clone)]
pub struct LedgerSnapshot {
    /// The node this snapshot is from.
    pub node: NodeId,
    /// Total obligations tracked.
    pub total: usize,
    /// Obligations still pending (Reserved).
    pub pending: usize,
    /// Obligations committed.
    pub committed: usize,
    /// Obligations aborted.
    pub aborted: usize,
    /// Obligations in conflict.
    pub conflicts: usize,
    /// Obligations with linearity violations.
    pub linearity_violations: usize,
}

impl fmt::Display for LedgerSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] total={} pending={} committed={} aborted={} conflicts={} violations={}",
            self.node,
            self.total,
            self.pending,
            self.committed,
            self.aborted,
            self.conflicts,
            self.linearity_violations
        )
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::NodeId;
    use crate::types::ObligationId;

    fn oid(index: u32) -> ObligationId {
        ObligationId::new_for_test(index, 0)
    }

    fn node(name: &str) -> NodeId {
        NodeId::new(name)
    }

    // ── Basic operations ────────────────────────────────────────────────

    #[test]
    fn acquire_sets_reserved() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        let state = ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        assert_eq!(state, LatticeState::Reserved);
        assert_eq!(ledger.get(&oid(1)), LatticeState::Reserved);
    }

    #[test]
    fn commit_sets_committed() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::Ack);
        let state = ledger.record_commit(oid(1));
        assert_eq!(state, LatticeState::Committed);
    }

    #[test]
    fn abort_sets_aborted() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::Lease);
        let state = ledger.record_abort(oid(1));
        assert_eq!(state, LatticeState::Aborted);
    }

    #[test]
    fn unknown_obligation_returns_unknown() {
        let ledger = CrdtObligationLedger::new(node("A"));
        assert_eq!(ledger.get(&oid(99)), LatticeState::Unknown);
    }

    // ── Linearity tracking ──────────────────────────────────────────────

    #[test]
    fn single_acquire_resolve_is_linear() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_commit(oid(1));
        let entry = ledger.get_entry(&oid(1)).unwrap();
        assert!(entry.is_linear());
        assert_eq!(entry.total_acquires(), 1);
        assert_eq!(entry.total_resolves(), 1);
    }

    #[test]
    fn double_acquire_on_same_node_violates_linearity() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        let entry = ledger.get_entry(&oid(1)).unwrap();
        assert!(!entry.is_linear());
        assert_eq!(entry.total_acquires(), 2);
    }

    #[test]
    fn double_resolve_violates_linearity() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_commit(oid(1));
        ledger.record_commit(oid(1));
        let entry = ledger.get_entry(&oid(1)).unwrap();
        assert!(!entry.is_linear());
        assert_eq!(entry.total_resolves(), 2);
    }

    #[test]
    fn linearity_violations_reported() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        let violations = ledger.linearity_violations();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].id, oid(1));
    }

    // ── Merge semantics ─────────────────────────────────────────────────

    #[test]
    fn merge_two_replicas_converges() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(2), ObligationKind::Ack);
        b.record_abort(oid(2));

        a.merge(&b);
        assert_eq!(a.get(&oid(1)), LatticeState::Committed);
        assert_eq!(a.get(&oid(2)), LatticeState::Aborted);
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn merge_is_commutative() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(ab.get(&oid(1)), ba.get(&oid(1)));
        assert_eq!(ab.get(&oid(1)), LatticeState::Committed);
    }

    #[test]
    fn merge_is_associative() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);
        b.record_commit(oid(1));

        let mut c = CrdtObligationLedger::new(node("C"));
        c.record_acquire(oid(2), ObligationKind::Lease);

        // (a ⊔ b) ⊔ c
        let mut ab_c = a.clone();
        ab_c.merge(&b);
        ab_c.merge(&c);

        // a ⊔ (b ⊔ c)
        let mut bc = b.clone();
        bc.merge(&c);
        let mut a_bc = a.clone();
        a_bc.merge(&bc);

        assert_eq!(ab_c.get(&oid(1)), a_bc.get(&oid(1)));
        assert_eq!(ab_c.get(&oid(2)), a_bc.get(&oid(2)));
    }

    #[test]
    fn merge_is_idempotent() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let before = a.clone();
        a.merge(&before);
        assert_eq!(a, before);
    }

    #[test]
    fn conflict_detected_on_commit_abort_merge() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);
        b.record_abort(oid(1));

        a.merge(&b);
        assert_eq!(a.get(&oid(1)), LatticeState::Conflict);
        assert!(!a.is_sound());
        let conflicts = a.conflicts();
        assert_eq!(conflicts.len(), 1);
    }

    // ── Terminal state absorbing ────────────────────────────────────────

    #[test]
    fn terminal_state_absorbs_reserved() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        // Stale replica only saw the acquire
        let mut stale = CrdtObligationLedger::new(node("B"));
        stale.record_acquire(oid(1), ObligationKind::SendPermit);

        // Merge stale into committed: still committed
        a.merge(&stale);
        assert_eq!(a.get(&oid(1)), LatticeState::Committed);
    }

    // ── Compaction ──────────────────────────────────────────────────────

    #[test]
    fn compact_removes_terminal_linear_entries() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_commit(oid(1));
        ledger.record_acquire(oid(2), ObligationKind::Ack);
        // oid(2) still pending

        let compacted = ledger.compact();
        assert_eq!(compacted, 1);
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.get(&oid(1)), LatticeState::Unknown); // removed
        assert_eq!(ledger.get(&oid(2)), LatticeState::Reserved); // kept
    }

    #[test]
    fn compact_preserves_conflicts() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(1), ObligationKind::SendPermit);
        b.record_abort(oid(1));

        a.merge(&b);
        assert!(a.get(&oid(1)).is_conflict());

        let compacted = a.compact();
        assert_eq!(compacted, 0); // conflict not compacted
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn compact_preserves_linearity_violations() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_commit(oid(1));

        let compacted = ledger.compact();
        assert_eq!(compacted, 0); // violation not compacted
    }

    // ── Pending / snapshot ──────────────────────────────────────────────

    #[test]
    fn pending_returns_only_reserved() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(2), ObligationKind::Ack);
        ledger.record_commit(oid(2));

        let pending = ledger.pending();
        assert_eq!(pending, vec![oid(1)]);
    }

    #[test]
    fn snapshot_reflects_state() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(2), ObligationKind::Ack);
        ledger.record_commit(oid(2));
        ledger.record_acquire(oid(3), ObligationKind::Lease);
        ledger.record_abort(oid(3));

        let snap = ledger.snapshot();
        assert_eq!(snap.total, 3);
        assert_eq!(snap.pending, 1);
        assert_eq!(snap.committed, 1);
        assert_eq!(snap.aborted, 1);
        assert_eq!(snap.conflicts, 0);
        assert_eq!(snap.linearity_violations, 0);
    }

    #[test]
    fn is_sound_with_clean_ledger() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_commit(oid(1));
        assert!(ledger.is_sound());
    }

    // ── Ring gossip convergence ─────────────────────────────────────────

    #[test]
    fn three_node_ring_gossip_converges() {
        let mut a = CrdtObligationLedger::new(node("A"));
        a.record_acquire(oid(1), ObligationKind::SendPermit);
        a.record_commit(oid(1));

        let mut b = CrdtObligationLedger::new(node("B"));
        b.record_acquire(oid(2), ObligationKind::Ack);
        b.record_abort(oid(2));

        let mut c = CrdtObligationLedger::new(node("C"));
        c.record_acquire(oid(3), ObligationKind::Lease);

        // Ring gossip: a→b→c→a→b
        a.merge(&b);
        b.merge(&c);
        c.merge(&a);
        a.merge(&c);
        b.merge(&a);

        // All replicas should agree
        for id in [oid(1), oid(2), oid(3)] {
            assert_eq!(
                a.get(&id),
                b.get(&id),
                "divergence on {id:?} between A and B"
            );
            assert_eq!(
                b.get(&id),
                c.get(&id),
                "divergence on {id:?} between B and C"
            );
        }

        assert_eq!(a.get(&oid(1)), LatticeState::Committed);
        assert_eq!(a.get(&oid(2)), LatticeState::Aborted);
        assert_eq!(a.get(&oid(3)), LatticeState::Reserved);
    }

    // ── Display ─────────────────────────────────────────────────────────

    #[test]
    fn snapshot_display_is_readable() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        let snap = ledger.snapshot();
        let display = format!("{snap}");
        assert!(display.contains("total=1"));
        assert!(display.contains("pending=1"));
    }

    #[test]
    fn linearity_violation_display() {
        let mut ledger = CrdtObligationLedger::new(node("A"));
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        ledger.record_acquire(oid(1), ObligationKind::SendPermit);
        let violations = ledger.linearity_violations();
        let display = format!("{}", violations[0]);
        assert!(display.contains("acquires=2"));
    }
}
