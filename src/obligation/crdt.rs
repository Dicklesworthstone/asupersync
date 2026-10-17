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
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

// ─── Per-obligation CRDT entry ──────────────────────────────────────────────

/// A single obligation's convergent state across the cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrdtObligationEntry {
    /// Current lattice state (join of all observations).
    pub state: LatticeState,
    /// Which node reported which state (provenance).
    pub witnesses: BTreeMap<NodeId, LatticeState>,
    /// Nodes that have issued an abort repair for this entry.
    repair_nodes: BTreeSet<NodeId>,
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
            repair_nodes: BTreeSet::new(),
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
    /// exactly one acquire and at most one resolve, with resolves
    /// never exceeding acquires (no resolve-without-acquire).
    #[must_use]
    pub fn is_linear(&self) -> bool {
        let acq = self.total_acquires();
        let res = self.total_resolves();
        acq <= 1 && res <= acq
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
        for (node, &other_state) in &other.witnesses {
            let entry = self
                .witnesses
                .entry(node.clone())
                .or_insert(LatticeState::Unknown);
            *entry = entry.join(other_state);
        }
        match (self.kind, other.kind) {
            (None, rhs) => {
                self.kind = rhs;
            }
            (Some(lhs), Some(rhs)) if lhs != rhs => {
                self.state = self.state.join(LatticeState::Conflict);
                self.kind = Some(lhs.min(rhs));
            }
            _ => {}
        }
        for (node, &count) in &other.acquire_counts {
            let entry = self.acquire_counts.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(count);
        }
        for (node, &count) in &other.resolve_counts {
            let entry = self.resolve_counts.entry(node.clone()).or_insert(0);
            *entry = (*entry).max(count);
        }
        self.repair_nodes.extend(other.repair_nodes.iter().cloned());
        self.normalize_repair_tombstone();
    }

    fn repair_owner(&self) -> Option<&NodeId> {
        self.repair_nodes.iter().next()
    }

    fn is_repair_tombstone(&self) -> bool {
        let Some(owner) = self.repair_owner() else {
            return false;
        };
        self.state == LatticeState::Aborted
            && self.witnesses.len() == 1
            && self.witnesses.get(owner).copied() == Some(LatticeState::Aborted)
            && self.acquire_counts.len() == 1
            && self.acquire_counts.get(owner).copied() == Some(1)
            && self.resolve_counts.len() == 1
            && self.resolve_counts.get(owner).copied() == Some(1)
    }

    fn normalize_repair_tombstone(&mut self) {
        let Some(owner) = self.repair_owner().cloned() else {
            return;
        };

        self.state = LatticeState::Aborted;
        self.witnesses.clear();
        self.witnesses.insert(owner.clone(), LatticeState::Aborted);
        self.acquire_counts.clear();
        self.acquire_counts.insert(owner.clone(), 1);
        self.resolve_counts.clear();
        self.resolve_counts.insert(owner, 1);
    }

    fn is_compact_tombstone_for(&self, local_node: &NodeId) -> bool {
        if !self.repair_nodes.is_empty() {
            return self.is_repair_tombstone();
        }
        let witness_ok = self.witnesses.len() == 1
            && self.witnesses.get(local_node).copied() == Some(self.state);
        let acquire_ok = self.acquire_counts.len() == 1
            && self.acquire_counts.get(local_node).copied() == Some(1);
        let resolve_ok = self.resolve_counts.len() == 1
            && self.resolve_counts.get(local_node).copied() == Some(1);
        witness_ok && acquire_ok && resolve_ok
    }

    fn compact_terminal_tombstone(&mut self, local_node: &NodeId) -> bool {
        if self.is_compact_tombstone_for(local_node) {
            return false;
        }

        if !self.repair_nodes.is_empty() {
            self.normalize_repair_tombstone();
            return true;
        }

        self.witnesses.clear();
        self.witnesses.insert(local_node.clone(), self.state);
        self.acquire_counts.clear();
        self.resolve_counts.clear();
        self.acquire_counts.insert(local_node.clone(), 1);
        self.resolve_counts.insert(local_node.clone(), 1);
        true
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
        if entry.is_terminal() {
            return entry.state;
        }
        match entry.kind {
            None => {
                entry.kind = Some(kind);
            }
            Some(existing_kind) if existing_kind != kind => {
                entry.state = entry.state.join(LatticeState::Conflict);
                let witness = entry
                    .witnesses
                    .entry(self.local_node.clone())
                    .or_insert(LatticeState::Unknown);
                *witness = witness.join(LatticeState::Conflict);
                return entry.state;
            }
            Some(_) => {}
        }
        *entry
            .acquire_counts
            .entry(self.local_node.clone())
            .or_insert(0) += 1;
        entry.state = entry.state.join(LatticeState::Reserved);
        let witness = entry
            .witnesses
            .entry(self.local_node.clone())
            .or_insert(LatticeState::Unknown);
        *witness = witness.join(LatticeState::Reserved);
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
    /// This is a recovery-only repair that marks the entry as repaired and
    /// then projects it onto a deterministic single-abort tombstone.
    /// The repair marker is convergent, so later merges with stale replicas
    /// cannot resurrect the pre-repair conflict or linearity violation.
    /// Only applies to entries that are in conflict or violate linearity;
    /// healthy terminal states (Committed/Aborted without conflict) are
    /// left unchanged.
    pub fn force_abort_repair(&mut self, id: ObligationId) {
        let Some(entry) = self.entries.get_mut(&id) else {
            return;
        };
        // Guard: only repair entries that are actually broken.
        if !entry.is_conflict() && entry.is_linear() {
            return;
        }
        entry.repair_nodes.insert(self.local_node.clone());
        entry.normalize_repair_tombstone();
    }

    fn record_resolve(&mut self, id: ObligationId, terminal: LatticeState) -> LatticeState {
        let entry = self
            .entries
            .entry(id)
            .or_insert_with(CrdtObligationEntry::new);
        // Repaired entries are terminal tombstones — resolving them again is
        // a no-op (the tombstone shape would just be re-applied by
        // normalize_repair_tombstone, silently discarding the work).
        if !entry.repair_nodes.is_empty() {
            return entry.state;
        }
        entry.state = entry.state.join(terminal);
        let witness = entry
            .witnesses
            .entry(self.local_node.clone())
            .or_insert(LatticeState::Unknown);
        *witness = witness.join(terminal);
        *entry
            .resolve_counts
            .entry(self.local_node.clone())
            .or_insert(0) += 1;
        entry.normalize_repair_tombstone();
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
        self.conflicts_iter().collect()
    }

    /// Returns an iterator over all obligations in conflict.
    pub fn conflicts_iter(&self) -> impl Iterator<Item = (ObligationId, &CrdtObligationEntry)> {
        self.entries
            .iter()
            .filter(|(_, e)| e.state.is_conflict())
            .map(|(id, e)| (*id, e))
    }

    /// Returns all obligations with linearity violations
    /// (acquired or resolved more than once across the cluster).
    #[must_use]
    pub fn linearity_violations(&self) -> Vec<LinearityViolation> {
        self.linearity_violations_iter().collect()
    }

    /// Returns an iterator over all obligations with linearity violations.
    pub fn linearity_violations_iter(&self) -> impl Iterator<Item = LinearityViolation> + '_ {
        self.entries
            .iter()
            .filter(|(_, e)| !e.is_linear())
            .map(|(id, e)| LinearityViolation {
                id: *id,
                total_acquires: e.total_acquires(),
                total_resolves: e.total_resolves(),
                witnesses: e.witnesses.clone(),
            })
    }

    /// Returns true if no obligation has a linearity violation or conflict.
    #[must_use]
    pub fn is_sound(&self) -> bool {
        self.entries
            .values()
            .all(|e| e.is_linear() && !e.is_conflict())
    }

    /// Compacts the ledger by reducing terminal, linear entries to
    /// minimal tombstones (state + one local witness/counter pair).
    ///
    /// We intentionally retain a terminal tombstone so stale replicas that
    /// still carry `Reserved` cannot resurrect completed obligations on merge.
    ///
    /// Returns the number of entries compacted.
    pub fn compact(&mut self) -> usize {
        let mut compacted = 0;
        for entry in self.entries.values_mut() {
            if entry.is_terminal()
                && entry.is_linear()
                && !entry.is_conflict()
                && entry.compact_terminal_tombstone(&self.local_node)
            {
                compacted += 1;
            }
        }
        compacted
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
#[path = "crdt_inline_tests.rs"]
mod tests;
