//! Convergent state lattice for distributed obligation and lease state.
//!
//! In a distributed system, obligation and lease states may be observed at
//! different replicas with different orderings. This module defines a
//! join-semilattice that ensures convergence: merging state from any two
//! replicas yields the same result regardless of order.
//!
//! # State Lattice
//!
//! The obligation lifecycle forms a lattice:
//!
//! ```text
//!     Conflict (⊤)
//!      /      \
//!  Committed  Aborted
//!      \      /
//!     Reserved
//!        |
//!     Unknown (⊥)
//! ```
//!
//! - `Reserved ⊔ Committed = Committed` (committed supersedes reserved)
//! - `Reserved ⊔ Aborted = Aborted` (aborted supersedes reserved)
//! - `Committed ⊔ Aborted = Conflict` (protocol violation — should never happen)
//! - `Unknown ⊔ X = X` (unknown is the bottom element)
//! - `Conflict ⊔ X = Conflict` (conflict absorbs everything)
//!
//! The merge operation is associative, commutative, and idempotent.

use crate::remote::NodeId;
use crate::types::ObligationId;
use std::collections::BTreeMap;
use std::fmt;

/// The distributed view of an obligation's state, forming a join-semilattice.
///
/// Unlike the local `ObligationState` (which has a `Leaked` variant for
/// resource-level errors), the distributed lattice focuses on the protocol-level
/// states that replicas must agree on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LatticeState {
    /// Bottom element. No information received about this obligation.
    Unknown,
    /// The obligation has been reserved but not yet resolved.
    Reserved,
    /// The obligation was committed (successful completion).
    Committed,
    /// The obligation was aborted (intentional cancellation).
    Aborted,
    /// Protocol violation: incompatible states merged (Committed ⊔ Aborted).
    Conflict,
}

impl LatticeState {
    /// Returns the join (least upper bound) of two states.
    ///
    /// This operation is:
    /// - Associative: `(a ⊔ b) ⊔ c = a ⊔ (b ⊔ c)`
    /// - Commutative: `a ⊔ b = b ⊔ a`
    /// - Idempotent: `a ⊔ a = a`
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        use LatticeState::{Aborted, Committed, Conflict, Reserved, Unknown};
        match (self, other) {
            // Identity: Unknown is the bottom element
            (Unknown, x) | (x, Unknown) => x,
            // Absorb: Conflict is the top element
            (Conflict, _) | (_, Conflict) | (Committed, Aborted) | (Aborted, Committed) => Conflict,
            // Idempotent
            (Reserved, Reserved) => Reserved,
            // Progressing from Reserved
            (Committed | Reserved, Committed) | (Committed, Reserved) => Committed,
            (Aborted | Reserved, Aborted) | (Aborted, Reserved) => Aborted,
        }
    }

    /// Returns true if this state is a terminal state (Committed, Aborted, or Conflict).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Aborted | Self::Conflict)
    }

    /// Returns true if this state indicates a protocol violation.
    #[must_use]
    pub fn is_conflict(self) -> bool {
        self == Self::Conflict
    }

    /// Returns the numeric rank in the lattice (for ordering).
    /// Unknown(0) < Reserved(1) < Committed|Aborted(2) < Conflict(3)
    #[must_use]
    fn rank(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Reserved => 1,
            Self::Committed | Self::Aborted => 2,
            Self::Conflict => 3,
        }
    }
}

impl fmt::Display for LatticeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Reserved => write!(f, "Reserved"),
            Self::Committed => write!(f, "Committed"),
            Self::Aborted => write!(f, "Aborted"),
            Self::Conflict => write!(f, "CONFLICT"),
        }
    }
}

/// Partial order for lattice states.
///
/// Two states are comparable if one can reach the other via `join` operations.
/// `Committed` and `Aborted` are incomparable (concurrent in the lattice).
impl PartialOrd for LatticeState {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self == other {
            return Some(std::cmp::Ordering::Equal);
        }
        let sr = self.rank();
        let or = other.rank();
        if sr != or {
            return Some(sr.cmp(&or));
        }
        // Same rank but different values: Committed vs Aborted — incomparable
        None
    }
}

/// The distributed view of a lease's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeaseLatticeState {
    /// No information about this lease.
    Unknown,
    /// The lease is active.
    Active,
    /// The lease has been explicitly released by its holder.
    Released,
    /// The lease expired without renewal.
    Expired,
    /// Conflicting information (e.g., Released and Active from different replicas
    /// after the release was observed). This should not happen under correct
    /// protocol usage but is detectable.
    Conflict,
}

impl LeaseLatticeState {
    /// Returns the join (least upper bound) of two lease states.
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        use LeaseLatticeState::{Active, Conflict, Expired, Released, Unknown};
        match (self, other) {
            (Unknown, x) | (x, Unknown) => x,
            (Conflict, _) | (_, Conflict) | (Released, Expired) | (Expired, Released) => Conflict,
            // Idempotent
            (Active, Active) => Active,
            // Active can progress to Released or Expired
            (Released | Active, Released) | (Released, Active) => Released,
            (Expired | Active, Expired) | (Expired, Active) => Expired,
        }
    }

    /// Returns true if this is a terminal state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Released | Self::Expired | Self::Conflict)
    }

    /// Returns true if this indicates a protocol violation.
    #[must_use]
    pub fn is_conflict(self) -> bool {
        self == Self::Conflict
    }
}

impl fmt::Display for LeaseLatticeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Active => write!(f, "Active"),
            Self::Released => write!(f, "Released"),
            Self::Expired => write!(f, "Expired"),
            Self::Conflict => write!(f, "CONFLICT"),
        }
    }
}

/// A distributed obligation state map that converges across replicas.
///
/// Each replica independently merges observations. The map itself forms
/// a join-semilattice: merging two maps yields the componentwise join
/// of each obligation's state.
#[derive(Clone, Debug)]
pub struct ObligationLattice {
    obligations: BTreeMap<ObligationId, ObligationEntry>,
}

/// An entry in the obligation lattice, tracking state and provenance.
#[derive(Clone, Debug)]
pub struct ObligationEntry {
    /// The current lattice state.
    pub state: LatticeState,
    /// Which nodes have reported which states.
    pub witnesses: BTreeMap<NodeId, LatticeState>,
}

impl ObligationEntry {
    fn new() -> Self {
        Self {
            state: LatticeState::Unknown,
            witnesses: BTreeMap::new(),
        }
    }
}

impl ObligationLattice {
    /// Creates an empty obligation lattice.
    #[must_use]
    pub fn new() -> Self {
        Self {
            obligations: BTreeMap::new(),
        }
    }

    /// Records a state observation from a node.
    ///
    /// Returns the resulting state after joining. If the result is `Conflict`,
    /// the witnesses map shows which nodes reported incompatible states.
    pub fn observe(
        &mut self,
        obligation: ObligationId,
        node: NodeId,
        state: LatticeState,
    ) -> LatticeState {
        let entry = self
            .obligations
            .entry(obligation)
            .or_insert_with(ObligationEntry::new);
        entry.witnesses.insert(node, state);
        entry.state = entry.state.join(state);
        entry.state
    }

    /// Merges another lattice into this one.
    ///
    /// The result is the componentwise join of all obligations.
    pub fn merge(&mut self, other: &Self) {
        for (id, other_entry) in &other.obligations {
            let entry = self
                .obligations
                .entry(*id)
                .or_insert_with(ObligationEntry::new);
            entry.state = entry.state.join(other_entry.state);
            for (node, &state) in &other_entry.witnesses {
                entry.witnesses.insert(node.clone(), state);
            }
        }
    }

    /// Returns the current state of an obligation.
    #[must_use]
    pub fn get(&self, obligation: &ObligationId) -> LatticeState {
        self.obligations
            .get(obligation)
            .map_or(LatticeState::Unknown, |e| e.state)
    }

    /// Returns the full entry for an obligation, including witnesses.
    #[must_use]
    pub fn get_entry(&self, obligation: &ObligationId) -> Option<&ObligationEntry> {
        self.obligations.get(obligation)
    }

    /// Returns all obligations currently in conflict.
    #[must_use]
    pub fn conflicts(&self) -> Vec<(ObligationId, &ObligationEntry)> {
        self.obligations
            .iter()
            .filter(|(_, e)| e.state.is_conflict())
            .map(|(id, e)| (*id, e))
            .collect()
    }

    /// Returns the number of tracked obligations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.obligations.len()
    }

    /// Returns true if no obligations are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.obligations.is_empty()
    }

    /// Returns true if any obligation is in conflict.
    #[must_use]
    pub fn has_conflicts(&self) -> bool {
        self.obligations.values().any(|e| e.state.is_conflict())
    }
}

impl Default for ObligationLattice {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(index: u32) -> ObligationId {
        ObligationId::new_for_test(index, 0)
    }

    fn node(name: &str) -> NodeId {
        NodeId::new(name)
    }

    // -----------------------------------------------------------------------
    // LatticeState semilattice laws
    // -----------------------------------------------------------------------

    #[test]
    fn join_is_commutative() {
        let states = [
            LatticeState::Unknown,
            LatticeState::Reserved,
            LatticeState::Committed,
            LatticeState::Aborted,
            LatticeState::Conflict,
        ];
        for &a in &states {
            for &b in &states {
                assert_eq!(
                    a.join(b),
                    b.join(a),
                    "commutativity failed for {a:?} ⊔ {b:?}"
                );
            }
        }
    }

    #[test]
    fn join_is_associative() {
        let states = [
            LatticeState::Unknown,
            LatticeState::Reserved,
            LatticeState::Committed,
            LatticeState::Aborted,
            LatticeState::Conflict,
        ];
        for &a in &states {
            for &b in &states {
                for &c in &states {
                    assert_eq!(
                        a.join(b).join(c),
                        a.join(b.join(c)),
                        "associativity failed for ({a:?} ⊔ {b:?}) ⊔ {c:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn join_is_idempotent() {
        let states = [
            LatticeState::Unknown,
            LatticeState::Reserved,
            LatticeState::Committed,
            LatticeState::Aborted,
            LatticeState::Conflict,
        ];
        for &a in &states {
            assert_eq!(a.join(a), a, "idempotency failed for {a:?}");
        }
    }

    #[test]
    fn unknown_is_bottom() {
        let states = [
            LatticeState::Reserved,
            LatticeState::Committed,
            LatticeState::Aborted,
            LatticeState::Conflict,
        ];
        for &s in &states {
            assert_eq!(LatticeState::Unknown.join(s), s);
            assert_eq!(s.join(LatticeState::Unknown), s);
        }
    }

    #[test]
    fn conflict_is_top() {
        let states = [
            LatticeState::Unknown,
            LatticeState::Reserved,
            LatticeState::Committed,
            LatticeState::Aborted,
        ];
        for &s in &states {
            assert_eq!(LatticeState::Conflict.join(s), LatticeState::Conflict);
            assert_eq!(s.join(LatticeState::Conflict), LatticeState::Conflict);
        }
    }

    #[test]
    fn committed_aborted_is_conflict() {
        assert_eq!(
            LatticeState::Committed.join(LatticeState::Aborted),
            LatticeState::Conflict
        );
    }

    #[test]
    fn reserved_progresses_to_committed() {
        assert_eq!(
            LatticeState::Reserved.join(LatticeState::Committed),
            LatticeState::Committed
        );
    }

    #[test]
    fn reserved_progresses_to_aborted() {
        assert_eq!(
            LatticeState::Reserved.join(LatticeState::Aborted),
            LatticeState::Aborted
        );
    }

    // -----------------------------------------------------------------------
    // LeaseLatticeState
    // -----------------------------------------------------------------------

    #[test]
    fn lease_join_is_commutative() {
        let states = [
            LeaseLatticeState::Unknown,
            LeaseLatticeState::Active,
            LeaseLatticeState::Released,
            LeaseLatticeState::Expired,
            LeaseLatticeState::Conflict,
        ];
        for &a in &states {
            for &b in &states {
                assert_eq!(a.join(b), b.join(a));
            }
        }
    }

    #[test]
    fn lease_join_is_associative() {
        let states = [
            LeaseLatticeState::Unknown,
            LeaseLatticeState::Active,
            LeaseLatticeState::Released,
            LeaseLatticeState::Expired,
            LeaseLatticeState::Conflict,
        ];
        for &a in &states {
            for &b in &states {
                for &c in &states {
                    assert_eq!(a.join(b).join(c), a.join(b.join(c)));
                }
            }
        }
    }

    #[test]
    fn lease_join_is_idempotent() {
        let states = [
            LeaseLatticeState::Unknown,
            LeaseLatticeState::Active,
            LeaseLatticeState::Released,
            LeaseLatticeState::Expired,
            LeaseLatticeState::Conflict,
        ];
        for &a in &states {
            assert_eq!(a.join(a), a);
        }
    }

    #[test]
    fn lease_released_expired_is_conflict() {
        assert_eq!(
            LeaseLatticeState::Released.join(LeaseLatticeState::Expired),
            LeaseLatticeState::Conflict
        );
    }

    #[test]
    fn lease_active_progresses() {
        assert_eq!(
            LeaseLatticeState::Active.join(LeaseLatticeState::Released),
            LeaseLatticeState::Released
        );
        assert_eq!(
            LeaseLatticeState::Active.join(LeaseLatticeState::Expired),
            LeaseLatticeState::Expired
        );
    }

    // -----------------------------------------------------------------------
    // ObligationLattice
    // -----------------------------------------------------------------------

    #[test]
    fn obligation_lattice_observe_single() {
        let mut lat = ObligationLattice::new();
        let id = oid(1);
        let n = node("A");

        let result = lat.observe(id, n, LatticeState::Reserved);
        assert_eq!(result, LatticeState::Reserved);
        assert_eq!(lat.get(&id), LatticeState::Reserved);
    }

    #[test]
    fn obligation_lattice_observe_progression() {
        let mut lat = ObligationLattice::new();
        let id = oid(1);
        let na = node("A");
        let nb = node("B");

        lat.observe(id, na, LatticeState::Reserved);
        let result = lat.observe(id, nb, LatticeState::Committed);
        assert_eq!(result, LatticeState::Committed);
    }

    #[test]
    fn obligation_lattice_detects_conflict() {
        let mut lat = ObligationLattice::new();
        let id = oid(1);
        let na = node("A");
        let nb = node("B");

        lat.observe(id, na.clone(), LatticeState::Committed);
        let result = lat.observe(id, nb.clone(), LatticeState::Aborted);
        assert_eq!(result, LatticeState::Conflict);
        assert!(lat.has_conflicts());

        let conflicts = lat.conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].0, id);
        // Witnesses show who reported what
        let entry = &conflicts[0].1;
        assert_eq!(entry.witnesses.get(&na), Some(&LatticeState::Committed));
        assert_eq!(entry.witnesses.get(&nb), Some(&LatticeState::Aborted));
    }

    #[test]
    fn obligation_lattice_merge_two_replicas() {
        let na = node("A");
        let nb = node("B");
        let id1 = oid(1);
        let id2 = oid(2);

        let mut replica_a = ObligationLattice::new();
        replica_a.observe(id1, na.clone(), LatticeState::Committed);
        replica_a.observe(id2, na, LatticeState::Reserved);

        let mut replica_b = ObligationLattice::new();
        replica_b.observe(id1, nb.clone(), LatticeState::Reserved);
        replica_b.observe(id2, nb, LatticeState::Aborted);

        // Merge B into A
        replica_a.merge(&replica_b);

        // id1: Committed ⊔ Reserved = Committed
        assert_eq!(replica_a.get(&id1), LatticeState::Committed);
        // id2: Reserved ⊔ Aborted = Aborted
        assert_eq!(replica_a.get(&id2), LatticeState::Aborted);
        assert!(!replica_a.has_conflicts());
    }

    #[test]
    fn obligation_lattice_merge_is_commutative() {
        let na = node("A");
        let nb = node("B");
        let id = oid(1);

        let mut a = ObligationLattice::new();
        a.observe(id, na, LatticeState::Committed);

        let mut b = ObligationLattice::new();
        b.observe(id, nb, LatticeState::Reserved);

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(ab.get(&id), ba.get(&id));
    }

    #[test]
    fn lattice_state_partial_order() {
        assert!(LatticeState::Unknown < LatticeState::Reserved);
        assert!(LatticeState::Reserved < LatticeState::Committed);
        assert!(LatticeState::Reserved < LatticeState::Aborted);
        assert!(LatticeState::Committed < LatticeState::Conflict);
        assert!(LatticeState::Aborted < LatticeState::Conflict);
        // Committed and Aborted are incomparable
        assert_eq!(
            LatticeState::Committed.partial_cmp(&LatticeState::Aborted),
            None
        );
    }

    #[test]
    fn unknown_obligation_returns_unknown() {
        let lat = ObligationLattice::new();
        assert_eq!(lat.get(&oid(99)), LatticeState::Unknown);
    }

    #[test]
    fn lattice_state_debug_clone_copy_hash() {
        use std::collections::HashSet;
        let s = LatticeState::Committed;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Committed"), "{dbg}");
        let copied: LatticeState = s;
        let cloned = s.clone();
        assert_eq!(copied, cloned);

        let mut set = HashSet::new();
        set.insert(LatticeState::Unknown);
        set.insert(LatticeState::Reserved);
        set.insert(LatticeState::Committed);
        set.insert(LatticeState::Aborted);
        set.insert(LatticeState::Conflict);
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn lease_lattice_state_debug_clone_copy_hash() {
        use std::collections::HashSet;
        let s = LeaseLatticeState::Active;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Active"), "{dbg}");
        let copied: LeaseLatticeState = s;
        let cloned = s.clone();
        assert_eq!(copied, cloned);

        let mut set = HashSet::new();
        set.insert(LeaseLatticeState::Unknown);
        set.insert(LeaseLatticeState::Active);
        set.insert(LeaseLatticeState::Released);
        set.insert(LeaseLatticeState::Expired);
        set.insert(LeaseLatticeState::Conflict);
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn obligation_lattice_debug_clone() {
        let mut lat = ObligationLattice::new();
        lat.observe(oid(1), node("n1"), LatticeState::Reserved);
        let dbg = format!("{lat:?}");
        assert!(dbg.contains("ObligationLattice"), "{dbg}");
        let cloned = lat.clone();
        assert_eq!(cloned.get(&oid(1)), LatticeState::Reserved);
    }
}
