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
#[derive(Clone, Debug, Default)]
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

#[cfg(test)]
#[path = "lattice_inline_tests.rs"]
mod tests;
