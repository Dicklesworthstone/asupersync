//! Sheaf-theoretic consistency checks for distributed sagas.
//!
//! # Problem Statement
//!
//! In a distributed saga, multiple nodes observe obligation states independently.
//! Pairwise merging (via the [`LatticeState`] join-semilattice) detects when two
//! nodes disagree on a single obligation. But pairwise checks can miss *global*
//! inconsistencies where:
//!
//! - Each pair of nodes appears locally consistent, yet
//! - No single global assignment satisfies all constraints.
//!
//! # Concrete Example
//!
//! Consider a saga with three steps (obligations O1, O2, O3) that must be
//! *all-or-nothing*. Three nodes observe:
//!
//! - Node A: O1=Committed, O2=Committed, O3=Reserved
//! - Node B: O1=Committed, O2=Reserved,  O3=Committed
//! - Node C: O1=Reserved,  O2=Committed, O3=Committed
//!
//! **Pairwise**: merging any two nodes via `LatticeState::join` produces
//! `Committed` for each obligation — no conflicts detected.
//!
//! **Globally**: No single node has observed all three as Committed. The
//! "committed everywhere" view is a *phantom*: it exists in the pairwise merge
//! but not in any actual node's observation. If the saga requires a coordinator
//! to witness all-committed before finalizing, this state is inconsistent.
//!
//! # Sheaf Interpretation
//!
//! - **Open cover**: Each node's observation is a "local section" over its view.
//! - **Presheaf condition**: Local sections must agree on overlaps (shared obligations).
//! - **Global section**: A globally consistent state that restricts to each
//!   local observation — exists iff local sections are compatible.
//! - **H¹ ≠ 0**: When local sections cannot be glued into a global section,
//!   there is a topological obstruction (the "split-brain" signal).
//!
//! # What This Module Detects
//!
//! The [`SagaConsistencyChecker`] takes a set of `NodeSnapshot`s (each node's
//! local view of saga obligation states) and a set of `SagaConstraint`s
//! (atomicity requirements like "all-or-nothing") and reports:
//!
//! 1. **Pairwise conflicts**: obligations where two nodes directly disagree.
//! 2. **Phantom commits**: obligations that appear committed in the merge but
//!    were never observed as committed by any single node.
//! 3. **Constraint violations**: saga constraints (e.g., all-or-nothing) that
//!    hold in the pairwise merge but are violated by the actual observations.

use crate::remote::NodeId;
use crate::types::ObligationId;
use std::collections::{BTreeMap, BTreeSet};

use super::lattice::LatticeState;

/// A snapshot of one node's local view of obligation states.
#[derive(Clone, Debug)]
pub struct NodeSnapshot {
    /// The observing node.
    pub node: NodeId,
    /// The node's view of each obligation.
    pub states: BTreeMap<ObligationId, LatticeState>,
}

impl NodeSnapshot {
    /// Creates a new snapshot for a node.
    #[must_use]
    pub fn new(node: NodeId) -> Self {
        Self {
            node,
            states: BTreeMap::new(),
        }
    }

    /// Records an obligation state observation.
    pub fn observe(&mut self, obligation: ObligationId, state: LatticeState) {
        self.states.insert(obligation, state);
    }
}

/// A constraint on a set of obligations (e.g., saga atomicity).
#[derive(Clone, Debug)]
pub enum SagaConstraint {
    /// All obligations in the set must reach the same terminal state.
    /// Either all committed or all aborted — never a mix.
    AllOrNothing {
        /// Human-readable name for this saga.
        name: String,
        /// The obligations that must agree.
        obligations: BTreeSet<ObligationId>,
    },
}

/// Result of a consistency check.
#[derive(Clone, Debug)]
pub struct ConsistencyReport {
    /// Obligations where two nodes directly disagree (join = Conflict).
    pub pairwise_conflicts: Vec<PairwiseConflict>,
    /// Obligations that appear in a terminal state in the pairwise merge
    /// but were never observed in that state by any single node.
    pub phantom_states: Vec<PhantomState>,
    /// Saga constraints violated by the actual observations, even though
    /// the pairwise merge might look consistent.
    pub constraint_violations: Vec<ConstraintViolation>,
}

impl ConsistencyReport {
    /// Returns true if any inconsistency was detected.
    #[must_use]
    pub fn has_issues(&self) -> bool {
        !self.pairwise_conflicts.is_empty()
            || !self.phantom_states.is_empty()
            || !self.constraint_violations.is_empty()
    }

    /// Returns true if sheaf-level issues exist (beyond what pairwise checks find).
    #[must_use]
    pub fn has_sheaf_issues(&self) -> bool {
        !self.phantom_states.is_empty() || !self.constraint_violations.is_empty()
    }
}

/// A pairwise conflict between two nodes on a single obligation.
#[derive(Clone, Debug)]
pub struct PairwiseConflict {
    /// The obligation in conflict.
    pub obligation: ObligationId,
    /// First node and its observed state.
    pub node_a: NodeId,
    /// State observed by node A.
    pub state_a: LatticeState,
    /// Second node and its observed state.
    pub node_b: NodeId,
    /// State observed by node B.
    pub state_b: LatticeState,
}

/// An obligation whose merged state was never actually observed by any node.
#[derive(Clone, Debug)]
pub struct PhantomState {
    /// The obligation.
    pub obligation: ObligationId,
    /// The "phantom" state produced by merging.
    pub merged_state: LatticeState,
    /// What each node actually observed.
    pub node_observations: BTreeMap<NodeId, LatticeState>,
}

/// A saga constraint that is violated by the actual observations.
#[derive(Clone, Debug)]
pub struct ConstraintViolation {
    /// The constraint that was violated.
    pub constraint_name: String,
    /// Per-obligation detail: the merged state and per-node observations.
    pub obligation_states: BTreeMap<ObligationId, ObligationDetail>,
    /// Explanation of the violation.
    pub explanation: String,
}

/// Detail for one obligation within a constraint violation.
#[derive(Clone, Debug)]
pub struct ObligationDetail {
    /// The pairwise-merged state.
    pub merged: LatticeState,
    /// What each node observed.
    pub per_node: BTreeMap<NodeId, LatticeState>,
}

/// Checks consistency of distributed saga observations.
pub struct SagaConsistencyChecker {
    snapshots: Vec<NodeSnapshot>,
    constraints: Vec<SagaConstraint>,
}

impl SagaConsistencyChecker {
    /// Creates a new checker with the given node snapshots and constraints.
    #[must_use]
    pub fn new(snapshots: Vec<NodeSnapshot>, constraints: Vec<SagaConstraint>) -> Self {
        Self {
            snapshots,
            constraints,
        }
    }

    /// Runs the full consistency check.
    #[must_use]
    pub fn check(&self) -> ConsistencyReport {
        let pairwise_conflicts = self.find_pairwise_conflicts();
        let phantom_states = self.find_phantom_states();
        let constraint_violations = self.find_constraint_violations();

        ConsistencyReport {
            pairwise_conflicts,
            phantom_states,
            constraint_violations,
        }
    }

    /// Finds obligations where pairwise merge produces a Conflict.
    fn find_pairwise_conflicts(&self) -> Vec<PairwiseConflict> {
        let mut conflicts = Vec::new();
        let all_obligations = self.all_obligations();

        for &obligation in &all_obligations {
            let observations: Vec<(NodeId, LatticeState)> = self
                .snapshots
                .iter()
                .filter_map(|snap| {
                    snap.states
                        .get(&obligation)
                        .map(|&s| (snap.node.clone(), s))
                })
                .collect();

            for i in 0..observations.len() {
                for j in (i + 1)..observations.len() {
                    let (ref na, sa) = observations[i];
                    let (ref nb, sb) = observations[j];
                    if sa.join(sb).is_conflict() {
                        conflicts.push(PairwiseConflict {
                            obligation,
                            node_a: na.clone(),
                            state_a: sa,
                            node_b: nb.clone(),
                            state_b: sb,
                        });
                    }
                }
            }
        }

        conflicts
    }

    /// Finds obligations where the merged state was never observed by any node.
    ///
    /// # Structural note — single-obligation phantoms are unreachable
    ///
    /// For a **single** obligation this detection can never fire, and that is a
    /// property of the [`LatticeState`] join table rather than a coding
    /// accident. `merged` is `LatticeState::Unknown` folded over each node's
    /// observation via [`LatticeState::join`]. The only way `join` yields a
    /// terminal, non-conflict state (`Committed` or `Aborted`) is for one of its
    /// inputs — i.e. one node's own observation — to already be that terminal
    /// state: `Unknown`/`Reserved` joins never manufacture a terminal
    /// (`Unknown ⊔ x = x`, `Reserved ⊔ Reserved = Reserved`), and mixing the two
    /// terminals yields `Conflict`, which is excluded here. Hence whenever
    /// `merged.is_terminal() && !merged.is_conflict()` holds, some node observed
    /// exactly `merged`, so `any_node_saw_merged` is always `true` and the push
    /// below is dead.
    ///
    /// A **genuine** phantom — a terminal "global section" that emerges only
    /// from gluing and that no single node witnessed — is inherently a
    /// *multi-obligation* phenomenon (e.g. an all-or-nothing saga where each
    /// node saw a different subset committed, so the pairwise merge is
    /// "all committed" yet no node witnessed the whole set). That case is
    /// detected by [`Self::check_all_or_nothing`], not here.
    ///
    /// The `debug_assert!` encodes the invariant so that any future change to
    /// the lattice which *would* make a single-obligation phantom reachable
    /// trips loudly in debug builds. Future work: if per-obligation phantoms
    /// ever become meaningful (e.g. a lattice that can synthesize a terminal
    /// from non-terminal inputs), redesign this to compare the merged terminal
    /// against node observations across an obligation *cover* rather than a
    /// single obligation.
    fn find_phantom_states(&self) -> Vec<PhantomState> {
        let mut phantoms = Vec::new();
        let all_obligations = self.all_obligations();

        for &obligation in &all_obligations {
            let mut observations = BTreeMap::new();
            let mut merged = LatticeState::Unknown;

            for snap in &self.snapshots {
                if let Some(&state) = snap.states.get(&obligation) {
                    observations.insert(snap.node.clone(), state);
                    merged = merged.join(state);
                }
            }

            // A phantom would exist when the merged state is terminal but no
            // node actually observed that terminal state. See the doc comment:
            // for a single obligation this is unreachable under the current
            // join table, and the assertion below guards that invariant.
            if merged.is_terminal() && !merged.is_conflict() {
                let any_node_saw_merged = observations.values().any(|&s| s == merged);
                debug_assert!(
                    any_node_saw_merged,
                    "single-obligation terminal merge {merged:?} witnessed by no node: \
                     impossible under the current LatticeState join table (see fn docs); \
                     a lattice change may have made per-obligation phantoms reachable"
                );
                if !any_node_saw_merged {
                    phantoms.push(PhantomState {
                        obligation,
                        merged_state: merged,
                        node_observations: observations,
                    });
                }
            }
        }

        phantoms
    }

    /// Finds saga constraints violated by the actual observations.
    fn find_constraint_violations(&self) -> Vec<ConstraintViolation> {
        let mut violations = Vec::new();

        for constraint in &self.constraints {
            match constraint {
                SagaConstraint::AllOrNothing { name, obligations } => {
                    if let Some(violation) = self.check_all_or_nothing(name, obligations) {
                        violations.push(violation);
                    }
                }
            }
        }

        violations
    }

    /// Checks an all-or-nothing constraint.
    ///
    /// The constraint is violated if the merged states show a mix of
    /// Committed and non-Committed (or Aborted and non-Aborted) across
    /// the obligation set, OR if no single node has observed the full
    /// commitment.
    fn check_all_or_nothing(
        &self,
        name: &str,
        obligations: &BTreeSet<ObligationId>,
    ) -> Option<ConstraintViolation> {
        let mut obligation_states: BTreeMap<ObligationId, ObligationDetail> = BTreeMap::new();

        for &obligation in obligations {
            let mut per_node = BTreeMap::new();
            let mut merged = LatticeState::Unknown;

            for snap in &self.snapshots {
                if let Some(&state) = snap.states.get(&obligation) {
                    per_node.insert(snap.node.clone(), state);
                    merged = merged.join(state);
                }
            }

            obligation_states.insert(obligation, ObligationDetail { merged, per_node });
        }

        // Check 1: Are all merged states the same terminal state?
        let mut terminal_states: Vec<LatticeState> = obligation_states
            .values()
            .map(|d| d.merged)
            .filter(|s| s.is_terminal())
            .collect();
        terminal_states.dedup();

        if terminal_states.len() > 1 {
            return Some(ConstraintViolation {
                constraint_name: name.to_string(),
                obligation_states,
                explanation: format!(
                    "Merged states disagree: {terminal_states:?}. \
                     All-or-nothing requires uniform terminal state."
                ),
            });
        }

        // Check 2: Even if merged states agree, does any single node
        // witness all obligations in the terminal state?
        // This is the sheaf check: a global section must exist.
        if let Some(&terminal) = terminal_states.first() {
            let any_node_witnesses_all = self.snapshots.iter().any(|snap| {
                obligations.iter().all(|oid| {
                    snap.states
                        .get(oid)
                        .copied()
                        .unwrap_or(LatticeState::Unknown)
                        == terminal
                })
            });

            if !any_node_witnesses_all {
                return Some(ConstraintViolation {
                    constraint_name: name.to_string(),
                    obligation_states,
                    explanation: format!(
                        "No single node observed all obligations as {terminal}. \
                         The global '{terminal}' state is a phantom — \
                         it exists in the pairwise merge but not in any node's view. \
                         (H¹ ≠ 0: local sections do not glue into a global section.)"
                    ),
                });
            }
        }

        None
    }

    /// Collects all obligation IDs mentioned in any snapshot.
    fn all_obligations(&self) -> BTreeSet<ObligationId> {
        self.snapshots
            .iter()
            .flat_map(|s| s.states.keys().copied())
            .collect()
    }
}

#[cfg(test)]
#[path = "sheaf_inline_tests.rs"]
mod tests;
