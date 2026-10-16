//! Deterministic best-plan extraction with cost model.
//!
//! Chooses an optimized representative from an e-graph using a deterministic
//! cost model. The extraction algorithm is greedy and produces stable output
//! given the same e-graph structure.

use super::certificate::{CertificateVersion, PlanHash};
use super::{EClassId, EGraph, ENode, PlanDag, PlanId, PlanNode};
use std::collections::{BTreeMap, BTreeSet};

// ===========================================================================
// Cost model
// ===========================================================================

/// Cost components for a plan node.
///
/// All costs are additive and deterministic. Lower is better.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlanCost {
    /// Estimated allocations (heap objects created).
    pub allocations: u64,
    /// Cancel checkpoints (race nodes that need loser draining).
    pub cancel_checkpoints: u64,
    /// Obligation pressure (pending obligations that must resolve).
    pub obligation_pressure: u64,
    /// Critical path length (Foata depth - longest sequential chain).
    pub critical_path: u64,
}

impl PlanCost {
    /// Zero cost.
    pub const ZERO: Self = Self {
        allocations: 0,
        cancel_checkpoints: 0,
        obligation_pressure: 0,
        critical_path: 0,
    };

    /// Sentinel cost for unknown nodes.
    pub const UNKNOWN: Self = Self {
        allocations: u64::MAX,
        cancel_checkpoints: u64::MAX,
        obligation_pressure: u64::MAX,
        critical_path: u64::MAX,
    };

    /// Cost of a leaf node.
    pub const LEAF: Self = Self {
        allocations: 1, // One task allocation
        cancel_checkpoints: 0,
        obligation_pressure: 0,
        critical_path: 1,
    };

    /// Add costs together (for parallel/join composition).
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: Self) -> Self {
        Self {
            allocations: self.allocations.saturating_add(other.allocations),
            cancel_checkpoints: self
                .cancel_checkpoints
                .saturating_add(other.cancel_checkpoints),
            obligation_pressure: self
                .obligation_pressure
                .saturating_add(other.obligation_pressure),
            critical_path: self.critical_path.max(other.critical_path),
        }
    }

    /// Sequential cost (critical path is sum, not max).
    #[must_use]
    pub fn sequential(self, other: Self) -> Self {
        Self {
            allocations: self.allocations.saturating_add(other.allocations),
            cancel_checkpoints: self
                .cancel_checkpoints
                .saturating_add(other.cancel_checkpoints),
            obligation_pressure: self
                .obligation_pressure
                .saturating_add(other.obligation_pressure),
            critical_path: self.critical_path.saturating_add(other.critical_path),
        }
    }

    /// Total scalar cost for comparison (weighted sum).
    #[must_use]
    pub const fn total(&self) -> u64 {
        // Weight critical path heavily, then cancel checkpoints, then allocations
        self.critical_path
            .saturating_mul(1000)
            .saturating_add(self.cancel_checkpoints.saturating_mul(100))
            .saturating_add(self.obligation_pressure.saturating_mul(10))
            .saturating_add(self.allocations)
    }

    #[must_use]
    fn comparison_key(&self) -> (u64, u64, u64, u64, u64) {
        // Break weighted-total ties with the full vector so `Ord` stays
        // consistent with the derived field-wise `Eq`.
        (
            self.total(),
            self.critical_path,
            self.cancel_checkpoints,
            self.obligation_pressure,
            self.allocations,
        )
    }
}

impl PartialOrd for PlanCost {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PlanCost {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.comparison_key().cmp(&other.comparison_key())
    }
}

impl std::fmt::Display for PlanCost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "alloc={} cancel={} obl={} depth={}",
            self.allocations, self.cancel_checkpoints, self.obligation_pressure, self.critical_path
        )
    }
}

// ===========================================================================
// Extractor
// ===========================================================================

/// Extracts the best plan from an e-graph class.
#[derive(Debug)]
pub struct Extractor<'a> {
    egraph: &'a mut EGraph,
    /// Best cost for each class (memoized).
    costs: BTreeMap<EClassId, PlanCost>,
    /// Best e-node for each class.
    best_node: BTreeMap<EClassId, ENode>,
    /// Classes currently being costed; revisiting one indicates a cyclic candidate.
    computing: BTreeSet<EClassId>,
}

impl<'a> Extractor<'a> {
    /// Creates a new extractor for the given e-graph.
    pub fn new(egraph: &'a mut EGraph) -> Self {
        Self {
            egraph,
            costs: BTreeMap::new(),
            best_node: BTreeMap::new(),
            computing: BTreeSet::new(),
        }
    }

    /// Extracts the best plan for a class and returns it as a `PlanDag`.
    ///
    /// The extraction is deterministic: given the same e-graph structure,
    /// it always produces the same `PlanDag`.
    pub fn extract(
        &mut self,
        root: EClassId,
    ) -> Result<(PlanDag, ExtractionCertificate), ExtractionError> {
        // Compute costs for all reachable classes
        self.compute_cost(root);

        // Build the plan DAG from the best nodes
        let mut dag = PlanDag::new();
        let mut id_map: BTreeMap<EClassId, PlanId> = BTreeMap::new();
        let canonical_root = self.egraph.canonical_id(root);
        if !self.best_node.contains_key(&canonical_root) {
            return Err(ExtractionError::NoExtractableCandidate {
                class: canonical_root,
            });
        }
        let mut building = BTreeSet::new();

        let dag_root = self.build_plan_node(root, &mut dag, &mut id_map, &mut building)?;
        dag.set_root(dag_root);

        let cost = self
            .costs
            .get(&self.egraph.canonical_id(root))
            .copied()
            .unwrap_or(PlanCost::ZERO);

        let cert = ExtractionCertificate {
            version: CertificateVersion::CURRENT,
            root_class: root,
            cost,
            plan_hash: PlanHash::of(&dag),
            node_count: dag.nodes.len(),
        };

        Ok((dag, cert))
    }

    /// Computes the best cost for a class (memoized, bottom-up).
    fn compute_cost(&mut self, id: EClassId) -> PlanCost {
        let canonical = self.egraph.canonical_id(id);

        if let Some(&cost) = self.costs.get(&canonical) {
            return cost;
        }

        // Merges can create cyclic e-classes. Treat them as non-extractable
        // candidates so a cheaper acyclic alternative in the same class can win.
        if !self.computing.insert(canonical) {
            return PlanCost::UNKNOWN;
        }

        // Get all nodes in this class (resolved from arena)
        let Some(nodes) = self.egraph.class_nodes_cloned(canonical) else {
            self.computing.remove(&canonical);
            return PlanCost::ZERO;
        };

        if nodes.is_empty() {
            self.computing.remove(&canonical);
            self.costs.insert(canonical, PlanCost::ZERO);
            return PlanCost::ZERO;
        }

        // Find the best node in this class
        let mut best_cost = PlanCost {
            allocations: u64::MAX,
            cancel_checkpoints: u64::MAX,
            obligation_pressure: u64::MAX,
            critical_path: u64::MAX,
        };
        let mut best: Option<ENode> = None;

        for node in nodes {
            let cost = self.node_cost(&node);
            if cost == PlanCost::UNKNOWN {
                continue;
            }
            if best.is_none() || cost < best_cost {
                best_cost = cost;
                best = Some(node);
            }
        }

        self.computing.remove(&canonical);
        self.costs.insert(canonical, best_cost);
        if let Some(node) = best {
            self.best_node.insert(canonical, node);
        }

        best_cost
    }

    /// Computes the cost of a single e-node.
    fn node_cost(&mut self, node: &ENode) -> PlanCost {
        match node {
            ENode::Leaf { label } => {
                let mut cost = PlanCost::LEAF;
                if label.starts_with("obl:") {
                    cost.obligation_pressure = 1;
                }
                cost
            }
            ENode::Join { children } => {
                if children.is_empty() {
                    return PlanCost::UNKNOWN;
                }
                let mut cost = PlanCost::ZERO;
                for child in children {
                    let child_cost = self.compute_cost(*child);
                    cost = cost.add(child_cost);
                }
                // Add one allocation for the join combinator
                cost.allocations = cost.allocations.saturating_add(1);
                cost
            }
            ENode::Race { children } => {
                if children.is_empty() {
                    return PlanCost::UNKNOWN;
                }
                let mut cost = PlanCost::ZERO;
                for child in children {
                    let child_cost = self.compute_cost(*child);
                    cost = cost.add(child_cost);
                }
                // Race adds a cancel checkpoint
                cost.cancel_checkpoints = cost.cancel_checkpoints.saturating_add(1);
                // Add one allocation for the race combinator
                cost.allocations = cost.allocations.saturating_add(1);
                cost
            }
            ENode::Timeout { child, duration: _ } => {
                let mut cost = self.compute_cost(*child);
                // Timeout adds one allocation and increments critical path
                cost.allocations = cost.allocations.saturating_add(1);
                cost.critical_path = cost.critical_path.saturating_add(1);
                cost
            }
        }
    }

    /// Builds a `PlanNode` from the best e-node for a class.
    fn build_plan_node(
        &mut self,
        id: EClassId,
        dag: &mut PlanDag,
        id_map: &mut BTreeMap<EClassId, PlanId>,
        building: &mut BTreeSet<EClassId>,
    ) -> Result<PlanId, ExtractionError> {
        let canonical = self.egraph.canonical_id(id);

        if let Some(&plan_id) = id_map.get(&canonical) {
            return Ok(plan_id);
        }
        if !building.insert(canonical) {
            return Err(ExtractionError::CycleSurvivedCostSelection { class: canonical });
        }

        let node = self
            .best_node
            .get(&canonical)
            .cloned()
            .ok_or(ExtractionError::NoExtractableCandidate { class: canonical })?;

        let plan_id = match &node {
            ENode::Leaf { label } => dag.leaf(label.as_str()),
            ENode::Join { children } => {
                let child_ids: Vec<PlanId> = children
                    .iter()
                    .map(|c| self.build_plan_node(*c, dag, id_map, building))
                    .collect::<Result<_, _>>()?;
                dag.join(child_ids)
            }
            ENode::Race { children } => {
                let child_ids: Vec<PlanId> = children
                    .iter()
                    .map(|c| self.build_plan_node(*c, dag, id_map, building))
                    .collect::<Result<_, _>>()?;
                dag.race(child_ids)
            }
            ENode::Timeout { child, duration } => {
                let child_id = self.build_plan_node(*child, dag, id_map, building)?;
                dag.timeout(child_id, *duration)
            }
        };

        building.remove(&canonical);
        id_map.insert(canonical, plan_id);
        Ok(plan_id)
    }
}

// ===========================================================================
// Extraction certificate
// ===========================================================================

/// Certificate for a plan extraction.
///
/// Records the root class, computed cost, and plan hash for verification.
#[derive(Debug, Clone)]
pub struct ExtractionCertificate {
    /// Schema version.
    pub version: CertificateVersion,
    /// Root class that was extracted.
    pub root_class: EClassId,
    /// Computed cost of the extracted plan.
    pub cost: PlanCost,
    /// Stable hash of the extracted plan DAG.
    pub plan_hash: PlanHash,
    /// Number of nodes in the extracted plan.
    pub node_count: usize,
}

impl ExtractionCertificate {
    /// Verifies that the certificate matches the given plan DAG.
    pub fn verify(&self, dag: &PlanDag) -> Result<(), ExtractionVerifyError> {
        if self.version != CertificateVersion::CURRENT {
            return Err(ExtractionVerifyError::VersionMismatch {
                expected: CertificateVersion::CURRENT.number(),
                found: self.version.number(),
            });
        }

        if let Err(err) = dag.validate() {
            return Err(ExtractionVerifyError::InvalidPlan(err));
        }

        let actual_hash = PlanHash::of(dag);
        if self.plan_hash != actual_hash {
            return Err(ExtractionVerifyError::HashMismatch {
                expected: self.plan_hash.to_hex(),
                actual: actual_hash.to_hex(),
            });
        }

        if self.node_count != dag.nodes.len() {
            return Err(ExtractionVerifyError::NodeCountMismatch {
                expected: self.node_count,
                actual: dag.nodes.len(),
            });
        }

        let actual_cost = dag_plan_cost(dag);
        if self.cost != actual_cost {
            return Err(ExtractionVerifyError::CostMismatch {
                expected: self.cost,
                actual: actual_cost,
            });
        }

        Ok(())
    }
}

fn dag_plan_cost(dag: &PlanDag) -> PlanCost {
    fn visit(dag: &PlanDag, id: PlanId, memo: &mut BTreeMap<PlanId, PlanCost>) -> PlanCost {
        if let Some(&cost) = memo.get(&id) {
            return cost;
        }

        let cost = match dag.node(id) {
            Some(PlanNode::Leaf { label }) => {
                let mut cost = PlanCost::LEAF;
                if label.starts_with("obl:") {
                    cost.obligation_pressure = 1;
                }
                cost
            }
            Some(PlanNode::Join { children }) => {
                let mut cost = PlanCost::ZERO;
                for child in children {
                    cost = cost.add(visit(dag, *child, memo));
                }
                cost.allocations = cost.allocations.saturating_add(1);
                cost
            }
            Some(PlanNode::Race { children }) => {
                let mut cost = PlanCost::ZERO;
                for child in children {
                    cost = cost.add(visit(dag, *child, memo));
                }
                cost.cancel_checkpoints = cost.cancel_checkpoints.saturating_add(1);
                cost.allocations = cost.allocations.saturating_add(1);
                cost
            }
            Some(PlanNode::Timeout { child, .. }) => {
                let mut cost = visit(dag, *child, memo);
                cost.allocations = cost.allocations.saturating_add(1);
                cost.critical_path = cost.critical_path.saturating_add(1);
                cost
            }
            None => PlanCost::ZERO,
        };

        memo.insert(id, cost);
        cost
    }

    let Some(root) = dag.root() else {
        return PlanCost::ZERO;
    };

    let mut memo = BTreeMap::new();
    visit(dag, root, &mut memo)
}

/// Error from plan extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractionError {
    /// The target e-class had no valid acyclic extraction candidate.
    NoExtractableCandidate {
        /// Canonical class that could not be extracted.
        class: EClassId,
    },
    /// An internally selected candidate re-entered a class during DAG building.
    CycleSurvivedCostSelection {
        /// Canonical class where the cycle was detected.
        class: EClassId,
    },
}

impl std::fmt::Display for ExtractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoExtractableCandidate { class } => {
                write!(f, "no extractable candidate for e-class {}", class.index())
            }
            Self::CycleSurvivedCostSelection { class } => write!(
                f,
                "cyclic extraction candidate survived cost selection for e-class {}",
                class.index()
            ),
        }
    }
}

impl std::error::Error for ExtractionError {}

/// Error from extraction verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractionVerifyError {
    /// Schema version mismatch.
    VersionMismatch {
        /// Expected version.
        expected: u32,
        /// Found version.
        found: u32,
    },
    /// Plan hash mismatch.
    ///
    /// br-asupersync-eyb1s5: hashes are the full SHA-256 digest, encoded
    /// as a 64-character lowercase hex string.
    HashMismatch {
        /// Expected hash (hex).
        expected: String,
        /// Actual hash (hex).
        actual: String,
    },
    /// Node count mismatch.
    NodeCountMismatch {
        /// Expected count.
        expected: usize,
        /// Actual count.
        actual: usize,
    },
    /// Extracted cost does not match the plan DAG.
    CostMismatch {
        /// Expected cost recorded in the certificate.
        expected: PlanCost,
        /// Actual cost recomputed from the DAG.
        actual: PlanCost,
    },
    /// The extracted plan DAG is structurally invalid.
    InvalidPlan(crate::plan::PlanError),
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[path = "extractor_inline_tests.rs"]
mod tests;
