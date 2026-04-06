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
                expected: self.plan_hash.value(),
                actual: actual_hash.value(),
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
    HashMismatch {
        /// Expected hash.
        expected: u64,
        /// Actual hash.
        actual: u64,
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
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::time::Duration;

    fn init_test() {
        init_test_logging();
    }

    #[test]
    fn extract_single_leaf() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(a)
            .expect("leaf extraction should succeed");

        assert_eq!(dag.nodes.len(), 1);
        assert!(cert.verify(&dag).is_ok());
        assert_eq!(cert.cost.allocations, 1);
        assert_eq!(cert.cost.critical_path, 1);
    }

    #[test]
    fn extract_join_of_leaves() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");
        let b = eg.add_leaf("b");
        let join = eg.add_join(vec![a, b]);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(join)
            .expect("join extraction should succeed");

        assert_eq!(dag.nodes.len(), 3);
        assert!(cert.verify(&dag).is_ok());
        // 2 leaves + 1 join = 3 allocations
        assert_eq!(cert.cost.allocations, 3);
        // Critical path is max of children = 1
        assert_eq!(cert.cost.critical_path, 1);
    }

    #[test]
    fn extract_race_adds_cancel_checkpoint() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");
        let b = eg.add_leaf("b");
        let race = eg.add_race(vec![a, b]);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(race)
            .expect("race extraction should succeed");

        assert_eq!(dag.nodes.len(), 3);
        assert!(cert.verify(&dag).is_ok());
        assert_eq!(cert.cost.cancel_checkpoints, 1);
    }

    #[test]
    fn extract_obligation_pressure() {
        init_test();
        let mut eg = EGraph::new();
        let obl = eg.add_leaf("obl:permit");
        let plain = eg.add_leaf("compute");
        let join = eg.add_join(vec![obl, plain]);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(join)
            .expect("obligation extraction should succeed");

        assert_eq!(dag.nodes.len(), 3);
        assert!(cert.verify(&dag).is_ok());
        assert_eq!(cert.cost.obligation_pressure, 1);
    }

    #[test]
    fn extract_nested_critical_path() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");
        let t1 = eg.add_timeout(a, Duration::from_secs(5));
        let t2 = eg.add_timeout(t1, Duration::from_secs(10));

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(t2)
            .expect("timeout extraction should succeed");

        assert_eq!(dag.nodes.len(), 3);
        assert!(cert.verify(&dag).is_ok());
        // Leaf (1) + timeout (1) + timeout (1) = 3
        assert_eq!(cert.cost.critical_path, 3);
    }

    #[test]
    fn extraction_is_deterministic() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");
        let b = eg.add_leaf("b");
        let c = eg.add_leaf("c");
        let j1 = eg.add_join(vec![a, b]);
        let r = eg.add_race(vec![j1, c]);

        let mut extractor1 = Extractor::new(&mut eg);
        let (dag1, cert1) = extractor1
            .extract(r)
            .expect("first extraction should succeed");

        // Extract again (new extractor, same egraph)
        let mut extractor2 = Extractor::new(&mut eg);
        let (dag2, cert2) = extractor2
            .extract(r)
            .expect("second extraction should succeed");

        assert_eq!(cert1.plan_hash, cert2.plan_hash);
        assert_eq!(cert1.cost, cert2.cost);
        assert_eq!(dag1.nodes.len(), dag2.nodes.len());
    }

    #[test]
    fn extract_after_merge_picks_best() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");
        let b = eg.add_leaf("b");
        let c = eg.add_leaf("c");

        // Two different representations of the same thing
        let j1 = eg.add_join(vec![a, b, c]);
        let inner_join = eg.add_join(vec![a, b]);
        let j2 = eg.add_join(vec![inner_join, c]);

        // Merge them into the same class
        eg.merge(j1, j2);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(j1)
            .expect("merged extraction should succeed");

        // Should pick the flatter representation (lower cost)
        assert!(cert.verify(&dag).is_ok());
        // The flat join is cheaper (fewer allocations)
        assert_eq!(cert.cost.allocations, 4); // 3 leaves + 1 join
    }

    #[test]
    fn extract_total_tie_prefers_better_full_cost_vector() {
        init_test();
        let mut eg = EGraph::new();

        let seed = eg.add_leaf("seed");
        let worse = eg.add_race(vec![seed]);

        let better_children: Vec<_> = (0..101)
            .map(|idx| eg.add_leaf(format!("join-{idx}")))
            .collect();
        let better = eg.add_join(better_children);

        eg.merge(worse, better);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(worse)
            .expect("tie-broken extraction should succeed");

        assert!(cert.verify(&dag).is_ok());
        assert_eq!(cert.cost.total(), 1102);
        assert_eq!(cert.cost.cancel_checkpoints, 0);
        assert_eq!(cert.cost.critical_path, 1);
        assert_eq!(cert.cost.allocations, 102);

        let root = dag.root().expect("root");
        assert!(matches!(
            dag.node(root),
            Some(PlanNode::Join { children }) if children.len() == 101
        ));
    }

    #[test]
    fn extract_merge_with_cyclic_enode_prefers_acyclic_candidate() {
        init_test();
        let mut eg = EGraph::new();
        let leaf = eg.add_leaf("a");
        let recursive_join = eg.add_join(vec![leaf]);

        // Rebuild canonicalizes the join into Join([leaf]), so this merge creates
        // a class containing both an acyclic leaf and a self-referential join.
        eg.merge(leaf, recursive_join);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(leaf)
            .expect("cyclic merge extraction should succeed");

        assert!(cert.verify(&dag).is_ok());
        assert_eq!(dag.nodes.len(), 1);
        assert_eq!(cert.cost, PlanCost::LEAF);

        let root = dag.root().expect("root");
        assert!(matches!(
            dag.node(root),
            Some(PlanNode::Leaf { label }) if label == "a"
        ));
    }

    #[test]
    fn extract_merge_with_empty_join_prefers_valid_candidate() {
        init_test();
        let mut eg = EGraph::new();
        let leaf = eg.add_leaf("a");
        let empty_join = eg.add_join(Vec::new());

        eg.merge(leaf, empty_join);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor
            .extract(leaf)
            .expect("empty-join merge extraction should succeed");

        assert!(cert.verify(&dag).is_ok());
        assert_eq!(dag.nodes.len(), 1);
        assert_eq!(cert.cost, PlanCost::LEAF);

        let root = dag.root().expect("root");
        assert!(matches!(
            dag.node(root),
            Some(PlanNode::Leaf { label }) if label == "a"
        ));
    }

    #[test]
    fn cost_total_ordering() {
        init_test();
        let low = PlanCost {
            allocations: 10,
            cancel_checkpoints: 0,
            obligation_pressure: 0,
            critical_path: 1,
        };
        let high = PlanCost {
            allocations: 1,
            cancel_checkpoints: 0,
            obligation_pressure: 0,
            critical_path: 10,
        };

        // Critical path dominates
        assert!(low.total() < high.total());
    }

    #[test]
    fn extract_root_with_only_empty_join_returns_error() {
        init_test();
        let mut eg = EGraph::new();
        let empty_join = eg.add_join(Vec::new());

        let result = Extractor::new(&mut eg).extract(empty_join);
        assert!(matches!(
            result,
            Err(ExtractionError::NoExtractableCandidate { class }) if class == empty_join
        ));
    }

    #[test]
    fn cost_display() {
        init_test();
        let cost = PlanCost {
            allocations: 5,
            cancel_checkpoints: 2,
            obligation_pressure: 1,
            critical_path: 3,
        };
        let display = format!("{cost}");
        assert!(display.contains("alloc=5"));
        assert!(display.contains("cancel=2"));
        assert!(display.contains("obl=1"));
        assert!(display.contains("depth=3"));
    }

    #[test]
    fn cost_ordering_breaks_weighted_total_ties_by_full_vector() {
        init_test();
        let shallower_without_cancel = PlanCost {
            allocations: 102,
            cancel_checkpoints: 0,
            obligation_pressure: 0,
            critical_path: 1,
        };
        let racier_with_fewer_allocations = PlanCost {
            allocations: 2,
            cancel_checkpoints: 1,
            obligation_pressure: 0,
            critical_path: 1,
        };

        assert_eq!(
            shallower_without_cancel.total(),
            racier_with_fewer_allocations.total()
        );
        assert_ne!(shallower_without_cancel, racier_with_fewer_allocations);
        assert_ne!(
            shallower_without_cancel.cmp(&racier_with_fewer_allocations),
            std::cmp::Ordering::Equal
        );
        assert!(shallower_without_cancel < racier_with_fewer_allocations);
    }

    #[test]
    fn certificate_version_mismatch() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");

        let mut extractor = Extractor::new(&mut eg);
        let (dag, mut cert) = extractor
            .extract(a)
            .expect("certificate source extraction should succeed");

        cert.version = CertificateVersion::from_number(99);
        let result = cert.verify(&dag);
        assert!(matches!(
            result,
            Err(ExtractionVerifyError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn certificate_hash_mismatch() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");

        let mut extractor = Extractor::new(&mut eg);
        let (mut dag, cert) = extractor
            .extract(a)
            .expect("hash-mismatch source extraction should succeed");

        // Mutate the DAG
        dag.leaf("extra");

        let result = cert.verify(&dag);
        assert!(matches!(
            result,
            Err(ExtractionVerifyError::HashMismatch { .. })
        ));
    }

    #[test]
    fn certificate_cost_mismatch_is_rejected() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");
        let b = eg.add_leaf("b");
        let join = eg.add_join(vec![a, b]);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, mut cert) = extractor
            .extract(join)
            .expect("cost-mismatch source extraction should succeed");

        cert.cost.allocations = cert.cost.allocations.saturating_add(1);

        let result = cert.verify(&dag);
        assert!(matches!(
            result,
            Err(ExtractionVerifyError::CostMismatch { .. })
        ));
    }

    #[test]
    fn certificate_rejects_structurally_invalid_dag() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");

        let mut extractor = Extractor::new(&mut eg);
        let (mut dag, mut cert) = extractor
            .extract(a)
            .expect("invalid-dag source extraction should succeed");

        let root = dag.root().expect("root");
        dag.nodes[root.index()] = PlanNode::Join {
            children: Vec::new(),
        };
        cert.plan_hash = PlanHash::of(&dag);
        cert.node_count = dag.nodes.len();
        cert.cost = dag_plan_cost(&dag);

        let result = cert.verify(&dag);
        assert!(matches!(
            result,
            Err(ExtractionVerifyError::InvalidPlan(
                crate::plan::PlanError::EmptyChildren { parent }
            ))
                if parent == root
        ));
    }

    // Pure data-type tests (wave 37 – CyanBarn)

    #[test]
    fn plan_cost_debug_copy_default() {
        let cost = PlanCost::default();
        assert_eq!(cost.allocations, 0);
        assert_eq!(cost.cancel_checkpoints, 0);
        assert_eq!(cost.obligation_pressure, 0);
        assert_eq!(cost.critical_path, 0);

        let dbg = format!("{cost:?}");
        assert!(dbg.contains("PlanCost"));

        // Copy
        let cost2 = cost;
        assert_eq!(cost, cost2);

        // Clone
        let cost3 = cost;
        assert_eq!(cost, cost3);
    }

    #[test]
    fn plan_cost_constants() {
        assert_eq!(PlanCost::ZERO.total(), 0);
        assert_eq!(PlanCost::ZERO.allocations, 0);

        assert_eq!(PlanCost::LEAF.allocations, 1);
        assert_eq!(PlanCost::LEAF.critical_path, 1);
        assert_eq!(PlanCost::LEAF.cancel_checkpoints, 0);

        // UNKNOWN is sentinel
        assert_eq!(PlanCost::UNKNOWN.allocations, u64::MAX);
        assert_eq!(PlanCost::UNKNOWN.critical_path, u64::MAX);
    }

    #[test]
    fn plan_cost_add_sequential() {
        let a = PlanCost {
            allocations: 2,
            cancel_checkpoints: 1,
            obligation_pressure: 0,
            critical_path: 3,
        };
        let b = PlanCost {
            allocations: 3,
            cancel_checkpoints: 0,
            obligation_pressure: 1,
            critical_path: 5,
        };

        // add: critical_path = max
        let sum = a.add(b);
        assert_eq!(sum.allocations, 5);
        assert_eq!(sum.cancel_checkpoints, 1);
        assert_eq!(sum.obligation_pressure, 1);
        assert_eq!(sum.critical_path, 5); // max(3,5)

        // sequential: critical_path = sum
        let seq = a.sequential(b);
        assert_eq!(seq.allocations, 5);
        assert_eq!(seq.critical_path, 8); // 3+5
    }

    #[test]
    fn extraction_certificate_debug_clone() {
        let mut eg = EGraph::new();
        let a = eg.add_leaf("x");
        let mut ext = Extractor::new(&mut eg);
        let (_dag, cert) = ext
            .extract(a)
            .expect("certificate extraction should succeed");

        let dbg = format!("{cert:?}");
        assert!(dbg.contains("ExtractionCertificate"));

        let cloned = cert.clone();
        assert_eq!(cloned.node_count, cert.node_count);
        assert_eq!(cloned.cost, cert.cost);
    }

    #[test]
    fn extraction_verify_error_debug_clone_eq() {
        let e1 = ExtractionVerifyError::VersionMismatch {
            expected: 1,
            found: 2,
        };
        let e2 = ExtractionVerifyError::HashMismatch {
            expected: 10,
            actual: 20,
        };
        let e3 = ExtractionVerifyError::NodeCountMismatch {
            expected: 5,
            actual: 3,
        };
        let e4 = ExtractionVerifyError::CostMismatch {
            expected: PlanCost::ZERO,
            actual: PlanCost::LEAF,
        };
        let e5 = ExtractionVerifyError::InvalidPlan(crate::plan::PlanError::Cycle {
            at: PlanId::new(0),
        });

        let dbg1 = format!("{e1:?}");
        assert!(dbg1.contains("VersionMismatch"));
        let dbg2 = format!("{e2:?}");
        assert!(dbg2.contains("HashMismatch"));
        let dbg3 = format!("{e3:?}");
        assert!(dbg3.contains("NodeCountMismatch"));
        let dbg4 = format!("{e4:?}");
        assert!(dbg4.contains("CostMismatch"));
        let dbg5 = format!("{e5:?}");
        assert!(dbg5.contains("InvalidPlan"));

        // Clone + PartialEq
        let e1c = e1.clone();
        assert_eq!(e1, e1c);
        assert_ne!(e1, e2);
    }
}
