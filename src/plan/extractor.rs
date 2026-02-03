//! Deterministic best-plan extraction with cost model.
//!
//! Chooses an optimized representative from an e-graph using a deterministic
//! cost model. The extraction algorithm is greedy and produces stable output
//! given the same e-graph structure.

use super::certificate::{CertificateVersion, PlanHash, RewriteCertificate};
use super::rewrite::RewritePolicy;
use super::{EClassId, EGraph, ENode, PlanDag, PlanId, PlanNode};
use std::collections::BTreeMap;
use std::time::Duration;

// ===========================================================================
// Cost model
// ===========================================================================

/// Cost components for a plan node.
///
/// All costs are additive and deterministic. Lower is better.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
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

    /// Cost of a leaf node.
    pub const LEAF: Self = Self {
        allocations: 1, // One task allocation
        cancel_checkpoints: 0,
        obligation_pressure: 0,
        critical_path: 1,
    };

    /// Add costs together (for joins and sequential composition).
    #[must_use]
    pub fn add(self, other: Self) -> Self {
        Self {
            allocations: self.allocations.saturating_add(other.allocations),
            cancel_checkpoints: self.cancel_checkpoints.saturating_add(other.cancel_checkpoints),
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
            cancel_checkpoints: self.cancel_checkpoints.saturating_add(other.cancel_checkpoints),
            obligation_pressure: self
                .obligation_pressure
                .saturating_add(other.obligation_pressure),
            critical_path: self.critical_path.saturating_add(other.critical_path),
        }
    }

    /// Total scalar cost for comparison (weighted sum).
    #[must_use]
    pub fn total(&self) -> u64 {
        // Weight critical path heavily, then cancel checkpoints, then allocations
        self.critical_path
            .saturating_mul(1000)
            .saturating_add(self.cancel_checkpoints.saturating_mul(100))
            .saturating_add(self.obligation_pressure.saturating_mul(10))
            .saturating_add(self.allocations)
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
}

impl<'a> Extractor<'a> {
    /// Creates a new extractor for the given e-graph.
    pub fn new(egraph: &'a mut EGraph) -> Self {
        Self {
            egraph,
            costs: BTreeMap::new(),
            best_node: BTreeMap::new(),
        }
    }

    /// Extracts the best plan for a class and returns it as a `PlanDag`.
    ///
    /// The extraction is deterministic: given the same e-graph structure,
    /// it always produces the same `PlanDag`.
    pub fn extract(&mut self, root: EClassId) -> (PlanDag, ExtractionCertificate) {
        // Compute costs for all reachable classes
        self.compute_cost(root);

        // Build the plan DAG from the best nodes
        let mut dag = PlanDag::new();
        let mut id_map: BTreeMap<EClassId, PlanId> = BTreeMap::new();

        let dag_root = self.build_plan_node(root, &mut dag, &mut id_map);
        dag.set_root(dag_root);

        let cost = self.costs.get(&self.egraph.canonical_id(root)).copied().unwrap_or(PlanCost::ZERO);

        let cert = ExtractionCertificate {
            version: CertificateVersion::CURRENT,
            root_class: root,
            cost,
            plan_hash: PlanHash::of(&dag),
            node_count: dag.node_count(),
        };

        (dag, cert)
    }

    /// Computes the best cost for a class (memoized, bottom-up).
    fn compute_cost(&mut self, id: EClassId) -> PlanCost {
        let canonical = self.egraph.canonical_id(id);

        if let Some(&cost) = self.costs.get(&canonical) {
            return cost;
        }

        // Get all nodes in this class
        let Some(class) = self.egraph.class(canonical) else {
            return PlanCost::ZERO;
        };

        let nodes: Vec<ENode> = class.nodes.clone();

        if nodes.is_empty() {
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
            if cost.total() < best_cost.total() || (cost.total() == best_cost.total() && best.is_none()) {
                best_cost = cost;
                best = Some(node);
            }
        }

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
    ) -> PlanId {
        let canonical = self.egraph.canonical_id(id);

        if let Some(&plan_id) = id_map.get(&canonical) {
            return plan_id;
        }

        let node = self
            .best_node
            .get(&canonical)
            .cloned()
            .expect("best_node computed for all reachable classes");

        let plan_id = match &node {
            ENode::Leaf { label } => dag.leaf(label.as_str()),
            ENode::Join { children } => {
                let child_ids: Vec<PlanId> = children
                    .iter()
                    .map(|c| self.build_plan_node(*c, dag, id_map))
                    .collect();
                dag.join(child_ids)
            }
            ENode::Race { children } => {
                let child_ids: Vec<PlanId> = children
                    .iter()
                    .map(|c| self.build_plan_node(*c, dag, id_map))
                    .collect();
                dag.race(child_ids)
            }
            ENode::Timeout { child, duration } => {
                let child_id = self.build_plan_node(*child, dag, id_map);
                dag.timeout(child_id, *duration)
            }
        };

        id_map.insert(canonical, plan_id);
        plan_id
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

        let actual_hash = PlanHash::of(dag);
        if self.plan_hash != actual_hash {
            return Err(ExtractionVerifyError::HashMismatch {
                expected: self.plan_hash.value(),
                actual: actual_hash.value(),
            });
        }

        if self.node_count != dag.node_count() {
            return Err(ExtractionVerifyError::NodeCountMismatch {
                expected: self.node_count,
                actual: dag.node_count(),
            });
        }

        Ok(())
    }
}

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
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

    fn init_test() {
        init_test_logging();
    }

    #[test]
    fn extract_single_leaf() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor.extract(a);

        assert_eq!(dag.node_count(), 1);
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
        let (dag, cert) = extractor.extract(join);

        assert_eq!(dag.node_count(), 3);
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
        let (dag, cert) = extractor.extract(race);

        assert_eq!(dag.node_count(), 3);
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
        let (dag, cert) = extractor.extract(join);

        assert_eq!(dag.node_count(), 3);
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
        let (dag, cert) = extractor.extract(t2);

        assert_eq!(dag.node_count(), 3);
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
        let (dag1, cert1) = extractor1.extract(r);

        // Extract again (new extractor, same egraph)
        let mut extractor2 = Extractor::new(&mut eg);
        let (dag2, cert2) = extractor2.extract(r);

        assert_eq!(cert1.plan_hash, cert2.plan_hash);
        assert_eq!(cert1.cost, cert2.cost);
        assert_eq!(dag1.node_count(), dag2.node_count());
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
        let j2 = eg.add_join(vec![eg.add_join(vec![a, b]), c]);

        // Merge them into the same class
        eg.merge(j1, j2);

        let mut extractor = Extractor::new(&mut eg);
        let (dag, cert) = extractor.extract(j1);

        // Should pick the flatter representation (lower cost)
        assert!(cert.verify(&dag).is_ok());
        // The flat join is cheaper (fewer allocations)
        assert_eq!(cert.cost.allocations, 4); // 3 leaves + 1 join
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
    fn certificate_version_mismatch() {
        init_test();
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");

        let mut extractor = Extractor::new(&mut eg);
        let (dag, mut cert) = extractor.extract(a);

        cert.version = CertificateVersion(99);
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
        let (mut dag, cert) = extractor.extract(a);

        // Mutate the DAG
        dag.leaf("extra");

        let result = cert.verify(&dag);
        assert!(matches!(
            result,
            Err(ExtractionVerifyError::HashMismatch { .. })
        ));
    }
}
