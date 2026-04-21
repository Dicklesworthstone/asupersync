#![allow(clippy::all)]
//! Metamorphic tests for plan analysis DAG equivalence invariants.
//!
//! Tests the 5 core metamorphic relations for plan DAG analysis:
//! 1. DAG rewrites preserve semantic equivalence - transformations maintain behavior
//! 2. Dead-code elimination preserves required outputs - unused nodes can be removed safely
//! 3. Combinator fusion identities hold - algebraic laws for join/race/timeout are sound
//! 4. Plan canonicalization idempotent - repeated canonicalization reaches fixed point
//! 5. Plan serialization roundtrip preserves equivalence - serialized plans maintain semantics
//!
//! Uses LabRuntime for deterministic property-based testing with plan analysis.

use asupersync::lab::runtime::LabRuntime;
use asupersync::plan::{
    PlanDag, PlanId, PlanNode, EGraph, ENode, EClassId, RewritePolicy, RewriteRule,
    PlanCost, Extractor, PlanAnalyzer, BudgetEffect, ObligationSafety, CancelSafety,
    DeadlineMicros,
};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

/// Maximum number of nodes in test plans
const MAX_PLAN_NODES: usize = 10;

/// Maximum timeout duration in milliseconds
const MAX_TIMEOUT_MS: u64 = 10_000;

/// Strategy for generating plan node labels
fn label_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("task_a".to_string()),
        Just("task_b".to_string()),
        Just("task_c".to_string()),
        Just("compute".to_string()),
        Just("io_op".to_string()),
        Just("network".to_string()),
    ]
}

/// Strategy for generating timeout durations
fn duration_strategy() -> impl Strategy<Value = Duration> {
    (1u64..=MAX_TIMEOUT_MS).prop_map(Duration::from_millis)
}

/// Strategy for generating rewrite policies
fn rewrite_policy_strategy() -> impl Strategy<Value = RewritePolicy> {
    (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>())
        .prop_map(|(assoc, comm, dist, binary, timeout)| {
            RewritePolicy::new()
                .with_associativity(assoc)
                .with_commutativity(comm)
                .with_distributivity(dist)
                .with_require_binary_joins(binary)
                .with_timeout_simplification(timeout)
        })
}

/// Configuration for a test plan DAG
#[derive(Debug, Clone)]
struct TestPlanConfig {
    nodes: Vec<TestNode>,
    root_index: usize,
}

/// Test node specification
#[derive(Debug, Clone)]
enum TestNode {
    Leaf { label: String },
    Join { children: Vec<usize> },
    Race { children: Vec<usize> },
    Timeout { child: usize, duration: Duration },
}

/// Helper for building test plans
struct PlanBuilder;

impl PlanBuilder {
    fn build_dag(config: &TestPlanConfig) -> Result<PlanDag, String> {
        let mut dag = PlanDag::new();
        let mut node_map = HashMap::new();

        // Build nodes in order
        for (i, test_node) in config.nodes.iter().enumerate() {
            let plan_id = match test_node {
                TestNode::Leaf { label } => dag.leaf(label.clone()),
                TestNode::Join { children } => {
                    let child_ids: Result<Vec<_>, _> = children
                        .iter()
                        .map(|&idx| {
                            node_map.get(&idx)
                                .copied()
                                .ok_or_else(|| format!("Missing child node {}", idx))
                        })
                        .collect();
                    dag.join(child_ids?)
                }
                TestNode::Race { children } => {
                    let child_ids: Result<Vec<_>, _> = children
                        .iter()
                        .map(|&idx| {
                            node_map.get(&idx)
                                .copied()
                                .ok_or_else(|| format!("Missing child node {}", idx))
                        })
                        .collect();
                    dag.race(child_ids?)
                }
                TestNode::Timeout { child, duration } => {
                    let child_id = node_map.get(child)
                        .copied()
                        .ok_or_else(|| format!("Missing timeout child {}", child))?;
                    dag.timeout(child_id, *duration)
                }
            };
            node_map.insert(i, plan_id);
        }

        // Set root if valid
        if let Some(&root_id) = node_map.get(&config.root_index) {
            dag.set_root(root_id);
        }

        dag.validate().map_err(|e| format!("DAG validation failed: {:?}", e))?;
        Ok(dag)
    }

    fn build_egraph(config: &TestPlanConfig) -> Result<(EGraph, EClassId), String> {
        let mut egraph = EGraph::new();
        let mut node_map = HashMap::new();

        for (i, test_node) in config.nodes.iter().enumerate() {
            let class_id = match test_node {
                TestNode::Leaf { label } => egraph.add_leaf(label.clone()),
                TestNode::Join { children } => {
                    let child_ids: Result<Vec<_>, _> = children
                        .iter()
                        .map(|&idx| {
                            node_map.get(&idx)
                                .copied()
                                .ok_or_else(|| format!("Missing child node {}", idx))
                        })
                        .collect();
                    egraph.add_join(child_ids?)
                }
                TestNode::Race { children } => {
                    let child_ids: Result<Vec<_>, _> = children
                        .iter()
                        .map(|&idx| {
                            node_map.get(&idx)
                                .copied()
                                .ok_or_else(|| format!("Missing child node {}", idx))
                        })
                        .collect();
                    egraph.add_race(child_ids?)
                }
                TestNode::Timeout { child, duration } => {
                    let child_id = node_map.get(child)
                        .copied()
                        .ok_or_else(|| format!("Missing timeout child {}", child))?;
                    egraph.add_timeout(child_id, *duration)
                }
            };
            node_map.insert(i, class_id);
        }

        let root_id = node_map.get(&config.root_index)
            .copied()
            .ok_or_else(|| "Missing root node".to_string())?;

        Ok((egraph, root_id))
    }
}

/// Strategy for generating test plan configurations
fn plan_config_strategy() -> impl Strategy<Value = TestPlanConfig> {
    (1usize..=MAX_PLAN_NODES)
        .prop_flat_map(|size| {
            let nodes_strategy = prop::collection::vec(
                prop_oneof![
                    label_strategy().prop_map(|label| TestNode::Leaf { label }),
                    // Generate joins/races with valid child indices
                    prop::collection::vec(0usize..size, 1..=3.min(size))
                        .prop_filter("non-empty children", |children| !children.is_empty())
                        .prop_map(|children| TestNode::Join { children }),
                    prop::collection::vec(0usize..size, 1..=3.min(size))
                        .prop_filter("non-empty children", |children| !children.is_empty())
                        .prop_map(|children| TestNode::Race { children }),
                    (0usize..size, duration_strategy())
                        .prop_map(|(child, duration)| TestNode::Timeout { child, duration }),
                ],
                size,
            );

            (nodes_strategy, 0usize..size).prop_map(|(nodes, root_index)| {
                TestPlanConfig { nodes, root_index }
            })
        })
        .prop_filter("valid dag structure", |config| {
            // Ensure DAG is well-formed (no cycles, valid references)
            Self::is_valid_dag_structure(config)
        })
}

impl TestPlanConfig {
    fn is_valid_dag_structure(config: &TestPlanConfig) -> bool {
        // Check that all child indices are valid
        for node in &config.nodes {
            match node {
                TestNode::Join { children } | TestNode::Race { children } => {
                    if children.is_empty() || children.iter().any(|&i| i >= config.nodes.len()) {
                        return false;
                    }
                }
                TestNode::Timeout { child, .. } => {
                    if *child >= config.nodes.len() {
                        return false;
                    }
                }
                TestNode::Leaf { .. } => {}
            }
        }

        // Check root index is valid
        config.root_index < config.nodes.len()
    }
}

/// Simple plan serialization for roundtrip testing
#[derive(Debug, Clone, PartialEq, Eq)]
struct SerializedPlan {
    nodes: Vec<SerializedNode>,
    root: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SerializedNode {
    Leaf { label: String },
    Join { children: Vec<usize> },
    Race { children: Vec<usize> },
    Timeout { child: usize, duration_ms: u64 },
}

impl SerializedPlan {
    fn from_dag(dag: &PlanDag) -> Self {
        let nodes = (0..dag.node_count())
            .map(|i| {
                let plan_id = PlanId::new(i);
                match dag.node(plan_id) {
                    Some(PlanNode::Leaf { label }) => {
                        SerializedNode::Leaf { label: label.clone() }
                    }
                    Some(PlanNode::Join { children }) => {
                        SerializedNode::Join {
                            children: children.iter().map(|id| id.index()).collect()
                        }
                    }
                    Some(PlanNode::Race { children }) => {
                        SerializedNode::Race {
                            children: children.iter().map(|id| id.index()).collect()
                        }
                    }
                    Some(PlanNode::Timeout { child, duration }) => {
                        SerializedNode::Timeout {
                            child: child.index(),
                            duration_ms: duration.as_millis() as u64
                        }
                    }
                    None => SerializedNode::Leaf { label: "invalid".to_string() },
                }
            })
            .collect();

        Self {
            nodes,
            root: dag.root().map(|id| id.index()),
        }
    }

    fn to_dag(&self) -> PlanDag {
        let mut dag = PlanDag::new();

        for node in &self.nodes {
            match node {
                SerializedNode::Leaf { label } => {
                    dag.leaf(label.clone());
                }
                SerializedNode::Join { children } => {
                    let child_ids = children.iter().map(|&i| PlanId::new(i)).collect();
                    dag.join(child_ids);
                }
                SerializedNode::Race { children } => {
                    let child_ids = children.iter().map(|&i| PlanId::new(i)).collect();
                    dag.race(child_ids);
                }
                SerializedNode::Timeout { child, duration_ms } => {
                    dag.timeout(PlanId::new(*child), Duration::from_millis(*duration_ms));
                }
            }
        }

        if let Some(root_idx) = self.root {
            dag.set_root(PlanId::new(root_idx));
        }

        dag
    }
}

/// MR1: DAG rewrites preserve semantic equivalence
#[test]
fn mr_dag_rewrites_preserve_semantic_equivalence() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(
        config in plan_config_strategy(),
        policy in rewrite_policy_strategy(),
    )| {
        runtime.block_on(&cx, async {
            // Property: Rewriting a plan according to algebraic laws should preserve semantics
            // The cost and analysis results should be equivalent or improved

            if config.nodes.len() < 2 {
                return Ok(());
            }

            let dag = match PlanBuilder::build_dag(&config) {
                Ok(d) => d,
                Err(_) => return Ok(()),
            };

            // Build e-graph for rewriting
            let (mut egraph, root_class) = match PlanBuilder::build_egraph(&config) {
                Ok(eg) => eg,
                Err(_) => return Ok(()),
            };

            // Get original analysis
            let mut analyzer = PlanAnalyzer::new();
            let original_analysis = analyzer.analyze(&dag);

            // Apply canonical class finding (simulates rewriting)
            let canonical_root = egraph.canonical_id(root_class);

            // Extract optimized plan
            let mut extractor = Extractor::new();
            let (optimized_dag, _extraction_cert) = extractor.extract(&mut egraph, canonical_root);

            // Analyze optimized plan
            let optimized_analysis = analyzer.analyze(&optimized_dag);

            // Test semantic equivalence invariants
            if let (Some(orig_root), Some(opt_root)) = (dag.root(), optimized_dag.root()) {
                if let (Some(orig_safety), Some(opt_safety)) = (
                    original_analysis.obligation_safety(orig_root),
                    optimized_analysis.obligation_safety(opt_root)
                ) {
                    // Obligation safety should not degrade
                    prop_assert!(
                        opt_safety >= orig_safety || opt_safety == ObligationSafety::Unknown,
                        "Rewrite degraded obligation safety: {:?} -> {:?}", orig_safety, opt_safety
                    );
                }

                if let (Some(orig_cancel), Some(opt_cancel)) = (
                    original_analysis.cancel_safety(orig_root),
                    optimized_analysis.cancel_safety(opt_root)
                ) {
                    // Cancel safety should not degrade
                    prop_assert!(
                        opt_cancel >= orig_cancel || opt_cancel == CancelSafety::Unknown,
                        "Rewrite degraded cancel safety: {:?} -> {:?}", orig_cancel, opt_cancel
                    );
                }

                // Budget effects should be preserved or improved
                let orig_budget = original_analysis.budget_effect(orig_root).unwrap_or(BudgetEffect::UNKNOWN);
                let opt_budget = optimized_analysis.budget_effect(opt_root).unwrap_or(BudgetEffect::UNKNOWN);

                // Check that budget effects are not worse (when analyzable)
                if orig_budget != BudgetEffect::UNKNOWN && opt_budget != BudgetEffect::UNKNOWN {
                    prop_assert!(
                        opt_budget.is_not_worse_than(orig_budget),
                        "Rewrite made budget effects worse: orig={:?}, opt={:?}", orig_budget, opt_budget
                    );
                }
            }

            // Test that extraction cost is deterministic
            let (optimized_dag2, _extraction_cert2) = extractor.extract(&mut egraph, canonical_root);
            let optimized_analysis2 = analyzer.analyze(&optimized_dag2);

            // Multiple extractions should yield equivalent results
            prop_assert_eq!(optimized_dag.node_count(), optimized_dag2.node_count(),
                "Multiple extractions should yield same node count");
        }).await;
    });
}

/// MR2: Dead-code elimination preserves required outputs
#[test]
fn mr_dead_code_elimination_preserves_required_outputs() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(config in plan_config_strategy())| {
        runtime.block_on(&cx, async {
            // Property: Removing unreachable nodes should not affect reachable computation

            if config.nodes.len() < 3 {
                return Ok(());
            }

            let original_dag = match PlanBuilder::build_dag(&config) {
                Ok(d) => d,
                Err(_) => return Ok(()),
            };

            // Find reachable nodes from root
            let mut reachable = BTreeSet::new();
            if let Some(root) = original_dag.root() {
                Self::mark_reachable(&original_dag, root, &mut reachable);
            }

            // Create DAG with only reachable nodes (simulated dead-code elimination)
            let mut pruned_config = config.clone();
            let reachable_indices: Vec<_> = (0..config.nodes.len())
                .filter(|i| reachable.contains(&PlanId::new(*i)))
                .collect();

            // If no pruning possible, test trivially passes
            if reachable_indices.len() == config.nodes.len() {
                return Ok(());
            }

            // Create mapping from old to new indices
            let mut index_map = HashMap::new();
            for (new_idx, &old_idx) in reachable_indices.iter().enumerate() {
                index_map.insert(old_idx, new_idx);
            }

            // Build pruned configuration
            pruned_config.nodes = reachable_indices
                .into_iter()
                .map(|old_idx| {
                    let node = &config.nodes[old_idx];
                    match node {
                        TestNode::Leaf { label } => TestNode::Leaf { label: label.clone() },
                        TestNode::Join { children } => {
                            let new_children = children
                                .iter()
                                .filter_map(|&old_child| index_map.get(&old_child).copied())
                                .collect();
                            TestNode::Join { children: new_children }
                        }
                        TestNode::Race { children } => {
                            let new_children = children
                                .iter()
                                .filter_map(|&old_child| index_map.get(&old_child).copied())
                                .collect();
                            TestNode::Race { children: new_children }
                        }
                        TestNode::Timeout { child, duration } => {
                            if let Some(&new_child) = index_map.get(child) {
                                TestNode::Timeout { child: new_child, duration: *duration }
                            } else {
                                // Skip timeouts with unreachable children
                                return TestNode::Leaf { label: "pruned".to_string() };
                            }
                        }
                    }
                })
                .collect();

            if let Some(&new_root) = index_map.get(&config.root_index) {
                pruned_config.root_index = new_root;
            }

            let pruned_dag = match PlanBuilder::build_dag(&pruned_config) {
                Ok(d) => d,
                Err(_) => return Ok(()),
            };

            // Analyze both DAGs
            let mut analyzer = PlanAnalyzer::new();
            let original_analysis = analyzer.analyze(&original_dag);
            let pruned_analysis = analyzer.analyze(&pruned_dag);

            // Dead-code elimination should preserve required outputs
            if let (Some(orig_root), Some(pruned_root)) = (original_dag.root(), pruned_dag.root()) {
                // Safety properties for the reachable computation should be preserved
                let orig_safety = original_analysis.obligation_safety(orig_root).unwrap_or(ObligationSafety::Unknown);
                let pruned_safety = pruned_analysis.obligation_safety(pruned_root).unwrap_or(ObligationSafety::Unknown);

                prop_assert!(
                    pruned_safety >= orig_safety || orig_safety == ObligationSafety::Unknown,
                    "Dead-code elimination degraded obligation safety: {:?} -> {:?}", orig_safety, pruned_safety
                );

                // Budget effects should be the same or better (less work)
                let orig_budget = original_analysis.budget_effect(orig_root).unwrap_or(BudgetEffect::UNKNOWN);
                let pruned_budget = pruned_analysis.budget_effect(pruned_root).unwrap_or(BudgetEffect::UNKNOWN);

                if orig_budget != BudgetEffect::UNKNOWN && pruned_budget != BudgetEffect::UNKNOWN {
                    // Dead-code elimination should not make things worse
                    prop_assert!(
                        pruned_budget.is_not_worse_than(orig_budget) || pruned_budget == orig_budget,
                        "Dead-code elimination made budget worse: {:?} -> {:?}", orig_budget, pruned_budget
                    );
                }
            }
        }).await;
    });
}

impl TestPlanConfig {
    fn mark_reachable(dag: &PlanDag, node_id: PlanId, reachable: &mut BTreeSet<PlanId>) {
        if !reachable.insert(node_id) {
            return; // Already visited
        }

        if let Some(node) = dag.node(node_id) {
            match node {
                PlanNode::Join { children } | PlanNode::Race { children } => {
                    for &child in children {
                        Self::mark_reachable(dag, child, reachable);
                    }
                }
                PlanNode::Timeout { child, .. } => {
                    Self::mark_reachable(dag, *child, reachable);
                }
                PlanNode::Leaf { .. } => {}
            }
        }
    }
}

/// MR3: Combinator fusion identities hold
#[test]
fn mr_combinator_fusion_identities_hold() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(
        labels in prop::collection::vec(label_strategy(), 2..=4),
        timeout_durations in prop::collection::vec(duration_strategy(), 1..=2),
    )| {
        runtime.block_on(&cx, async {
            // Property: Algebraic laws for combinators should hold
            // Test specific fusion identities like associativity, timeout composition, etc.

            if labels.len() < 2 {
                return Ok(());
            }

            // Test Join associativity: Join(a, Join(b, c)) == Join(a, b, c)
            let mut dag1 = PlanDag::new();
            let a = dag1.leaf(&labels[0]);
            let b = dag1.leaf(&labels[1]);
            let c = dag1.leaf(labels.get(2).unwrap_or(&labels[0]));

            let bc_join = dag1.join(vec![b, c]);
            let nested_join = dag1.join(vec![a, bc_join]);
            dag1.set_root(nested_join);

            let mut dag2 = PlanDag::new();
            let a2 = dag2.leaf(&labels[0]);
            let b2 = dag2.leaf(&labels[1]);
            let c2 = dag2.leaf(labels.get(2).unwrap_or(&labels[0]));
            let flat_join = dag2.join(vec![a2, b2, c2]);
            dag2.set_root(flat_join);

            let mut analyzer = PlanAnalyzer::new();
            let nested_analysis = analyzer.analyze(&dag1);
            let flat_analysis = analyzer.analyze(&dag2);

            // Associativity should preserve semantics
            let nested_safety = nested_analysis.obligation_safety(nested_join).unwrap_or(ObligationSafety::Unknown);
            let flat_safety = flat_analysis.obligation_safety(flat_join).unwrap_or(ObligationSafety::Unknown);

            prop_assert_eq!(nested_safety, flat_safety,
                "Join associativity should preserve obligation safety");

            // Test Timeout composition: Timeout(d1, Timeout(d2, f)) -> Timeout(min(d1, d2), f)
            if timeout_durations.len() >= 2 {
                let d1 = timeout_durations[0];
                let d2 = timeout_durations[1];

                let mut dag3 = PlanDag::new();
                let task = dag3.leaf(&labels[0]);
                let inner_timeout = dag3.timeout(task, d2);
                let outer_timeout = dag3.timeout(inner_timeout, d1);
                dag3.set_root(outer_timeout);

                let mut dag4 = PlanDag::new();
                let task2 = dag4.leaf(&labels[0]);
                let min_duration = if d1 < d2 { d1 } else { d2 };
                let fused_timeout = dag4.timeout(task2, min_duration);
                dag4.set_root(fused_timeout);

                let nested_timeout_analysis = analyzer.analyze(&dag3);
                let fused_timeout_analysis = analyzer.analyze(&dag4);

                // Timeout fusion should preserve or improve budget effects
                let nested_budget = nested_timeout_analysis.budget_effect(outer_timeout).unwrap_or(BudgetEffect::UNKNOWN);
                let fused_budget = fused_timeout_analysis.budget_effect(fused_timeout).unwrap_or(BudgetEffect::UNKNOWN);

                if nested_budget != BudgetEffect::UNKNOWN && fused_budget != BudgetEffect::UNKNOWN {
                    // Fused timeout should have tighter or equal deadline constraints
                    prop_assert!(
                        fused_budget.has_deadline >= nested_budget.has_deadline,
                        "Timeout fusion should preserve deadline constraints"
                    );

                    // The fused version should not be worse
                    prop_assert!(
                        fused_budget.is_not_worse_than(nested_budget) || fused_budget == nested_budget,
                        "Timeout fusion should not degrade budget effects"
                    );
                }
            }
        }).await;
    });
}

/// MR4: Plan canonicalization idempotent
#[test]
fn mr_plan_canonicalization_idempotent() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(config in plan_config_strategy())| {
        runtime.block_on(&cx, async {
            // Property: Repeated canonicalization should reach a fixed point
            // canonicalize(canonicalize(plan)) == canonicalize(plan)

            if config.nodes.is_empty() {
                return Ok(());
            }

            let (mut egraph, root_class) = match PlanBuilder::build_egraph(&config) {
                Ok(eg) => eg,
                Err(_) => return Ok(()),
            };

            // First canonicalization
            let canonical1 = egraph.canonical_id(root_class);
            let nodes1 = egraph.class_nodes_cloned(canonical1).unwrap_or_default();

            // Second canonicalization (should be idempotent)
            let canonical2 = egraph.canonical_id(canonical1);
            let nodes2 = egraph.class_nodes_cloned(canonical2).unwrap_or_default();

            // Canonicalization should be idempotent
            prop_assert_eq!(canonical1, canonical2,
                "Canonicalization should be idempotent: {:?} != {:?}", canonical1, canonical2);

            prop_assert_eq!(nodes1, nodes2,
                "Canonical class nodes should be stable under repeated canonicalization");

            // Third canonicalization (further verify idempotency)
            let canonical3 = egraph.canonical_id(canonical2);
            prop_assert_eq!(canonical2, canonical3,
                "Triple canonicalization should still be idempotent");

            // Extract plan from canonical representation
            let mut extractor = Extractor::new();
            let (plan1, _) = extractor.extract(&mut egraph, canonical1);
            let (plan2, _) = extractor.extract(&mut egraph, canonical2);

            // Extracted plans should be identical
            prop_assert_eq!(plan1.node_count(), plan2.node_count(),
                "Extracted plans from canonical representations should have same size");

            // Test structural equivalence of extracted plans
            if let (Some(root1), Some(root2)) = (plan1.root(), plan2.root()) {
                let equivalent = Self::plans_structurally_equivalent(&plan1, root1, &plan2, root2);
                prop_assert!(equivalent,
                    "Plans extracted from canonical representations should be structurally equivalent");
            }
        }).await;
    });
}

impl TestPlanConfig {
    fn plans_structurally_equivalent(
        plan1: &PlanDag,
        node1: PlanId,
        plan2: &PlanDag,
        node2: PlanId
    ) -> bool {
        match (plan1.node(node1), plan2.node(node2)) {
            (Some(PlanNode::Leaf { label: l1 }), Some(PlanNode::Leaf { label: l2 })) => l1 == l2,
            (Some(PlanNode::Join { children: c1 }), Some(PlanNode::Join { children: c2 })) => {
                c1.len() == c2.len() &&
                c1.iter().zip(c2.iter()).all(|(&child1, &child2)| {
                    Self::plans_structurally_equivalent(plan1, child1, plan2, child2)
                })
            }
            (Some(PlanNode::Race { children: c1 }), Some(PlanNode::Race { children: c2 })) => {
                c1.len() == c2.len() &&
                c1.iter().zip(c2.iter()).all(|(&child1, &child2)| {
                    Self::plans_structurally_equivalent(plan1, child1, plan2, child2)
                })
            }
            (Some(PlanNode::Timeout { child: c1, duration: d1 }),
             Some(PlanNode::Timeout { child: c2, duration: d2 })) => {
                d1 == d2 && Self::plans_structurally_equivalent(plan1, *c1, plan2, *c2)
            }
            _ => false,
        }
    }
}

/// MR5: Plan serialization roundtrip preserves equivalence
#[test]
fn mr_plan_serialization_roundtrip_preserves_equivalence() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(config in plan_config_strategy())| {
        runtime.block_on(&cx, async {
            // Property: serialize(deserialize(plan)) should preserve semantic equivalence

            if config.nodes.is_empty() {
                return Ok(());
            }

            let original_dag = match PlanBuilder::build_dag(&config) {
                Ok(d) => d,
                Err(_) => return Ok(()),
            };

            // Serialize the plan
            let serialized = SerializedPlan::from_dag(&original_dag);

            // Deserialize back to DAG
            let roundtrip_dag = serialized.to_dag();

            // Analyze both plans
            let mut analyzer = PlanAnalyzer::new();
            let original_analysis = analyzer.analyze(&original_dag);
            let roundtrip_analysis = analyzer.analyze(&roundtrip_dag);

            // Roundtrip should preserve structure
            prop_assert_eq!(original_dag.node_count(), roundtrip_dag.node_count(),
                "Serialization roundtrip should preserve node count");

            // Roundtrip should preserve analysis results
            if let (Some(orig_root), Some(rt_root)) = (original_dag.root(), roundtrip_dag.root()) {
                let orig_safety = original_analysis.obligation_safety(orig_root).unwrap_or(ObligationSafety::Unknown);
                let rt_safety = roundtrip_analysis.obligation_safety(rt_root).unwrap_or(ObligationSafety::Unknown);

                prop_assert_eq!(orig_safety, rt_safety,
                    "Serialization roundtrip should preserve obligation safety");

                let orig_cancel = original_analysis.cancel_safety(orig_root).unwrap_or(CancelSafety::Unknown);
                let rt_cancel = roundtrip_analysis.cancel_safety(rt_root).unwrap_or(CancelSafety::Unknown);

                prop_assert_eq!(orig_cancel, rt_cancel,
                    "Serialization roundtrip should preserve cancel safety");

                let orig_budget = original_analysis.budget_effect(orig_root).unwrap_or(BudgetEffect::UNKNOWN);
                let rt_budget = roundtrip_analysis.budget_effect(rt_root).unwrap_or(BudgetEffect::UNKNOWN);

                // Budget effects should be equivalent after roundtrip
                prop_assert_eq!(orig_budget.min_polls, rt_budget.min_polls,
                    "Roundtrip should preserve minimum polls");
                prop_assert_eq!(orig_budget.has_deadline, rt_budget.has_deadline,
                    "Roundtrip should preserve deadline constraints");
            }

            // Test structural equivalence
            if let (Some(orig_root), Some(rt_root)) = (original_dag.root(), roundtrip_dag.root()) {
                let structurally_equivalent = Self::plans_structurally_equivalent(&original_dag, orig_root, &roundtrip_dag, rt_root);
                prop_assert!(structurally_equivalent,
                    "Serialization roundtrip should preserve structural equivalence");
            }

            // Test that multiple roundtrips are idempotent
            let serialized2 = SerializedPlan::from_dag(&roundtrip_dag);
            prop_assert_eq!(serialized, serialized2,
                "Multiple serialization roundtrips should be idempotent");
        }).await;
    });
}

/// Integration test: Combined plan analysis properties
#[test]
fn mr_combined_plan_analysis_properties() {
    let runtime = LabRuntime::new(LabConfig::default());
    let cx = runtime.cx();

    proptest!(|(
        config in plan_config_strategy(),
        policy in rewrite_policy_strategy(),
    )| {
        runtime.block_on(&cx, async {
            // Property: All plan analysis metamorphic relations should hold simultaneously

            if config.nodes.len() < 2 {
                return Ok(());
            }

            let dag = match PlanBuilder::build_dag(&config) {
                Ok(d) => d,
                Err(_) => return Ok(()),
            };

            let (mut egraph, root_class) = match PlanBuilder::build_egraph(&config) {
                Ok(eg) => eg,
                Err(_) => return Ok(()),
            };

            let mut analyzer = PlanAnalyzer::new();
            let original_analysis = analyzer.analyze(&dag);

            // Test canonicalization idempotency
            let canonical1 = egraph.canonical_id(root_class);
            let canonical2 = egraph.canonical_id(canonical1);
            prop_assert_eq!(canonical1, canonical2, "Canonicalization should be idempotent");

            // Test extraction determinism
            let mut extractor = Extractor::new();
            let (extracted1, _) = extractor.extract(&mut egraph, canonical1);
            let (extracted2, _) = extractor.extract(&mut egraph, canonical1);
            prop_assert_eq!(extracted1.node_count(), extracted2.node_count(),
                "Multiple extractions should be deterministic");

            // Test serialization roundtrip
            let serialized = SerializedPlan::from_dag(&extracted1);
            let roundtrip = serialized.to_dag();
            prop_assert_eq!(extracted1.node_count(), roundtrip.node_count(),
                "Serialization roundtrip should preserve node count");

            // Test that analysis properties are preserved through transformations
            let extracted_analysis = analyzer.analyze(&extracted1);
            let roundtrip_analysis = analyzer.analyze(&roundtrip);

            if let (Some(orig_root), Some(ext_root), Some(rt_root)) = (
                dag.root(), extracted1.root(), roundtrip.root()
            ) {
                // Check that transformations preserve key properties
                let orig_safety = original_analysis.obligation_safety(orig_root).unwrap_or(ObligationSafety::Unknown);
                let ext_safety = extracted_analysis.obligation_safety(ext_root).unwrap_or(ObligationSafety::Unknown);
                let rt_safety = roundtrip_analysis.obligation_safety(rt_root).unwrap_or(ObligationSafety::Unknown);

                // Extraction should not degrade safety
                prop_assert!(
                    ext_safety >= orig_safety || orig_safety == ObligationSafety::Unknown || ext_safety == ObligationSafety::Unknown,
                    "Extraction should not degrade obligation safety: {:?} -> {:?}", orig_safety, ext_safety
                );

                // Roundtrip should preserve extracted safety
                prop_assert_eq!(ext_safety, rt_safety,
                    "Roundtrip should preserve obligation safety");
            }
        }).await;
    });
}

#[cfg(test)]
mod property_validation {
    use super::*;

    /// Verify test framework setup
    #[test]
    fn test_framework_validation() {
        let runtime = LabRuntime::new(LabConfig::default());
        let cx = runtime.cx();

        runtime.block_on(&cx, async {
            // Test basic plan DAG creation
            let mut dag = PlanDag::new();
            let task_a = dag.leaf("task_a");
            let task_b = dag.leaf("task_b");
            let join_node = dag.join(vec![task_a, task_b]);
            dag.set_root(join_node);

            assert_eq!(dag.node_count(), 3);
            assert_eq!(dag.root(), Some(join_node));
            assert!(dag.validate().is_ok());

            // Test e-graph canonicalization
            let mut egraph = EGraph::new();
            let leaf_a = egraph.add_leaf("task_a");
            let leaf_b = egraph.add_leaf("task_b");
            let join_class = egraph.add_join(vec![leaf_a, leaf_b]);

            let canonical = egraph.canonical_id(join_class);
            assert_eq!(canonical, join_class);

            // Test plan cost
            let cost = PlanCost::LEAF;
            assert_eq!(cost.allocations, 1);
            assert_eq!(cost.critical_path, 1);

            let combined = cost.add(cost);
            assert_eq!(combined.allocations, 2);
            assert_eq!(combined.critical_path, 1); // Max for parallel

            // Test serialization
            let serialized = SerializedPlan::from_dag(&dag);
            assert_eq!(serialized.nodes.len(), 3);
            assert_eq!(serialized.root, Some(2));

            let roundtrip = serialized.to_dag();
            assert_eq!(roundtrip.node_count(), 3);
        }).await;
    }
}