#![allow(warnings)]
#![allow(clippy::all)]
//! Golden tests for Plan DAG rewrite transformation vectors.
//!
//! Tests deterministic application of algebraic laws (associativity, commutativity,
//! distributivity, timeout simplification) to plan DAGs under different rewrite policies.

use asupersync::plan::{PlanDag, PlanId, PlanNode, RewritePolicy, RewriteRule};
use insta::assert_json_snapshot;
use serde::Serialize;
use std::time::Duration;

/// Golden snapshot format for plan DAG rewrite results.
#[derive(Debug, Serialize)]
struct PlanRewriteGolden {
    /// Test scenario name.
    scenario: &'static str,
    /// Input plan metadata.
    input_metadata: PlanInputMetadata,
    /// Applied rewrite policy.
    rewrite_policy: RewritePolicySnapshot,
    /// Transformation result.
    transformation_result: TransformationSnapshot,
}

/// Metadata about the input plan DAG.
#[derive(Debug, Serialize)]
struct PlanInputMetadata {
    /// Number of nodes in the input plan.
    node_count: usize,
    /// Root node ID.
    root_node: Option<usize>,
    /// Node types present.
    node_types: Vec<&'static str>,
    /// Maximum depth from root.
    max_depth: usize,
    /// Plan structure description.
    description: &'static str,
}

/// Snapshot of the rewrite policy used.
#[derive(Debug, Serialize)]
struct RewritePolicySnapshot {
    /// Policy name.
    policy_name: &'static str,
    /// Associativity allowed.
    associativity: bool,
    /// Commutativity allowed.
    commutativity: bool,
    /// Distributivity allowed.
    distributivity: bool,
    /// Require binary joins for distributivity.
    require_binary_joins: bool,
    /// Timeout simplification allowed.
    timeout_simplification: bool,
}

/// Snapshot of the transformation process and results.
#[derive(Debug, Serialize)]
struct TransformationSnapshot {
    /// Input plan DAG structure.
    input_plan: PlanDagSnapshot,
    /// Output plan DAG structure.
    output_plan: PlanDagSnapshot,
    /// Rules that could be applied.
    applicable_rules: Vec<&'static str>,
    /// Rules that were actually fired.
    rules_applied: Vec<&'static str>,
    /// Whether any transformation occurred.
    transformed: bool,
    /// Transformation provenance.
    transformation_steps: Vec<TransformationStep>,
}

/// One step in the transformation process.
#[derive(Debug, Serialize)]
struct TransformationStep {
    /// Rule applied.
    rule: &'static str,
    /// Node(s) where rule applied.
    target_nodes: Vec<usize>,
    /// Pre-transformation structure.
    before: String,
    /// Post-transformation structure.
    after: String,
}

/// Serializable snapshot of a plan DAG.
#[derive(Debug, Serialize)]
struct PlanDagSnapshot {
    /// Root node ID.
    root: Option<usize>,
    /// All nodes with their IDs.
    nodes: Vec<PlanNodeSnapshot>,
    /// Canonical string representation.
    canonical_form: String,
}

/// Serializable snapshot of a plan node.
#[derive(Debug, Serialize)]
struct PlanNodeSnapshot {
    /// Node ID.
    id: usize,
    /// Node type.
    node_type: &'static str,
    /// Node details.
    details: PlanNodeDetails,
}

/// Details of different node types.
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum PlanNodeDetails {
    Leaf { label: String },
    Join { children: Vec<usize> },
    Race { children: Vec<usize> },
    Timeout { child: usize, duration_ms: u64 },
}

/// Create golden snapshot from plan DAG and policy.
fn create_golden_snapshot(
    scenario: &'static str,
    description: &'static str,
    input_plan: &PlanDag,
    policy: RewritePolicy,
    policy_name: &'static str,
) -> PlanRewriteGolden {
    let input_snapshot = create_plan_snapshot(input_plan);

    let (output_plan, transformation_steps) = apply_real_transformations(input_plan, policy);
    let output_snapshot = create_plan_snapshot(&output_plan);

    let input_metadata = PlanInputMetadata {
        node_count: input_plan.node_count(),
        root_node: input_plan.root().map(|id| id.index()),
        node_types: get_node_types(input_plan),
        max_depth: calculate_max_depth(input_plan),
        description,
    };

    let policy_snapshot = RewritePolicySnapshot {
        policy_name,
        associativity: policy.associativity,
        commutativity: policy.commutativity,
        distributivity: policy.distributivity,
        require_binary_joins: policy.require_binary_joins,
        timeout_simplification: policy.timeout_simplification,
    };

    let transformed = input_snapshot.canonical_form != output_snapshot.canonical_form;

    let applicable_rules = get_applicable_rules(&input_plan, policy);
    let rules_applied = transformation_steps.iter().map(|step| step.rule).collect();

    let transformation_result = TransformationSnapshot {
        input_plan: input_snapshot,
        output_plan: output_snapshot,
        applicable_rules,
        rules_applied,
        transformed,
        transformation_steps,
    };

    PlanRewriteGolden {
        scenario,
        input_metadata,
        rewrite_policy: policy_snapshot,
        transformation_result,
    }
}

/// Create a snapshot of a plan DAG.
fn create_plan_snapshot(plan: &PlanDag) -> PlanDagSnapshot {
    let mut nodes: Vec<PlanNodeSnapshot> = Vec::new();

    for id in 0..plan.node_count() {
        let plan_id = PlanId::new(id);
        if let Some(node) = plan.node(plan_id) {
            let (node_type, details) = match node {
                PlanNode::Leaf { label } => (
                    "leaf",
                    PlanNodeDetails::Leaf {
                        label: label.clone(),
                    },
                ),
                PlanNode::Join { children } => (
                    "join",
                    PlanNodeDetails::Join {
                        children: children.iter().map(|id| id.index()).collect(),
                    },
                ),
                PlanNode::Race { children } => (
                    "race",
                    PlanNodeDetails::Race {
                        children: children.iter().map(|id| id.index()).collect(),
                    },
                ),
                PlanNode::Timeout { child, duration } => (
                    "timeout",
                    PlanNodeDetails::Timeout {
                        child: child.index(),
                        duration_ms: duration.as_millis() as u64,
                    },
                ),
            };

            nodes.push(PlanNodeSnapshot {
                id,
                node_type,
                details,
            });
        }
    }

    let canonical_form = render_plan_canonical(plan);

    PlanDagSnapshot {
        root: plan.root().map(|id| id.index()),
        nodes,
        canonical_form,
    }
}

/// Render plan in canonical string form for comparison.
fn render_plan_canonical(plan: &PlanDag) -> String {
    if let Some(root) = plan.root() {
        render_node_canonical(plan, root)
    } else {
        "empty".to_string()
    }
}

/// Render a single node in canonical form.
fn render_node_canonical(plan: &PlanDag, node_id: PlanId) -> String {
    match plan.node(node_id) {
        Some(PlanNode::Leaf { label }) => label.clone(),
        Some(PlanNode::Join { children }) => {
            let child_reprs: Vec<String> = children
                .iter()
                .map(|&child| render_node_canonical(plan, child))
                .collect();
            format!("Join[{}]", child_reprs.join(","))
        }
        Some(PlanNode::Race { children }) => {
            let child_reprs: Vec<String> = children
                .iter()
                .map(|&child| render_node_canonical(plan, child))
                .collect();
            format!("Race[{}]", child_reprs.join(","))
        }
        Some(PlanNode::Timeout { child, duration }) => {
            let child_repr = render_node_canonical(plan, *child);
            format!("Timeout({}ms, {})", duration.as_millis(), child_repr)
        }
        None => "invalid".to_string(),
    }
}

/// Get node types present in the plan.
fn get_node_types(plan: &PlanDag) -> Vec<&'static str> {
    let mut types = std::collections::BTreeSet::new();
    for id in 0..plan.node_count() {
        let plan_id = PlanId::new(id);
        if let Some(node) = plan.node(plan_id) {
            let node_type = match node {
                PlanNode::Leaf { .. } => "leaf",
                PlanNode::Join { .. } => "join",
                PlanNode::Race { .. } => "race",
                PlanNode::Timeout { .. } => "timeout",
            };
            types.insert(node_type);
        }
    }
    types.into_iter().collect()
}

/// Calculate maximum depth from root.
fn calculate_max_depth(plan: &PlanDag) -> usize {
    if let Some(root) = plan.root() {
        calculate_node_depth(plan, root, 0)
    } else {
        0
    }
}

/// Calculate depth of a node recursively.
fn calculate_node_depth(plan: &PlanDag, node_id: PlanId, current_depth: usize) -> usize {
    let Some(node) = plan.node(node_id) else {
        return current_depth;
    };

    match node {
        PlanNode::Leaf { .. } => current_depth,
        PlanNode::Join { children } | PlanNode::Race { children } => children
            .iter()
            .map(|&child| calculate_node_depth(plan, child, current_depth + 1))
            .max()
            .unwrap_or(current_depth),
        PlanNode::Timeout { child, .. } => calculate_node_depth(plan, *child, current_depth + 1),
    }
}

/// Get rules applicable to this plan under the given policy.
fn get_applicable_rules(plan: &PlanDag, policy: RewritePolicy) -> Vec<&'static str> {
    let mut rules = Vec::new();

    // Check each rule's applicability
    if policy.associativity {
        if has_nested_joins(plan) {
            rules.push("JoinAssoc");
        }
        if has_nested_races(plan) {
            rules.push("RaceAssoc");
        }
    }

    if policy.commutativity {
        if has_commutable_joins(plan) {
            rules.push("JoinCommute");
        }
        if has_commutable_races(plan) {
            rules.push("RaceCommute");
        }
    }

    if policy.timeout_simplification {
        if has_nested_timeouts(plan) {
            rules.push("TimeoutMin");
        }
    }

    if policy.distributivity {
        if has_race_of_joins_with_shared_child(plan) {
            rules.push("DedupRaceJoin");
        }
    }

    rules
}

/// Apply transformations through the production PlanDag rewrite engine.
fn apply_real_transformations(
    plan: &PlanDag,
    policy: RewritePolicy,
) -> (PlanDag, Vec<TransformationStep>) {
    let mut output = plan.clone();
    let report = output.apply_rewrites(policy, RewriteRule::all());
    let steps = report
        .steps()
        .iter()
        .map(|step| TransformationStep {
            rule: rewrite_rule_name(step.rule),
            target_nodes: vec![step.before.index(), step.after.index()],
            before: render_node_canonical(plan, step.before),
            after: render_node_canonical(&output, step.after),
        })
        .collect();

    (output, steps)
}

fn has_nested_joins(plan: &PlanDag) -> bool {
    for id in 0..plan.node_count() {
        let plan_id = PlanId::new(id);
        if let Some(node) = plan.node(plan_id) {
            if let PlanNode::Join { children } = node {
                if children
                    .iter()
                    .any(|&child_id| matches!(plan.node(child_id), Some(PlanNode::Join { .. })))
                {
                    return true;
                }
            }
        }
    }
    false
}

fn has_nested_races(plan: &PlanDag) -> bool {
    for id in 0..plan.node_count() {
        let plan_id = PlanId::new(id);
        if let Some(node) = plan.node(plan_id) {
            if let PlanNode::Race { children } = node {
                if children
                    .iter()
                    .any(|&child_id| matches!(plan.node(child_id), Some(PlanNode::Race { .. })))
                {
                    return true;
                }
            }
        }
    }
    false
}

fn has_commutable_joins(plan: &PlanDag) -> bool {
    for id in 0..plan.node_count() {
        let plan_id = PlanId::new(id);
        if let Some(node) = plan.node(plan_id) {
            if matches!(node, PlanNode::Join { children } if children.len() > 1) {
                return true;
            }
        }
    }
    false
}

fn has_commutable_races(plan: &PlanDag) -> bool {
    for id in 0..plan.node_count() {
        let plan_id = PlanId::new(id);
        if let Some(node) = plan.node(plan_id) {
            if matches!(node, PlanNode::Race { children } if children.len() > 1) {
                return true;
            }
        }
    }
    false
}

fn has_nested_timeouts(plan: &PlanDag) -> bool {
    for id in 0..plan.node_count() {
        let plan_id = PlanId::new(id);
        if let Some(node) = plan.node(plan_id) {
            if let PlanNode::Timeout { child, .. } = node {
                if matches!(plan.node(*child), Some(PlanNode::Timeout { .. })) {
                    return true;
                }
            }
        }
    }
    false
}

fn has_race_of_joins_with_shared_child(plan: &PlanDag) -> bool {
    // Simplified check for Race[Join[shared, a], Join[shared, b]] pattern
    for id in 0..plan.node_count() {
        let plan_id = PlanId::new(id);
        if let Some(node) = plan.node(plan_id) {
            if let PlanNode::Race { children } = node {
                if children.len() >= 2
                    && children
                        .iter()
                        .all(|&child_id| matches!(plan.node(child_id), Some(PlanNode::Join { .. })))
                {
                    return true;
                }
            }
        }
    }
    false
}

fn rewrite_rule_name(rule: RewriteRule) -> &'static str {
    match rule {
        RewriteRule::JoinAssoc => "JoinAssoc",
        RewriteRule::RaceAssoc => "RaceAssoc",
        RewriteRule::JoinCommute => "JoinCommute",
        RewriteRule::RaceCommute => "RaceCommute",
        RewriteRule::TimeoutMin => "TimeoutMin",
        RewriteRule::DedupRaceJoin => "DedupRaceJoin",
    }
}

// ============================================================================
// Golden Test Cases
// ============================================================================

#[test]
fn golden_simple_leaf() {
    let mut plan = PlanDag::new();
    let leaf_a = plan.leaf("task_a");
    plan.set_root(leaf_a);

    let golden = create_golden_snapshot(
        "simple_leaf",
        "Single leaf node - no transformations possible",
        &plan,
        RewritePolicy::conservative(),
        "conservative",
    );
    assert_json_snapshot!("plan_rewrite_simple_leaf", golden);
}

#[test]
fn golden_join_associativity() {
    let mut plan = PlanDag::new();
    let leaf_a = plan.leaf("task_a");
    let leaf_b = plan.leaf("task_b");
    let leaf_c = plan.leaf("task_c");

    // Create nested join: Join[Join[a,b], c]
    let inner_join = plan.join(vec![leaf_a, leaf_b]);
    let outer_join = plan.join(vec![inner_join, leaf_c]);
    plan.set_root(outer_join);

    let golden = create_golden_snapshot(
        "join_associativity",
        "Nested join structure - tests associativity rewrite",
        &plan,
        RewritePolicy::conservative(),
        "conservative",
    );
    assert_json_snapshot!("plan_rewrite_join_associativity", golden);
}

#[test]
fn golden_race_commutativity() {
    let mut plan = PlanDag::new();
    let leaf_a = plan.leaf("task_a");
    let leaf_b = plan.leaf("task_b");
    let leaf_c = plan.leaf("task_c");

    // Create race with multiple children
    let race = plan.race(vec![leaf_c, leaf_a, leaf_b]); // Non-canonical order
    plan.set_root(race);

    let golden = create_golden_snapshot(
        "race_commutativity",
        "Race with unordered children - tests commutativity rewrite",
        &plan,
        RewritePolicy::assume_all(),
        "assume_all",
    );
    assert_json_snapshot!("plan_rewrite_race_commutativity", golden);
}

#[test]
fn golden_timeout_simplification() {
    let mut plan = PlanDag::new();
    let leaf_a = plan.leaf("task_a");

    // Create nested timeouts: Timeout(100ms, Timeout(50ms, task_a))
    let inner_timeout = plan.timeout(leaf_a, Duration::from_millis(50));
    let outer_timeout = plan.timeout(inner_timeout, Duration::from_millis(100));
    plan.set_root(outer_timeout);

    let golden = create_golden_snapshot(
        "timeout_simplification",
        "Nested timeouts - tests timeout minimization rewrite",
        &plan,
        RewritePolicy::conservative(),
        "conservative",
    );
    assert_json_snapshot!("plan_rewrite_timeout_simplification", golden);
}

#[test]
fn golden_distributivity_pattern() {
    let mut plan = PlanDag::new();
    let shared = plan.leaf("shared_task");
    let task_a = plan.leaf("task_a");
    let task_b = plan.leaf("task_b");

    // Create Race[Join[shared, a], Join[shared, b]]
    let join_1 = plan.join(vec![shared, task_a]);
    let join_2 = plan.join(vec![shared, task_b]);
    let race = plan.race(vec![join_1, join_2]);
    plan.set_root(race);

    let golden = create_golden_snapshot(
        "distributivity_pattern",
        "Race of joins with shared child - tests distributivity rewrite",
        &plan,
        RewritePolicy::assume_all(),
        "assume_all",
    );
    assert_json_snapshot!("plan_rewrite_distributivity", golden);
}

#[test]
fn golden_complex_mixed_policy() {
    let mut plan = PlanDag::new();
    let leaf_a = plan.leaf("task_a");
    let leaf_b = plan.leaf("task_b");
    let leaf_c = plan.leaf("task_c");
    let leaf_d = plan.leaf("task_d");

    // Complex structure with multiple patterns
    let join_1 = plan.join(vec![leaf_a, leaf_b]);
    let join_2 = plan.join(vec![leaf_c, leaf_d]);
    let race = plan.race(vec![join_2, join_1]); // Non-canonical order
    let timeout = plan.timeout(race, Duration::from_millis(1000));
    plan.set_root(timeout);

    let golden = create_golden_snapshot(
        "complex_mixed",
        "Complex plan with timeout, race, joins - multiple rewrite opportunities",
        &plan,
        RewritePolicy::new()
            .with_commutativity(true)
            .with_timeout_simplification(true),
        "custom_selective",
    );
    assert_json_snapshot!("plan_rewrite_complex_mixed", golden);
}

#[test]
fn golden_no_rewrites_conservative() {
    let mut plan = PlanDag::new();
    let leaf_a = plan.leaf("task_a");
    let leaf_b = plan.leaf("task_b");

    // Simple race - no rewrites possible under conservative policy
    let race = plan.race(vec![leaf_a, leaf_b]);
    plan.set_root(race);

    let golden = create_golden_snapshot(
        "no_rewrites_conservative",
        "Simple race under conservative policy - no rewrites applied",
        &plan,
        RewritePolicy::new(), // All flags disabled
        "none",
    );
    assert_json_snapshot!("plan_rewrite_no_rewrites", golden);
}

#[test]
fn golden_deep_nested_structure() {
    let mut plan = PlanDag::new();
    let leaf_a = plan.leaf("task_a");
    let leaf_b = plan.leaf("task_b");
    let leaf_c = plan.leaf("task_c");

    // Deep nesting: Timeout(Join[Race[a,b], Timeout(c)])
    let race = plan.race(vec![leaf_a, leaf_b]);
    let inner_timeout = plan.timeout(leaf_c, Duration::from_millis(200));
    let join = plan.join(vec![race, inner_timeout]);
    let outer_timeout = plan.timeout(join, Duration::from_millis(500));
    plan.set_root(outer_timeout);

    let golden = create_golden_snapshot(
        "deep_nested",
        "Deep nested structure - tests multiple rewrite interactions",
        &plan,
        RewritePolicy::assume_all(),
        "assume_all",
    );
    assert_json_snapshot!("plan_rewrite_deep_nested", golden);
}

#[test]
fn golden_source_uses_real_rewrite_engine() {
    let source = include_str!("plan_dag_rewrite_golden.rs");

    assert!(
        source.contains("apply_rewrites(policy, RewriteRule::all())"),
        "golden helper must use the production PlanDag rewrite engine"
    );
    assert!(!source.contains(concat!("mock", " for now")));
    assert!(!source.contains(concat!("apply_", "mock_", "transformations")));
    assert!(!source.contains(concat!("would use ", "real rewriter in practice")));
}
