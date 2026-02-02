//! Plan DAG rewrites and rewrite policies.

use std::collections::HashSet;
use std::fmt::Write;

use super::{PlanDag, PlanId, PlanNode};

/// Policy controlling which rewrites are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RewritePolicy {
    /// Conservative: only rewrite when the shared child is a leaf and joins are binary.
    #[default]
    Conservative,
    /// Assume associativity/commutativity and independence of children.
    AssumeAssociativeComm,
}

impl RewritePolicy {
    fn allows_shared_non_leaf(self) -> bool {
        matches!(self, Self::AssumeAssociativeComm)
    }

    fn requires_binary_joins(self) -> bool {
        matches!(self, Self::Conservative)
    }
}

/// Rewrite rules available for plan DAGs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewriteRule {
    /// Dedupe a shared child across a race of joins.
    DedupRaceJoin,
}

/// A single rewrite step applied to the plan DAG.
#[derive(Debug, Clone)]
pub struct RewriteStep {
    /// The rewrite rule applied.
    pub rule: RewriteRule,
    /// Node replaced by the rewrite.
    pub before: PlanId,
    /// Node introduced by the rewrite.
    pub after: PlanId,
    /// Human-readable explanation of the change.
    pub detail: String,
}

/// Report describing all rewrites applied to a plan DAG.
#[derive(Debug, Default, Clone)]
pub struct RewriteReport {
    steps: Vec<RewriteStep>,
}

impl RewriteReport {
    /// Returns the applied rewrite steps.
    #[must_use]
    pub fn steps(&self) -> &[RewriteStep] {
        &self.steps
    }

    /// Returns true if no rewrites were applied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Returns a human-readable summary of rewrite steps.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.steps.is_empty() {
            return "no rewrites applied".to_string();
        }

        let mut out = String::new();
        for (idx, step) in self.steps.iter().enumerate() {
            let _ = writeln!(
                out,
                "{}. {:?}: {} ({} -> {})",
                idx + 1,
                step.rule,
                step.detail,
                step.before.index(),
                step.after.index()
            );
        }
        out
    }
}

impl PlanDag {
    /// Apply rewrite rules to the plan DAG using the provided policy.
    pub fn apply_rewrites(
        &mut self,
        policy: RewritePolicy,
        rules: &[RewriteRule],
    ) -> RewriteReport {
        let mut report = RewriteReport::default();
        let original_len = self.nodes.len();

        for idx in 0..original_len {
            let id = PlanId::new(idx);
            for rule in rules {
                if let Some(step) = self.apply_rule(id, policy, *rule) {
                    report.steps.push(step);
                }
            }
        }

        report
    }

    fn apply_rule(
        &mut self,
        id: PlanId,
        policy: RewritePolicy,
        rule: RewriteRule,
    ) -> Option<RewriteStep> {
        match rule {
            RewriteRule::DedupRaceJoin => self.rewrite_dedup_race_join(id, policy),
        }
    }

    fn rewrite_dedup_race_join(
        &mut self,
        id: PlanId,
        policy: RewritePolicy,
    ) -> Option<RewriteStep> {
        let PlanNode::Race { children } = self.node(id)?.clone() else {
            return None;
        };

        if children.len() < 2 {
            return None;
        }

        if policy.requires_binary_joins() && children.len() != 2 {
            return None;
        }

        let mut join_children = Vec::with_capacity(children.len());
        for child in &children {
            match self.node(*child)? {
                PlanNode::Join { children } => {
                    if policy.requires_binary_joins() && children.len() != 2 {
                        return None;
                    }
                    join_children.push((*child, children.clone()));
                }
                _ => return None,
            }
        }

        if policy.requires_binary_joins() {
            for (_, join_nodes) in &join_children {
                let mut unique = HashSet::new();
                for child in join_nodes {
                    if !unique.insert(*child) {
                        return None;
                    }
                }
            }
        }

        let mut intersection: HashSet<PlanId> = join_children[0].1.iter().copied().collect();
        for (_, join_nodes) in join_children.iter().skip(1) {
            let set: HashSet<PlanId> = join_nodes.iter().copied().collect();
            intersection.retain(|id| set.contains(id));
        }

        if intersection.len() != 1 {
            return None;
        }

        let shared = *intersection.iter().next()?;

        if !policy.allows_shared_non_leaf() {
            match self.node(shared) {
                Some(PlanNode::Leaf { .. }) => {}
                _ => return None,
            }
        }

        let mut race_branches = Vec::with_capacity(join_children.len());
        for (_, join_nodes) in &join_children {
            let mut remaining: Vec<PlanId> = join_nodes
                .iter()
                .copied()
                .filter(|id| *id != shared)
                .collect();
            if remaining.is_empty() {
                return None;
            }
            if policy.requires_binary_joins() && remaining.len() != 1 {
                return None;
            }
            if remaining.len() == 1 {
                race_branches.push(remaining.remove(0));
            } else {
                let join_id = self.push_node(PlanNode::Join {
                    children: remaining,
                });
                race_branches.push(join_id);
            }
        }

        let race_id = if race_branches.len() == 1 {
            race_branches[0]
        } else {
            self.push_node(PlanNode::Race {
                children: race_branches,
            })
        };

        let new_join_id = self.push_node(PlanNode::Join {
            children: vec![shared, race_id],
        });

        self.replace_parents(id, new_join_id);
        if self.root == Some(id) {
            self.root = Some(new_join_id);
        }

        Some(RewriteStep {
            rule: RewriteRule::DedupRaceJoin,
            before: id,
            after: new_join_id,
            detail: format!(
                "deduped shared child {} across {} joins",
                shared.index(),
                join_children.len()
            ),
        })
    }

    fn replace_parents(&mut self, old: PlanId, new: PlanId) {
        for parent in self.parent_map(old) {
            if let Some(node) = self.nodes.get_mut(parent.index()) {
                match node {
                    PlanNode::Join { children } | PlanNode::Race { children } => {
                        for child in children.iter_mut() {
                            if *child == old {
                                *child = new;
                            }
                        }
                    }
                    PlanNode::Timeout { child, .. } => {
                        if *child == old {
                            *child = new;
                        }
                    }
                    PlanNode::Leaf { .. } => {}
                }
            }
        }
    }

    fn parent_map(&self, target: PlanId) -> Vec<PlanId> {
        let mut parents = Vec::new();
        for (idx, node) in self.nodes.iter().enumerate() {
            let id = PlanId::new(idx);
            for child in node.children() {
                if child == target {
                    parents.push(id);
                }
            }
        }
        parents
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

    fn init_test() {
        init_test_logging();
    }

    fn shared_leaf_race_plan() -> (PlanDag, PlanId, PlanId, PlanId) {
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let join_a = dag.join(vec![shared, left]);
        let join_b = dag.join(vec![shared, right]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);
        (dag, shared, left, right)
    }

    #[test]
    fn test_apply_rewrites_empty_dag_no_steps() {
        init_test();
        let mut dag = PlanDag::new();
        let report = dag.apply_rewrites(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);
        assert!(report.is_empty());
    }

    #[test]
    fn test_dedup_race_join_conservative_applies() {
        init_test();
        let (mut dag, shared, left, right) = shared_leaf_race_plan();
        let report = dag.apply_rewrites(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);
        assert_eq!(report.steps().len(), 1);
        let root = dag.root().expect("root set");
        let PlanNode::Join { children } = dag.node(root).expect("root exists") else {
            panic!("expected join at root");
        };
        assert!(children.contains(&shared));
        let race_child = children
            .iter()
            .copied()
            .find(|id| *id != shared)
            .expect("race");
        let PlanNode::Race { children } = dag.node(race_child).expect("race exists") else {
            panic!("expected race child");
        };
        assert!(children.contains(&left));
        assert!(children.contains(&right));
    }

    #[test]
    fn test_dedup_race_join_conservative_rejects_non_leaf_shared() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let shared = dag.join(vec![a, b]);
        let c = dag.leaf("c");
        let d = dag.leaf("d");
        let join_a = dag.join(vec![shared, c]);
        let join_b = dag.join(vec![shared, d]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let report = dag.apply_rewrites(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);
        assert!(report.is_empty());

        let report = dag.apply_rewrites(
            RewritePolicy::AssumeAssociativeComm,
            &[RewriteRule::DedupRaceJoin],
        );
        assert_eq!(report.steps().len(), 1);
    }

    #[test]
    fn test_dedup_race_join_conservative_rejects_non_binary_joins() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let d = dag.leaf("d");
        let join_a = dag.join(vec![shared, a, b]);
        let join_b = dag.join(vec![shared, c, d]);
        let race = dag.race(vec![join_a, join_b]);
        dag.set_root(race);

        let report = dag.apply_rewrites(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);
        assert!(report.is_empty());

        let report = dag.apply_rewrites(
            RewritePolicy::AssumeAssociativeComm,
            &[RewriteRule::DedupRaceJoin],
        );
        assert_eq!(report.steps().len(), 1);
    }

    #[test]
    fn test_dedup_race_join_idempotent_on_rewritten_shape() {
        init_test();
        let mut dag = PlanDag::new();
        let shared = dag.leaf("shared");
        let left = dag.leaf("left");
        let right = dag.leaf("right");
        let race = dag.race(vec![left, right]);
        let join = dag.join(vec![shared, race]);
        dag.set_root(join);

        let report = dag.apply_rewrites(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);
        assert!(report.is_empty());
    }

    #[test]
    fn test_apply_rewrites_handles_missing_child_gracefully() {
        init_test();
        let mut dag = PlanDag::new();
        let leaf = dag.leaf("leaf");
        let missing = PlanId::new(999);
        let join = dag.join(vec![leaf, missing]);
        let race = dag.race(vec![join, leaf]);
        dag.set_root(race);

        let report = dag.apply_rewrites(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);
        assert!(report.is_empty());
        assert_eq!(dag.root(), Some(race));
    }

    #[test]
    fn test_apply_rewrites_multiple_races_single_pass() {
        init_test();
        let (mut dag, _shared1, _left1, _right1) = shared_leaf_race_plan();
        let shared2 = dag.leaf("shared2");
        let left2 = dag.leaf("left2");
        let right2 = dag.leaf("right2");
        let join_a = dag.join(vec![shared2, left2]);
        let join_b = dag.join(vec![shared2, right2]);
        let race2 = dag.race(vec![join_a, join_b]);
        let root = dag.join(vec![dag.root().expect("root"), race2]);
        dag.set_root(root);

        let report = dag.apply_rewrites(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);
        assert_eq!(report.steps().len(), 2);
        assert!(report
            .steps()
            .iter()
            .all(|step| step.rule == RewriteRule::DedupRaceJoin));
        let root = dag.root().expect("root");
        let PlanNode::Join { children } = dag.node(root).expect("root exists") else {
            panic!("expected join at root");
        };
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn test_dedup_race_join_skips_single_child_race() {
        init_test();
        let mut dag = PlanDag::new();
        let leaf = dag.leaf("leaf");
        let race = dag.race(vec![leaf]);
        dag.set_root(race);

        let report = dag.apply_rewrites(RewritePolicy::Conservative, &[RewriteRule::DedupRaceJoin]);
        assert!(report.is_empty());
        assert_eq!(dag.root(), Some(race));
    }
}
