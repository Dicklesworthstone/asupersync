//! Plan DAG rewrites and rewrite policies.

use std::collections::HashSet;
use std::fmt::Write;

use super::analysis::SideConditionChecker;
use super::{PlanDag, PlanId, PlanNode};

/// Policy controlling which rewrites are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RewritePolicy {
    /// Conservative: only apply rewrites that do not assume commutativity.
    #[default]
    Conservative,
    /// Assume associativity/commutativity and independence of children.
    AssumeAssociativeComm,
}

impl RewritePolicy {
    #[allow(clippy::unused_self)]
    fn allows_associative(self) -> bool {
        true
    }

    fn allows_commutative(self) -> bool {
        matches!(self, Self::AssumeAssociativeComm)
    }

    fn allows_shared_non_leaf(self) -> bool {
        matches!(self, Self::AssumeAssociativeComm)
    }

    fn requires_binary_joins(self) -> bool {
        matches!(self, Self::Conservative)
    }
}

/// Declarative schema for a rewrite rule.
#[derive(Debug, Clone, Copy)]
pub struct RewriteRuleSchema {
    /// Pattern shape (lhs).
    pub pattern: &'static str,
    /// Replacement shape (rhs).
    pub replacement: &'static str,
    /// Side conditions that must hold.
    pub side_conditions: &'static [&'static str],
    /// Human-readable explanation.
    pub explanation: &'static str,
}

/// Rewrite rules available for plan DAGs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewriteRule {
    /// Associativity for joins: Join[Join[a,b], c] -> Join[a,b,c].
    JoinAssoc,
    /// Associativity for races: Race[Race[a,b], c] -> Race[a,b,c].
    RaceAssoc,
    /// Commutativity for joins (deterministic canonical order).
    JoinCommute,
    /// Commutativity for races (deterministic canonical order).
    RaceCommute,
    /// Minimize nested timeouts: Timeout(d1, Timeout(d2, f)) -> Timeout(min(d1,d2), f).
    TimeoutMin,
    /// Dedupe a shared child across a race of joins.
    DedupRaceJoin,
}

const ALL_REWRITE_RULES: &[RewriteRule] = &[
    RewriteRule::JoinAssoc,
    RewriteRule::RaceAssoc,
    RewriteRule::JoinCommute,
    RewriteRule::RaceCommute,
    RewriteRule::TimeoutMin,
    RewriteRule::DedupRaceJoin,
];

impl RewriteRule {
    /// Returns the full rule schema (pattern, replacement, side conditions, explanation).
    #[must_use]
    pub fn schema(self) -> RewriteRuleSchema {
        match self {
            Self::JoinAssoc => RewriteRuleSchema {
                pattern: "Join[Join[a,b], c]",
                replacement: "Join[a,b,c]",
                side_conditions: &[
                    "policy allows associativity",
                    "obligations safe (before/after)",
                    "cancel safe (before/after)",
                    "budget monotone (after <= before)",
                ],
                explanation: "Associativity of join: regrouping does not change outcomes.",
            },
            Self::RaceAssoc => RewriteRuleSchema {
                pattern: "Race[Race[a,b], c]",
                replacement: "Race[a,b,c]",
                side_conditions: &[
                    "policy allows associativity",
                    "obligations safe (before/after)",
                    "cancel safe (before/after)",
                    "budget monotone (after <= before)",
                ],
                explanation: "Associativity of race: regrouping preserves winner set.",
            },
            Self::JoinCommute => RewriteRuleSchema {
                pattern: "Join[a,b]",
                replacement: "Join[b,a] (canonical order)",
                side_conditions: &[
                    "policy allows commutativity",
                    "children pairwise independent",
                    "deterministic child order",
                    "obligations safe (before/after)",
                    "cancel safe (before/after)",
                    "budget monotone (after <= before)",
                ],
                explanation: "Commutativity of join when children are independent.",
            },
            Self::RaceCommute => RewriteRuleSchema {
                pattern: "Race[a,b]",
                replacement: "Race[b,a] (canonical order)",
                side_conditions: &[
                    "policy allows commutativity",
                    "children pairwise independent",
                    "deterministic child order",
                    "obligations safe (before/after)",
                    "cancel safe (before/after)",
                    "budget monotone (after <= before)",
                ],
                explanation: "Commutativity of race when children are independent.",
            },
            Self::TimeoutMin => RewriteRuleSchema {
                pattern: "Timeout(d1, Timeout(d2, f))",
                replacement: "Timeout(min(d1,d2), f)",
                side_conditions: &[
                    "obligations safe (before/after)",
                    "cancel safe (before/after)",
                    "budget monotone (after <= before)",
                ],
                explanation: "Nested timeouts reduce to the tighter deadline.",
            },
            Self::DedupRaceJoin => RewriteRuleSchema {
                pattern: "Race[Join[s,a], Join[s,b]]",
                replacement: "Join[s, Race[a,b]]",
                side_conditions: &[
                    "policy allows shared-child law",
                    "shared child leaf if conservative",
                    "joins binary if conservative",
                    "obligations safe (before/after)",
                    "cancel safe (before/after)",
                    "budget monotone (after <= before)",
                ],
                explanation: "Race/Join distributivity with shared work dedup.",
            },
        }
    }

    /// Returns all known rules in a stable order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        ALL_REWRITE_RULES
    }
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
                if let Some(step) = self.apply_rule_checked(id, policy, *rule) {
                    report.steps.push(step);
                }
            }
        }

        report
    }

    fn apply_rule_checked(
        &mut self,
        id: PlanId,
        policy: RewritePolicy,
        rule: RewriteRule,
    ) -> Option<RewriteStep> {
        let mut scratch = (*self).clone();
        let step = scratch.apply_rule_unchecked(id, policy, rule)?;
        let checker = SideConditionChecker::new(&scratch);
        if check_side_conditions(rule, policy, &checker, &scratch, step.before, step.after).is_err()
        {
            return None;
        }
        self.apply_rule_unchecked(id, policy, rule)
    }

    fn apply_rule_unchecked(
        &mut self,
        id: PlanId,
        policy: RewritePolicy,
        rule: RewriteRule,
    ) -> Option<RewriteStep> {
        match rule {
            RewriteRule::JoinAssoc => self.rewrite_join_assoc(id, policy),
            RewriteRule::RaceAssoc => self.rewrite_race_assoc(id, policy),
            RewriteRule::JoinCommute => self.rewrite_join_commute(id, policy),
            RewriteRule::RaceCommute => self.rewrite_race_commute(id, policy),
            RewriteRule::TimeoutMin => self.rewrite_timeout_min(id, policy),
            RewriteRule::DedupRaceJoin => self.rewrite_dedup_race_join(id, policy),
        }
    }

    fn rewrite_join_assoc(&mut self, id: PlanId, policy: RewritePolicy) -> Option<RewriteStep> {
        if !policy.allows_associative() {
            return None;
        }
        let PlanNode::Join { children } = self.node(id)?.clone() else {
            return None;
        };
        let mut flattened = Vec::with_capacity(children.len());
        let mut changed = false;
        for child in children {
            match self.node(child)? {
                PlanNode::Join { children } => {
                    flattened.extend(children.iter().copied());
                    changed = true;
                }
                _ => flattened.push(child),
            }
        }
        if !changed {
            return None;
        }

        let new_join_id = self.push_node(PlanNode::Join {
            children: flattened,
        });
        self.replace_parents(id, new_join_id);
        if self.root == Some(id) {
            self.root = Some(new_join_id);
        }
        Some(RewriteStep {
            rule: RewriteRule::JoinAssoc,
            before: id,
            after: new_join_id,
            detail: "flattened nested join".to_string(),
        })
    }

    fn rewrite_race_assoc(&mut self, id: PlanId, policy: RewritePolicy) -> Option<RewriteStep> {
        if !policy.allows_associative() {
            return None;
        }
        let PlanNode::Race { children } = self.node(id)?.clone() else {
            return None;
        };
        let mut flattened = Vec::with_capacity(children.len());
        let mut changed = false;
        for child in children {
            match self.node(child)? {
                PlanNode::Race { children } => {
                    flattened.extend(children.iter().copied());
                    changed = true;
                }
                _ => flattened.push(child),
            }
        }
        if !changed {
            return None;
        }

        let new_race_id = self.push_node(PlanNode::Race {
            children: flattened,
        });
        self.replace_parents(id, new_race_id);
        if self.root == Some(id) {
            self.root = Some(new_race_id);
        }
        Some(RewriteStep {
            rule: RewriteRule::RaceAssoc,
            before: id,
            after: new_race_id,
            detail: "flattened nested race".to_string(),
        })
    }

    fn rewrite_join_commute(&mut self, id: PlanId, policy: RewritePolicy) -> Option<RewriteStep> {
        if !policy.allows_commutative() {
            return None;
        }
        let PlanNode::Join { children } = self.node(id)?.clone() else {
            return None;
        };
        if children.len() < 2 {
            return None;
        }
        let mut ordered = children.clone();
        ordered.sort_by_key(|child| child.index());
        if ordered == children {
            return None;
        }
        let new_join_id = self.push_node(PlanNode::Join { children: ordered });
        self.replace_parents(id, new_join_id);
        if self.root == Some(id) {
            self.root = Some(new_join_id);
        }
        Some(RewriteStep {
            rule: RewriteRule::JoinCommute,
            before: id,
            after: new_join_id,
            detail: "reordered join children into canonical order".to_string(),
        })
    }

    fn rewrite_race_commute(&mut self, id: PlanId, policy: RewritePolicy) -> Option<RewriteStep> {
        if !policy.allows_commutative() {
            return None;
        }
        let PlanNode::Race { children } = self.node(id)?.clone() else {
            return None;
        };
        if children.len() < 2 {
            return None;
        }
        let mut ordered = children.clone();
        ordered.sort_by_key(|child| child.index());
        if ordered == children {
            return None;
        }
        let new_race_id = self.push_node(PlanNode::Race { children: ordered });
        self.replace_parents(id, new_race_id);
        if self.root == Some(id) {
            self.root = Some(new_race_id);
        }
        Some(RewriteStep {
            rule: RewriteRule::RaceCommute,
            before: id,
            after: new_race_id,
            detail: "reordered race children into canonical order".to_string(),
        })
    }

    fn rewrite_timeout_min(&mut self, id: PlanId, _policy: RewritePolicy) -> Option<RewriteStep> {
        let PlanNode::Timeout { child, duration } = self.node(id)?.clone() else {
            return None;
        };
        let PlanNode::Timeout {
            child: inner_child,
            duration: inner_duration,
        } = self.node(child)?.clone()
        else {
            return None;
        };
        let min_duration = if duration <= inner_duration {
            duration
        } else {
            inner_duration
        };
        let new_timeout_id = self.push_node(PlanNode::Timeout {
            child: inner_child,
            duration: min_duration,
        });
        self.replace_parents(id, new_timeout_id);
        if self.root == Some(id) {
            self.root = Some(new_timeout_id);
        }
        Some(RewriteStep {
            rule: RewriteRule::TimeoutMin,
            before: id,
            after: new_timeout_id,
            detail: "collapsed nested timeouts".to_string(),
        })
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

#[allow(clippy::too_many_lines)]
pub(crate) fn check_side_conditions(
    rule: RewriteRule,
    policy: RewritePolicy,
    checker: &SideConditionChecker<'_>,
    dag: &PlanDag,
    before: PlanId,
    after: PlanId,
) -> Result<(), String> {
    if !checker.obligations_safe(before) {
        return Err("obligations not safe before rewrite".to_string());
    }
    if !checker.obligations_safe(after) {
        return Err("obligations not safe after rewrite".to_string());
    }
    if !checker.cancel_safe(before) {
        return Err("cancel safety not satisfied before rewrite".to_string());
    }
    if !checker.cancel_safe(after) {
        return Err("cancel safety not satisfied after rewrite".to_string());
    }
    if !checker.rewrite_preserves_budget(before, after) {
        return Err("budget monotonicity violated".to_string());
    }

    match rule {
        RewriteRule::JoinAssoc | RewriteRule::RaceAssoc => {
            if !policy.allows_associative() {
                return Err("policy disallows associativity".to_string());
            }
        }
        RewriteRule::JoinCommute => {
            if !policy.allows_commutative() {
                return Err("policy disallows join commutation".to_string());
            }
            let PlanNode::Join { children } = dag
                .node(before)
                .ok_or_else(|| "missing before join".to_string())?
            else {
                return Err("before node is not Join".to_string());
            };
            if !checker.children_pairwise_independent(children) {
                return Err("join children not pairwise independent".to_string());
            }
            let PlanNode::Join {
                children: after_children,
            } = dag
                .node(after)
                .ok_or_else(|| "missing after join".to_string())?
            else {
                return Err("after node is not Join".to_string());
            };
            if !same_children_unordered(children, after_children) {
                return Err("join children mismatch after commutation".to_string());
            }
            if !is_sorted_children(after_children) {
                return Err("join children not in canonical order".to_string());
            }
        }
        RewriteRule::RaceCommute => {
            if !policy.allows_commutative() {
                return Err("policy disallows race commutation".to_string());
            }
            let PlanNode::Race { children } = dag
                .node(before)
                .ok_or_else(|| "missing before race".to_string())?
            else {
                return Err("before node is not Race".to_string());
            };
            if !checker.children_pairwise_independent(children) {
                return Err("race children not pairwise independent".to_string());
            }
            let PlanNode::Race {
                children: after_children,
            } = dag
                .node(after)
                .ok_or_else(|| "missing after race".to_string())?
            else {
                return Err("after node is not Race".to_string());
            };
            if !same_children_unordered(children, after_children) {
                return Err("race children mismatch after commutation".to_string());
            }
            if !is_sorted_children(after_children) {
                return Err("race children not in canonical order".to_string());
            }
        }
        RewriteRule::TimeoutMin => {
            let PlanNode::Timeout { child, duration } = dag
                .node(before)
                .ok_or_else(|| "missing before timeout".to_string())?
            else {
                return Err("before node is not Timeout".to_string());
            };
            let PlanNode::Timeout {
                child: inner_child,
                duration: inner_duration,
            } = dag
                .node(*child)
                .ok_or_else(|| "missing inner timeout".to_string())?
            else {
                return Err("before timeout child is not Timeout".to_string());
            };
            let PlanNode::Timeout {
                child: after_child,
                duration: after_duration,
            } = dag
                .node(after)
                .ok_or_else(|| "missing after timeout".to_string())?
            else {
                return Err("after node is not Timeout".to_string());
            };
            let min_duration = if duration <= inner_duration {
                duration
            } else {
                inner_duration
            };
            if after_child != inner_child {
                return Err("timeout min child mismatch".to_string());
            }
            if after_duration != min_duration {
                return Err("timeout min duration mismatch".to_string());
            }
        }
        RewriteRule::DedupRaceJoin => {
            let PlanNode::Race { children } = dag
                .node(before)
                .ok_or_else(|| "missing before race".to_string())?
            else {
                return Err("before node is not Race".to_string());
            };
            if children.len() < 2 {
                return Err("dedup requires race with at least 2 children".to_string());
            }
            if policy.requires_binary_joins() && children.len() != 2 {
                return Err("policy requires binary joins".to_string());
            }

            let mut join_children: Vec<Vec<PlanId>> = Vec::with_capacity(children.len());
            for child in children {
                let PlanNode::Join { children } = dag
                    .node(*child)
                    .ok_or_else(|| "missing join child".to_string())?
                else {
                    return Err("race child is not Join".to_string());
                };
                if policy.requires_binary_joins() && children.len() != 2 {
                    return Err("policy requires binary joins".to_string());
                }
                join_children.push(children.clone());
            }

            let mut intersection: HashSet<PlanId> =
                join_children[0].iter().copied().collect();
            for nodes in join_children.iter().skip(1) {
                let set: HashSet<PlanId> = nodes.iter().copied().collect();
                intersection.retain(|id| set.contains(id));
            }
            if intersection.len() != 1 {
                return Err("dedup requires exactly one shared child".to_string());
            }
            let shared = *intersection.iter().next().expect("len == 1");
            if !policy.allows_shared_non_leaf() {
                match dag.node(shared) {
                    Some(PlanNode::Leaf { .. }) => {}
                    _ => return Err("shared child must be Leaf in conservative policy".to_string()),
                }
            }

            let PlanNode::Join {
                children: after_children,
            } = dag
                .node(after)
                .ok_or_else(|| "missing after join".to_string())?
            else {
                return Err("after node is not Join".to_string());
            };
            if after_children.len() != 2 {
                return Err("after join must have exactly two children".to_string());
            }
            let race_candidate = if after_children[0] == shared {
                after_children[1]
            } else if after_children[1] == shared {
                after_children[0]
            } else {
                return Err("after join missing shared child".to_string());
            };

            let actual_branches: Vec<PlanId> = match dag.node(race_candidate) {
                Some(PlanNode::Race { children }) => children.clone(),
                Some(_) => vec![race_candidate],
                None => return Err("missing race candidate".to_string()),
            };

            let mut expected_signatures: Vec<Vec<usize>> =
                Vec::with_capacity(join_children.len());
            for nodes in &join_children {
                let mut remaining: Vec<PlanId> =
                    nodes.iter().copied().filter(|id| *id != shared).collect();
                if remaining.is_empty() {
                    return Err("dedup rewrite has empty branch".to_string());
                }
                if policy.requires_binary_joins() && remaining.len() != 1 {
                    return Err("policy requires binary joins".to_string());
                }
                if remaining.len() == 1 {
                    expected_signatures.push(vec![remaining[0].index()]);
                } else {
                    remaining.sort_by_key(|id| id.index());
                    expected_signatures.push(remaining.iter().map(|id| id.index()).collect());
                }
            }

            let mut actual_signatures: Vec<Vec<usize>> =
                Vec::with_capacity(actual_branches.len());
            for branch in actual_branches {
                actual_signatures.push(branch_signature(dag, branch)?);
            }
            expected_signatures.sort();
            actual_signatures.sort();
            if expected_signatures != actual_signatures {
                return Err("dedup race-join branches mismatch".to_string());
            }
        }
    }

    Ok(())
}

fn branch_signature(dag: &PlanDag, id: PlanId) -> Result<Vec<usize>, String> {
    match dag.node(id) {
        Some(PlanNode::Join { children }) => {
            let mut sig: Vec<usize> = children.iter().map(|id| id.index()).collect();
            sig.sort_unstable();
            Ok(sig)
        }
        Some(_) => Ok(vec![id.index()]),
        None => Err("missing branch node".to_string()),
    }
}

fn same_children_unordered(a: &[PlanId], b: &[PlanId]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut left = a.to_vec();
    let mut right = b.to_vec();
    left.sort_by_key(|id| id.index());
    right.sort_by_key(|id| id.index());
    left == right
}

fn is_sorted_children(children: &[PlanId]) -> bool {
    children
        .windows(2)
        .all(|pair| pair[0].index() <= pair[1].index())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use std::time::Duration;

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

    #[test]
    fn test_join_assoc_flattens_nested_join() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let inner = dag.join(vec![a, b]);
        let outer = dag.join(vec![inner, c]);
        dag.set_root(outer);

        let report = dag.apply_rewrites(RewritePolicy::Conservative, &[RewriteRule::JoinAssoc]);
        assert_eq!(report.steps().len(), 1);
        let root = dag.root().expect("root");
        let PlanNode::Join { children } = dag.node(root).expect("join") else {
            panic!("expected join root");
        };
        assert_eq!(children.len(), 3);
    }

    #[test]
    fn test_race_assoc_flattens_nested_race() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let inner = dag.race(vec![a, b]);
        let outer = dag.race(vec![inner, c]);
        dag.set_root(outer);

        let report = dag.apply_rewrites(RewritePolicy::Conservative, &[RewriteRule::RaceAssoc]);
        assert_eq!(report.steps().len(), 1);
        let root = dag.root().expect("root");
        let PlanNode::Race { children } = dag.node(root).expect("race") else {
            panic!("expected race root");
        };
        assert_eq!(children.len(), 3);
    }

    #[test]
    fn test_join_commute_canonical_order() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let join = dag.join(vec![c, b, a]);
        dag.set_root(join);

        let report = dag.apply_rewrites(
            RewritePolicy::AssumeAssociativeComm,
            &[RewriteRule::JoinCommute],
        );
        assert_eq!(report.steps().len(), 1);
        let root = dag.root().expect("root");
        let PlanNode::Join { children } = dag.node(root).expect("join") else {
            panic!("expected join root");
        };
        let indices: Vec<_> = children.iter().map(|id| id.index()).collect();
        assert_eq!(indices, vec![a.index(), b.index(), c.index()]);
    }

    #[test]
    fn test_join_commute_rejects_shared_subtree() {
        init_test();
        let mut dag = PlanDag::new();
        let s = dag.leaf("s");
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let j1 = dag.join(vec![s, a]);
        let j2 = dag.join(vec![s, b]);
        let join = dag.join(vec![j1, j2]);
        dag.set_root(join);

        let report = dag.apply_rewrites(
            RewritePolicy::AssumeAssociativeComm,
            &[RewriteRule::JoinCommute],
        );
        assert!(report.is_empty());
    }

    #[test]
    fn test_race_commute_canonical_order() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let race = dag.race(vec![c, b, a]);
        dag.set_root(race);

        let report = dag.apply_rewrites(
            RewritePolicy::AssumeAssociativeComm,
            &[RewriteRule::RaceCommute],
        );
        assert_eq!(report.steps().len(), 1);
        let root = dag.root().expect("root");
        let PlanNode::Race { children } = dag.node(root).expect("race") else {
            panic!("expected race root");
        };
        let indices: Vec<_> = children.iter().map(|id| id.index()).collect();
        assert_eq!(indices, vec![a.index(), b.index(), c.index()]);
    }

    #[test]
    fn test_timeout_min_collapses_nested_timeouts() {
        init_test();
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let inner = dag.timeout(a, Duration::from_secs(10));
        let outer = dag.timeout(inner, Duration::from_secs(5));
        dag.set_root(outer);

        let report = dag.apply_rewrites(RewritePolicy::Conservative, &[RewriteRule::TimeoutMin]);
        assert_eq!(report.steps().len(), 1);
        let root = dag.root().expect("root");
        let PlanNode::Timeout { duration, child } = dag.node(root).expect("timeout") else {
            panic!("expected timeout root");
        };
        assert_eq!(*duration, Duration::from_secs(5));
        assert_eq!(*child, a);
    }

    #[test]
    fn rule_schema_has_explanations() {
        init_test();
        for rule in RewriteRule::all() {
            let schema = rule.schema();
            assert!(!schema.pattern.is_empty());
            assert!(!schema.replacement.is_empty());
            assert!(!schema.explanation.is_empty());
            assert!(!schema.side_conditions.is_empty());
        }
    }
}
