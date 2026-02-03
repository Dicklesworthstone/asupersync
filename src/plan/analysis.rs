//! Static analysis domain for plan DAG applicability checking.
//!
//! Provides conservative analyses that answer side-condition queries for
//! the rewrite engine and certificate verifier:
//!
//! - **Obligation safety**: Does this plan structure leak obligations?
//! - **Cancel safety**: Are race losers properly drained?
//! - **Budget effects**: What are the budget effects of a plan node?
//!
//! All results are deterministic and conservative: the analysis never claims
//! a property unless it is guaranteed by the plan structure.

use super::{PlanDag, PlanId, PlanNode};
use std::collections::BTreeMap;
use std::fmt;

// ===========================================================================
// Obligation flow analysis
// ===========================================================================

/// Abstract obligation state for a plan node.
///
/// Models whether obligations flowing through a node are guaranteed to be
/// resolved. The lattice is:
/// ```text
///       Unknown
///      /       \
///   Clean    MayLeak
///      \       /
///      Leaked
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObligationSafety {
    /// All obligations are resolved on every path through this node.
    Clean,
    /// Obligations may leak on some paths (conservative: uncertain).
    MayLeak,
    /// Obligations definitely leak (e.g., unreachable cleanup path).
    Leaked,
    /// Insufficient information to determine safety.
    Unknown,
}

impl ObligationSafety {
    /// Lattice join: the least-safe of two states.
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        use ObligationSafety::{Clean, Leaked, MayLeak, Unknown};
        match (self, other) {
            (Clean, Clean) => Clean,
            (Leaked, _) | (_, Leaked) => Leaked,
            (MayLeak, _) | (_, MayLeak) => MayLeak,
            (Unknown, _) | (_, Unknown) => Unknown,
        }
    }

    /// Returns true if obligations are guaranteed safe.
    #[must_use]
    pub fn is_safe(self) -> bool {
        matches!(self, Self::Clean)
    }
}

impl fmt::Display for ObligationSafety {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => f.write_str("clean"),
            Self::MayLeak => f.write_str("may-leak"),
            Self::Leaked => f.write_str("leaked"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

// ===========================================================================
// Cancel safety analysis
// ===========================================================================

/// Cancel safety for a plan node.
///
/// Models whether race losers are guaranteed to be drained after cancellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CancelSafety {
    /// No cancel concerns: node has no races, or all races properly drain losers.
    Safe,
    /// Races exist but losers may not be fully drained.
    MayOrphan,
    /// Races definitely leave orphan tasks.
    Orphan,
    /// Insufficient information.
    Unknown,
}

impl CancelSafety {
    /// Lattice join: the least-safe of two states.
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        use CancelSafety::{MayOrphan, Orphan, Safe, Unknown};
        match (self, other) {
            (Safe, Safe) => Safe,
            (Orphan, _) | (_, Orphan) => Orphan,
            (MayOrphan, _) | (_, MayOrphan) => MayOrphan,
            (Unknown, _) | (_, Unknown) => Unknown,
        }
    }

    /// Returns true if cancel behavior is guaranteed safe.
    #[must_use]
    pub fn is_safe(self) -> bool {
        matches!(self, Self::Safe)
    }
}

impl fmt::Display for CancelSafety {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Safe => f.write_str("safe"),
            Self::MayOrphan => f.write_str("may-orphan"),
            Self::Orphan => f.write_str("orphan"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

// ===========================================================================
// Budget effects
// ===========================================================================

/// Conservative budget effect summary for a plan node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetEffect {
    /// Minimum number of poll steps on the critical path.
    pub min_polls: u32,
    /// Maximum number of poll steps on the critical path (None = unbounded).
    pub max_polls: Option<u32>,
    /// Whether the node introduces a deadline (via Timeout).
    pub has_deadline: bool,
    /// Number of concurrent branches (for cost estimation).
    pub parallelism: u32,
}

impl BudgetEffect {
    /// A zero-cost effect (leaf with single poll).
    pub const LEAF: Self = Self {
        min_polls: 1,
        max_polls: Some(1),
        has_deadline: false,
        parallelism: 1,
    };

    /// An unknown effect (conservative: unbounded).
    pub const UNKNOWN: Self = Self {
        min_polls: 0,
        max_polls: None,
        has_deadline: false,
        parallelism: 1,
    };
}

impl fmt::Display for BudgetEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "polls=[{}, ", self.min_polls)?;
        match self.max_polls {
            Some(max) => write!(f, "{max}]")?,
            None => f.write_str("∞]")?,
        }
        if self.has_deadline {
            f.write_str(" +deadline")?;
        }
        if self.parallelism > 1 {
            write!(f, " par={}", self.parallelism)?;
        }
        Ok(())
    }
}

// ===========================================================================
// Per-node analysis result
// ===========================================================================

/// Complete analysis result for a single plan node.
#[derive(Debug, Clone)]
pub struct NodeAnalysis {
    /// Node identifier.
    pub id: PlanId,
    /// Obligation safety.
    pub obligation: ObligationSafety,
    /// Cancel safety.
    pub cancel: CancelSafety,
    /// Budget effects.
    pub budget: BudgetEffect,
}

impl NodeAnalysis {
    /// Returns true if the node is safe on all dimensions.
    #[must_use]
    pub fn is_safe(&self) -> bool {
        self.obligation.is_safe() && self.cancel.is_safe()
    }
}

// ===========================================================================
// Plan analysis report
// ===========================================================================

/// Full analysis report for a plan DAG.
///
/// Results are stored in a `BTreeMap` for deterministic iteration order.
#[derive(Debug, Clone)]
pub struct PlanAnalysis {
    /// Per-node analysis results, keyed by `PlanId`.
    pub nodes: BTreeMap<usize, NodeAnalysis>,
}

impl PlanAnalysis {
    /// Returns true if every reachable node is safe on all dimensions.
    #[must_use]
    pub fn all_safe(&self) -> bool {
        self.nodes.values().all(NodeAnalysis::is_safe)
    }

    /// Returns the analysis for a specific node.
    #[must_use]
    pub fn get(&self, id: PlanId) -> Option<&NodeAnalysis> {
        self.nodes.get(&id.index())
    }

    /// Returns all nodes that have obligation issues.
    #[must_use]
    pub fn obligation_issues(&self) -> Vec<&NodeAnalysis> {
        self.nodes
            .values()
            .filter(|n| !n.obligation.is_safe())
            .collect()
    }

    /// Returns all nodes that have cancel safety issues.
    #[must_use]
    pub fn cancel_issues(&self) -> Vec<&NodeAnalysis> {
        self.nodes
            .values()
            .filter(|n| !n.cancel.is_safe())
            .collect()
    }

    /// Returns a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let total = self.nodes.len();
        let safe = self.nodes.values().filter(|n| n.is_safe()).count();
        let obl_issues = self.obligation_issues().len();
        let cancel_issues = self.cancel_issues().len();
        format!(
            "{safe}/{total} safe, {obl_issues} obligation issue(s), {cancel_issues} cancel issue(s)"
        )
    }
}

// ===========================================================================
// Analyzer
// ===========================================================================

/// Static analyzer for plan DAGs.
///
/// Computes per-node obligation safety, cancel safety, and budget effects
/// via a single bottom-up pass over the DAG.
pub struct PlanAnalyzer;

impl PlanAnalyzer {
    /// Analyze all reachable nodes in the DAG.
    ///
    /// Performs a bottom-up traversal from leaves to root, computing analyses
    /// for each node. Results are deterministic.
    #[must_use]
    pub fn analyze(dag: &PlanDag) -> PlanAnalysis {
        let mut results = BTreeMap::new();
        let Some(root) = dag.root() else {
            return PlanAnalysis { nodes: results };
        };
        Self::analyze_node(dag, root, &mut results);
        PlanAnalysis { nodes: results }
    }

    #[allow(clippy::too_many_lines)]
    fn analyze_node(
        dag: &PlanDag,
        id: PlanId,
        results: &mut BTreeMap<usize, NodeAnalysis>,
    ) -> NodeAnalysis {
        if let Some(existing) = results.get(&id.index()) {
            return existing.clone();
        }

        let Some(node) = dag.node(id) else {
            let analysis = NodeAnalysis {
                id,
                obligation: ObligationSafety::Unknown,
                cancel: CancelSafety::Unknown,
                budget: BudgetEffect::UNKNOWN,
            };
            results.insert(id.index(), analysis.clone());
            return analysis;
        };

        let analysis = match node.clone() {
            PlanNode::Leaf { .. } => NodeAnalysis {
                id,
                obligation: ObligationSafety::Clean,
                cancel: CancelSafety::Safe,
                budget: BudgetEffect::LEAF,
            },

            PlanNode::Join { children } => {
                let child_analyses: Vec<NodeAnalysis> = children
                    .iter()
                    .map(|c| Self::analyze_node(dag, *c, results))
                    .collect();

                // Join obligation safety: all children must be clean.
                let obligation = child_analyses
                    .iter()
                    .map(|a| a.obligation)
                    .fold(ObligationSafety::Clean, ObligationSafety::join);

                // Join cancel safety: all children must be safe.
                let cancel = child_analyses
                    .iter()
                    .map(|a| a.cancel)
                    .fold(CancelSafety::Safe, CancelSafety::join);

                // Join budget: sum of polls (all children must complete),
                // max parallelism is sum of children's parallelism.
                let min_polls = child_analyses.iter().map(|a| a.budget.min_polls).sum();
                let max_polls = child_analyses.iter().try_fold(0u32, |acc, a| {
                    a.budget.max_polls.map(|m| acc.saturating_add(m))
                });
                let has_deadline = child_analyses.iter().any(|a| a.budget.has_deadline);
                let parallelism = child_analyses
                    .iter()
                    .map(|a| a.budget.parallelism)
                    .sum::<u32>()
                    .max(1);

                NodeAnalysis {
                    id,
                    obligation,
                    cancel,
                    budget: BudgetEffect {
                        min_polls,
                        max_polls,
                        has_deadline,
                        parallelism,
                    },
                }
            }

            PlanNode::Race { children } => {
                let child_analyses: Vec<NodeAnalysis> = children
                    .iter()
                    .map(|c| Self::analyze_node(dag, *c, results))
                    .collect();

                // Race obligation safety: losers are cancelled, so obligations
                // in losers must be abortable. Conservatively, if any child
                // has obligation issues, the race inherits them.
                let obligation = child_analyses
                    .iter()
                    .map(|a| a.obligation)
                    .fold(ObligationSafety::Clean, ObligationSafety::join);

                // Race cancel safety: the race itself introduces cancel
                // concerns — losers must be drained. If children have
                // complex structure (nested races, joins with obligations),
                // we conservatively mark as MayOrphan.
                let child_cancel = child_analyses
                    .iter()
                    .map(|a| a.cancel)
                    .fold(CancelSafety::Safe, CancelSafety::join);
                // A race with >1 children always introduces cancel pressure:
                // losers are cancelled. If all children are simple (Safe cancel
                // + Clean obligations), the race is safe because draining is
                // straightforward. Otherwise, be conservative.
                let cancel = if children.len() <= 1 {
                    child_cancel
                } else if child_cancel.is_safe()
                    && child_analyses.iter().all(|a| a.obligation.is_safe())
                {
                    CancelSafety::Safe
                } else {
                    child_cancel.join(CancelSafety::MayOrphan)
                };

                // Race budget: min of children (winner completes first),
                // parallelism is max (children race concurrently).
                let min_polls = child_analyses
                    .iter()
                    .map(|a| a.budget.min_polls)
                    .min()
                    .unwrap_or(0);
                let max_polls = child_analyses.iter().try_fold(0u32, |acc, a| {
                    a.budget.max_polls.map(|m| acc.max(m))
                });
                let has_deadline = child_analyses.iter().any(|a| a.budget.has_deadline);
                let parallelism = child_analyses
                    .iter()
                    .map(|a| a.budget.parallelism)
                    .max()
                    .unwrap_or(1);

                NodeAnalysis {
                    id,
                    obligation,
                    cancel,
                    budget: BudgetEffect {
                        min_polls,
                        max_polls,
                        has_deadline,
                        parallelism,
                    },
                }
            }

            PlanNode::Timeout { child, .. } => {
                let child_analysis = Self::analyze_node(dag, child, results);

                NodeAnalysis {
                    id,
                    obligation: child_analysis.obligation,
                    // Timeout introduces cancel: if child exceeds the deadline,
                    // it is cancelled. Same logic as race with deadline branch.
                    cancel: if child_analysis.cancel.is_safe()
                        && child_analysis.obligation.is_safe()
                    {
                        CancelSafety::Safe
                    } else {
                        child_analysis.cancel.join(CancelSafety::MayOrphan)
                    },
                    budget: BudgetEffect {
                        min_polls: child_analysis.budget.min_polls,
                        max_polls: child_analysis.budget.max_polls,
                        has_deadline: true,
                        parallelism: child_analysis.budget.parallelism,
                    },
                }
            }
        };

        results.insert(id.index(), analysis.clone());
        analysis
    }
}

// ===========================================================================
// Side-condition queries for the rewrite engine
// ===========================================================================

/// Answers side-condition queries for plan rewrites.
///
/// Used by the certificate verifier and rewrite engine to check whether
/// a rewrite is safe to apply.
pub struct SideConditionChecker<'a> {
    dag: &'a PlanDag,
    analysis: PlanAnalysis,
}

impl<'a> SideConditionChecker<'a> {
    /// Creates a new checker, running the analysis eagerly.
    #[must_use]
    pub fn new(dag: &'a PlanDag) -> Self {
        let analysis = PlanAnalyzer::analyze(dag);
        Self { dag, analysis }
    }

    /// Returns the underlying analysis.
    #[must_use]
    pub fn analysis(&self) -> &PlanAnalysis {
        &self.analysis
    }

    /// Check if a node's children are obligation-safe (no leaks).
    #[must_use]
    pub fn obligations_safe(&self, id: PlanId) -> bool {
        self.analysis
            .get(id)
            .is_some_and(|a| a.obligation.is_safe())
    }

    /// Check if a node's cancel behavior is safe (losers drained).
    #[must_use]
    pub fn cancel_safe(&self, id: PlanId) -> bool {
        self.analysis
            .get(id)
            .is_some_and(|a| a.cancel.is_safe())
    }

    /// Check if two subtrees are independent (no shared mutable state).
    ///
    /// Conservative: returns true only if neither subtree contains nodes
    /// that appear in the other's reachable set. This is a structural
    /// check — it cannot detect aliased external state.
    #[must_use]
    pub fn are_independent(&self, a: PlanId, b: PlanId) -> bool {
        let reachable_a = self.reachable(a);
        let reachable_b = self.reachable(b);
        // No node appears in both reachable sets.
        reachable_a.iter().all(|id| !reachable_b.contains(id))
    }

    /// Check if a rewrite from `before` to `after` preserves obligation safety.
    ///
    /// Conservative: requires both the before and after nodes to be obligation-safe.
    #[must_use]
    pub fn rewrite_preserves_obligations(&self, before: PlanId, after: PlanId) -> bool {
        self.obligations_safe(before) && self.obligations_safe(after)
    }

    /// Check if a rewrite preserves cancel safety.
    #[must_use]
    pub fn rewrite_preserves_cancel(&self, before: PlanId, after: PlanId) -> bool {
        self.cancel_safe(before) && self.cancel_safe(after)
    }

    /// Collect all node ids reachable from a given node.
    fn reachable(&self, id: PlanId) -> Vec<usize> {
        let mut visited = Vec::new();
        self.reachable_inner(id, &mut visited);
        visited
    }

    fn reachable_inner(&self, id: PlanId, visited: &mut Vec<usize>) {
        if visited.contains(&id.index()) {
            return;
        }
        visited.push(id.index());
        let Some(node) = self.dag.node(id) else {
            return;
        };
        match node {
            PlanNode::Leaf { .. } => {}
            PlanNode::Join { children } | PlanNode::Race { children } => {
                for child in children {
                    self.reachable_inner(*child, visited);
                }
            }
            PlanNode::Timeout { child, .. } => {
                self.reachable_inner(*child, visited);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn leaf_dag(label: &str) -> (PlanDag, PlanId) {
        let mut dag = PlanDag::new();
        let id = dag.leaf(label);
        dag.set_root(id);
        (dag, id)
    }

    // ---- Leaf analysis ----

    #[test]
    fn leaf_is_fully_safe() {
        let (dag, root) = leaf_dag("a");
        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(root).expect("root analyzed");
        assert!(node.is_safe());
        assert_eq!(node.obligation, ObligationSafety::Clean);
        assert_eq!(node.cancel, CancelSafety::Safe);
        assert_eq!(node.budget.min_polls, 1);
        assert_eq!(node.budget.max_polls, Some(1));
    }

    // ---- Join analysis ----

    #[test]
    fn join_of_leaves_is_safe() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(join).expect("join analyzed");
        assert!(node.is_safe());
        assert_eq!(node.budget.min_polls, 2);
        assert_eq!(node.budget.max_polls, Some(2));
        assert_eq!(node.budget.parallelism, 2);
    }

    // ---- Race analysis ----

    #[test]
    fn race_of_leaves_is_safe() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let race = dag.race(vec![a, b]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(race).expect("race analyzed");
        assert!(node.is_safe());
        assert_eq!(node.budget.min_polls, 1);
        assert_eq!(node.budget.max_polls, Some(1));
    }

    // ---- Timeout analysis ----

    #[test]
    fn timeout_adds_deadline() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t = dag.timeout(a, Duration::from_secs(5));
        dag.set_root(t);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(t).expect("timeout analyzed");
        assert!(node.is_safe());
        assert!(node.budget.has_deadline);
    }

    // ---- Composite: Race[Join[s,a], Join[s,b]] (the DedupRaceJoin pattern) ----

    #[test]
    fn dedup_race_join_pattern_is_safe() {
        let mut dag = PlanDag::new();
        let s = dag.leaf("s");
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let j1 = dag.join(vec![s, a]);
        let j2 = dag.join(vec![s, b]);
        let race = dag.race(vec![j1, j2]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        assert!(analysis.all_safe());
    }

    // ---- Rewritten form: Join[s, Race[a, b]] ----

    #[test]
    fn rewritten_form_is_safe() {
        let mut dag = PlanDag::new();
        let s = dag.leaf("s");
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let race = dag.race(vec![a, b]);
        let join = dag.join(vec![s, race]);
        dag.set_root(join);

        let analysis = PlanAnalyzer::analyze(&dag);
        assert!(analysis.all_safe());
    }

    // ---- Empty DAG ----

    #[test]
    fn empty_dag_analysis() {
        let dag = PlanDag::new();
        let analysis = PlanAnalyzer::analyze(&dag);
        assert!(analysis.all_safe());
        assert!(analysis.nodes.is_empty());
    }

    // ---- Side condition checker ----

    #[test]
    fn side_condition_independence() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let checker = SideConditionChecker::new(&dag);
        assert!(checker.are_independent(a, b));
    }

    #[test]
    fn shared_child_not_independent() {
        let mut dag = PlanDag::new();
        let s = dag.leaf("s");
        let a = dag.leaf("a");
        let j1 = dag.join(vec![s, a]);
        let j2 = dag.join(vec![s]);
        let race = dag.race(vec![j1, j2]);
        dag.set_root(race);

        let checker = SideConditionChecker::new(&dag);
        // j1 and j2 share s
        assert!(!checker.are_independent(j1, j2));
    }

    // ---- Rewrite preservation ----

    #[test]
    fn rewrite_preserves_safety_for_leaves() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let checker = SideConditionChecker::new(&dag);
        assert!(checker.rewrite_preserves_obligations(a, b));
        assert!(checker.rewrite_preserves_cancel(a, b));
    }

    // ---- Summary ----

    #[test]
    fn analysis_summary_format() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        dag.set_root(join);

        let analysis = PlanAnalyzer::analyze(&dag);
        let summary = analysis.summary();
        assert!(summary.contains("3/3 safe"));
    }

    // ---- Display impls ----

    #[test]
    fn display_impls() {
        assert_eq!(format!("{}", ObligationSafety::Clean), "clean");
        assert_eq!(format!("{}", CancelSafety::MayOrphan), "may-orphan");
        assert_eq!(format!("{}", BudgetEffect::LEAF), "polls=[1, 1]");
    }

    // ---- Deterministic ordering ----

    #[test]
    fn analysis_is_deterministic() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let j = dag.join(vec![a, b]);
        let r = dag.race(vec![j, c]);
        dag.set_root(r);

        let a1 = PlanAnalyzer::analyze(&dag);
        let a2 = PlanAnalyzer::analyze(&dag);
        // Same keys in same order.
        let keys1: Vec<usize> = a1.nodes.keys().copied().collect();
        let keys2: Vec<usize> = a2.nodes.keys().copied().collect();
        assert_eq!(keys1, keys2);
        // Same obligation safety.
        for (k, v1) in &a1.nodes {
            let v2 = a2.nodes.get(k).expect("key exists");
            assert_eq!(v1.obligation, v2.obligation);
            assert_eq!(v1.cancel, v2.cancel);
        }
    }
}
