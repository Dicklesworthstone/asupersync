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
// Deadline bounds (for rewrite safety side conditions)
// ===========================================================================

/// Bound on a deadline duration (microseconds for precision).
///
/// Uses microseconds internally to avoid floating point while supporting
/// sub-millisecond precision. This is a min-plus semiring element where:
/// - `None` = +∞ (unbounded)
/// - `Some(n)` = finite bound of n microseconds
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeadlineMicros(pub Option<u64>);

impl DeadlineMicros {
    /// Unbounded deadline (no constraint).
    pub const UNBOUNDED: Self = Self(None);

    /// Zero deadline (instant).
    pub const ZERO: Self = Self(Some(0));

    /// Creates a deadline from microseconds.
    #[must_use]
    pub const fn from_micros(micros: u64) -> Self {
        Self(Some(micros))
    }

    /// Creates a deadline from a Duration.
    #[must_use]
    pub fn from_duration(d: std::time::Duration) -> Self {
        Self(Some(d.as_micros().try_into().unwrap_or(u64::MAX)))
    }

    /// Returns the inner value (None = unbounded).
    #[must_use]
    pub const fn as_micros(self) -> Option<u64> {
        self.0
    }

    /// Returns true if this deadline is unbounded.
    #[must_use]
    pub const fn is_unbounded(self) -> bool {
        self.0.is_none()
    }

    /// Min-plus addition: min(a, b) in the deadline semiring.
    ///
    /// The tighter (smaller) deadline wins.
    #[must_use]
    pub fn min(self, other: Self) -> Self {
        match (self.0, other.0) {
            (None, _) => other,
            (_, None) => self,
            (Some(a), Some(b)) => Self(Some(a.min(b))),
        }
    }

    /// Min-plus "multiplication": a + b (sequential composition).
    ///
    /// Sequential work adds deadlines.
    #[must_use]
    pub fn add(self, other: Self) -> Self {
        match (self.0, other.0) {
            (None, _) | (_, None) => Self::UNBOUNDED,
            (Some(a), Some(b)) => Self(Some(a.saturating_add(b))),
        }
    }

    /// Returns true if `self` is at least as tight as `other`.
    ///
    /// Used for rewrite safety: a rewrite is safe if the new deadline
    /// is at least as tight as the original.
    #[must_use]
    pub fn is_at_least_as_tight_as(self, other: Self) -> bool {
        match (self.0, other.0) {
            (_, None) => true,           // anything is as tight as unbounded
            (None, Some(_)) => false,    // unbounded is looser than any bound
            (Some(a), Some(b)) => a <= b, // tighter means smaller
        }
    }
}

impl fmt::Display for DeadlineMicros {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            None => f.write_str("∞"),
            Some(us) if us >= 1_000_000 => write!(f, "{}s", us / 1_000_000),
            Some(us) if us >= 1_000 => write!(f, "{}ms", us / 1_000),
            Some(us) => write!(f, "{}µs", us),
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
    /// Minimum deadline bound (tightest deadline on any path).
    pub min_deadline: DeadlineMicros,
    /// Maximum deadline bound (loosest deadline, for worst-case analysis).
    pub max_deadline: DeadlineMicros,
}

impl BudgetEffect {
    /// A zero-cost effect (leaf with single poll).
    pub const LEAF: Self = Self {
        min_polls: 1,
        max_polls: Some(1),
        has_deadline: false,
        parallelism: 1,
        min_deadline: DeadlineMicros::UNBOUNDED,
        max_deadline: DeadlineMicros::UNBOUNDED,
    };

    /// An unknown effect (conservative: unbounded).
    pub const UNKNOWN: Self = Self {
        min_polls: 0,
        max_polls: None,
        has_deadline: false,
        parallelism: 1,
        min_deadline: DeadlineMicros::UNBOUNDED,
        max_deadline: DeadlineMicros::UNBOUNDED,
    };

    /// Creates a budget effect with a specific deadline.
    #[must_use]
    pub const fn with_deadline(mut self, deadline: DeadlineMicros) -> Self {
        self.has_deadline = true;
        self.min_deadline = deadline;
        self.max_deadline = deadline;
        self
    }

    /// Sequential composition (Join semantics): both effects must complete.
    ///
    /// Polls sum, deadlines add (sequential work).
    #[must_use]
    pub fn sequential(self, other: Self) -> Self {
        Self {
            min_polls: self.min_polls.saturating_add(other.min_polls),
            max_polls: match (self.max_polls, other.max_polls) {
                (Some(a), Some(b)) => Some(a.saturating_add(b)),
                _ => None,
            },
            has_deadline: self.has_deadline || other.has_deadline,
            parallelism: self.parallelism.max(other.parallelism),
            // Tightest deadline in sequence (min of mins)
            min_deadline: self.min_deadline.min(other.min_deadline),
            // Loosest deadline in sequence (we need both to complete)
            max_deadline: self.max_deadline.add(other.max_deadline),
        }
    }

    /// Parallel composition (Race semantics): first to complete wins.
    ///
    /// Polls take min (fastest path), deadlines take min (tightest constraint).
    #[must_use]
    pub fn parallel(self, other: Self) -> Self {
        Self {
            min_polls: self.min_polls.min(other.min_polls),
            max_polls: match (self.max_polls, other.max_polls) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            },
            has_deadline: self.has_deadline || other.has_deadline,
            parallelism: self.parallelism.max(other.parallelism),
            // In a race, the tightest deadline applies
            min_deadline: self.min_deadline.min(other.min_deadline),
            max_deadline: self.max_deadline.min(other.max_deadline),
        }
    }

    /// Returns true if this effect is no worse than `before`.
    ///
    /// "No worse" means:
    /// - does not remove a deadline
    /// - does not increase the minimum polls required
    /// - does not increase (or unbound) the maximum polls when previously bounded
    /// - does not loosen the deadline guarantee
    #[must_use]
    pub fn is_not_worse_than(self, before: Self) -> bool {
        if before.has_deadline && !self.has_deadline {
            return false;
        }
        if self.min_polls > before.min_polls {
            return false;
        }
        if let Some(max_before) = before.max_polls {
            match self.max_polls {
                Some(max_after) if max_after <= max_before => {}
                _ => return false,
            }
        }
        // Deadline must be at least as tight
        if !self.min_deadline.is_at_least_as_tight_as(before.min_deadline) {
            return false;
        }
        true
    }

    /// Returns true if the rewrite preserves deadline guarantees.
    ///
    /// More precise than `is_not_worse_than` for deadline-specific checks:
    /// - If `before` has no deadline, any deadline is acceptable
    /// - If `before` has a deadline, `after` must have one at least as tight
    #[must_use]
    pub fn preserves_deadline_guarantee(self, before: Self) -> bool {
        if !before.has_deadline {
            return true;
        }
        if !self.has_deadline {
            return false;
        }
        self.min_deadline.is_at_least_as_tight_as(before.min_deadline)
    }

    /// Returns the effective deadline for worst-case analysis.
    ///
    /// Returns `None` if no deadline is set, otherwise returns the
    /// tightest deadline constraint.
    #[must_use]
    pub fn effective_deadline(self) -> Option<DeadlineMicros> {
        if self.has_deadline {
            Some(self.min_deadline)
        } else {
            None
        }
    }
}

impl fmt::Display for BudgetEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "polls=[{}, ", self.min_polls)?;
        match self.max_polls {
            Some(max) => write!(f, "{max}]")?,
            None => f.write_str("∞]")?,
        }
        if self.has_deadline {
            write!(f, " deadline=[{}, {}]", self.min_deadline, self.max_deadline)?;
        }
        if self.parallelism > 1 {
            write!(f, " par={}", self.parallelism)?;
        }
        Ok(())
    }
}

// ===========================================================================
// Obligation flow analysis (detailed)
// ===========================================================================

/// Abstract obligation descriptor for a plan node.
///
/// Unlike `ObligationSafety` which gives a yes/no answer about leaks,
/// `ObligationFlow` tracks which obligations may be reserved, committed,
/// or aborted at this node, providing detailed diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObligationFlow {
    /// Obligations that may be reserved (created) at this node.
    ///
    /// Empty for leaf nodes without obligation annotations; populated
    /// by analyzing join/race/timeout structure.
    pub reserves: Vec<String>,
    /// Obligations that must be resolved (committed or aborted) for this
    /// node to complete cleanly.
    pub must_resolve: Vec<String>,
    /// Obligations that may leak if this node is cancelled.
    pub leak_on_cancel: Vec<String>,
    /// Whether all paths through this node resolve all obligations.
    pub all_paths_resolve: bool,
}

impl ObligationFlow {
    /// Creates an empty flow (no obligations).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            reserves: Vec::new(),
            must_resolve: Vec::new(),
            leak_on_cancel: Vec::new(),
            all_paths_resolve: true,
        }
    }

    /// Creates a flow for a leaf with a single obligation.
    #[must_use]
    pub fn leaf_with_obligation(name: String) -> Self {
        Self {
            reserves: vec![name.clone()],
            must_resolve: vec![name.clone()],
            leak_on_cancel: vec![name],
            all_paths_resolve: true, // Leaf obligation is resolved by leaf completing
        }
    }

    /// Joins two flows (for Join nodes).
    ///
    /// All obligations from both children are combined.
    #[must_use]
    pub fn join(mut self, other: Self) -> Self {
        self.reserves.extend(other.reserves);
        self.must_resolve.extend(other.must_resolve);
        self.leak_on_cancel.extend(other.leak_on_cancel);
        self.all_paths_resolve = self.all_paths_resolve && other.all_paths_resolve;
        self.dedupe();
        self
    }

    /// Races two flows (for Race nodes).
    ///
    /// Obligations from losers become leak candidates.
    #[must_use]
    pub fn race(mut self, other: Self) -> Self {
        // Both sets of obligations are started, but only winner completes.
        // Loser's obligations become leak candidates.
        let other_all_paths_resolve = other.all_paths_resolve;
        self.reserves.extend(other.reserves);
        self.must_resolve.extend(other.must_resolve);
        // In a race, the loser's obligations may leak unless explicitly drained.
        self.leak_on_cancel.extend(other.leak_on_cancel);
        self.leak_on_cancel
            .extend(self.must_resolve.iter().cloned());
        // Conservative: can't guarantee all paths resolve in a race unless
        // both children guarantee it and are properly drained.
        self.all_paths_resolve = self.all_paths_resolve && other_all_paths_resolve;
        self.dedupe();
        self
    }

    /// Deduplicates the obligation lists while preserving order.
    fn dedupe(&mut self) {
        Self::dedupe_vec(&mut self.reserves);
        Self::dedupe_vec(&mut self.must_resolve);
        Self::dedupe_vec(&mut self.leak_on_cancel);
    }

    /// Deduplicates a vector while preserving order.
    pub fn dedupe_vec(v: &mut Vec<String>) {
        let mut seen = std::collections::BTreeSet::new();
        v.retain(|s| seen.insert(s.clone()));
    }

    /// Returns diagnostics about potential obligation issues.
    #[must_use]
    pub fn diagnostics(&self) -> Vec<String> {
        let mut diags = Vec::new();
        if !self.all_paths_resolve && !self.must_resolve.is_empty() {
            diags.push(format!(
                "not all paths resolve obligations: {:?}",
                self.must_resolve
            ));
        }
        if !self.leak_on_cancel.is_empty() {
            diags.push(format!(
                "obligations may leak on cancel: {:?}",
                self.leak_on_cancel
            ));
        }
        diags
    }
}

impl fmt::Display for ObligationFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reserves={:?}", self.reserves)?;
        if !self.must_resolve.is_empty() {
            write!(f, " must_resolve={:?}", self.must_resolve)?;
        }
        if !self.leak_on_cancel.is_empty() {
            write!(f, " leak_on_cancel={:?}", self.leak_on_cancel)?;
        }
        if self.all_paths_resolve {
            f.write_str(" [all-paths-ok]")?;
        } else {
            f.write_str(" [LEAK-RISK]")?;
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
    /// Obligation safety (summary).
    pub obligation: ObligationSafety,
    /// Detailed obligation flow.
    pub obligation_flow: ObligationFlow,
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
                obligation_flow: ObligationFlow::empty(),
                cancel: CancelSafety::Unknown,
                budget: BudgetEffect::UNKNOWN,
            };
            results.insert(id.index(), analysis.clone());
            return analysis;
        };

        let analysis = match node.clone() {
            PlanNode::Leaf { label } => NodeAnalysis {
                id,
                obligation: ObligationSafety::Clean,
                // Leaves with labels that look like obligations get tracked.
                // Convention: labels starting with "obl:" have obligations.
                obligation_flow: if label.starts_with("obl:") {
                    ObligationFlow::leaf_with_obligation(label)
                } else {
                    ObligationFlow::empty()
                },
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

                // Join deadline: tightest min_deadline (all must meet it),
                // and sequential max_deadline (all must complete).
                let min_deadline = child_analyses
                    .iter()
                    .map(|a| a.budget.min_deadline)
                    .fold(DeadlineMicros::UNBOUNDED, DeadlineMicros::min);
                let max_deadline = child_analyses
                    .iter()
                    .map(|a| a.budget.max_deadline)
                    .fold(DeadlineMicros::ZERO, DeadlineMicros::add);

                // Join obligation flow: combine all children's flows.
                let obligation_flow = child_analyses
                    .iter()
                    .map(|a| a.obligation_flow.clone())
                    .fold(ObligationFlow::empty(), ObligationFlow::join);

                NodeAnalysis {
                    id,
                    obligation,
                    obligation_flow,
                    cancel,
                    budget: BudgetEffect {
                        min_polls,
                        max_polls,
                        has_deadline,
                        parallelism,
                        min_deadline,
                        max_deadline,
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
                let max_polls = child_analyses
                    .iter()
                    .try_fold(0u32, |acc, a| a.budget.max_polls.map(|m| acc.max(m)));
                let has_deadline = child_analyses.iter().any(|a| a.budget.has_deadline);
                let parallelism = child_analyses
                    .iter()
                    .map(|a| a.budget.parallelism)
                    .max()
                    .unwrap_or(1);

                // Race deadline: tightest constraint wins (first to complete).
                let min_deadline = child_analyses
                    .iter()
                    .map(|a| a.budget.min_deadline)
                    .fold(DeadlineMicros::UNBOUNDED, DeadlineMicros::min);
                let max_deadline = child_analyses
                    .iter()
                    .map(|a| a.budget.max_deadline)
                    .fold(DeadlineMicros::UNBOUNDED, DeadlineMicros::min);

                // Race obligation flow: combine with race semantics
                // (losers may leak if not drained).
                let obligation_flow = child_analyses
                    .iter()
                    .map(|a| a.obligation_flow.clone())
                    .fold(ObligationFlow::empty(), ObligationFlow::race);

                NodeAnalysis {
                    id,
                    obligation,
                    obligation_flow,
                    cancel,
                    budget: BudgetEffect {
                        min_polls,
                        max_polls,
                        has_deadline,
                        parallelism,
                        min_deadline,
                        max_deadline,
                    },
                }
            }

            PlanNode::Timeout { child, duration } => {
                let child_analysis = Self::analyze_node(dag, child, results);

                // Timeout obligation flow: child's flow with added leak risk.
                let mut obligation_flow = child_analysis.obligation_flow.clone();
                // On timeout, child obligations may leak.
                obligation_flow
                    .leak_on_cancel
                    .extend(obligation_flow.must_resolve.iter().cloned());
                ObligationFlow::dedupe_vec(&mut obligation_flow.leak_on_cancel);

                // Compute deadline from the Duration
                let deadline = DeadlineMicros::from_duration(duration);

                NodeAnalysis {
                    id,
                    obligation: child_analysis.obligation,
                    obligation_flow,
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
                        // Deadline is the tighter of child's deadline and this timeout
                        min_deadline: child_analysis.budget.min_deadline.min(deadline),
                        max_deadline: deadline, // Timeout caps the max deadline
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
        self.analysis.get(id).is_some_and(|a| a.cancel.is_safe())
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

    /// Check if a rewrite preserves budget monotonicity.
    #[must_use]
    pub fn rewrite_preserves_budget(&self, before: PlanId, after: PlanId) -> bool {
        let Some(before) = self.analysis.get(before) else {
            return false;
        };
        let Some(after) = self.analysis.get(after) else {
            return false;
        };
        after.budget.is_not_worse_than(before.budget)
    }

    /// Check if a rewrite preserves deadline guarantees specifically.
    ///
    /// This is a more focused check than `rewrite_preserves_budget`:
    /// - If the original has no deadline, any deadline is acceptable
    /// - If the original has a deadline, the rewritten must have one
    ///   that is at least as tight
    #[must_use]
    pub fn rewrite_preserves_deadline(&self, before: PlanId, after: PlanId) -> bool {
        let Some(before) = self.analysis.get(before) else {
            return false;
        };
        let Some(after) = self.analysis.get(after) else {
            return false;
        };
        after.budget.preserves_deadline_guarantee(before.budget)
    }

    /// Returns the effective deadline for a node, if any.
    #[must_use]
    pub fn effective_deadline(&self, id: PlanId) -> Option<DeadlineMicros> {
        self.analysis.get(id).and_then(|a| a.budget.effective_deadline())
    }

    /// Check if a rewrite does not worsen the deadline by more than a given amount.
    ///
    /// Useful for allowing small deadline relaxations in exchange for other benefits.
    #[must_use]
    pub fn deadline_within_tolerance(
        &self,
        before: PlanId,
        after: PlanId,
        tolerance_micros: u64,
    ) -> bool {
        let Some(before_analysis) = self.analysis.get(before) else {
            return false;
        };
        let Some(after_analysis) = self.analysis.get(after) else {
            return false;
        };

        match (
            before_analysis.budget.effective_deadline(),
            after_analysis.budget.effective_deadline(),
        ) {
            // No deadline before: any deadline is acceptable
            (None, _) => true,
            // Had deadline, lost it: not acceptable (infinite tolerance doesn't help)
            (Some(_), None) => false,
            // Both have deadlines: check tolerance
            (Some(before_dl), Some(after_dl)) => {
                match (before_dl.as_micros(), after_dl.as_micros()) {
                    (Some(b), Some(a)) => a <= b.saturating_add(tolerance_micros),
                    _ => false,
                }
            }
        }
    }

    /// Check whether all children are pairwise independent.
    #[must_use]
    pub fn children_pairwise_independent(&self, children: &[PlanId]) -> bool {
        for (idx, a) in children.iter().enumerate() {
            for b in children.iter().skip(idx + 1) {
                if !self.are_independent(*a, *b) {
                    return false;
                }
            }
        }
        true
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
        let join_node = dag.join(vec![a, b]);
        dag.set_root(join_node);

        let checker = SideConditionChecker::new(&dag);
        assert!(checker.rewrite_preserves_obligations(a, b));
        assert!(checker.rewrite_preserves_cancel(a, b));
    }

    #[test]
    fn budget_monotonicity_rejects_unbounded_after() {
        let before = BudgetEffect {
            min_polls: 2,
            max_polls: Some(10),
            has_deadline: true,
            parallelism: 2,
        };
        let after = BudgetEffect {
            min_polls: 1,
            max_polls: None,
            has_deadline: true,
            parallelism: 1,
        };
        assert!(!after.is_not_worse_than(before));
    }

    #[test]
    fn budget_monotonicity_accepts_tighter_deadline() {
        let before = BudgetEffect {
            min_polls: 5,
            max_polls: Some(10),
            has_deadline: false,
            parallelism: 2,
        };
        let after = BudgetEffect {
            min_polls: 4,
            max_polls: Some(8),
            has_deadline: true,
            parallelism: 1,
        };
        assert!(after.is_not_worse_than(before));
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

    // ---- ObligationFlow tests ----

    #[test]
    fn obligation_flow_empty_is_clean() {
        let flow = ObligationFlow::empty();
        assert!(flow.reserves.is_empty());
        assert!(flow.must_resolve.is_empty());
        assert!(flow.leak_on_cancel.is_empty());
        assert!(flow.all_paths_resolve);
        assert!(flow.diagnostics().is_empty());
    }

    #[test]
    fn obligation_flow_leaf_with_obligation_tracks_it() {
        let flow = ObligationFlow::leaf_with_obligation("obl:permit".to_string());
        assert_eq!(flow.reserves, vec!["obl:permit"]);
        assert_eq!(flow.must_resolve, vec!["obl:permit"]);
        assert_eq!(flow.leak_on_cancel, vec!["obl:permit"]);
        assert!(flow.all_paths_resolve);
    }

    #[test]
    fn obligation_flow_join_combines_children() {
        let f1 = ObligationFlow::leaf_with_obligation("obl:a".to_string());
        let f2 = ObligationFlow::leaf_with_obligation("obl:b".to_string());
        let joined = f1.join(f2);
        assert_eq!(joined.reserves.len(), 2);
        assert!(joined.reserves.contains(&"obl:a".to_string()));
        assert!(joined.reserves.contains(&"obl:b".to_string()));
    }

    #[test]
    fn obligation_flow_race_adds_leak_risk() {
        let f1 = ObligationFlow::leaf_with_obligation("obl:a".to_string());
        let f2 = ObligationFlow::leaf_with_obligation("obl:b".to_string());
        let raced = f1.race(f2);
        // Both are started, loser may leak.
        assert!(!raced.leak_on_cancel.is_empty());
        assert!(raced.leak_on_cancel.contains(&"obl:a".to_string()));
        assert!(raced.leak_on_cancel.contains(&"obl:b".to_string()));
    }

    #[test]
    fn analyzer_tracks_obligation_flow_for_annotated_leaves() {
        let mut dag = PlanDag::new();
        let obl = dag.leaf("obl:permit");
        let plain = dag.leaf("compute");
        let join = dag.join(vec![obl, plain]);
        dag.set_root(join);

        let analysis = PlanAnalyzer::analyze(&dag);
        let join_node = analysis.get(join).expect("join analyzed");
        // The join should track the obligation from the obl: leaf.
        assert!(join_node
            .obligation_flow
            .reserves
            .contains(&"obl:permit".to_string()));
    }

    #[test]
    fn analyzer_detects_race_obligation_leak_risk() {
        let mut dag = PlanDag::new();
        let obl_a = dag.leaf("obl:a");
        let obl_b = dag.leaf("obl:b");
        let race = dag.race(vec![obl_a, obl_b]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        let race_node = analysis.get(race).expect("race analyzed");
        // In a race, the loser's obligations may leak.
        assert!(!race_node.obligation_flow.leak_on_cancel.is_empty());
    }

    #[test]
    fn obligation_flow_display() {
        let flow = ObligationFlow {
            reserves: vec!["obl:x".to_string()],
            must_resolve: vec!["obl:x".to_string()],
            leak_on_cancel: vec![],
            all_paths_resolve: true,
        };
        let display = format!("{flow}");
        assert!(display.contains("reserves="));
        assert!(display.contains("[all-paths-ok]"));
    }

    #[test]
    fn obligation_flow_diagnostics_reports_issues() {
        let flow = ObligationFlow {
            reserves: vec!["obl:x".to_string()],
            must_resolve: vec!["obl:x".to_string()],
            leak_on_cancel: vec!["obl:x".to_string()],
            all_paths_resolve: false,
        };
        let diags = flow.diagnostics();
        assert!(!diags.is_empty());
        assert!(diags.iter().any(|d| d.contains("not all paths")));
        assert!(diags.iter().any(|d| d.contains("leak on cancel")));
    }

    // ---- DeadlineMicros tests ----

    #[test]
    fn deadline_micros_unbounded() {
        let unbounded = DeadlineMicros::UNBOUNDED;
        assert!(unbounded.is_unbounded());
        assert_eq!(unbounded.as_micros(), None);
    }

    #[test]
    fn deadline_micros_from_duration() {
        let deadline = DeadlineMicros::from_duration(Duration::from_millis(500));
        assert!(!deadline.is_unbounded());
        assert_eq!(deadline.as_micros(), Some(500_000));
    }

    #[test]
    fn deadline_micros_min_takes_tighter() {
        let d1 = DeadlineMicros::from_micros(1000);
        let d2 = DeadlineMicros::from_micros(500);
        let unbounded = DeadlineMicros::UNBOUNDED;

        assert_eq!(d1.min(d2), d2); // 500 < 1000
        assert_eq!(d2.min(d1), d2);
        assert_eq!(d1.min(unbounded), d1); // finite < unbounded
        assert_eq!(unbounded.min(d1), d1);
    }

    #[test]
    fn deadline_micros_add_sequential() {
        let d1 = DeadlineMicros::from_micros(1000);
        let d2 = DeadlineMicros::from_micros(500);
        let unbounded = DeadlineMicros::UNBOUNDED;

        assert_eq!(d1.add(d2), DeadlineMicros::from_micros(1500));
        assert_eq!(d1.add(unbounded), DeadlineMicros::UNBOUNDED);
        assert_eq!(unbounded.add(d1), DeadlineMicros::UNBOUNDED);
    }

    #[test]
    fn deadline_micros_is_at_least_as_tight() {
        let tight = DeadlineMicros::from_micros(100);
        let loose = DeadlineMicros::from_micros(1000);
        let unbounded = DeadlineMicros::UNBOUNDED;

        assert!(tight.is_at_least_as_tight_as(loose));
        assert!(!loose.is_at_least_as_tight_as(tight));
        assert!(tight.is_at_least_as_tight_as(unbounded));
        assert!(loose.is_at_least_as_tight_as(unbounded));
        assert!(!unbounded.is_at_least_as_tight_as(tight));
    }

    #[test]
    fn deadline_micros_display() {
        assert_eq!(format!("{}", DeadlineMicros::UNBOUNDED), "∞");
        assert_eq!(format!("{}", DeadlineMicros::from_micros(500)), "500µs");
        assert_eq!(format!("{}", DeadlineMicros::from_micros(5000)), "5ms");
        assert_eq!(format!("{}", DeadlineMicros::from_micros(5_000_000)), "5s");
    }

    // ---- Budget deadline tracking tests ----

    #[test]
    fn timeout_tracks_actual_deadline() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t = dag.timeout(a, Duration::from_millis(100));
        dag.set_root(t);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(t).expect("timeout analyzed");
        assert!(node.budget.has_deadline);
        assert_eq!(
            node.budget.min_deadline,
            DeadlineMicros::from_micros(100_000)
        );
    }

    #[test]
    fn nested_timeout_takes_tighter_deadline() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t1 = dag.timeout(a, Duration::from_millis(200)); // outer: looser
        let t2 = dag.timeout(t1, Duration::from_millis(100)); // inner: tighter
        dag.set_root(t2);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(t2).expect("timeout analyzed");
        // Tightest deadline should be 100ms
        assert_eq!(
            node.budget.min_deadline,
            DeadlineMicros::from_micros(100_000)
        );
    }

    #[test]
    fn join_propagates_deadline_from_child() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let t = dag.timeout(a, Duration::from_millis(50));
        let join = dag.join(vec![t, b]);
        dag.set_root(join);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(join).expect("join analyzed");
        assert!(node.budget.has_deadline);
        assert_eq!(node.budget.min_deadline, DeadlineMicros::from_micros(50_000));
    }

    #[test]
    fn race_propagates_tightest_deadline() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let t1 = dag.timeout(a, Duration::from_millis(100));
        let t2 = dag.timeout(b, Duration::from_millis(50)); // tighter
        let race = dag.race(vec![t1, t2]);
        dag.set_root(race);

        let analysis = PlanAnalyzer::analyze(&dag);
        let node = analysis.get(race).expect("race analyzed");
        assert!(node.budget.has_deadline);
        assert_eq!(node.budget.min_deadline, DeadlineMicros::from_micros(50_000));
    }

    // ---- Side condition deadline preservation tests ----

    #[test]
    fn rewrite_preserves_deadline_when_tighter() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t1 = dag.timeout(a, Duration::from_millis(100)); // original
        let t2 = dag.timeout(a, Duration::from_millis(50)); // tighter
        dag.set_root(t1);

        let checker = SideConditionChecker::new(&dag);
        assert!(checker.rewrite_preserves_deadline(t1, t2)); // tighter is ok
    }

    #[test]
    fn rewrite_fails_deadline_when_looser() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t1 = dag.timeout(a, Duration::from_millis(50)); // original: tight
        let t2 = dag.timeout(a, Duration::from_millis(100)); // looser
        dag.set_root(t1);

        let checker = SideConditionChecker::new(&dag);
        assert!(!checker.rewrite_preserves_deadline(t1, t2)); // looser not ok
    }

    #[test]
    fn rewrite_allows_deadline_when_none_before() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t = dag.timeout(a, Duration::from_millis(100));
        dag.set_root(t);

        let checker = SideConditionChecker::new(&dag);
        // No deadline -> any deadline is ok
        assert!(checker.rewrite_preserves_deadline(a, t));
    }

    #[test]
    fn deadline_tolerance_check() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t1 = dag.timeout(a, Duration::from_millis(100));
        let t2 = dag.timeout(a, Duration::from_millis(110)); // 10ms looser
        dag.set_root(t1);

        let checker = SideConditionChecker::new(&dag);
        // 10ms tolerance: 110ms - 100ms = 10ms, should pass
        assert!(checker.deadline_within_tolerance(t1, t2, 10_000));
        // 5ms tolerance: should fail (10ms > 5ms)
        assert!(!checker.deadline_within_tolerance(t1, t2, 5_000));
    }

    #[test]
    fn effective_deadline_returns_none_for_no_deadline() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        dag.set_root(a);

        let checker = SideConditionChecker::new(&dag);
        assert!(checker.effective_deadline(a).is_none());
    }

    #[test]
    fn effective_deadline_returns_value_for_timeout() {
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let t = dag.timeout(a, Duration::from_millis(75));
        dag.set_root(t);

        let checker = SideConditionChecker::new(&dag);
        let deadline = checker.effective_deadline(t);
        assert!(deadline.is_some());
        assert_eq!(deadline.unwrap().as_micros(), Some(75_000));
    }

    // ---- Budget effect composition tests ----

    #[test]
    fn budget_effect_sequential_adds_deadlines() {
        let e1 = BudgetEffect::LEAF.with_deadline(DeadlineMicros::from_micros(100));
        let e2 = BudgetEffect::LEAF.with_deadline(DeadlineMicros::from_micros(200));
        let combined = e1.sequential(e2);

        assert!(combined.has_deadline);
        // Sequential: max_deadline adds up
        assert_eq!(combined.max_deadline, DeadlineMicros::from_micros(300));
        // min_deadline takes tighter
        assert_eq!(combined.min_deadline, DeadlineMicros::from_micros(100));
    }

    #[test]
    fn budget_effect_parallel_takes_tighter_deadline() {
        let e1 = BudgetEffect::LEAF.with_deadline(DeadlineMicros::from_micros(100));
        let e2 = BudgetEffect::LEAF.with_deadline(DeadlineMicros::from_micros(200));
        let combined = e1.parallel(e2);

        assert!(combined.has_deadline);
        // Parallel: both take min (tightest)
        assert_eq!(combined.min_deadline, DeadlineMicros::from_micros(100));
        assert_eq!(combined.max_deadline, DeadlineMicros::from_micros(100));
    }

    #[test]
    fn budget_effect_display_shows_deadline_range() {
        let effect = BudgetEffect {
            min_polls: 2,
            max_polls: Some(5),
            has_deadline: true,
            parallelism: 1,
            min_deadline: DeadlineMicros::from_micros(100_000),
            max_deadline: DeadlineMicros::from_micros(500_000),
        };
        let display = format!("{effect}");
        assert!(display.contains("deadline="));
        assert!(display.contains("100ms"));
        assert!(display.contains("500ms"));
    }
}
