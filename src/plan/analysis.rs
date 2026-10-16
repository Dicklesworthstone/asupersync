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

use super::{PlanCost, PlanDag, PlanId, PlanNode};
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
            (Unknown, _) | (_, Unknown) => Unknown,
            (Clean, Clean) => Clean,
            (Leaked, _) | (_, Leaked) => Leaked,
            (MayLeak, _) | (_, MayLeak) => MayLeak,
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
            (Unknown, _) | (_, Unknown) => Unknown,
            (Safe, Safe) => Safe,
            (Orphan, _) | (_, Orphan) => Orphan,
            (MayOrphan, _) | (_, MayOrphan) => MayOrphan,
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
    #[allow(clippy::should_implement_trait)]
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
            (_, None) => true,            // anything is as tight as unbounded
            (None, Some(_)) => false,     // unbounded is looser than any bound
            (Some(a), Some(b)) => a <= b, // tighter means smaller
        }
    }
}

impl fmt::Display for DeadlineMicros {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            None => f.write_str("∞"),
            Some(us) if us >= 1_000_000 => {
                let s = us / 1_000_000;
                write!(f, "{s}s")
            }
            Some(us) if us >= 1_000 => {
                let ms = us / 1_000;
                write!(f, "{ms}ms")
            }
            Some(us) => write!(f, "{us}µs"),
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
            max_polls: parallel_max_polls(self.max_polls, other.max_polls),
            has_deadline: self.has_deadline || other.has_deadline,
            parallelism: self.parallelism.saturating_add(other.parallelism),
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
    /// - does not increase the concurrency envelope
    /// - does not loosen the deadline guarantee
    /// - does not loosen the worst-case deadline guarantee
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
        if self.parallelism > before.parallelism {
            return false;
        }
        // Deadline must be at least as tight
        if !self
            .min_deadline
            .is_at_least_as_tight_as(before.min_deadline)
        {
            return false;
        }
        if !self
            .max_deadline
            .is_at_least_as_tight_as(before.max_deadline)
        {
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
        self.min_deadline
            .is_at_least_as_tight_as(before.min_deadline)
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

#[inline]
fn parallel_max_polls(lhs: Option<u32>, rhs: Option<u32>) -> Option<u32> {
    match (lhs, rhs) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
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
            write!(
                f,
                " deadline=[{}, {}]",
                self.min_deadline, self.max_deadline
            )?;
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
        // Conservative: in a race the loser is cancelled, so its obligations
        // will not resolve.  Only claim all_paths_resolve if there are no
        // must_resolve obligations at all (nothing can leak from either branch).
        self.all_paths_resolve =
            self.all_paths_resolve && other_all_paths_resolve && self.must_resolve.is_empty();
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

    /// Returns the effective obligation safety implied by the detailed flow.
    #[must_use]
    pub fn effective_safety(&self) -> ObligationSafety {
        let mut safety = ObligationSafety::Clean;
        if !self.leak_on_cancel.is_empty() {
            safety = safety.join(ObligationSafety::MayLeak);
        }
        if !self.all_paths_resolve && !self.must_resolve.is_empty() {
            safety = safety.join(ObligationSafety::Leaked);
        }
        safety
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

fn obligation_pressure(flow: &ObligationFlow) -> u64 {
    // Count distinct obligations across both lists to avoid double-counting
    // obligations that appear in both must_resolve and leak_on_cancel.
    let mut all = std::collections::BTreeSet::new();
    all.extend(flow.must_resolve.iter());
    all.extend(flow.leak_on_cancel.iter());
    all.len() as u64
}

fn sum_costs(costs: impl Iterator<Item = u64>) -> u64 {
    costs.fold(0u64, u64::saturating_add)
}

fn max_cost(costs: impl Iterator<Item = u64>) -> u64 {
    costs.max().unwrap_or(0)
}

fn min_cost(costs: impl Iterator<Item = u64>) -> u64 {
    costs.min().unwrap_or(0)
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
    /// Cost summary for extraction.
    pub cost: PlanCost,
}

impl NodeAnalysis {
    /// Returns the fail-closed obligation safety after considering detailed flow.
    #[must_use]
    pub fn effective_obligation(&self) -> ObligationSafety {
        self.obligation
            .join(self.obligation_flow.effective_safety())
    }

    /// Returns true if the node has any obligation safety issue.
    #[must_use]
    pub fn has_obligation_issues(&self) -> bool {
        !self.effective_obligation().is_safe()
    }

    /// Returns true if the node is safe on all dimensions.
    #[must_use]
    pub fn is_safe(&self) -> bool {
        !self.has_obligation_issues() && self.cancel.is_safe()
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
            .filter(|n| n.has_obligation_issues())
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
// Display implementations for golden artifact testing
// ===========================================================================

impl fmt::Display for NodeAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Node {} Analysis:", self.id.index())?;
        writeln!(
            f,
            "  Obligation Safety: {} (effective: {})",
            self.obligation,
            self.effective_obligation()
        )?;
        writeln!(f, "  Cancel Safety: {}", self.cancel)?;
        writeln!(f, "  Budget Effect: {}", self.budget)?;
        writeln!(f, "  Cost: {}", self.cost)?;
        writeln!(f, "  Obligation Flow: {}", self.obligation_flow)?;
        writeln!(f, "  Overall Safe: {}", self.is_safe())?;
        Ok(())
    }
}

impl fmt::Display for PlanAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Plan Analysis Report")?;
        writeln!(f, "====================")?;
        writeln!(f)?;
        writeln!(f, "Summary: {}", self.summary())?;
        writeln!(f, "Overall Safe: {}", self.all_safe())?;
        writeln!(f)?;

        if self.nodes.is_empty() {
            writeln!(f, "No nodes analyzed.")?;
            return Ok(());
        }

        // Group nodes by safety status for clear reporting
        let safe_nodes: Vec<_> = self.nodes.values().filter(|n| n.is_safe()).collect();
        let obligation_issues: Vec<_> = self.obligation_issues();
        let cancel_issues: Vec<_> = self.cancel_issues();

        if !safe_nodes.is_empty() {
            writeln!(f, "Safe Nodes ({}):", safe_nodes.len())?;
            for node in safe_nodes {
                writeln!(
                    f,
                    "  Node {}: {} (cost: {})",
                    node.id.index(),
                    node.obligation,
                    node.cost
                )?;
            }
            writeln!(f)?;
        }

        if !obligation_issues.is_empty() {
            writeln!(f, "Obligation Issues ({}):", obligation_issues.len())?;
            for node in obligation_issues {
                writeln!(
                    f,
                    "  Node {}: {} → {} (flow: {})",
                    node.id.index(),
                    node.obligation,
                    node.effective_obligation(),
                    node.obligation_flow
                )?;
            }
            writeln!(f)?;
        }

        if !cancel_issues.is_empty() {
            writeln!(f, "Cancel Issues ({}):", cancel_issues.len())?;
            for node in cancel_issues {
                writeln!(f, "  Node {}: {}", node.id.index(), node.cancel)?;
            }
            writeln!(f)?;
        }

        writeln!(f, "Detailed Node Analysis:")?;
        writeln!(f, "----------------------")?;
        for (id, node) in &self.nodes {
            writeln!(f, "Node {}:", id)?;
            writeln!(
                f,
                "  Safety: obligation={}, cancel={}, overall={}",
                node.effective_obligation(),
                node.cancel,
                node.is_safe()
            )?;
            writeln!(f, "  Budget: {}", node.budget)?;
            writeln!(f, "  Cost: {}", node.cost)?;
            writeln!(f, "  Obligation Flow: {}", node.obligation_flow)?;
        }

        Ok(())
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
        if let Some(root) = dag.root() {
            Self::analyze_node(dag, root, &mut results);
        }
        // Include any unreachable nodes so rewrite side-condition checks
        // can still reason about "before" nodes after a structural rewrite.
        for idx in 0..dag.nodes.len() {
            if !results.contains_key(&idx) {
                let id = PlanId::new(idx);
                Self::analyze_node(dag, id, &mut results);
            }
        }
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
                cost: PlanCost::UNKNOWN,
            };
            results.insert(id.index(), analysis.clone());
            return analysis;
        };

        let analysis = match node.clone() {
            PlanNode::Leaf { label } => {
                // Leaves with labels that look like obligations get tracked.
                // Convention: labels starting with "obl:" have obligations.
                let obligation_flow = if label.starts_with("obl:") {
                    ObligationFlow::leaf_with_obligation(label)
                } else {
                    ObligationFlow::empty()
                };
                let cost = PlanCost {
                    allocations: 1,
                    cancel_checkpoints: u64::from(BudgetEffect::LEAF.min_polls),
                    obligation_pressure: obligation_pressure(&obligation_flow),
                    critical_path: 1,
                };

                NodeAnalysis {
                    id,
                    obligation: ObligationSafety::Clean,
                    obligation_flow,
                    cancel: CancelSafety::Safe,
                    budget: BudgetEffect::LEAF,
                    cost,
                }
            }

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
                let min_polls = child_analyses
                    .iter()
                    .map(|a| a.budget.min_polls)
                    .fold(0u32, u32::saturating_add);
                let max_polls = child_analyses.iter().try_fold(0u32, |acc, a| {
                    a.budget.max_polls.map(|m| acc.saturating_add(m))
                });
                let has_deadline = child_analyses.iter().any(|a| a.budget.has_deadline);
                let parallelism = child_analyses
                    .iter()
                    .map(|a| a.budget.parallelism)
                    .fold(0u32, u32::saturating_add)
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

                let cost = PlanCost {
                    allocations: sum_costs(child_analyses.iter().map(|a| a.cost.allocations))
                        .saturating_add(1),
                    cancel_checkpoints: u64::from(min_polls),
                    obligation_pressure: obligation_pressure(&obligation_flow),
                    critical_path: max_cost(child_analyses.iter().map(|a| a.cost.critical_path))
                        .saturating_add(1),
                };

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
                    cost,
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
                    // Additional check for simple dedup patterns: if all children
                    // are directly drainable shapes, the pattern is safe.
                    let all_simple = children
                        .iter()
                        .all(|&child_id| race_child_has_simple_drain_shape(dag, child_id));
                    if all_simple {
                        CancelSafety::Safe
                    } else {
                        child_cancel.join(CancelSafety::MayOrphan)
                    }
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
                    .fold(None, |acc, a| parallel_max_polls(acc, a.budget.max_polls));
                let has_deadline = child_analyses.iter().any(|a| a.budget.has_deadline);
                let parallelism = child_analyses
                    .iter()
                    .map(|a| a.budget.parallelism)
                    .fold(0u32, u32::saturating_add)
                    .max(1);

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
                let obligation = if obligation_flow.leak_on_cancel.is_empty() {
                    obligation
                } else {
                    obligation.join(ObligationSafety::MayLeak)
                };
                let cancel = if obligation_flow.leak_on_cancel.is_empty() {
                    cancel
                } else {
                    cancel.join(CancelSafety::MayOrphan)
                };

                let cost = PlanCost {
                    allocations: sum_costs(child_analyses.iter().map(|a| a.cost.allocations))
                        .saturating_add(1),
                    cancel_checkpoints: u64::from(min_polls),
                    obligation_pressure: obligation_pressure(&obligation_flow),
                    critical_path: min_cost(child_analyses.iter().map(|a| a.cost.critical_path))
                        .saturating_add(1),
                };

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
                    cost,
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
                let obligation = if obligation_flow.leak_on_cancel.is_empty() {
                    child_analysis.obligation
                } else {
                    child_analysis.obligation.join(ObligationSafety::MayLeak)
                };
                let cancel =
                    if child_analysis.cancel.is_safe() && child_analysis.obligation.is_safe() {
                        CancelSafety::Safe
                    } else {
                        child_analysis.cancel.join(CancelSafety::MayOrphan)
                    };
                let cancel = if obligation_flow.leak_on_cancel.is_empty() {
                    cancel
                } else {
                    cancel.join(CancelSafety::MayOrphan)
                };

                // Compute deadline from the Duration
                let deadline = DeadlineMicros::from_duration(duration);

                let cost = PlanCost {
                    allocations: child_analysis.cost.allocations.saturating_add(1),
                    cancel_checkpoints: u64::from(child_analysis.budget.min_polls),
                    obligation_pressure: obligation_pressure(&obligation_flow),
                    critical_path: child_analysis.cost.critical_path.saturating_add(1),
                };

                NodeAnalysis {
                    id,
                    obligation,
                    obligation_flow,
                    // Timeout introduces cancel: if child exceeds the deadline,
                    // it is cancelled. Same logic as race with deadline branch.
                    cancel,
                    budget: BudgetEffect {
                        min_polls: child_analysis.budget.min_polls,
                        max_polls: child_analysis.budget.max_polls,
                        has_deadline: true,
                        parallelism: child_analysis.budget.parallelism,
                        // Deadline is the tighter of child's deadline and this timeout
                        min_deadline: child_analysis.budget.min_deadline.min(deadline),
                        max_deadline: deadline, // Timeout caps the max deadline
                    },
                    cost,
                }
            }
        };

        results.insert(id.index(), analysis.clone());
        analysis
    }
}

fn race_child_has_simple_drain_shape(dag: &PlanDag, child_id: PlanId) -> bool {
    match dag.node(child_id) {
        Some(PlanNode::Leaf { .. } | PlanNode::Join { .. }) => true,
        Some(PlanNode::Timeout { child, .. }) => {
            matches!(
                dag.node(*child),
                Some(PlanNode::Leaf { .. } | PlanNode::Join { .. })
            )
        }
        Some(PlanNode::Race { .. }) | None => false,
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

    /// Check if a node's children are obligation-safe (no cancel leaks).
    #[must_use]
    pub fn obligations_safe(&self, id: PlanId) -> bool {
        self.analysis
            .get(id)
            .is_some_and(|a| a.effective_obligation().is_safe())
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
        self.analysis
            .get(id)
            .and_then(|a| a.budget.effective_deadline())
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

    // =========================================================================
    // Cancellation / obligation safety side conditions (bd-3a1g)
    // =========================================================================

    /// Returns true when a rewrite preserves the loser-drain property.
    ///
    /// A rewrite is safe only when the rewritten shape is absolutely cancel-safe,
    /// does not move to a less-safe cancel state, and does not introduce new
    /// obligation leak candidates on the cancel path.
    #[must_use]
    pub fn rewrite_preserves_loser_drain(&self, before: PlanId, after: PlanId) -> bool {
        let Some(before_a) = self.analysis.get(before) else {
            return false;
        };
        let Some(after_a) = self.analysis.get(after) else {
            return false;
        };
        // Relative safety is not enough: MayOrphan -> MayOrphan would preserve
        // ordering in the lattice while still failing the loser-drain guarantee.
        if !after_a.cancel.is_safe() {
            return false;
        }
        // Degrading to a less-safe cancel state is forbidden.
        if after_a.cancel > before_a.cancel {
            return false;
        }
        // The set of obligations that may leak on cancel must not grow.
        let before_leaks: std::collections::BTreeSet<&str> = before_a
            .obligation_flow
            .leak_on_cancel
            .iter()
            .map(String::as_str)
            .collect();
        let after_leaks: std::collections::BTreeSet<&str> = after_a
            .obligation_flow
            .leak_on_cancel
            .iter()
            .map(String::as_str)
            .collect();
        after_leaks.is_subset(&before_leaks)
    }

    /// Returns true when a rewrite preserves the relative order of
    /// obligation-bearing children inside a Join node.
    ///
    /// For Race/Timeout/Leaf rewrites this always returns true (no ordering
    /// contract). Race → Join (e.g., `DedupRaceJoin`) is allowed because a
    /// Race imposes no finalize ordering on its children; any ordering in the
    /// resulting Join is valid.
    #[must_use]
    pub fn rewrite_preserves_finalize_order(&self, before: PlanId, after: PlanId) -> bool {
        let Some(before_node) = self.dag.node(before) else {
            return false;
        };
        let Some(after_node) = self.dag.node(after) else {
            return false;
        };
        match (before_node, after_node) {
            (
                PlanNode::Join {
                    children: before_ch,
                },
                PlanNode::Join { children: after_ch },
            ) => {
                let before_obl = self.obligation_finalize_order(before_ch);
                let after_obl = self.obligation_finalize_order(after_ch);
                before_obl == after_obl
            }
            // Race has no finalize ordering, so Race → Join is always valid
            // (e.g., DedupRaceJoin: Race[Join[s,a], Join[s,b]] → Join[s, Race[a,b]])
            (PlanNode::Race { .. }, PlanNode::Join { .. })
            | (PlanNode::Race { .. }, PlanNode::Race { .. })
            | (PlanNode::Timeout { .. }, PlanNode::Timeout { .. })
            | (PlanNode::Leaf { .. }, PlanNode::Leaf { .. }) => true,
            _ => false,
        }
    }

    /// Returns true when a rewrite does not introduce new obligation leaks.
    ///
    /// This checks three properties:
    /// 1. Obligation safety does not degrade (safe → unsafe).
    /// 2. The `all_paths_resolve` flag does not become false.
    /// 3. The set of `leak_on_cancel` obligations does not grow.
    /// 4. Previously `must_resolve` obligations are not demoted to leak-or-reserve.
    #[must_use]
    pub fn rewrite_no_new_obligation_leaks(&self, before: PlanId, after: PlanId) -> bool {
        let Some(before_a) = self.analysis.get(before) else {
            return false;
        };
        let Some(after_a) = self.analysis.get(after) else {
            return false;
        };
        // Safety must not degrade.
        if before_a.effective_obligation().is_safe() && !after_a.effective_obligation().is_safe() {
            return false;
        }
        let bf = &before_a.obligation_flow;
        let af = &after_a.obligation_flow;
        // all_paths_resolve must not degrade.
        if bf.all_paths_resolve && !af.all_paths_resolve {
            return false;
        }
        // leak_on_cancel set must not grow.
        let before_leaks: std::collections::BTreeSet<&str> =
            bf.leak_on_cancel.iter().map(String::as_str).collect();
        let after_leaks: std::collections::BTreeSet<&str> =
            af.leak_on_cancel.iter().map(String::as_str).collect();
        if !after_leaks.is_subset(&before_leaks) {
            return false;
        }
        // must_resolve obligations should not be demoted to leak-or-reserve.
        let after_resolves: std::collections::BTreeSet<&str> =
            af.must_resolve.iter().map(String::as_str).collect();
        for obl in &bf.must_resolve {
            if !after_resolves.contains(obl.as_str())
                && (af.leak_on_cancel.contains(obl) || af.reserves.contains(obl))
            {
                return false;
            }
        }
        true
    }

    /// Helper: returns the left-to-right finalize order for obligation-bearing
    /// units in a join frontier.
    ///
    /// Nested joins are flattened because associativity rewrites only regroup
    /// the join tree; they do not change the relative finalize order of the
    /// obligation-bearing descendants inside that tree.
    fn obligation_finalize_order(&self, children: &[PlanId]) -> Vec<PlanId> {
        let mut order = Vec::new();
        for child in children {
            self.collect_obligation_finalize_order(*child, &mut order);
        }
        order
    }

    fn collect_obligation_finalize_order(&self, id: PlanId, order: &mut Vec<PlanId>) {
        match self.dag.node(id) {
            Some(PlanNode::Join { children }) => {
                for child in children {
                    self.collect_obligation_finalize_order(*child, order);
                }
            }
            Some(_) | None => {
                if self.analysis.get(id).is_some_and(|a| {
                    !a.obligation_flow.must_resolve.is_empty()
                        || !a.obligation_flow.leak_on_cancel.is_empty()
                }) {
                    order.push(id);
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
        let mut visited_set = std::collections::BTreeSet::new();
        let mut visited = Vec::new();
        self.reachable_inner(id, &mut visited_set, &mut visited);
        visited
    }

    fn reachable_inner(
        &self,
        id: PlanId,
        visited_set: &mut std::collections::BTreeSet<usize>,
        visited: &mut Vec<usize>,
    ) {
        if !visited_set.insert(id.index()) {
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
                    self.reachable_inner(*child, visited_set, visited);
                }
            }
            PlanNode::Timeout { child, .. } => {
                self.reachable_inner(*child, visited_set, visited);
            }
        }
    }
}

// ===========================================================================
// Independence-aware equivalence hints (Mazurkiewicz trace semantics)
// ===========================================================================

/// Result of an independence analysis between two plan nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndependenceResult {
    /// The nodes are independent and can be safely reordered.
    Independent,
    /// The nodes are dependent and cannot be reordered.
    Dependent,
    /// The independence is uncertain (conservative: treat as dependent).
    Uncertain,
}

impl IndependenceResult {
    /// Returns true if the nodes are provably independent.
    #[must_use]
    pub fn is_independent(self) -> bool {
        matches!(self, Self::Independent)
    }

    /// Join two results: if either is dependent, the result is dependent.
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Independent, Self::Independent) => Self::Independent,
            (Self::Dependent, _) | (_, Self::Dependent) => Self::Dependent,
            _ => Self::Uncertain,
        }
    }
}

impl fmt::Display for IndependenceResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Independent => f.write_str("independent"),
            Self::Dependent => f.write_str("dependent"),
            Self::Uncertain => f.write_str("uncertain"),
        }
    }
}

/// Independence relation for a set of plan nodes.
///
/// This is used for Mazurkiewicz trace equivalence: two execution
/// sequences are equivalent if one can be transformed into the other
/// by commuting independent operations.
#[derive(Debug, Clone)]
pub struct IndependenceRelation {
    /// Pairs of node indices that are independent.
    /// Stored as (min, max) to ensure canonical ordering.
    independent_pairs: Vec<(usize, usize)>,
}

impl IndependenceRelation {
    /// Creates an empty independence relation.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            independent_pairs: Vec::new(),
        }
    }

    /// Adds an independence pair.
    pub fn add(&mut self, a: usize, b: usize) {
        let pair = if a <= b { (a, b) } else { (b, a) };
        if !self.independent_pairs.contains(&pair) {
            self.independent_pairs.push(pair);
        }
    }

    /// Checks if two nodes are independent.
    #[must_use]
    pub fn are_independent(&self, a: usize, b: usize) -> bool {
        let pair = if a <= b { (a, b) } else { (b, a) };
        self.independent_pairs.contains(&pair)
    }

    /// Returns the number of independent pairs.
    #[must_use]
    pub fn pair_count(&self) -> usize {
        self.independent_pairs.len()
    }

    /// Returns all independent pairs.
    #[must_use]
    pub fn pairs(&self) -> &[(usize, usize)] {
        &self.independent_pairs
    }
}

impl SideConditionChecker<'_> {
    // =========================================================================
    // Independence / commutativity analysis for Mazurkiewicz traces
    // =========================================================================

    /// Check if two nodes are independent (can be safely reordered).
    ///
    /// Two nodes are independent if:
    /// - They don't share any common descendants (structural independence)
    /// - They don't have data dependencies through obligations
    /// - Reordering them doesn't change observable behavior
    ///
    /// This is a conservative analysis: if uncertain, returns `Uncertain`.
    #[must_use]
    pub fn check_independence(&self, a: PlanId, b: PlanId) -> IndependenceResult {
        // Same node is trivially not independent with itself
        if a == b {
            return IndependenceResult::Dependent;
        }

        // Check structural independence (no shared nodes)
        if !self.are_independent(a, b) {
            return IndependenceResult::Dependent;
        }

        // Check obligation independence: if both have obligations,
        // they might conflict through external state
        let a_analysis = self.analysis.get(a);
        let b_analysis = self.analysis.get(b);

        match (a_analysis, b_analysis) {
            (Some(a_node), Some(b_node)) => {
                // If both have obligation flow, check for conflicts
                let a_obls = &a_node.obligation_flow;
                let b_obls = &b_node.obligation_flow;

                // If obligations intersect, they might depend on each other
                let has_conflict = a_obls.reserves.iter().any(|obl| {
                    b_obls.reserves.contains(obl)
                        || b_obls.must_resolve.contains(obl)
                        || b_obls.leak_on_cancel.contains(obl)
                }) || b_obls.reserves.iter().any(|obl| {
                    a_obls.reserves.contains(obl)
                        || a_obls.must_resolve.contains(obl)
                        || a_obls.leak_on_cancel.contains(obl)
                });

                if has_conflict {
                    return IndependenceResult::Uncertain;
                }

                IndependenceResult::Independent
            }
            _ => IndependenceResult::Uncertain,
        }
    }

    /// Check if two nodes commute (can be reordered without changing semantics).
    ///
    /// This is an alias for `check_independence` with a clearer name for
    /// users thinking in terms of commutativity.
    #[must_use]
    pub fn commutes(&self, a: PlanId, b: PlanId) -> bool {
        self.check_independence(a, b).is_independent()
    }

    /// Compute the independence relation for all leaf nodes in the DAG.
    ///
    /// This builds a relation that can be used for Mazurkiewicz trace
    /// equivalence checking: two sequences are equivalent if one can be
    /// transformed into the other by commuting independent operations.
    #[must_use]
    pub fn compute_independence_relation(&self) -> IndependenceRelation {
        let mut relation = IndependenceRelation::empty();
        let leaves = self.collect_leaves();

        // Check all pairs of leaves
        for (i, &a) in leaves.iter().enumerate() {
            for &b in leaves.iter().skip(i + 1) {
                if self.check_independence(a, b).is_independent() {
                    relation.add(a.index(), b.index());
                }
            }
        }

        relation
    }

    /// Collect all leaf node IDs reachable from the root.
    fn collect_leaves(&self) -> Vec<PlanId> {
        let Some(root) = self.dag.root() else {
            return Vec::new();
        };
        let mut leaves = Vec::new();
        self.collect_leaves_inner(root, &mut leaves);
        leaves
    }

    fn collect_leaves_inner(&self, id: PlanId, leaves: &mut Vec<PlanId>) {
        let Some(node) = self.dag.node(id) else {
            return;
        };
        match node {
            PlanNode::Leaf { .. } => {
                if !leaves.contains(&id) {
                    leaves.push(id);
                }
            }
            PlanNode::Join { children } | PlanNode::Race { children } => {
                for child in children {
                    self.collect_leaves_inner(*child, leaves);
                }
            }
            PlanNode::Timeout { child, .. } => {
                self.collect_leaves_inner(*child, leaves);
            }
        }
    }

    /// Check if a rewrite is valid up to Mazurkiewicz trace equivalence.
    ///
    /// A rewrite is valid if:
    /// 1. The structural transformation is correct
    /// 2. The rewrite preserves the independence relation
    /// 3. The observable behavior is preserved (up to reordering of independent operations)
    ///
    /// This is useful for rewrites like `Join[a, b] -> Join[b, a]` where
    /// the order doesn't matter if a and b are independent.
    #[must_use]
    pub fn rewrite_valid_up_to_trace(&self, before: PlanId, after: PlanId) -> bool {
        // Basic safety checks must still pass
        if !self.rewrite_preserves_obligations(before, after) {
            return false;
        }
        if !self.rewrite_preserves_cancel(before, after) {
            return false;
        }

        // Check that the independence relation is preserved
        // (i.e., operations that were independent before are still independent)
        let before_leaves = {
            let mut leaves = Vec::new();
            self.collect_leaves_inner(before, &mut leaves);
            leaves
        };
        let after_leaves = {
            let mut leaves = Vec::new();
            self.collect_leaves_inner(after, &mut leaves);
            leaves
        };

        // Same set of leaves means trace-equivalent
        let mut before_sorted: Vec<_> = before_leaves.iter().map(|id| id.index()).collect();
        let mut after_sorted: Vec<_> = after_leaves.iter().map(|id| id.index()).collect();
        before_sorted.sort_unstable();
        after_sorted.sort_unstable();

        before_sorted == after_sorted
    }

    /// Check if the children of a Join can be reordered.
    ///
    /// Returns the indices of children that can be freely reordered
    /// (all pairs in the returned set are mutually independent).
    #[must_use]
    pub fn reorderable_join_children(&self, children: &[PlanId]) -> Vec<Vec<usize>> {
        // Build groups of mutually independent children
        let mut groups: Vec<Vec<usize>> = Vec::new();

        for (i, &child) in children.iter().enumerate() {
            // Try to add to an existing group where this child is independent
            // from all current members
            let mut added = false;
            for group in &mut groups {
                let independent_from_all = group
                    .iter()
                    .all(|&j| self.check_independence(child, children[j]).is_independent());
                if independent_from_all {
                    group.push(i);
                    added = true;
                    break;
                }
            }
            if !added {
                groups.push(vec![i]);
            }
        }

        groups
    }

    /// Get a trace equivalence hint for a node.
    ///
    /// Returns a summary of which operations can commute, useful for
    /// the rewrite engine to know when certain rewrites are safe.
    #[must_use]
    pub fn trace_equivalence_hint(&self, id: PlanId) -> TraceEquivalenceHint {
        let Some(node) = self.dag.node(id) else {
            return TraceEquivalenceHint::Unknown;
        };

        match node {
            PlanNode::Leaf { .. } | PlanNode::Timeout { .. } => TraceEquivalenceHint::Atomic,
            PlanNode::Join { children } => {
                let independent_groups = self.reorderable_join_children(children);
                if independent_groups.len() == 1 && independent_groups[0].len() == children.len() {
                    TraceEquivalenceHint::FullyCommutative
                } else if independent_groups.iter().any(|g| g.len() > 1) {
                    TraceEquivalenceHint::PartiallyCommutative {
                        groups: independent_groups,
                    }
                } else {
                    TraceEquivalenceHint::Sequential
                }
            }
            PlanNode::Race { children } => {
                // Race children run concurrently; winner is nondeterministic
                // but the race itself is atomic from a trace perspective
                if self.children_pairwise_independent(children) {
                    TraceEquivalenceHint::FullyCommutative
                } else {
                    TraceEquivalenceHint::Atomic
                }
            }
        }
    }
}

/// Hint about trace equivalence for a plan node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceEquivalenceHint {
    /// Node is atomic (cannot be decomposed further).
    Atomic,
    /// All children commute (can be freely reordered).
    FullyCommutative,
    /// Some children commute within groups.
    PartiallyCommutative {
        /// Groups of child indices that can be freely reordered within the group.
        groups: Vec<Vec<usize>>,
    },
    /// Children must execute in sequence (no commutativity).
    Sequential,
    /// Insufficient information to determine hint.
    Unknown,
}

impl fmt::Display for TraceEquivalenceHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Atomic => f.write_str("atomic"),
            Self::FullyCommutative => f.write_str("fully-commutative"),
            Self::PartiallyCommutative { groups } => {
                write!(f, "partially-commutative({} groups)", groups.len())
            }
            Self::Sequential => f.write_str("sequential"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

#[cfg(test)]
#[path = "analysis_inline_tests.rs"]
mod tests;
