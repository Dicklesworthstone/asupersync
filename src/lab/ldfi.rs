//! Lineage-driven fault injection (LDFI): minimal fault-hypothesis generation.
//!
//! Blind chaos injects seeded-but-undirected faults. LDFI's insight is that a
//! *successful* execution's trace reveals which events causally supported the
//! outcome; the faults worth trying are exactly those that could remove that
//! support. Each independent way the outcome was produced is a *derivation* —
//! the set of fault-able events it depended on. The outcome survives a fault
//! hypothesis iff at least one derivation is left fully intact, so a hypothesis
//! that *breaks* the outcome must disable at least one event in **every**
//! derivation — i.e. it is a hitting set (transversal) of the family of
//! derivations. LDFI enumerates the *minimal* such hitting sets, bounded by a
//! depth budget, giving orders of magnitude fewer experiments than blind chaos.
//!
//! This module is the pure algorithmic core (bead
//! `asupersync-adaptive-control-plane-yj2nxx.4`): the support graph, the
//! bounded minimal-hitting-set generator, causal-cone extraction, and the
//! deterministic experiment-loop state machine. It has no I/O, no clock, and no
//! dependency on the chaos machinery — the lab-runtime adapter (consuming
//! `trace/causality`), fault injection, and the `frankenlab ldfi` CLI build on
//! top of it in sibling slices.
//!
//! # Soundness note
//!
//! Over-approximating a derivation's support (listing more events than strictly
//! necessary) is *safe*: it only produces extra hypotheses to test. Under-
//! approximation is unsafe — it can miss the fault that breaks the outcome. The
//! lineage-extraction layer must therefore err toward including an event when in
//! doubt. An empty derivation (an outcome that holds with no fault-able support)
//! is *unbreakable* by event faults within that lineage.

use std::collections::{BTreeMap, BTreeSet};

/// Identifier of a fault-able event (a send, ack, timer fire, or lease) drawn
/// from a lab trace. The pure generator treats it as an opaque ordered token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FaultEventId(pub u64);

impl FaultEventId {
    /// Wraps a raw event id.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// The raw event id.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for FaultEventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "e{}", self.0)
    }
}

/// Budget bounding the (NP-hard) hitting-set enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HittingSetBudget {
    /// Maximum hypothesis size (fault depth `k`) to consider.
    pub max_depth: usize,
    /// Maximum number of minimal hypotheses to return.
    pub max_hypotheses: usize,
}

impl Default for HittingSetBudget {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_hypotheses: 64,
        }
    }
}

/// The result of bounded minimal hitting-set enumeration over a support graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HittingSetResult {
    /// Minimal fault hypotheses (each a set of events to disable together) that
    /// hit every derivation, ordered smallest-first.
    pub hypotheses: Vec<BTreeSet<FaultEventId>>,
    /// Whether the full bounded space was explored without truncation. If
    /// `false`, the depth or hypothesis budget cut the search short.
    pub exhausted: bool,
    /// Whether some derivation had no fault-able events, making the outcome
    /// unbreakable by event faults within this lineage.
    pub unbreakable: bool,
    /// The depth budget the search ran under.
    pub max_depth: usize,
}

impl HittingSetResult {
    /// Whether no breaking hypothesis was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hypotheses.is_empty()
    }

    /// The number of hypotheses found.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hypotheses.len()
    }

    /// A per-corpus coverage certificate: `Some(k)` means no fault hypothesis of
    /// size `<= k` can break the outcome for *this* support graph (either the
    /// bounded space was exhausted with no hypothesis, or a derivation is
    /// unbreakable). Honestly scoped: this is per-trace, not universal.
    #[must_use]
    pub fn coverage_certificate(&self) -> Option<usize> {
        if self.hypotheses.is_empty() && (self.exhausted || self.unbreakable) {
            Some(self.max_depth)
        } else {
            None
        }
    }

    /// Runs the deterministic LDFI experiment loop over the generated
    /// hypotheses.
    ///
    /// The caller supplies the actual experiment executor (today usually a lab
    /// or chaos adapter). This pure loop owns the admission policy: test
    /// hypotheses in their deterministic minimal order, stop at the first
    /// invariant violation, and refuse to over-claim coverage when either the
    /// experiment budget or the hypothesis-search budget cut the run short.
    pub fn run_experiments<F>(
        &self,
        budget: LdfiExperimentBudget,
        mut experiment: F,
    ) -> LdfiExperimentReport
    where
        F: FnMut(&BTreeSet<FaultEventId>) -> LdfiExperimentObservation,
    {
        let mut refuted = Vec::new();
        if self.hypotheses.is_empty() {
            let status = if self.exhausted || self.unbreakable {
                LdfiExperimentStatus::RefutedUpToDepth {
                    max_depth: self.max_depth,
                }
            } else {
                LdfiExperimentStatus::HypothesisSearchTruncated
            };
            return LdfiExperimentReport {
                status,
                experiments_run: 0,
                refuted,
            };
        }

        let max_experiments = budget.max_experiments.min(self.hypotheses.len());
        for hypothesis in self.hypotheses.iter().take(max_experiments) {
            match experiment(hypothesis) {
                LdfiExperimentObservation::InvariantViolated => {
                    return LdfiExperimentReport {
                        status: LdfiExperimentStatus::FoundViolation {
                            hypothesis: hypothesis.clone(),
                        },
                        experiments_run: refuted.len() + 1,
                        refuted,
                    };
                }
                LdfiExperimentObservation::InvariantHeld => {
                    refuted.push(hypothesis.clone());
                }
            }
        }

        let status = if refuted.len() < self.hypotheses.len() {
            LdfiExperimentStatus::ExperimentBudgetExhausted {
                remaining_hypotheses: self.hypotheses.len() - refuted.len(),
            }
        } else if self.exhausted {
            LdfiExperimentStatus::RefutedUpToDepth {
                max_depth: self.max_depth,
            }
        } else {
            LdfiExperimentStatus::HypothesisSearchTruncated
        };

        LdfiExperimentReport {
            experiments_run: refuted.len(),
            status,
            refuted,
        }
    }
}

/// Budget for the deterministic experiment loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdfiExperimentBudget {
    /// Maximum generated hypotheses to execute in this loop.
    pub max_experiments: usize,
}

impl Default for LdfiExperimentBudget {
    fn default() -> Self {
        Self {
            max_experiments: usize::MAX,
        }
    }
}

/// Result of one injected-fault experiment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdfiExperimentObservation {
    /// The invariant still held under this hypothesis.
    InvariantHeld,
    /// The invariant failed under this hypothesis.
    InvariantViolated,
}

/// Stop condition for the LDFI experiment loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdfiExperimentStatus {
    /// A concrete hypothesis broke the invariant.
    FoundViolation {
        /// The fault hypothesis that produced the violation.
        hypothesis: BTreeSet<FaultEventId>,
    },
    /// Every generated hypothesis was refuted and the hypothesis generator
    /// exhausted the requested depth, so this trace corpus has no counterexample
    /// at or below `max_depth`.
    RefutedUpToDepth {
        /// The fault depth covered for this trace corpus.
        max_depth: usize,
    },
    /// The experiment budget ran out before every generated hypothesis ran.
    ExperimentBudgetExhausted {
        /// Generated hypotheses still untested.
        remaining_hypotheses: usize,
    },
    /// The hitting-set generator itself was truncated, so even refuting all
    /// returned hypotheses is not a coverage proof.
    HypothesisSearchTruncated,
}

/// Deterministic summary of a pure LDFI experiment-loop run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdfiExperimentReport {
    /// Why the loop stopped.
    pub status: LdfiExperimentStatus,
    /// Number of hypotheses actually executed.
    pub experiments_run: usize,
    /// Hypotheses that were tested and did not violate the invariant.
    pub refuted: Vec<BTreeSet<FaultEventId>>,
}

impl LdfiExperimentReport {
    /// Per-corpus coverage certificate from this experiment run, if any.
    #[must_use]
    pub fn coverage_certificate(&self) -> Option<usize> {
        match self.status {
            LdfiExperimentStatus::RefutedUpToDepth { max_depth } => Some(max_depth),
            LdfiExperimentStatus::FoundViolation { .. }
            | LdfiExperimentStatus::ExperimentBudgetExhausted { .. }
            | LdfiExperimentStatus::HypothesisSearchTruncated => None,
        }
    }
}

/// The lineage support of a target outcome: each derivation is the set of
/// fault-able events one successful production of the outcome depended on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SupportGraph {
    derivations: Vec<BTreeSet<FaultEventId>>,
}

impl SupportGraph {
    /// An empty support graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one derivation (one causal way the outcome was produced).
    pub fn add_derivation(&mut self, events: impl IntoIterator<Item = FaultEventId>) {
        self.derivations.push(events.into_iter().collect());
    }

    /// The recorded derivations.
    #[must_use]
    pub fn derivations(&self) -> &[BTreeSet<FaultEventId>] {
        &self.derivations
    }

    /// Whether no derivations have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.derivations.is_empty()
    }

    /// Enumerates minimal fault hypotheses (hitting sets) up to the budget.
    ///
    /// Branches on the events of the first not-yet-hit derivation (Berge-style
    /// transversal search), which is far cheaper than enumerating all
    /// size-`<=k` subsets, then filters the collected transversals down to the
    /// minimal ones.
    #[must_use]
    pub fn minimal_hitting_sets(&self, budget: HittingSetBudget) -> HittingSetResult {
        if self.derivations.is_empty() {
            return HittingSetResult {
                hypotheses: Vec::new(),
                exhausted: true,
                unbreakable: false,
                max_depth: budget.max_depth,
            };
        }
        if self.derivations.iter().any(|d| d.is_empty()) {
            return HittingSetResult {
                hypotheses: Vec::new(),
                exhausted: true,
                unbreakable: true,
                max_depth: budget.max_depth,
            };
        }

        // Collect a bounded pool of raw transversals, then minimize. The pool
        // is larger than the requested count so minimization has room to work.
        let raw_cap = budget
            .max_hypotheses
            .saturating_mul(4)
            .max(budget.max_hypotheses)
            .max(1);
        let mut found: Vec<BTreeSet<FaultEventId>> = Vec::new();
        let mut exhausted = true;
        let mut partial = BTreeSet::new();
        self.search(
            &mut partial,
            budget.max_depth,
            raw_cap,
            &mut found,
            &mut exhausted,
        );

        let mut hypotheses = filter_minimal(found);
        if hypotheses.len() > budget.max_hypotheses {
            hypotheses.truncate(budget.max_hypotheses);
            exhausted = false;
        }

        HittingSetResult {
            hypotheses,
            exhausted,
            unbreakable: false,
            max_depth: budget.max_depth,
        }
    }

    fn search(
        &self,
        partial: &mut BTreeSet<FaultEventId>,
        remaining_depth: usize,
        cap: usize,
        found: &mut Vec<BTreeSet<FaultEventId>>,
        exhausted: &mut bool,
    ) {
        if found.len() >= cap {
            *exhausted = false;
            return;
        }
        // First derivation not yet hit by the partial hypothesis.
        match self.derivations.iter().find(|d| d.is_disjoint(partial)) {
            None => {
                // `partial` hits every derivation: a transversal.
                found.push(partial.clone());
            }
            Some(clause) => {
                if remaining_depth == 0 {
                    // Could not cover within the depth budget on this branch.
                    *exhausted = false;
                    return;
                }
                for &event in clause {
                    if partial.contains(&event) {
                        continue;
                    }
                    partial.insert(event);
                    self.search(partial, remaining_depth - 1, cap, found, exhausted);
                    partial.remove(&event);
                    if found.len() >= cap {
                        *exhausted = false;
                        return;
                    }
                }
            }
        }
    }
}

/// Keeps only the minimal sets: a set is dropped if any already-kept set is a
/// subset of it. Sorting smallest-first makes a single pass sufficient and also
/// de-duplicates identical transversals.
fn filter_minimal(mut sets: Vec<BTreeSet<FaultEventId>>) -> Vec<BTreeSet<FaultEventId>> {
    sets.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.iter().cmp(b.iter())));
    let mut result: Vec<BTreeSet<FaultEventId>> = Vec::new();
    for candidate in sets {
        if !result.iter().any(|kept| kept.is_subset(&candidate)) {
            result.push(candidate);
        }
    }
    result
}

/// A causal happens-before relation over lab events, the input to lineage
/// extraction (bead `yj2nxx.4`, WHAT step 1).
///
/// This is the pure boundary between the trace machinery and the hitting-set
/// core: a sibling lab-runtime adapter populates it from `trace/causality`
/// happens-before edges, then [`SupportGraph::from_causal_cones`] turns the
/// causal cone of each outcome production into a derivation. Keeping the graph
/// here free of any trace, I/O, or clock types is deliberate — the algorithm
/// (backward reachability over predecessors) is what is reusable and testable;
/// the adapter that fills it is not.
///
/// Each event carries a *fault-able* flag: a fault can only be injected on the
/// fault-able events (sends, acks, timer fires, leases). Non-fault-able events
/// (local computation, the outcome assertion itself) still propagate causality —
/// their predecessors are followed — but they never appear in a derivation,
/// because there is no fault to inject on them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CausalLineage {
    /// Direct happens-before predecessors of each registered event.
    predecessors: BTreeMap<FaultEventId, BTreeSet<FaultEventId>>,
    /// Events on which a fault can be injected.
    faultable: BTreeSet<FaultEventId>,
}

impl CausalLineage {
    /// An empty lineage.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `event`, setting whether a fault can be injected on it.
    ///
    /// Idempotent on the causal structure; re-declaring an event only updates its
    /// fault-able flag (so a later non-fault-able declaration can demote it).
    pub fn add_event(&mut self, event: FaultEventId, faultable: bool) {
        self.predecessors.entry(event).or_default();
        if faultable {
            self.faultable.insert(event);
        } else {
            self.faultable.remove(&event);
        }
    }

    /// Marks `event` fault-able, registering it if new. Idempotent.
    pub fn mark_faultable(&mut self, event: FaultEventId) {
        self.predecessors.entry(event).or_default();
        self.faultable.insert(event);
    }

    /// Records a happens-before edge: `before` causally precedes `after`.
    ///
    /// Both endpoints are registered (non-fault-able unless separately marked).
    /// A self-edge is ignored — an event cannot causally precede itself.
    pub fn add_happens_before(&mut self, before: FaultEventId, after: FaultEventId) {
        self.predecessors.entry(before).or_default();
        let preds = self.predecessors.entry(after).or_default();
        if before != after {
            preds.insert(before);
        }
    }

    /// Whether `event` is fault-able.
    #[must_use]
    pub fn is_faultable(&self, event: FaultEventId) -> bool {
        self.faultable.contains(&event)
    }

    /// The full backward causal cone of `target`: `target` itself plus every
    /// event that happens-before it, transitively. Deterministic (BTree order)
    /// and cycle-safe (a malformed cyclic input still terminates).
    #[must_use]
    pub fn causal_cone(&self, target: FaultEventId) -> BTreeSet<FaultEventId> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![target];
        while let Some(event) = stack.pop() {
            if !seen.insert(event) {
                continue;
            }
            if let Some(preds) = self.predecessors.get(&event) {
                for &pred in preds {
                    if !seen.contains(&pred) {
                        stack.push(pred);
                    }
                }
            }
        }
        seen
    }

    /// The fault-able support of `target`: its causal cone intersected with the
    /// fault-able events. This is the over-approximating lineage support of one
    /// production of the outcome — per the soundness note, include-when-in-doubt,
    /// so the full cone (not a minimal cut) is the safe choice.
    #[must_use]
    pub fn support_of(&self, target: FaultEventId) -> BTreeSet<FaultEventId> {
        self.causal_cone(target)
            .into_iter()
            .filter(|event| self.faultable.contains(event))
            .collect()
    }
}

impl SupportGraph {
    /// Builds a single-derivation support graph from the fault-able causal cone
    /// of one outcome-producing event.
    #[must_use]
    pub fn from_causal_cone(lineage: &CausalLineage, target: FaultEventId) -> Self {
        Self::from_causal_cones(lineage, std::iter::once(target))
    }

    /// Builds a support graph from several alternative productions of an outcome:
    /// each `target` contributes one derivation (its fault-able causal cone).
    ///
    /// The outcome survives a fault hypothesis iff at least one target's cone is
    /// left fully intact, so the minimal hitting sets over these derivations are
    /// exactly the fault hypotheses worth testing — composing this extractor with
    /// [`SupportGraph::minimal_hitting_sets`] is the AC1 lineage→hypothesis path.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::lab::ldfi::{CausalLineage, FaultEventId, HittingSetBudget, SupportGraph};
    ///
    /// // ack(2) and ack(3) each independently confirm delivery; both depend on
    /// // the single send(1). Dropping send(1) breaks every path.
    /// let (send, ack_a, ack_b, ok_a, ok_b) = (
    ///     FaultEventId::new(1),
    ///     FaultEventId::new(2),
    ///     FaultEventId::new(3),
    ///     FaultEventId::new(10),
    ///     FaultEventId::new(11),
    /// );
    /// let mut lineage = CausalLineage::new();
    /// for e in [send, ack_a, ack_b] {
    ///     lineage.mark_faultable(e);
    /// }
    /// lineage.add_happens_before(send, ack_a);
    /// lineage.add_happens_before(send, ack_b);
    /// lineage.add_happens_before(ack_a, ok_a); // ok_* are non-fault-able outcomes
    /// lineage.add_happens_before(ack_b, ok_b);
    ///
    /// let graph = SupportGraph::from_causal_cones(&lineage, [ok_a, ok_b]);
    /// let result = graph.minimal_hitting_sets(HittingSetBudget::default());
    /// // The minimal breaking hypothesis is exactly {send}.
    /// assert_eq!(result.hypotheses.first().map(|h| h.len()), Some(1));
    /// assert!(result.hypotheses[0].contains(&send));
    /// ```
    #[must_use]
    pub fn from_causal_cones(
        lineage: &CausalLineage,
        targets: impl IntoIterator<Item = FaultEventId>,
    ) -> Self {
        let mut graph = Self::new();
        for target in targets {
            graph.add_derivation(lineage.support_of(target));
        }
        graph
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: u64) -> FaultEventId {
        FaultEventId::new(id)
    }

    fn set(ids: &[u64]) -> BTreeSet<FaultEventId> {
        ids.iter().copied().map(FaultEventId::new).collect()
    }

    #[test]
    fn single_shared_event_is_a_depth_one_hypothesis() {
        // AC1: one event supports every derivation -> dropping it breaks the
        // outcome; LDFI finds it at depth 1.
        let mut g = SupportGraph::new();
        g.add_derivation([ev(1), ev(2)]);
        g.add_derivation([ev(1), ev(3)]);
        g.add_derivation([ev(1), ev(4)]);
        let result = g.minimal_hitting_sets(HittingSetBudget::default());
        assert!(result.hypotheses.contains(&set(&[1])));
        // The single-event hypothesis is minimal, so no larger superset of {1}
        // is reported.
        assert!(
            result
                .hypotheses
                .iter()
                .all(|h| !h.is_superset(&set(&[1])) || *h == set(&[1]))
        );
        assert!(result.exhausted);
        assert!(result.coverage_certificate().is_none());
    }

    #[test]
    fn disjoint_derivations_require_a_depth_two_hypothesis() {
        // No single event hits both derivations; the minimal hypothesis has size 2.
        let mut g = SupportGraph::new();
        g.add_derivation([ev(1), ev(2)]);
        g.add_derivation([ev(3), ev(4)]);
        let result = g.minimal_hitting_sets(HittingSetBudget::default());
        assert!(result.hypotheses.iter().all(|h| h.len() == 2));
        // Every hypothesis must hit both derivations.
        for h in &result.hypotheses {
            assert!(!h.is_disjoint(&set(&[1, 2])));
            assert!(!h.is_disjoint(&set(&[3, 4])));
        }
        assert!(result.exhausted);
    }

    #[test]
    fn unbreakable_outcome_yields_coverage_certificate() {
        // AC2: a derivation with no fault-able events cannot be hit.
        let mut g = SupportGraph::new();
        g.add_derivation([ev(1)]);
        g.add_derivation(std::iter::empty());
        let result = g.minimal_hitting_sets(HittingSetBudget::default());
        assert!(result.is_empty());
        assert!(result.unbreakable);
        assert_eq!(result.coverage_certificate(), Some(3));
    }

    #[test]
    fn depth_budget_limits_hypothesis_size() {
        // Three pairwise-disjoint derivations need a size-3 hitting set; a
        // depth-2 budget cannot cover them, so no hypothesis and not exhausted.
        let mut g = SupportGraph::new();
        g.add_derivation([ev(1), ev(2)]);
        g.add_derivation([ev(3), ev(4)]);
        g.add_derivation([ev(5), ev(6)]);
        let result = g.minimal_hitting_sets(HittingSetBudget {
            max_depth: 2,
            max_hypotheses: 64,
        });
        assert!(result.is_empty());
        assert!(!result.exhausted);
        // Not exhausted => no coverage certificate.
        assert!(result.coverage_certificate().is_none());
    }

    #[test]
    fn determinism() {
        let mut g = SupportGraph::new();
        g.add_derivation([ev(1), ev(2), ev(3)]);
        g.add_derivation([ev(2), ev(4)]);
        let a = g.minimal_hitting_sets(HittingSetBudget::default());
        let b = g.minimal_hitting_sets(HittingSetBudget::default());
        assert_eq!(a, b);
    }

    #[test]
    fn empty_support_graph_is_trivially_exhausted() {
        let g = SupportGraph::new();
        let result = g.minimal_hitting_sets(HittingSetBudget::default());
        assert!(result.is_empty());
        assert!(result.exhausted);
        assert!(!result.unbreakable);
    }

    #[test]
    fn causal_cone_collects_transitive_faultable_ancestry_only() {
        // 1 -> 2 -> 3 (-> 4, non-fault-able outcome). The support of 4 is the
        // fault-able cone {1,2,3}; the non-fault-able 4 propagates causality but
        // never appears in a derivation.
        let mut lineage = CausalLineage::new();
        for id in [1, 2, 3] {
            lineage.mark_faultable(ev(id));
        }
        lineage.add_happens_before(ev(1), ev(2));
        lineage.add_happens_before(ev(2), ev(3));
        lineage.add_happens_before(ev(3), ev(4)); // 4 left non-fault-able

        assert_eq!(lineage.causal_cone(ev(4)), set(&[1, 2, 3, 4]));
        assert_eq!(lineage.support_of(ev(4)), set(&[1, 2, 3]));
        assert!(!lineage.is_faultable(ev(4)));
    }

    #[test]
    fn shared_root_cone_yields_depth_one_hypothesis_end_to_end() {
        // Two independent ack paths both rooted at the single send: dropping the
        // send breaks both, so the lineage->hitting-set pipeline returns {send}.
        let mut lineage = CausalLineage::new();
        for id in [1, 2, 3] {
            lineage.mark_faultable(ev(id));
        }
        lineage.add_happens_before(ev(1), ev(2));
        lineage.add_happens_before(ev(1), ev(3));
        lineage.add_happens_before(ev(2), ev(10));
        lineage.add_happens_before(ev(3), ev(11));

        let graph = SupportGraph::from_causal_cones(&lineage, [ev(10), ev(11)]);
        assert_eq!(graph.derivations().len(), 2);
        let result = graph.minimal_hitting_sets(HittingSetBudget::default());
        assert!(result.hypotheses.contains(&set(&[1])));
        assert!(result.coverage_certificate().is_none());
    }

    #[test]
    fn outcome_with_no_faultable_support_is_unbreakable() {
        // The outcome is produced with no fault-able ancestry: its derivation is
        // empty, so it cannot be hit -> coverage certificate.
        let mut lineage = CausalLineage::new();
        lineage.add_event(ev(7), false); // a non-fault-able local outcome
        let graph = SupportGraph::from_causal_cone(&lineage, ev(7));
        let result = graph.minimal_hitting_sets(HittingSetBudget::default());
        assert!(result.unbreakable);
        assert_eq!(result.coverage_certificate(), Some(3));
    }

    #[test]
    fn add_event_can_demote_a_previously_faultable_event() {
        let mut lineage = CausalLineage::new();
        lineage.mark_faultable(ev(1));
        assert!(lineage.is_faultable(ev(1)));
        lineage.add_event(ev(1), false);
        assert!(!lineage.is_faultable(ev(1)));
        assert!(lineage.support_of(ev(1)).is_empty());
    }
}
