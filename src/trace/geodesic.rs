//! Geodesic schedule normalization: minimize owner switches in linear extensions.
//!
//! This module provides deterministic heuristics for producing low-switch-cost
//! linearizations of trace posets. The goal is canonical, minimal-entropy
//! replay schedules.
//!
//! # Problem Statement
//!
//! Given a trace poset (dependency DAG) and owner assignments for events:
//! - Find a linear extension (total order respecting dependencies)
//! - Minimize the number of "owner switches" (adjacent events with different owners)
//!
//! # Algorithms
//!
//! - **Exact (A\*)**: Optimal for bounded traces, exponential worst-case
//! - **Greedy**: O(n²) - pick available events that match current owner first
//! - **Beam search**: O(n² * beam_width) - explore multiple candidate paths
//!
//! # Determinism
//!
//! All algorithms produce identical output for identical input:
//! - Tie-breaking uses stable event indices (lowest index wins)
//! - No randomness except explicit seeds
//! - Iteration order is deterministic (sorted by index)
//!
//! # Correctness Sketch
//!
//! Let `P` be the trace poset (dependency DAG). Every algorithm constructs a
//! schedule by repeatedly selecting from the set of *available* events (those
//! whose predecessors have all been scheduled) and then updating that frontier
//! by removing the chosen event and decrementing successor indegrees. Thus, the
//! produced schedule is a linear extension of `P`, which preserves happens-
//! before: for every edge `u -> v` in `P`, `u` appears before `v` in the
//! schedule.
//!
//! Switch cost is the number of adjacent owner changes. The exact solver uses
//! A* search over partial schedules with `g` = switches accumulated so far and
//! `h` = `owner_switch_lower_bound`, an admissible lower bound on remaining
//! switches. Because the heuristic is admissible and the state space is finite,
//! A* returns an optimal schedule minimizing total switch count. Greedy and
//! beam-search variants preserve happens-before but trade optimality for speed.

use crate::trace::event_structure::{OwnerKey, TracePoset};
use crate::util::DetHashMap;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
#[cfg(feature = "test-internals")]
use std::fmt::Write;

/// Result of geodesic normalization.
#[derive(Debug, Clone)]
pub struct GeodesicResult {
    /// The linearized schedule (indices into original trace).
    pub schedule: Vec<usize>,
    /// Number of owner switches in this schedule.
    pub switch_count: usize,
    /// Algorithm used to produce this result.
    pub algorithm: GeodesicAlgorithm,
}

/// Which algorithm produced the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeodesicAlgorithm {
    /// Exact A* search (bounded traces).
    ExactAStar,
    /// Greedy "same owner first" heuristic.
    Greedy,
    /// Beam search with specified width.
    BeamSearch {
        /// Beam width used for search.
        width: usize,
    },
    /// Fallback to topological sort (no optimization).
    TopoSort,
}

/// Configuration for geodesic normalization.
#[derive(Debug, Clone)]
pub struct GeodesicConfig {
    /// Maximum trace size for exact search (larger traces use heuristics).
    pub exact_threshold: usize,
    /// Maximum trace size for beam search (larger traces use greedy).
    pub beam_threshold: usize,
    /// Beam width for beam search.
    pub beam_width: usize,
    /// Step budget (max work units before fallback).
    pub step_budget: usize,
}

impl Default for GeodesicConfig {
    fn default() -> Self {
        Self {
            exact_threshold: 30,
            beam_threshold: 100,
            beam_width: 8,
            step_budget: 100_000,
        }
    }
}

impl GeodesicConfig {
    /// Create a config that always uses greedy (fast, lower quality).
    #[must_use]
    pub fn greedy_only() -> Self {
        Self {
            exact_threshold: 0,
            beam_threshold: 0,
            beam_width: 1,
            step_budget: usize::MAX,
        }
    }

    /// Create a config for high-quality results (slower).
    #[must_use]
    pub fn high_quality() -> Self {
        Self {
            exact_threshold: 30,
            beam_threshold: 200,
            beam_width: 16,
            step_budget: 1_000_000,
        }
    }
}

// ============================================================================
// Decision ledger: debug-only structured log of normalization decisions
// ============================================================================

/// A single decision recorded during geodesic normalization.
///
/// Each entry captures one decision point: algorithm selection, event choice,
/// or tie-break resolution. The ledger is deterministic — identical inputs
/// produce identical ledger entries.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone)]
pub enum DecisionEntry {
    /// Which algorithm was selected for this trace.
    AlgorithmSelected {
        /// The algorithm chosen.
        algorithm: GeodesicAlgorithm,
        /// Number of events in the poset.
        trace_len: usize,
        /// Why this algorithm was chosen (thresholds vs trace size).
        reason: String,
    },
    /// An event was chosen at a greedy step.
    GreedyChoice {
        /// Step index (0-based).
        step: usize,
        /// The event index chosen.
        chosen: usize,
        /// Owner of the chosen event.
        chosen_owner: OwnerKey,
        /// Whether the chosen event matched the current owner (no switch).
        owner_match: bool,
        /// Number of same-owner successors for the chosen event.
        same_owner_successors: usize,
        /// Number of candidates available at this step.
        candidates: usize,
        /// Runner-up event index, if any.
        runner_up: Option<usize>,
    },
    /// Beam search pruned candidates at a level.
    BeamPrune {
        /// Schedule depth at this prune.
        depth: usize,
        /// Number of candidates before pruning.
        candidates_before: usize,
        /// Number of candidates after pruning (beam width).
        candidates_after: usize,
        /// Switch count of the best surviving candidate.
        best_switch_count: usize,
        /// Switch count of the worst surviving candidate.
        worst_switch_count: usize,
    },
    /// A* search expanded a state.
    ExactExpansion {
        /// Number of events placed so far.
        depth: usize,
        /// Current cost (g).
        cost: usize,
        /// Heuristic estimate (h).
        heuristic: usize,
        /// Number of successors generated.
        successors: usize,
    },
    /// Algorithm fell back to topological sort.
    Fallback {
        /// Why the fallback was needed.
        reason: String,
    },
}

/// A structured log of all decisions made during geodesic normalization.
///
/// The ledger is deterministic: identical inputs produce identical entries.
/// It is intended for debugging and test assertions, not production use.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone)]
pub struct DecisionLedger {
    /// All decisions in chronological order.
    pub entries: Vec<DecisionEntry>,
    /// The final result.
    pub result: GeodesicResult,
}

#[cfg(feature = "test-internals")]
impl DecisionLedger {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            result: GeodesicResult {
                schedule: vec![],
                switch_count: 0,
                algorithm: GeodesicAlgorithm::Greedy,
            },
        }
    }

    fn push(&mut self, entry: DecisionEntry) {
        self.entries.push(entry);
    }

    /// Returns a deterministic human-readable summary of the decision ledger.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut s = format!(
            "geodesic: algorithm={:?}, switches={}, schedule_len={}\n",
            self.result.algorithm,
            self.result.switch_count,
            self.result.schedule.len(),
        );
        for (i, entry) in self.entries.iter().enumerate() {
            match entry {
                DecisionEntry::AlgorithmSelected {
                    algorithm,
                    trace_len,
                    reason,
                } => {
                    let _ = writeln!(
                        &mut s,
                        "  [{i}] SELECT algo={algorithm:?} n={trace_len} reason=\"{reason}\""
                    );
                }
                DecisionEntry::GreedyChoice {
                    step,
                    chosen,
                    chosen_owner,
                    owner_match,
                    same_owner_successors,
                    candidates,
                    runner_up,
                } => {
                    let match_tag = if *owner_match { "match" } else { "switch" };
                    let runner = runner_up.map_or_else(|| "none".to_string(), |r| r.to_string());
                    let _ = writeln!(
                        &mut s,
                        "  [{i}] GREEDY step={step} chose={chosen} \
                         owner={chosen_owner:?} {match_tag} \
                         succ_same={same_owner_successors} \
                         pool={candidates} runner_up={runner}"
                    );
                }
                DecisionEntry::BeamPrune {
                    depth,
                    candidates_before,
                    candidates_after,
                    best_switch_count,
                    worst_switch_count,
                } => {
                    let _ = writeln!(
                        &mut s,
                        "  [{i}] BEAM_PRUNE depth={depth} \
                         {candidates_before}->{candidates_after} \
                         switches=[{best_switch_count}..{worst_switch_count}]"
                    );
                }
                DecisionEntry::ExactExpansion {
                    depth,
                    cost,
                    heuristic,
                    successors,
                } => {
                    let _ = writeln!(
                        &mut s,
                        "  [{i}] A*_EXPAND depth={depth} g={cost} h={heuristic} \
                         f={} children={successors}",
                        cost + heuristic
                    );
                }
                DecisionEntry::Fallback { reason } => {
                    let _ = writeln!(&mut s, "  [{i}] FALLBACK reason=\"{reason}\"");
                }
            }
        }
        s
    }
}

/// Normalize with a decision ledger for debugging/testing.
///
/// Same semantics as [`normalize`], but also returns a [`DecisionLedger`]
/// recording every decision point. Gated behind `test-internals` to avoid
/// any overhead in production builds.
#[cfg(feature = "test-internals")]
#[must_use]
pub fn normalize_with_ledger(poset: &TracePoset, config: &GeodesicConfig) -> DecisionLedger {
    let n = poset.len();
    let mut ledger = DecisionLedger::new();

    if n == 0 {
        ledger.result = GeodesicResult {
            schedule: vec![],
            switch_count: 0,
            algorithm: GeodesicAlgorithm::Greedy,
        };
        return ledger;
    }

    if n == 1 {
        ledger.result = GeodesicResult {
            schedule: vec![0],
            switch_count: 0,
            algorithm: GeodesicAlgorithm::Greedy,
        };
        return ledger;
    }

    if n <= config.exact_threshold {
        ledger.push(DecisionEntry::AlgorithmSelected {
            algorithm: GeodesicAlgorithm::ExactAStar,
            trace_len: n,
            reason: format!("n={n} <= exact_threshold={}", config.exact_threshold),
        });
        if let Some(result) = exact_search_with_ledger(poset, config.step_budget, &mut ledger) {
            ledger.result = result;
            return ledger;
        }
        ledger.push(DecisionEntry::Fallback {
            reason: "exact search exhausted budget, trying heuristic".into(),
        });
    }

    if n <= config.beam_threshold && config.beam_width > 1 {
        ledger.push(DecisionEntry::AlgorithmSelected {
            algorithm: GeodesicAlgorithm::BeamSearch {
                width: config.beam_width,
            },
            trace_len: n,
            reason: format!(
                "n={n} <= beam_threshold={}, beam_width={}",
                config.beam_threshold, config.beam_width
            ),
        });
        ledger.result =
            beam_search_with_ledger(poset, config.beam_width, config.step_budget, &mut ledger);
    } else {
        ledger.push(DecisionEntry::AlgorithmSelected {
            algorithm: GeodesicAlgorithm::Greedy,
            trace_len: n,
            reason: format!(
                "n={n} > beam_threshold={} or beam_width={}",
                config.beam_threshold, config.beam_width
            ),
        });
        ledger.result = greedy_with_ledger(poset, config.step_budget, &mut ledger);
    }
    ledger
}

#[cfg(feature = "test-internals")]
#[allow(clippy::too_many_lines)]
fn exact_search_with_ledger(
    poset: &TracePoset,
    step_budget: usize,
    ledger: &mut DecisionLedger,
) -> Option<GeodesicResult> {
    let n = poset.len();
    if n == 0 || n > 63 {
        return None;
    }

    let pred_masks = build_pred_masks(poset);
    let full_mask = (1u64 << n).saturating_sub(1);

    let start = ExactState {
        mask: 0,
        last_owner: None,
    };
    let mut open = BinaryHeap::new();
    let mut best_g: DetHashMap<ExactState, usize> = DetHashMap::default();
    let mut parent: DetHashMap<ExactState, ExactParent> = DetHashMap::default();

    let start_h = owner_switch_lower_bound(poset, start.mask, start.last_owner);
    open.push(ExactQueueEntry {
        f: start_h,
        g: 0,
        mask: 0,
        last_owner: None,
    });
    best_g.insert(start, 0);

    let mut steps = 0usize;
    // Sample expansions for the ledger (every 100th or when we find the goal)
    let mut last_logged_depth = 0;
    while let Some(entry) = open.pop() {
        if steps >= step_budget {
            return None;
        }
        steps = steps.saturating_add(1);

        let state = ExactState {
            mask: entry.mask,
            last_owner: entry.last_owner,
        };

        if entry.g.ne(best_g.get(&state).unwrap_or(&usize::MAX)) {
            continue;
        }

        let depth = state.mask.count_ones() as usize;

        if state.mask == full_mask {
            let schedule = reconstruct_exact_schedule(state, &parent, n);
            let h = 0;
            ledger.push(DecisionEntry::ExactExpansion {
                depth,
                cost: entry.g,
                heuristic: h,
                successors: 0,
            });
            return Some(GeodesicResult {
                schedule,
                switch_count: entry.g,
                algorithm: GeodesicAlgorithm::ExactAStar,
            });
        }

        let mut successors = 0usize;
        for (idx, &pred_mask) in pred_masks.iter().enumerate() {
            let bit = 1u64 << idx;
            if state.mask & bit != 0 {
                continue;
            }
            if pred_mask & !state.mask != 0 {
                continue;
            }

            let owner = poset.owner(idx);
            let mut new_g = entry.g;
            if let Some(prev_owner) = state.last_owner {
                if prev_owner != owner {
                    new_g = new_g.saturating_add(1);
                }
            }
            let new_state = ExactState {
                mask: state.mask | bit,
                last_owner: Some(owner),
            };

            let best = best_g.get(&new_state).copied().unwrap_or(usize::MAX);
            if new_g < best {
                best_g.insert(new_state, new_g);
                parent.insert(
                    new_state,
                    ExactParent {
                        prev: state,
                        chosen: idx,
                    },
                );
                let h = owner_switch_lower_bound(poset, new_state.mask, new_state.last_owner);
                open.push(ExactQueueEntry {
                    f: new_g.saturating_add(h),
                    g: new_g,
                    mask: new_state.mask,
                    last_owner: new_state.last_owner,
                });
                successors = successors.saturating_add(1);
            }
        }

        // Log at each new depth level to keep the ledger bounded
        if depth > last_logged_depth {
            let h = owner_switch_lower_bound(poset, state.mask, state.last_owner);
            ledger.push(DecisionEntry::ExactExpansion {
                depth,
                cost: entry.g,
                heuristic: h,
                successors,
            });
            last_logged_depth = depth;
        }
    }

    None
}

#[cfg(feature = "test-internals")]
fn greedy_with_ledger(
    poset: &TracePoset,
    step_budget: usize,
    ledger: &mut DecisionLedger,
) -> GeodesicResult {
    let n = poset.len();
    let mut indeg: Vec<usize> = (0..n).map(|i| poset.preds(i).len()).collect();
    let mut available: Vec<usize> = (0..n).filter(|&i| indeg[i] == 0).collect();
    let mut schedule = Vec::with_capacity(n);
    let mut current_owner: Option<OwnerKey> = None;
    let mut switch_count: usize = 0;
    let mut steps = 0;

    while !available.is_empty() && steps < step_budget {
        steps = steps.saturating_add(1);

        available.sort_by(|&a, &b| {
            let owner_a = poset.owner(a);
            let owner_b = poset.owner(b);
            let match_a = current_owner == Some(owner_a);
            let match_b = current_owner == Some(owner_b);
            if match_a != match_b {
                return match_b.cmp(&match_a);
            }
            let score_a = count_same_owner_successors(poset, a, &indeg);
            let score_b = count_same_owner_successors(poset, b, &indeg);
            if score_a != score_b {
                return score_b.cmp(&score_a);
            }
            a.cmp(&b)
        });

        let chosen = available[0];
        let chosen_owner = poset.owner(chosen);
        let owner_match = current_owner == Some(chosen_owner);
        let same_owner_successors = count_same_owner_successors(poset, chosen, &indeg);
        let runner_up = if available.len() > 1 {
            Some(available[1])
        } else {
            None
        };

        ledger.push(DecisionEntry::GreedyChoice {
            step: steps.saturating_sub(1),
            chosen,
            chosen_owner,
            owner_match,
            same_owner_successors,
            candidates: available.len(),
            runner_up,
        });

        available.remove(0);

        if let Some(prev) = current_owner {
            if prev != chosen_owner {
                switch_count = switch_count.saturating_add(1);
            }
        }
        current_owner = Some(chosen_owner);
        schedule.push(chosen);

        for &succ in poset.succs(chosen) {
            indeg[succ] -= 1;
            if indeg[succ] == 0 {
                available.push(succ);
            }
        }
    }

    if schedule.len() < n {
        ledger.push(DecisionEntry::Fallback {
            reason: format!(
                "greedy budget exhausted at step {steps}, placed {}/{}",
                schedule.len(),
                n
            ),
        });
        return fallback_topo(poset);
    }

    GeodesicResult {
        schedule,
        switch_count,
        algorithm: GeodesicAlgorithm::Greedy,
    }
}

#[cfg(feature = "test-internals")]
fn beam_search_with_ledger(
    poset: &TracePoset,
    beam_width: usize,
    step_budget: usize,
    ledger: &mut DecisionLedger,
) -> GeodesicResult {
    let n = poset.len();
    let init_indeg: Vec<usize> = (0..n).map(|i| poset.preds(i).len()).collect();

    let init_state = BeamState {
        schedule: Vec::with_capacity(n),
        scheduled: vec![false; n],
        indeg: init_indeg,
        current_owner: None,
        switch_count: 0,
    };

    let mut beam = vec![init_state];
    let mut steps = 0;

    while steps < step_budget {
        if beam.iter().all(|s| s.schedule.len() == n) {
            break;
        }

        let mut candidates: Vec<BeamState> = Vec::new();
        let depth = beam.first().map_or(0, |s| s.schedule.len());

        for state in &beam {
            if state.schedule.len() == n {
                candidates.push(state.clone());
                continue;
            }

            let available = state.available();
            if available.is_empty() {
                continue;
            }

            for &chosen in &available {
                steps = steps.saturating_add(1);
                if steps >= step_budget {
                    break;
                }

                let mut new_state = state.clone();
                let chosen_owner = poset.owner(chosen);

                if let Some(prev) = new_state.current_owner {
                    if prev != chosen_owner {
                        new_state.switch_count = new_state.switch_count.saturating_add(1);
                    }
                }
                new_state.current_owner = Some(chosen_owner);
                new_state.schedule.push(chosen);
                new_state.scheduled[chosen] = true;

                for &succ in poset.succs(chosen) {
                    new_state.indeg[succ] -= 1;
                }

                candidates.push(new_state);
            }

            if steps >= step_budget {
                break;
            }
        }

        if candidates.is_empty() {
            break;
        }

        let candidates_before = candidates.len();
        candidates.sort_by(|a, b| {
            let key_a = a.key();
            let key_b = b.key();
            if key_a != key_b {
                return key_a.cmp(&key_b);
            }
            a.schedule.cmp(&b.schedule)
        });

        candidates.truncate(beam_width);
        let candidates_after = candidates.len();

        if candidates_before > candidates_after {
            let best_sc = candidates.first().map_or(0, |s| s.switch_count);
            let worst_sc = candidates.last().map_or(0, |s| s.switch_count);
            ledger.push(DecisionEntry::BeamPrune {
                depth,
                candidates_before,
                candidates_after,
                best_switch_count: best_sc,
                worst_switch_count: worst_sc,
            });
        }

        beam = candidates;
    }

    let best = beam
        .into_iter()
        .filter(|s| s.schedule.len() == n)
        .min_by(|a, b| {
            let key_a = (a.switch_count, &a.schedule);
            let key_b = (b.switch_count, &b.schedule);
            key_a.cmp(&key_b)
        });

    if let Some(state) = best {
        GeodesicResult {
            schedule: state.schedule,
            switch_count: state.switch_count,
            algorithm: GeodesicAlgorithm::BeamSearch { width: beam_width },
        }
    } else {
        ledger.push(DecisionEntry::Fallback {
            reason: "beam search budget exhausted without completion".into(),
        });
        fallback_topo(poset)
    }
}

/// Compute a geodesic (low-switch-cost) linear extension of the poset.
///
/// # Arguments
///
/// * `poset` - The dependency DAG with owner assignments
/// * `config` - Algorithm configuration
///
/// # Returns
///
/// A [`GeodesicResult`] containing the schedule and statistics.
///
/// # Guarantees
///
/// - The returned schedule is always a valid linear extension
/// - Deterministic: identical inputs produce identical outputs
/// - Switch count is never worse than naive topological sort
#[must_use]
pub fn normalize(poset: &TracePoset, config: &GeodesicConfig) -> GeodesicResult {
    let n = poset.len();

    if n == 0 {
        return GeodesicResult {
            schedule: vec![],
            switch_count: 0,
            algorithm: GeodesicAlgorithm::Greedy,
        };
    }

    if n == 1 {
        return GeodesicResult {
            schedule: vec![0],
            switch_count: 0,
            algorithm: GeodesicAlgorithm::Greedy,
        };
    }

    if n <= config.exact_threshold {
        if let Some(result) = exact_search(poset, config.step_budget) {
            return result;
        }
    }

    // Choose algorithm based on trace size
    if n <= config.beam_threshold && config.beam_width > 1 {
        beam_search(poset, config.beam_width, config.step_budget)
    } else {
        greedy(poset, config.step_budget)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ExactState {
    mask: u64,
    last_owner: Option<OwnerKey>,
}

#[derive(Debug, Clone, Copy)]
struct ExactParent {
    prev: ExactState,
    chosen: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExactQueueEntry {
    f: usize,
    g: usize,
    mask: u64,
    last_owner: Option<OwnerKey>,
}

impl Ord for ExactQueueEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .f
            .cmp(&self.f)
            .then_with(|| other.g.cmp(&self.g))
            .then_with(|| other.mask.cmp(&self.mask))
            .then_with(|| other.last_owner.cmp(&self.last_owner))
    }
}

impl PartialOrd for ExactQueueEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn exact_search(poset: &TracePoset, step_budget: usize) -> Option<GeodesicResult> {
    let n = poset.len();
    if n == 0 {
        return Some(GeodesicResult {
            schedule: vec![],
            switch_count: 0,
            algorithm: GeodesicAlgorithm::ExactAStar,
        });
    }
    if n > 63 {
        return None;
    }

    let pred_masks = build_pred_masks(poset);
    let full_mask = (1u64 << n).saturating_sub(1);

    let start = ExactState {
        mask: 0,
        last_owner: None,
    };
    let mut open = BinaryHeap::new();
    let mut best_g: DetHashMap<ExactState, usize> = DetHashMap::default();
    let mut parent: DetHashMap<ExactState, ExactParent> = DetHashMap::default();

    let start_h = owner_switch_lower_bound(poset, start.mask, start.last_owner);
    open.push(ExactQueueEntry {
        f: start_h,
        g: 0,
        mask: 0,
        last_owner: None,
    });
    best_g.insert(start, 0);

    let mut steps = 0usize;
    while let Some(entry) = open.pop() {
        if steps >= step_budget {
            return None;
        }
        steps = steps.saturating_add(1);

        let state = ExactState {
            mask: entry.mask,
            last_owner: entry.last_owner,
        };

        if entry.g.ne(best_g.get(&state).unwrap_or(&usize::MAX)) {
            continue;
        }

        if state.mask == full_mask {
            let schedule = reconstruct_exact_schedule(state, &parent, n);
            return Some(GeodesicResult {
                schedule,
                switch_count: entry.g,
                algorithm: GeodesicAlgorithm::ExactAStar,
            });
        }

        for (idx, &pred_mask) in pred_masks.iter().enumerate() {
            let bit = 1u64 << idx;
            if state.mask & bit != 0 {
                continue;
            }
            if pred_mask & !state.mask != 0 {
                continue;
            }

            let owner = poset.owner(idx);
            let mut new_g = entry.g;
            if let Some(prev_owner) = state.last_owner {
                if prev_owner != owner {
                    new_g = new_g.saturating_add(1);
                }
            }
            let new_state = ExactState {
                mask: state.mask | bit,
                last_owner: Some(owner),
            };

            let best = best_g.get(&new_state).copied().unwrap_or(usize::MAX);
            if new_g < best {
                best_g.insert(new_state, new_g);
                parent.insert(
                    new_state,
                    ExactParent {
                        prev: state,
                        chosen: idx,
                    },
                );

                let h = owner_switch_lower_bound(poset, new_state.mask, new_state.last_owner);
                open.push(ExactQueueEntry {
                    f: new_g.saturating_add(h),
                    g: new_g,
                    mask: new_state.mask,
                    last_owner: new_state.last_owner,
                });
            }
        }
    }

    None
}

fn build_pred_masks(poset: &TracePoset) -> Vec<u64> {
    let n = poset.len();
    let mut masks = vec![0u64; n];
    for (i, mask_slot) in masks.iter_mut().enumerate() {
        let mut mask = 0u64;
        for &pred in poset.preds(i) {
            mask |= 1u64 << pred;
        }
        *mask_slot = mask;
    }
    masks
}

fn owner_switch_lower_bound(poset: &TracePoset, mask: u64, last_owner: Option<OwnerKey>) -> usize {
    let mut owners: Vec<OwnerKey> = Vec::new();
    for i in 0..poset.len() {
        if mask & (1u64 << i) == 0 {
            let owner = poset.owner(i);
            if !owners.contains(&owner) {
                owners.push(owner);
            }
        }
    }

    let k = owners.len();
    if k == 0 {
        return 0;
    }

    last_owner.map_or_else(
        || k.saturating_sub(1),
        |owner| {
            if owners.contains(&owner) {
                k.saturating_sub(1)
            } else {
                k
            }
        },
    )
}

fn reconstruct_exact_schedule(
    goal: ExactState,
    parent: &DetHashMap<ExactState, ExactParent>,
    n: usize,
) -> Vec<usize> {
    let mut schedule = Vec::with_capacity(n);
    let mut state = goal;
    while let Some(p) = parent.get(&state) {
        schedule.push(p.chosen);
        state = p.prev;
    }
    schedule.reverse();
    schedule
}

/// Greedy "same owner first" heuristic.
///
/// At each step, pick an available event that:
/// 1. Matches the current owner (if any such event exists)
/// 2. Otherwise, pick the event with the most same-owner successors
/// 3. Tie-break by lowest event index
fn greedy(poset: &TracePoset, step_budget: usize) -> GeodesicResult {
    let n = poset.len();
    let mut indeg: Vec<usize> = (0..n).map(|i| poset.preds(i).len()).collect();
    let mut available: Vec<usize> = (0..n).filter(|&i| indeg[i] == 0).collect();
    let mut schedule = Vec::with_capacity(n);
    let mut current_owner: Option<OwnerKey> = None;
    let mut switch_count: usize = 0;
    let mut steps = 0;

    while !available.is_empty() && steps < step_budget {
        steps = steps.saturating_add(1);

        // Sort available by our preference order
        available.sort_by(|&a, &b| {
            let owner_a = poset.owner(a);
            let owner_b = poset.owner(b);

            // Prefer events matching current owner
            let match_a = current_owner == Some(owner_a);
            let match_b = current_owner == Some(owner_b);

            if match_a != match_b {
                return match_b.cmp(&match_a); // true before false
            }

            // Secondary: count of same-owner successors (higher is better)
            let score_a = count_same_owner_successors(poset, a, &indeg);
            let score_b = count_same_owner_successors(poset, b, &indeg);

            if score_a != score_b {
                return score_b.cmp(&score_a); // higher score first
            }

            // Tertiary: lowest index wins (deterministic tie-break)
            a.cmp(&b)
        });

        let chosen = available.remove(0);
        let chosen_owner = poset.owner(chosen);

        // Count switch
        if let Some(prev) = current_owner {
            if prev != chosen_owner {
                switch_count = switch_count.saturating_add(1);
            }
        }
        current_owner = Some(chosen_owner);
        schedule.push(chosen);

        // Update in-degrees and available set
        for &succ in poset.succs(chosen) {
            indeg[succ] -= 1;
            if indeg[succ] == 0 {
                available.push(succ);
            }
        }
    }

    // If we ran out of budget, fall back to topo sort for remaining
    if schedule.len() < n {
        return fallback_topo(poset);
    }

    GeodesicResult {
        schedule,
        switch_count,
        algorithm: GeodesicAlgorithm::Greedy,
    }
}

/// Count how many available successors have the same owner.
fn count_same_owner_successors(poset: &TracePoset, idx: usize, indeg: &[usize]) -> usize {
    let owner = poset.owner(idx);
    poset
        .succs(idx)
        .iter()
        .filter(|&&s| {
            // Would become available after choosing idx
            let will_be_available = indeg[s] == 1;
            will_be_available && poset.owner(s) == owner
        })
        .count()
}

#[derive(Clone)]
struct BeamState {
    schedule: Vec<usize>,
    scheduled: Vec<bool>,
    indeg: Vec<usize>,
    current_owner: Option<OwnerKey>,
    switch_count: usize,
}

impl BeamState {
    fn available(&self) -> Vec<usize> {
        self.indeg
            .iter()
            .enumerate()
            .filter_map(|(i, &deg)| {
                if deg == 0 && !self.scheduled[i] {
                    Some(i)
                } else {
                    None
                }
            })
            .collect()
    }

    fn key(&self) -> (usize, Reverse<usize>) {
        // Lower switch count is better, longer schedule breaks ties
        (self.switch_count, Reverse(self.schedule.len()))
    }
}

/// Beam search: explore multiple candidate paths in parallel.
///
/// State = (schedule_so_far, in_degrees, current_owner, switch_count).
/// At each step, expand top `beam_width` states and keep best `beam_width`.
#[allow(clippy::too_many_lines)]
fn beam_search(poset: &TracePoset, beam_width: usize, step_budget: usize) -> GeodesicResult {
    let n = poset.len();
    let init_indeg: Vec<usize> = (0..n).map(|i| poset.preds(i).len()).collect();

    let init_state = BeamState {
        schedule: Vec::with_capacity(n),
        scheduled: vec![false; n],
        indeg: init_indeg,
        current_owner: None,
        switch_count: 0,
    };

    let mut beam = vec![init_state];
    let mut steps = 0;

    while steps < step_budget {
        // Check if all states are complete
        if beam.iter().all(|s| s.schedule.len() == n) {
            break;
        }

        let mut candidates: Vec<BeamState> = Vec::new();

        for state in &beam {
            if state.schedule.len() == n {
                candidates.push(state.clone());
                continue;
            }

            let available = state.available();
            if available.is_empty() {
                // Stuck - shouldn't happen for valid posets
                continue;
            }

            // Generate successors for each available event
            for &chosen in &available {
                steps = steps.saturating_add(1);
                if steps >= step_budget {
                    break;
                }

                let mut new_state = state.clone();
                let chosen_owner = poset.owner(chosen);

                // Count switch
                if let Some(prev) = new_state.current_owner {
                    if prev != chosen_owner {
                        new_state.switch_count = new_state.switch_count.saturating_add(1);
                    }
                }
                new_state.current_owner = Some(chosen_owner);
                new_state.schedule.push(chosen);
                new_state.scheduled[chosen] = true;

                // Update in-degrees
                for &succ in poset.succs(chosen) {
                    new_state.indeg[succ] -= 1;
                }

                candidates.push(new_state);
            }

            if steps >= step_budget {
                break;
            }
        }

        if candidates.is_empty() {
            break;
        }

        // Sort by (switch_count, -schedule_len, schedule for determinism)
        candidates.sort_by(|a, b| {
            let key_a = a.key();
            let key_b = b.key();
            if key_a != key_b {
                return key_a.cmp(&key_b);
            }
            // Deterministic tie-break: compare schedules lexicographically
            a.schedule.cmp(&b.schedule)
        });

        // Keep top beam_width states
        candidates.truncate(beam_width);
        beam = candidates;
    }

    // Pick the best completed state
    let best = beam
        .into_iter()
        .filter(|s| s.schedule.len() == n)
        .min_by(|a, b| {
            let key_a = (a.switch_count, &a.schedule);
            let key_b = (b.switch_count, &b.schedule);
            key_a.cmp(&key_b)
        });

    match best {
        Some(state) => GeodesicResult {
            schedule: state.schedule,
            switch_count: state.switch_count,
            algorithm: GeodesicAlgorithm::BeamSearch { width: beam_width },
        },
        None => {
            // Budget exhausted without completing - fall back
            fallback_topo(poset)
        }
    }
}

/// Fallback: deterministic topological sort (no optimization).
fn fallback_topo(poset: &TracePoset) -> GeodesicResult {
    let schedule = poset
        .topo_sort()
        .unwrap_or_else(|| (0..poset.len()).collect());
    let switch_count = count_switches(poset, &schedule);

    GeodesicResult {
        schedule,
        switch_count,
        algorithm: GeodesicAlgorithm::TopoSort,
    }
}

/// Count the number of owner switches in a schedule.
#[must_use]
pub fn count_switches(poset: &TracePoset, schedule: &[usize]) -> usize {
    schedule
        .windows(2)
        .filter(|w| poset.owner(w[0]) != poset.owner(w[1]))
        .count()
}

/// Verify that a schedule is a valid linear extension of the poset.
#[must_use]
pub fn is_valid_linear_extension(poset: &TracePoset, schedule: &[usize]) -> bool {
    let n = poset.len();

    // Check length
    if schedule.len() != n {
        return false;
    }

    // Check that all indices appear exactly once
    let mut seen = vec![false; n];
    for &idx in schedule {
        if idx >= n || seen[idx] {
            return false;
        }
        seen[idx] = true;
    }

    // Check that dependencies are respected
    let mut position = vec![0usize; n];
    for (pos, &idx) in schedule.iter().enumerate() {
        position[idx] = pos;
    }

    for i in 0..n {
        for &pred in poset.preds(i) {
            if position[pred] >= position[i] {
                return false; // Predecessor must come before
            }
        }
    }

    true
}

#[cfg(test)]
#[path = "geodesic_inline_tests.rs"]
mod tests;
