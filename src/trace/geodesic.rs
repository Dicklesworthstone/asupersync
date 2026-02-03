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
    let full_mask = (1u64 << n) - 1;

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
        steps += 1;

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
                    new_g += 1;
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
                    f: new_g + h,
                    g: new_g,
                    mask: new_state.mask,
                    last_owner: new_state.last_owner,
                });
                successors += 1;
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
    let mut switch_count = 0;
    let mut steps = 0;

    while !available.is_empty() && steps < step_budget {
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
            step: steps,
            chosen,
            chosen_owner,
            owner_match,
            same_owner_successors,
            candidates: available.len(),
            runner_up,
        });

        available.remove(0);
        steps += 1;

        if let Some(prev) = current_owner {
            if prev != chosen_owner {
                switch_count += 1;
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
                steps += 1;
                if steps >= step_budget {
                    break;
                }

                let mut new_state = state.clone();
                let chosen_owner = poset.owner(chosen);

                if let Some(prev) = new_state.current_owner {
                    if prev != chosen_owner {
                        new_state.switch_count += 1;
                    }
                }
                new_state.current_owner = Some(chosen_owner);
                new_state.schedule.push(chosen);

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
    let full_mask = (1u64 << n) - 1;

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
        steps += 1;

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
                    new_g += 1;
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
                    f: new_g + h,
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
        |owner| if owners.contains(&owner) { k - 1 } else { k },
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
    let mut switch_count = 0;
    let mut steps = 0;

    while !available.is_empty() && steps < step_budget {
        steps += 1;

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
                switch_count += 1;
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
                if deg == 0 && !self.schedule.contains(&i) {
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
                steps += 1;
                if steps >= step_budget {
                    break;
                }

                let mut new_state = state.clone();
                let chosen_owner = poset.owner(chosen);

                // Count switch
                if let Some(prev) = new_state.current_owner {
                    if prev != chosen_owner {
                        new_state.switch_count += 1;
                    }
                }
                new_state.current_owner = Some(chosen_owner);
                new_state.schedule.push(chosen);

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
mod tests {
    use super::*;
    use crate::trace::event_structure::TracePoset;
    use crate::trace::TraceEvent;
    use crate::types::{RegionId, TaskId, Time};

    fn make_poset(events: &[TraceEvent]) -> TracePoset {
        TracePoset::from_trace(events)
    }

    fn tid(n: u32) -> TaskId {
        TaskId::new_for_test(n, 0)
    }

    fn rid(n: u32) -> RegionId {
        RegionId::new_for_test(n, 0)
    }

    #[test]
    fn empty_trace() {
        let poset = make_poset(&[]);
        let result = normalize(&poset, &GeodesicConfig::default());
        assert!(result.schedule.is_empty());
        assert_eq!(result.switch_count, 0);
    }

    #[test]
    fn single_event() {
        let events = [TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1))];
        let poset = make_poset(&events);
        let result = normalize(&poset, &GeodesicConfig::default());
        assert_eq!(result.schedule, vec![0]);
        assert_eq!(result.switch_count, 0);
    }

    #[test]
    fn independent_same_owner_no_switches() {
        // Two independent events with same owner -> 0 switches
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::poll(2, Time::ZERO, tid(1), rid(1)),
        ];
        let poset = make_poset(&events);

        // Note: these are dependent (same task), so only one valid order
        let result = normalize(&poset, &GeodesicConfig::default());
        assert!(is_valid_linear_extension(&poset, &result.schedule));
        assert_eq!(result.switch_count, 0);
    }

    #[test]
    fn independent_different_owners_one_switch() {
        // Two independent events with different owners -> 1 switch
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        ];
        let poset = make_poset(&events);
        let result = normalize(&poset, &GeodesicConfig::default());

        assert!(is_valid_linear_extension(&poset, &result.schedule));
        // Two events with different owners always have 1 switch
        assert_eq!(result.switch_count, 1);
    }

    #[test]
    fn greedy_prefers_same_owner() {
        // Events: A1, B1, A2, B2 where A* has owner 1, B* has owner 2
        // A1 -> A2 (dependent), B1 -> B2 (dependent), others independent
        // Optimal: A1, A2, B1, B2 (1 switch) or B1, B2, A1, A2 (1 switch)
        // Bad: A1, B1, A2, B2 (3 switches)
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)), // A1
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)), // B1
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)), // A2
            TraceEvent::complete(4, Time::ZERO, tid(2), rid(2)), // B2
        ];
        let poset = make_poset(&events);
        let result = normalize(&poset, &GeodesicConfig::greedy_only());

        assert!(is_valid_linear_extension(&poset, &result.schedule));
        // Greedy should achieve 1 switch (group by owner)
        assert_eq!(
            result.switch_count, 1,
            "Expected 1 switch, got {}",
            result.switch_count
        );
    }

    #[test]
    fn beam_search_finds_optimal() {
        // Same test case as above but with beam search
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(4, Time::ZERO, tid(2), rid(2)),
        ];
        let poset = make_poset(&events);
        let result = normalize(&poset, &GeodesicConfig::high_quality());

        assert!(is_valid_linear_extension(&poset, &result.schedule));
        assert_eq!(result.switch_count, 1);
    }

    #[test]
    fn deterministic_results() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::spawn(3, Time::ZERO, tid(3), rid(3)),
            TraceEvent::complete(4, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(5, Time::ZERO, tid(2), rid(2)),
        ];
        let poset = make_poset(&events);

        let r1 = normalize(&poset, &GeodesicConfig::default());
        let r2 = normalize(&poset, &GeodesicConfig::default());

        assert_eq!(r1.schedule, r2.schedule);
        assert_eq!(r1.switch_count, r2.switch_count);
    }

    #[test]
    fn valid_linear_extension_check() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::poll(2, Time::ZERO, tid(1), rid(1)),
        ];
        let poset = make_poset(&events);

        // Valid: spawn before poll
        assert!(is_valid_linear_extension(&poset, &[0, 1]));

        // Invalid: poll before spawn (violates dependency)
        assert!(!is_valid_linear_extension(&poset, &[1, 0]));

        // Invalid: wrong length
        assert!(!is_valid_linear_extension(&poset, &[0]));

        // Invalid: duplicate
        assert!(!is_valid_linear_extension(&poset, &[0, 0]));
    }

    #[test]
    fn switch_count_calculation() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::spawn(3, Time::ZERO, tid(1), rid(1)),
        ];
        let poset = make_poset(&events);

        // Schedule [0, 2, 1]: owner1, owner1, owner2 -> 1 switch
        // But we need to check if this is valid first
        // Events 0 and 2 are both task 1 events, so they might be dependent

        // Let's just test the counting function
        // [0, 1, 2] if all independent would be: owner1, owner2, owner1 -> 2 switches
        let count = count_switches(&poset, &[0, 1, 2]);
        assert_eq!(count, 2);
    }

    #[test]
    fn fallback_on_budget_exhaustion() {
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
        ];
        let poset = make_poset(&events);

        // Very low budget should trigger fallback
        let config = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 1000,
            beam_width: 100,
            step_budget: 1, // Very low budget
        };
        let result = normalize(&poset, &config);

        // Should still produce a valid result
        assert!(is_valid_linear_extension(&poset, &result.schedule));
    }

    #[test]
    fn large_trace_uses_greedy() {
        // Create a trace larger than beam_threshold
        let n: u32 = 150;
        let events: Vec<TraceEvent> = (0..n)
            .map(|i| TraceEvent::spawn(u64::from(i), Time::ZERO, tid(i), rid(i)))
            .collect();
        let poset = make_poset(&events);

        let config = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 100, // Less than n
            beam_width: 8,
            step_budget: 1_000_000,
        };
        let result = normalize(&poset, &config);

        assert_eq!(result.algorithm, GeodesicAlgorithm::Greedy);
        assert!(is_valid_linear_extension(&poset, &result.schedule));
    }

    fn brute_force_min_switches(poset: &TracePoset) -> usize {
        fn dfs(
            poset: &TracePoset,
            indeg: &mut [usize],
            available: &mut Vec<usize>,
            schedule_len: usize,
            current_owner: Option<OwnerKey>,
            switches: usize,
            best: &mut usize,
        ) {
            if switches >= *best {
                return;
            }
            if schedule_len == poset.len() {
                *best = switches;
                return;
            }

            available.sort_unstable();
            let candidates = available.clone();

            for chosen in candidates {
                let owner = poset.owner(chosen);
                let mut next_switches = switches;
                if let Some(prev) = current_owner {
                    if prev != owner {
                        next_switches += 1;
                    }
                }

                // Apply choice
                let idx = available
                    .iter()
                    .position(|&v| v == chosen)
                    .expect("chosen must be available");
                available.remove(idx);

                let mut newly_available = Vec::new();
                for &succ in poset.succs(chosen) {
                    indeg[succ] -= 1;
                    if indeg[succ] == 0 {
                        newly_available.push(succ);
                    }
                }
                available.extend(newly_available.iter().copied());

                dfs(
                    poset,
                    indeg,
                    available,
                    schedule_len + 1,
                    Some(owner),
                    next_switches,
                    best,
                );

                // Undo choice
                available.retain(|&v| v != chosen);
                available.push(chosen);
                for &succ in poset.succs(chosen) {
                    if indeg[succ] == 0 {
                        if let Some(pos) = available.iter().position(|&v| v == succ) {
                            available.remove(pos);
                        }
                    }
                    indeg[succ] += 1;
                }
            }
        }

        let n = poset.len();
        let mut indeg: Vec<usize> = (0..n).map(|i| poset.preds(i).len()).collect();
        let mut available: Vec<usize> = (0..n).filter(|&i| indeg[i] == 0).collect();
        let mut best = usize::MAX;
        dfs(poset, &mut indeg, &mut available, 0, None, 0, &mut best);
        best
    }

    #[test]
    fn exact_solver_matches_bruteforce_two_chains() {
        let r = rid(1);
        let t1 = tid(1);
        let t2 = tid(2);

        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, t1, r),
            TraceEvent::spawn(2, Time::ZERO, t2, r),
            TraceEvent::schedule(3, Time::ZERO, t1, r),
            TraceEvent::schedule(4, Time::ZERO, t2, r),
            TraceEvent::poll(5, Time::ZERO, t1, r),
            TraceEvent::poll(6, Time::ZERO, t2, r),
            TraceEvent::yield_task(7, Time::ZERO, t1, r),
            TraceEvent::yield_task(8, Time::ZERO, t2, r),
            TraceEvent::complete(9, Time::ZERO, t1, r),
            TraceEvent::complete(10, Time::ZERO, t2, r),
        ];
        let poset = make_poset(&events);

        let config = GeodesicConfig {
            exact_threshold: 10,
            beam_threshold: 0,
            beam_width: 1,
            step_budget: 200_000,
        };
        let result = normalize(&poset, &config);

        assert_eq!(result.algorithm, GeodesicAlgorithm::ExactAStar);
        assert!(is_valid_linear_extension(&poset, &result.schedule));

        let brute = brute_force_min_switches(&poset);
        assert_eq!(result.switch_count, brute);
    }

    // ================================================================
    // bd-28sb acceptance criteria tests
    // ================================================================

    fn foata_flatten_switch_cost(events: &[TraceEvent]) -> usize {
        use crate::trace::canonicalize::canonicalize;
        use crate::trace::event_structure::OwnerKey;
        let foata = canonicalize(events);
        let flat = foata.flatten();
        if flat.len() < 2 {
            return 0;
        }
        flat.windows(2)
            .filter(|w| OwnerKey::for_event(&w[0]) != OwnerKey::for_event(&w[1]))
            .count()
    }

    fn verify_exact_acceptance(events: &[TraceEvent], label: &str) {
        let poset = make_poset(events);
        let n = poset.len();
        if n == 0 {
            return;
        }
        let config = GeodesicConfig {
            exact_threshold: 64,
            beam_threshold: 0,
            beam_width: 1,
            step_budget: 500_000,
        };
        let result = normalize(&poset, &config);
        assert!(
            is_valid_linear_extension(&poset, &result.schedule),
            "{label}: not a valid linear extension"
        );
        let foata_cost = foata_flatten_switch_cost(events);
        assert!(
            result.switch_count <= foata_cost,
            "{label}: exact ({}) > foata ({foata_cost})",
            result.switch_count,
        );
        if n <= 10 {
            let brute = brute_force_min_switches(&poset);
            assert_eq!(
                result.switch_count, brute,
                "{label}: exact ({}) != brute ({brute})",
                result.switch_count,
            );
        }
    }

    #[test]
    fn exact_cost_leq_foata_two_parallel_chains() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::complete(3, Time::ZERO, tid(1), r),
            TraceEvent::complete(4, Time::ZERO, tid(2), r),
        ];
        verify_exact_acceptance(&events, "two_parallel_chains");
    }

    #[test]
    fn exact_cost_leq_foata_three_tasks() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::spawn(3, Time::ZERO, tid(3), r),
            TraceEvent::poll(4, Time::ZERO, tid(1), r),
            TraceEvent::poll(5, Time::ZERO, tid(2), r),
            TraceEvent::poll(6, Time::ZERO, tid(3), r),
            TraceEvent::complete(7, Time::ZERO, tid(1), r),
            TraceEvent::complete(8, Time::ZERO, tid(2), r),
            TraceEvent::complete(9, Time::ZERO, tid(3), r),
        ];
        verify_exact_acceptance(&events, "three_tasks");
    }

    #[test]
    fn exact_cost_leq_foata_diamond() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::spawn(3, Time::ZERO, tid(3), r),
            TraceEvent::complete(4, Time::ZERO, tid(2), r),
            TraceEvent::complete(5, Time::ZERO, tid(3), r),
            TraceEvent::complete(6, Time::ZERO, tid(1), r),
        ];
        verify_exact_acceptance(&events, "diamond");
    }

    #[test]
    fn exact_cost_leq_foata_single_chain() {
        let r = rid(1);
        let t = tid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, t, r),
            TraceEvent::schedule(2, Time::ZERO, t, r),
            TraceEvent::poll(3, Time::ZERO, t, r),
            TraceEvent::yield_task(4, Time::ZERO, t, r),
            TraceEvent::complete(5, Time::ZERO, t, r),
        ];
        verify_exact_acceptance(&events, "single_chain");
    }

    #[test]
    fn exact_cost_leq_foata_star() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::spawn(3, Time::ZERO, tid(3), r),
            TraceEvent::spawn(4, Time::ZERO, tid(4), r),
            TraceEvent::spawn(5, Time::ZERO, tid(5), r),
        ];
        verify_exact_acceptance(&events, "star");
    }

    #[test]
    fn exact_cost_leq_foata_asymmetric() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::poll(3, Time::ZERO, tid(1), r),
            TraceEvent::complete(4, Time::ZERO, tid(2), r),
            TraceEvent::yield_task(5, Time::ZERO, tid(1), r),
            TraceEvent::complete(6, Time::ZERO, tid(1), r),
        ];
        verify_exact_acceptance(&events, "asymmetric");
    }

    #[test]
    fn exact_cost_leq_foata_four_tasks() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::spawn(3, Time::ZERO, tid(3), r),
            TraceEvent::spawn(4, Time::ZERO, tid(4), r),
            TraceEvent::complete(5, Time::ZERO, tid(1), r),
            TraceEvent::complete(6, Time::ZERO, tid(2), r),
            TraceEvent::complete(7, Time::ZERO, tid(3), r),
            TraceEvent::complete(8, Time::ZERO, tid(4), r),
        ];
        verify_exact_acceptance(&events, "four_tasks");
    }

    #[test]
    fn exact_cost_leq_foata_mixed_regions() {
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
            TraceEvent::spawn(3, Time::ZERO, tid(3), rid(1)),
            TraceEvent::complete(4, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(5, Time::ZERO, tid(2), rid(2)),
            TraceEvent::complete(6, Time::ZERO, tid(3), rid(1)),
        ];
        verify_exact_acceptance(&events, "mixed_regions");
    }

    #[test]
    fn exhaustive_bruteforce_n2_to_n8() {
        let r = rid(1);
        let shapes: Vec<(&str, Vec<TraceEvent>)> = vec![
            (
                "n2_ind",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), r),
                    TraceEvent::spawn(2, Time::ZERO, tid(2), r),
                ],
            ),
            (
                "n2_same",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), r),
                    TraceEvent::poll(2, Time::ZERO, tid(1), r),
                ],
            ),
            (
                "n3_ind",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), r),
                    TraceEvent::spawn(2, Time::ZERO, tid(2), r),
                    TraceEvent::spawn(3, Time::ZERO, tid(3), r),
                ],
            ),
            (
                "n4_chain",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), r),
                    TraceEvent::schedule(2, Time::ZERO, tid(1), r),
                    TraceEvent::poll(3, Time::ZERO, tid(1), r),
                    TraceEvent::complete(4, Time::ZERO, tid(1), r),
                ],
            ),
            (
                "n6_2chains",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), r),
                    TraceEvent::spawn(2, Time::ZERO, tid(2), r),
                    TraceEvent::schedule(3, Time::ZERO, tid(1), r),
                    TraceEvent::schedule(4, Time::ZERO, tid(2), r),
                    TraceEvent::complete(5, Time::ZERO, tid(1), r),
                    TraceEvent::complete(6, Time::ZERO, tid(2), r),
                ],
            ),
            (
                "n8_4chains",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), r),
                    TraceEvent::spawn(2, Time::ZERO, tid(2), r),
                    TraceEvent::spawn(3, Time::ZERO, tid(3), r),
                    TraceEvent::spawn(4, Time::ZERO, tid(4), r),
                    TraceEvent::complete(5, Time::ZERO, tid(1), r),
                    TraceEvent::complete(6, Time::ZERO, tid(2), r),
                    TraceEvent::complete(7, Time::ZERO, tid(3), r),
                    TraceEvent::complete(8, Time::ZERO, tid(4), r),
                ],
            ),
            (
                "n7_asym",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), r),
                    TraceEvent::spawn(2, Time::ZERO, tid(2), r),
                    TraceEvent::schedule(3, Time::ZERO, tid(1), r),
                    TraceEvent::poll(4, Time::ZERO, tid(1), r),
                    TraceEvent::yield_task(5, Time::ZERO, tid(1), r),
                    TraceEvent::complete(6, Time::ZERO, tid(1), r),
                    TraceEvent::complete(7, Time::ZERO, tid(2), r),
                ],
            ),
            (
                "n5_ind_multiregion",
                vec![
                    TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
                    TraceEvent::spawn(2, Time::ZERO, tid(2), rid(2)),
                    TraceEvent::spawn(3, Time::ZERO, tid(3), rid(3)),
                    TraceEvent::spawn(4, Time::ZERO, tid(4), rid(4)),
                    TraceEvent::spawn(5, Time::ZERO, tid(5), rid(5)),
                ],
            ),
        ];
        for (label, events) in &shapes {
            verify_exact_acceptance(events, label);
        }
    }

    #[test]
    fn exact_deterministic_across_runs() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::spawn(3, Time::ZERO, tid(3), r),
            TraceEvent::poll(4, Time::ZERO, tid(1), r),
            TraceEvent::poll(5, Time::ZERO, tid(2), r),
            TraceEvent::complete(6, Time::ZERO, tid(1), r),
            TraceEvent::complete(7, Time::ZERO, tid(2), r),
            TraceEvent::complete(8, Time::ZERO, tid(3), r),
        ];
        let poset = make_poset(&events);
        let config = GeodesicConfig {
            exact_threshold: 64,
            beam_threshold: 0,
            beam_width: 1,
            step_budget: 500_000,
        };
        let first = normalize(&poset, &config);
        for i in 1..10 {
            let run = normalize(&poset, &config);
            assert_eq!(first.schedule, run.schedule, "Run {i} differs");
            assert_eq!(first.switch_count, run.switch_count, "Run {i} cost differs");
        }
    }

    #[test]
    fn heuristic_admissibility() {
        let r = rid(1);
        let events = vec![
            TraceEvent::spawn(1, Time::ZERO, tid(1), r),
            TraceEvent::spawn(2, Time::ZERO, tid(2), r),
            TraceEvent::spawn(3, Time::ZERO, tid(3), r),
            TraceEvent::complete(4, Time::ZERO, tid(1), r),
            TraceEvent::complete(5, Time::ZERO, tid(2), r),
            TraceEvent::complete(6, Time::ZERO, tid(3), r),
        ];
        let poset = make_poset(&events);
        let brute_optimal = brute_force_min_switches(&poset);
        let h_start = owner_switch_lower_bound(&poset, 0, None);
        assert!(
            h_start <= brute_optimal,
            "h({h_start}) > optimal({brute_optimal}): inadmissible"
        );
    }

    // ========================================================================
    // bd-3dre: Property tests (soundness, equivalence, determinism)
    // ========================================================================

    use proptest::prelude::*;

    /// Strategy: generate a small trace with n events across k owners.
    /// Events with the same owner form dependency chains (same task id →
    /// sequential via `from_trace`). Events with different owners are
    /// independent.
    fn arb_trace(max_n: usize, max_owners: u32) -> impl Strategy<Value = Vec<TraceEvent>> {
        (1..=max_n).prop_flat_map(move |n| {
            proptest::collection::vec(1..=max_owners, n).prop_map(move |owners| {
                owners
                    .into_iter()
                    .enumerate()
                    .map(|(i, owner)| {
                        TraceEvent::spawn(
                            (i + 1) as u64,
                            Time::from_nanos(i as u64 * 1000),
                            tid(owner),
                            rid(owner),
                        )
                    })
                    .collect::<Vec<_>>()
            })
        })
    }

    // ========================================================================
    // Decision ledger tests
    // ========================================================================

    #[test]
    fn ledger_exact_has_algorithm_selected() {
        let events = [
            TraceEvent::spawn(1, Time::from_nanos(0), tid(1), rid(1)),
            TraceEvent::spawn(2, Time::from_nanos(1000), tid(2), rid(2)),
            TraceEvent::spawn(3, Time::from_nanos(2000), tid(1), rid(1)),
        ];
        let poset = make_poset(&events);
        let config = GeodesicConfig {
            exact_threshold: 10,
            beam_threshold: 0,
            beam_width: 0,
            step_budget: 100_000,
        };
        let ledger = normalize_with_ledger(&poset, &config);

        // Must have at least one AlgorithmSelected entry
        let has_algo = ledger.entries.iter().any(|e| {
            matches!(
                e,
                DecisionEntry::AlgorithmSelected {
                    algorithm: GeodesicAlgorithm::ExactAStar,
                    ..
                }
            )
        });
        assert!(has_algo, "ledger missing AlgorithmSelected for exact");
        assert_eq!(ledger.result.schedule.len(), 3);
        assert!(is_valid_linear_extension(&poset, &ledger.result.schedule));
    }

    #[test]
    fn ledger_greedy_records_choices() {
        let events: Vec<TraceEvent> = (0..10)
            .map(|i| {
                TraceEvent::spawn(
                    (i + 1) as u64,
                    Time::from_nanos(i as u64 * 1000),
                    tid((i % 3) as u32),
                    rid((i % 3) as u32),
                )
            })
            .collect();
        let poset = make_poset(&events);
        let config = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 0,
            beam_width: 0,
            step_budget: 100_000,
        };
        let ledger = normalize_with_ledger(&poset, &config);

        // Must have greedy choice entries
        let greedy_choices: Vec<_> = ledger
            .entries
            .iter()
            .filter(|e| matches!(e, DecisionEntry::GreedyChoice { .. }))
            .collect();
        assert_eq!(greedy_choices.len(), 10, "one greedy choice per event");

        // Result must match normalize()
        let plain = normalize(&poset, &config);
        assert_eq!(ledger.result.schedule, plain.schedule);
        assert_eq!(ledger.result.switch_count, plain.switch_count);
    }

    #[test]
    fn ledger_beam_records_prunes() {
        let events: Vec<TraceEvent> = (0..15)
            .map(|i| {
                TraceEvent::spawn(
                    (i + 1) as u64,
                    Time::from_nanos(i as u64 * 1000),
                    tid((i % 4) as u32),
                    rid((i % 4) as u32),
                )
            })
            .collect();
        let poset = make_poset(&events);
        let config = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 100,
            beam_width: 4,
            step_budget: 100_000,
        };
        let ledger = normalize_with_ledger(&poset, &config);

        // Must have beam prune entries
        let prune_count = ledger
            .entries
            .iter()
            .filter(|e| matches!(e, DecisionEntry::BeamPrune { .. }))
            .count();
        assert!(prune_count > 0, "beam search should produce prune entries");
        assert!(is_valid_linear_extension(&poset, &ledger.result.schedule));
    }

    #[test]
    fn ledger_deterministic() {
        let events: Vec<TraceEvent> = (0..12)
            .map(|i| {
                TraceEvent::spawn(
                    (i + 1) as u64,
                    Time::from_nanos(i as u64 * 1000),
                    tid((i % 3) as u32),
                    rid((i % 3) as u32),
                )
            })
            .collect();
        let poset = make_poset(&events);
        let config = GeodesicConfig::default();

        let ledger1 = normalize_with_ledger(&poset, &config);
        let ledger2 = normalize_with_ledger(&poset, &config);

        assert_eq!(ledger1.result.schedule, ledger2.result.schedule);
        assert_eq!(ledger1.result.switch_count, ledger2.result.switch_count);
        assert_eq!(ledger1.entries.len(), ledger2.entries.len());
        assert_eq!(ledger1.summary(), ledger2.summary());
    }

    #[test]
    fn ledger_summary_is_readable() {
        let events = [
            TraceEvent::spawn(1, Time::from_nanos(0), tid(1), rid(1)),
            TraceEvent::spawn(2, Time::from_nanos(1000), tid(2), rid(2)),
            TraceEvent::spawn(3, Time::from_nanos(2000), tid(1), rid(1)),
            TraceEvent::spawn(4, Time::from_nanos(3000), tid(2), rid(2)),
        ];
        let poset = make_poset(&events);
        let config = GeodesicConfig {
            exact_threshold: 10,
            beam_threshold: 0,
            beam_width: 0,
            step_budget: 100_000,
        };
        let ledger = normalize_with_ledger(&poset, &config);
        let summary = ledger.summary();

        // Summary must contain key information
        assert!(
            summary.contains("algorithm="),
            "summary missing algorithm info"
        );
        assert!(
            summary.contains("switches="),
            "summary missing switch count"
        );
        assert!(!summary.is_empty());
    }

    proptest! {
        /// Soundness: exact solver always produces a valid linear extension.
        #[test]
        fn prop_soundness_exact(events in arb_trace(15, 4)) {
            let poset = make_poset(&events);
            let config = GeodesicConfig {
                exact_threshold: 15,
                beam_threshold: 0,
                beam_width: 1,
                step_budget: 200_000,
            };
            let result = normalize(&poset, &config);
            prop_assert!(
                is_valid_linear_extension(&poset, &result.schedule),
                "Exact solver produced invalid linear extension for {} events",
                events.len()
            );
            prop_assert_eq!(
                count_switches(&poset, &result.schedule),
                result.switch_count,
            );
        }

        /// Soundness: greedy solver always produces a valid linear extension.
        #[test]
        fn prop_soundness_greedy(events in arb_trace(30, 5)) {
            let poset = make_poset(&events);
            let result = normalize(&poset, &GeodesicConfig::greedy_only());
            prop_assert!(
                is_valid_linear_extension(&poset, &result.schedule),
                "Greedy produced invalid linear extension for {} events",
                events.len()
            );
            prop_assert_eq!(
                count_switches(&poset, &result.schedule),
                result.switch_count,
            );
        }

        /// Soundness: beam search always produces a valid linear extension.
        #[test]
        fn prop_soundness_beam(events in arb_trace(20, 4)) {
            let poset = make_poset(&events);
            let config = GeodesicConfig {
                exact_threshold: 0,
                beam_threshold: 100,
                beam_width: 8,
                step_budget: 100_000,
            };
            let result = normalize(&poset, &config);
            prop_assert!(
                is_valid_linear_extension(&poset, &result.schedule),
                "Beam search produced invalid linear extension for {} events",
                events.len()
            );
        }

        /// Determinism: same input always produces identical output across
        /// all algorithm tiers.
        #[test]
        fn prop_determinism(events in arb_trace(20, 4)) {
            let poset = make_poset(&events);
            for config in &[
                GeodesicConfig::default(),
                GeodesicConfig::greedy_only(),
                GeodesicConfig::high_quality(),
            ] {
                let r1 = normalize(&poset, config);
                let r2 = normalize(&poset, config);
                prop_assert_eq!(&r1.schedule, &r2.schedule);
                prop_assert_eq!(r1.switch_count, r2.switch_count);
            }
        }

        /// Equivalence: all algorithms produce schedules that are valid
        /// linear extensions of the same poset, and the exact solver
        /// (optimal) never has higher cost than heuristics.
        #[test]
        fn prop_equivalence_across_algorithms(events in arb_trace(15, 3)) {
            let poset = make_poset(&events);

            let exact_cfg = GeodesicConfig {
                exact_threshold: 15, beam_threshold: 0,
                beam_width: 1, step_budget: 200_000,
            };
            let greedy_cfg = GeodesicConfig::greedy_only();
            let beam_cfg = GeodesicConfig {
                exact_threshold: 0, beam_threshold: 100,
                beam_width: 8, step_budget: 100_000,
            };

            let r_exact = normalize(&poset, &exact_cfg);
            let r_greedy = normalize(&poset, &greedy_cfg);
            let r_beam = normalize(&poset, &beam_cfg);

            // All must be valid linear extensions
            prop_assert!(is_valid_linear_extension(&poset, &r_exact.schedule));
            prop_assert!(is_valid_linear_extension(&poset, &r_greedy.schedule));
            prop_assert!(is_valid_linear_extension(&poset, &r_beam.schedule));

            // All must include every event exactly once
            prop_assert_eq!(r_exact.schedule.len(), events.len());
            prop_assert_eq!(r_greedy.schedule.len(), events.len());
            prop_assert_eq!(r_beam.schedule.len(), events.len());

            // Exact solver is optimal: cost <= all heuristics
            prop_assert!(
                r_exact.switch_count <= r_greedy.switch_count,
                "exact {} > greedy {}", r_exact.switch_count, r_greedy.switch_count,
            );
            prop_assert!(
                r_exact.switch_count <= r_beam.switch_count,
                "exact {} > beam {}", r_exact.switch_count, r_beam.switch_count,
            );
        }

        /// Optimality: for tiny traces, exact solver matches brute force.
        #[test]
        fn prop_optimality_small(events in arb_trace(8, 3)) {
            let poset = make_poset(&events);
            let config = GeodesicConfig {
                exact_threshold: 10,
                beam_threshold: 0,
                beam_width: 1,
                step_budget: 500_000,
            };
            let result = normalize(&poset, &config);
            let brute = brute_force_min_switches(&poset);
            prop_assert_eq!(
                result.switch_count, brute,
                "exact {} != brute {} for {} events",
                result.switch_count, brute, events.len(),
            );
        }

        /// Regression: geodesic cost is never worse than Foata-flatten cost.
        #[test]
        fn prop_geodesic_leq_foata(events in arb_trace(15, 4)) {
            let poset = make_poset(&events);
            let config = GeodesicConfig {
                exact_threshold: 15,
                beam_threshold: 0,
                beam_width: 1,
                step_budget: 200_000,
            };
            let result = normalize(&poset, &config);
            let foata_cost = foata_flatten_switch_cost(&events);
            prop_assert!(
                result.switch_count <= foata_cost,
                "geodesic {} > foata {} for {} events",
                result.switch_count, foata_cost, events.len(),
            );
        }
    }

    // =========================================================================
    // Additional decision ledger tests
    // =========================================================================

    #[test]
    fn ledger_empty_trace() {
        let poset = make_poset(&[]);
        let ledger = normalize_with_ledger(&poset, &GeodesicConfig::default());
        assert!(ledger.entries.is_empty());
        assert_eq!(ledger.result.switch_count, 0);
        assert!(ledger.result.schedule.is_empty());
    }

    #[test]
    fn ledger_single_event() {
        let events = [TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1))];
        let poset = make_poset(&events);
        let ledger = normalize_with_ledger(&poset, &GeodesicConfig::default());
        assert!(ledger.entries.is_empty());
        assert_eq!(ledger.result.schedule, vec![0]);
    }

    #[test]
    fn ledger_greedy_shows_owner_match() {
        // Chain of same-owner events followed by different owner
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::poll(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(3, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(4, Time::ZERO, tid(2), rid(2)),
        ];
        let poset = make_poset(&events);
        let ledger = normalize_with_ledger(&poset, &GeodesicConfig::greedy_only());

        let greedy_choices: Vec<_> = ledger
            .entries
            .iter()
            .filter_map(|e| {
                if let DecisionEntry::GreedyChoice { owner_match, .. } = e {
                    Some(*owner_match)
                } else {
                    None
                }
            })
            .collect();

        // First step has no previous owner
        assert!(!greedy_choices[0], "first step has no previous owner");
        // Middle steps are same-owner continuations
        for &m in &greedy_choices[1..greedy_choices.len() - 1] {
            assert!(m, "continuation of same owner should match");
        }
    }

    #[test]
    fn ledger_result_matches_normalize() {
        // Ledger result must match plain normalize for all config presets
        let events = [
            TraceEvent::spawn(1, Time::ZERO, tid(1), rid(1)),
            TraceEvent::complete(2, Time::ZERO, tid(1), rid(1)),
            TraceEvent::spawn(3, Time::ZERO, tid(2), rid(2)),
            TraceEvent::complete(4, Time::ZERO, tid(2), rid(2)),
        ];
        let poset = make_poset(&events);

        for config in &[
            GeodesicConfig::default(),
            GeodesicConfig::greedy_only(),
            GeodesicConfig::high_quality(),
        ] {
            let plain = normalize(&poset, config);
            let ledger = normalize_with_ledger(&poset, config);
            assert_eq!(plain.schedule, ledger.result.schedule);
            assert_eq!(plain.switch_count, ledger.result.switch_count);
        }
    }
}
