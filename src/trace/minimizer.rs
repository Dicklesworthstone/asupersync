//! Scenario-level hierarchical delta debugging (bd-77g6j.2).
//!
//! Minimizes a failing scenario described as [`ScenarioElement`]s by
//! exploiting the structured concurrency tree.  This complements the
//! event-level [`super::delta_debug`] module: `delta_debug` minimizes
//! replay event sequences, while this module minimizes the higher-level
//! scenario construction that *produces* those events.
//!
//! # When to use which
//!
//! | Failure type | Module |
//! |---|---|
//! | Scheduling-order dependent (race, divergence) | `delta_debug` |
//! | Scenario-construction dependent (obligation leak, region structure) | `minimizer` |

use crate::record::ObligationKind;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// br-asupersync-qu7yet — Pluggable wall-clock for the minimizer.
///
/// `TraceMinimizer::minimize` previously called `std::time::Instant::now()`
/// at four sites to time minimization phases. Wall-clock durations baked
/// into the resulting `MinimizationReport` make the report non-stable
/// across deterministic replays — the same scenario minimized twice
/// produces different `wall_time_ms` / `replay_time_ms` values, which
/// breaks property tests that assert byte-identical reports.
///
/// Production callers use [`WallMinimizerClock`] (the default — reads
/// `Instant::now()`); deterministic tests pass a [`LogicalMinimizerClock`]
/// that monotonically advances by 1 ms per query.
pub trait MinimizerClock: Send + Sync {
    /// Returns "now" in milliseconds since the clock was created.
    fn now_ms(&self) -> u64;
}

/// Wall-clock implementation of [`MinimizerClock`].
pub struct WallMinimizerClock {
    started_at: Instant,
}

impl WallMinimizerClock {
    /// Creates a new wall-clock anchored at the current `Instant::now()`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
        }
    }
}

impl Default for WallMinimizerClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MinimizerClock for WallMinimizerClock {
    fn now_ms(&self) -> u64 {
        self.started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64
    }
}

/// Logical (counter-driven) implementation of [`MinimizerClock`] for
/// deterministic tests. Each `now_ms()` call returns the next monotonic
/// integer, so phase timings are stable across runs.
pub struct LogicalMinimizerClock {
    counter: AtomicU64,
}

impl LogicalMinimizerClock {
    /// Creates a new logical clock at counter = 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }
}

impl Default for LogicalMinimizerClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MinimizerClock for LogicalMinimizerClock {
    fn now_ms(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
}

// ============================================================================
// Scenario elements
// ============================================================================

/// A high-level scenario action that can be included or excluded during
/// hierarchical delta debugging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScenarioElement {
    /// Create a child region.
    CreateRegion {
        /// Logical region index (0 = root).
        region_idx: usize,
        /// Parent region index.
        parent_idx: usize,
    },
    /// Spawn a task in a region.
    SpawnTask {
        /// Logical task index (spawn order).
        task_idx: usize,
        /// Owning region index.
        region_idx: usize,
        /// Scheduling lane.
        lane: u8,
    },
    /// Create an obligation on a task.
    CreateObligation {
        /// Owning task index.
        task_idx: usize,
        /// Region index.
        region_idx: usize,
        /// Obligation kind.
        kind: ObligationKind,
        /// Commit (true) or abort (false) when resolved.
        commit: bool,
        /// Not resolved before cancel — enters the race window.
        is_late: bool,
    },
    /// Advance virtual time.
    AdvanceTime {
        /// Nanoseconds to advance.
        nanos: u64,
    },
    /// Cancel a region.
    CancelRegion {
        /// Region index to cancel.
        region_idx: usize,
    },
}

impl ScenarioElement {
    /// Region this element belongs to, if any.
    #[must_use]
    pub fn region_idx(&self) -> Option<usize> {
        match self {
            Self::CreateRegion { region_idx, .. }
            | Self::SpawnTask { region_idx, .. }
            | Self::CreateObligation { region_idx, .. }
            | Self::CancelRegion { region_idx } => Some(*region_idx),
            Self::AdvanceTime { .. } => None,
        }
    }
}

impl fmt::Display for ScenarioElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateRegion {
                region_idx,
                parent_idx,
            } => write!(f, "create_region({region_idx}, parent={parent_idx})"),
            Self::SpawnTask {
                task_idx,
                region_idx,
                lane,
            } => write!(
                f,
                "spawn_task({task_idx}, region={region_idx}, lane={lane})"
            ),
            Self::CreateObligation {
                task_idx,
                kind,
                is_late,
                commit,
                ..
            } => {
                let action = if *commit { "commit" } else { "abort" };
                let late = if *is_late { " LATE" } else { "" };
                write!(f, "obligation(task={task_idx}, {kind:?}, {action}{late})")
            }
            Self::AdvanceTime { nanos } => write!(f, "advance_time({nanos}ns)"),
            Self::CancelRegion { region_idx } => write!(f, "cancel_region({region_idx})"),
        }
    }
}

// ============================================================================
// Concurrency tree
// ============================================================================

struct ConcurrencyTree {
    children: BTreeMap<usize, Vec<usize>>,
    elements_by_region: BTreeMap<usize, Vec<usize>>,
    non_root_regions: Vec<usize>,
}

impl ConcurrencyTree {
    fn build(elements: &[ScenarioElement]) -> Self {
        let mut children: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        let mut elements_by_region: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        let mut non_root_regions = Vec::new();

        for (i, elem) in elements.iter().enumerate() {
            match elem {
                ScenarioElement::CreateRegion {
                    region_idx,
                    parent_idx,
                } => {
                    // Skip self-referencing root regions.
                    if *region_idx != *parent_idx {
                        children.entry(*parent_idx).or_default().push(*region_idx);
                        non_root_regions.push(*region_idx);
                    }
                    elements_by_region.entry(*region_idx).or_default().push(i);
                }
                ScenarioElement::SpawnTask { region_idx, .. }
                | ScenarioElement::CreateObligation { region_idx, .. }
                | ScenarioElement::CancelRegion { region_idx } => {
                    elements_by_region.entry(*region_idx).or_default().push(i);
                }
                ScenarioElement::AdvanceTime { .. } => {}
            }
        }

        Self {
            children,
            elements_by_region,
            non_root_regions,
        }
    }

    fn subtree_elements(&self, region_idx: usize) -> Vec<usize> {
        let mut result = Vec::new();
        self.collect_subtree(region_idx, &mut result);
        result
    }

    fn collect_subtree(&self, region_idx: usize, out: &mut Vec<usize>) {
        if let Some(elems) = self.elements_by_region.get(&region_idx) {
            out.extend(elems);
        }
        if let Some(kids) = self.children.get(&region_idx) {
            for &kid in kids {
                self.collect_subtree(kid, out);
            }
        }
    }
}

// ============================================================================
// Step logging
// ============================================================================

/// Phase of minimization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    /// Top-down region subtree pruning.
    TopDownPrune,
    /// Bottom-up chunk removal (ddmin).
    BottomUpRemove,
    /// 1-minimality verification.
    MinimalityCheck,
}

impl fmt::Display for StepKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TopDownPrune => f.write_str("top_down_prune"),
            Self::BottomUpRemove => f.write_str("bottom_up_remove"),
            Self::MinimalityCheck => f.write_str("minimality_check"),
        }
    }
}

/// A single minimization step.
#[derive(Debug, Clone)]
pub struct MinimizationStep {
    /// Phase.
    pub kind: StepKind,
    /// Elements remaining after this step.
    pub events_remaining: usize,
    /// Elements removed (0 if rejected).
    pub events_removed: usize,
    /// Whether the failure reproduced.
    pub replay_result: bool,
    /// Wall time for this check (ms).
    pub replay_time_ms: u64,
}

// ============================================================================
// Report
// ============================================================================

/// Result of scenario-level hierarchical delta debugging.
#[derive(Debug)]
pub struct MinimizationReport {
    /// Original scenario elements.
    pub original_elements: Vec<ScenarioElement>,
    /// Indices into `original_elements` forming the minimal set.
    pub minimized_indices: Vec<usize>,
    /// Count before.
    pub original_count: usize,
    /// Count after.
    pub minimized_count: usize,
    /// Fraction removed (0.0–1.0).
    pub reduction_ratio: f64,
    /// Total checker invocations.
    pub replay_attempts: usize,
    /// Total wall time (ms).
    pub wall_time_ms: u64,
    /// True if 1-minimal.
    pub is_minimal: bool,
    /// Per-step log.
    pub steps: Vec<MinimizationStep>,
}

impl MinimizationReport {
    /// Minimized elements in original order.
    #[must_use]
    pub fn minimized_elements(&self) -> Vec<ScenarioElement> {
        self.minimized_indices
            .iter()
            .map(|&i| self.original_elements[i].clone())
            .collect()
    }
}

// ============================================================================
// Minimizer
// ============================================================================

/// Hierarchical delta debugging minimizer for structured concurrency scenarios.
pub struct TraceMinimizer;

impl TraceMinimizer {
    /// Find the minimal subset of `elements` that still reproduces the failure.
    ///
    /// Uses a [`WallMinimizerClock`] for phase timings. Deterministic callers
    /// must use [`Self::minimize_with_clock`] instead.
    ///
    /// # Panics
    ///
    /// Panics if the full element set does not reproduce the failure.
    #[allow(clippy::cast_precision_loss)]
    pub fn minimize(
        elements: &[ScenarioElement],
        checker: impl Fn(&[ScenarioElement]) -> bool,
    ) -> MinimizationReport {
        Self::minimize_with_clock(elements, checker, &WallMinimizerClock::new())
    }

    /// br-asupersync-qu7yet — Same as [`Self::minimize`] but uses an
    /// explicit clock for phase timings. Deterministic-replay tests
    /// pass a [`LogicalMinimizerClock`] so the resulting report is
    /// byte-stable across runs.
    ///
    /// # Panics
    ///
    /// Panics if the full element set does not reproduce the failure.
    #[allow(clippy::cast_precision_loss)]
    pub fn minimize_with_clock(
        elements: &[ScenarioElement],
        checker: impl Fn(&[ScenarioElement]) -> bool,
        clock: &dyn MinimizerClock,
    ) -> MinimizationReport {
        let start_ms = clock.now_ms();
        let mut steps = Vec::new();
        let mut replays: usize = 0;
        let n = elements.len();

        assert!(
            checker(elements),
            "full scenario must reproduce the failure"
        );
        replays += 1;

        let tree = ConcurrencyTree::build(elements);

        // Phase 1: top-down region pruning.
        let mut active = vec![true; n];
        top_down_prune(
            elements,
            &tree,
            &checker,
            clock,
            &mut active,
            &mut replays,
            &mut steps,
        );

        // Phase 2: bottom-up ddmin.
        let mut remaining: Vec<usize> = active
            .iter()
            .enumerate()
            .filter(|(_, a)| **a)
            .map(|(i, _)| i)
            .collect();
        remaining = ddmin(
            &remaining,
            elements,
            &checker,
            clock,
            &mut replays,
            &mut steps,
        );

        // Phase 3: 1-minimality check.
        let is_minimal = verify_minimality(
            &remaining,
            elements,
            &checker,
            clock,
            &mut replays,
            &mut steps,
        );

        let minimized_count = remaining.len();
        MinimizationReport {
            original_elements: elements.to_vec(),
            minimized_indices: remaining,
            original_count: n,
            minimized_count,
            reduction_ratio: if n > 0 {
                1.0 - (minimized_count as f64 / n as f64)
            } else {
                0.0
            },
            replay_attempts: replays,
            wall_time_ms: clock.now_ms().saturating_sub(start_ms),
            is_minimal,
            steps,
        }
    }
}

// ============================================================================
// Phase 1
// ============================================================================

fn top_down_prune(
    elements: &[ScenarioElement],
    tree: &ConcurrencyTree,
    checker: &impl Fn(&[ScenarioElement]) -> bool,
    clock: &dyn MinimizerClock,
    active: &mut [bool],
    replays: &mut usize,
    steps: &mut Vec<MinimizationStep>,
) {
    for &region_idx in &tree.non_root_regions {
        let subtree = tree.subtree_elements(region_idx);
        if subtree.iter().all(|&i| !active[i]) {
            continue;
        }
        let saved: Vec<(usize, bool)> = subtree.iter().map(|&i| (i, active[i])).collect();
        for &idx in &subtree {
            active[idx] = false;
        }
        let subset = collect_active(elements, active);
        let t_start = clock.now_ms();
        *replays += 1;
        let ok = checker(&subset);
        let ms = clock.now_ms().saturating_sub(t_start);
        if ok {
            steps.push(MinimizationStep {
                kind: StepKind::TopDownPrune,
                events_remaining: active.iter().filter(|&&a| a).count(),
                events_removed: subtree.len(),
                replay_result: true,
                replay_time_ms: ms,
            });
        } else {
            for (idx, was) in saved {
                active[idx] = was;
            }
            steps.push(MinimizationStep {
                kind: StepKind::TopDownPrune,
                events_remaining: active.iter().filter(|&&a| a).count(),
                events_removed: 0,
                replay_result: false,
                replay_time_ms: ms,
            });
        }
    }
}

// ============================================================================
// Phase 2
// ============================================================================

fn ddmin(
    indices: &[usize],
    all: &[ScenarioElement],
    checker: &impl Fn(&[ScenarioElement]) -> bool,
    clock: &dyn MinimizerClock,
    replays: &mut usize,
    steps: &mut Vec<MinimizationStep>,
) -> Vec<usize> {
    if indices.len() <= 1 {
        return indices.to_vec();
    }
    let mut current = indices.to_vec();
    let mut granularity = 2usize;

    loop {
        let chunks = granularity.min(current.len());
        if chunks == 0 {
            break;
        }
        let chunk_sz = current.len().div_ceil(chunks);
        let mut reduced = false;

        for i in 0..chunks {
            let lo = i * chunk_sz;
            let hi = ((i + 1) * chunk_sz).min(current.len());
            // `chunk_sz` is rounded up, so a trailing chunk can start at or
            // past `current.len()` (`lo >= hi`). Such a chunk is empty: its
            // complement is the whole set, which is not a reduction. Skipping
            // it avoids both the `hi - lo` underflow below and a non-progress
            // loop where `current = complement` never shrinks `current`.
            if lo >= hi {
                continue;
            }
            let complement: Vec<usize> = current
                .iter()
                .enumerate()
                .filter(|(j, _)| *j < lo || *j >= hi)
                .map(|(_, &v)| v)
                .collect();
            if complement.is_empty() {
                continue;
            }
            let subset: Vec<ScenarioElement> =
                complement.iter().map(|&idx| all[idx].clone()).collect();
            let t_start = clock.now_ms();
            *replays += 1;
            let ok = checker(&subset);
            let ms = clock.now_ms().saturating_sub(t_start);
            steps.push(MinimizationStep {
                kind: StepKind::BottomUpRemove,
                events_remaining: complement.len(),
                events_removed: hi - lo,
                replay_result: ok,
                replay_time_ms: ms,
            });
            if ok {
                current = complement;
                granularity = 2.max(granularity - 1);
                reduced = true;
                break;
            }
        }
        if !reduced {
            if granularity >= current.len() {
                break;
            }
            granularity *= 2;
        }
    }
    current
}

// ============================================================================
// Phase 3
// ============================================================================

fn verify_minimality(
    indices: &[usize],
    all: &[ScenarioElement],
    checker: &impl Fn(&[ScenarioElement]) -> bool,
    clock: &dyn MinimizerClock,
    replays: &mut usize,
    steps: &mut Vec<MinimizationStep>,
) -> bool {
    let mut minimal = true;
    for skip in 0..indices.len() {
        let without: Vec<ScenarioElement> = indices
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != skip)
            .map(|(_, &idx)| all[idx].clone())
            .collect();
        let t_start = clock.now_ms();
        *replays += 1;
        let ok = checker(&without);
        let ms = clock.now_ms().saturating_sub(t_start);
        steps.push(MinimizationStep {
            kind: StepKind::MinimalityCheck,
            events_remaining: without.len(),
            events_removed: 1,
            replay_result: ok,
            replay_time_ms: ms,
        });
        if ok {
            minimal = false;
        }
    }
    minimal
}

fn collect_active(elements: &[ScenarioElement], active: &[bool]) -> Vec<ScenarioElement> {
    elements
        .iter()
        .enumerate()
        .filter(|(i, _)| active[*i])
        .map(|(_, e)| e.clone())
        .collect()
}

// ============================================================================
// Narrative
// ============================================================================

/// Generate a Markdown narrative for the minimized failure.
#[must_use]
pub fn generate_narrative(report: &MinimizationReport) -> String {
    use std::fmt::Write;

    let minimized = report.minimized_elements();
    let mut md = String::new();

    md.push_str("# Minimized Failure Narrative\n\n");
    let _ = write!(
        md,
        "Original: {} elements | Minimized: {} elements | Reduction: {:.1}%\n\n",
        report.original_count,
        report.minimized_count,
        report.reduction_ratio * 100.0,
    );

    md.push_str("## Timeline of Critical Events\n\n");
    for (i, elem) in minimized.iter().enumerate() {
        let _ = writeln!(md, "{}. `{elem}`", i + 1);
    }

    md.push_str("\n## Root Cause Analysis\n\n");

    let late: Vec<_> = minimized
        .iter()
        .filter_map(|e| match e {
            ScenarioElement::CreateObligation {
                task_idx,
                kind,
                is_late: true,
                region_idx,
                ..
            } => Some((*task_idx, kind, *region_idx)),
            _ => None,
        })
        .collect();

    let cancels: Vec<usize> = minimized
        .iter()
        .filter_map(|e| match e {
            ScenarioElement::CancelRegion { region_idx } => Some(*region_idx),
            _ => None,
        })
        .collect();

    if !late.is_empty() {
        md.push_str("**Race condition: cancel propagation vs obligation resolution**\n\n");
        for (task, kind, region) in &late {
            let _ = writeln!(
                md,
                "- Task {task} acquires `{kind:?}` obligation in region {region}"
            );
        }
        for r in &cancels {
            let _ = writeln!(md, "- Cancel requested on region {r}");
        }
        md.push_str("- The obligation is **not resolved** before the region closes\n");
        md.push_str("- Runtime detects an **obligation leak** (Reserved at region close)\n");
    }

    md.push_str("\n## Statistics\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    let _ = writeln!(md, "| Original events | {} |", report.original_count);
    let _ = writeln!(md, "| Minimized events | {} |", report.minimized_count);
    let _ = writeln!(md, "| Reduction | {:.1}% |", report.reduction_ratio * 100.0);
    let _ = writeln!(md, "| Replays | {} |", report.replay_attempts);
    let _ = writeln!(md, "| Wall time | {}ms |", report.wall_time_ms);
    let _ = writeln!(
        md,
        "| 1-minimal | {} |",
        if report.is_minimal { "yes" } else { "no" }
    );

    md
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "minimizer_inline_tests.rs"]
mod tests;
