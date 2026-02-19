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
use std::time::Instant;

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
    /// # Panics
    ///
    /// Panics if the full element set does not reproduce the failure.
    #[allow(clippy::cast_precision_loss)]
    pub fn minimize(
        elements: &[ScenarioElement],
        checker: impl Fn(&[ScenarioElement]) -> bool,
    ) -> MinimizationReport {
        let start = Instant::now();
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
        remaining = ddmin(&remaining, elements, &checker, &mut replays, &mut steps);

        // Phase 3: 1-minimality check.
        let is_minimal =
            verify_minimality(&remaining, elements, &checker, &mut replays, &mut steps);

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
            wall_time_ms: start.elapsed().as_millis() as u64,
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
        let t = Instant::now();
        *replays += 1;
        let ok = checker(&subset);
        let ms = t.elapsed().as_millis() as u64;
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
            let t = Instant::now();
            *replays += 1;
            let ok = checker(&subset);
            let ms = t.elapsed().as_millis() as u64;
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
        let t = Instant::now();
        *replays += 1;
        let ok = checker(&without);
        let ms = t.elapsed().as_millis() as u64;
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
mod tests {
    use super::*;

    fn make_scenario(n_tasks: usize, failing_task: usize) -> Vec<ScenarioElement> {
        let mut elems = Vec::new();
        // Region 0 (root) is implicit. Only child regions are elements.
        elems.push(ScenarioElement::CreateRegion {
            region_idx: 1,
            parent_idx: 0,
        });
        elems.push(ScenarioElement::CreateRegion {
            region_idx: 2,
            parent_idx: 0,
        });

        for i in 0..n_tasks {
            let region = if i == failing_task { 1 } else { 2 };
            elems.push(ScenarioElement::SpawnTask {
                task_idx: i,
                region_idx: region,
                lane: (i % 4) as u8,
            });
            let n_obl = 1 + (i % 3);
            for j in 0..n_obl {
                elems.push(ScenarioElement::CreateObligation {
                    task_idx: i,
                    region_idx: region,
                    kind: ObligationKind::SendPermit,
                    commit: true,
                    is_late: i == failing_task && j == 0,
                });
            }
        }
        elems.push(ScenarioElement::AdvanceTime { nanos: 1000 });
        elems.push(ScenarioElement::CancelRegion { region_idx: 1 });
        elems.push(ScenarioElement::AdvanceTime { nanos: 1_000_000 });
        elems
    }

    fn leak_checker(target_task: usize) -> impl Fn(&[ScenarioElement]) -> bool {
        move |subset: &[ScenarioElement]| {
            let has_late = subset.iter().any(|e| {
                matches!(e, ScenarioElement::CreateObligation { task_idx, is_late: true, .. } if *task_idx == target_task)
            });
            let has_cancel = subset
                .iter()
                .any(|e| matches!(e, ScenarioElement::CancelRegion { region_idx: 1 }));
            let has_region = subset
                .iter()
                .any(|e| matches!(e, ScenarioElement::CreateRegion { region_idx: 1, .. }));
            let has_task = subset.iter().any(|e| {
                matches!(e, ScenarioElement::SpawnTask { task_idx, .. } if *task_idx == target_task)
            });
            has_late && has_cancel && has_region && has_task
        }
    }

    #[test]
    fn synthetic_known_minimum() {
        let elems = make_scenario(100, 42);
        assert!(elems.len() > 100);
        let report = TraceMinimizer::minimize(&elems, leak_checker(42));
        assert_eq!(report.minimized_count, 4);
        assert!(report.is_minimal);
        assert!(report.reduction_ratio > 0.95);
        assert!(report.replay_attempts < 100);
    }

    #[test]
    fn determinism_10_runs() {
        let elems = make_scenario(50, 7);
        let first = TraceMinimizer::minimize(&elems, leak_checker(7));
        for _ in 0..9 {
            let run = TraceMinimizer::minimize(&elems, leak_checker(7));
            assert_eq!(run.minimized_indices, first.minimized_indices);
        }
    }

    #[test]
    fn scaling_sub_linear() {
        let sizes = [100, 500, 1000];
        let mut counts = Vec::new();
        for &sz in &sizes {
            let elems = make_scenario(sz, sz / 2);
            let r = TraceMinimizer::minimize(&elems, leak_checker(sz / 2));
            counts.push(r.replay_attempts);
        }
        #[allow(clippy::cast_precision_loss)]
        let ratio = counts[2] as f64 / counts[0] as f64;
        #[allow(clippy::cast_precision_loss)]
        let size_ratio = sizes[2] as f64 / sizes[0] as f64;
        assert!(
            ratio < size_ratio,
            "replay scaling ({ratio:.1}x) should be < size scaling ({size_ratio:.1}x)"
        );
    }

    #[test]
    fn narrative_contains_essentials() {
        let elems = make_scenario(10, 3);
        let report = TraceMinimizer::minimize(&elems, leak_checker(3));
        let md = generate_narrative(&report);
        assert!(md.contains("Minimized Failure Narrative"));
        assert!(md.contains("obligation leak"));
        assert!(md.contains("Statistics"));
    }

    #[test]
    fn already_minimal_scenario() {
        let elems = vec![
            ScenarioElement::CreateRegion {
                region_idx: 1,
                parent_idx: 0,
            },
            ScenarioElement::SpawnTask {
                task_idx: 0,
                region_idx: 1,
                lane: 0,
            },
            ScenarioElement::CreateObligation {
                task_idx: 0,
                region_idx: 1,
                kind: ObligationKind::SendPermit,
                commit: true,
                is_late: true,
            },
            ScenarioElement::CancelRegion { region_idx: 1 },
        ];
        let report = TraceMinimizer::minimize(&elems, leak_checker(0));
        assert_eq!(report.minimized_count, 4);
        assert!(report.is_minimal);
    }

    // Pure data-type tests (wave 16 – CyanBarn)

    #[test]
    fn scenario_element_debug() {
        let elem = ScenarioElement::AdvanceTime { nanos: 100 };
        let dbg = format!("{elem:?}");
        assert!(dbg.contains("AdvanceTime"));
    }

    #[test]
    fn scenario_element_clone_eq() {
        let a = ScenarioElement::CreateRegion {
            region_idx: 1,
            parent_idx: 0,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn scenario_element_ne() {
        let a = ScenarioElement::AdvanceTime { nanos: 100 };
        let b = ScenarioElement::AdvanceTime { nanos: 200 };
        assert_ne!(a, b);
    }

    #[test]
    fn scenario_element_display_all() {
        let cases: Vec<ScenarioElement> = vec![
            ScenarioElement::CreateRegion {
                region_idx: 1,
                parent_idx: 0,
            },
            ScenarioElement::SpawnTask {
                task_idx: 5,
                region_idx: 2,
                lane: 3,
            },
            ScenarioElement::CreateObligation {
                task_idx: 1,
                region_idx: 0,
                kind: ObligationKind::SendPermit,
                commit: true,
                is_late: false,
            },
            ScenarioElement::CreateObligation {
                task_idx: 2,
                region_idx: 0,
                kind: ObligationKind::SendPermit,
                commit: false,
                is_late: true,
            },
            ScenarioElement::AdvanceTime { nanos: 1000 },
            ScenarioElement::CancelRegion { region_idx: 3 },
        ];

        let displays: Vec<String> = cases.iter().map(std::string::ToString::to_string).collect();
        assert!(displays[0].contains("create_region"));
        assert!(displays[1].contains("spawn_task"));
        assert!(displays[2].contains("obligation"));
        assert!(displays[2].contains("commit"));
        assert!(displays[3].contains("abort"));
        assert!(displays[3].contains("LATE"));
        assert!(displays[4].contains("advance_time"));
        assert!(displays[5].contains("cancel_region"));
    }

    #[test]
    fn scenario_element_region_idx() {
        assert_eq!(
            ScenarioElement::CreateRegion {
                region_idx: 5,
                parent_idx: 0
            }
            .region_idx(),
            Some(5)
        );
        assert_eq!(
            ScenarioElement::SpawnTask {
                task_idx: 0,
                region_idx: 3,
                lane: 0
            }
            .region_idx(),
            Some(3)
        );
        assert_eq!(
            ScenarioElement::CancelRegion { region_idx: 7 }.region_idx(),
            Some(7)
        );
        assert_eq!(
            ScenarioElement::AdvanceTime { nanos: 100 }.region_idx(),
            None
        );
    }

    #[test]
    fn step_kind_debug_clone_copy_eq() {
        let kind = StepKind::TopDownPrune;
        let cloned = kind;
        let copied = kind;
        assert_eq!(cloned, copied);
        assert_eq!(kind, StepKind::TopDownPrune);
        assert_ne!(kind, StepKind::BottomUpRemove);
    }

    #[test]
    fn step_kind_display_all() {
        assert_eq!(StepKind::TopDownPrune.to_string(), "top_down_prune");
        assert_eq!(StepKind::BottomUpRemove.to_string(), "bottom_up_remove");
        assert_eq!(StepKind::MinimalityCheck.to_string(), "minimality_check");
    }

    #[test]
    fn minimization_step_debug_clone() {
        let step = MinimizationStep {
            kind: StepKind::BottomUpRemove,
            events_remaining: 10,
            events_removed: 3,
            replay_result: true,
            replay_time_ms: 42,
        };
        let dbg = format!("{step:?}");
        assert!(dbg.contains("MinimizationStep"));

        let cloned = step;
        assert_eq!(cloned.events_remaining, 10);
        assert_eq!(cloned.replay_time_ms, 42);
    }

    #[test]
    fn minimization_report_debug() {
        let elems = make_scenario(5, 1);
        let report = TraceMinimizer::minimize(&elems, leak_checker(1));
        let dbg = format!("{report:?}");
        assert!(dbg.contains("MinimizationReport"));
    }

    #[test]
    fn minimization_report_minimized_elements() {
        let elems = make_scenario(5, 1);
        let report = TraceMinimizer::minimize(&elems, leak_checker(1));
        let minimized = report.minimized_elements();
        assert_eq!(minimized.len(), report.minimized_count);
    }
}
