//! Hierarchical delta debugging for trace minimization.
//!
//! Given a replay trace that reproduces a failure, finds the minimal subset
//! of events that still reproduces. Exploits the structured concurrency tree
//! to prune entire region subtrees before fine-grained event-level minimization.
//!
//! # Algorithm
//!
//! 1. **Build region tree** from `RegionCreated` events (parent pointers).
//! 2. **Top-down phase**: try removing each top-level region subtree.
//!    If the failure still reproduces, mark the region as irrelevant.
//! 3. **Bottom-up phase**: within remaining events, apply ddmin — partition
//!    into chunks, try removing each chunk, keep removals that preserve failure.
//! 4. **Minimality check**: verify each event in the result is necessary.
//!
//! # References
//!
//! - Zeller, A. (1999). "Yesterday, my program worked. Today, it does not."
//! - Hierarchical extension: exploit structured concurrency tree structure
//!   to reduce the search space from O(n) to O(regions + remaining).

use crate::trace::replay::{CompactRegionId, ReplayEvent, ReplayTrace, TraceMetadata};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Newtype key for region IDs in hash maps (wraps the inner u64).
type RegionKey = u64;

fn rkey(r: CompactRegionId) -> RegionKey {
    r.0
}

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for hierarchical delta debugging.
#[derive(Debug, Clone)]
pub struct DeltaDebugConfig {
    /// Maximum number of oracle (replay) evaluations before stopping.
    /// 0 = unlimited.
    pub max_evaluations: usize,

    /// Whether to run the minimality verification pass.
    /// This requires one oracle call per event in the minimized trace.
    pub verify_minimality: bool,

    /// Whether to run the top-down region pruning phase.
    /// Disable for flat traces without region hierarchy.
    pub hierarchical: bool,

    /// Chunk granularity for bottom-up ddmin phase.
    /// Smaller values find more precise minimizations but cost more oracle calls.
    /// 0 = auto (start at n/2 and halve).
    pub initial_chunk_size: usize,
}

impl Default for DeltaDebugConfig {
    fn default() -> Self {
        Self {
            max_evaluations: 0,
            verify_minimality: true,
            hierarchical: true,
            initial_chunk_size: 0,
        }
    }
}

// =============================================================================
// Region Tree
// =============================================================================

/// A node in the region hierarchy tree.
#[derive(Debug, Clone)]
struct RegionNode {
    /// Child regions.
    children: Vec<RegionKey>,
    /// Indices of events belonging to this region (not children).
    event_indices: Vec<usize>,
    /// All event indices in this subtree (self + descendants).
    subtree_indices: Vec<usize>,
}

/// Build a region tree from a replay trace.
///
/// Returns: (tree, roots) where tree maps region keys to nodes
/// and roots are regions with no parent.
/// Compute subtree indices via post-order traversal.
fn collect_subtree(region: RegionKey, tree: &mut BTreeMap<RegionKey, RegionNode>) -> Vec<usize> {
    let children: Vec<RegionKey> = tree
        .get(&region)
        .map(|n| n.children.clone())
        .unwrap_or_default();

    let mut indices: Vec<usize> = tree
        .get(&region)
        .map(|n| n.event_indices.clone())
        .unwrap_or_default();

    for child in children {
        indices.extend(collect_subtree(child, tree));
    }

    indices.sort_unstable();
    indices.dedup();

    if let Some(node) = tree.get_mut(&region) {
        node.subtree_indices.clone_from(&indices);
    }

    indices
}

fn build_region_tree(events: &[ReplayEvent]) -> (BTreeMap<RegionKey, RegionNode>, Vec<RegionKey>) {
    // First pass: discover all regions and parent relationships.
    let mut parent_map: BTreeMap<RegionKey, Option<RegionKey>> = BTreeMap::new();
    let mut region_events: BTreeMap<RegionKey, Vec<usize>> = BTreeMap::new();

    for (idx, event) in events.iter().enumerate() {
        match event {
            ReplayEvent::RegionCreated { region, parent, .. } => {
                parent_map.insert(rkey(*region), parent.map(rkey));
                region_events.entry(rkey(*region)).or_default().push(idx);
            }
            ReplayEvent::RegionClosed { region, .. }
            | ReplayEvent::RegionCancelled { region, .. }
            | ReplayEvent::TaskSpawned { region, .. } => {
                region_events.entry(rkey(*region)).or_default().push(idx);
            }
            _ => {
                // Events not tied to a specific region are "global".
            }
        }
    }

    // Build tree nodes.
    let mut tree: BTreeMap<RegionKey, RegionNode> = BTreeMap::new();
    let mut roots = Vec::new();

    // Initialize nodes.
    for (&region, parent) in &parent_map {
        tree.entry(region).or_insert_with(|| RegionNode {
            children: Vec::new(),
            event_indices: region_events.get(&region).cloned().unwrap_or_default(),
            subtree_indices: Vec::new(),
        });

        if let Some(parent_id) = parent {
            tree.entry(*parent_id)
                .or_insert_with(|| RegionNode {
                    children: Vec::new(),
                    event_indices: region_events.get(parent_id).cloned().unwrap_or_default(),
                    subtree_indices: Vec::new(),
                })
                .children
                .push(region);
        } else {
            roots.push(region);
        }
    }

    for root in &roots {
        collect_subtree(*root, &mut tree);
    }

    (tree, roots)
}

/// Assign non-region-specific events to the nearest enclosing region.
///
/// Events like `TaskScheduled`, `TaskYielded`, `TaskCompleted` reference tasks
/// but not regions directly. We map them to regions via the task-to-region
/// binding established by `TaskSpawned`.
fn assign_task_events_to_regions(
    events: &[ReplayEvent],
    tree: &mut BTreeMap<RegionKey, RegionNode>,
) {
    // Build task → region map from TaskSpawned events.
    let mut task_region: BTreeMap<u64, RegionKey> = BTreeMap::new();
    for event in events {
        if let ReplayEvent::TaskSpawned { task, region, .. } = event {
            task_region.insert(task.0, rkey(*region));
        }
    }

    // Assign task-level events to their owning region.
    for (idx, event) in events.iter().enumerate() {
        let task_id = match event {
            ReplayEvent::TaskScheduled { task, .. }
            | ReplayEvent::TaskYielded { task }
            | ReplayEvent::TaskCompleted { task, .. }
            | ReplayEvent::WakerWake { task } => Some(task.0),
            _ => None,
        };

        if let Some(tid) = task_id {
            if let Some(region) = task_region.get(&tid) {
                if let Some(node) = tree.get_mut(region) {
                    if !node.subtree_indices.contains(&idx) {
                        node.event_indices.push(idx);
                        node.subtree_indices.push(idx);
                    }
                }
            }
        }
    }
}

// =============================================================================
// Delta Debugging Core
// =============================================================================

/// Run the oracle on a subset of events (identified by a keep-set of indices).
fn run_oracle_subset<F>(
    events: &[ReplayEvent],
    metadata: &TraceMetadata,
    keep: &BTreeSet<usize>,
    oracle: &mut F,
) -> bool
where
    F: FnMut(&ReplayTrace) -> bool,
{
    let subset_events: Vec<ReplayEvent> = keep
        .iter()
        .filter_map(|&i| events.get(i).cloned())
        .collect();

    let trace = ReplayTrace {
        metadata: metadata.clone(),
        events: subset_events,
        cursor: 0,
    };

    oracle(&trace)
}

/// Context for region pruning to avoid passing many arguments.
struct PruneCtx<'a> {
    events: &'a [ReplayEvent],
    metadata: &'a TraceMetadata,
    tree: &'a BTreeMap<RegionKey, RegionNode>,
    max_evals: usize,
}

/// Recursively try pruning a region subtree.
fn try_prune_region<F>(
    region: RegionKey,
    ctx: &PruneCtx<'_>,
    keep: &mut BTreeSet<usize>,
    oracle: &mut F,
    stats: &mut MinimizationStats,
) where
    F: FnMut(&ReplayTrace) -> bool,
{
    if ctx.max_evals > 0 && stats.oracle_calls >= ctx.max_evals {
        return;
    }

    let Some(node) = ctx.tree.get(&region) else {
        return;
    };

    // Try removing the entire subtree.
    let subtree_set: BTreeSet<usize> = node.subtree_indices.iter().copied().collect();
    let candidate: BTreeSet<usize> = keep.difference(&subtree_set).copied().collect();

    if candidate.is_empty() {
        return; // Can't remove everything.
    }

    stats.oracle_calls += 1;
    if run_oracle_subset(ctx.events, ctx.metadata, &candidate, oracle) {
        // Success: this region is irrelevant.
        stats.regions_pruned += 1;
        stats.events_pruned_top_down += subtree_set.len();
        *keep = candidate;
        return;
    }

    // Can't remove this region entirely — try removing its children.
    for child in &node.children {
        try_prune_region(*child, ctx, keep, oracle, stats);
    }
}

/// Top-down phase: try removing each top-level region subtree.
///
/// Returns the set of event indices to keep.
fn top_down_prune<F>(
    events: &[ReplayEvent],
    metadata: &TraceMetadata,
    tree: &BTreeMap<RegionKey, RegionNode>,
    roots: &[RegionKey],
    oracle: &mut F,
    stats: &mut MinimizationStats,
    config: &DeltaDebugConfig,
) -> BTreeSet<usize>
where
    F: FnMut(&ReplayTrace) -> bool,
{
    let mut keep: BTreeSet<usize> = (0..events.len()).collect();

    let ctx = PruneCtx {
        events,
        metadata,
        tree,
        max_evals: config.max_evaluations,
    };

    for root in roots {
        try_prune_region(*root, &ctx, &mut keep, oracle, stats);
    }

    keep
}

/// Bottom-up ddmin phase: iteratively remove chunks of events.
///
/// Classic delta debugging: partition into chunks, try removing each,
/// keep removals that preserve the failure.
fn ddmin_phase<F>(
    events: &[ReplayEvent],
    metadata: &TraceMetadata,
    keep: &BTreeSet<usize>,
    oracle: &mut F,
    stats: &mut MinimizationStats,
    config: &DeltaDebugConfig,
) -> BTreeSet<usize>
where
    F: FnMut(&ReplayTrace) -> bool,
{
    let mut current: Vec<usize> = keep.iter().copied().collect();
    let n = current.len();

    if n <= 1 {
        return keep.clone();
    }

    let mut chunk_size = if config.initial_chunk_size > 0 {
        config.initial_chunk_size.min(n)
    } else {
        n / 2
    };

    while chunk_size >= 1 {
        let max_evals = config.max_evaluations;
        if max_evals > 0 && stats.oracle_calls >= max_evals {
            break;
        }

        let mut changed = false;
        let chunks: Vec<Vec<usize>> = current.chunks(chunk_size).map(<[usize]>::to_vec).collect();

        for chunk in &chunks {
            if max_evals > 0 && stats.oracle_calls >= max_evals {
                break;
            }

            // Try removing this chunk.
            let candidate: BTreeSet<usize> = current
                .iter()
                .filter(|idx| !chunk.contains(idx))
                .copied()
                .collect();

            if candidate.is_empty() {
                continue;
            }

            stats.oracle_calls += 1;
            if run_oracle_subset(events, metadata, &candidate, oracle) {
                // Removal succeeded — update current.
                current = candidate.into_iter().collect();
                stats.events_pruned_bottom_up += chunk.len();
                changed = true;
                break; // Restart with fresh chunking at same granularity.
            }
        }

        if !changed {
            // No chunk could be removed at this granularity — halve chunk size.
            if chunk_size == 1 {
                break;
            }
            chunk_size /= 2;
        }
    }

    current.into_iter().collect()
}

/// Minimality verification: for each remaining event, check it's necessary.
fn verify_minimality_pass<F>(
    events: &[ReplayEvent],
    metadata: &TraceMetadata,
    keep: &BTreeSet<usize>,
    oracle: &mut F,
    stats: &mut MinimizationStats,
    config: &DeltaDebugConfig,
) -> (BTreeSet<usize>, bool)
where
    F: FnMut(&ReplayTrace) -> bool,
{
    let mut result = keep.clone();

    loop {
        let indices: Vec<usize> = result.iter().copied().collect();
        let mut removed_this_pass = false;

        for idx in indices {
            if !result.contains(&idx) {
                continue;
            }

            let max_evals = config.max_evaluations;
            if max_evals > 0 && stats.oracle_calls >= max_evals {
                return (result, false);
            }

            let candidate: BTreeSet<usize> =
                result.iter().filter(|&&i| i != idx).copied().collect();
            if candidate.is_empty() {
                continue;
            }

            stats.oracle_calls += 1;
            if run_oracle_subset(events, metadata, &candidate, oracle) {
                result = candidate;
                stats.events_pruned_minimality += 1;
                removed_this_pass = true;
            }
        }

        if !removed_this_pass {
            return (result, true);
        }
    }
}

// =============================================================================
// Results
// =============================================================================

/// Statistics from the minimization process.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MinimizationStats {
    /// Total oracle (replay) evaluations performed.
    pub oracle_calls: usize,
    /// Number of regions pruned in top-down phase.
    pub regions_pruned: usize,
    /// Events removed during top-down region pruning.
    pub events_pruned_top_down: usize,
    /// Events removed during bottom-up ddmin.
    pub events_pruned_bottom_up: usize,
    /// Events removed during minimality verification.
    pub events_pruned_minimality: usize,
    /// Whether the budget was exhausted before completion.
    pub budget_exhausted: bool,
    /// Whether the result passed minimality verification.
    pub minimality_verified: bool,
}

/// Result of hierarchical delta debugging.
#[derive(Debug)]
pub struct DeltaDebugResult {
    /// The minimized replay trace.
    pub minimized: ReplayTrace,

    /// Original event count.
    pub original_event_count: usize,

    /// Minimized event count.
    pub minimized_event_count: usize,

    /// Reduction ratio (0.0 = no reduction, 1.0 = eliminated everything).
    pub reduction_ratio: f64,

    /// Detailed statistics.
    pub stats: MinimizationStats,

    /// Indices of the critical events in the original trace.
    pub critical_indices: Vec<usize>,
}

impl fmt::Display for DeltaDebugResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeltaDebug: {} -> {} events ({:.1}% reduction, {} oracle calls, {} regions pruned)",
            self.original_event_count,
            self.minimized_event_count,
            self.reduction_ratio * 100.0,
            self.stats.oracle_calls,
            self.stats.regions_pruned,
        )
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Minimize a failing replay trace using hierarchical delta debugging.
///
/// The `oracle` callback is called with candidate traces and must return `true`
/// if the candidate still reproduces the target failure.
///
/// # Algorithm
///
/// 1. Build region tree from `RegionCreated` events
/// 2. Top-down: try removing entire region subtrees
/// 3. Bottom-up: ddmin on remaining events
/// 4. (Optional) Minimality verification
///
/// # Panics
///
/// Panics if the trace is empty or the oracle returns false for the full trace.
pub fn minimize<F>(
    trace: &ReplayTrace,
    config: &DeltaDebugConfig,
    mut oracle: F,
) -> DeltaDebugResult
where
    F: FnMut(&ReplayTrace) -> bool,
{
    let n = trace.events.len();
    assert!(n > 0, "cannot minimize an empty trace");

    // Verify the full trace reproduces the failure.
    assert!(oracle(trace), "oracle must return true for the full trace");

    let mut stats = MinimizationStats {
        oracle_calls: 1, // The verification call above.
        ..MinimizationStats::default()
    };

    // Phase 1: Build region tree and top-down prune.
    let keep = if config.hierarchical {
        let (mut tree, roots) = build_region_tree(&trace.events);
        assign_task_events_to_regions(&trace.events, &mut tree);
        // Re-compute subtree indices so ancestors include late-added task events.
        for root in &roots {
            collect_subtree(*root, &mut tree);
        }

        if roots.is_empty() {
            // No region hierarchy — skip top-down.
            (0..n).collect()
        } else {
            top_down_prune(
                &trace.events,
                &trace.metadata,
                &tree,
                &roots,
                &mut oracle,
                &mut stats,
                config,
            )
        }
    } else {
        (0..n).collect()
    };

    // Phase 2: Bottom-up ddmin.
    let keep = ddmin_phase(
        &trace.events,
        &trace.metadata,
        &keep,
        &mut oracle,
        &mut stats,
        config,
    );

    // Phase 3: Minimality verification.
    let (keep, minimality_verified) = if config.verify_minimality {
        let (result, verified) = verify_minimality_pass(
            &trace.events,
            &trace.metadata,
            &keep,
            &mut oracle,
            &mut stats,
            config,
        );
        stats.minimality_verified = verified;
        (result, verified)
    } else {
        (keep, false)
    };

    stats.budget_exhausted =
        config.max_evaluations > 0 && stats.oracle_calls >= config.max_evaluations;
    let _ = minimality_verified; // used via stats

    // Build result.
    let critical_indices: Vec<usize> = keep.iter().copied().collect();
    let minimized_events: Vec<ReplayEvent> = critical_indices
        .iter()
        .filter_map(|&i| trace.events.get(i).cloned())
        .collect();

    let minimized_count = minimized_events.len();

    #[allow(clippy::cast_precision_loss)]
    let reduction_ratio = if n > 0 {
        1.0 - (minimized_count as f64 / n as f64)
    } else {
        0.0
    };

    DeltaDebugResult {
        minimized: ReplayTrace {
            metadata: trace.metadata.clone(),
            events: minimized_events,
            cursor: 0,
        },
        original_event_count: n,
        minimized_event_count: minimized_count,
        reduction_ratio,
        stats,
        critical_indices,
    }
}

// =============================================================================
// Narrative Generation
// =============================================================================

/// Generate a human-readable narrative of the critical events.
///
/// Returns Markdown text describing which events are critical and why.
#[must_use]
pub fn generate_narrative(original: &ReplayTrace, result: &DeltaDebugResult) -> String {
    use crate::trace::divergence::EventSummary;
    use std::fmt::Write;

    let mut md = String::new();
    md.push_str("# Trace Minimization Report\n\n");
    let _ = writeln!(
        md,
        "Reduced from **{}** to **{}** events ({:.1}% reduction).\n",
        result.original_event_count,
        result.minimized_event_count,
        result.reduction_ratio * 100.0,
    );

    md.push_str("## Statistics\n\n");
    let _ = writeln!(md, "- Oracle evaluations: {}", result.stats.oracle_calls);
    let _ = writeln!(
        md,
        "- Regions pruned (top-down): {}",
        result.stats.regions_pruned
    );
    let _ = writeln!(
        md,
        "- Events pruned (top-down): {}",
        result.stats.events_pruned_top_down
    );
    let _ = writeln!(
        md,
        "- Events pruned (bottom-up): {}",
        result.stats.events_pruned_bottom_up
    );
    if result.stats.events_pruned_minimality > 0 {
        let _ = writeln!(
            md,
            "- Events pruned (minimality): {}",
            result.stats.events_pruned_minimality
        );
    }
    let _ = writeln!(
        md,
        "- Minimality verified: {}",
        result.stats.minimality_verified
    );

    md.push_str("\n## Critical Events\n\n");
    md.push_str("| # | Index | Type | Details |\n");
    md.push_str("|---|-------|------|---------|\n");

    for (i, &idx) in result.critical_indices.iter().enumerate() {
        if let Some(event) = original.events.get(idx) {
            let summary = EventSummary::from_event(idx, event);
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} |",
                i + 1,
                summary.index,
                summary.event_type,
                summary.details,
            );
        }
    }

    md
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[path = "delta_debug_inline_tests.rs"]
mod tests;
