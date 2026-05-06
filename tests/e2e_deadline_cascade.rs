//! T5.3 — Deadline cascade through a 7-level deep region tree.
//!
//! Builds a binary tree of 7 levels (root + L1..L6, 127 regions total), spawns
//! checkpoint+yield tasks in every leaf, then simulates cascading deadline
//! expiry by cancelling subtrees at different virtual-time points and verifying
//! partial drainage preserves sibling liveness.

#[macro_use]
mod common;

use asupersync::cx::Cx;
use asupersync::runtime::yield_now;
use common::e2e_harness::E2eLabHarness;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEED_CALM: u64 = 0xE2E5_3001;
const SEED_CHAOS: u64 = 0xE2E5_3002;

/// Depth of the region tree (root = level 0, leaves = level 6).
const TREE_DEPTH: usize = 7;
/// Branching factor at every non-leaf level.
const BRANCH: usize = 2;
/// Tasks spawned per leaf region.
const TASKS_PER_LEAF: usize = 3;
/// Yield iterations each task performs.
/// Must be large enough that 100 warm-up steps + a partial cancel leaves
/// surviving tasks still alive when we check sibling liveness.
const TASK_ITERS: usize = 500;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

use asupersync::types::RegionId;

/// Recursively build a binary tree of regions returning a flat list of
/// `(RegionId, depth)` tuples (root at index 0).
fn build_tree(h: &mut E2eLabHarness) -> Vec<(RegionId, usize)> {
    let root = h.create_root();
    let mut nodes: Vec<(RegionId, usize)> = vec![(root, 0)];
    let mut frontier_start = 0;
    for depth in 1..TREE_DEPTH {
        let frontier_end = nodes.len();
        for i in frontier_start..frontier_end {
            let parent = nodes[i].0;
            for _ in 0..BRANCH {
                let child = h.create_child(parent);
                nodes.push((child, depth));
            }
        }
        frontier_start = frontier_end;
    }
    nodes
}

/// Spawn `TASKS_PER_LEAF` checkpoint+yield tasks in every leaf region.
/// Returns the shared work counter.
fn spawn_leaf_tasks(h: &mut E2eLabHarness, nodes: &[(RegionId, usize)]) -> Arc<AtomicUsize> {
    let counter = Arc::new(AtomicUsize::new(0));
    let leaf_depth = TREE_DEPTH - 1;
    for &(region, depth) in nodes {
        if depth == leaf_depth {
            for _ in 0..TASKS_PER_LEAF {
                let c = Arc::clone(&counter);
                h.spawn(region, async move {
                    for _ in 0..TASK_ITERS {
                        let Some(cx) = Cx::current() else { return };
                        if cx.checkpoint().is_err() {
                            return;
                        }
                        c.fetch_add(1, Ordering::Relaxed);
                        yield_now().await;
                    }
                });
            }
        }
    }
    counter
}

/// Collect direct children (depth == parent_depth+1) of `parent` whose
/// subtree root was created right after `parent` in the node list.
fn children_of(nodes: &[(RegionId, usize)], parent_idx: usize) -> Vec<usize> {
    let parent_depth = nodes[parent_idx].1;
    let child_depth = parent_depth + 1;
    // Children of parent_idx are the next `BRANCH` nodes at child_depth
    // that appear after parent_idx in BFS order.
    let mut children = Vec::new();
    for (i, &(_, d)) in nodes.iter().enumerate().skip(parent_idx + 1) {
        if d == child_depth {
            children.push(i);
            if children.len() == BRANCH {
                break;
            }
        } else if d <= parent_depth {
            break;
        }
    }
    children
}

/// Count leaf regions in subtree rooted at `root_idx`.
fn subtree_leaf_count(nodes: &[(RegionId, usize)], root_idx: usize) -> usize {
    let root_depth = nodes[root_idx].1;
    let leaf_depth = TREE_DEPTH - 1;
    let mut count = 0;
    if root_depth == leaf_depth {
        return 1;
    }
    for &(_, d) in &nodes[root_idx + 1..] {
        if d > root_depth {
            if d == leaf_depth {
                count += 1;
            }
        } else {
            break;
        }
    }
    count
}

// ---------------------------------------------------------------------------
// Core test driver
// ---------------------------------------------------------------------------

fn run_deadline_cascade(mut h: E2eLabHarness) {
    // Phase 1 — Build tree and spawn tasks
    h.phase("build");
    let nodes = build_tree(&mut h);
    let total_regions = nodes.len();
    // 2^7 - 1 = 127
    assert_with_log!(
        total_regions == 127,
        "7-level binary tree",
        127,
        total_regions
    );

    let counter = spawn_leaf_tasks(&mut h, &nodes);
    let leaf_count = nodes.iter().filter(|(_, d)| *d == TREE_DEPTH - 1).count();
    let total_tasks = leaf_count * TASKS_PER_LEAF;
    // 2^6 = 64 leaves, 64 * 3 = 192 tasks
    assert_with_log!(total_tasks == 192, "leaf tasks", 192, total_tasks);

    // Phase 2 — Run partial steps (NOT to quiescence — tasks are finite loops,
    // running to quiescence would complete them all, making cancel vacuous).
    h.phase("warmup");
    h.advance_time(1_000_000_000); // 1s
    for _ in 0..100 {
        h.runtime.step_for_test();
    }
    let work_after_warmup = counter.load(Ordering::Relaxed);
    tracing::info!(work = work_after_warmup, "warmup done (partial)");
    assert_with_log!(
        work_after_warmup > 0,
        "tasks must execute during warmup",
        "> 0",
        work_after_warmup
    );

    // Phase 3 — Cancel L1's first subtree (simulating 8s deadline)
    h.phase("cancel_l1_first_subtree");
    h.advance_time(7_000_000_000); // now at 8s
    let root_idx = 0;
    let l1_children = children_of(&nodes, root_idx);
    assert_with_log!(
        l1_children.len() == 2,
        "root has 2 children",
        2,
        l1_children.len()
    );
    let first_l1_idx = l1_children[0];

    let first_subtree_leaves = subtree_leaf_count(&nodes, first_l1_idx);
    let first_subtree_tasks = first_subtree_leaves * TASKS_PER_LEAF;
    tracing::info!(first_subtree_tasks, "cancelling first L1 subtree");

    let live_before_cancel = h.live_task_count();
    let cancelled = h.cancel_region(nodes[first_l1_idx].0, "L1 deadline 8s");
    tracing::info!(cancelled, live_before_cancel, "cancel_region returned");

    // Run a limited number of steps — enough to drain cancelled tasks but NOT
    // enough to finish all surviving tasks (they have TASK_ITERS=500 iterations).
    for _ in 0..200 {
        h.runtime.step_for_test();
    }

    // Surviving subtree's tasks should still be alive (some, at least)
    let live = h.live_task_count();
    tracing::info!(live, "live tasks after partial cancel + limited steps");
    assert_with_log!(
        live > 0,
        "surviving subtree still has live tasks",
        "> 0",
        live
    );

    // Phase 4 — Cancel root (simulating 10s deadline), draining everything
    h.phase("cancel_root");
    h.advance_time(2_000_000_000); // now at 10s
    let cancelled_root = h.cancel_region(nodes[root_idx].0, "root deadline 10s");
    tracing::info!(cancelled_root, "cancel_region returned for root");

    let drain2 = h.run_until_quiescent();
    tracing::info!(drain2, "drain after root cancel");

    // Phase 5 — Verify full drainage
    h.phase("verify");
    let live_final = h.live_task_count();
    assert_with_log!(
        live_final == 0,
        "all tasks drained after root cancel",
        0usize,
        live_final
    );

    assert_with_log!(
        h.is_quiescent(),
        "runtime quiescent after full cascade",
        true,
        h.is_quiescent()
    );

    let pending = h.pending_obligation_count();
    assert_with_log!(pending == 0, "no pending obligations", 0usize, pending);

    let total_work = counter.load(Ordering::Relaxed);
    tracing::info!(total_work, "total work units across all tasks");
    assert_with_log!(total_work > 0, "tasks performed work", "> 0", total_work);

    h.finish();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn e2e_deadline_cascade_calm() {
    test_phase!("e2e_deadline_cascade_calm");
    let h = E2eLabHarness::new("e2e_deadline_cascade_calm", SEED_CALM);
    run_deadline_cascade(h);
    test_complete!("e2e_deadline_cascade_calm");
}

#[test]
fn e2e_deadline_cascade_chaos() {
    test_phase!("e2e_deadline_cascade_chaos");
    let h = E2eLabHarness::with_light_chaos("e2e_deadline_cascade_chaos", SEED_CHAOS);
    run_deadline_cascade(h);
    test_complete!("e2e_deadline_cascade_chaos");
}
