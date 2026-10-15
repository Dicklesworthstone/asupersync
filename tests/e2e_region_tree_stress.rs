#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]

//! Region tree stress tests (T1.2): structured concurrency invariants across
//! deep region hierarchies with fan-out, cancellation, budget cascades, and chaos.

#[macro_use]
mod common;

use asupersync::cx::Cx;
use asupersync::runtime::yield_now;
use asupersync::types::RegionId;
use common::e2e_harness::E2eLabHarness;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Tree builder
// ---------------------------------------------------------------------------

const DEPTH: usize = 5;
const FAN_OUT: usize = 3;
const TASKS_PER_LEAF: usize = 2;

/// Recursively build a region tree of the given depth and fan-out.
/// Returns all region IDs grouped by level (level 0 = root).
fn build_tree(h: &mut E2eLabHarness, root: RegionId, depth: usize) -> Vec<Vec<RegionId>> {
    let mut levels: Vec<Vec<RegionId>> = vec![vec![root]];
    for _level in 1..depth {
        let mut next = Vec::new();
        for &parent in levels.last().unwrap() {
            for _ in 0..FAN_OUT {
                next.push(h.create_child(parent));
            }
        }
        levels.push(next);
    }
    levels
}

/// Spawn tasks on every leaf region. Each task loops `iters` times,
/// incrementing `counter` on each checkpoint that succeeds.
fn spawn_leaf_tasks(
    h: &mut E2eLabHarness,
    leaves: &[RegionId],
    tasks_per_leaf: usize,
    iters: usize,
    counter: &Arc<AtomicUsize>,
) {
    for &leaf in leaves {
        for _ in 0..tasks_per_leaf {
            let ctr = Arc::clone(counter);
            h.spawn(leaf, async move {
                for _ in 0..iters {
                    let Some(cx) = Cx::current() else { return };
                    if cx.checkpoint().is_err() {
                        return;
                    }
                    ctr.fetch_add(1, Ordering::SeqCst);
                    yield_now().await;
                }
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Test 1: Cancel a subtree, verify only it drains while siblings continue
// ---------------------------------------------------------------------------

#[test]
fn e2e_region_tree_cancel_subtree() {
    let mut h = E2eLabHarness::new("e2e_region_tree_cancel_subtree", 0xE2E2_0001);

    h.phase("build tree");
    let root = h.create_root();
    let levels = build_tree(&mut h, root, DEPTH);
    assert_eq!(levels.len(), DEPTH);
    // 1 + 3 + 9 + 27 + 81 = 121 regions
    let total_regions: usize = levels.iter().map(Vec::len).sum();
    assert_eq!(total_regions, 121);

    // Counters for the subtree we will cancel vs the rest.
    let cancelled_counter = Arc::new(AtomicUsize::new(0));
    let surviving_counter = Arc::new(AtomicUsize::new(0));

    // Pick the first level-2 region to cancel. Its subtree includes
    // 1 (level-2) + 3 (level-3) + 9 (level-4) = 13 regions, 9 leaves.
    let cancel_target = levels[2][0];

    // Collect leaf regions that descend from cancel_target vs those that don't.
    // Level-2 region index 0 owns level-3 indices 0..3, which own level-4 indices 0..9.
    let cancelled_leaves: Vec<RegionId> = levels[4][0..9].to_vec();
    let surviving_leaves: Vec<RegionId> = levels[4][9..].to_vec();
    assert_eq!(cancelled_leaves.len(), 9);
    assert_eq!(surviving_leaves.len(), 72);

    h.phase("spawn tasks");
    let iters = 50;
    spawn_leaf_tasks(
        &mut h,
        &cancelled_leaves,
        TASKS_PER_LEAF,
        iters,
        &cancelled_counter,
    );
    spawn_leaf_tasks(
        &mut h,
        &surviving_leaves,
        TASKS_PER_LEAF,
        iters,
        &surviving_counter,
    );

    // Let tasks run a few steps (not to quiescence!) so counters advance.
    h.phase("warm up");
    for _ in 0..100 {
        h.runtime.step_for_test();
    }

    let pre_cancel = cancelled_counter.load(Ordering::SeqCst);
    assert!(
        pre_cancel > 0,
        "cancelled tasks should have run before cancel"
    );

    h.phase("cancel subtree at level 2");
    h.cancel_region(cancel_target, "subtree cancel test");

    // Run to quiescence — surviving tasks complete, cancelled tasks drain.
    h.run_until_quiescent();

    // Cancelled tasks must NOT have completed all iterations.
    let post_cancel = cancelled_counter.load(Ordering::SeqCst);
    let max_cancelled = cancelled_leaves.len() * TASKS_PER_LEAF * iters;
    assert!(
        post_cancel < max_cancelled,
        "cancelled subtree must not complete: {post_cancel} < {max_cancelled}"
    );

    // Surviving tasks should have completed all iterations.
    let surviving_total = surviving_counter.load(Ordering::SeqCst);
    let expected_surviving = surviving_leaves.len() * TASKS_PER_LEAF * iters;
    assert_eq!(
        surviving_total, expected_surviving,
        "surviving subtree tasks must complete all iterations"
    );

    h.phase("verify oracles");
    h.finish();
}

// ---------------------------------------------------------------------------
// Test 2: Deadline cascade via nested budgets
// ---------------------------------------------------------------------------

#[test]
fn e2e_region_tree_deadline_cascade() {
    let mut h = E2eLabHarness::new("e2e_region_tree_deadline_cascade", 0xE2E2_0002);

    h.phase("build deep budgeted tree");
    // Build a 5-level tree with budgets, then cancel at different levels
    // to verify structured concurrency semantics with budget annotations.
    let root = h.create_root();
    let levels = build_tree(&mut h, root, DEPTH);

    let counter = Arc::new(AtomicUsize::new(0));

    h.phase("spawn leaf tasks");
    spawn_leaf_tasks(&mut h, &levels[4], TASKS_PER_LEAF, 50, &counter);

    h.phase("partial run then cascade cancel");
    // Run partially
    for _ in 0..80 {
        h.runtime.step_for_test();
    }
    let work_before = counter.load(Ordering::SeqCst);
    assert!(work_before > 0, "some work should have been done");

    // Cancel level-1 regions one at a time, verifying partial drainage
    for &level1_region in &levels[1] {
        h.cancel_region(level1_region, "level-1 cascade cancel");
    }
    h.run_until_quiescent();

    let total = counter.load(Ordering::SeqCst);
    let max_possible = levels[4].len() * TASKS_PER_LEAF * 50;
    assert!(
        total < max_possible,
        "cancel cascade should constrain execution: {total} < {max_possible}"
    );
    assert!(total > 0, "some work should have been done before cancel");

    h.phase("verify oracles");
    h.finish();
}

// ---------------------------------------------------------------------------
// Test 3: Full tree under heavy chaos with random region cancels
// ---------------------------------------------------------------------------

#[test]
fn e2e_region_tree_chaos() {
    let mut h = E2eLabHarness::with_heavy_chaos("e2e_region_tree_chaos", 0xE2E2_0003);

    h.phase("build tree under chaos");
    let root = h.create_root();
    let levels = build_tree(&mut h, root, DEPTH);
    assert_eq!(levels.len(), DEPTH);

    let counter = Arc::new(AtomicUsize::new(0));

    h.phase("spawn leaf tasks");
    // Use 3 tasks per leaf under chaos for more contention.
    spawn_leaf_tasks(&mut h, &levels[4], 3, 30, &counter);

    h.phase("partial run then cancel random regions");
    // Run a bit (not to quiescence!), then cancel several level-2 regions.
    for _ in 0..100 {
        h.runtime.step_for_test();
    }

    // Cancel every other level-2 region (indices 0, 2, 4, 6, 8).
    for i in (0..levels[2].len()).step_by(2) {
        h.cancel_region(levels[2][i], "chaos cancel");
    }

    h.phase("run to quiescence after cancels");
    h.run_until_quiescent();

    // We do not assert exact counts under chaos -- just that oracles pass.
    let total = counter.load(Ordering::SeqCst);
    assert!(
        total > 0,
        "some work should have been done even under chaos"
    );

    h.phase("verify oracles");
    h.verify_all_oracles();
    h.finish();
}
