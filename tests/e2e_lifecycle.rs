#![allow(clippy::all)]
//! T1.1 — Full runtime startup-to-shutdown lifecycle E2E test.
//!
//! Verifies: LabRuntime -> root region -> 3-level region tree -> 50 tasks ->
//! real work (yield + checkpoint loops) -> cancel root -> drain -> quiescence ->
//! oracle verify.

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

const SEED_CALM: u64 = 0xE2E1_0001;
const SEED_LIGHT: u64 = 0xE2E1_0002;
const SEED_HEAVY: u64 = 0xE2E1_0003;

/// Iterations each task performs per yield/checkpoint cycle.
const TASK_ITERATIONS: usize = 20;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the 3-level region tree, spawn ~50 tasks, return the global work counter.
///
/// Tree shape:
///   root  (4 + 4 extra = 8 tasks)
///     mid_0 .. mid_2  (5 tasks each = 15)
///       leaf_00 .. leaf_02, leaf_10 .. leaf_12, leaf_20 .. leaf_22  (3 tasks each = 27)
///
/// Total: 8 + 15 + 27 = 50 tasks.
fn build_tree_and_spawn(h: &mut E2eLabHarness) -> Arc<AtomicUsize> {
    let counter = Arc::new(AtomicUsize::new(0));

    h.phase("setup");

    // --- Root ---
    let root = h.create_root();
    h.section("spawn root tasks");
    for _ in 0..8 {
        let c = Arc::clone(&counter);
        h.spawn(root, make_work(c, TASK_ITERATIONS));
    }

    // --- Mid-level (3 children of root) ---
    h.section("spawn mid-level regions + tasks");
    let mut mid_regions = Vec::with_capacity(3);
    for _ in 0..3 {
        let mid = h.create_child(root);
        mid_regions.push(mid);
        for _ in 0..5 {
            let c = Arc::clone(&counter);
            h.spawn(mid, make_work(c, TASK_ITERATIONS));
        }
    }

    // --- Leaf-level (3 children per mid = 9 grandchildren) ---
    h.section("spawn leaf-level regions + tasks");
    for &mid in &mid_regions {
        for _ in 0..3 {
            let leaf = h.create_child(mid);
            for _ in 0..3 {
                let c = Arc::clone(&counter);
                h.spawn(leaf, make_work(c, TASK_ITERATIONS));
            }
        }
    }

    // --- Run tasks to let them do real work ---
    h.phase("run");
    let steps = h.run_until_quiescent();
    tracing::info!(steps, "initial run complete");

    // --- Cancel root, draining entire tree ---
    h.phase("cancel");
    let cancelled = h.cancel_region(root, "lifecycle test shutdown");
    tracing::info!(cancelled, "cancel_region returned");

    // --- Drain to quiescence ---
    h.phase("drain");
    let drain_steps = h.run_until_quiescent();
    tracing::info!(drain_steps, "drain complete");

    counter
}

/// Produce a future that does meaningful yield + checkpoint work.
async fn make_work(counter: Arc<AtomicUsize>, iterations: usize) {
    for _ in 0..iterations {
        let Some(cx) = Cx::current() else { return };
        if cx.checkpoint().is_err() {
            return;
        }
        counter.fetch_add(1, Ordering::SeqCst);
        yield_now().await;
    }
}

// ---------------------------------------------------------------------------
// Core lifecycle helper — shared across calm / light / heavy variants
// ---------------------------------------------------------------------------

fn run_lifecycle(mut h: E2eLabHarness) {
    let counter = build_tree_and_spawn(&mut h);

    // --- Verify ---
    h.phase("verify");

    let work_done = counter.load(Ordering::SeqCst);
    tracing::info!(work_done, "total work units completed");

    // At least some tasks must have executed real work before cancellation.
    assert_with_log!(
        work_done > 0,
        "tasks must perform work before cancel",
        "> 0",
        work_done
    );

    // Runtime must be quiescent after drain.
    assert_with_log!(
        h.is_quiescent(),
        "runtime must be quiescent after drain",
        true,
        h.is_quiescent()
    );

    // No live tasks should remain.
    let live = h.live_task_count();
    assert_with_log!(
        live == 0,
        "no live tasks after cancel + drain",
        0usize,
        live
    );

    // No pending obligations.
    let pending = h.pending_obligation_count();
    assert_with_log!(
        pending == 0,
        "no pending obligations after drain",
        0usize,
        pending
    );

    // Oracle suite must pass.
    h.finish();
}

// ---------------------------------------------------------------------------
// Test variants
// ---------------------------------------------------------------------------

#[test]
fn e2e_lifecycle_calm() {
    test_phase!("e2e_lifecycle_calm");
    let h = E2eLabHarness::new("e2e_lifecycle_calm", SEED_CALM);
    run_lifecycle(h);
    test_complete!("e2e_lifecycle_calm");
}

#[test]
fn e2e_lifecycle_light_chaos() {
    test_phase!("e2e_lifecycle_light_chaos");
    let h = E2eLabHarness::with_light_chaos("e2e_lifecycle_light_chaos", SEED_LIGHT);
    run_lifecycle(h);
    test_complete!("e2e_lifecycle_light_chaos");
}

#[test]
fn e2e_lifecycle_heavy_chaos() {
    test_phase!("e2e_lifecycle_heavy_chaos");
    let h = E2eLabHarness::with_heavy_chaos("e2e_lifecycle_heavy_chaos", SEED_HEAVY);
    run_lifecycle(h);
    test_complete!("e2e_lifecycle_heavy_chaos");
}

// ---------------------------------------------------------------------------
// Multi-seed determinism check
// ---------------------------------------------------------------------------

/// Run the calm lifecycle with multiple seeds and verify that each run
/// independently reaches quiescence with oracles passing. This does NOT
/// assert identical step counts (chaos would break that), but confirms the
/// invariant holds across seeds.
#[test]
fn e2e_lifecycle_multi_seed_determinism() {
    test_phase!("e2e_lifecycle_multi_seed_determinism");

    let seeds: [u64; 3] = [0xE2E1_D001, 0xE2E1_D002, 0xE2E1_D003];

    for (i, &seed) in seeds.iter().enumerate() {
        tracing::info!(seed, "--- seed {i}: {seed:#x} ---");

        let name = format!("e2e_lifecycle_determinism_seed_{i}");
        let mut h = E2eLabHarness::new(&name, seed);
        let counter = build_tree_and_spawn(&mut h);

        let work = counter.load(Ordering::SeqCst);
        tracing::info!(seed, work, "seed {i} completed");

        assert_with_log!(work > 0, "each seed must do work", "> 0", work);
        assert_with_log!(
            h.is_quiescent(),
            "each seed must reach quiescence",
            true,
            h.is_quiescent()
        );

        h.finish();
    }

    // Under deterministic scheduling with no chaos, identical seeds produce
    // identical runs. Different seeds may differ, but all must be non-zero.
    // Verify a same-seed replay is bit-identical.
    {
        let mut h1 = E2eLabHarness::new("determinism_replay_a", seeds[0]);
        let c1 = build_tree_and_spawn(&mut h1);
        let w1 = c1.load(Ordering::SeqCst);
        h1.verify_all_oracles();

        let mut h2 = E2eLabHarness::new("determinism_replay_b", seeds[0]);
        let c2 = build_tree_and_spawn(&mut h2);
        let w2 = c2.load(Ordering::SeqCst);
        h2.verify_all_oracles();

        assert_with_log!(
            w1 == w2,
            "same seed must produce identical work count",
            w1,
            w2
        );
    }

    test_complete!("e2e_lifecycle_multi_seed_determinism");
}
