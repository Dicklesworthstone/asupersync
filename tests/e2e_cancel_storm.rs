#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]
//! T5.1 — Cancellation storm with obligation cleanup E2E test.
//!
//! 500 tasks across 50 regions, each doing yield+checkpoint loops.
//! Cancel root -> all drain -> every task completed or cancelled -> quiescence.
//! All 6 core invariants verified via oracle suite.

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

/// Iterations each task performs per yield/checkpoint cycle.
const TASK_ITERATIONS: usize = 40;

/// Number of child regions under root.
const REGION_COUNT: usize = 50;

/// Tasks per region.
const TASKS_PER_REGION: usize = 10;

/// Total expected tasks.
const TOTAL_TASKS: usize = REGION_COUNT * TASKS_PER_REGION; // 500

/// Calm seeds: 0xE2E5_0001 .. 0xE2E5_000A
const CALM_SEEDS: [u64; 10] = [
    0xE2E5_0001,
    0xE2E5_0002,
    0xE2E5_0003,
    0xE2E5_0004,
    0xE2E5_0005,
    0xE2E5_0006,
    0xE2E5_0007,
    0xE2E5_0008,
    0xE2E5_0009,
    0xE2E5_000A,
];

/// Chaos seeds: first 5.
const CHAOS_SEEDS: [u64; 5] = [
    0xE2E5_0001,
    0xE2E5_0002,
    0xE2E5_0003,
    0xE2E5_0004,
    0xE2E5_0005,
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Produce a future that does yield + checkpoint work, incrementing the counter.
async fn make_storm_task(counter: Arc<AtomicUsize>, iterations: usize) {
    for _ in 0..iterations {
        let Some(cx) = Cx::current() else { return };
        if cx.checkpoint().is_err() {
            return;
        }
        counter.fetch_add(1, Ordering::Relaxed);
        yield_now().await;
    }
}

/// Core cancel-storm driver, used by both calm and chaos variants.
fn run_cancel_storm(seed: u64, chaos: bool) {
    let name = if chaos {
        format!("cancel_storm_chaos_{seed:#x}")
    } else {
        format!("cancel_storm_calm_{seed:#x}")
    };

    let mut h = if chaos {
        E2eLabHarness::with_light_chaos(&name, seed)
    } else {
        E2eLabHarness::new(&name, seed)
    };

    let counter = Arc::new(AtomicUsize::new(0));

    // Phase 1: Build 50 child regions under root, spawn 10 tasks each.
    h.phase("setup");
    let root = h.create_root();
    for _ in 0..REGION_COUNT {
        let child = h.create_child(root);
        for _ in 0..TASKS_PER_REGION {
            let c = Arc::clone(&counter);
            h.spawn(child, make_storm_task(c, TASK_ITERATIONS));
        }
    }

    assert_eq!(
        h.live_task_count(),
        TOTAL_TASKS,
        "expected {TOTAL_TASKS} live tasks after spawn"
    );

    // Phase 2: Let tasks run a few steps so some make partial progress.
    // Don't run to quiescence — stop after limited steps so cancel is meaningful.
    h.phase("partial_run");
    for _ in 0..200 {
        h.runtime.step_for_test();
    }
    let work_before_cancel = counter.load(Ordering::Relaxed);
    tracing::info!(work_before_cancel, "partial run complete");

    // Phase 3: Cancel root — propagates to all 50 child regions and 500 tasks.
    h.phase("cancel");
    let cancelled = h.cancel_region(root, "cancel storm");
    tracing::info!(cancelled, "cancel_region issued");

    // Phase 4: Drain to quiescence.
    h.phase("drain");
    let drain_steps = h.run_until_quiescent();
    tracing::info!(drain_steps, "drain complete");

    // Phase 5: Verify invariants.
    h.phase("verify");

    assert!(
        h.is_quiescent(),
        "[{name}] runtime must be quiescent after drain"
    );

    assert_eq!(
        h.live_task_count(),
        0,
        "[{name}] all tasks must have completed or been cancelled"
    );

    assert_eq!(
        h.pending_obligation_count(),
        0,
        "[{name}] no obligation leaks allowed"
    );

    let total_work = counter.load(Ordering::Relaxed);
    tracing::info!(
        total_work,
        work_before_cancel,
        "work counter: {total_work} iterations completed ({work_before_cancel} before cancel)"
    );

    // Some tasks should have done work before being cancelled.
    assert!(
        work_before_cancel > 0,
        "[{name}] tasks should have made progress before cancel"
    );

    // Not all tasks should have completed all iterations (cancel interrupted them).
    let max_possible = TOTAL_TASKS * TASK_ITERATIONS;
    assert!(
        total_work < max_possible,
        "[{name}] cancel storm should have interrupted some tasks \
         (got {total_work}/{max_possible})"
    );

    // Oracle verification: all 6 core invariants.
    h.finish();
}

// ---------------------------------------------------------------------------
// Test functions
// ---------------------------------------------------------------------------

#[test]
fn e2e_cancel_storm_calm() {
    for &seed in &CALM_SEEDS {
        run_cancel_storm(seed, false);
    }
}

#[test]
fn e2e_cancel_storm_chaos() {
    for &seed in &CHAOS_SEEDS {
        run_cancel_storm(seed, true);
    }
}
