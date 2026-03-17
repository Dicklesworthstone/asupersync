#![allow(missing_docs)]

//! E2E chaos resilience validation (T5.2).
//!
//! "Typical server workload" under escalating chaos levels:
//! baseline → light → heavy → extreme. Multiple seeds per level.
//! No invariant violations at any level.

#[macro_use]
mod common;

use asupersync::channel::mpsc;
use asupersync::cx::Cx;
use asupersync::lab::chaos::ChaosConfig;
use asupersync::runtime::yield_now;
use asupersync::types::RegionId;
use common::e2e_harness::E2eLabHarness;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Workload builder: simulates a realistic server workload
// ---------------------------------------------------------------------------

/// Spawn a realistic server workload: request handlers + work queue + timers.
fn spawn_server_workload(
    h: &mut E2eLabHarness,
    region: RegionId,
    request_count: usize,
    work_items: usize,
) -> (Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let requests_handled = Arc::new(AtomicUsize::new(0));
    let work_completed = Arc::new(AtomicUsize::new(0));

    let (tx, rx) = mpsc::channel::<u64>(16);

    // Request handler tasks
    for i in 0..request_count {
        let tx = tx.clone();
        let handled = requests_handled.clone();
        h.spawn(region, async move {
            let Some(cx) = Cx::current() else {
                return;
            };
            if cx.checkpoint().is_err() {
                return;
            }
            handled.fetch_add(1, Ordering::SeqCst);
            // Enqueue work item
            let _ = tx.send(&cx, i as u64).await;
            yield_now().await;
        });
    }
    drop(tx);

    // Work queue processor
    let completed = work_completed.clone();
    h.spawn(region, async move {
        let mut rx = rx;
        loop {
            let Some(cx) = Cx::current() else {
                return;
            };
            if cx.checkpoint().is_err() {
                return;
            }
            let Ok(_item) = rx.recv(&cx).await else {
                return;
            };
            completed.fetch_add(1, Ordering::SeqCst);
            yield_now().await;
        }
    });

    // Background work tasks (simulating timers, health checks)
    for _ in 0..work_items {
        let completed = work_completed.clone();
        h.spawn(region, async move {
            for _ in 0..5 {
                let Some(cx) = Cx::current() else {
                    return;
                };
                if cx.checkpoint().is_err() {
                    return;
                }
                completed.fetch_add(1, Ordering::SeqCst);
                yield_now().await;
            }
        });
    }

    (requests_handled, work_completed)
}

/// Run a workload at a specific chaos level and verify invariants.
fn run_chaos_level(
    label: &str,
    seed: u64,
    chaos: Option<ChaosConfig>,
    requests: usize,
    work_items: usize,
) {
    let name = format!("e2e_chaos_{label}_seed_{seed:#x}");
    let mut h = chaos.map_or_else(
        || E2eLabHarness::new(&name, seed),
        |c| E2eLabHarness::with_chaos(&name, seed, c),
    );

    let root = h.create_root();

    h.phase(label);
    let (handled, completed) = spawn_server_workload(&mut h, root, requests, work_items);

    h.run_until_quiescent();

    let h_count = handled.load(Ordering::SeqCst);
    let c_count = completed.load(Ordering::SeqCst);
    tracing::info!(
        label = label,
        seed = seed,
        requests_handled = h_count,
        work_completed = c_count,
        quiescent = h.is_quiescent(),
        "chaos level complete"
    );

    assert_with_log!(
        h.is_quiescent(),
        "quiescent after workload",
        true,
        h.is_quiescent()
    );

    h.finish();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn e2e_chaos_baseline() {
    for seed in [0xE2E5_2001, 0xE2E5_2002, 0xE2E5_2003] {
        run_chaos_level("baseline", seed, None, 30, 5);
    }
}

#[test]
fn e2e_chaos_light() {
    for seed in [0xE2E5_2011, 0xE2E5_2012, 0xE2E5_2013] {
        run_chaos_level("light", seed, Some(ChaosConfig::light()), 30, 5);
    }
}

#[test]
fn e2e_chaos_heavy() {
    for seed in [0xE2E5_2021, 0xE2E5_2022, 0xE2E5_2023] {
        run_chaos_level("heavy", seed, Some(ChaosConfig::heavy()), 30, 5);
    }
}

#[test]
fn e2e_chaos_extreme() {
    let extreme = ChaosConfig::new(0)
        .with_cancel_probability(0.30)
        .with_delay_probability(0.50)
        .with_io_error_probability(0.25);

    for seed in [0xE2E5_2031, 0xE2E5_2032, 0xE2E5_2033] {
        run_chaos_level("extreme", seed, Some(extreme.clone()), 20, 3);
    }
}
