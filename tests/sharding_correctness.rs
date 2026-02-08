#![allow(missing_docs)]

//! Sharding correctness tests (unit + lab).
//!
//! Validates invariants after the sharding refactor (bd-2ijqf):
//! - Lock ordering (implied by absence of deadlocks)
//! - No task leaks
//! - No obligation leaks
//! - Deterministic trace replay

#[macro_use]
mod common;

use asupersync::channel::mpsc;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::types::{CancelReason, Outcome};
use common::*;

fn init() {
    init_test_logging();
}

#[test]
fn sharding_region_close_quiescence() {
    init();
    let seed = 0x544152445_u64; // "SHARDS"
    let config = LabConfig::default().seed(seed).max_steps(10_000); // Sufficient for small test

    let mut runtime = LabRuntime::new(config);

    runtime.block_on(async move |cx| {
        // Spawn a region with multiple concurrent tasks
        cx.region(|scope| async move {
            for i in 0..10 {
                scope.spawn(async move |_cx| {
                    // Do some work that involves allocation/state access
                    for _ in 0..5 {
                        asupersync::runtime::yield_now().await;
                    }
                    Outcome::ok(i)
                });
            }
            Outcome::ok(())
        })
        .await
    });

    let report = runtime.report();
    assert!(report.quiescent, "Runtime must be quiescent");
    assert!(
        report.invariant_violations.is_empty(),
        "No invariant violations"
    );
}

#[test]
fn sharding_obligation_resolution() {
    init();
    let seed = 0x4F424C4947_u64; // "OBLIG"
    let config = LabConfig::default().seed(seed);
    let mut runtime = LabRuntime::new(config);

    runtime.block_on(async move |cx| {
        cx.region(|scope| async move {
            let (tx, mut rx) = mpsc::channel(10);

            // Task A: Produces with obligations
            scope.spawn(async move |cx| {
                for i in 0..5 {
                    let permit = tx.reserve(cx).await.expect("reserve failed");
                    permit.send(i);
                }
                Outcome::ok(())
            });

            // Task B: Consumes
            scope.spawn(async move |cx| {
                let mut count = 0;
                while let Some(item) = rx.recv(cx).await {
                    count += 1;
                    if count == 5 {
                        break;
                    }
                }
                Outcome::ok(count)
            });

            Outcome::ok(())
        })
        .await
    });

    let report = runtime.report();
    assert!(report.quiescent);
    assert!(report.invariant_violations.is_empty());
}

#[test]
fn sharding_cancellation_drain() {
    init();
    let seed = 0x43414E43454C_u64; // "CANCEL"
    let config = LabConfig::default().seed(seed);
    let mut runtime = LabRuntime::new(config);

    runtime.block_on(async move |cx| {
        cx.region(|scope| async move {
            let (tx, _rx) = mpsc::channel(1);

            // Task that gets cancelled while holding obligation
            let h = scope.spawn(async move |cx| {
                let permit = tx.reserve(cx).await.expect("reserve");
                // Wait forever, holding permit
                loop {
                    cx.checkpoint()?; // Should catch cancel
                    asupersync::runtime::yield_now().await;
                }
                #[allow(unreachable_code)]
                {
                    permit.send(0); // Never reached
                    Outcome::ok(())
                }
            });

            // Let it run a bit
            for _ in 0..10 {
                asupersync::runtime::yield_now().await;
            }

            // Cancel it
            h.cancel(CancelReason::user("test"));
            let res = h.await;

            assert!(matches!(res, Outcome::Cancelled(_)));

            Outcome::ok(())
        })
        .await
    });

    let report = runtime.report();
    assert!(report.quiescent);
    assert!(report.invariant_violations.is_empty());
}

#[test]
fn sharding_trace_replay_determinism() {
    init();
    let seed = 0x5245504C4159_u64; // "REPLAY"

    // Run 1
    let config1 = LabConfig::default().seed(seed).capture_trace(true);
    let mut runtime1 = LabRuntime::new(config1);

    let scenario = |cx: &mut asupersync::Cx| {
        Box::pin(async move {
            cx.region(|scope| async move {
                let (tx, mut rx) = mpsc::channel(5);
                scope.spawn(async move |cx| {
                    tx.send(cx, 1).await.ok();
                    Outcome::ok(())
                });
                scope.spawn(async move |cx| {
                    rx.recv(cx).await;
                    Outcome::ok(())
                });
                Outcome::ok(())
            })
            .await
        })
    };

    // Need to cast to the expected function pointer or closure type for block_on
    // LabRuntime::block_on takes: impl FnOnce(&mut Cx) -> Pin<Box<dyn Future<Output = Outcome<(), Error>> + Send + '_>>
    // The strict typing might require a wrapper helper if 'scenario' closure is tricky.
    // Let's rely on type inference for now.

    runtime1.block_on(scenario);
    let report1 = runtime1.report();

    // Run 2
    let config2 = LabConfig::default().seed(seed).capture_trace(true);
    let mut runtime2 = LabRuntime::new(config2);
    runtime2.block_on(scenario);
    let report2 = runtime2.report();

    assert_eq!(
        report1.trace_fingerprint, report2.trace_fingerprint,
        "Trace fingerprints must match"
    );
    assert_eq!(
        report1.steps_total, report2.steps_total,
        "Total steps must match"
    );
}
