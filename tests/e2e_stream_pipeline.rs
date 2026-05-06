#![allow(missing_docs, clippy::many_single_char_names)]

//! E2E stream processing pipeline test (T4.3).
//!
//! mpsc source → parse JSON → filter ERROR/WARN → count by level in tumbling windows
//! → collect results. 1000 events, backpressure propagation, cancel mid-pipeline.

#[macro_use]
mod common;

use asupersync::channel::mpsc;
use asupersync::cx::Cx;
use asupersync::runtime::yield_now;
use common::e2e_harness::E2eLabHarness;
use common::payloads;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// T4.3a: Stream pipeline — produce, filter, count
// ---------------------------------------------------------------------------

#[test]
fn e2e_stream_pipeline_filter_and_count() {
    let mut h = E2eLabHarness::new("e2e_stream_pipeline_filter_and_count", 0xE2E4_3001);
    let root = h.create_root();

    h.phase("setup");

    let total_events: usize = 200;
    let (tx, rx) = mpsc::channel::<String>(32);
    let produced = Arc::new(AtomicUsize::new(0));
    let consumed = Arc::new(AtomicUsize::new(0));
    let error_count = Arc::new(AtomicUsize::new(0));
    let warn_count = Arc::new(AtomicUsize::new(0));
    let info_count = Arc::new(AtomicUsize::new(0));

    // Producer: generate realistic log events
    let produced_clone = produced.clone();
    h.spawn(root, async move {
        for i in 0..total_events {
            let (level, msg) = match i % 20 {
                0 => ("ERROR", "connection refused to upstream service"),
                1 => ("WARN", "request latency exceeded 200ms threshold"),
                2 => ("WARN", "retry attempt 2/3 for database query"),
                3 => ("ERROR", "timeout waiting for response from auth-service"),
                _ => ("INFO", "request processed successfully"),
            };
            let event = payloads::json_log_event(i as u64, level, msg);
            let Some(cx) = Cx::current() else {
                break;
            };
            if tx.send(&cx, event).await.is_err() {
                break;
            }
            produced_clone.fetch_add(1, Ordering::SeqCst);
            yield_now().await;
        }
        drop(tx);
    });

    // Consumer: parse, filter, count by level
    let consumed_clone = consumed.clone();
    let error_clone = error_count.clone();
    let warn_clone = warn_count.clone();
    let info_clone = info_count.clone();
    h.spawn(root, async move {
        let mut rx = rx;
        loop {
            let Some(cx) = Cx::current() else {
                break;
            };
            let Ok(event) = rx.recv(&cx).await else {
                break;
            };
            consumed_clone.fetch_add(1, Ordering::SeqCst);

            // Parse level from JSON event
            if event.contains(r#""level":"ERROR""#) {
                error_clone.fetch_add(1, Ordering::SeqCst);
            } else if event.contains(r#""level":"WARN""#) {
                warn_clone.fetch_add(1, Ordering::SeqCst);
            } else if event.contains(r#""level":"INFO""#) {
                info_clone.fetch_add(1, Ordering::SeqCst);
            }

            yield_now().await;
        }
    });

    h.phase("execute");
    let steps = h.run_until_quiescent();
    assert_with_log!(steps > 0, "pipeline ran", "> 0", steps);

    h.phase("verify");
    let p = produced.load(Ordering::SeqCst);
    let c = consumed.load(Ordering::SeqCst);
    assert_with_log!(p == total_events, "produced all events", total_events, p);
    assert_with_log!(c == total_events, "consumed all events", total_events, c);

    // Expected: 2 ERRORs per 20 (indices 0,3), 2 WARNs per 20 (indices 1,2), 16 INFOs per 20
    let expected_errors = total_events / 10; // 2/20 = 1/10
    let expected_warns = total_events / 10;
    let expected_infos = total_events - expected_errors - expected_warns;

    let e = error_count.load(Ordering::SeqCst);
    let w = warn_count.load(Ordering::SeqCst);
    let inf = info_count.load(Ordering::SeqCst);

    assert_with_log!(e == expected_errors, "error count", expected_errors, e);
    assert_with_log!(w == expected_warns, "warn count", expected_warns, w);
    assert_with_log!(inf == expected_infos, "info count", expected_infos, inf);

    tracing::info!(
        errors = e,
        warns = w,
        infos = inf,
        total = c,
        "stream pipeline level counts verified"
    );

    h.finish();
}

// ---------------------------------------------------------------------------
// T4.3b: Pipeline with backpressure — small buffer, fast producer, slow consumer
// ---------------------------------------------------------------------------

#[test]
fn e2e_stream_pipeline_backpressure() {
    let mut h = E2eLabHarness::new("e2e_stream_pipeline_backpressure", 0xE2E4_3002);
    let root = h.create_root();

    h.phase("setup");

    let total_events: usize = 100;
    // Very small buffer to force backpressure
    let (tx, rx) = mpsc::channel::<u64>(4);
    let produced = Arc::new(AtomicUsize::new(0));
    let consumed = Arc::new(AtomicUsize::new(0));

    // Fast producer
    let produced_clone = produced.clone();
    h.spawn(root, async move {
        for i in 0..total_events {
            let Some(cx) = Cx::current() else {
                break;
            };
            if tx.send(&cx, i as u64).await.is_err() {
                break;
            }
            produced_clone.fetch_add(1, Ordering::SeqCst);
            // No yield — tries to send as fast as possible
        }
    });

    // Slow consumer — yields between each recv
    let consumed_clone = consumed.clone();
    h.spawn(root, async move {
        let mut rx = rx;
        loop {
            let Some(cx) = Cx::current() else {
                break;
            };
            let Ok(_val) = rx.recv(&cx).await else {
                break;
            };
            consumed_clone.fetch_add(1, Ordering::SeqCst);
            yield_now().await;
            yield_now().await; // Extra yield to simulate slow processing
        }
    });

    h.phase("execute");
    let steps = h.run_until_quiescent();
    assert_with_log!(steps > 0, "pipeline ran", "> 0", steps);

    h.phase("verify");
    let p = produced.load(Ordering::SeqCst);
    let c = consumed.load(Ordering::SeqCst);
    assert_with_log!(p == total_events, "produced all", total_events, p);
    assert_with_log!(c == total_events, "consumed all", total_events, c);

    h.finish();
}

// ---------------------------------------------------------------------------
// T4.3c: Cancel mid-pipeline
// ---------------------------------------------------------------------------

#[test]
fn e2e_stream_pipeline_cancel_mid_flight() {
    let mut h = E2eLabHarness::new("e2e_stream_pipeline_cancel_mid_flight", 0xE2E4_3003);
    let root = h.create_root();
    let pipeline_region = h.create_child(root);

    h.phase("setup");

    let (tx, rx) = mpsc::channel::<u64>(16);
    let produced = Arc::new(AtomicUsize::new(0));
    let consumed = Arc::new(AtomicUsize::new(0));

    // Producer: tries to send 1000 items
    let produced_clone = produced.clone();
    h.spawn(pipeline_region, async move {
        for i in 0u64..1000 {
            let Some(cx) = Cx::current() else {
                return;
            };
            if cx.checkpoint().is_err() {
                return;
            }
            if tx.send(&cx, i).await.is_err() {
                return;
            }
            produced_clone.fetch_add(1, Ordering::SeqCst);
            yield_now().await;
        }
    });

    // Consumer
    let consumed_clone = consumed.clone();
    h.spawn(pipeline_region, async move {
        let mut rx = rx;
        loop {
            let Some(cx) = Cx::current() else {
                return;
            };
            if cx.checkpoint().is_err() {
                return;
            }
            match rx.recv(&cx).await {
                Ok(_) => {
                    consumed_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(_) => return,
            }
            yield_now().await;
        }
    });

    h.phase("partial execution");
    // Run a limited number of steps to let pipeline partially execute
    for _ in 0..50 {
        h.runtime.step_for_test();
    }

    let p_before = produced.load(Ordering::SeqCst);
    let c_before = consumed.load(Ordering::SeqCst);
    tracing::info!(produced = p_before, consumed = c_before, "before cancel");

    h.phase("cancel pipeline");
    let cancelled = h.cancel_region(pipeline_region, "mid-pipeline cancel");
    tracing::info!(cancelled_tasks = cancelled, "cancelled pipeline region");

    h.phase("drain");
    h.run_until_quiescent();

    h.phase("verify");
    // After cancellation, no more items should be produced
    let p_after = produced.load(Ordering::SeqCst);
    let c_after = consumed.load(Ordering::SeqCst);
    tracing::info!(
        produced_before = p_before,
        produced_after = p_after,
        consumed_before = c_before,
        consumed_after = c_after,
        "pipeline state after cancel"
    );

    // Should not have produced all 1000
    assert_with_log!(
        p_after < 1000,
        "pipeline cancelled before completion",
        "< 1000",
        p_after
    );

    assert_with_log!(
        h.is_quiescent(),
        "quiescent after cancel",
        true,
        h.is_quiescent()
    );

    h.finish();
}
