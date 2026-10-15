//! Dedicated region-close quiescence conformance tests.
//!
//! The reusable `RuntimeInterface` does not yet expose first-class region or scope handles.
//! These tests therefore model region close with an explicit shutdown signal and treat
//! "close complete" as the point where all region-owned tasks have drained and joined.

use crate::{
    ConformanceTest, MpscReceiver, MpscSender, RuntimeInterface, TestCategory, TestMeta,
    TestResult, WatchReceiver, WatchSender, checkpoint,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Get all dedicated region-quiescence conformance tests.
pub fn all_tests<RT: RuntimeInterface>() -> Vec<ConformanceTest<RT>> {
    vec![
        rq_001_close_waits_for_live_children_and_cleanup::<RT>(),
        rq_002_close_complete_blocks_post_close_side_effects::<RT>(),
    ]
}

/// RQ-001: Region close waits for live children and cleanup before completing.
pub fn rq_001_close_waits_for_live_children_and_cleanup<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "rq-001".to_string(),
            name: "Region close waits for live children and cleanup".to_string(),
            description:
                "Region close must not complete until live children have observed shutdown and finished cleanup"
                    .to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "region".to_string(),
                "quiescence".to_string(),
                "cleanup".to_string(),
            ],
            expected: "All children and cleanup hooks finish before close completes".to_string(),
        },
        |rt| {
            rt.block_on(async {
                checkpoint(
                    "starting_region_quiescence_cleanup_test",
                    serde_json::json!({}),
                );

                let live_children = Arc::new(AtomicUsize::new(0));
                let cleanup_count = Arc::new(AtomicUsize::new(0));
                let (close_tx, close_rx) = rt.watch_channel(false);
                let (cleanup_tx, mut cleanup_rx) = rt.mpsc_channel::<usize>(3);

                let mut tasks = Vec::new();
                for task_id in 0..3usize {
                    let mut close_rx = close_rx.clone();
                    let live_children = live_children.clone();
                    let cleanup_count = cleanup_count.clone();
                    let cleanup_tx = cleanup_tx.clone();

                    tasks.push(rt.spawn(async move {
                        live_children.fetch_add(1, Ordering::SeqCst);
                        checkpoint(
                            "region_child_started",
                            serde_json::json!({ "task_id": task_id }),
                        );

                        while !close_rx.borrow_and_clone() {
                            close_rx
                                .changed()
                                .await
                                .map_err(|_| "close signal dropped before region shutdown")?;
                        }

                        // Model child cleanup/finalizer work that must complete before close returns.
                        for _ in 0..32 {
                            std::hint::spin_loop();
                        }
                        cleanup_count.fetch_add(1, Ordering::SeqCst);
                        cleanup_tx
                            .send(task_id)
                            .await
                            .map_err(|_| "cleanup receiver dropped")?;
                        live_children.fetch_sub(1, Ordering::SeqCst);

                        checkpoint(
                            "region_child_cleaned_up",
                            serde_json::json!({ "task_id": task_id }),
                        );
                        Ok::<(), &'static str>(())
                    }));
                }
                drop(cleanup_tx);

                while live_children.load(Ordering::Acquire) < 3 {
                    rt.sleep(Duration::from_millis(1)).await;
                }

                checkpoint("region_close_requested", serde_json::json!({}));
                if close_tx.send(true).is_err() {
                    return TestResult::failed("failed to broadcast region close signal");
                }

                let mut cleaned_children = Vec::new();
                while cleaned_children.len() < 3 {
                    match rt.timeout(Duration::from_millis(250), cleanup_rx.recv()).await {
                        Ok(Some(task_id)) => cleaned_children.push(task_id),
                        Ok(None) => {
                            return TestResult::failed(
                                "cleanup channel closed before all children reported cleanup",
                            );
                        }
                        Err(_) => {
                            return TestResult::failed(
                                "timed out waiting for child cleanup during region close",
                            );
                        }
                    }
                }

                for task in tasks {
                    match rt.timeout(Duration::from_millis(250), task).await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            return TestResult::failed(format!(
                                "child cleanup task failed during close: {err}"
                            ));
                        }
                        Err(_) => {
                            return TestResult::failed(
                                "region close did not wait for child task completion",
                            );
                        }
                    }
                }

                let live = live_children.load(Ordering::Acquire);
                let cleanup = cleanup_count.load(Ordering::Acquire);
                if live != 0 || cleanup != 3 {
                    return TestResult::failed(format!(
                        "expected quiescent close with 0 live children and 3 cleanups, got live={live} cleanup={cleanup}"
                    ));
                }

                checkpoint(
                    "region_close_completed_after_cleanup",
                    serde_json::json!({
                        "cleanup_reports": cleaned_children.len(),
                        "live_children": live,
                    }),
                );
                TestResult::passed()
            })
        },
    )
}

/// RQ-002: No child side effects are emitted after close completes.
pub fn rq_002_close_complete_blocks_post_close_side_effects<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "rq-002".to_string(),
            name: "No child side effects after close completes".to_string(),
            description:
                "Once region close completes, children must be drained and cannot emit new side effects"
                    .to_string(),
            category: TestCategory::Spawn,
            tags: vec![
                "region".to_string(),
                "quiescence".to_string(),
                "side-effects".to_string(),
            ],
            expected: "No child emits side effects after close completion".to_string(),
        },
        |rt| {
            rt.block_on(async {
                checkpoint(
                    "starting_post_close_side_effect_test",
                    serde_json::json!({}),
                );

                let (close_tx, mut close_rx) = rt.watch_channel(false);
                let (effect_tx, mut effect_rx) = rt.mpsc_channel::<&'static str>(2);

                let task = rt.spawn(async move {
                    effect_tx
                        .send("pre-close")
                        .await
                        .map_err(|_| "effect receiver dropped")?;

                    while !close_rx.borrow_and_clone() {
                        close_rx
                            .changed()
                            .await
                            .map_err(|_| "close signal dropped before region shutdown")?;
                    }

                    // Close-complete is defined as the join of region-owned work.
                    // If this future exits without a second send, no new side effects remain.
                    Ok::<(), &'static str>(())
                });

                match rt.timeout(Duration::from_millis(100), effect_rx.recv()).await {
                    Ok(Some("pre-close")) => {}
                    Ok(Some(other)) => {
                        return TestResult::failed(format!(
                            "unexpected pre-close side effect payload: {other}"
                        ));
                    }
                    Ok(None) => {
                        return TestResult::failed(
                            "child exited before emitting expected pre-close side effect",
                        );
                    }
                    Err(_) => {
                        return TestResult::failed(
                            "timed out waiting for pre-close child side effect",
                        );
                    }
                }

                checkpoint("region_close_requested", serde_json::json!({}));
                if close_tx.send(true).is_err() {
                    return TestResult::failed("failed to broadcast region close signal");
                }

                match rt.timeout(Duration::from_millis(250), task).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        return TestResult::failed(format!(
                            "child failed while draining during close: {err}"
                        ));
                    }
                    Err(_) => {
                        return TestResult::failed(
                            "region close did not drain child before completing",
                        );
                    }
                }

                match rt.timeout(Duration::from_millis(50), effect_rx.recv()).await {
                    Ok(None) => {
                        checkpoint(
                            "region_close_completed_without_post_close_effects",
                            serde_json::json!({}),
                        );
                        TestResult::passed()
                    }
                    Ok(Some(effect)) => TestResult::failed(format!(
                        "child emitted side effect after close completed: {effect}"
                    )),
                    Err(_) => TestResult::failed(
                        "side-effect channel stayed open after close completed",
                    ),
                }
            })
        },
    )
}
