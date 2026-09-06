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

// Public executing APIs: the same suspended-consumer journeys run on seeded
// Lab schedules and both native state backends. The existing stream tests above
// remain independent coverage of manually connected channels.
mod executing_scope {
    use super::{Arc, AtomicUsize, Cx, Ordering, mpsc};
    use asupersync::combinator::{MapReduceLimits, PipelineExecutionConfig};
    use asupersync::lab::{LabConfig, LabRuntime};
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::sync::{Mutex, OwnedMutexGuard};
    use asupersync::types::{Budget, CancelReason, Outcome};
    use std::future::Future;
    use std::num::NonZeroUsize;
    use std::pin::Pin;
    use std::task::Poll;
    use std::time::{Duration, Instant};

    const ITEMS: usize = 24;
    const WINDOW: usize = 3;
    type TraceSnapshot = Box<dyn Fn() -> Vec<asupersync::trace::TraceEvent> + Send + Sync>;

    fn capacity(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).expect("test capacity is nonzero")
    }

    async fn observed_gate(
        cx: &Cx,
        gate: Arc<Mutex<()>>,
        events: &mpsc::Sender<usize>,
        event: usize,
    ) {
        let mut lock = std::pin::pin!(OwnedMutexGuard::lock(gate, cx));
        let mut observed_pending = false;
        let guard = std::future::poll_fn(|poll_cx| {
            let result = lock.as_mut().poll(poll_cx);
            if result.is_pending() && !observed_pending {
                observed_pending = true;
                events.try_send(event).unwrap();
            }
            result
        })
        .await
        .unwrap();
        assert!(observed_pending, "the held guard must force a real wait");
        drop(guard);
    }

    async fn event_while_execution_pending<F: Future>(
        cx: &Cx,
        execution: &mut Pin<Box<F>>,
        events: &mut mpsc::Receiver<usize>,
    ) -> usize {
        let mut event = std::pin::pin!(events.recv(cx));
        std::future::poll_fn(|poll_cx| {
            assert!(
                execution.as_mut().poll(poll_cx).is_pending(),
                "owned work is still gated; returning success here abandons it"
            );
            event.as_mut().poll(poll_cx)
        })
        .await
        .expect("a real worker/input boundary publishes the next observation")
    }

    async fn ordered_map(cx: Cx, snapshot: TraceSnapshot) -> serde_json::Value {
        let gate = Arc::new(Mutex::new(()));
        let held = gate.try_lock_owned().unwrap();
        let pulled = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let identities = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (events, mut observations) = mpsc::channel(WINDOW);
        let input_pulled = Arc::clone(&pulled);
        let child_gate = Arc::clone(&gate);
        let child_active = Arc::clone(&active);
        let child_peak = Arc::clone(&peak);
        let child_identities = Arc::clone(&identities);
        let scope = cx.scope();
        let mut execution = Box::pin(scope.map_reduce(
            &cx,
            MapReduceLimits::new(capacity(2), capacity(WINDOW)),
            (0..ITEMS).inspect(move |_| {
                input_pulled.fetch_add(1, Ordering::SeqCst);
            }),
            move |child, index| {
                let gate = Arc::clone(&child_gate);
                let active = Arc::clone(&child_active);
                let peak = Arc::clone(&child_peak);
                let identities = Arc::clone(&child_identities);
                let events = events.clone();
                async move {
                    let running = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(running, Ordering::SeqCst);
                    identities.lock().unwrap().push((index, child.task_id()));
                    if index == 0 {
                        observed_gate(&child, gate, &events, index).await;
                    }
                    let value = format!("{}={}", index, index * index + 7);
                    active.fetch_sub(1, Ordering::SeqCst);
                    if (1..WINDOW).contains(&index) {
                        events.try_send(index).unwrap();
                    }
                    Outcome::<_, &'static str>::Ok(value)
                }
            },
            |left, right| format!("({left}>{right})"),
        ));
        let mut observed = Vec::new();
        for _ in 0..WINDOW {
            observed
                .push(event_while_execution_pending(&cx, &mut execution, &mut observations).await);
        }
        observed.sort_unstable();
        assert_eq!(observed, (0..WINDOW).collect::<Vec<_>>());
        let later_ids = identities
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(index, id)| (*index != 0).then_some(*id))
            .collect::<Vec<_>>();
        assert_eq!(later_ids.len(), WINDOW - 1);
        let started = Instant::now();
        loop {
            let all_completed = std::future::poll_fn(|poll_cx| {
                assert!(execution.as_mut().poll(poll_cx).is_pending());
                let trace = snapshot();
                Poll::Ready(later_ids.iter().all(|id| {
                    trace.iter().filter(|event| {
                        event.kind == asupersync::trace::TraceEventKind::Complete
                            && matches!(event.data, asupersync::trace::TraceData::Task { task, region }
                                if task == *id && region == cx.region_id())
                    }).count() == 1
                }))
            }).await;
            if all_completed {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "later maps did not actually terminate"
            );
            asupersync::runtime::yield_now().await;
        }
        assert_eq!(gate.waiters(), 1, "the first map really crossed Pending");
        assert_eq!(active.load(Ordering::SeqCst), 1);
        assert_eq!(pulled.load(Ordering::SeqCst), WINDOW);
        assert!(peak.load(Ordering::SeqCst) <= 2);
        // The two later tasks actually completed, but they cannot admit a fourth
        // input while the first result still occupies the ordered window.
        drop(held);
        let report = execution.await;
        let expected = (0..ITEMS)
            .map(|index| format!("{}={}", index, index * index + 7))
            .reduce(|left, right| format!("({left}>{right})"));
        assert_eq!(report.outcome.unwrap(), expected);
        assert_eq!(
            (report.admitted, report.completed, report.reduced),
            (ITEMS, ITEMS, ITEMS)
        );
        assert_eq!(report.max_retained, WINDOW);
        assert_eq!(report.max_in_flight, 2);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(gate.waiters(), 0);
        let mut identities = identities.lock().unwrap();
        identities.sort_unstable_by_key(|(index, _)| *index);
        assert_eq!(identities.len(), ITEMS);
        for (expected, (index, _)) in identities.iter().enumerate() {
            assert_eq!(*index, expected);
        }
        serde_json::json!({
            "scenario": "public_ordered_map_held_prefix",
            "coordinator": format!("{:?}", cx.task_id()),
            "region": format!("{:?}", cx.region_id()),
            "child_ids": identities.iter().map(|(index, id)|
                serde_json::json!({"input":index,"task":format!("{id:?}")})).collect::<Vec<_>>(),
            "admitted": report.admitted, "joined": report.completed, "reduced": report.reduced,
            "max_active": peak.load(Ordering::SeqCst), "max_retained": report.max_retained,
            "held_prefix_pulled": WINDOW, "held_prefix_later_tasks_completed": later_ids.len(),
            "noncommutative_order_matches": true
        })
    }

    fn verify_delivery(observed: &[Vec<u8>], expected: &[Vec<u8>]) -> Result<(), &'static str> {
        if observed == expected {
            Ok(())
        } else {
            Err("delivery_mismatch")
        }
    }

    async fn streaming_pipeline(cx: Cx, drop_output: bool) -> serde_json::Value {
        let gate = Arc::new(Mutex::new(()));
        let held = gate.try_lock_owned().unwrap();
        let pulled = Arc::new(AtomicUsize::new(0));
        let published = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (events, mut observations) = mpsc::channel(WINDOW + 1);
        let input_events = events.clone();
        let input_pulled = Arc::clone(&pulled);
        let sink_gate = Arc::clone(&gate);
        let sink_published = Arc::clone(&published);
        let mut sink_index = 0;
        let mut execution = Box::pin(
            cx.scope()
                .pipeline(
                    &cx,
                    PipelineExecutionConfig::new(capacity(1), capacity(WINDOW)),
                    (0..ITEMS).inspect(move |index| {
                        input_pulled.fetch_add(1, Ordering::SeqCst);
                        if *index < WINDOW {
                            input_events.try_send(*index).unwrap();
                        }
                    }),
                )
                .then(capacity(1), |_child, value| async move {
                    Outcome::<_, &'static str>::Ok(format!("{value}:{}", value * value + 11))
                })
                .then(capacity(1), |_child, value: String| async move {
                    Outcome::Ok(value.into_bytes())
                })
                .run(move |child, value| {
                    let index = sink_index;
                    sink_index += 1;
                    let gate = Arc::clone(&sink_gate);
                    let published = Arc::clone(&sink_published);
                    let events = events.clone();
                    async move {
                        if index == 0 {
                            observed_gate(&child, gate, &events, WINDOW).await;
                        }
                        // Causal negative: a genuinely invoked sink falsely acknowledges
                        // one output without publishing it. The independent delivery
                        // checker must refuse even though all pipeline counters balance.
                        if !(drop_output && index == 7) {
                            published.lock().unwrap().push(value);
                        }
                        asupersync::runtime::yield_now().await;
                        Outcome::Ok(())
                    }
                }),
        );
        let mut observed = Vec::new();
        for _ in 0..=WINDOW {
            observed
                .push(event_while_execution_pending(&cx, &mut execution, &mut observations).await);
        }
        observed.sort_unstable();
        assert_eq!(observed, (0..=WINDOW).collect::<Vec<_>>());
        assert_eq!(gate.waiters(), 1, "the actual async sink is suspended");
        assert_eq!(pulled.load(Ordering::SeqCst), WINDOW);
        assert!(published.lock().unwrap().is_empty());
        drop(held);
        let report = execution.await;
        assert!(report.outcome.is_ok(), "{report:?}");
        assert_eq!(report.summary.admitted, ITEMS);
        assert_eq!(report.summary.consumed, ITEMS);
        assert_eq!(report.summary.max_in_flight, WINDOW);
        assert_eq!(report.summary.stages, 2);
        assert_eq!(pulled.load(Ordering::SeqCst), ITEMS);
        assert_eq!(gate.waiters(), 0);
        let expected = (0..ITEMS)
            .map(|index| format!("{index}:{}", index * index + 11).into_bytes())
            .collect::<Vec<_>>();
        let published = published.lock().unwrap();
        let verdict = verify_delivery(&published, &expected);
        assert_eq!(
            verdict,
            if drop_output {
                Err("delivery_mismatch")
            } else {
                Ok(())
            }
        );
        assert_eq!(published.len(), ITEMS - usize::from(drop_output));
        serde_json::json!({
            "scenario": if drop_output {"public_pipeline_dropped_output_control"}
                else {"public_pipeline_suspended_sink"},
            "coordinator": format!("{:?}", cx.task_id()),
            "region": format!("{:?}", cx.region_id()),
            "stages": report.summary.stages, "edge_capacity": 1,
            "held_sink_pulled": WINDOW, "held_sink_published": 0,
            "admitted": report.summary.admitted, "acknowledged": report.summary.consumed,
            "max_in_flight": report.summary.max_in_flight,
            "expected_outputs": ITEMS, "observed_outputs": published.len(),
            "delivery_refusal": verdict.err()
        })
    }

    async fn journeys(cx: Cx, snapshot: TraceSnapshot) -> Vec<serde_json::Value> {
        vec![
            ordered_map(cx.clone(), snapshot).await,
            streaming_pipeline(cx.clone(), false).await,
            streaming_pipeline(cx, true).await,
        ]
    }

    #[test]
    fn public_executing_combinators_seeded_lab_delivery_and_backpressure() {
        for seed in [0x3301, 0x3302, 0x3303] {
            let mut lab = LabRuntime::new(
                LabConfig::new(seed)
                    .max_steps(100_000)
                    .trace_capacity(100_000),
            );
            let root = lab.state.create_root_region(Budget::INFINITE);
            let trace = lab.state.trace_handle();
            // Keep the complete journey Send-checked without recursively
            // expanding it through the Lab task-storage wrappers as well.
            let coordinator: Pin<Box<dyn Future<Output = Vec<serde_json::Value>> + Send>> =
                Box::pin(async move {
                    journeys(
                        Cx::current().expect("actual Lab coordinator"),
                        Box::new(move || trace.snapshot()),
                    )
                    .await
                });
            let (parent, mut joined) = lab
                .state
                .create_task(root, Budget::INFINITE, coordinator)
                .unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            lab.run_until_idle();
            let reports = joined
                .try_join()
                .unwrap()
                .expect("all public journeys terminated");
            assert_eq!(reports.len(), 3);
            assert_eq!(lab.state.live_task_count(), 0);
            assert_eq!(lab.state.pending_obligation_count(), 0);
            assert_eq!(lab.state.leak_count(), 0);
            let report = lab.run_until_quiescent_with_report();
            assert!(report.lab_test_passed(), "{report:?}");
            let effects =
                lab.state
                    .cancel_request(root, &CancelReason::user("journeys complete"), None);
            let (tasks, wakes) = effects.into_parts();
            assert!(tasks.is_empty());
            wakes.dispatch();
            lab.state.advance_region_state(root);
            assert!(lab.state.region(root).is_none());
            assert!(lab.run_until_quiescent_with_report().lab_test_passed());
            eprintln!(
                "ASUPERSYNC_EXECUTING_COMBINATORS {}",
                serde_json::json!({
                    "backend":"lab", "seed":seed, "journeys":reports,
                    "live_tasks":0,"pending_obligations":0,"leaks":0,"original_region_closed":true
                })
            );
        }
    }

    #[test]
    fn public_executing_combinators_native_delivery_and_backpressure() {
        for sharded in [false, true] {
            let (finished, completion) = std::sync::mpsc::sync_channel(1);
            let worker = std::thread::spawn(move || {
                let result = std::panic::catch_unwind(|| run_native_journeys(sharded));
                let _ = finished.send(result);
            });
            let result = completion.recv_timeout(Duration::from_secs(45))
                .expect("native journey exceeded its whole-run bound; this is a failure, not cleanup evidence");
            worker.join().expect("owned test supervisor terminated");
            if let Err(payload) = result {
                std::panic::resume_unwind(payload);
            }
        }
    }

    fn run_native_journeys(sharded: bool) {
        let runtime = if sharded {
            RuntimeBuilder::multi_thread()
                .worker_threads(2)
                .with_sharded_state(true)
        } else {
            RuntimeBuilder::current_thread()
        }
        .build()
        .unwrap();
        assert_eq!(runtime.config().worker_threads, if sharded { 2 } else { 1 });
        assert_eq!(
            runtime.config().runtime_state_shape,
            if sharded {
                asupersync::runtime::config::RuntimeStateShape::Sharded
            } else {
                asupersync::runtime::config::RuntimeStateShape::Unified
            }
        );
        let trace_runtime = runtime.handle();
        // Check Send here before embedding the complete journey future in the
        // runtime's completion and panic-isolation wrappers.
        let parent: Pin<Box<dyn Future<Output = Vec<serde_json::Value>> + Send>> =
            Box::pin(async move {
                journeys(
                    Cx::current().expect("actual native coordinator"),
                    Box::new(move || {
                        trace_runtime
                            .trace_snapshot()
                            .expect("owned runtime remains live")
                    }),
                )
                .await
            });
        let reports = runtime.block_on(runtime.handle().spawn(parent));
        assert_eq!(reports.len(), 3);
        runtime.block_on(async {
            let started = Instant::now();
            while !runtime.is_quiescent() {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "owned work did not drain"
                );
                asupersync::runtime::yield_now().await;
            }
        });
        assert!(
            runtime
                .task_inspector(Default::default())
                .list_tasks()
                .is_empty()
        );
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
        eprintln!(
            "ASUPERSYNC_EXECUTING_COMBINATORS {}",
            serde_json::json!({
                "backend": if sharded {"native_two_worker_sharded"} else {"native_current_thread"},
                "journeys":reports,"live_tasks":0,"leaks":0,"shutdown_completed":true
            })
        );
    }

    // These are user callback gates, not simulated runtime tasks. The initial
    // wait uses the public cancel-aware mutex; cleanup deliberately needs a
    // separate external wake after that wait acknowledges cancellation.
    #[derive(Default)]
    struct CleanupGate {
        state: std::sync::Mutex<(bool, Option<std::task::Waker>)>,
    }

    impl CleanupGate {
        fn release(&self) {
            let wake = {
                let mut state = self.state.lock().unwrap();
                assert!(!state.0, "each cleanup release is issued exactly once");
                state.0 = true;
                state.1.take()
            };
            if let Some(wake) = wake {
                wake.wake();
            }
        }

        async fn wait(&self, stage: usize, controls: &FailureControls) {
            let mut entered = false;
            std::future::poll_fn(|poll_cx| {
                let mut state = self.state.lock().unwrap();
                if state.0 {
                    assert!(entered, "cleanup must actually cross Pending");
                    return Poll::Ready(());
                }
                state.1 = Some(poll_cx.waker().clone());
                if !entered {
                    entered = true;
                    assert_eq!(
                        controls.cleanup_pending[stage].fetch_add(1, Ordering::SeqCst),
                        0
                    );
                    controls.events.try_send(3 + stage).unwrap();
                }
                Poll::Pending
            })
            .await;
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FailureKind {
        Error,
        Panic,
        EncodedPanic,
        Cancelled,
        CallerCancellation,
    }

    impl FailureKind {
        fn label(self) -> &'static str {
            match self {
                Self::Error => "typed_error",
                Self::Panic => "actual_future_panic",
                Self::EncodedPanic => "encoded_panicked_outcome",
                Self::Cancelled => "cancelled_outcome",
                Self::CallerCancellation => "explicit_caller_cancellation",
            }
        }
    }

    type WorkerIdentity = (asupersync::types::TaskId, asupersync::types::RegionId);

    struct FailureControls {
        target: Option<usize>,
        failure: FailureKind,
        work: [Arc<Mutex<()>>; 3],
        cleanup: [CleanupGate; 3],
        calls: [AtomicUsize; 3],
        cancelled: [AtomicUsize; 3],
        cleanup_pending: [AtomicUsize; 3],
        cleaned: [AtomicUsize; 3],
        exited: [AtomicUsize; 3],
        identities: std::sync::Mutex<[Option<WorkerIdentity>; 3]>,
        output: std::sync::Mutex<Vec<usize>>,
        events: mpsc::Sender<usize>,
    }

    struct CallbackExit<'a> {
        stage: usize,
        controls: &'a FailureControls,
    }

    impl Drop for CallbackExit<'_> {
        fn drop(&mut self) {
            assert_eq!(
                self.controls.exited[self.stage].fetch_add(1, Ordering::SeqCst),
                0,
                "the selected callback must be destroyed exactly once"
            );
        }
    }

    async fn controlled_callback(
        child: Cx,
        controls: Arc<FailureControls>,
        stage: usize,
        input: usize,
    ) -> Outcome<usize, &'static str> {
        assert_eq!(controls.calls[stage].fetch_add(1, Ordering::SeqCst), input);
        if input != 3 - stage {
            return Outcome::Ok(input);
        }
        let _exit = CallbackExit {
            stage,
            controls: &controls,
        };
        assert!(
            controls.identities.lock().unwrap()[stage]
                .replace((child.task_id(), child.region_id()))
                .is_none()
        );
        let mut lock = std::pin::pin!(OwnedMutexGuard::lock(
            Arc::clone(&controls.work[stage]),
            &child
        ));
        let mut entered = false;
        let result = std::future::poll_fn(|poll_cx| {
            let result = lock.as_mut().poll(poll_cx);
            if result.is_pending() && !entered {
                entered = true;
                controls.events.try_send(stage).unwrap();
            }
            result
        })
        .await;
        assert!(entered, "the actual callback must register a pending wait");
        match result {
            Ok(guard) => {
                drop(guard);
                assert_eq!(controls.target, Some(stage));
                match controls.failure {
                    FailureKind::Error => Outcome::Err("public pipeline stage failure"),
                    FailureKind::Panic => panic!("public pipeline actual callback panic"),
                    FailureKind::EncodedPanic => Outcome::Panicked(
                        asupersync::types::PanicPayload::new("public pipeline encoded panic"),
                    ),
                    FailureKind::Cancelled => {
                        Outcome::Cancelled(CancelReason::user("public pipeline stage cancellation"))
                    }
                    FailureKind::CallerCancellation => {
                        panic!("caller cancellation cannot unlock a held work gate")
                    }
                }
            }
            Err(error) => {
                assert_eq!(error, asupersync::sync::LockError::Cancelled);
                assert_ne!(controls.target, Some(stage));
                assert!(child.checkpoint().is_err());
                assert_eq!(controls.cancelled[stage].fetch_add(1, Ordering::SeqCst), 0);
                controls.cleanup[stage].wait(stage, &controls).await;
                assert_eq!(controls.cleaned[stage].fetch_add(1, Ordering::SeqCst), 0);
                controls.events.try_send(6 + stage).unwrap();
                Outcome::Cancelled(
                    child
                        .cancel_reason()
                        .expect("actual attributed cancellation"),
                )
            }
        }
    }

    fn worker_event_count(
        trace: &[asupersync::trace::TraceEvent],
        identity: WorkerIdentity,
        kind: asupersync::trace::TraceEventKind,
    ) -> usize {
        trace
            .iter()
            .filter(|event| {
                event.kind == kind
                    && matches!(event.data, asupersync::trace::TraceData::Task { task, region }
                        if (task, region) == identity)
            })
            .count()
    }

    // The planted terminal claim is checked against the SAME live callback
    // state and actual runtime trace as the later legitimate terminal report.
    // It is a refused observation, never substituted for an engine return.
    fn verify_cleanup_claim(
        controls: &FailureControls,
        trace: &[asupersync::trace::TraceEvent],
        claimed_terminal: bool,
    ) -> Result<(), &'static str> {
        use asupersync::trace::TraceEventKind;
        let identities = *controls.identities.lock().unwrap();
        for (stage, identity) in identities.into_iter().enumerate() {
            let identity = identity.ok_or("missing_owned_worker")?;
            if worker_event_count(trace, identity, TraceEventKind::Spawn) != 1 {
                return Err("missing_owned_spawn");
            }
            let complete = worker_event_count(trace, identity, TraceEventKind::Complete);
            if complete > 1 {
                return Err("duplicate_owned_terminal");
            }
            let cleanup_required = usize::from(controls.target != Some(stage));
            if claimed_terminal
                && (complete != 1
                    || controls.exited[stage].load(Ordering::SeqCst) != 1
                    || controls.cleaned[stage].load(Ordering::SeqCst) != cleanup_required)
            {
                return Err("owned_cleanup_pending");
            }
        }
        Ok(())
    }

    async fn await_actual_completions(snapshot: &TraceSnapshot, identities: &[WorkerIdentity]) {
        let started = Instant::now();
        loop {
            let trace = snapshot();
            if identities.iter().all(|identity| {
                worker_event_count(
                    &trace,
                    *identity,
                    asupersync::trace::TraceEventKind::Complete,
                ) == 1
            }) {
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "actual task terminals missing"
            );
            asupersync::runtime::yield_now().await;
        }
    }

    async fn pipeline_failure_journey(
        cx: &Cx,
        snapshot: &TraceSnapshot,
        failure: FailureKind,
        target: Option<usize>,
    ) -> serde_json::Value {
        let (events, mut observations) = mpsc::channel(16);
        let controls = Arc::new(FailureControls {
            target,
            failure,
            work: std::array::from_fn(|_| Arc::new(Mutex::new(()))),
            cleanup: std::array::from_fn(|_| CleanupGate::default()),
            calls: std::array::from_fn(|_| AtomicUsize::new(0)),
            cancelled: std::array::from_fn(|_| AtomicUsize::new(0)),
            cleanup_pending: std::array::from_fn(|_| AtomicUsize::new(0)),
            cleaned: std::array::from_fn(|_| AtomicUsize::new(0)),
            exited: std::array::from_fn(|_| AtomicUsize::new(0)),
            identities: std::sync::Mutex::new([None; 3]),
            output: std::sync::Mutex::new(Vec::new()),
            events,
        });
        let mut held: [Option<OwnedMutexGuard<()>>; 3] =
            std::array::from_fn(|stage| Some(controls.work[stage].try_lock_owned().unwrap()));
        let returned = Arc::new(std::sync::Mutex::new(None));
        let owner_returned = Arc::clone(&returned);
        let owner_controls = Arc::clone(&controls);
        let mut owner = cx
            .spawn(move |owner_cx| async move {
                let first = Arc::clone(&owner_controls);
                let second = Arc::clone(&owner_controls);
                let sink = Arc::clone(&owner_controls);
                let report = owner_cx
                    .scope()
                    .pipeline::<_, &'static str>(
                        &owner_cx,
                        PipelineExecutionConfig::new(capacity(1), capacity(4)),
                        0..4,
                    )
                    .then(capacity(1), move |child, input| {
                        controlled_callback(child, Arc::clone(&first), 0, input)
                    })
                    .then(capacity(1), move |child, input| {
                        controlled_callback(child, Arc::clone(&second), 1, input)
                    })
                    .run(move |child, input| {
                        let sink = Arc::clone(&sink);
                        async move {
                            controlled_callback(child, Arc::clone(&sink), 2, input)
                                .await
                                .map(|value| sink.output.lock().unwrap().push(value))
                        }
                    })
                    .await;
                if owner_controls.target.is_none() {
                    assert!(owner_cx.checkpoint().is_err());
                    assert_eq!(
                        owner_cx.cancel_reason().unwrap().message.as_deref(),
                        Some("public pipeline caller cancellation")
                    );
                }
                assert!(owner_returned.lock().unwrap().replace(report).is_none());
            })
            .unwrap();

        let mut entered = Vec::new();
        for _ in 0..3 {
            entered.push(observations.recv(cx).await.unwrap());
        }
        entered.sort_unstable();
        assert_eq!(entered, vec![0, 1, 2]);
        assert_eq!(*controls.output.lock().unwrap(), vec![0]);
        assert_eq!(
            std::array::from_fn::<_, 3, _>(|stage| controls.calls[stage].load(Ordering::SeqCst)),
            [4, 3, 2]
        );
        assert!(returned.lock().unwrap().is_none());
        assert!(!owner.is_finished());
        for gate in &controls.work {
            assert_eq!(gate.waiters(), 1);
        }
        let identities = (*controls.identities.lock().unwrap()).map(Option::unwrap);
        let owner_identity = (owner.task_id(), cx.region_id());
        assert_eq!(
            identities
                .iter()
                .map(|identity| identity.0)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
        assert!(
            identities
                .iter()
                .all(|identity| identity.1 == cx.region_id() && identity.0 != owner_identity.0)
        );

        if let Some(stage) = target {
            drop(held[stage].take().unwrap());
        } else {
            assert_eq!(failure, FailureKind::CallerCancellation);
            owner.abort_with_reason(CancelReason::user("public pipeline caller cancellation"));
        }
        let losers = (0..3)
            .filter(|stage| Some(*stage) != target)
            .collect::<Vec<_>>();
        let mut pending = Vec::new();
        for _ in &losers {
            pending.push(observations.recv(cx).await.unwrap());
        }
        pending.sort_unstable();
        assert_eq!(
            pending,
            losers.iter().map(|stage| stage + 3).collect::<Vec<_>>()
        );
        let trace = snapshot();
        assert_eq!(verify_cleanup_claim(&controls, &trace, false), Ok(()));
        assert_eq!(
            verify_cleanup_claim(&controls, &trace, true),
            Err("owned_cleanup_pending")
        );
        assert!(returned.lock().unwrap().is_none());
        assert!(!owner.is_finished());
        for &stage in &losers {
            assert_eq!(
                controls.work[stage].waiters(),
                0,
                "cancellation unlinks the real mutex waiter"
            );
            assert_eq!(controls.cancelled[stage].load(Ordering::SeqCst), 1);
            assert_eq!(controls.cleanup_pending[stage].load(Ordering::SeqCst), 1);
            assert_eq!(controls.cleaned[stage].load(Ordering::SeqCst), 0);
            assert_eq!(
                worker_event_count(
                    &trace,
                    identities[stage],
                    asupersync::trace::TraceEventKind::Complete
                ),
                0
            );
        }

        // Keep one real child noncooperative after cancellation while its two
        // siblings actually finish. The operation must retain this ownership;
        // the bounded observation below is not a termination guarantee.
        if target.is_none() {
            for stage in 0..2 {
                controls.cleanup[stage].release();
            }
            let mut cleaned = vec![
                observations.recv(cx).await.unwrap(),
                observations.recv(cx).await.unwrap(),
            ];
            cleaned.sort_unstable();
            assert_eq!(cleaned, vec![6, 7]);
            await_actual_completions(snapshot, &identities[..2]).await;
            for _ in 0..8 {
                asupersync::runtime::yield_now().await;
            }
            let trace = snapshot();
            assert_eq!(controls.cleaned[2].load(Ordering::SeqCst), 0);
            assert_eq!(
                worker_event_count(
                    &trace,
                    identities[2],
                    asupersync::trace::TraceEventKind::Complete
                ),
                0
            );
            assert_eq!(
                worker_event_count(
                    &trace,
                    owner_identity,
                    asupersync::trace::TraceEventKind::Complete
                ),
                0
            );
            assert_eq!(verify_cleanup_claim(&controls, &trace, false), Ok(()));
            assert_eq!(
                verify_cleanup_claim(&controls, &trace, true),
                Err("owned_cleanup_pending")
            );
            assert!(returned.lock().unwrap().is_none());
            assert!(!owner.is_finished());
            controls.cleanup[2].release();
            assert_eq!(observations.recv(cx).await.unwrap(), 8);
        } else {
            for &stage in &losers {
                controls.cleanup[stage].release();
            }
            let mut cleaned = Vec::new();
            for _ in &losers {
                cleaned.push(observations.recv(cx).await.unwrap());
            }
            cleaned.sort_unstable();
            assert_eq!(
                cleaned,
                losers.iter().map(|stage| stage + 6).collect::<Vec<_>>()
            );
        }
        let owner_result = owner.join(cx).await;
        // Public Cx::spawn preserves the returned value after the user's
        // explicit attributed cancellation acknowledgement above.
        assert!(
            owner_result.is_ok(),
            "actual acknowledged owner completion: {owner_result:?}"
        );
        let report = returned
            .lock()
            .unwrap()
            .take()
            .expect("engine returned its actual report after drain");
        await_actual_completions(snapshot, &identities).await;
        await_actual_completions(snapshot, &[owner_identity]).await;
        let trace = snapshot();
        assert_eq!(verify_cleanup_claim(&controls, &trace, true), Ok(()));
        assert_eq!(report.summary.admitted, 4);
        assert_eq!(report.summary.consumed, 1);
        assert_eq!(report.summary.stages, 2);
        assert!(report.summary.max_in_flight <= 4);
        assert_eq!(*controls.output.lock().unwrap(), vec![0]);
        assert_eq!(
            std::array::from_fn::<_, 3, _>(|stage| controls.calls[stage].load(Ordering::SeqCst)),
            [4, 3, 2]
        );
        for stage in 0..3 {
            let expected = usize::from(target != Some(stage));
            assert_eq!(controls.cancelled[stage].load(Ordering::SeqCst), expected);
            assert_eq!(
                controls.cleanup_pending[stage].load(Ordering::SeqCst),
                expected
            );
            assert_eq!(controls.cleaned[stage].load(Ordering::SeqCst), expected);
            assert_eq!(controls.exited[stage].load(Ordering::SeqCst), 1);
            assert_eq!(controls.work[stage].waiters(), 0);
        }
        match failure {
            FailureKind::Error => {
                let Outcome::Cancelled(reason) = &report.outcome else {
                    panic!("actual loser cancellation is stronger than Err: {report:?}");
                };
                assert_eq!(reason.kind, asupersync::types::CancelKind::FailFast);
                assert_eq!(reason.message, None);
                assert_eq!(reason.cause, None);
                assert!(
                    matches!(report.error(), Some(asupersync::combinator::PipelineExecutionError::Stage {
                    stage, input, error: "public pipeline stage failure"
                }) if Some(*stage) == target && *input == 3 - *stage)
                );
            }
            FailureKind::Panic | FailureKind::EncodedPanic => {
                let Outcome::Panicked(payload) = &report.outcome else {
                    panic!("panic severity must survive drained cancellation: {report:?}");
                };
                assert_eq!(
                    payload.message(),
                    if failure == FailureKind::Panic {
                        "public pipeline actual callback panic"
                    } else {
                        "public pipeline encoded panic"
                    }
                );
                assert!(report.error().is_none());
            }
            FailureKind::Cancelled => {
                let Outcome::Cancelled(reason) = &report.outcome else {
                    panic!("stage cancellation must remain a cancellation: {report:?}");
                };
                // The initiating callback returns User. Actual losing workers
                // receive the engine's sibling_failed() reason; strengthen()
                // must preserve that stronger FailFast, including its empty
                // cause/message, rather than retain the initial User label.
                assert_eq!(reason.kind, asupersync::types::CancelKind::FailFast);
                assert_eq!(reason.message, None);
                assert_eq!(reason.cause, None);
                assert!(report.error().is_none());
            }
            FailureKind::CallerCancellation => {
                let Outcome::Cancelled(reason) = &report.outcome else {
                    panic!("caller cancellation must remain attributed: {report:?}");
                };
                assert_eq!(reason.kind, asupersync::types::CancelKind::User);
                assert_eq!(
                    reason.message.as_deref(),
                    Some("public pipeline caller cancellation")
                );
                assert_eq!(reason.cause, None);
                assert!(report.error().is_none());
            }
        }
        let (terminal_outcome, terminal_cancel_reason, terminal_panic_message) = match &report
            .outcome
        {
            Outcome::Cancelled(reason) => ("cancelled", Some(reason), None),
            Outcome::Panicked(payload) => ("panicked", None, Some(payload.message())),
            unexpected => panic!("failure control produced an unexpected terminal: {unexpected:?}"),
        };
        let terminal_typed_trigger = report.error().map(|error| {
            let asupersync::combinator::PipelineExecutionError::Stage {
                stage,
                input,
                error,
            } = error
            else {
                panic!("unexpected typed terminal trigger: {error:?}");
            };
            serde_json::json!({"stage":stage,"input":input,"error":error})
        });
        // Join every actual coordinator Lease ID against its real terminal,
        // including the optional EOF probe. The delivered prefix commits once;
        // each unresolved suffix/probe aborts once, with no leaked/double ID.
        use asupersync::trace::{TraceData, TraceEventKind};
        let leases = trace
            .iter()
            .filter_map(|event| {
                if event.kind != TraceEventKind::ObligationReserve {
                    return None;
                }
                match event.data {
                    TraceData::Obligation {
                        obligation,
                        task,
                        region,
                        kind: asupersync::record::ObligationKind::Lease,
                        ..
                    } if (task, region) == owner_identity => Some(obligation),
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        assert!(
            (4..=5).contains(&leases.len()),
            "four actual items plus at most one EOF probe"
        );
        assert_eq!(
            leases
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            leases.len()
        );
        for (index, id) in leases.iter().enumerate() {
            let terminals = trace
                .iter()
                .filter_map(|event| {
                    if !matches!(
                        event.kind,
                        TraceEventKind::ObligationCommit
                            | TraceEventKind::ObligationAbort
                            | TraceEventKind::ObligationLeak
                    ) {
                        return None;
                    }
                    match event.data {
                        TraceData::Obligation {
                            obligation,
                            task,
                            region,
                            ..
                        } if obligation == *id => {
                            assert_eq!((task, region), owner_identity);
                            Some(event.kind)
                        }
                        _ => None,
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(
                terminals,
                vec![if index == 0 {
                    TraceEventKind::ObligationCommit
                } else {
                    TraceEventKind::ObligationAbort
                }]
            );
        }
        let owned_credits = trace
            .iter()
            .filter_map(|event| match event.data {
                TraceData::Obligation {
                    obligation,
                    task,
                    region,
                    kind,
                    ..
                } if event.kind == TraceEventKind::ObligationReserve
                    && ((task, region) == owner_identity
                        || identities.contains(&(task, region))) =>
                {
                    Some((obligation, task, region, kind))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            owned_credits.len() > leases.len(),
            "the real checked channel edges also admitted credits"
        );
        assert_eq!(
            owned_credits
                .iter()
                .map(|credit| credit.0)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            owned_credits.len()
        );
        for &(id, holder, owner_region, kind) in &owned_credits {
            let terminals = trace
                .iter()
                .filter(|event| {
                    if !matches!(
                        event.kind,
                        TraceEventKind::ObligationCommit
                            | TraceEventKind::ObligationAbort
                            | TraceEventKind::ObligationLeak
                    ) {
                        return false;
                    }
                    match event.data {
                        TraceData::Obligation {
                            obligation,
                            task,
                            region,
                            kind: terminal_kind,
                            ..
                        } if obligation == id => {
                            assert_eq!((task, region, terminal_kind), (holder, owner_region, kind));
                            assert_ne!(event.kind, TraceEventKind::ObligationLeak);
                            true
                        }
                        _ => false,
                    }
                })
                .count();
            assert_eq!(
                terminals, 1,
                "each actual work/channel credit settles exactly once: {id:?}"
            );
        }
        drop(held);
        for gate in &controls.work {
            assert!(
                gate.try_lock_owned().is_ok(),
                "every physical lock is reusable"
            );
        }
        serde_json::json!({
            "scenario":"public_pipeline_failure_cleanup", "failure":failure.label(),
            "target_stage":target, "target_input":target.map(|stage| 3-stage),
            "owner":format!("{:?}",owner_identity.0), "region":format!("{:?}",owner_identity.1),
            "workers":identities.map(|(task,region)| serde_json::json!({"task":format!("{task:?}"),"region":format!("{region:?}")})),
            "callback_calls":[4,3,2], "delivered":[0], "admitted":report.summary.admitted,
            "acknowledged":report.summary.consumed, "edge_capacity":1,
            "max_in_flight":report.summary.max_in_flight, "window":4,
            "cancelled_losers":losers.len(), "cleanup_pending":losers.len(),
            "cleanup_completed":losers.len(), "actual_child_completions":3,
            "premature_success_refusal":"owned_cleanup_pending",
            "withheld_child_observed":target.is_none(), "withheld_observation_yields":if target.is_none() {8} else {0},
            "lease_ids":leases.iter().map(|id| format!("{id:?}")).collect::<Vec<_>>(),
            "lease_commits":1,"lease_aborts":leases.len()-1,"lease_leaks":0,
            "all_owned_credit_reservations":owned_credits.len(),
            "all_owned_credit_terminals":owned_credits.len(),
            "terminal_outcome":terminal_outcome,
            "terminal_cancel_reason":terminal_cancel_reason,
            "terminal_panic_message":terminal_panic_message,
            "terminal_typed_trigger":terminal_typed_trigger,
            "typed_trigger_preserved":failure == FailureKind::Error,
            "terminal_cleanup_accepted":true
        })
    }

    async fn failure_journeys(cx: Cx, snapshot: TraceSnapshot) -> Vec<serde_json::Value> {
        let mut reports = Vec::new();
        for failure in [
            FailureKind::Error,
            FailureKind::Panic,
            FailureKind::EncodedPanic,
            FailureKind::Cancelled,
        ] {
            for stage in 0..3 {
                reports.push(pipeline_failure_journey(&cx, &snapshot, failure, Some(stage)).await);
            }
        }
        reports.push(
            pipeline_failure_journey(&cx, &snapshot, FailureKind::CallerCancellation, None).await,
        );
        assert_eq!(reports.len(), 13);
        reports
    }

    #[test]
    fn public_executing_pipeline_seeded_lab_failure_cleanup_controls() {
        for seed in [0x3311, 0x3312, 0x3313] {
            let mut lab = LabRuntime::new(
                LabConfig::new(seed)
                    .max_steps(100_000)
                    .trace_capacity(100_000),
            );
            let root = lab.state.create_root_region(Budget::INFINITE);
            let trace = lab.state.trace_handle();
            // Use the same checked boundary for every actual failure journey;
            // task admission, scheduling and terminal assertions stay intact.
            let coordinator: Pin<Box<dyn Future<Output = Vec<serde_json::Value>> + Send>> =
                Box::pin(async move {
                    failure_journeys(
                        Cx::current().expect("actual Lab coordinator"),
                        Box::new(move || trace.snapshot()),
                    )
                    .await
                });
            let (parent, mut joined) = lab
                .state
                .create_task(root, Budget::INFINITE, coordinator)
                .unwrap();
            lab.scheduler.lock().schedule(parent, 0);
            lab.run_until_idle();
            let reports = joined
                .try_join()
                .unwrap()
                .expect("all real failure controls drained");
            assert_eq!(reports.len(), 13);
            assert_eq!(lab.state.live_task_count(), 0);
            assert_eq!(lab.state.pending_obligation_count(), 0);
            assert_eq!(lab.state.leak_count(), 0);
            let gateway = lab.state.obligation_gateway().unwrap();
            let mailbox = gateway.mailbox();
            let stats = mailbox.stats();
            assert_eq!(stats.posted, stats.applied);
            assert_eq!(stats.reserved, stats.committed + stats.aborted);
            assert_eq!(mailbox.open_tickets(), 0);
            assert!(mailbox.is_empty());
            assert_eq!(lab.state.region(root).unwrap().pending_obligations(), 0);
            assert_eq!(
                lab.state.region(root).unwrap().unapplied_obligation_count(),
                0
            );
            let trace = lab.state.trace_handle();
            assert!(
                trace.total_pushed() < trace.capacity() as u64,
                "full retained trace required"
            );
            let report = lab.run_until_quiescent_with_report();
            assert!(report.lab_test_passed(), "{report:?}");
            assert!(!report.refinement_firewall_skipped_due_to_trace_truncation);
            let effects = lab.state.cancel_request(
                root,
                &CancelReason::user("failure controls complete"),
                None,
            );
            let (tasks, wakes) = effects.into_parts();
            assert!(tasks.is_empty());
            wakes.dispatch();
            lab.state.advance_region_state(root);
            assert!(lab.state.region(root).is_none());
            assert!(lab.run_until_quiescent_with_report().lab_test_passed());
            eprintln!(
                "ASUPERSYNC_EXECUTING_PIPELINE_CONTROLS {}",
                serde_json::json!({
                    "backend":"lab","seed":seed,"journeys":reports,
                    "live_tasks":0,"pending_obligations":0,"leaks":0,"original_region_closed":true
                })
            );
        }
    }

    #[test]
    fn public_executing_pipeline_native_failure_cleanup_controls() {
        for sharded in [false, true] {
            let (finished, completion) = std::sync::mpsc::sync_channel(1);
            let worker = std::thread::spawn(move || {
                let result = std::panic::catch_unwind(|| run_native_failure_journeys(sharded));
                let _ = finished.send(result);
            });
            let result = completion
                .recv_timeout(Duration::from_secs(45))
                .expect("native failure controls exceeded the whole-run bound; no cleanup claim");
            worker
                .join()
                .expect("owned failure-control supervisor terminated");
            if let Err(payload) = result {
                std::panic::resume_unwind(payload);
            }
        }
    }

    fn run_native_failure_journeys(sharded: bool) {
        let runtime = if sharded {
            RuntimeBuilder::multi_thread()
                .worker_threads(2)
                .with_sharded_state(true)
        } else {
            RuntimeBuilder::current_thread()
        }
        // This public policy only increases trace retention; scheduling and
        // cancellation behavior remain those of the selected native backend.
        .trace_storage_profile(asupersync::runtime::config::TraceStorageProfile::LargeMemory256G)
        .build()
        .unwrap();
        assert_eq!(runtime.config().worker_threads, if sharded { 2 } else { 1 });
        assert_eq!(
            runtime.config().runtime_state_shape,
            if sharded {
                asupersync::runtime::config::RuntimeStateShape::Sharded
            } else {
                asupersync::runtime::config::RuntimeStateShape::Unified
            }
        );
        let trace_runtime = runtime.handle();
        // Preserve the Send requirement without recursively expanding the
        // whole failure journey through each native task wrapper.
        let parent: Pin<Box<dyn Future<Output = Vec<serde_json::Value>> + Send>> =
            Box::pin(async move {
                failure_journeys(
                    Cx::current().expect("actual native coordinator"),
                    Box::new(move || {
                        trace_runtime
                            .trace_snapshot()
                            .expect("owned native runtime remains live")
                    }),
                )
                .await
            });
        let reports = runtime.block_on(runtime.handle().spawn(parent));
        assert_eq!(reports.len(), 13);
        runtime.block_on(async {
            let started = Instant::now();
            while !runtime.is_quiescent() {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "failure control ownership did not drain"
                );
                asupersync::runtime::yield_now().await;
            }
        });
        assert!(
            runtime
                .task_inspector(Default::default())
                .list_tasks()
                .is_empty()
        );
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(
            runtime.trace_snapshot().len() < runtime.trace_buffer_capacity(),
            "full retained trace required"
        );
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
        eprintln!(
            "ASUPERSYNC_EXECUTING_PIPELINE_CONTROLS {}",
            serde_json::json!({
                "backend":if sharded {"native_two_worker_sharded"} else {"native_current_thread"},
                "journeys":reports,"live_tasks":0,"leaks":0,"shutdown_completed":true
            })
        );
    }
}
