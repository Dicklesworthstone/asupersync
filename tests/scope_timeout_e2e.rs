//! Behavioral proof for `Scope::timeout`, the drain-correct timeout.
//!
//! `asupersync::time::timeout` drops the inner future when the clock wins.
//! `Scope::timeout` spawns the operation as a region task and, when the
//! deadline (or caller cancellation) wins, protocol-cancels it and JOINS it
//! before returning. These tests run on the production runtime and assert:
//!
//! - an operation that finishes in time reports `Completed(Ok)`;
//! - an operation that overruns is cancelled, its post-cancel cleanup has run
//!   by the time `timeout` returns (a counter is checked immediately, not after
//!   a sleep), and because it acknowledged the cancellation its returned
//!   `Err` is preserved as `Completed(Err)`;
//! - the "no data loss" rule: an operation that observes cancellation and
//!   still returns `Ok` during the drain is reported as `Completed(Ok)`;
//! - planted negative: a cancellation-blind operation (never checkpoints,
//!   returns a value after the abort) is reported as `TimedOut` and its late
//!   value is discarded, per the v0.4.3 task-level cancellation rule;
//! - the region reaches quiescence afterwards (the runtime shuts down within
//!   its bound).
//!
//! No-claim: this does not prove timing precision, fairness, or behaviour
//! under runtime shutdown.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use asupersync::CancelReason;
use asupersync::combinator::timeout::{TimedError, TimedResult};
use asupersync::cx::Cx;
use asupersync::runtime::{RuntimeBuilder, yield_now};

/// Parks (self-waking) until the task's own context has been cancelled.
async fn park_until_cancelled(task_cx: &Cx) {
    std::future::poll_fn(|poll_cx| {
        if task_cx.checkpoint().is_err() {
            Poll::Ready(())
        } else {
            poll_cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

fn run_on_production<F, Fut, R>(scenario: F) -> R
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    let runtime = RuntimeBuilder::new()
        .build()
        .expect("production runtime build");
    let handle = runtime.handle().spawn(async move {
        let cx = Cx::current().expect("runtime task installs ambient Cx");
        scenario(cx).await
    });
    let report = runtime.block_on(handle);
    assert!(
        runtime.shutdown_timeout(Duration::from_secs(10)),
        "production runtime must reach quiescence and shut down within the timeout"
    );
    report
}

#[test]
fn operation_that_finishes_in_time_is_completed_ok() {
    let value = run_on_production(|cx| async move {
        let result = cx
            .scope()
            .timeout::<u32, String, _, _>(&cx, Duration::from_secs(5), |_task_cx| async { Ok(42) })
            .await
            .expect("spawn");
        match result {
            TimedResult::Completed(outcome) => outcome.into_result().expect("ok outcome"),
            TimedResult::TimedOut(err) => panic!("must not time out: {err}"),
        }
    });
    assert_eq!(value, 42);
}

#[test]
fn overrunning_operation_is_cancelled_and_drained_before_return() {
    let cleanup_runs = Arc::new(AtomicUsize::new(0));
    let cleanup_for_task = Arc::clone(&cleanup_runs);
    let (timed_out, cleanup_seen_at_return) = run_on_production(move |cx| async move {
        let result = cx
            .scope()
            .timeout::<u32, String, _, _>(&cx, Duration::from_millis(50), move |task_cx| {
                let cleanup = cleanup_for_task;
                async move {
                    park_until_cancelled(&task_cx).await;
                    // Post-cancel cleanup that takes real time and is not a
                    // cancellation point: a drain-correct timeout must wait
                    // for it; a drop-based one would not.
                    std::thread::sleep(Duration::from_millis(150));
                    cleanup.fetch_add(1, Ordering::SeqCst);
                    Err("cancelled".to_string())
                }
            })
            .await
            .expect("spawn");
        let cleanup_seen = cleanup_runs.load(Ordering::SeqCst);
        // `TimedResult::into_result` maps Completed(Err(e)) to
        // Err(TimedError::Error(e)) and TimedOut to Err(TimedError::TimedOut).
        let acknowledged_err = matches!(
            result.into_result(),
            Err(TimedError::Error(ref e)) if e == "cancelled"
        );
        (acknowledged_err, cleanup_seen)
    });
    assert!(
        timed_out,
        "the task acknowledged the deadline's cancellation and returned Err; that value must be preserved as Completed(Err)"
    );
    assert_eq!(
        cleanup_seen_at_return, 1,
        "the drained task's cleanup must have run before Scope::timeout returned"
    );
}

/// When the caller is cancelled, the operation must see the caller's reason.
/// The timer's cancel-aware poll completed on the caller's cancellation
/// before the caller's checkpoint was checked, so it was treated as the
/// deadline and the operation was aborted with `Timeout`.
#[test]
fn caller_cancellation_reaches_the_operation_as_the_callers_reason() {
    let seen = Arc::new(std::sync::Mutex::new(None::<String>));
    let seen_by_operation = Arc::clone(&seen);
    let started = Arc::new(AtomicUsize::new(0));
    let started_by_operation = Arc::clone(&started);
    run_on_production(move |cx| async move {
        let mut owner = cx
            .spawn(move |owner_cx| async move {
                let _ = owner_cx
                    .scope()
                    .timeout::<u32, String, _, _>(
                        &owner_cx,
                        Duration::from_secs(30),
                        move |task_cx| async move {
                            started_by_operation.store(1, Ordering::SeqCst);
                            park_until_cancelled(&task_cx).await;
                            *seen_by_operation.lock().expect("record reason") = task_cx
                                .cancel_reason()
                                .map(|reason| format!("{:?}", reason.kind));
                            Err("cancelled".to_string())
                        },
                    )
                    .await;
            })
            .expect("spawn owner");
        while started.load(Ordering::SeqCst) == 0 {
            yield_now().await;
        }
        owner.abort_with_reason(CancelReason::user("caller gave up"));
        let _ = owner.join(&cx).await;
    });
    assert_eq!(
        seen.lock().expect("read reason").as_deref(),
        Some("User"),
        "the operation must be cancelled with the caller's reason, not Timeout"
    );
}

#[test]
fn cancellation_blind_operation_is_reported_as_timed_out_planted_negative() {
    let result = run_on_production(|cx| async move {
        cx.scope()
            .timeout::<u32, String, _, _>(&cx, Duration::from_millis(50), |_task_cx| async move {
                // Never checkpoints: it cannot acknowledge the cancellation,
                // so its late value is cancellation-blind and is discarded.
                std::thread::sleep(Duration::from_millis(200));
                Ok(7)
            })
            .await
            .expect("spawn")
    });
    assert!(
        result.is_timed_out(),
        "a cancellation-blind late value must be reported as TimedOut, got {result:?}"
    );
}

#[test]
fn late_ok_produced_during_drain_is_not_lost() {
    let result = run_on_production(|cx| async move {
        cx.scope()
            .timeout::<&'static str, String, _, _>(&cx, Duration::from_millis(50), |task_cx| {
                async move {
                    park_until_cancelled(&task_cx).await;
                    // The operation acknowledges cancellation but still has a
                    // result to hand back; the drain must surface it.
                    Ok("committed-after-deadline")
                }
            })
            .await
            .expect("spawn")
    });
    match result {
        TimedResult::Completed(outcome) => {
            assert_eq!(
                outcome.into_result().expect("late Ok is preserved"),
                "committed-after-deadline"
            );
        }
        TimedResult::TimedOut(err) => panic!("a late Ok must not be reported as a timeout: {err}"),
    }
}

#[test]
fn dropping_scope_timeout_future_aborts_spawned_task() {
    let cancelled = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(AtomicUsize::new(0));
    let cancelled_clone = Arc::clone(&cancelled);
    let started_clone = Arc::clone(&started);

    let aborted_while_running = run_on_production(move |cx| async move {
        let scope = cx.scope();
        // Boxed, so `drop` below really drops the timeout future and the
        // abort guard inside it; `pin!` would keep both alive until the end
        // of this block and leave the abort to a race with shutdown.
        let mut timeout_fut = Box::pin(scope.timeout::<(), (), _, _>(
            &cx,
            Duration::from_secs(30),
            move |task_cx| async move {
                started_clone.store(1, Ordering::SeqCst);
                park_until_cancelled(&task_cx).await;
                cancelled_clone.store(1, Ordering::SeqCst);
                Ok(())
            },
        ));
        // Poll once so the operation is spawned and starts running.
        let _ = std::future::poll_fn(|poll_cx| {
            let _ = timeout_fut.as_mut().poll(poll_cx);
            Poll::Ready(())
        })
        .await;

        while started.load(Ordering::SeqCst) == 0 {
            yield_now().await;
        }

        drop(timeout_fut);

        // The operation must see the abort while the runtime still runs it,
        // well inside its 30 s deadline.
        let bound = std::time::Instant::now() + Duration::from_secs(10);
        while cancelled.load(Ordering::SeqCst) == 0 {
            if std::time::Instant::now() >= bound {
                return false;
            }
            yield_now().await;
        }
        true
    });

    assert!(
        aborted_while_running,
        "dropping a Scope::timeout future must abort the spawned task"
    );
}

// The error-returning sleep is an opt-in path through the sleep/timeout policy
// in asupersync-combinator-time-audit-fqdvqn. Legacy Sleep and Scope::timeout
// keep their existing output and late-value policies.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn fallible_sleep_stops_at_scope_timeout_before_running_subsequent_effects() {
    use asupersync::time::{SleepError, sleep_cx, timeout};
    use asupersync::types::CancelKind;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;

    struct Cleanup(Arc<AtomicUsize>);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    for workers in [1, 2] {
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let runner = std::thread::spawn(move || {
            let builder = if workers == 1 {
                RuntimeBuilder::current_thread()
            } else {
                RuntimeBuilder::multi_thread().worker_threads(workers)
            };
            let runtime = builder.build().expect("fallible sleep runtime");
            let completed = Arc::new(AtomicBool::new(false));
            let completion = Arc::clone(&completed);
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().expect("runtime task context");
                let cleanup_runs = Arc::new(AtomicUsize::new(0));
                let subsequent_effects = Arc::new(AtomicUsize::new(0));
                let parked = Arc::new(AtomicBool::new(false));
                let task_cleanup = Arc::clone(&cleanup_runs);
                let task_effects = Arc::clone(&subsequent_effects);
                let task_parked = Arc::clone(&parked);
                let scope = cx.scope();
                let operation = scope.timeout::<(), SleepError, _, _>(
                    &cx,
                    Duration::from_millis(250),
                    move |task_cx| async move {
                        let _cleanup = Cleanup(task_cleanup);
                        let mut waiting =
                            Box::pin(sleep_cx(&task_cx, Duration::from_secs(3600)));
                        std::future::poll_fn(|task| {
                            let polled = waiting.as_mut().poll(task);
                            if polled.is_pending() {
                                task_parked.store(true, Ordering::Release);
                            }
                            polled
                        })
                        .await?;
                        task_effects.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                );
                let result = timeout(cx.now(), Duration::from_secs(10), operation)
                    .await
                    .expect("Scope::timeout must not drain the original one-hour sleep")
                    .expect("spawn sleeping operation");

                assert!(parked.load(Ordering::Acquire), "sleep must actually park");
                assert!(
                    matches!(
                        result.into_result(),
                        Err(TimedError::Error(SleepError::Cancelled(reason)))
                            if reason.kind == CancelKind::Timeout
                    ),
                    "the acknowledged timeout must preserve the typed sleep error"
                );
                assert_eq!(subsequent_effects.load(Ordering::SeqCst), 0);
                assert_eq!(
                    cleanup_runs.load(Ordering::SeqCst),
                    1,
                    "the sleeping operation must finish cleanup before the timeout returns"
                );
                completion.store(true, Ordering::Release);
            }));
            assert!(completed.load(Ordering::Acquire), "scenario must complete");
            assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
            done_tx.send(()).expect("watchdog receiver");
        });

        match done_rx.recv_timeout(Duration::from_secs(20)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                runner.join().expect("fallible sleep scope timeout scenario");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("fallible sleep scope timeout exceeded its external watchdog");
            }
        }
    }
}


/// A production-runtime proof that the deadline drains a real operation
/// subtree, even after the direct task's retirement barrier has opened.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn scoped_timeout_native_waits_for_grandchild_after_direct_body_has_finished() {
    use asupersync::cx::{ChildRegionSpec, ScopedTimeoutStop, ScopedTimeoutTask};
    use asupersync::observability::TaskInspectorConfig;
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use asupersync::types::Time;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Mutex, mpsc};
    use std::task::{Context, Wake, Waker};

    #[derive(Default)]
    struct Gate {
        released: AtomicBool,
        parked: AtomicBool,
        waker: Mutex<Option<Waker>>,
    }

    impl Gate {
        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            let waker = self.waker.lock().unwrap().take();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    struct WaitGate(Arc<Gate>);

    impl Future for WaitGate {
        type Output = ();

        fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<()> {
            if self.0.released.load(Ordering::SeqCst) {
                return Poll::Ready(());
            }
            *self.0.waker.lock().unwrap() = Some(task.waker().clone());
            if self.0.released.load(Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                self.0.parked.store(true, Ordering::SeqCst);
                Poll::Pending
            }
        }
    }

    /// Installed only after timeout entered its unconditional task join.
    /// The expired timer and owner-cancel registration are already gone.
    struct JoinWake {
        count: AtomicUsize,
        parent: Waker,
    }

    impl Wake for JoinWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.parent.wake_by_ref();
        }
    }

    for (current_thread, sharded) in [(true, false), (true, true), (false, false), (false, true)] {
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let runner = std::thread::spawn(move || {
            let clock = Arc::new(VirtualClock::new());
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let builder = if current_thread {
                RuntimeBuilder::current_thread()
            } else {
                RuntimeBuilder::multi_thread().worker_threads(2)
            };
            let runtime = builder
                .with_sharded_state(sharded)
                .with_timer_driver(timer.clone())
                .build()
                .unwrap();
            let inspector = runtime.task_inspector(TaskInspectorConfig::default());
            runtime.block_on(async move {
                let root = Cx::current().expect("native root context");
                let cancellation_parked = Arc::new(AtomicBool::new(false));
                let body_cancellation_parked = Arc::clone(&cancellation_parked);
                let body_id = Arc::new(Mutex::new(None));
                let published_body = Arc::clone(&body_id);
                let cleanup_gate = Arc::new(Gate::default());
                let body_gate = Arc::new(Gate::default());
                let descendant_cleanup = Arc::clone(&cleanup_gate);
                let body_return = Arc::clone(&body_gate);
                let mut timeout = Box::pin(root.timeout_scoped(
                    Duration::from_millis(50),
                    move |body| async move {
                        *published_body.lock().unwrap() = Some(body.task_id());
                        let body_region = body.region_id();
                        let _child = body.spawn(move |child| async move {
                            let region = child
                                .open_child_region(ChildRegionSpec::inherit())
                                .await
                                .unwrap();
                            assert_ne!(region.region_id(), body_region);
                            let mut grandchild = region.cx().spawn(move |grandchild| async move {
                                let mut cancelled = std::pin::pin!(grandchild.cancelled());
                                std::future::poll_fn(|task| {
                                    let poll = cancelled.as_mut().poll(task);
                                    if poll.is_pending() {
                                        body_cancellation_parked.store(true, Ordering::SeqCst);
                                    }
                                    poll
                                }).await;
                                assert!(grandchild.checkpoint().is_err());
                                WaitGate(descendant_cleanup).await;
                            }).unwrap();
                            let _ = grandchild.join(&child).await;
                            region.close().await.unwrap();
                        }).unwrap();
                        body.cancelled().await;
                        assert!(body.checkpoint().is_err());
                        WaitGate(body_return).await;
                        "late acknowledged value"
                    },
                ));
                std::future::poll_fn(|task| {
                    assert!(timeout.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;

                // Observe an actual Pending cancellation registration before
                // advancing the clock; admission speed cannot consume the bound.
                while !cancellation_parked.load(Ordering::SeqCst) {
                    yield_now().await;
                }
                let actual_body = body_id.lock().unwrap().expect("actual body identity");
                clock.advance_to(Time::from_millis(50));
                timer.process_timers();
                std::future::poll_fn(|task| {
                    assert!(timeout.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                while !cleanup_gate.parked.load(Ordering::SeqCst)
                    || !body_gate.parked.load(Ordering::SeqCst)
                {
                    yield_now().await;
                }

                // The body cannot retire before this poll because its return
                // gate is closed. This fresh waker can only be woken by the
                // direct join's terminal publication/retirement, not the timer.
                let joined = std::future::poll_fn(|task| {
                    let joined = Arc::new(JoinWake {
                        count: AtomicUsize::new(0),
                        parent: task.waker().clone(),
                    });
                    let waker = Waker::from(Arc::clone(&joined));
                    assert!(timeout.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
                    Poll::Ready(joined)
                }).await;
                body_gate.release();
                while joined.count.load(Ordering::SeqCst) == 0 {
                    yield_now().await;
                }
                assert!(inspector.inspect_task(actual_body).is_none_or(|task| task.is_terminal()));

                // The direct join is now ready. A task-only timeout would be
                // Ready here; the owned timeout must still await the grandchild.
                std::future::poll_fn(|task| {
                    assert!(timeout.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                assert!(!cleanup_gate.released.load(Ordering::SeqCst));
                cleanup_gate.release();
                let report = timeout.await.unwrap();
                assert!(matches!(report.stop, ScopedTimeoutStop::TimedOut));
                assert!(matches!(
                    report.task,
                    ScopedTimeoutTask::Joined(Ok("late acknowledged value"))
                ));
                assert!(report.region_id.is_some());
                assert!(report.close.unwrap().is_ok());
                assert!(!root.is_cancel_requested());
                assert!(timer.is_empty());
            });
            assert!(runtime.shutdown_timeout(Duration::from_secs(10)));
            done_tx.send(()).unwrap();
        });
        done_rx.recv_timeout(Duration::from_secs(30)).unwrap_or_else(|error| {
            panic!("scoped timeout did not drain: current_thread={current_thread}, sharded={sharded}: {error}");
        });
        runner.join().expect("native scoped-timeout runner");
    }
}
