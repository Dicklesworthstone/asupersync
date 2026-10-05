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
