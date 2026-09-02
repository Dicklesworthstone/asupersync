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
//!   a sleep), and the result is `TimedOut`;
//! - planted negative for the "no data loss" rule: an operation that observes
//!   cancellation and still returns `Ok` during the drain is reported as
//!   `Completed(Ok)`, not `TimedOut`;
//! - the region reaches quiescence afterwards (the runtime shuts down within
//!   its bound).
//!
//! No-claim: this does not prove timing precision, fairness, or behaviour
//! under runtime shutdown.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use asupersync::combinator::timeout::TimedResult;
use asupersync::cx::Cx;
use asupersync::runtime::RuntimeBuilder;

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
        (result.is_timed_out(), cleanup_seen)
    });
    assert!(
        timed_out,
        "the 50 ms deadline must win against a parked task"
    );
    assert_eq!(
        cleanup_seen_at_return, 1,
        "the drained task's cleanup must have run before Scope::timeout returned"
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
