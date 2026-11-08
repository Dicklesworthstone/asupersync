//! Native ownership boundaries for strategy-driven retries.

use super::{ScopedRetryReport, ScopedRetryStop, ScopedRetryTask};
use crate::Cx;
use crate::channel::oneshot;
use crate::combinator::retry::{AlwaysRetry, RetryIf, RetryPolicy};
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::sync::Notify;
use crate::types::{CancelReason, RegionId};
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

#[derive(Default)]
struct Witness {
    parked: AtomicBool,
    cleaning: AtomicBool,
    finished: AtomicBool,
    retired: AtomicBool,
    changed: Notify,
}

impl Witness {
    fn note(&self, flag: &AtomicBool) {
        flag.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }

    async fn wait(&self, ready: impl Fn(&Self) -> bool) {
        self.changed.wait_until(|| ready(self)).await;
    }
}

struct Retire(Arc<Witness>);

impl Drop for Retire {
    fn drop(&mut self) {
        self.0.note(&self.0.retired);
    }
}

async fn child_cleanup(cx: Cx, seen: Arc<Witness>, mut release: oneshot::Receiver<()>) {
    let _retire = Retire(Arc::clone(&seen));
    {
        let mut cancelled = std::pin::pin!(cx.cancelled());
        poll_fn(|task| {
            let progress = cancelled.as_mut().poll(task);
            if progress.is_pending() && !seen.parked.load(Ordering::Acquire) {
                seen.note(&seen.parked);
            }
            progress
        })
        .await;
    }
    assert!(
        cx.checkpoint().is_err(),
        "child acknowledges subtree cancellation"
    );
    {
        let mut cleanup = std::pin::pin!(release.recv_uninterruptible());
        poll_fn(|task| {
            let progress = cleanup.as_mut().poll(task);
            if progress.is_pending() && !seen.cleaning.load(Ordering::Acquire) {
                seen.note(&seen.cleaning);
            }
            progress
        })
        .await
        .expect("controller releases cleanup after witnessing Pending");
    }
    seen.note(&seen.finished);
}

fn native<F, Fut>(scenario: F)
where
    F: Fn(Cx) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (send, receive) = std::sync::mpsc::channel();
    let thread = std::thread::Builder::new()
        .name("scoped-retry-native".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                for workers in [1, 2] {
                    for sharded in [false, true] {
                        let builder = if workers == 1 {
                            RuntimeBuilder::current_thread()
                        } else {
                            RuntimeBuilder::new().worker_threads(workers)
                        };
                        let runtime = builder.with_sharded_state(sharded).build().unwrap();
                        runtime.block_on(async {
                            let root = Cx::current().expect("native root context");
                            let mut owner = root.spawn(scenario).expect("native scenario owner");
                            owner.join(&root).await.expect("native retry scenario");
                        });
                        let drain = runtime.shutdown_drained(Duration::from_secs(5));
                        assert_eq!(
                            drain.outcome,
                            RootDrainOutcome::Quiescent,
                            "workers={workers}, sharded={sharded}: {drain:?}"
                        );
                        assert_eq!(drain.live_tasks, 0);
                        assert_eq!(drain.live_regions, 0);
                        assert_eq!(drain.pending_spawns, 0);
                        assert_eq!(drain.pending_obligations, 0);
                        assert!(runtime.is_quiescent());
                    }
                }
            }));
            let _ = send.send(result);
        })
        .unwrap();
    // The watchdog bounds a broken test; no sleep establishes readiness.
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("scoped retry must retire every owned attempt");
    thread.join().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn assert_closed<T, E>(report: &ScopedRetryReport<T, E>, parent: RegionId) {
    for (index, attempt) in report.attempts.iter().enumerate() {
        assert_eq!(attempt.attempt as usize, index + 1);
        let region = attempt.region_id.expect("private attempt region");
        assert_ne!(region, parent);
        assert!(
            report.attempts[..index]
                .iter()
                .all(|earlier| earlier.region_id != Some(region)),
            "attempts must never reuse a live ownership region"
        );
        let close = attempt
            .close
            .as_ref()
            .expect("attempt has a close receipt")
            .as_ref()
            .expect("attempt actually quiesced");
        assert!(close.descendant_panic.is_none());
        assert!(close.cleanup_outcome.is_none());
    }
}

async fn failed_attempt_drains_before_retry(owner: Cx) {
    let seen = Arc::new(Witness::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let predicates = Arc::new(AtomicUsize::new(0));
    let (release, cleanup) = oneshot::channel();
    let mut cleanup = Some(cleanup);
    let mut generation = 0;
    let factory_seen = Arc::clone(&seen);
    let factory_calls = Arc::clone(&calls);
    let predicate_seen = Arc::clone(&seen);
    let predicate_calls = Arc::clone(&predicates);
    let mut retry = std::pin::pin!(owner.retry_scoped(
        RetryPolicy::immediate(3),
        RetryIf(move |error: &&'static str, attempt| {
            assert_eq!(*error, "retryable first attempt");
            assert_eq!(attempt, 1);
            assert!(predicate_seen.retired.load(Ordering::Acquire));
            predicate_calls.fetch_add(1, Ordering::SeqCst);
            true
        }),
        move |attempt_cx, attempt| {
            generation += 1;
            assert_eq!(
                generation, attempt,
                "FnMut state survives each owned attempt"
            );
            factory_calls.fetch_add(1, Ordering::SeqCst);
            let cleanup = cleanup.take();
            let seen = Arc::clone(&factory_seen);
            async move {
                if attempt == 1 {
                    let child_seen = Arc::clone(&seen);
                    attempt_cx
                        .spawn(move |child| child_cleanup(child, child_seen, cleanup.unwrap()))
                        .unwrap();
                    seen.wait(|state| state.parked.load(Ordering::Acquire))
                        .await;
                    Err("retryable first attempt")
                } else {
                    assert_eq!(attempt, 2);
                    assert!(seen.retired.load(Ordering::Acquire));
                    Ok(73_u64)
                }
            }
        },
    ));
    let mut cleaning = std::pin::pin!(seen.wait(|state| state.cleaning.load(Ordering::Acquire)));
    poll_fn(|task| {
        assert!(
            retry.as_mut().poll(task).is_pending(),
            "cleanup remains held"
        );
        cleaning.as_mut().poll(task)
    })
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(predicates.load(Ordering::SeqCst), 0);
    assert!(!seen.retired.load(Ordering::Acquire));
    release.send_blocking(()).unwrap();
    let report = retry.await.expect("owned retry report");
    assert!(matches!(
        report.stop,
        ScopedRetryStop::Succeeded { attempt: 2 }
    ));
    assert_eq!(report.attempts.len(), 2);
    assert!(matches!(
        report.attempts[0].task,
        ScopedRetryTask::Joined(Ok(Err("retryable first attempt")))
    ));
    assert!(matches!(
        report.attempts[1].task,
        ScopedRetryTask::Joined(Ok(Ok(73)))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(predicates.load(Ordering::SeqCst), 1);
    assert_eq!(report.total_delay, Duration::ZERO);
    assert!(report.owner_cancellation.is_none());
    assert!(seen.finished.load(Ordering::Acquire));
    assert!(seen.retired.load(Ordering::Acquire));
    assert_closed(&report, owner.region_id());
    assert!(!owner.is_cancel_requested());
}

#[test]
fn scoped_retry_native_drains_failed_descendants_before_predicate_and_next_attempt() {
    native(failed_attempt_drains_before_retry);
}

async fn cancellation_during_backoff(owner: Cx) {
    let backoff = Arc::new(Witness::default());
    let observed = Arc::clone(&backoff);
    let calls = Arc::new(AtomicUsize::new(0));
    let factory_calls = Arc::clone(&calls);
    let predicate_called = Arc::new(AtomicBool::new(false));
    let predicate_witness = Arc::clone(&predicate_called);
    let mut retrying = owner
        .spawn(move |retry_owner| async move {
            let timer = retry_owner.timer_driver().expect("native owner timer");
            let mut retry = std::pin::pin!(retry_owner.retry_scoped(
                RetryPolicy::fixed_delay(Duration::from_secs(60), 3),
                RetryIf(move |error: &&'static str, attempt| {
                    assert_eq!(*error, "try later");
                    assert_eq!(attempt, 1);
                    predicate_witness.store(true, Ordering::Release);
                    true
                }),
                move |_, attempt| {
                    factory_calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(attempt, 1, "cancellation must prevent the second factory");
                    async { Err::<u64, _>("try later") }
                },
            ));
            let report = poll_fn(|task| {
                let progress = retry.as_mut().poll(task);
                if progress.is_pending()
                    && predicate_called.load(Ordering::Acquire)
                    && !timer.is_empty()
                {
                    observed.note(&observed.parked);
                }
                progress
            })
            .await
            .expect("cancelled backoff has a report");
            assert!(retry_owner.checkpoint().is_err());
            assert!(
                timer.is_empty(),
                "cancelled backoff retires its timer entry"
            );
            report
        })
        .unwrap();
    backoff
        .wait(|state| state.parked.load(Ordering::Acquire))
        .await;
    let reason = CancelReason::shutdown().with_cause(CancelReason::user("stop retry backoff"));
    retrying.abort_with_reason(reason.clone());
    let report = retrying
        .join(&owner)
        .await
        .expect("acknowledged cancellation report");
    assert!(matches!(&report.stop, ScopedRetryStop::Cancelled(actual) if actual == &reason));
    assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
    assert_eq!(report.attempts.len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        report.attempts[0].task,
        ScopedRetryTask::Joined(Ok(Err("try later")))
    ));
    assert_closed(&report, owner.region_id());
    assert!(!owner.is_cancel_requested());
}

#[test]
fn scoped_retry_native_cancelled_backoff_starts_no_new_attempt_and_retires_timer() {
    native(cancellation_during_backoff);
}

async fn selected_success_survives_late_cancel(owner: Cx) {
    let seen = Arc::new(Witness::default());
    let factory_seen = Arc::clone(&seen);
    let (release, cleanup) = oneshot::channel();
    let mut cleanup = Some(cleanup);
    let mut retrying = owner
        .spawn(move |retry_owner| async move {
            let report = retry_owner
                .retry_scoped(
                    RetryPolicy::immediate(3),
                    AlwaysRetry,
                    move |attempt_cx, attempt| {
                        assert_eq!(attempt, 1, "selected success must not be retried");
                        let cleanup = cleanup.take().expect("one successful attempt");
                        let seen = Arc::clone(&factory_seen);
                        async move {
                            let child_seen = Arc::clone(&seen);
                            attempt_cx
                                .spawn(move |child| child_cleanup(child, child_seen, cleanup))
                                .unwrap();
                            seen.wait(|state| state.parked.load(Ordering::Acquire))
                                .await;
                            Ok::<_, &'static str>(91_u64)
                        }
                    },
                )
                .await
                .expect("successful retry report");
            assert!(retry_owner.checkpoint().is_err());
            report
        })
        .unwrap();
    seen.wait(|state| state.cleaning.load(Ordering::Acquire))
        .await;
    let reason =
        CancelReason::shutdown().with_cause(CancelReason::user("cancel during success drain"));
    retrying.abort_with_reason(reason.clone());
    release.send_blocking(()).unwrap();
    let report = retrying
        .join(&owner)
        .await
        .expect("acknowledged success receipt");
    assert!(matches!(
        report.stop,
        ScopedRetryStop::Succeeded { attempt: 1 }
    ));
    assert_eq!(report.owner_cancellation.as_ref(), Some(&reason));
    assert_eq!(report.attempts.len(), 1);
    assert!(matches!(
        report.attempts[0].task,
        ScopedRetryTask::Joined(Ok(Ok(91)))
    ));
    assert!(seen.finished.load(Ordering::Acquire));
    assert!(seen.retired.load(Ordering::Acquire));
    assert_closed(&report, owner.region_id());
    assert!(!owner.is_cancel_requested());
}

#[test]
fn scoped_retry_native_preserves_success_when_owner_cancels_during_cleanup() {
    native(selected_success_survives_late_cancel);
}
