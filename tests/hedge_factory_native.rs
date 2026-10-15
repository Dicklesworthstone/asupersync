//! R37b / asupersync-bi2462.90: real child contexts, lazy backup and loser drain.
#![cfg(not(target_arch = "wasm32"))]

use asupersync::Cx;
use asupersync::channel::mpsc;
use asupersync::cx::cap;
use asupersync::runtime::{JoinError, RuntimeBuilder};
use asupersync::sync::Notify;
use asupersync::types::{CancelKind, CancelReason, TaskId};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

#[derive(Default)]
struct Witness {
    parked: AtomicBool,
    cancelled: AtomicBool,
    released: AtomicBool,
    retired: AtomicBool,
    task: Mutex<Option<TaskId>>,
    reason: Mutex<Option<CancelKind>>,
    full_reason: Mutex<Option<CancelReason>>,
    changed: Notify,
}

impl Witness {
    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}

struct Retire(Arc<Witness>);

impl Drop for Retire {
    fn drop(&mut self) {
        self.0.retired.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }
}

fn native<F, Fut>(workers: usize, body: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread().build().unwrap()
    } else {
        RuntimeBuilder::new().worker_threads(workers).build().unwrap()
    };
    runtime.block_on(runtime.handle().spawn(async move {
        let cx = Cx::current().expect("admitted native owner");
        asupersync::time::timeout(cx.now(), Duration::from_secs(10), body(cx.clone()))
            .await
            .expect("native hedge/drain watchdog");
    }));
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

async fn parked_loser(child: Cx, mut receiver: mpsc::Receiver<()>, seen: Arc<Witness>) -> u8 {
    let _retire = Retire(Arc::clone(&seen));
    *seen.task.lock().unwrap() = Some(child.task_id());
    let received = {
        let mut receive = std::pin::pin!(receiver.recv(&child));
        poll_fn(|task| {
            let progress = receive.as_mut().poll(task);
            if progress.is_pending() && !seen.parked.swap(true, Ordering::AcqRel) {
                seen.changed.notify_waiters();
            }
            progress
        })
        .await
    };
    // The owner retains the sender and never sends. Only child cancellation
    // may release the pending receive; an ordinary closed channel is not proof.
    assert!(received.is_err());
    assert!(child.is_cancel_requested());
    assert!(child.checkpoint().is_err());
    *seen.reason.lock().unwrap() = Some(child.cancel_reason().unwrap().kind);
    *seen.full_reason.lock().unwrap() = child.cancel_reason();
    seen.cancelled.store(true, Ordering::Release);
    seen.changed.notify_waiters();
    seen.changed
        .wait_until(|| seen.released.load(Ordering::Acquire))
        .await;
    0
}

async fn wait_cancel<F: Future>(future: &mut Pin<Box<F>>, seen: &Witness) {
    let mut cancelled = std::pin::pin!(
        seen.changed.wait_until(|| seen.cancelled.load(Ordering::Acquire))
    );
    poll_fn(|task| {
        assert!(
            future.as_mut().poll(task).is_pending(),
            "hedge returned before withheld loser cleanup"
        );
        cancelled.as_mut().poll(task)
    })
    .await;
    assert!(!seen.retired.load(Ordering::Acquire));
}

#[test]
fn fast_primary_cancels_an_hour_long_delay_without_invoking_backup() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let calls = Arc::new(AtomicUsize::new(0));
            let backup_calls = Arc::clone(&calls);
            let result = cx
                .hedge_drained_with(
                    Duration::from_secs(3600),
                    |_child| std::future::ready(7_u8),
                    move |_child| {
                        backup_calls.fetch_add(1, Ordering::SeqCst);
                        async { 9_u8 }
                    },
                )
                .await;
            assert_eq!(result.unwrap(), 7);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(!cx.is_cancel_requested());
        });
    }
}

#[test]
fn delayed_backup_wins_but_waits_for_parked_primary_cleanup() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let seen = Arc::new(Witness::default());
            let (_sender, receiver) = mpsc::channel(1);
            let primary = Arc::clone(&seen);
            let backup = Arc::clone(&seen);
            let delay = Duration::from_millis(25);
            let earliest = cx.now() + delay;
            let mut hedge = Box::pin(cx.hedge_drained_with(
                delay,
                move |child| parked_loser(child, receiver, primary),
                move |child| async move {
                    assert!(child.now() >= earliest, "backup started before delay");
                    backup.changed
                        .wait_until(|| backup.parked.load(Ordering::Acquire))
                        .await;
                    9_u8
                },
            ));
            wait_cancel(&mut hedge, &seen).await;
            assert_ne!(seen.task.lock().unwrap().unwrap(), cx.task_id());
            assert_eq!(*seen.reason.lock().unwrap(), Some(CancelKind::RaceLost));
            seen.release();
            assert_eq!(hedge.await.unwrap(), 9);
            assert!(seen.retired.load(Ordering::Acquire));
            assert!(!cx.is_cancel_requested());
        });
    }
}

#[test]
fn primary_winner_drains_an_already_started_backup() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let seen = Arc::new(Witness::default());
            let (_sender, receiver) = mpsc::channel(1);
            let primary = Arc::clone(&seen);
            let backup = Arc::clone(&seen);
            let mut hedge = Box::pin(cx.hedge_drained_with(
                Duration::ZERO,
                move |_child| async move {
                    primary.changed
                        .wait_until(|| primary.parked.load(Ordering::Acquire))
                        .await;
                    7_u8
                },
                move |child| parked_loser(child, receiver, backup),
            ));
            wait_cancel(&mut hedge, &seen).await;
            assert_ne!(seen.task.lock().unwrap().unwrap(), cx.task_id());
            assert_eq!(*seen.reason.lock().unwrap(), Some(CancelKind::RaceLost));
            seen.release();
            assert_eq!(hedge.await.unwrap(), 7);
            assert!(seen.retired.load(Ordering::Acquire));
        });
    }
}

#[test]
fn completed_primary_suppresses_backup_even_while_owner_is_unpolled() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let release_primary = Arc::new(Notify::new());
            let primary_done = Arc::new(Notify::new());
            let gate = Arc::clone(&release_primary);
            let done = Arc::clone(&primary_done);
            let calls = Arc::new(AtomicUsize::new(0));
            let backup_calls = Arc::clone(&calls);
            let mut hedge = Box::pin(cx.hedge_drained_with(
                Duration::from_secs(1),
                move |_child| async move {
                    gate.notified().await;
                    done.notify_one();
                    7_u8
                },
                move |_child| {
                    backup_calls.fetch_add(1, Ordering::SeqCst);
                    async { 9_u8 }
                },
            ));
            // Admit both tasks, but withhold primary completion until this poll
            // returns. Thereafter the owner deliberately stops polling the hedge.
            poll_fn(|task| {
                assert!(hedge.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            release_primary.notify_one();
            primary_done.notified().await;
            asupersync::time::sleep(cx.now(), Duration::from_millis(1100)).await;
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(hedge.await.unwrap(), 7);
        });
    }
}

#[test]
fn synchronous_primary_factory_panic_is_a_join_error_not_an_owner_panic() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let calls = Arc::new(AtomicUsize::new(0));
            let backup_calls = Arc::clone(&calls);
            let result = cx
                .hedge_drained_with(
                    Duration::from_secs(3600),
                    |_child| -> std::future::Ready<u8> {
                        panic!("synchronous hedge primary sentinel");
                    },
                    move |_child| {
                        backup_calls.fetch_add(1, Ordering::SeqCst);
                        async { 9_u8 }
                    },
                )
                .await;
            assert!(matches!(result, Err(JoinError::Panicked(_))));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        });
    }
}

#[test]
fn timer_authority_is_required_only_when_delay_is_nonzero() {
    native(1, |cx| async move {
        let no_time = {
            let _guard = cx.clone()
                .restrict::<cap::CapSet<true, false, true, true, true>>()
                .set_current_restricted();
            Cx::current().unwrap()
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let primary_calls = Arc::clone(&calls);
        let backup_calls = Arc::clone(&calls);
        let result = no_time
            .hedge_drained_with(
                Duration::from_secs(1),
                move |_child| {
                    primary_calls.fetch_add(1, Ordering::SeqCst);
                    async { 1_u8 }
                },
                move |_child| {
                    backup_calls.fetch_add(1, Ordering::SeqCst);
                    async { 2_u8 }
                },
            )
            .await;
        assert!(matches!(result, Err(JoinError::Cancelled(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            no_time.hedge_drained_with(
                Duration::ZERO,
                |_child| async { 1_u8 },
                |_child| async { 2_u8 },
            ).await,
            Ok(1 | 2)
        ));
    });
}

#[test]
fn cancellation_during_backup_delay_stops_primary_and_never_launches_backup() {
    for workers in [1, 2] {
        for timed in [false, true] {
        native(workers, move |cx| async move {
            let seen = Arc::new(Witness::default());
            let (_sender, receiver) = mpsc::channel(1);
            let primary = Arc::clone(&seen);
            let calls = Arc::new(AtomicUsize::new(0));
            let backup_calls = Arc::clone(&calls);
            let reported = Arc::new(AtomicBool::new(false));
            let publication = Arc::clone(&reported);
            let reason = CancelReason::user("stop hedged request");
            let expected = reason.clone();
            let mut owner = cx.spawn(move |owner| async move {
                let primary = move |child| parked_loser(child, receiver, primary);
                let backup = move |_child| {
                    backup_calls.fetch_add(1, Ordering::SeqCst);
                    async { 9_u8 }
                };
                let result = if timed {
                    owner.hedge_drained_with_timeout(
                        Duration::from_secs(3600),
                        Duration::from_secs(7200),
                        primary,
                        backup,
                    ).await
                } else {
                    owner.hedge_drained_with(Duration::from_secs(3600), primary, backup).await
                };
                assert!(matches!(result, Err(JoinError::Cancelled(actual)) if actual == expected));
                publication.store(true, Ordering::Release);
            }).unwrap();
            seen.changed
                .wait_until(|| seen.parked.load(Ordering::Acquire))
                .await;
            owner.abort_with_reason(reason.clone());
            let mut joined = Box::pin(owner.join(&cx));
            wait_cancel(&mut joined, &seen).await;
            assert_eq!(*seen.full_reason.lock().unwrap(), Some(reason));
            assert!(!reported.load(Ordering::Acquire));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            seen.release();
            assert!(matches!(joined.await, Ok(())));
            assert!(reported.load(Ordering::Acquire));
            assert!(seen.cancelled.load(Ordering::Acquire));
            assert!(seen.retired.load(Ordering::Acquire));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        });
        }
    }
}

#[test]
fn owner_cancellation_drains_both_already_started_hedge_attempts() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let seen = [Arc::new(Witness::default()), Arc::new(Witness::default())];
            let [primary, backup] = seen.clone();
            let (_sa, ra) = mpsc::channel(1);
            let (_sb, rb) = mpsc::channel(1);
            let reason = CancelReason::user("stop both hedge attempts");
            let expected = reason.clone();
            let mut owner = cx
                .spawn(move |owner| async move {
                    let result = owner
                        .hedge_drained_with(
                            Duration::ZERO,
                            move |child| parked_loser(child, ra, primary),
                            move |child| parked_loser(child, rb, backup),
                        )
                        .await;
                    assert!(
                        matches!(result, Err(JoinError::Cancelled(actual)) if actual == expected)
                    );
                })
                .unwrap();
            for branch in &seen {
                branch
                    .changed
                    .wait_until(|| branch.parked.load(Ordering::Acquire))
                    .await;
            }
            owner.abort_with_reason(reason.clone());
            let mut joined = Box::pin(owner.join(&cx));
            for branch in &seen {
                wait_cancel(&mut joined, branch).await;
                assert_eq!(*branch.full_reason.lock().unwrap(), Some(reason.clone()));
            }
            for branch in &seen {
                branch.release();
            }
            assert!(matches!(joined.await, Ok(())));
            assert!(
                seen.iter()
                    .all(|branch| branch.retired.load(Ordering::Acquire))
            );
            assert!(!cx.is_cancel_requested());
        });
    }
}

#[test]
fn panic_in_backup_cleanup_overrides_a_successful_primary() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let seen = Arc::new(Witness::default());
            let (_sender, receiver) = mpsc::channel(1);
            let primary = Arc::clone(&seen);
            let backup = Arc::clone(&seen);
            let mut hedge = Box::pin(cx.hedge_drained_with(
                Duration::ZERO,
                move |_child| async move {
                    primary.changed
                        .wait_until(|| primary.parked.load(Ordering::Acquire))
                        .await;
                    7_u8
                },
                move |child| async move {
                    parked_loser(child, receiver, backup).await;
                    panic!("hedge backup cleanup sentinel");
                },
            ));
            wait_cancel(&mut hedge, &seen).await;
            seen.release();
            assert!(matches!(hedge.await, Err(JoinError::Panicked(_))));
            assert!(seen.retired.load(Ordering::Acquire));
        });
    }
}

#[test]
fn overall_timeout_cancels_primary_without_starting_a_delayed_backup() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let seen = Arc::new(Witness::default());
            let (_sender, receiver) = mpsc::channel(1);
            let primary = Arc::clone(&seen);
            let calls = Arc::new(AtomicUsize::new(0));
            let backup_calls = Arc::clone(&calls);
            let mut hedge = Box::pin(cx.hedge_drained_with_timeout(
                Duration::from_secs(3600),
                Duration::from_millis(500),
                move |child| parked_loser(child, receiver, primary),
                move |_child| {
                    backup_calls.fetch_add(1, Ordering::SeqCst);
                    async { 9_u8 }
                },
            ));
            wait_cancel(&mut hedge, &seen).await;
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            seen.release();
            assert!(matches!(hedge.await,
                Err(JoinError::Cancelled(reason)) if reason.kind == CancelKind::Timeout));
            assert!(seen.retired.load(Ordering::Acquire));
            assert!(!cx.is_cancel_requested());
        });
    }
}

#[test]
fn overall_timeout_waits_for_cleanup_of_both_started_attempts() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let a = Arc::new(Witness::default());
            let b = Arc::new(Witness::default());
            let (_sa, ra) = mpsc::channel(1);
            let (_sb, rb) = mpsc::channel(1);
            let primary = Arc::clone(&a);
            let backup = Arc::clone(&b);
            let mut hedge = Box::pin(cx.hedge_drained_with_timeout(
                Duration::ZERO,
                Duration::from_millis(500),
                move |child| parked_loser(child, ra, primary),
                move |child| parked_loser(child, rb, backup),
            ));
            wait_cancel(&mut hedge, &a).await;
            wait_cancel(&mut hedge, &b).await;
            assert!(a.parked.load(Ordering::Acquire));
            assert!(b.parked.load(Ordering::Acquire));
            assert_eq!(*a.reason.lock().unwrap(), Some(CancelKind::RaceLost));
            assert_eq!(*b.reason.lock().unwrap(), Some(CancelKind::RaceLost));
            a.release();
            // Releasing one attempt cannot waive the other's cleanup.
            poll_fn(|task| {
                assert!(hedge.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
            b.release();
            assert!(matches!(hedge.await,
                Err(JoinError::Cancelled(reason)) if reason.kind == CancelKind::Timeout));
            assert!(a.retired.load(Ordering::Acquire));
            assert!(b.retired.load(Ordering::Acquire));
            assert!(!cx.is_cancel_requested());
        });
    }
}

#[test]
fn expired_or_unauthorized_timed_hedges_do_not_invoke_either_factory() {
    native(1, |cx| async move {
        for delay in [Duration::ZERO, Duration::from_secs(1)] {
            let calls = Arc::new(AtomicUsize::new(0));
            let a = Arc::clone(&calls);
            let b = Arc::clone(&calls);
            let result = cx.hedge_drained_with_timeout(
                delay,
                Duration::ZERO,
                move |_child| {
                    a.fetch_add(1, Ordering::SeqCst);
                    async { 1_u8 }
                },
                move |_child| {
                    b.fetch_add(1, Ordering::SeqCst);
                    async { 2_u8 }
                },
            ).await;
            assert!(matches!(result,
                Err(JoinError::Cancelled(reason)) if reason.kind == CancelKind::Timeout));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
        let no_time = {
            let _guard = cx.clone()
                .restrict::<cap::CapSet<true, false, true, true, true>>()
                .set_current_restricted();
            Cx::current().unwrap()
        };
        let result = no_time.hedge_drained_with_timeout(
            Duration::ZERO,
            Duration::from_secs(1),
            |_child| -> std::future::Ready<u8> { panic!("unauthorized primary invoked") },
            |_child| -> std::future::Ready<u8> { panic!("unauthorized backup invoked") },
        ).await;
        assert!(matches!(result, Err(JoinError::Cancelled(_))));
    });
}

#[test]
fn timely_winner_survives_cleanup_that_finishes_after_overall_deadline() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let seen = Arc::new(Witness::default());
            let (_sender, receiver) = mpsc::channel(1);
            let primary = Arc::clone(&seen);
            let backup = Arc::clone(&seen);
            let mut hedge = Box::pin(cx.hedge_drained_with_timeout(
                Duration::ZERO,
                Duration::from_secs(1),
                move |child| parked_loser(child, receiver, primary),
                move |_child| async move {
                    backup.changed
                        .wait_until(|| backup.parked.load(Ordering::Acquire))
                        .await;
                    9_u8
                },
            ));
            wait_cancel(&mut hedge, &seen).await;
            asupersync::time::sleep(cx.now(), Duration::from_millis(1100)).await;
            poll_fn(|task| {
                assert!(hedge.as_mut().poll(task).is_pending());
                Poll::Ready(())
            }).await;
            seen.release();
            assert_eq!(hedge.await.unwrap(), 9);
            assert!(seen.retired.load(Ordering::Acquire));
        });
    }
}

#[test]
fn primary_cleanup_panic_takes_precedence_over_overall_timeout() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let seen = Arc::new(Witness::default());
            let (_sender, receiver) = mpsc::channel(1);
            let primary = Arc::clone(&seen);
            let mut hedge = Box::pin(cx.hedge_drained_with_timeout(
                Duration::from_secs(3600),
                Duration::from_millis(500),
                move |child| async move {
                    parked_loser(child, receiver, primary).await;
                    panic!("timed hedge primary cleanup sentinel");
                },
                |_child| async { 9_u8 },
            ));
            wait_cancel(&mut hedge, &seen).await;
            seen.release();
            assert!(matches!(hedge.await, Err(JoinError::Panicked(_))));
            assert!(seen.retired.load(Ordering::Acquire));
        });
    }
}

#[test]
fn deadline_prevents_backup_side_effects_while_owner_is_not_polling() {
    for workers in [1, 2] {
        native(workers, |cx| async move {
            let seen = Arc::new(Witness::default());
            seen.release();
            let (_sender, receiver) = mpsc::channel(1);
            let primary = Arc::clone(&seen);
            let calls = Arc::new(AtomicUsize::new(0));
            let backup_calls = Arc::clone(&calls);
            let mut hedge = Box::pin(cx.hedge_drained_with_timeout(
                Duration::from_secs(2),
                Duration::from_secs(1),
                move |child| parked_loser(child, receiver, primary),
                move |_child| {
                    backup_calls.fetch_add(1, Ordering::SeqCst);
                    async { 9_u8 }
                },
            ));
            let mut parked = std::pin::pin!(
                seen.changed.wait_until(|| seen.parked.load(Ordering::Acquire))
            );
            poll_fn(|task| {
                assert!(hedge.as_mut().poll(task).is_pending());
                parked.as_mut().poll(task)
            }).await;
            // Child tasks and timers progress, but the owner does not select a
            // winner or send loser cancellation until it resumes polling.
            asupersync::time::sleep(cx.now(), Duration::from_millis(2100)).await;
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(matches!(hedge.await,
                Err(JoinError::Cancelled(reason)) if reason.kind == CancelKind::Timeout));
            assert!(seen.cancelled.load(Ordering::Acquire));
            assert!(seen.retired.load(Ordering::Acquire));
        });
    }
}
