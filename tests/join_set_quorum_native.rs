//! Native task-group success selection; no self-waking stand-ins for parked work.
//! Run with the repository-authorized RCH lane and default features.
#![cfg(not(target_arch = "wasm32"))]
use asupersync::combinator::{JoinSet, QuorumError};
use asupersync::channel::oneshot;
use asupersync::runtime::{RootDrainOutcome, RuntimeBuilder};
use asupersync::types::{CancelKind, CancelReason};
use asupersync::Cx;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::Poll;
use std::time::Duration;

fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("native task quorum scenario exceeded watchdog");
    worker.join().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn run<F, Fut>(workers: usize, test: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    };
    let runtime = builder.build().unwrap();
    runtime.block_on(runtime.handle().spawn(async move {
        test(Cx::current().expect("native task context")).await;
    }));
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
    eprintln!("task-quorum: workers={workers}, root quiescent, tasks=0 spawns=0 obligations=0");
}

async fn parked(child: &Cx, ready: oneshot::Sender<()>) {
    let mut ready = Some(ready);
    let mut cancellation = pin!(child.cancelled());
    poll_fn(|task| match cancellation.as_mut().poll(task) {
        Poll::Ready(()) => Poll::Ready(()),
        Poll::Pending => {
            if let Some(ready) = ready.take() {
                // Witness is emitted AFTER a real cancellation waker is installed.
                ready.send_blocking(()).unwrap();
            }
            Poll::Pending
        }
    })
    .await;
    assert!(child.is_cancel_requested());
    let _ = child.checkpoint();
}

#[test]
fn first_success_tolerates_error_and_retires_parked_sibling() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let cleaned = Arc::new(AtomicUsize::new(0));
                let count = Arc::clone(&cleaned);
                let (ready, mut witness) = oneshot::channel();
                let mut set = JoinSet::<u8, &'static str, _>::in_cx(&cx);
                set.spawn(&cx, move |child| async move {
                    parked(&child, ready).await;
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(99)
                }).unwrap();
                witness.recv(&cx).await.unwrap();
                set.spawn(&cx, |_| async { Err("one backend failed") }).unwrap();
                set.spawn(&cx, |_| async { Ok(7) }).unwrap();
                assert_eq!(set.join_first_ok(&cx).await.unwrap(), 7);
                assert_eq!(cleaned.load(Ordering::SeqCst), 1);
            });
        }
    });
}

#[test]
fn quorum_retires_parked_prefix_and_returns_exact_number_of_values() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let cleaned = Arc::new(AtomicUsize::new(0));
                let mut set = JoinSet::<u8, &'static str, _>::in_cx(&cx);
                for _ in 0..3 {
                    let (ready, mut witness) = oneshot::channel();
                    let count = Arc::clone(&cleaned);
                    set.spawn(&cx, move |child| async move {
                        parked(&child, ready).await;
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok(99)
                    }).unwrap();
                    witness.recv(&cx).await.unwrap();
                }
                set.spawn(&cx, |_| async { Ok(3) }).unwrap();
                set.spawn(&cx, |_| async { Ok(8) }).unwrap();
                let mut values = set.join_quorum(&cx, 2).await.unwrap();
                values.sort_unstable();
                assert_eq!(values, [3, 8]);
                assert_eq!(cleaned.load(Ordering::SeqCst), 3);
            });
        }
    });
}

#[test]
fn impossible_quorum_preserves_errors_instead_of_cleanup_cancellation() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let cleaned = Arc::new(AtomicUsize::new(0));
                let count = Arc::clone(&cleaned);
                let (ready, mut witness) = oneshot::channel();
                let mut set = JoinSet::<u8, &'static str, _>::in_cx(&cx);
                set.spawn(&cx, move |child| async move {
                    parked(&child, ready).await;
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(9)
                }).unwrap();
                witness.recv(&cx).await.unwrap();
                set.spawn(&cx, |_| async { Err("unavailable") }).unwrap();
                let result = set.join_quorum(&cx, 2).await;
                assert!(matches!(result,
                    Err(QuorumError::InsufficientSuccesses {
                        required: 2, total: 2, achieved: 0, errors
                    }) if errors == ["unavailable"]));
                assert_eq!(cleaned.load(Ordering::SeqCst), 1);
            });
        }
    });
}

#[test]
fn invalid_quorums_drain_already_admitted_work() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                for required in [0, 2, usize::MAX] {
                    let cleaned = Arc::new(AtomicUsize::new(0));
                    let count = Arc::clone(&cleaned);
                    let (ready, mut witness) = oneshot::channel();
                    let mut set = JoinSet::<u8, (), _>::in_cx(&cx);
                    set.spawn(&cx, move |child| async move {
                        parked(&child, ready).await;
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok(9)
                    }).unwrap();
                    witness.recv(&cx).await.unwrap();
                    assert!(matches!(set.join_quorum(&cx, required).await,
                        Err(QuorumError::InvalidQuorum { required: actual, total: 1 })
                        if actual == required));
                    assert_eq!(cleaned.load(Ordering::SeqCst), 1);
                }
                let empty = JoinSet::<u8, (), _>::in_cx(&cx);
                assert!(matches!(empty.join_first_ok(&cx).await,
                    Err(QuorumError::InvalidQuorum { required: 1, total: 0 })));
            });
        }
    });
}

#[test]
fn previously_collected_members_do_not_vote_in_a_later_quorum() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let mut set = JoinSet::<u8, (), _>::in_cx(&cx);
                set.spawn(&cx, |_| async { Ok(10) }).unwrap();
                assert_eq!(set.join_next(&cx).await.unwrap().expect("first member"), 10);
                set.spawn(&cx, |_| async { Ok(20) }).unwrap();
                assert_eq!(set.join_first_ok(&cx).await.unwrap(), 20);
            });
        }
    });
}

#[test]
fn owner_abort_reaches_every_parked_member() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let cleaned = Arc::new(AtomicUsize::new(0));
                let count = Arc::clone(&cleaned);
                let (ready, mut witness) = oneshot::channel();
                let mut owner = cx.spawn(move |owner| async move {
                    let mut set = JoinSet::<u8, (), _>::in_cx(&owner);
                    set.spawn(&owner, move |child| async move {
                        parked(&child, ready).await;
                        assert_eq!(child.cancel_reason().unwrap().kind, CancelKind::Shutdown);
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok(9)
                    }).unwrap();
                    set.join_first_ok(&owner).await
                }).unwrap();
                witness.recv(&cx).await.unwrap();
                owner.abort_with_reason(CancelReason::shutdown());
                assert!(matches!(owner.join(&cx).await.unwrap(),
                    Err(QuorumError::Cancelled(reason)) if reason.kind == CancelKind::Shutdown));
                assert_eq!(cleaned.load(Ordering::SeqCst), 1);
            });
        }
    });
}

#[test]
fn cleanup_panic_defeats_an_already_selected_success() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let (ready, mut witness) = oneshot::channel();
                let mut set = JoinSet::<u8, (), _>::in_cx(&cx);
                set.spawn(&cx, move |child| async move {
                    parked(&child, ready).await;
                    panic!("intentional quorum loser cleanup panic");
                }).unwrap();
                witness.recv(&cx).await.unwrap();
                set.spawn(&cx, |_| async { Ok(1) }).unwrap();
                assert!(matches!(set.join_first_ok(&cx).await, Err(QuorumError::Panicked(_))));
            });
        }
    });
}

#[derive(Debug)]
struct DropAfterCleanup {
    cleaned: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}

impl Drop for DropAfterCleanup {
    fn drop(&mut self) {
        assert_eq!(self.cleaned.load(Ordering::SeqCst), 1,
            "selected value destroyed before sibling cleanup");
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn cancellation_during_slow_drain_keeps_selected_value_until_cleanup() {
    bounded(|| {
        for workers in [1, 2] {
            run(workers, |cx| async move {
                let cleaned = Arc::new(AtomicUsize::new(0));
                let dropped = Arc::new(AtomicUsize::new(0));
                let (parked_send, mut parked_receive) = oneshot::channel();
                let (draining_send, mut draining_receive) = oneshot::channel();
                let (release, mut wait_release) = oneshot::channel();
                let count = Arc::clone(&cleaned);
                let winning = DropAfterCleanup {
                    cleaned: Arc::clone(&cleaned), dropped: Arc::clone(&dropped),
                };
                let cleanup_cx = cx.clone();
                let mut owner = cx.spawn(move |owner| async move {
                    let mut set = JoinSet::<DropAfterCleanup, &'static str, _>::in_cx(&owner);
                    set.spawn(&owner, move |child| async move {
                        parked(&child, parked_send).await;
                        draining_send.send_blocking(()).unwrap();
                        wait_release.recv(&cleanup_cx).await.unwrap();
                        count.fetch_add(1, Ordering::SeqCst);
                        Err("cleanup finished")
                    }).unwrap();
                    set.spawn(&owner, move |_| async move { Ok(winning) }).unwrap();
                    set.join_first_ok(&owner).await
                }).unwrap();
                parked_receive.recv(&cx).await.unwrap();
                draining_receive.recv(&cx).await.unwrap();
                assert_eq!(cleaned.load(Ordering::SeqCst), 0);
                assert_eq!(dropped.load(Ordering::SeqCst), 0);
                assert!(matches!(owner.try_join(), Ok(None)), "winner escaped before drain");
                owner.abort_with_reason(CancelReason::shutdown());
                assert!(matches!(owner.try_join(), Ok(None)), "abort abandoned cleanup");
                release.send_blocking(()).unwrap();
                assert!(matches!(owner.join(&cx).await.unwrap(),
                    Err(QuorumError::Cancelled(reason)) if reason.kind == CancelKind::Shutdown));
                assert_eq!(cleaned.load(Ordering::SeqCst), 1);
                assert_eq!(dropped.load(Ordering::SeqCst), 1);
            });
        }
    });
}
