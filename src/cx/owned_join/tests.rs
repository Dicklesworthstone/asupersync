//! Native ownership/cancellation journeys, not a model of the join algorithm.

use super::*;
use crate::channel::oneshot;
use crate::cx::ChildRegionSpec;
use crate::runtime::{RootDrainOutcome, Runtime, RuntimeBuilder, yield_now};
use crate::types::CancelKind;
use std::marker::PhantomPinned;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

// This file is only ever compiled as owned_join's `#[cfg(test)] mod tests;`.
// The ambient-authority audit reads files one at a time and cannot see that,
// so this helper's watchdog thread says it is test code here
// (br-asupersync-5w2yte).
#[cfg(test)]
fn bounded(test: impl FnOnce() + Send + 'static) {
    let (send, receive) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(test));
        let _ = send.send(result);
    });
    let result = receive.recv_timeout(Duration::from_secs(45))
        .expect("owned join must terminate and retire every participant");
    worker.join().unwrap();
    if let Err(payload) = result {
        resume_unwind(payload);
    }
}

fn runtime(workers: usize) -> Runtime {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    };
    builder.build().unwrap()
}

fn drained(runtime: &Runtime) {
    let report = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
    assert_eq!(report.live_tasks, 0);
    assert_eq!(report.pending_spawns, 0);
    assert_eq!(report.pending_obligations, 0);
}

// Signal only AFTER polling the real cancellation observer to Pending. A task
// that merely started is insufficient evidence that cancellation wakes a wait.
async fn parked_until_cancelled(cx: &Cx, started: oneshot::Sender<Cx>) -> CancelKind {
    let mut started = Some(started);
    let mut wait = pin!(cx.cancelled());
    poll_fn(|task| {
        match wait.as_mut().poll(task) {
            Poll::Ready(()) => Poll::Ready(()),
            Poll::Pending => {
                if let Some(started) = started.take() {
                    started.send_blocking(cx.clone()).unwrap();
                }
                Poll::Pending
            }
        }
    }).await;
    assert!(cx.checkpoint().is_err(), "child acknowledges the delivered request");
    cx.cancel_reason().expect("delivered cancellation has a reason").kind
}

#[test]
fn pair_forwards_to_both_children_before_waiting_for_dependent_cleanup() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (start_a, mut parked_a) = oneshot::channel();
                let (start_b, mut parked_b) = oneshot::channel();
                let (peer_done, mut peer_wait) = oneshot::channel();
                let drain_cx = cx.clone();
                let mut owner = cx.spawn(move |owner| async move {
                    let first = owner.spawn(move |child| async move {
                        let reason = parked_until_cancelled(&child, start_a).await;
                        // A's cleanup needs B to have observed its cancellation.
                        peer_wait.recv(&drain_cx).await.unwrap();
                        (11_u8, reason)
                    }).unwrap();
                    let second = owner.spawn(move |child| async move {
                        let reason = parked_until_cancelled(&child, start_b).await;
                        peer_done.send_blocking(()).unwrap();
                        (String::from("drained"), reason)
                    }).unwrap();
                    owner.scope().join_owned(&owner, first, second).await
                }).unwrap();
                let child_a = parked_a.recv(&cx).await.unwrap();
                let child_b = parked_b.recv(&cx).await.unwrap();
                owner.abort_with_reason(CancelReason::race_loser());
                let (first, second) = owner.join(&cx).await.unwrap();
                assert_eq!(first.unwrap(), (11, CancelKind::RaceLost));
                assert_eq!(second.unwrap(), (String::from("drained"), CancelKind::RaceLost));
                assert!(child_a.is_cancel_requested());
                assert!(child_b.is_cancel_requested());
                assert!(!cx.is_cancel_requested());
            });
            drained(&runtime);
        }
    });
}

#[test]
fn many_forwards_owner_reason_to_every_parked_child_and_preserves_input_order() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let mut senders = Vec::new();
                let mut receivers = Vec::new();
                for _ in 0..5 {
                    let (send, receive) = oneshot::channel();
                    senders.push(send);
                    receivers.push(receive);
                }
                let mut owner = cx.spawn(move |owner| async move {
                    let handles = senders.into_iter().enumerate().map(|(index, started)| {
                        owner.spawn(move |child| async move {
                            let reason = parked_until_cancelled(&child, started).await;
                            yield_now().await;
                            (index, reason)
                        }).unwrap()
                    }).collect();
                    owner.scope().join_all_owned(&owner, handles).await
                }).unwrap();
                for receiver in &mut receivers {
                    receiver.recv(&cx).await.unwrap();
                }
                owner.abort_with_reason(CancelReason::shutdown());
                let results = owner.join(&cx).await.unwrap();
                assert_eq!(results.len(), 5);
                for (index, result) in results.into_iter().enumerate() {
                    assert_eq!(result.unwrap(), (index, CancelKind::Shutdown));
                }
            });
            drained(&runtime);
        }
    });
}

#[test]
fn cancellation_of_an_explicit_nonscheduled_owner_wakes_the_collector() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let owner = Cx::detached_cancel_context();
                let (started, mut parked) = oneshot::channel();
                let handle = cx.spawn(move |child| async move {
                    parked_until_cancelled(&child, started).await
                }).unwrap();
                parked.recv(&cx).await.unwrap();
                let mut joining = Box::pin(cx.scope().join_all_owned(&owner, vec![handle]));
                poll_fn(|task| {
                    assert!(joining.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                // This context has no runtime task/cancel-lane waker. Only the
                // collector's owned cancellation registration can wake it.
                let publisher = std::thread::spawn(move || {
                    owner.cancel_with(CancelKind::User, Some("external owner stop"));
                });
                let results = joining.await;
                publisher.join().unwrap();
                assert_eq!(results.len(), 1);
                assert_eq!(results.into_iter().next().unwrap().unwrap(), CancelKind::User);
                assert!(!cx.is_cancel_requested());
            });
            drained(&runtime);
        }
    });
}

#[test]
fn normal_empty_and_large_joins_preserve_nonclone_nonunpin_results() {
    struct Value {
        index: usize,
        _pin: PhantomPinned,
    }
    fn assert_send_static<T: Send + 'static>(_: &T) {}
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let empty = cx.scope().join_all_owned::<Value, _>(&cx, Vec::new()).await;
                assert!(empty.is_empty());
                let handles = (0..130).map(|index| {
                    cx.spawn(move |_| async move {
                        if index % 2 == 0 {
                            yield_now().await;
                        }
                        Value { index, _pin: PhantomPinned }
                    }).unwrap()
                }).collect();
                let future = {
                    let scope = cx.scope();
                    scope.join_all_owned(&cx, handles)
                };
                assert_send_static(&future);
                let results = future.await;
                assert_eq!(results.len(), 130);
                for (index, result) in results.into_iter().enumerate() {
                    assert_eq!(result.unwrap().index, index);
                }
                let a = cx.spawn(|_| async { 7_u8 }).unwrap();
                let b = cx.spawn(|_| async { String::from("ok") }).unwrap();
                let pair = cx.scope().join_owned(&cx, a, b);
                assert_send_static(&pair);
                let (a, b) = pair.await;
                assert_eq!(a.unwrap(), 7);
                assert_eq!(b.unwrap(), "ok");
            });
            drained(&runtime);
        }
    });
}

#[test]
fn dropping_an_unpolled_pair_requests_both_children_without_cancelling_parent() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                let owner = region.cx();
                let (start_a, mut parked_a) = oneshot::channel();
                let (start_b, mut parked_b) = oneshot::channel();
                let first = owner.spawn(move |child| async move {
                    parked_until_cancelled(&child, start_a).await
                }).unwrap();
                let second = owner.spawn(move |child| async move {
                    parked_until_cancelled(&child, start_b).await
                }).unwrap();
                let a = parked_a.recv(&cx).await.unwrap();
                let b = parked_b.recv(&cx).await.unwrap();
                drop(owner.scope().join_owned(owner, first, second));
                assert!(a.is_cancel_requested());
                assert!(b.is_cancel_requested());
                assert!(!owner.is_cancel_requested());
                region.close().await.unwrap();
            });
            drained(&runtime);
        }
    });
}

#[test]
fn dropping_an_unpolled_many_join_already_owns_the_entire_input() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                let owner = region.cx();
                let mut handles = Vec::new();
                let mut children = Vec::new();
                for _ in 0..3 {
                    let (started, mut parked) = oneshot::channel();
                    handles.push(owner.spawn(move |child| async move {
                        parked_until_cancelled(&child, started).await
                    }).unwrap());
                    children.push(parked.recv(&cx).await.unwrap());
                }
                drop(owner.scope().join_all_owned(owner, handles));
                assert!(children.iter().all(Cx::is_cancel_requested));
                assert!(!owner.is_cancel_requested());
                region.close().await.unwrap();
            });
            drained(&runtime);
        }
    });
}

#[test]
fn dropping_a_partial_many_join_cancels_the_unpolled_suffix_not_the_ready_prefix() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let region = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
                let owner = region.cx();
                let (prefix_started, mut prefix_cx) = oneshot::channel();
                let prefix = owner.spawn(move |child| async move {
                    prefix_started.send_blocking(child).unwrap();
                    0_usize
                }).unwrap();
                let completed_cx = prefix_cx.recv(&cx).await.unwrap();
                while !prefix.is_finished() {
                    yield_now().await;
                }
                let mut handles = vec![prefix];
                let mut pending = Vec::new();
                let cleaned = Arc::new(AtomicUsize::new(0));
                for index in 1..3 {
                    let (started, mut parked) = oneshot::channel();
                    let cleaned = Arc::clone(&cleaned);
                    handles.push(owner.spawn(move |child| async move {
                        parked_until_cancelled(&child, started).await;
                        cleaned.fetch_add(1, Ordering::SeqCst);
                        index
                    }).unwrap());
                    pending.push(parked.recv(&cx).await.unwrap());
                }
                let mut joining = Box::pin(owner.scope().join_all_owned(owner, handles));
                poll_fn(|task| {
                    assert!(joining.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                drop(joining);
                assert!(!completed_cx.is_cancel_requested());
                assert!(pending.iter().all(Cx::is_cancel_requested));
                region.close().await.unwrap();
                assert_eq!(cleaned.load(Ordering::SeqCst), 2);
            });
            drained(&runtime);
        }
    });
}

#[test]
fn child_panic_is_retained_and_does_not_skip_sibling_cleanup() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let (start_a, mut parked_a) = oneshot::channel();
                let (start_b, mut parked_b) = oneshot::channel();
                let cleaned = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&cleaned);
                let mut owner = cx.spawn(move |owner| async move {
                    let a: TaskHandle<()> = owner.spawn(move |child| async move {
                        parked_until_cancelled(&child, start_a).await;
                        panic!("owned join child panic");
                    }).unwrap();
                    let b = owner.spawn(move |child| async move {
                        parked_until_cancelled(&child, start_b).await;
                        yield_now().await;
                        observed.fetch_add(1, Ordering::SeqCst);
                        23_u8
                    }).unwrap();
                    owner.scope().join_owned(&owner, a, b).await
                }).unwrap();
                parked_a.recv(&cx).await.unwrap();
                parked_b.recv(&cx).await.unwrap();
                owner.abort();
                let (a, b) = owner.join(&cx).await.unwrap();
                assert!(matches!(a, Err(JoinError::Panicked(_))));
                assert_eq!(b.unwrap(), 23);
                assert_eq!(cleaned.load(Ordering::SeqCst), 1);
            });
            drained(&runtime);
        }
    });
}

#[test]
fn precancelled_owner_preserves_ready_results_and_cancels_only_pending_work() {
    bounded(|| {
        for workers in [1, 2] {
            let runtime = runtime(workers);
            runtime.block_on(async {
                let cx = Cx::current().unwrap();
                let owner = Cx::detached_cancel_context();
                let completed = cx.spawn(|_| async { 19_u8 }).unwrap();
                while !completed.is_finished() {
                    yield_now().await;
                }
                let (started, mut parked) = oneshot::channel();
                let pending = cx.spawn(move |child| async move {
                    parked_until_cancelled(&child, started).await;
                    31_u8
                }).unwrap();
                parked.recv(&cx).await.unwrap();
                owner.cancel_with(CancelKind::User, Some("before owned join"));
                let results = cx.scope().join_all_owned(&owner, vec![completed, pending]).await;
                let values: Vec<_> = results.into_iter().map(Result::unwrap).collect();
                assert_eq!(values, [19, 31]);
            });
            drained(&runtime);
        }
    });
}
