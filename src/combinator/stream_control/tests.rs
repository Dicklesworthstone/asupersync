#![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

use super::*;
use crate::channel::{mpsc, oneshot};
use crate::lab::run_async_under_lab;
use crate::runtime::yield_now;
use crate::stream::{StreamExt, iter};
use crate::sync::Notify;
use std::sync::atomic::AtomicUsize;
use std::task::Waker;

struct Idle {
    first: bool,
    polls: Arc<AtomicUsize>,
}

impl Stream for Idle {
    type Item = u8;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<u8>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if self.first {
            self.first = false;
            Poll::Ready(Some(0))
        } else {
            Poll::Pending
        }
    }
}

#[derive(Clone, Copy)]
enum StopKind { Error, Panic, HostilePayload }

struct HostilePayload;
impl Drop for HostilePayload {
    fn drop(&mut self) { panic!("secondary stop payload panic"); }
}

async fn stopped_journey(cx: Cx, kind: StopKind, cleanup_panics: bool) {
    let (signal, mut stop_signal) = oneshot::channel::<()>();
    let (started, mut ready) = oneshot::channel::<()>();
    let started = Arc::new(parking_lot::Mutex::new(Some(started)));
    let (resource, _resource_receiver) = mpsc::channel::<()>(1);
    let member_resource = resource.clone();
    let cleaned = Arc::new(AtomicUsize::new(0));
    let child_cleaned = Arc::clone(&cleaned);
    let handles = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let retained = Arc::clone(&handles);
    let polls = Arc::new(AtomicUsize::new(0));
    let source_polls = Arc::clone(&polls);
    let at_return = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&at_return);
    let observed_cleaned = Arc::clone(&cleaned);
    let mut producer = cx.spawn(move |owner| async move {
        let stop = async move {
            stop_signal.recv_uninterruptible().await.unwrap();
            match kind {
                StopKind::Error => "consumer stopped",
                StopKind::Panic => panic!("stop observer panic"),
                StopKind::HostilePayload => std::panic::panic_any(HostilePayload),
            }
        };
        let result = try_for_each_concurrent_scoped_until(
            &owner, Idle { first: true, polls: source_polls }, 2, stop,
            move |child, _| {
                let resource = member_resource.clone();
                let started = Arc::clone(&started);
                let cleaned = Arc::clone(&child_cleaned);
                let handles = Arc::clone(&retained);
                async move {
                    let (done, mut completed) = oneshot::channel();
                    let grandchild = child.spawn(move |grandchild| async move {
                        let permit = resource.reserve_checked(&grandchild).await.unwrap();
                        let started = started.lock().take().unwrap();
                        started.send_blocking(()).unwrap();
                        grandchild.cancelled().await;
                        assert!(grandchild.checkpoint().is_err());
                        yield_now().await;
                        yield_now().await;
                        drop(permit);
                        cleaned.fetch_add(1, Ordering::SeqCst);
                        done.send_blocking(()).unwrap();
                        if cleanup_panics { panic!("descendant cleanup panic"); }
                    }).unwrap();
                    handles.lock().push(grandchild);
                    // Cancelling only this direct member cannot release this
                    // dependency: its descendant must receive cancellation too.
                    completed.recv_uninterruptible().await.unwrap();
                    Ok::<_, &'static str>(())
                }
            },
        ).await;
        assert!(!owner.is_cancel_requested(), "stop must not cancel its caller");
        observed.store(observed_cleaned.load(Ordering::SeqCst), Ordering::SeqCst);
        result
    }).unwrap();
    ready.recv(&cx).await.unwrap();
    assert_eq!(resource.telemetry_snapshot(1).reserved_uncommitted_obligations, 1);
    let before = polls.load(Ordering::SeqCst);
    signal.send_blocking(()).unwrap();
    let result = producer.join(&cx).await.unwrap();
    assert_eq!(cleaned.load(Ordering::SeqCst), 1);
    assert_eq!(at_return.load(Ordering::SeqCst), 1, "cleanup happened before return");
    // Work gets the first poll at a selection point. Once stop is observed,
    // however, not a single further source poll is allowed during drain.
    assert!(polls.load(Ordering::SeqCst) <= before + 1);
    assert!(!cx.is_cancel_requested());
    assert!(handles.lock().iter().all(|handle| handle.is_finished()));
    assert_eq!(resource.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);
    resource.try_reserve().unwrap().abort();
    if cleanup_panics {
        assert!(matches!(result, Outcome::Panicked(ref p) if p.message().contains("descendant cleanup panic")));
    } else {
        match kind {
            StopKind::Error => assert!(matches!(result, Outcome::Err(ScopedStreamError::Item("consumer stopped")))),
            StopKind::Panic => assert!(matches!(result, Outcome::Panicked(ref p) if p.message().contains("stop observer panic"))),
            StopKind::HostilePayload => assert!(matches!(result, Outcome::Panicked(ref p) if p.message().contains("non-string payload"))),
        }
    }
}

#[test]
fn external_stop_drains_nested_dependencies_and_checked_resources_in_lab() {
    for kind in [StopKind::Error, StopKind::Panic, StopKind::HostilePayload] {
        let ((), report) = run_async_under_lab(0x5701, move |cx| stopped_journey(cx, kind, false));
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn external_stop_drains_nested_dependencies_on_native_runtime() {
    let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(runtime.handle().spawn(async {
        stopped_journey(Cx::current().unwrap(), StopKind::Error, false).await;
    }));
}

#[test]
fn cleanup_panic_has_precedence_over_external_stop() {
    let ((), report) = run_async_under_lab(0x5702, |cx| stopped_journey(cx, StopKind::Error, true));
    assert!(report.quiescent && report.invariant_violations.is_empty());
}

#[test]
fn precompleted_stop_needs_no_runtime_and_does_not_poll_borrowed_source() {
    let cx = Cx::for_testing();
    let reads = std::rc::Rc::new(std::cell::Cell::new(0));
    let borrowed = &reads;
    let source = iter([1]).inspect(|_| reads.set(reads.get() + 1));
    let stop = async { assert_eq!(borrowed.get(), 0); "already stopped" };
    let mut run = Box::pin(try_for_each_concurrent_scoped_until(
        &cx, source, 1, stop, |_child, _| async { panic!("no mapper admitted") },
    ));
    assert!(matches!(run.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Outcome::Err(ScopedStreamError::Item("already stopped")))));
    drop(run);
    assert_eq!(reads.get(), 0);
}

#[test]
fn source_fence_never_touches_the_source_again_and_reports_eof() {
    let reads = Arc::new(AtomicUsize::new(0));
    let fence = Arc::new(AtomicBool::new(false));
    let mut source = StopSource {
        inner: Idle { first: true, polls: Arc::clone(&reads) },
        stopped: Arc::clone(&fence),
    };
    let mut task = Context::from_waker(Waker::noop());
    assert_eq!(Pin::new(&mut source).poll_next(&mut task), Poll::Ready(Some(0)));
    fence.store(true, Ordering::Release);
    for _ in 0..3 {
        assert_eq!(Pin::new(&mut source).poll_next(&mut task), Poll::Ready(None));
    }
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(source.size_hint(), (0, Some(0)));
}

#[test]
fn idle_empty_source_is_interrupted_without_a_source_event() {
    let ((), report) = run_async_under_lab(0x5703, |cx| async move {
        let stop = Arc::new(Notify::new());
        let requested = Arc::new(AtomicBool::new(false));
        let observer = Arc::clone(&stop);
        let flag = Arc::clone(&requested);
        let polls = Arc::new(AtomicUsize::new(0));
        let watched = Arc::clone(&polls);
        let mut producer = cx.spawn(move |owner| async move {
            try_for_each_concurrent_scoped_until(
                &owner, Idle { first: false, polls: watched }, 2,
                async move { observer.wait_until(|| flag.load(Ordering::Acquire)).await; "idle stop" },
                |_child, _| async { panic!("empty source must never spawn") },
            ).await
        }).unwrap();
        for _ in 0..1000 {
            if polls.load(Ordering::SeqCst) > 0 { break; }
            yield_now().await;
        }
        assert!(polls.load(Ordering::SeqCst) > 0);
        for _ in 0..16 { yield_now().await; }
        let before = polls.load(Ordering::SeqCst);
        for _ in 0..16 { yield_now().await; }
        assert_eq!(polls.load(Ordering::SeqCst), before, "idle work must not self-spin");
        requested.store(true, Ordering::Release);
        stop.notify_waiters();
        assert!(matches!(producer.join(&cx).await.unwrap(),
            Outcome::Err(ScopedStreamError::Item("idle stop"))));
        assert_eq!(stop.waiter_count(), 0);
        assert!(!cx.is_cancel_requested());
    });
    assert!(report.quiescent && report.invariant_violations.is_empty());
}

#[test]
fn successful_work_retires_unused_observer_and_preserves_item_errors() {
    let ((), report) = run_async_under_lab(0x5704, |cx| async move {
        for failure in [false, true] {
            let notify = Notify::new();
            let outcome = try_for_each_concurrent_scoped_until(
                &cx, iter([0]), 1,
                async { notify.notified().await; "unused stop" },
                move |_child, _| async move { if failure { Err("item failed") } else { Ok(()) } },
            ).await;
            if failure {
                assert!(matches!(outcome, Outcome::Err(ScopedStreamError::Item("item failed"))));
            } else { assert!(outcome.is_ok()); }
            assert_eq!(notify.waiter_count(), 0);
        }
    });
    assert!(report.quiescent && report.invariant_violations.is_empty());
}

#[test]
fn zero_limit_refuses_before_polling_the_stop() {
    let cx = Cx::for_testing();
    let polls = std::cell::Cell::new(0);
    let stop = async { polls.set(polls.get() + 1); "stop" };
    let mut run = Box::pin(try_for_each_concurrent_scoped_until(
        &cx, iter([0]), 0, stop, |_child, _| async { Ok(()) },
    ));
    assert!(catch_unwind(AssertUnwindSafe(|| run.as_mut().poll(&mut Context::from_waker(Waker::noop())))).is_err());
    drop(run);
    assert_eq!(polls.get(), 0);
}

#[test]
fn stop_during_error_drain_does_not_replace_the_selected_item_failure() {
    let ((), report) = run_async_under_lab(0x5705, |cx| async move {
        let (stop, mut stopped) = oneshot::channel();
        let (in_cleanup, mut cleaning) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let gates = Arc::new(parking_lot::Mutex::new(Some((in_cleanup, released))));
        let started = Arc::new(AtomicBool::new(false));
        let mut producer = cx.spawn(move |owner| async move {
            try_for_each_concurrent_scoped_until(
                &owner, iter([0, 1]), 2,
                async move { stopped.recv_uninterruptible().await.unwrap(); "later stop" },
                move |child, item| {
                    let gates = Arc::clone(&gates);
                    let started = Arc::clone(&started);
                    async move {
                        if item == 1 {
                            while !started.load(Ordering::Acquire) { yield_now().await; }
                            return Err("original item error");
                        }
                        let (in_cleanup, mut released) = gates.lock().take().unwrap();
                        started.store(true, Ordering::Release);
                        child.cancelled().await;
                        in_cleanup.send_blocking(()).unwrap();
                        released.recv_uninterruptible().await.unwrap();
                        Ok(())
                    }
                },
            ).await
        }).unwrap();
        cleaning.recv(&cx).await.unwrap();
        stop.send_blocking(()).unwrap();
        for _ in 0..8 { yield_now().await; }
        assert!(producer.try_join().unwrap().is_none(), "explicit cleanup gate still held");
        release.send_blocking(()).unwrap();
        assert!(matches!(producer.join(&cx).await.unwrap(),
            Outcome::Err(ScopedStreamError::Item("original item error"))));
    });
    assert!(report.quiescent && report.invariant_violations.is_empty());
}
