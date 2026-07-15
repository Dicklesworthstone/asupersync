//! Regression coverage for empty `Cx::race` cancellation wakeups.

#![allow(missing_docs)]

use asupersync::cx::Cx;
use asupersync::runtime::{JoinError, RuntimeState};
use asupersync::types::{Budget, CancelKind, CancelReason, Outcome, TaskId};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

struct CountWaker(Arc<AtomicUsize>);

impl Wake for CountWaker {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn test_race_empty_wakes_on_cancel() {
    let mut state = RuntimeState::new();
    let root_region = state.create_root_region(Budget::INFINITE);
    let cx: Cx = Cx::new_with_observability(
        root_region,
        TaskId::new_for_test(0, 0),
        Budget::INFINITE,
        None,
        None,
        None,
    );

    let mut handle = cx
        .scope()
        .spawn_registered(&mut state, &cx, |task_cx| async move {
            let empty: Vec<Pin<Box<dyn Future<Output = i32> + Send>>> = Vec::new();
            task_cx.race(empty).await
        })
        .expect("spawn race-empty task");

    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountWaker(Arc::clone(&wakes))));
    let mut poll_cx = Context::from_waker(&waker);

    {
        let task = state
            .task(handle.task_id())
            .expect("spawned task should have a record");
        let inner = task
            .cx_inner
            .as_ref()
            .expect("spawned task should have a cancellation context");
        inner.write().cancel_waker = Some(Arc::new(
            asupersync::types::task_context::CancelWaker::new(waker.clone()),
        ));
    }

    {
        let stored = state
            .get_stored_future(handle.task_id())
            .expect("spawned task should have a stored future");
        assert!(stored.poll(&mut poll_cx).is_pending());
    }

    handle.abort_with_reason(CancelReason::new(CancelKind::User));

    assert_eq!(
        wakes.load(Ordering::SeqCst),
        0,
        "a bare RuntimeState handle must not invoke arbitrary Wakers on the caller stack"
    );

    let (should_schedule, cancel_wakes) = state
        .cancel_task(handle.task_id(), &CancelReason::new(CancelKind::User))
        .into_parts();
    assert!(
        should_schedule,
        "the state owner publishes cancellation work"
    );
    assert_eq!(wakes.load(Ordering::SeqCst), 0);
    cancel_wakes.dispatch();

    assert_eq!(
        wakes.load(Ordering::SeqCst),
        1,
        "authoritative bare-state cancellation wakes race([]) after owner publication"
    );

    {
        let stored = state
            .get_stored_future(handle.task_id())
            .expect("spawned task should still have a stored future");
        assert!(matches!(
            stored.poll(&mut poll_cx),
            Poll::Ready(Outcome::Ok(()))
        ));
    }

    match handle.try_join() {
        Ok(Some(Err(JoinError::Cancelled(reason)))) => {
            assert_eq!(reason.kind, CancelKind::User);
        }
        other => panic!("expected race([]) cancellation result, got {other:?}"),
    }
}
