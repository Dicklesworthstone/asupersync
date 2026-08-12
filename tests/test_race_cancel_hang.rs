//! Regression coverage for empty `Cx::race` cancellation publication.

#![allow(missing_docs)]

use asupersync::cx::Cx;
use asupersync::runtime::{JoinError, RuntimeState};
use asupersync::types::{Budget, CancelKind, CancelReason, Outcome, TaskId};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

#[test]
fn test_race_empty_observes_cancel_after_publication() {
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

    let waker = Waker::noop().clone();
    let mut poll_cx = Context::from_waker(&waker);

    {
        let task = state
            .task_mut(handle.task_id())
            .expect("spawned task should have a record");
        assert!(task.install_cancel_waker(waker.clone()));
    }

    {
        let stored = state
            .get_stored_future(handle.task_id())
            .expect("spawned task should have a stored future");
        assert!(stored.poll(&mut poll_cx).is_pending());
    }

    handle.abort_with_reason(CancelReason::new(CancelKind::User));

    assert_eq!(
        state
            .task(handle.task_id())
            .expect("spawned task should have a record")
            .context_cancel_requested(),
        Some(true),
        "handle cancellation must publish to the sealed task context"
    );

    let (should_schedule, cancel_wakes) = state
        .cancel_task(handle.task_id(), &CancelReason::new(CancelKind::User))
        .into_parts();
    assert!(
        should_schedule,
        "the state owner publishes cancellation work"
    );
    cancel_wakes.dispatch();

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
