//! Repro test for race loser cancellation behavior.

mod common;
use common::*;

use asupersync::cx::Cx;
use asupersync::runtime::RuntimeState;
use asupersync::types::Budget;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

struct Flag {
    set: bool,
}

impl Flag {
    fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self { set: false }))
    }

    fn set(flag: &Arc<Mutex<Self>>) {
        flag.lock().unwrap().set = true;
    }
}

// A future that waits until told to finish, and sets a flag when dropped.
struct DroppableFuture {
    on_drop: Arc<Mutex<Flag>>,
    waker: Option<Waker>,
    ready: bool,
}

impl DroppableFuture {
    fn new(on_drop: Arc<Mutex<Flag>>) -> Self {
        Self {
            on_drop,
            waker: None,
            ready: false,
        }
    }
}

impl Future for DroppableFuture {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.ready {
            Poll::Ready(())
        } else {
            self.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Drop for DroppableFuture {
    fn drop(&mut self) {
        Flag::set(&self.on_drop);
    }
}

#[test]
fn repro_race_leak() {
    init_test_logging();
    test_phase!("repro_race_leak");
    run_test(|| async {
        // Setup manual runtime state for testing
        let mut state = RuntimeState::new();
        let cx = Cx::for_testing();
        let region = state.create_root_region(Budget::INFINITE);
        let scope = cx.scope();
        assert_eq!(scope.region_id(), region, "test scope region mismatch");

        // Flag to check if the loser task actually ran its cleanup (simulate drain)
        let loser_flag = Flag::new();
        let loser_flag_clone = loser_flag.clone();

        // Spawn a loser task that never finishes but has a drop guard
        let (loser_handle, mut stored_loser) =
            scope
                .spawn(&mut state, &cx, move |_| async move {
                    // This task runs forever. If it's cancelled, it should be dropped.
                    let fut = DroppableFuture::new(loser_flag_clone);
                    fut.await;
                    "loser"
                })
                .expect("spawn failed");

        // Spawn a winner task that finishes immediately
        let (winner_handle, mut stored_winner) = scope
            .spawn(&mut state, &cx, |_| async { "winner" })
            .expect("spawn failed");

        // Manually drive tasks (since we don't have a real reactor/executor loop in this test setup)
        // We need to poll them.
        // In a real runtime, the executor polls them.
        // Here we simulate the executor.

        // Create a waker
        struct NoopWaker;
        impl std::task::Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }
        let waker = Waker::from(Arc::new(NoopWaker));
        let mut ctx = Context::from_waker(&waker);

        // Poll tasks once to get them started
        assert!(stored_winner.poll(&mut ctx).is_ready()); // Winner finishes
        assert!(stored_loser.poll(&mut ctx).is_pending()); // Loser is pending

        let loser_task_id = loser_handle.task_id();

        // Now race the handles using Cx::race (simulating what race! macro does)
        let race_future = cx.race(vec![
            {
                let cx = cx.clone();
                let handle = winner_handle;
                Box::pin(async move { handle.join(&cx).await })
            },
            {
                let cx = cx.clone();
                let handle = loser_handle;
                Box::pin(async move { handle.join(&cx).await })
            },
        ]);

        // Await the race
        let result = race_future.await;

        // Race should finish with "winner"
        assert_eq!(result.unwrap(), Ok("winner"));

        // CRITICAL CHECK: Did the loser task get cancelled/dropped?
        // Since we used Cx::race, it dropped the join future.
        // But does dropping the join future cancel the task?
        // NO. TaskHandle says: "If the TaskHandle is dropped, the task continues running."

        // If the task was cancelled, stored_loser should resolve to Ready or be dropped?
        // In our manual setup, stored_loser is held by us (simulating executor).
        // If cancellation happened, next poll of stored_loser should see cancellation.

        // Check if cancellation request was sent to loser
        // We can check if the loser task's context has cancellation requested.
        // We need to peek into the stored task or the runtime state.

        let task_record = state.task(loser_task_id).expect("task record");
        let inner = task_record
            .cx_inner
            .as_ref()
            .expect("cx inner missing");
        let is_cancelled = inner.read().unwrap().cancel_requested;

        tracing::debug!(is_cancelled, "loser cancelled");

        // With the fix, dropping JoinFuture should abort the task.
        assert!(
            is_cancelled,
            "Loser task SHOULD be cancelled by Cx::race (TaskHandle leak fixed)"
        );

        // If we use Scope::race, it SHOULD cancel.
        // Let's verify that.

        // Use Scope::race
        let (winner_handle2, mut stored_winner2) = scope
            .spawn(&mut state, &cx, |_| async { "winner2" })
            .unwrap();
        let (loser_handle2, mut stored_loser2) = scope
            .spawn(&mut state, &cx, |_| async {
                std::future::pending::<&str>().await
            })
            .unwrap();
        let loser_task_id2 = loser_handle2.task_id();

        assert!(stored_winner2.poll(&mut ctx).is_ready());
        assert!(stored_loser2.poll(&mut ctx).is_pending());

        let _ = scope
            .race(&cx, winner_handle2, loser_handle2)
            .await
            .unwrap();

        let task_record2 = state.task(loser_task_id2).expect("task record 2");
        let inner2 = task_record2
            .cx_inner
            .as_ref()
            .expect("cx inner 2 missing");
        let is_cancelled2 = inner2.read().unwrap().cancel_requested;

        tracing::debug!(is_cancelled2, "loser2 cancelled");

        // Expect TRUE
        assert!(is_cancelled2, "Loser task SHOULD be cancelled by Scope::race");
    });

    test_complete!("repro_race_leak");
}
