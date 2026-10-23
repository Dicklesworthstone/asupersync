    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::cap;
    use crate::types::{Budget, RegionId, TaskId};
    use crate::util::ArenaIndex;
    use parking_lot::Mutex;
    use std::cell::Cell;
    use std::future::Future;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    // =========================================================================
    // Test Utilities
    // =========================================================================

    fn noop_waker() -> Waker {
        Waker::noop().clone()
    }

    fn poll_ready<F: Future>(fut: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut boxed = Box::pin(fut);
        match boxed.as_mut().poll(&mut cx) {
            Poll::Ready(output) => output,
            Poll::Pending => unreachable!("Expected future to be ready"),
        }
    }

    fn test_cx() -> Cx<cap::All> {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 1)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    // =========================================================================
    // bracket() Function Tests
    // =========================================================================

    #[test]
    fn bracket_acquire_use_release_success() {
        let acquired = Arc::new(AtomicBool::new(false));
        let used = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));

        let acq = acquired.clone();
        let use_flag = used.clone();
        let rel = released.clone();

        let result = poll_ready(bracket(
            async move {
                acq.store(true, Ordering::SeqCst);
                Ok::<_, ()>(42)
            },
            move |x| {
                use_flag.store(true, Ordering::SeqCst);
                async move { Ok::<_, ()>(x * 2) }
            },
            move |_| {
                rel.store(true, Ordering::SeqCst);
                async {}
            },
        ));

        assert!(acquired.load(Ordering::SeqCst));
        assert!(used.load(Ordering::SeqCst));
        assert!(released.load(Ordering::SeqCst));
        assert_eq!(result, Ok(84));
    }

    #[test]
    fn bracket_acquire_failure_skips_use_and_release() {
        let used = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));

        let use_flag = used.clone();
        let rel = released.clone();

        let result = poll_ready(bracket(
            async { Err::<i32, _>("acquire failed") },
            move |_x| {
                use_flag.store(true, Ordering::SeqCst);
                async move { Ok::<_, &str>(0) }
            },
            move |_| {
                rel.store(true, Ordering::SeqCst);
                async {}
            },
        ));

        assert!(!used.load(Ordering::SeqCst));
        assert!(!released.load(Ordering::SeqCst));
        assert_eq!(result, Err(BracketError::Inner("acquire failed")));
    }

    #[test]
    fn bracket_use_failure_still_releases() {
        let released = Arc::new(AtomicBool::new(false));
        let rel = released.clone();

        let result = poll_ready(bracket(
            async { Ok::<_, &str>(42) },
            |_x| async { Err::<i32, _>("use failed") },
            move |_| {
                rel.store(true, Ordering::SeqCst);
                async {}
            },
        ));

        assert!(released.load(Ordering::SeqCst));
        assert_eq!(result, Err(BracketError::Inner("use failed")));
    }

    #[test]
    fn bracket_execution_order() {
        let order = Arc::new(Mutex::new(Vec::new()));

        let o1 = order.clone();
        let o2 = order.clone();
        let o3 = order.clone();

        let result = poll_ready(bracket(
            async move {
                o1.lock().push("acquire");
                Ok::<_, ()>("resource")
            },
            move |_| {
                o2.lock().push("use");
                async { Ok::<_, ()>("result") }
            },
            move |_| {
                o3.lock().push("release");
                async {}
            },
        ));

        let executed: Vec<&str> = order.lock().clone();
        drop(order);
        assert_eq!(executed, vec!["acquire", "use", "release"]);
        assert_eq!(result, Ok("result"));
    }

    #[test]
    fn bracket_resource_passed_to_use() {
        let result = poll_ready(bracket(
            async { Ok::<_, ()>(vec![1, 2, 3, 4, 5]) },
            |v| async move { Ok::<_, ()>(v.iter().sum::<i32>()) },
            |_| async {},
        ));

        assert_eq!(result, Ok(15));
    }

    #[test]
    fn bracket_resource_passed_to_release() {
        let released_value = Arc::new(Mutex::new(0i32));
        let rv = released_value.clone();

        let _ = poll_ready(bracket(
            async { Ok::<_, ()>(42) },
            |x| async move { Ok::<_, ()>(x) },
            move |x| {
                *rv.lock() = x;
                async {}
            },
        ));

        assert_eq!(*released_value.lock(), 42);
    }

    // =========================================================================
    // bracket_move() Function Tests
    // =========================================================================

    #[test]
    fn bracket_move_success() {
        let result = poll_ready(bracket_move(
            async { Ok::<_, ()>(42) },
            |x| (x * 2, None),
            |_| async {},
        ));

        assert_eq!(result, Ok(84));
    }

    #[test]
    fn bracket_move_acquire_failure() {
        let released = Arc::new(AtomicBool::new(false));
        let rel = released.clone();

        let result = poll_ready(bracket_move(
            async { Err::<i32, _>("acquire failed") },
            |x| (x, None),
            move |_| {
                rel.store(true, Ordering::SeqCst);
                async {}
            },
        ));

        assert!(!released.load(Ordering::SeqCst));
        assert_eq!(result, Err("acquire failed"));
    }

    #[test]
    fn bracket_move_releases_leftover() {
        let leftover_value = Arc::new(Mutex::new(None::<i32>));
        let lv = leftover_value.clone();

        let _ = poll_ready(bracket_move(
            async { Ok::<_, ()>(42) },
            |x| (x * 2, Some(x)),
            move |leftover| {
                *lv.lock() = leftover;
                async {}
            },
        ));

        assert_eq!(*leftover_value.lock(), Some(42));
    }

    #[test]
    fn bracket_move_releases_none_when_consumed() {
        let leftover_received = Arc::new(Mutex::new(Some(999i32)));
        let lr = leftover_received.clone();

        let _ = poll_ready(bracket_move(
            async { Ok::<_, ()>(42) },
            |_x| (100, None),
            move |leftover| {
                *lr.lock() = leftover;
                async {}
            },
        ));

        assert_eq!(*leftover_received.lock(), None);
    }

    #[test]
    fn bracket_move_no_clone_required() {
        struct NonCloneResource {
            value: i32,
        }

        let result = poll_ready(bracket_move(
            async { Ok::<_, ()>(NonCloneResource { value: 42 }) },
            |r| (r.value * 2, None),
            |_| async {},
        ));

        assert_eq!(result, Ok(84));
    }

    // =========================================================================
    // commit_section() Tests
    // =========================================================================

    #[test]
    fn commit_section_runs_future() {
        let cx = test_cx();
        let executed = Rc::new(Cell::new(false));
        let exec = executed.clone();

        let result = poll_ready(commit_section(&cx, 10, async move {
            exec.set(true);
            42
        }));

        assert!(executed.get());
        assert_eq!(result, 42);
    }

    #[test]
    fn commit_section_with_cancel_requested() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let executed = Rc::new(Cell::new(false));
        let exec = executed.clone();

        let result = poll_ready(commit_section(&cx, 10, async move {
            exec.set(true);
            "completed"
        }));

        assert!(executed.get());
        assert_eq!(result, "completed");
    }

    struct PendingThenCheckpoint<'a> {
        cx: &'a Cx,
        first_poll: bool,
    }

    impl Future for PendingThenCheckpoint<'_> {
        type Output = Result<(), crate::Error>;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.first_poll {
                self.first_poll = false;
                Poll::Pending
            } else {
                Poll::Ready(self.cx.checkpoint())
            }
        }
    }

    struct PendingThenCheckpointResult<'a> {
        cx: &'a Cx,
        first_poll: bool,
        value: i32,
    }

    impl Future for PendingThenCheckpointResult<'_> {
        type Output = Result<i32, crate::Error>;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.first_poll {
                self.first_poll = false;
                Poll::Pending
            } else {
                Poll::Ready(self.cx.checkpoint().map(|()| self.value))
            }
        }
    }

    #[test]
    fn commit_section_masks_checkpoint_on_later_polls() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(commit_section(
            &cx,
            10,
            PendingThenCheckpoint {
                cx: &cx,
                first_poll: true,
            },
        ));

        assert!(matches!(fut.as_mut().poll(&mut task_cx), Poll::Pending));

        let second = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(second, Poll::Ready(Ok(()))), "{second:?}");
    }

    #[test]
    fn commit_section_unmasks_after_max_polls() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(commit_section(
            &cx,
            1,
            PendingThenCheckpoint {
                cx: &cx,
                first_poll: true,
            },
        ));

        assert!(matches!(fut.as_mut().poll(&mut task_cx), Poll::Pending));

        let second = fut.as_mut().poll(&mut task_cx);
        match second {
            Poll::Ready(Err(err)) => assert!(err.is_cancelled(), "{err:?}"),
            other => panic!("expected cancelled result after masked poll budget, got {other:?}"),
        }
    }

    #[test]
    fn commit_section_zero_max_polls_never_masks() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let cx_clone = cx.clone();
        let result = poll_ready(commit_section(&cx, 0, async move { cx_clone.checkpoint() }));

        assert!(
            matches!(result, Err(ref err) if err.is_cancelled()),
            "{result:?}"
        );
    }

    #[test]
    fn commit_section_nested_masking_is_idempotent_once_budget_is_sufficient() {
        let cx = test_cx();
        cx.set_cancel_requested(true);
        let baseline_cx = cx.clone();
        let nested_inner_cx = cx.clone();

        let baseline = poll_ready(commit_section(
            &cx,
            1,
            async move { baseline_cx.checkpoint() },
        ));
        let nested = poll_ready(commit_section(
            &cx,
            1,
            commit_section(&cx, 1, async move { nested_inner_cx.checkpoint() }),
        ));

        assert!(baseline.is_ok(), "{baseline:?}");
        assert!(nested.is_ok(), "{nested:?}");
    }

    // =========================================================================
    // try_commit_section() Tests
    // =========================================================================

    #[test]
    fn try_commit_section_success() {
        let cx = test_cx();
        let result = poll_ready(try_commit_section(&cx, 10, async { Ok::<_, &str>(42) }));
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn try_commit_section_error() {
        let cx = test_cx();
        let result = poll_ready(try_commit_section(&cx, 10, async {
            Err::<i32, _>("error")
        }));
        assert_eq!(result, Err("error"));
    }

    #[test]
    fn try_commit_section_with_cancel_requested() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let executed = Rc::new(Cell::new(false));
        let exec = executed.clone();

        let result = poll_ready(try_commit_section(&cx, 10, async move {
            exec.set(true);
            Ok::<_, ()>(42)
        }));

        assert!(executed.get());
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn try_commit_section_masks_checkpoint_on_later_polls() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(try_commit_section(
            &cx,
            10,
            PendingThenCheckpointResult {
                cx: &cx,
                first_poll: true,
                value: 42,
            },
        ));

        assert!(matches!(fut.as_mut().poll(&mut task_cx), Poll::Pending));

        let second = fut.as_mut().poll(&mut task_cx);
        assert!(matches!(second, Poll::Ready(Ok(42))), "{second:?}");
    }

    #[test]
    fn try_commit_section_unmasks_after_max_polls() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut fut = Box::pin(try_commit_section(
            &cx,
            1,
            PendingThenCheckpointResult {
                cx: &cx,
                first_poll: true,
                value: 42,
            },
        ));

        assert!(matches!(fut.as_mut().poll(&mut task_cx), Poll::Pending));

        let second = fut.as_mut().poll(&mut task_cx);
        match second {
            Poll::Ready(Err(err)) => assert!(err.is_cancelled(), "{err:?}"),
            other => panic!("expected cancelled result after masked poll budget, got {other:?}"),
        }
    }

    #[test]
    fn try_commit_section_zero_max_polls_never_masks() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let cx_clone = cx.clone();
        let result = poll_ready(try_commit_section(&cx, 0, async move {
            cx_clone.checkpoint().map(|()| 42)
        }));

        assert!(
            matches!(result, Err(ref err) if err.is_cancelled()),
            "{result:?}"
        );
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn bracket_with_unit_resource() {
        let released = Arc::new(AtomicBool::new(false));
        let rel = released.clone();

        let result = poll_ready(bracket(
            async { Ok::<_, ()>(()) },
            |()| async { Ok::<_, ()>(42) },
            move |()| {
                rel.store(true, Ordering::SeqCst);
                async {}
            },
        ));

        assert!(released.load(Ordering::SeqCst));
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn bracket_with_large_resource() {
        let data: Vec<i32> = (0..1000).collect();

        let result = poll_ready(bracket(
            async { Ok::<_, ()>(data) },
            |v| async move { Ok::<_, ()>(v.iter().sum::<i32>()) },
            |_| async {},
        ));

        assert_eq!(result, Ok(499_500));
    }

    #[test]
    fn bracket_multiple_sequential() {
        let counter = Arc::new(AtomicUsize::new(0));

        for i in 0..5 {
            let c = counter.clone();
            let result = poll_ready(bracket(
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(i)
                },
                |x| async move { Ok::<_, ()>(x * 2) },
                |_| async {},
            ));
            assert_eq!(result, Ok(i * 2));
        }

        assert_eq!(counter.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn bracket_inferred_types() {
        let result = poll_ready(bracket(
            async { Ok::<i32, &str>(10) },
            |n| async move { Ok(format!("number: {n}")) },
            |_| async {},
        ));

        assert_eq!(result, Ok("number: 10".to_string()));
    }

    #[test]
    fn bracket_with_option_resource() {
        let result = poll_ready(bracket(
            async { Ok::<_, ()>(Some(42)) },
            |opt| async move { Ok::<_, ()>(opt.unwrap_or(0) * 2) },
            |_| async {},
        ));

        assert_eq!(result, Ok(84));
    }

    // =========================================================================
    // Drop-during-Releasing Regression Test
    // =========================================================================

    /// A release future that returns Pending on the first poll, then Ready
    /// on the second. Simulates a release that needs multiple polls.
    struct TwoPollRelease {
        done: bool,
        flag: Arc<AtomicBool>,
    }

    impl Future for TwoPollRelease {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            if self.done {
                self.flag.store(true, Ordering::SeqCst);
                Poll::Ready(())
            } else {
                self.done = true;
                Poll::Pending
            }
        }
    }

    struct NeverReadyRelease {
        polls: Arc<AtomicUsize>,
    }

    impl Future for NeverReadyRelease {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Pending
        }
    }

    struct PanicOnPollUse;

    impl Future for PanicOnPollUse {
        type Output = Result<(), ()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            panic!("use future panicked before release completed");
        }
    }

    /// Regression: if the bracket future is dropped while the release future
    /// is in progress (Releasing phase returns Pending then the bracket is
    /// dropped), the Drop handler must drive the release future to completion.
    /// Previously, the Drop handler only covered the Using phase, leaving the
    /// release abandoned if cancelled during Releasing.
    #[test]
    fn bracket_drop_during_releasing_drives_release_to_completion() {
        let released = Arc::new(AtomicBool::new(false));
        let rel = released.clone();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            async { Ok::<_, ()>(42_i32) },
            |x| async move { Ok::<_, ()>(x) },
            move |_| TwoPollRelease {
                done: false,
                flag: rel,
            },
        ));

        // First poll: acquire succeeds, use succeeds, release returns Pending.
        // Bracket is now in the Releasing phase.
        let poll1 = fut.as_mut().poll(&mut cx);
        assert!(
            poll1.is_pending(),
            "release future should return Pending on first poll"
        );
        assert!(!released.load(Ordering::SeqCst), "release not yet complete");

        // Drop the bracket while in Releasing phase.
        // The Drop handler must drive the release future to completion.
        drop(fut);

        assert!(
            released.load(Ordering::SeqCst),
            "release must complete even when bracket is dropped during Releasing phase"
        );
    }

    /// Clears its flag when dropped: stands for whatever the use future holds.
    struct HeldWhileAlive(Arc<AtomicBool>);

    impl Drop for HeldWhileAlive {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    /// Dropped during use, the bracket called release_fn while the use future
    /// was still alive, so a release that takes a lock the use future holds
    /// deadlocked.
    #[test]
    fn bracket_drop_during_use_drops_the_use_future_before_release_starts() {
        const NOT_CALLED: usize = 0;
        const USE_ALIVE: usize = 1;
        const USE_DROPPED: usize = 2;

        let held = Arc::new(AtomicBool::new(false));
        let use_held = held.clone();
        let release_held = held.clone();
        let release_saw = Arc::new(AtomicUsize::new(NOT_CALLED));
        let saw = release_saw.clone();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            async { Ok::<_, ()>(1_i32) },
            move |_| {
                use_held.store(true, Ordering::SeqCst);
                let guard = HeldWhileAlive(use_held);
                async move {
                    let _guard = guard;
                    std::future::pending::<()>().await;
                    Ok::<_, ()>(())
                }
            },
            move |_| {
                let seen = if release_held.load(Ordering::SeqCst) {
                    USE_ALIVE
                } else {
                    USE_DROPPED
                };
                saw.store(seen, Ordering::SeqCst);
                async {}
            },
        ));

        assert!(fut.as_mut().poll(&mut cx).is_pending());
        assert!(
            held.load(Ordering::SeqCst),
            "the use future must be running"
        );

        drop(fut);

        assert!(!held.load(Ordering::SeqCst));
        assert_eq!(
            release_saw.load(Ordering::SeqCst),
            USE_DROPPED,
            "release_fn must run after the use future is dropped (1 = it was still alive)"
        );
    }

    #[test]
    fn bracket_drop_during_releasing_panics_when_release_exhausts_poll_budget() {
        let polls = Arc::new(AtomicUsize::new(0));
        let release_polls = polls.clone();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            async { Ok::<_, ()>(42_i32) },
            |x| async move { Ok::<_, ()>(x) },
            move |_| NeverReadyRelease {
                polls: release_polls,
            },
        ));

        assert!(
            matches!(fut.as_mut().poll(&mut cx), Poll::Pending),
            "release future should require an external wake before drop"
        );

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(fut)));
        assert!(
            panic.is_err(),
            "drop must fail closed when release cannot complete under the cleanup poll budget"
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            DROP_RELEASE_POLL_BUDGET + 1,
            "drop should exhaust the bounded cleanup budget after the initial pending poll"
        );
    }

    #[test]
    fn bracket_drop_during_releasing_preserves_stored_use_panic() {
        let released = Arc::new(AtomicBool::new(false));
        let rel = released.clone();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            async { Ok::<_, ()>(42_i32) },
            |_x| PanicOnPollUse,
            move |_| TwoPollRelease {
                done: false,
                flag: rel,
            },
        ));

        let poll1 = fut.as_mut().poll(&mut cx);
        assert!(
            poll1.is_pending(),
            "panicking use future should still leave bracket pending until release finishes"
        );
        assert!(!released.load(Ordering::SeqCst), "release not yet complete");

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(fut)));
        assert!(
            panic.is_err(),
            "drop must rethrow the stored use panic after completing release"
        );
        assert!(
            released.load(Ordering::SeqCst),
            "drop should still finish the release future before rethrowing the use panic"
        );
    }

    struct NeverReadyUse;

    impl Future for NeverReadyUse {
        type Output = Result<(), ()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    struct PanicOnSecondPollRelease {
        first_poll: bool,
    }

    impl Future for PanicOnSecondPollRelease {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.first_poll {
                self.first_poll = false;
                Poll::Pending
            } else {
                panic!("release future panicked during drop"); // ubs:ignore - test assertion
            }
        }
    }

    #[test]
    fn bracket_drop_during_using_propagates_release_constructor_panic() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            async { Ok::<_, ()>(42_i32) },
            |_| NeverReadyUse,
            |_| -> std::future::Ready<()> { panic!("release constructor panicked during drop") },
        ));

        assert!(
            matches!(fut.as_mut().poll(&mut cx), Poll::Pending),
            "use future should still be pending before cancellation"
        );

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(fut)));
        assert!(
            panic.is_err(),
            "drop should surface release constructor panics when not already unwinding"
        );
    }

    #[test]
    fn bracket_drop_during_releasing_propagates_release_poll_panic() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            async { Ok::<_, ()>(42_i32) },
            |x| async move { Ok::<_, ()>(x) },
            |_| PanicOnSecondPollRelease { first_poll: true },
        ));

        assert!(
            matches!(fut.as_mut().poll(&mut cx), Poll::Pending),
            "release future should be pending before drop drives it again"
        );

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(fut)));
        assert!(
            panic.is_err(),
            "drop should surface release future panics when not already unwinding"
        );
    }

    struct PanicAcquireFuture;

    impl Future for PanicAcquireFuture {
        type Output = Result<i32, &'static str>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            panic!("acquire future panicked");
        }
    }

    struct ImmediatePanicRelease;

    impl Future for ImmediatePanicRelease {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            panic!("release future panicked during normal poll");
        }
    }

    struct PollCountingUse {
        polls: Arc<AtomicUsize>,
    }

    impl Future for PollCountingUse {
        type Output = Result<i32, &'static str>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(42))
        }
    }

    #[test]
    fn bracket_use_fn_panic_marks_future_done_after_unwind_is_caught() {
        let acquire_polls = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let rel = released.clone();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            PollCountingStream {
                polls: acquire_polls.clone(),
            },
            |_| -> std::future::Ready<Result<i32, &'static str>> {
                panic!("use_fn panicked during transition")
            },
            move |_| {
                rel.store(true, Ordering::SeqCst);
                async {}
            },
        ));

        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = fut.as_mut().poll(&mut cx);
        }));
        assert!(first.is_err(), "use_fn panic must still propagate");
        assert!(
            released.load(Ordering::SeqCst),
            "release must run before the panic escapes"
        );
        assert_eq!(acquire_polls.load(Ordering::SeqCst), 1);

        let second = fut.as_mut().poll(&mut cx);
        assert_eq!(
            second,
            Poll::Ready(Err(BracketError::PolledAfterCompletion))
        );
        assert_eq!(acquire_polls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn bracket_release_constructor_panic_marks_future_done_after_unwind_is_caught() {
        let use_polls = Arc::new(AtomicUsize::new(0));
        let use_polls_for_future = use_polls.clone();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            async { Ok::<_, &'static str>(42_i32) },
            move |_| PollCountingUse {
                polls: use_polls_for_future,
            },
            |_| -> std::future::Ready<()> { panic!("release constructor panicked") },
        ));

        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = fut.as_mut().poll(&mut cx);
        }));
        assert!(
            first.is_err(),
            "release constructor panic must still propagate"
        );
        assert_eq!(use_polls.load(Ordering::SeqCst), 1);

        let second = fut.as_mut().poll(&mut cx);
        assert_eq!(
            second,
            Poll::Ready(Err(BracketError::PolledAfterCompletion))
        );
        assert_eq!(use_polls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn bracket_acquire_panic_marks_future_done_after_unwind_is_caught() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            PanicAcquireFuture,
            |x| async move { Ok::<_, &'static str>(x) },
            |_| async {},
        ));

        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = fut.as_mut().poll(&mut cx);
        }));
        assert!(first.is_err(), "acquire panic must still propagate");

        let second = fut.as_mut().poll(&mut cx);
        assert_eq!(
            second,
            Poll::Ready(Err(BracketError::PolledAfterCompletion))
        );
    }

    #[test]
    fn bracket_release_poll_panic_marks_future_done_after_unwind_is_caught() {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            async { Ok::<_, &'static str>(42_i32) },
            |x| async move { Ok::<_, &'static str>(x) },
            |_| ImmediatePanicRelease,
        ));

        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = fut.as_mut().poll(&mut cx);
        }));
        assert!(first.is_err(), "release poll panic must still propagate");

        let second = fut.as_mut().poll(&mut cx);
        assert_eq!(
            second,
            Poll::Ready(Err(BracketError::PolledAfterCompletion))
        );
    }

    // =========================================================================
    // Repoll-after-completion Regression Test
    // =========================================================================

    #[derive(Debug)]
    struct PollCountingStream {
        polls: Arc<AtomicUsize>,
    }

    impl Future for PollCountingStream {
        type Output = Result<i32, &'static str>;
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(42))
        }
    }

    /// Regression: polling a `Bracket` after it has returned a terminal result
    /// must return `Err(BracketError::PolledAfterCompletion)` without touching
    /// upstream (acquire/use/release) futures.
    #[test]
    fn bracket_repoll_after_completion_returns_error_without_repolling_upstream() {
        let acquire_polls = Arc::new(AtomicUsize::new(0));
        let ap = acquire_polls.clone();

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut fut = Box::pin(bracket(
            PollCountingStream { polls: ap },
            |x| async move { Ok::<_, &str>(x * 2) },
            |_| async {},
        ));

        // First poll: completes normally.
        let first = fut.as_mut().poll(&mut cx);
        assert_eq!(first, Poll::Ready(Ok(84)));
        assert_eq!(acquire_polls.load(Ordering::SeqCst), 1);

        // Second poll: must return PolledAfterCompletion.
        let second = fut.as_mut().poll(&mut cx);
        assert_eq!(
            second,
            Poll::Ready(Err(BracketError::PolledAfterCompletion))
        );
        // Acquire stream must NOT have been polled again.
        assert_eq!(acquire_polls.load(Ordering::SeqCst), 1);
    }


    // asupersync-combinator-time-audit-fqdvqn: retirement must precede the
    // release constructor on normal and panic transitions, as it does on drop.
    mod retirement_order {
        use super::*;

        #[derive(Clone, Copy)]
        enum UseExit {
            Value,
            Error,
            Panicked,
        }

        struct GuardedTerminalUse<'a> {
            _guard: parking_lot::MutexGuard<'a, ()>,
            exit: UseExit,
            panic_on_drop: bool,
            drops: Arc<AtomicUsize>,
        }

        impl Future for GuardedTerminalUse<'_> {
            type Output = Result<u32, &'static str>;

            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
                match self.exit {
                    UseExit::Value => Poll::Ready(Ok(73)),
                    UseExit::Error => Poll::Ready(Err("use failed")),
                    UseExit::Panicked => panic!("use poll panic"),
                }
            }
        }

        impl Drop for GuardedTerminalUse<'_> {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                if self.panic_on_drop {
                    panic!("use destructor panic");
                }
            }
        }

        struct CountedRelease {
            polls: Arc<AtomicUsize>,
            completions: Arc<AtomicUsize>,
        }

        impl Future for CountedRelease {
            type Output = ();

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.polls.fetch_add(1, Ordering::SeqCst) == 0 {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    self.completions.fetch_add(1, Ordering::SeqCst);
                    Poll::Ready(())
                }
            }
        }

        fn poll_through_release<F: Future>(future: F, completions: &AtomicUsize) -> F::Output {
            // Own the bracket here so destructor panics exercise cleanup
            // during unwinding as well as the ordinary asynchronous path.
            let mut future = Box::pin(future);
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            assert!(
                future.as_mut().poll(&mut cx).is_pending(),
                "no use result or panic may escape while release is pending"
            );
            assert_eq!(completions.load(Ordering::SeqCst), 0);
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(result) => result,
                Poll::Pending => panic!("release must finish on its second poll"),
            }
        }

        fn check_use_retirement(
            exit: UseExit,
            panic_on_drop: bool,
            release_constructor_panics: bool,
        ) {
            let mutex = Mutex::new(());
            let drops = Arc::new(AtomicUsize::new(0));
            let constructors = AtomicUsize::new(0);
            let polls = Arc::new(AtomicUsize::new(0));
            let completions = Arc::new(AtomicUsize::new(0));
            let release_found_unlocked = AtomicBool::new(false);

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                poll_through_release(
                    bracket(
                        std::future::ready(Ok::<_, &'static str>(&mutex)),
                        |resource| GuardedTerminalUse {
                            _guard: resource.lock(),
                            exit,
                            panic_on_drop,
                            drops: Arc::clone(&drops),
                        },
                        |resource| {
                            constructors.fetch_add(1, Ordering::SeqCst);
                            // A blocking lock would hang the old implementation.
                            // Observe the same ownership defect without hanging.
                            release_found_unlocked
                                .store(resource.try_lock().is_some(), Ordering::SeqCst);
                            if release_constructor_panics {
                                panic!("release constructor panic");
                            }
                            CountedRelease {
                                polls: Arc::clone(&polls),
                                completions: Arc::clone(&completions),
                            }
                        },
                    ),
                    &completions,
                )
            }));

            let expected_panic = if release_constructor_panics {
                Some("release constructor panic")
            } else if panic_on_drop {
                Some("use destructor panic")
            } else if matches!(exit, UseExit::Panicked) {
                Some("use poll panic")
            } else {
                None
            };
            if let Some(expected) = expected_panic {
                let payload = result.expect_err("the original panic must escape");
                assert_eq!(payload.downcast_ref::<&str>().copied(), Some(expected));
            } else {
                let expected = match exit {
                    UseExit::Value => Ok(73),
                    UseExit::Error => Err(BracketError::Inner("use failed")),
                    UseExit::Panicked => unreachable!(),
                };
                assert_eq!(result.expect("ordinary outcomes must not panic"), expected);
            }

            assert_eq!(drops.load(Ordering::SeqCst), 1, "retire use exactly once");
            assert_eq!(constructors.load(Ordering::SeqCst), 1);
            assert!(
                release_found_unlocked.load(Ordering::SeqCst),
                "release must be constructed after the use future releases its lock"
            );
            assert!(mutex.try_lock().is_some());
            if release_constructor_panics {
                assert_eq!(polls.load(Ordering::SeqCst), 0);
                assert_eq!(completions.load(Ordering::SeqCst), 0);
            } else {
                assert_eq!(polls.load(Ordering::SeqCst), 2);
                assert_eq!(completions.load(Ordering::SeqCst), 1);
            }
        }

        #[test]
        fn release_constructor_runs_after_successful_use_future_is_dropped() {
            check_use_retirement(UseExit::Value, false, false);
        }

        #[test]
        fn release_constructor_runs_after_failed_use_future_is_dropped() {
            check_use_retirement(UseExit::Error, false, false);
        }

        #[test]
        fn release_constructor_runs_after_panicked_use_future_is_dropped() {
            check_use_retirement(UseExit::Panicked, false, false);
        }

        #[test]
        fn use_destructor_panic_still_installs_and_finishes_release_once() {
            check_use_retirement(UseExit::Value, true, false);
        }

        #[test]
        fn release_constructor_panic_still_takes_precedence_over_use_panic() {
            check_use_retirement(UseExit::Panicked, false, true);
            check_use_retirement(UseExit::Value, true, true);
        }

        #[test]
        fn caught_use_destructor_panic_keeps_release_owned_until_bracket_drop() {
            let mutex = Mutex::new(());
            let drops = Arc::new(AtomicUsize::new(0));
            let constructors = AtomicUsize::new(0);
            let polls = Arc::new(AtomicUsize::new(0));
            let completions = Arc::new(AtomicUsize::new(0));
            let release_found_unlocked = AtomicBool::new(false);
            let mut future = Box::pin(bracket(
                std::future::ready(Ok::<_, &'static str>(&mutex)),
                |resource| GuardedTerminalUse {
                    _guard: resource.lock(),
                    exit: UseExit::Value,
                    panic_on_drop: true,
                    drops: Arc::clone(&drops),
                },
                |resource| {
                    constructors.fetch_add(1, Ordering::SeqCst);
                    release_found_unlocked.store(resource.try_lock().is_some(), Ordering::SeqCst);
                    CountedRelease {
                        polls: Arc::clone(&polls),
                        completions: Arc::clone(&completions),
                    }
                },
            ));
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                future.as_mut().poll(&mut cx)
            }));
            let payload = first.expect_err("use destructor must unwind");
            assert_eq!(
                payload.downcast_ref::<&str>().copied(),
                Some("use destructor panic")
            );
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(constructors.load(Ordering::SeqCst), 1);
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert_eq!(completions.load(Ordering::SeqCst), 0);
            assert!(release_found_unlocked.load(Ordering::SeqCst));

            drop(future);

            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(constructors.load(Ordering::SeqCst), 1);
            assert_eq!(polls.load(Ordering::SeqCst), 2);
            assert_eq!(completions.load(Ordering::SeqCst), 1);
            assert!(mutex.try_lock().is_some());
        }

        struct GuardedAcquire<'a> {
            resource: &'a Mutex<()>,
            _guard: parking_lot::MutexGuard<'a, ()>,
            drops: Arc<AtomicUsize>,
        }

        impl<'a> Future for GuardedAcquire<'a> {
            type Output = Result<&'a Mutex<()>, &'static str>;

            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
                Poll::Ready(Ok(self.resource))
            }
        }

        impl Drop for GuardedAcquire<'_> {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        #[test]
        fn use_constructor_panic_retires_acquire_future_before_release() {
            let mutex = Mutex::new(());
            let drops = Arc::new(AtomicUsize::new(0));
            let constructors = AtomicUsize::new(0);
            let polls = Arc::new(AtomicUsize::new(0));
            let completions = Arc::new(AtomicUsize::new(0));
            let release_found_unlocked = AtomicBool::new(false);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                poll_through_release(
                    bracket(
                        GuardedAcquire {
                            resource: &mutex,
                            _guard: mutex.lock(),
                            drops: Arc::clone(&drops),
                        },
                        |_| -> std::future::Ready<Result<u32, &'static str>> {
                            panic!("use constructor panic")
                        },
                        |resource| {
                            constructors.fetch_add(1, Ordering::SeqCst);
                            release_found_unlocked
                                .store(resource.try_lock().is_some(), Ordering::SeqCst);
                            CountedRelease {
                                polls: Arc::clone(&polls),
                                completions: Arc::clone(&completions),
                            }
                        },
                    ),
                    &completions,
                )
            }));

            let payload = result.expect_err("use constructor panic must escape after release");
            assert_eq!(
                payload.downcast_ref::<&str>().copied(),
                Some("use constructor panic")
            );
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(constructors.load(Ordering::SeqCst), 1);
            assert_eq!(polls.load(Ordering::SeqCst), 2);
            assert_eq!(completions.load(Ordering::SeqCst), 1);
            assert!(
                release_found_unlocked.load(Ordering::SeqCst),
                "a completed acquire future must not retain its lock into release"
            );
            assert!(mutex.try_lock().is_some());
        }

        #[test]
        fn use_constructor_runs_after_completed_acquire_future_is_dropped() {
            let mutex = Mutex::new(());
            let drops = Arc::new(AtomicUsize::new(0));
            let constructors = AtomicUsize::new(0);
            let polls = Arc::new(AtomicUsize::new(0));
            let completions = Arc::new(AtomicUsize::new(0));
            let use_found_unlocked = AtomicBool::new(false);
            let release_found_unlocked = AtomicBool::new(false);
            let result = poll_through_release(
                bracket(
                    GuardedAcquire {
                        resource: &mutex,
                        _guard: mutex.lock(),
                        drops: Arc::clone(&drops),
                    },
                    |resource| {
                        use_found_unlocked.store(resource.try_lock().is_some(), Ordering::SeqCst);
                        std::future::ready(Ok::<_, &'static str>(73_u32))
                    },
                    |resource| {
                        constructors.fetch_add(1, Ordering::SeqCst);
                        release_found_unlocked
                            .store(resource.try_lock().is_some(), Ordering::SeqCst);
                        CountedRelease {
                            polls: Arc::clone(&polls),
                            completions: Arc::clone(&completions),
                        }
                    },
                ),
                &completions,
            );

            assert_eq!(result, Ok(73));
            assert!(
                use_found_unlocked.load(Ordering::SeqCst),
                "use must be constructed after the acquire future releases its lock"
            );
            assert!(release_found_unlocked.load(Ordering::SeqCst));
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(constructors.load(Ordering::SeqCst), 1);
            assert_eq!(polls.load(Ordering::SeqCst), 2);
            assert_eq!(completions.load(Ordering::SeqCst), 1);
        }

        struct PanickingAcquireDrop<'a>(GuardedAcquire<'a>);

        impl<'a> Future for PanickingAcquireDrop<'a> {
            type Output = Result<&'a Mutex<()>, &'static str>;

            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
                Poll::Ready(Ok(self.0.resource))
            }
        }

        impl Drop for PanickingAcquireDrop<'_> {
            fn drop(&mut self) {
                panic!("acquire destructor panic");
            }
        }

        #[test]
        fn acquire_destructor_panic_skips_use_and_waits_for_async_release() {
            let mutex = Mutex::new(());
            let drops = Arc::new(AtomicUsize::new(0));
            let use_called = AtomicBool::new(false);
            let constructors = AtomicUsize::new(0);
            let polls = Arc::new(AtomicUsize::new(0));
            let completions = Arc::new(AtomicUsize::new(0));
            let release_found_unlocked = AtomicBool::new(false);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                poll_through_release(
                    bracket(
                        PanickingAcquireDrop(GuardedAcquire {
                            resource: &mutex,
                            _guard: mutex.lock(),
                            drops: Arc::clone(&drops),
                        }),
                        |_| {
                            use_called.store(true, Ordering::SeqCst);
                            std::future::ready(Ok::<_, &'static str>(73_u32))
                        },
                        |resource| {
                            constructors.fetch_add(1, Ordering::SeqCst);
                            release_found_unlocked
                                .store(resource.try_lock().is_some(), Ordering::SeqCst);
                            CountedRelease {
                                polls: Arc::clone(&polls),
                                completions: Arc::clone(&completions),
                            }
                        },
                    ),
                    &completions,
                )
            }));

            let payload = result.expect_err("acquire destructor panic must escape after release");
            assert_eq!(
                payload.downcast_ref::<&str>().copied(),
                Some("acquire destructor panic")
            );
            assert!(!use_called.load(Ordering::SeqCst));
            assert!(release_found_unlocked.load(Ordering::SeqCst));
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(constructors.load(Ordering::SeqCst), 1);
            assert_eq!(polls.load(Ordering::SeqCst), 2);
            assert_eq!(completions.load(Ordering::SeqCst), 1);
            assert!(mutex.try_lock().is_some());
        }
    }
