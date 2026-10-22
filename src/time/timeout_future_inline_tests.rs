    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::Cx;
    use crate::test_utils::init_test_logging;
    use crate::time::{TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId};
    use std::future::Future;
    use std::future::{pending, ready};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    // =========================================================================
    // Construction Tests
    // =========================================================================

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    // Each test that needs a shared time source should use thread_local!
    // to avoid races when tests run in parallel.
    thread_local! {
        static CURRENT_TIME: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn set_current_time(nanos: u64) {
        CURRENT_TIME.with(|t| t.set(nanos));
    }

    fn get_current_time() -> u64 {
        CURRENT_TIME.with(std::cell::Cell::get)
    }

    struct CountingFuture {
        count: u32,
        ready_at: u32,
    }

    impl Future for CountingFuture {
        type Output = &'static str;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.count += 1;
            if self.count >= self.ready_at {
                Poll::Ready("done")
            } else {
                Poll::Pending
            }
        }
    }

    impl Unpin for CountingFuture {}

    struct ReadyOncePanicsOnRepoll {
        polled: bool,
    }

    impl Future for ReadyOncePanicsOnRepoll {
        type Output = &'static str;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            assert!(!self.polled, "inner future was polled after completion");
            self.polled = true;
            Poll::Ready("done")
        }
    }

    impl Unpin for ReadyOncePanicsOnRepoll {}

    struct ReadyAtTime {
        ready_at: Time,
    }

    impl Future for ReadyAtTime {
        type Output = &'static str;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if Time::from_nanos(get_current_time()) >= self.ready_at {
                Poll::Ready("done")
            } else {
                Poll::Pending
            }
        }
    }

    impl Unpin for ReadyAtTime {}

    struct ReadyWhenTimerReaches {
        timer: TimerDriverHandle,
        ready_at: Time,
    }

    #[test]
    fn owner_cancellation_preserves_pending_cleanup_until_real_deadline() {
        use crate::channel::oneshot;
        use crate::types::{CancelKind, Outcome};
        use std::sync::atomic::{AtomicBool, Ordering};

        for explicit_time in [false, true] {
            for release_cleanup in [false, true] {
                let clock = Arc::new(VirtualClock::new());
                let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
                let owner = Cx::new_with_drivers(
                    RegionId::new_for_test(1, 0),
                    TaskId::new_for_test(1, 0),
                    Budget::INFINITE,
                    None,
                    None,
                    None,
                    Some(timer.clone()),
                    None,
                );
                let _guard = Cx::set_current(Some(owner.clone()));
                let (release, mut cleanup) = oneshot::channel::<()>();
                let observed = Arc::new(AtomicBool::new(false));
                let inner_owner = owner.clone();
                let inner_observed = Arc::clone(&observed);
                let inner = Box::pin(async move {
                    inner_owner.cancelled().await;
                    assert!(
                        inner_owner.checkpoint().is_err(),
                        "inner must remain unmasked"
                    );
                    inner_observed.store(true, Ordering::Release);
                    // Real channel wait: cancellation starts cleanup but does
                    // not complete it. Only the external receipt may do that.
                    cleanup
                        .recv_uninterruptible()
                        .await
                        .expect("cleanup receipt");
                    Outcome::<(), ()>::Cancelled(inner_owner.cancel_reason().unwrap())
                });
                let deadline = Time::from_millis(5);
                let mut future = TimeoutFuture::new(inner, deadline);
                let mut task = Context::from_waker(Waker::noop());
                let mut poll = |future: &mut TimeoutFuture<_>| {
                    if explicit_time {
                        future.poll_with_time(&mut task, timer.now())
                    } else {
                        Pin::new(future).poll(&mut task)
                    }
                };
                assert!(poll(&mut future).is_pending());
                assert_eq!(timer.pending_count(), 1);
                owner.cancel_with(CancelKind::User, Some("cancel operation, await cleanup"));
                assert!(
                    poll(&mut future).is_pending(),
                    "cancellation is not elapsed time"
                );
                assert!(observed.load(Ordering::Acquire));
                assert_eq!(timer.now(), Time::ZERO);
                assert_eq!(timer.pending_count(), 1);

                if release_cleanup {
                    release.send_blocking(()).unwrap();
                    assert!(matches!(poll(&mut future),
                        Poll::Ready(Ok(Outcome::Cancelled(reason)))
                            if reason.kind == CancelKind::User
                                && reason.message.as_deref() == Some("cancel operation, await cleanup")));
                } else {
                    clock.advance_to(deadline);
                    assert_eq!(timer.process_timers(), 1);
                    assert!(matches!(poll(&mut future),
                        Poll::Ready(Err(elapsed)) if elapsed.deadline() == deadline));
                }
                drop(future);
                assert_eq!(timer.pending_count(), 0);
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "bead": "asupersync-bi2462.110",
                        "scenario": "owner_cancel_does_not_expire_timeout",
                        "explicit_time": explicit_time,
                        "cleanup_receipt": release_cleanup,
                        "inner_observed_cancel": observed.load(Ordering::Acquire),
                        "now_ns": timer.now().as_nanos(),
                        "deadline_ns": deadline.as_nanos(),
                        "pending_after_drop": timer.pending_count(),
                    })
                );
            }
        }
    }

    impl Future for ReadyWhenTimerReaches {
        type Output = &'static str;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.timer.now() >= self.ready_at {
                Poll::Ready("done")
            } else {
                Poll::Pending
            }
        }
    }

    #[test]
    fn new_creates_timeout() {
        init_test("new_creates_timeout");
        let future = ready(42);
        let timeout = TimeoutFuture::new(future, Time::from_secs(5));
        crate::assert_with_log!(
            timeout.deadline() == Time::from_secs(5),
            "deadline",
            Time::from_secs(5),
            timeout.deadline()
        );
        crate::test_complete!("new_creates_timeout");
    }

    #[test]
    fn after_computes_deadline() {
        init_test("after_computes_deadline");
        let future = ready(42);
        let timeout = TimeoutFuture::after(Time::from_secs(10), Duration::from_secs(5), future);
        crate::assert_with_log!(
            timeout.deadline() == Time::from_secs(15),
            "deadline",
            Time::from_secs(15),
            timeout.deadline()
        );
        crate::test_complete!("after_computes_deadline");
    }

    #[test]
    fn timeout_function() {
        init_test("timeout_function");
        let t = timeout(Time::from_secs(10), Duration::from_secs(3), ready(42));
        crate::assert_with_log!(
            t.deadline() == Time::from_secs(13),
            "deadline",
            Time::from_secs(13),
            t.deadline()
        );
        crate::test_complete!("timeout_function");
    }

    #[test]
    fn timeout_at_function() {
        init_test("timeout_at_function");
        let t = timeout_at(Time::from_secs(42), ready(123));
        crate::assert_with_log!(
            t.deadline() == Time::from_secs(42),
            "deadline",
            Time::from_secs(42),
            t.deadline()
        );
        crate::test_complete!("timeout_at_function");
    }

    // =========================================================================
    // Accessor Tests
    // =========================================================================

    #[test]
    fn remaining_before_deadline() {
        init_test("remaining_before_deadline");
        let t = TimeoutFuture::new(ready(42), Time::from_secs(10));
        let remaining = t.remaining(Time::from_secs(7));
        crate::assert_with_log!(
            remaining == Duration::from_secs(3),
            "remaining",
            Duration::from_secs(3),
            remaining
        );
        crate::test_complete!("remaining_before_deadline");
    }

    #[test]
    fn remaining_after_deadline() {
        init_test("remaining_after_deadline");
        let t = TimeoutFuture::new(ready(42), Time::from_secs(10));
        let remaining = t.remaining(Time::from_secs(15));
        crate::assert_with_log!(
            remaining == Duration::ZERO,
            "remaining",
            Duration::ZERO,
            remaining
        );
        crate::test_complete!("remaining_after_deadline");
    }

    #[test]
    fn is_elapsed() {
        init_test("is_elapsed");
        let t = TimeoutFuture::new(ready(42), Time::from_secs(10));
        crate::assert_with_log!(
            !t.is_elapsed(Time::from_secs(5)),
            "not elapsed at t=5",
            false,
            t.is_elapsed(Time::from_secs(5))
        );
        crate::assert_with_log!(
            t.is_elapsed(Time::from_secs(10)),
            "elapsed at t=10",
            true,
            t.is_elapsed(Time::from_secs(10))
        );
        crate::assert_with_log!(
            t.is_elapsed(Time::from_secs(15)),
            "elapsed at t=15",
            true,
            t.is_elapsed(Time::from_secs(15))
        );
        crate::test_complete!("is_elapsed");
    }

    #[test]
    fn inner() {
        init_test("inner");
        let future = ready(42);
        let t = TimeoutFuture::new(future, Time::from_secs(5));
        let _ = t.inner(); // Just check it compiles
        crate::test_complete!("inner");
    }

    #[test]
    fn inner_mut() {
        init_test("inner_mut");
        let future = ready(42);
        let mut t = TimeoutFuture::new(future, Time::from_secs(5));
        let _inner = t.inner_mut(); // Just check it compiles
        crate::test_complete!("inner_mut");
    }

    #[test]
    fn into_inner() {
        init_test("into_inner");
        let future = ready(42);
        let t = TimeoutFuture::new(future, Time::from_secs(5));
        let _inner = t.into_inner();
        crate::test_complete!("into_inner");
    }

    // =========================================================================
    // Reset Tests
    // =========================================================================

    #[test]
    fn reset_changes_deadline() {
        init_test("reset_changes_deadline");
        let mut t = TimeoutFuture::new(ready(42), Time::from_secs(5));
        t.reset(Time::from_secs(10));
        crate::assert_with_log!(
            t.deadline() == Time::from_secs(10),
            "deadline",
            Time::from_secs(10),
            t.deadline()
        );
        crate::test_complete!("reset_changes_deadline");
    }

    #[test]
    fn reset_after_changes_deadline() {
        init_test("reset_after_changes_deadline");
        let mut t = TimeoutFuture::new(ready(42), Time::from_secs(5));
        t.reset_after(Time::from_secs(3), Duration::from_secs(7));
        crate::assert_with_log!(
            t.deadline() == Time::from_secs(10),
            "deadline",
            Time::from_secs(10),
            t.deadline()
        );
        crate::test_complete!("reset_after_changes_deadline");
    }

    #[test]
    fn reset_after_inner_success_stays_terminal_for_poll_with_time() {
        init_test("reset_after_inner_success_stays_terminal_for_poll_with_time");
        let mut t = TimeoutFuture::new(
            ReadyOncePanicsOnRepoll { polled: false },
            Time::from_secs(5),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = t.poll_with_time(&mut cx, Time::from_secs(1));
        assert!(matches!(first, Poll::Ready(Ok("done"))));

        t.reset(Time::from_secs(10));
        let second = t.poll_with_time(&mut cx, Time::from_secs(2));
        assert!(matches!(second, Poll::Ready(Err(_))));
        crate::test_complete!("reset_after_inner_success_stays_terminal_for_poll_with_time");
    }

    #[test]
    fn reset_after_inner_success_stays_terminal_for_future_poll() {
        init_test("reset_after_inner_success_stays_terminal_for_future_poll");
        let mut t = TimeoutFuture::new(
            ReadyOncePanicsOnRepoll { polled: false },
            Time::from_secs(5),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut t).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Ok("done"))));

        t.reset_after(Time::from_secs(3), Duration::from_secs(7));
        let second = Pin::new(&mut t).poll(&mut cx);
        assert!(matches!(second, Poll::Ready(Err(_))));
        crate::test_complete!("reset_after_inner_success_stays_terminal_for_future_poll");
    }

    // =========================================================================
    // poll_with_time Tests
    // =========================================================================

    #[test]
    fn poll_with_time_future_completes() {
        init_test("poll_with_time_future_completes");
        let mut t = TimeoutFuture::new(ready(42), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Time is before deadline, future is ready
        let result = t.poll_with_time(&mut cx, Time::from_secs(5));
        let ready = matches!(result, Poll::Ready(Ok(42)));
        crate::assert_with_log!(ready, "ready ok", true, ready);
        crate::test_complete!("poll_with_time_future_completes");
    }

    #[test]
    fn poll_with_time_timeout_elapsed() {
        init_test("poll_with_time_timeout_elapsed");
        let mut t = TimeoutFuture::new(pending::<i32>(), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Time is past deadline
        let result = t.poll_with_time(&mut cx, Time::from_secs(15));
        let elapsed = matches!(result, Poll::Ready(Err(_)));
        crate::assert_with_log!(elapsed, "elapsed", true, elapsed);

        if let Poll::Ready(Err(elapsed)) = result {
            crate::assert_with_log!(
                elapsed.deadline() == Time::from_secs(10),
                "deadline",
                Time::from_secs(10),
                elapsed.deadline()
            );
        }
        crate::test_complete!("poll_with_time_timeout_elapsed");
    }

    #[test]
    fn poll_with_time_pending() {
        init_test("poll_with_time_pending");
        let mut t = TimeoutFuture::new(pending::<i32>(), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Time is before deadline, future is pending
        let result = t.poll_with_time(&mut cx, Time::from_secs(5));
        crate::assert_with_log!(result.is_pending(), "pending", true, result.is_pending());
        crate::test_complete!("poll_with_time_pending");
    }

    #[test]
    fn poll_with_time_at_exact_deadline() {
        init_test("poll_with_time_at_exact_deadline");
        let mut t = TimeoutFuture::new(pending::<i32>(), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Time is exactly at deadline
        let result = t.poll_with_time(&mut cx, Time::from_secs(10));
        let elapsed = matches!(result, Poll::Ready(Err(_)));
        crate::assert_with_log!(elapsed, "elapsed at deadline", true, elapsed);
        crate::test_complete!("poll_with_time_at_exact_deadline");
    }

    #[test]
    fn poll_with_time_zero_deadline() {
        init_test("poll_with_time_zero_deadline");
        let mut t = TimeoutFuture::new(pending::<i32>(), Time::ZERO);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Even at time zero, deadline is reached
        let result = t.poll_with_time(&mut cx, Time::ZERO);
        let elapsed = matches!(result, Poll::Ready(Err(_)));
        crate::assert_with_log!(elapsed, "elapsed at zero", true, elapsed);
        crate::test_complete!("poll_with_time_zero_deadline");
    }

    #[test]
    fn poll_with_time_ready_inner_wins_elapsed_deadline_boundary() {
        let mut t = TimeoutFuture::new(ready("done"), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = t.poll_with_time(&mut cx, Time::from_secs(10));

        assert!(matches!(result, Poll::Ready(Ok("done"))));
    }

    #[test]
    fn poll_with_time_elapsed_wins_late_poll_before_later_ready_inner() {
        set_current_time(0);
        let mut t = TimeoutFuture::with_time_getter(
            ReadyAtTime {
                ready_at: Time::from_secs(50),
            },
            Time::from_secs(10),
            test_now,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(t.poll_with_time(&mut cx, Time::ZERO).is_pending());

        set_current_time(50_000_000_000);
        let result = t.poll_with_time(&mut cx, Time::from_secs(50));

        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn poll_with_time_elapsed_deadline_clears_registered_timer() {
        let clock = Arc::new(crate::time::VirtualClock::new());
        let timer_driver = crate::time::TimerDriverHandle::with_virtual_clock(clock);
        let mut t = TimeoutFuture {
            future: pending::<()>(),
            sleep: Sleep::with_timer_driver(Time::from_secs(10), timer_driver.clone()),
            completed: false,
            timed_out: false,
        };
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Pin::new(&mut t).poll(&mut cx).is_pending());
        assert_eq!(timer_driver.pending_count(), 1);

        let result = t.poll_with_time(&mut cx, Time::from_secs(10));

        assert!(matches!(result, Poll::Ready(Err(_))));
        assert_eq!(timer_driver.pending_count(), 0);
    }

    #[test]
    fn poll_with_time_returns_elapsed_after_success_completion() {
        let mut t = TimeoutFuture::new(ready(42), Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = t.poll_with_time(&mut cx, Time::from_secs(5));
        assert!(matches!(first, Poll::Ready(Ok(42))));

        // Fail-closed: repoll returns Elapsed instead of panicking
        let repoll = t.poll_with_time(&mut cx, Time::from_secs(6));
        assert!(matches!(repoll, Poll::Ready(Err(_))));
    }

    #[test]
    fn poll_with_time_returns_elapsed_after_timeout_until_reset() {
        set_current_time(0);
        let future = CountingFuture {
            count: 0,
            ready_at: 3,
        };
        let mut t = TimeoutFuture::with_time_getter(future, Time::from_secs(5), test_now);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(t.poll_with_time(&mut cx, Time::from_secs(0)).is_pending());

        let elapsed = t.poll_with_time(&mut cx, Time::from_secs(10));
        assert!(matches!(elapsed, Poll::Ready(Err(_))));

        // Fail-closed: repoll returns Elapsed instead of panicking
        let repoll = t.poll_with_time(&mut cx, Time::from_secs(11));
        assert!(matches!(repoll, Poll::Ready(Err(_))));

        t.reset(Time::from_secs(20));
        let resumed = t.poll_with_time(&mut cx, Time::from_secs(12));
        assert!(resumed.is_pending());
        let resumed = t.poll_with_time(&mut cx, Time::from_secs(12));
        assert!(matches!(resumed, Poll::Ready(Ok("done"))));
    }

    fn test_now() -> Time {
        Time::from_nanos(get_current_time())
    }

    #[test]
    fn poll_returns_elapsed_after_success_completion() {
        set_current_time(0);
        let mut t = TimeoutFuture::with_time_getter(ready(42), Time::from_secs(10), test_now);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut t).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Ok(42))));

        // Fail-closed: repoll returns Elapsed instead of panicking
        let repoll = Pin::new(&mut t).poll(&mut cx);
        assert!(matches!(repoll, Poll::Ready(Err(_))));
    }

    #[test]
    fn poll_returns_elapsed_after_timeout_until_reset() {
        set_current_time(0);
        let future = CountingFuture {
            count: 0,
            ready_at: 3,
        };
        let mut t = TimeoutFuture::with_time_getter(future, Time::from_secs(5), test_now);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Pin::new(&mut t).poll(&mut cx).is_pending());

        set_current_time(10_000_000_000);
        let elapsed = Pin::new(&mut t).poll(&mut cx);
        assert!(matches!(elapsed, Poll::Ready(Err(_))));

        // Fail-closed: repoll returns Elapsed instead of panicking
        let repoll = Pin::new(&mut t).poll(&mut cx);
        assert!(matches!(repoll, Poll::Ready(Err(_))));

        t.reset(Time::from_secs(20));
        set_current_time(12_000_000_000);
        let resumed = Pin::new(&mut t).poll(&mut cx);
        assert!(matches!(resumed, Poll::Ready(Ok("done"))));
    }

    #[test]
    fn poll_ready_inner_wins_elapsed_deadline_boundary() {
        set_current_time(10_000_000_000);
        let mut t = TimeoutFuture::with_time_getter(ready("done"), Time::from_secs(10), test_now);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = Pin::new(&mut t).poll(&mut cx);

        assert!(matches!(result, Poll::Ready(Ok("done"))));
    }

    #[test]
    fn poll_elapsed_wins_late_timer_driver_poll_before_later_ready_inner() {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let runtime_cx = Cx::new_with_drivers(
            RegionId::new_for_test(0, 12),
            TaskId::new_for_test(0, 12),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _guard = Cx::set_current(Some(runtime_cx));
        let mut t = TimeoutFuture::new(
            ReadyWhenTimerReaches {
                timer: timer.clone(),
                ready_at: Time::from_secs(50),
            },
            Time::from_secs(10),
        );
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        assert!(Pin::new(&mut t).poll(&mut task_cx).is_pending());

        clock.set(Time::from_secs(50));
        let result = Pin::new(&mut t).poll(&mut task_cx);

        assert!(matches!(result, Poll::Ready(Err(_))));
    }

    #[test]
    fn custom_clock_timeout_ignores_runtime_wakes_until_its_deadline() {
        for explicit_time in [false, true] {
            let clock = Arc::new(VirtualClock::new());
            clock.set(Time::from_secs(100));
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let owner = Cx::new_with_drivers(
                RegionId::new_for_test(0, 121),
                TaskId::new_for_test(0, 121),
                Budget::INFINITE,
                None,
                None,
                None,
                Some(timer.clone()),
                None,
            );
            let _current = Cx::set_current(Some(owner));
            set_current_time(0);
            let mut timeout =
                TimeoutFuture::with_time_getter(pending::<()>(), Time::from_secs(5), test_now);
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);
            let first = if explicit_time {
                timeout.poll_with_time(&mut cx, test_now())
            } else {
                Pin::new(&mut timeout).poll(&mut cx)
            };
            assert!(first.is_pending());
            assert_eq!(timer.next_deadline(), Some(Time::from_secs(105)));

            clock.set(Time::from_secs(105));
            assert_eq!(timer.process_timers(), 1);
            let still_pending = if explicit_time {
                timeout.poll_with_time(&mut cx, test_now())
            } else {
                Pin::new(&mut timeout).poll(&mut cx)
            };
            assert!(still_pending.is_pending());
            assert_eq!(timer.next_deadline(), Some(Time::from_secs(110)));

            set_current_time(Time::from_secs(5).as_nanos());
            let elapsed = if explicit_time {
                timeout.poll_with_time(&mut cx, test_now())
            } else {
                Pin::new(&mut timeout).poll(&mut cx)
            };
            assert_eq!(elapsed, Poll::Ready(Err(Elapsed::new(Time::from_secs(5)))));
            assert_eq!(timer.pending_count(), 0);
        }
    }

    #[test]
    fn custom_clock_timeout_preserves_ready_inner_at_deadline_after_runtime_wake() {
        let clock = Arc::new(VirtualClock::new());
        clock.set(Time::from_secs(100));
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let owner = Cx::new_with_drivers(
            RegionId::new_for_test(0, 122),
            TaskId::new_for_test(0, 122),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let _current = Cx::set_current(Some(owner));
        set_current_time(0);
        let mut timeout = TimeoutFuture::with_time_getter(
            ReadyAtTime {
                ready_at: Time::from_secs(5),
            },
            Time::from_secs(5),
            test_now,
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut timeout).poll(&mut cx).is_pending());
        clock.set(Time::from_secs(105));
        assert_eq!(timer.process_timers(), 1);
        assert!(Pin::new(&mut timeout).poll(&mut cx).is_pending());
        set_current_time(Time::from_secs(5).as_nanos());
        assert_eq!(
            Pin::new(&mut timeout).poll(&mut cx),
            Poll::Ready(Ok("done"))
        );
        drop(timeout);
        assert_eq!(timer.pending_count(), 0);
    }

    // =========================================================================
    // Clone Tests
    // =========================================================================

    #[test]
    fn clone_copies_deadline_and_future() {
        init_test("clone_copies_deadline_and_future");
        let t = TimeoutFuture::new(ready(42), Time::from_secs(10));
        let t2 = t.clone();
        crate::assert_with_log!(
            t.deadline() == Time::from_secs(10),
            "t deadline",
            Time::from_secs(10),
            t.deadline()
        );
        crate::assert_with_log!(
            t2.deadline() == Time::from_secs(10),
            "t2 deadline",
            Time::from_secs(10),
            t2.deadline()
        );
        crate::test_complete!("clone_copies_deadline_and_future");
    }

    // =========================================================================
    // Integration Scenario Tests
    // =========================================================================

    #[test]
    fn simulated_timeout_scenario() {
        init_test("simulated_timeout_scenario");
        set_current_time(0);
        // Simulate a scenario where we poll multiple times as time advances

        let mut t = TimeoutFuture::with_time_getter(pending::<i32>(), Time::from_secs(5), test_now);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // t=0: pending
        let pending = t.poll_with_time(&mut cx, Time::ZERO).is_pending();
        crate::assert_with_log!(pending, "pending at t=0", true, pending);

        // t=2: still pending
        let pending = t.poll_with_time(&mut cx, Time::from_secs(2)).is_pending();
        crate::assert_with_log!(pending, "pending at t=2", true, pending);

        // t=4: still pending
        let pending = t.poll_with_time(&mut cx, Time::from_secs(4)).is_pending();
        crate::assert_with_log!(pending, "pending at t=4", true, pending);

        // t=5: timeout!
        let result = t.poll_with_time(&mut cx, Time::from_secs(5));
        let elapsed = matches!(result, Poll::Ready(Err(_)));
        crate::assert_with_log!(elapsed, "elapsed at t=5", true, elapsed);
        crate::test_complete!("simulated_timeout_scenario");
    }

    #[test]
    fn simulated_success_scenario() {
        init_test("simulated_success_scenario");
        // Future that completes on the 3rd poll
        let future = CountingFuture {
            count: 0,
            ready_at: 3,
        };
        let mut t = TimeoutFuture::new(future, Time::from_secs(10));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Poll 1: pending
        let pending = t.poll_with_time(&mut cx, Time::from_secs(1)).is_pending();
        crate::assert_with_log!(pending, "pending at t=1", true, pending);

        // Poll 2: pending
        let pending = t.poll_with_time(&mut cx, Time::from_secs(2)).is_pending();
        crate::assert_with_log!(pending, "pending at t=2", true, pending);

        // Poll 3: ready!
        let result = t.poll_with_time(&mut cx, Time::from_secs(3));
        let ready = matches!(result, Poll::Ready(Ok("done")));
        crate::assert_with_log!(ready, "ready at t=3", true, ready);
        crate::test_complete!("simulated_success_scenario");
    }

    // =========================================================================
    // Helper Functions
    // =========================================================================

    /// Creates a no-op waker for testing.
    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }
