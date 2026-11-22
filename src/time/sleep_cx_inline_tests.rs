use super::*;
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::time::{TimeSource, TimerDriver, VirtualClock};
use crate::types::{Budget, CancelKind, RegionId, TaskId};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::{Context, Wake, Waker};

fn context_with_driver(budget: Budget, driver: TimerDriverHandle) -> Cx {
    Cx::new_with_drivers(
        RegionId::new_for_test(0, 1),
        TaskId::new_for_test(0, 0),
        budget,
        None,
        None,
        None,
        Some(driver),
        None,
    )
}

fn virtual_context(budget: Budget) -> (Cx, Arc<VirtualClock>, TimerDriverHandle) {
    let clock = Arc::new(VirtualClock::new());
    let driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let cx = context_with_driver(budget, driver.clone());
    (cx, clock, driver)
}

fn ready_result(future: impl Future<Output = Result<(), SleepError>>) -> Result<(), SleepError> {
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("expected a ready context-driven sleep"),
    }
}

fn registrations(cx: &Cx) -> usize {
    cx.inner.read().cancel_waker_registrations.len()
}

#[derive(Default)]
struct CountWake(AtomicUsize);

impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn relative_sleep_starts_on_first_poll_and_cleans_up_on_completion() {
    let (cx, clock, driver) = virtual_context(Budget::INFINITE);
    let mut waiting = Box::pin(sleep_cx(&cx, Duration::from_millis(100)));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
    clock.advance_to(Time::from_millis(50));

    let counter = Arc::new(CountWake::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut task = Context::from_waker(&waker);
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    assert_eq!(driver.next_deadline(), Some(Time::from_millis(150)));
    assert_eq!(driver.pending_count(), 1);
    assert_eq!(registrations(&cx), 1);
    clock.advance_to(Time::from_millis(149));
    assert_eq!(driver.process_timers(), 0);
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    assert_eq!(counter.0.load(Ordering::Acquire), 0);

    clock.advance_to(Time::from_millis(150));
    assert_eq!(driver.process_timers(), 1);
    assert!(counter.0.load(Ordering::Acquire) > 0);
    assert!(matches!(waiting.as_mut().poll(&mut task), Poll::Ready(Ok(()))));
    // Terminal cleanup must not depend on dropping the completed future.
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
}

#[test]
fn absolute_sleep_uses_the_explicit_context_instead_of_the_ambient_context() {
    let (cx, clock, driver) = virtual_context(Budget::INFINITE);
    let (ambient, ambient_clock, ambient_driver) = virtual_context(Budget::INFINITE);
    ambient_clock.advance_to(Time::from_secs(100));
    ambient.cancel_fast(CancelKind::User);
    let _ambient = Cx::set_current(Some(ambient));

    let mut waiting = Box::pin(sleep_until_cx(&cx, Time::from_millis(100)));
    let mut task = Context::from_waker(Waker::noop());
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    assert_eq!(driver.next_deadline(), Some(Time::from_millis(100)));
    assert!(ambient_driver.is_empty());
    clock.advance_to(Time::from_millis(100));
    assert_eq!(driver.process_timers(), 1);
    assert!(matches!(waiting.as_mut().poll(&mut task), Poll::Ready(Ok(()))));
    assert!(driver.is_empty());
    assert!(ambient_driver.is_empty());
    assert_eq!(registrations(&cx), 0);
    assert!(ready_result(sleep_until_cx(&cx, Time::ZERO)).is_ok());
}

#[test]
fn cancellation_wakes_a_parked_sleep_and_preserves_the_entire_reason() {
    for reason in [
        CancelReason::user("fallible sleep cancellation"),
        CancelReason::timeout()
            .with_message("timeout witness")
            .with_cause(CancelReason::user("caller stopped")),
        CancelReason::deadline(),
        CancelReason::shutdown(),
    ] {
        let (cx, _, driver) = virtual_context(Budget::INFINITE);
        let counter = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut task = Context::from_waker(&waker);
        let mut waiting = Box::pin(sleep_cx(&cx, Duration::from_secs(3600)));
        assert!(waiting.as_mut().poll(&mut task).is_pending());
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(registrations(&cx), 1);

        cx.set_cancel_reason(reason.clone());
        assert!(counter.0.load(Ordering::Acquire) > 0);
        assert!(matches!(
            waiting.as_mut().poll(&mut task),
            Poll::Ready(Err(SleepError::Cancelled(actual))) if actual == reason
        ));
        assert!(driver.is_empty());
        assert_eq!(registrations(&cx), 0);
    }
}

#[test]
fn cancellation_wins_an_elapsed_timer_and_a_missing_timer() {
    let (cx, clock, driver) = virtual_context(Budget::INFINITE);
    let mut waiting = Box::pin(sleep_until_cx(&cx, Time::from_millis(100)));
    let mut task = Context::from_waker(Waker::noop());
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    clock.advance_to(Time::from_millis(100));
    assert_eq!(driver.process_timers(), 1);
    let reason = CancelReason::timeout();
    cx.set_cancel_reason(reason.clone());
    assert!(matches!(
        waiting.as_mut().poll(&mut task),
        Poll::Ready(Err(SleepError::Cancelled(actual))) if actual == reason
    ));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
    assert!(matches!(
        ready_result(sleep_cx(&cx, Duration::ZERO)),
        Err(SleepError::Cancelled(actual)) if actual == reason
    ));

    let no_timer = Cx::for_testing();
    no_timer.set_cancel_reason(reason.clone());
    assert!(matches!(
        ready_result(sleep_until_cx(&no_timer, Time::ZERO)),
        Err(SleepError::Cancelled(actual)) if actual == reason
    ));
    assert_eq!(registrations(&no_timer), 0);
}

#[test]
fn owner_deadline_wakes_a_long_sleep_without_an_external_monitor() {
    let (cx, clock, driver) =
        virtual_context(Budget::new().with_deadline(Time::from_millis(10)));
    let counter = Arc::new(CountWake::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut task = Context::from_waker(&waker);
    let mut waiting = Box::pin(sleep_until_cx(&cx, Time::from_secs(3600)));
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    assert_eq!(driver.next_deadline(), Some(Time::from_millis(10)));

    clock.advance_to(Time::from_millis(10));
    assert_eq!(driver.process_timers(), 1);
    assert!(counter.0.load(Ordering::Acquire) > 0);
    assert!(matches!(
        waiting.as_mut().poll(&mut task),
        Poll::Ready(Err(SleepError::Cancelled(reason))) if reason.kind == CancelKind::Deadline
    ));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
}

#[test]
fn expired_masked_owner_deadline_parks_without_self_waking() {
    let (cx, clock, driver) =
        virtual_context(Budget::new().with_deadline(Time::from_millis(1)));
    clock.advance_to(Time::from_millis(2));
    let counter = Arc::new(CountWake::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut task = Context::from_waker(&waker);
    let mut waiting = Box::pin(sleep_until_cx(&cx, Time::from_millis(100)));
    cx.masked(|| {
        for _ in 0..3 {
            assert!(waiting.as_mut().poll(&mut task).is_pending());
            assert_eq!(driver.next_deadline(), Some(Time::from_millis(100)));
            assert_eq!(driver.pending_count(), 1);
            assert_eq!(registrations(&cx), 1);
            assert_eq!(driver.process_timers(), 0);
            assert_eq!(counter.0.load(Ordering::Acquire), 0);
        }
    });
    assert!(counter.0.load(Ordering::Acquire) > 0, "unmask wakes the wait");
    assert!(matches!(
        waiting.as_mut().poll(&mut task),
        Poll::Ready(Err(SleepError::Cancelled(reason))) if reason.kind == CancelKind::Deadline
    ));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
}

#[test]
fn masked_cancellation_can_finish_at_the_requested_deadline() {
    let (cx, clock, driver) = virtual_context(Budget::INFINITE);
    cx.set_cancel_reason(CancelReason::timeout());
    let mut waiting = Box::pin(sleep_until_cx(&cx, Time::from_millis(100)));
    let mut task = Context::from_waker(Waker::noop());
    cx.masked(|| {
        assert!(waiting.as_mut().poll(&mut task).is_pending());
        assert_eq!(driver.next_deadline(), Some(Time::from_millis(100)));
        assert_eq!(registrations(&cx), 1);
        clock.advance_to(Time::from_millis(100));
        assert_eq!(driver.process_timers(), 1);
        assert!(matches!(waiting.as_mut().poll(&mut task), Poll::Ready(Ok(()))));
        assert_eq!(registrations(&cx), 0);
    });
    assert!(cx.checkpoint().is_err());
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
}

#[test]
fn dropping_before_or_after_timer_fire_releases_all_registrations() {
    for fire_before_drop in [false, true] {
        let (cx, clock, driver) = virtual_context(Budget::INFINITE);
        let mut waiting = Box::pin(sleep_until_cx(&cx, Time::from_millis(100)));
        let mut task = Context::from_waker(Waker::noop());
        assert!(waiting.as_mut().poll(&mut task).is_pending());
        assert_eq!(registrations(&cx), 1);
        if fire_before_drop {
            clock.advance_to(Time::from_millis(100));
            assert_eq!(driver.process_timers(), 1);
        }
        drop(waiting);
        assert!(driver.is_empty());
        assert_eq!(registrations(&cx), 0);
    }
}

#[test]
fn dropping_one_sleep_does_not_remove_another_sleeps_cancellation_wake() {
    let (cx, _, driver) = virtual_context(Budget::INFINITE);
    let counter = Arc::new(CountWake::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut task = Context::from_waker(&waker);
    let mut first = Box::pin(sleep_cx(&cx, Duration::from_secs(3600)));
    let mut second = Box::pin(sleep_cx(&cx, Duration::from_secs(7200)));
    assert!(first.as_mut().poll(&mut task).is_pending());
    assert!(second.as_mut().poll(&mut task).is_pending());
    assert_eq!(registrations(&cx), 2);
    assert_eq!(driver.pending_count(), 2);
    drop(first);
    assert_eq!(registrations(&cx), 1);
    assert_eq!(driver.pending_count(), 1);

    cx.set_cancel_reason(CancelReason::user("remaining sleep"));
    assert!(counter.0.load(Ordering::Acquire) > 0);
    assert!(matches!(
        second.as_mut().poll(&mut task),
        Poll::Ready(Err(SleepError::Cancelled(reason))) if reason.kind == CancelKind::User
    ));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
}

#[test]
fn masked_repolls_refresh_one_subscription_and_drop_only_their_own() {
    let (cx, _, driver) = virtual_context(Budget::INFINITE);
    let old_counter = Arc::new(CountWake::default());
    let old_waker = Waker::from(Arc::clone(&old_counter));
    let mut old_task = Context::from_waker(&old_waker);
    let new_counter = Arc::new(CountWake::default());
    let new_waker = Waker::from(Arc::clone(&new_counter));
    let mut new_task = Context::from_waker(&new_waker);
    let mut first = Box::pin(sleep_cx(&cx, Duration::from_secs(3600)));
    let mut second = Box::pin(sleep_until_cx(&cx, Time::from_secs(7200)));
    let reason = CancelReason::timeout().with_cause(CancelReason::user("masked wait"));

    cx.masked(|| {
        assert!(first.as_mut().poll(&mut old_task).is_pending());
        assert!(second.as_mut().poll(&mut old_task).is_pending());
        cx.cancel_with_reason(reason.clone());
        assert!(first.as_mut().poll(&mut new_task).is_pending());
        assert!(second.as_mut().poll(&mut old_task).is_pending());
        old_counter.0.store(0, Ordering::Release);
        new_counter.0.store(0, Ordering::Release);
        for _ in 0..3 {
            assert!(first.as_mut().poll(&mut new_task).is_pending());
            assert_eq!(registrations(&cx), 2);
            assert_eq!(driver.pending_count(), 2);
            assert_eq!(old_counter.0.load(Ordering::Acquire), 0);
            assert_eq!(new_counter.0.load(Ordering::Acquire), 0);
        }
        drop(first);
        assert_eq!(registrations(&cx), 1);
        assert_eq!(driver.pending_count(), 1);
    });

    assert!(old_counter.0.load(Ordering::Acquire) > 0);
    assert_eq!(new_counter.0.load(Ordering::Acquire), 0);
    assert!(matches!(
        second.as_mut().poll(&mut old_task),
        Poll::Ready(Err(SleepError::Cancelled(actual))) if actual == reason
    ));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
}

#[test]
fn an_authorized_driver_is_required_even_for_an_immediately_due_sleep() {
    type TimeOnly = crate::cx::cap::CapSet<false, true, false, false, false>;
    let no_timer = Cx::for_testing().restrict::<TimeOnly>();
    assert!(matches!(
        ready_result(sleep_cx(&no_timer, Duration::ZERO)),
        Err(SleepError::TimerUnavailable)
    ));
    assert!(matches!(
        ready_result(sleep_until_cx(&no_timer, Time::ZERO)),
        Err(SleepError::TimerUnavailable)
    ));

    let (cx, _, driver) = virtual_context(Budget::INFINITE);
    let restriction = cx
        .restrict::<crate::cx::cap::None>()
        .set_current_restricted();
    let masked = Cx::current().unwrap();
    assert!(matches!(
        ready_result(sleep_cx(&masked, Duration::ZERO)),
        Err(SleepError::TimerUnavailable)
    ));
    assert!(matches!(
        ready_result(sleep_until_cx(&masked, Time::ZERO)),
        Err(SleepError::TimerUnavailable)
    ));
    assert!(driver.is_empty());
    drop(restriction);

    let time_only = cx.restrict::<TimeOnly>();
    assert!(ready_result(sleep_cx(&time_only, Duration::ZERO)).is_ok());
    assert!(ready_result(sleep_until_cx(&time_only, Time::ZERO)).is_ok());
    assert!(driver.is_empty());
}

#[test]
fn a_duration_beyond_the_time_domain_saturates_and_completes_at_max() {
    let (cx, clock, driver) = virtual_context(Budget::INFINITE);
    // Stay inside the wheel's registration horizon while overflowing the
    // requested duration. A distant registration may legitimately re-arm.
    clock.advance_to(Time::MAX.saturating_sub_nanos(1_000_000));
    let mut waiting = Box::pin(sleep_cx(&cx, Duration::MAX));
    let mut task = Context::from_waker(Waker::noop());
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    assert_eq!(driver.next_deadline(), Some(Time::MAX));
    clock.advance_to(Time::MAX);
    assert_eq!(driver.process_timers(), 1);
    assert!(matches!(waiting.as_mut().poll(&mut task), Poll::Ready(Ok(()))));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
    assert!(ready_result(sleep_cx(&cx, Duration::MAX)).is_ok());
}

#[test]
fn crossing_an_owner_deadline_cannot_report_successful_expiry() {
    #[derive(Debug, Default)]
    struct CrossingClock(AtomicUsize);

    impl TimeSource for CrossingClock {
        fn now(&self) -> Time {
            if self.0.fetch_add(1, Ordering::SeqCst) < 2 {
                Time::ZERO
            } else {
                Time::from_millis(1)
            }
        }
    }

    let clock = Arc::new(CrossingClock::default());
    let driver = TimerDriverHandle::new(Arc::new(TimerDriver::with_clock(Arc::clone(&clock))));
    let cx = context_with_driver(
        Budget::new().with_deadline(Time::from_millis(1)),
        driver.clone(),
    );
    clock.0.store(0, Ordering::SeqCst);
    assert!(matches!(
        ready_result(sleep_until_cx(&cx, Time::ZERO)),
        Err(SleepError::Cancelled(reason)) if reason.kind == CancelKind::Deadline
    ));
    assert!(clock.0.load(Ordering::SeqCst) >= 3);
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
}

#[test]
fn native_foreign_owner_unmask_wakes_relative_and_absolute_sleeps() {
    for current_thread in [true, false] {
        for absolute in [false, true] {
            for request_before_first_poll in [false, true] {
                let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(5000)));
                let driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
                // This owner is separate from every native runtime task. Its
                // auxiliary subscription is the only cancellation wake source.
                let cx = context_with_driver(Budget::INFINITE, driver.clone());
                let reason = CancelReason::timeout()
                    .with_message("masked native sleep")
                    .with_cause(CancelReason::user("foreign owner cancelled"));
                let saved_waker = Arc::new(crate::sync::pl::Mutex::new(None::<Waker>));
                let (parked_tx, parked_rx) = mpsc::channel();
                let (done_tx, done_rx) = mpsc::channel();

                // The controller holds the mask through a real worker poll
                // that observes the request. Only then does it unmask; the
                // initial request's wake has already been consumed, if any.
                let (worker, first_park, requested_park) = cx.masked(|| {
                    if request_before_first_poll {
                        cx.cancel_with_reason(reason.clone());
                    }
                    let worker = std::thread::spawn({
                        let cx = cx.clone();
                        let driver = driver.clone();
                        let saved_waker = Arc::clone(&saved_waker);
                        move || {
                            let builder = if current_thread {
                                RuntimeBuilder::current_thread()
                            } else {
                                RuntimeBuilder::multi_thread()
                                    .worker_threads(2)
                                    .with_sharded_state(true)
                            };
                            let runtime = builder
                                .with_timer_driver(driver.clone())
                                .build()
                                .unwrap();
                            let result = runtime.block_on(async {
                                let mut waiting = std::pin::pin!(async {
                                    if absolute {
                                        sleep_until_cx(&cx, Time::from_secs(3605)).await
                                    } else {
                                        sleep_cx(&cx, Duration::from_secs(3600)).await
                                    }
                                });
                                let mut reported_initial = false;
                                let mut reported_requested = false;
                                poll_fn(|task| {
                                    let result = waiting.as_mut().poll(task);
                                    if result.is_pending() {
                                        *saved_waker.lock() = Some(task.waker().clone());
                                        let requested = cx.is_cancel_requested();
                                        if !reported_initial
                                            || (requested && !reported_requested)
                                        {
                                            reported_initial = true;
                                            reported_requested |= requested;
                                            parked_tx
                                                .send((
                                                    requested,
                                                    driver.pending_count(),
                                                    registrations(&cx),
                                                ))
                                                .unwrap();
                                        }
                                    }
                                    result
                                })
                                .await
                            });
                            let drain = runtime.shutdown_drained(Duration::from_secs(3));
                            done_tx
                                .send((
                                    result,
                                    drain,
                                    runtime.is_quiescent(),
                                    driver.pending_count(),
                                    registrations(&cx),
                                ))
                                .unwrap();
                        }
                    });
                    let first_park = parked_rx.recv_timeout(Duration::from_secs(3));
                    let requested_park = if request_before_first_poll {
                        None
                    } else {
                        cx.cancel_with_reason(reason.clone());
                        Some(parked_rx.recv_timeout(Duration::from_secs(3)))
                    };
                    (worker, first_park, requested_park)
                });

                let completed = done_rx.recv_timeout(Duration::from_secs(3));
                let woke_without_rescue = completed.is_ok();
                if !woke_without_rescue {
                    // A failing old implementation must still release the
                    // worker. This wake is recorded and cannot make it pass.
                    let wake = saved_waker.lock().take();
                    if let Some(wake) = wake {
                        wake.wake();
                    }
                }
                let (result, drain, quiescent, timers, observers) = completed
                    .or_else(|_| done_rx.recv_timeout(Duration::from_secs(3)))
                    .expect("native sleep must finish after the rescue wake");
                worker.join().unwrap();

                assert_eq!(
                    first_park.expect("native sleep must reach Pending"),
                    (request_before_first_poll, 1, 1)
                );
                if let Some(parked) = requested_park {
                    assert_eq!(
                        parked.expect("worker must observe the request while masked"),
                        (true, 1, 1)
                    );
                }
                assert!(
                    woke_without_rescue,
                    "unmask must wake the foreign owner's sleep: \
                     current_thread={current_thread}, absolute={absolute}, \
                     request_before_first_poll={request_before_first_poll}"
                );
                assert!(matches!(
                    result,
                    Err(SleepError::Cancelled(actual)) if actual == reason
                ));
                assert_eq!(clock.now(), Time::from_millis(5000));
                assert!(driver.is_empty());
                assert_eq!((timers, observers), (0, 0));
                assert_eq!(drain.outcome, RootDrainOutcome::Quiescent, "{drain:?}");
                assert_eq!(drain.live_tasks, 0);
                assert_eq!(drain.live_regions, 0);
                assert_eq!(drain.pending_spawns, 0);
                assert_eq!(drain.pending_obligations, 0);
                assert_eq!(drain.queued_finalizers, 0);
                assert!(!drain.has_pending_obligation_posts);
                assert!(quiescent);
            }
        }
    }
}
