//! Public admission paths must remain subscribed until masked cancellation
//! becomes observable, even when capacity and the owner clock never change.

use super::bulkhead::{Bulkhead, BulkheadAcquireError, BulkheadError, BulkheadPermit, BulkheadPolicy};
use super::rate_limit::{
    FixedWindowRateLimitPermit, FixedWindowRateLimiter, RateLimitAcquireError, RateLimitError,
    RateLimitPermit, RateLimitPolicy, RateLimiter, WaitStrategy,
};
use crate::cx::Cx;
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, CancelReason, Outcome, RegionId, TaskId, Time};
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
enum Kind {
    Bulkhead,
    TokenBucket,
    FixedWindow,
}

const KINDS: [Kind; 3] = [Kind::Bulkhead, Kind::TokenBucket, Kind::FixedWindow];

enum Admission {
    Bulkhead(Bulkhead),
    TokenBucket(RateLimiter),
    FixedWindow(FixedWindowRateLimiter),
}

enum Held<'a> {
    Bulkhead(BulkheadPermit<'a>),
    TokenBucket(RateLimitPermit<'a>),
    FixedWindow(FixedWindowRateLimitPermit<'a>),
}

impl Held<'_> {
    fn release(self) {
        match self {
            Self::Bulkhead(permit) => drop(permit),
            Self::TokenBucket(permit) => drop(permit),
            Self::FixedWindow(permit) => drop(permit),
        }
    }
}

#[derive(Debug)]
enum Failure {
    Bulkhead(BulkheadAcquireError),
    Rate(RateLimitAcquireError),
}

impl Admission {
    fn new(kind: Kind, max_queued: u32) -> Self {
        match kind {
            Kind::Bulkhead => Self::Bulkhead(Bulkhead::new(BulkheadPolicy {
                max_concurrent: 1,
                max_queue: max_queued,
                queue_timeout: Duration::from_secs(3600),
                ..Default::default()
            })),
            Kind::TokenBucket => Self::TokenBucket(RateLimiter::new(RateLimitPolicy {
                rate: 0,
                burst: 1,
                period: Duration::ZERO,
                wait_strategy: WaitStrategy::Block,
                ..Default::default()
            })),
            Kind::FixedWindow => Self::FixedWindow(FixedWindowRateLimiter::new(RateLimitPolicy {
                rate: 1,
                period: Duration::ZERO,
                wait_strategy: WaitStrategy::Block,
                ..Default::default()
            })),
        }
    }

    fn hold(&self) -> Held<'_> {
        match self {
            Self::Bulkhead(limiter) => {
                Held::Bulkhead(limiter.try_acquire(1, Time::ZERO).expect("initial capacity"))
            }
            Self::TokenBucket(limiter) => {
                Held::TokenBucket(limiter.acquire_permit(1, Time::ZERO).unwrap())
            }
            Self::FixedWindow(limiter) => {
                Held::FixedWindow(limiter.acquire_permit(1, Time::ZERO).unwrap())
            }
        }
    }

    fn available(&self) -> u32 {
        match self {
            Self::Bulkhead(limiter) => limiter.available(),
            Self::TokenBucket(limiter) => limiter.available_tokens(),
            Self::FixedWindow(limiter) => limiter.available_tokens(),
        }
    }

    async fn acquire(&self, cx: &Cx, max_queued: usize) -> Result<(), Failure> {
        match self {
            Self::Bulkhead(limiter) => limiter
                .acquire_async(cx, 1)
                .await
                .map(drop)
                .map_err(Failure::Bulkhead),
            Self::TokenBucket(limiter) => limiter
                .acquire_async_bounded(cx, 1, max_queued)
                .await
                .map(drop)
                .map_err(Failure::Rate),
            Self::FixedWindow(limiter) => limiter
                .acquire_async_bounded(cx, 1, max_queued)
                .await
                .map(drop)
                .map_err(Failure::Rate),
        }
    }

    fn assert_queue_full(&self, cx: &Cx) {
        let mut future = Box::pin(self.acquire(cx, 1));
        let mut task = Context::from_waker(Waker::noop());
        assert!(matches!(
            future.as_mut().poll(&mut task),
            Poll::Ready(Err(Failure::Bulkhead(BulkheadAcquireError::Admission(
                BulkheadError::QueueFull
            )))) | Poll::Ready(Err(Failure::Rate(RateLimitAcquireError::Admission(
                RateLimitError::RateLimitExceeded
            ))))
        ));
    }

    fn assert_queue_recovered(&self, cx: &Cx) {
        let mut future = Box::pin(self.acquire(cx, 1));
        let mut task = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut task).is_pending());
        drop(future);
        assert_eq!(registrations(cx), 0);
    }

    fn assert_available(&self, cx: &Cx) {
        let mut future = Box::pin(self.acquire(cx, 1));
        let mut task = Context::from_waker(Waker::noop());
        assert!(matches!(future.as_mut().poll(&mut task), Poll::Ready(Ok(()))));
        assert_eq!(self.available(), 1, "successful probe refunds its permit");
        assert_eq!(registrations(cx), 0);
    }
}

fn context(driver: TimerDriverHandle) -> Cx {
    Cx::new_with_drivers(
        RegionId::new_for_test(0, 1),
        TaskId::new_for_test(400, 0),
        Budget::INFINITE,
        None,
        None,
        None,
        Some(driver),
        None,
    )
}

fn registrations(cx: &Cx) -> usize {
    cx.inner.read().cancel_waker_registrations.len()
}

fn assert_cancelled(result: &Result<(), Failure>, reason: &CancelReason) {
    match result {
        Err(Failure::Bulkhead(BulkheadAcquireError::Cancelled(actual)))
        | Err(Failure::Rate(RateLimitAcquireError::Cancelled(actual))) => {
            assert_eq!(actual, reason);
        }
        other => panic!("admission must preserve the complete cancellation reason: {other:?}"),
    }
}

#[derive(Default)]
struct CountWake(AtomicUsize);

impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn masked_admission_refreshes_wakers_and_retires_only_its_own_wait() {
    for kind in KINDS {
        let clock = Arc::new(VirtualClock::new());
        let driver = TimerDriverHandle::with_virtual_clock(clock);
        let cx = context(driver.clone());
        let admission = Admission::new(kind, 2);
        let held = admission.hold();
        let old = Arc::new(CountWake::default());
        let old_waker = Waker::from(Arc::clone(&old));
        let mut old_task = Context::from_waker(&old_waker);
        let new = Arc::new(CountWake::default());
        let new_waker = Waker::from(Arc::clone(&new));
        let mut new_task = Context::from_waker(&new_waker);
        let mut first = Box::pin(admission.acquire(&cx, 2));
        let mut second = Box::pin(admission.acquire(&cx, 2));
        let reason = CancelReason::user("masked admission")
            .with_cause(CancelReason::timeout().with_message("retain cause"));

        cx.masked(|| {
            assert!(first.as_mut().poll(&mut old_task).is_pending());
            assert!(second.as_mut().poll(&mut old_task).is_pending());
            cx.cancel_with_reason(reason.clone());
            assert!(first.as_mut().poll(&mut new_task).is_pending());
            assert!(second.as_mut().poll(&mut old_task).is_pending());
            assert_eq!(registrations(&cx), 2);
            old.0.store(0, Ordering::Release);
            new.0.store(0, Ordering::Release);
            for _ in 0..3 {
                assert!(first.as_mut().poll(&mut new_task).is_pending());
                assert_eq!(old.0.load(Ordering::Acquire), 0);
                assert_eq!(new.0.load(Ordering::Acquire), 0);
            }
            drop(first);
            assert_eq!(registrations(&cx), 1);
            // Removing a predecessor can notify the second queue owner. Only
            // wakes following mask exit count toward the cancellation oracle.
            old.0.store(0, Ordering::Release);
            new.0.store(0, Ordering::Release);
        });

        assert!(old.0.load(Ordering::Acquire) > 0, "{kind:?} must wake on unmask");
        assert_eq!(new.0.load(Ordering::Acquire), 0);
        let Poll::Ready(result) = second.as_mut().poll(&mut old_task) else {
            panic!("{kind:?} did not observe unmasked cancellation");
        };
        assert_cancelled(&result, &reason);
        assert_eq!(registrations(&cx), 0);
        assert!(driver.is_empty());
        assert_eq!(admission.available(), 0);
        let healthy = context(driver.clone());
        admission.assert_queue_recovered(&healthy);
        held.release();
        admission.assert_available(&healthy);
        assert!(driver.is_empty());
    }
}

#[test]
fn admission_can_complete_while_masked_and_retires_its_subscription() {
    for kind in KINDS {
        let driver = TimerDriverHandle::with_virtual_clock(Arc::new(VirtualClock::new()));
        let cx = context(driver.clone());
        let admission = Admission::new(kind, 1);
        let held = admission.hold();
        let mut future = Box::pin(admission.acquire(&cx, 1));
        let mut task = Context::from_waker(Waker::noop());
        cx.masked(|| {
            cx.cancel_with_reason(CancelReason::user("deferred until outside admission"));
            assert!(future.as_mut().poll(&mut task).is_pending());
            assert_eq!(registrations(&cx), 1);
            held.release();
            assert!(matches!(future.as_mut().poll(&mut task), Poll::Ready(Ok(()))));
            assert_eq!(registrations(&cx), 0);
            assert_eq!(admission.available(), 1);
            assert!(driver.is_empty());
        });
        assert!(cx.checkpoint().is_err());
    }
}

#[test]
fn native_unmask_wakes_saturated_admission_without_capacity_or_clock_progress() {
    for kind in KINDS {
        for current_thread in [true, false] {
            for request_before_first_poll in [false, true] {
                let clock = Arc::new(VirtualClock::new());
                let driver = TimerDriverHandle::with_virtual_clock(clock);
                let cx = context(driver.clone());
                let healthy = context(driver.clone());
                let admission = Arc::new(Admission::new(kind, 1));
                let held = admission.hold();
                let reason = CancelReason::timeout()
                    .with_message("native admission mask exited")
                    .with_cause(CancelReason::user("upstream cancelled"));
                let saved_waker = Arc::new(parking_lot::Mutex::new(None::<Waker>));
                let (parked_tx, parked_rx) = mpsc::channel();
                let (done_tx, done_rx) = mpsc::channel();

                let (worker, first_park, requested_park) = cx.masked(|| {
                    if request_before_first_poll {
                        cx.cancel_with_reason(reason.clone());
                    }
                    let worker = std::thread::spawn({
                        let cx = cx.clone();
                        let driver = driver.clone();
                        let admission = Arc::clone(&admission);
                        let saved_waker = Arc::clone(&saved_waker);
                        move || {
                            let builder = if current_thread {
                                RuntimeBuilder::current_thread()
                            } else {
                                RuntimeBuilder::multi_thread()
                                    .worker_threads(2)
                                    .with_sharded_state(true)
                            };
                            let runtime = builder.with_timer_driver(driver.clone()).build().unwrap();
                            let joined = runtime.block_on(runtime.handle().spawn(async move {
                                let root = Cx::current().expect("native admission root");
                                let mut child = root
                                    .spawn(move |_child_cx| async move {
                                        let mut future = std::pin::pin!(admission.acquire(&cx, 1));
                                        let mut reported_initial = false;
                                        let mut reported_requested = false;
                                        let result = poll_fn(|task| {
                                            let result = future.as_mut().poll(task);
                                            if result.is_pending() {
                                                *saved_waker.lock() = Some(task.waker().clone());
                                                let requested = cx.is_cancel_requested();
                                                if !reported_initial || (requested && !reported_requested) {
                                                    reported_initial = true;
                                                    reported_requested |= requested;
                                                    parked_tx.send((
                                                        requested,
                                                        registrations(&cx),
                                                        driver.pending_count(),
                                                    )).unwrap();
                                                }
                                            }
                                            result
                                        }).await;
                                        assert_eq!(registrations(&cx), 0);
                                        assert!(driver.is_empty());
                                        Outcome::<_, ()>::Ok(result)
                                    })
                                    .expect("spawn native admission waiter");
                                child.join(&root).await
                            }));
                            let drain = runtime.shutdown_drained(Duration::from_secs(3));
                            done_tx.send((joined, drain, runtime.is_quiescent())).unwrap();
                        }
                    });
                    let first_park = parked_rx.recv_timeout(Duration::from_secs(3));
                    admission.assert_queue_full(&healthy);
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
                    let wake = saved_waker.lock().take();
                    if let Some(wake) = wake {
                        wake.wake();
                    }
                }
                let (joined, drain, quiescent) = completed
                    .or_else(|_| done_rx.recv_timeout(Duration::from_secs(3)))
                    .expect("admission must finish after the rescue wake");
                worker.join().unwrap();
                let timers = usize::from(matches!(kind, Kind::Bulkhead));
                assert_eq!(first_park.unwrap(), (request_before_first_poll, 1, timers));
                if let Some(parked) = requested_park {
                    assert_eq!(parked.unwrap(), (true, 1, timers));
                }
                assert!(woke_without_rescue, "{kind:?} missed its mask-exit wake");
                match &joined {
                    Ok(Outcome::Ok(result)) => assert_cancelled(result, &reason),
                    other => panic!("native task must publish the exact admission result: {other:?}"),
                }
                assert_eq!(driver.now(), Time::ZERO);
                assert!(driver.is_empty());
                assert_eq!(registrations(&cx), 0);
                assert_eq!(admission.available(), 0, "initial permit remains owned");
                admission.assert_queue_recovered(&healthy);
                held.release();
                admission.assert_available(&healthy);
                assert!(driver.is_empty());
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
