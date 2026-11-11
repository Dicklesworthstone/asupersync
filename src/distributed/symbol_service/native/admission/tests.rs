use super::*;
use std::pin::Pin;
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll, Waker};

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn zero_denies_before_invoking_an_eager_factory() {
    let limiter = Admission::new(0);
    let mut future = Box::pin(limiter.run(|| {
        panic!("denied factory must not encode or dispatch");
        #[allow(unreachable_code)]
        async { Ok::<_, RemoteSymbolError>(()) }
    }));
    assert!(matches!(poll(future.as_mut()), Poll::Ready(Err(RemoteSymbolError::Admission))));
    assert_eq!(limiter.active(), 0);
}

#[test]
fn admission_is_lazy_and_shared_between_clones_and_operation_kinds() {
    let root = Arc::new(Admission::new(1));
    let clone = Arc::clone(&root);
    let calls = AtomicUsize::new(0);
    let mut send = Box::pin(root.run(|| {
        calls.fetch_add(1, Ordering::SeqCst);
        std::future::pending::<Result<(), RemoteSymbolError>>()
    }));
    assert_eq!(root.active(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(poll(send.as_mut()).is_pending());
    assert_eq!(root.active(), 1);
    let mut fetch = Box::pin(clone.run(|| async { Ok(17) }));
    assert!(matches!(poll(fetch.as_mut()), Poll::Ready(Err(RemoteSymbolError::Admission))));
    drop(send);
    assert_eq!(clone.active(), 0);
    let mut fetch = Box::pin(clone.run(|| async { Ok(17) }));
    assert!(matches!(poll(fetch.as_mut()), Poll::Ready(Ok(17))));
    assert_eq!(root.active(), 0); // Completed wrapper deliberately stays alive.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

struct Owned<'a> {
    limiter: &'a Admission,
    drops: &'a AtomicUsize,
    ready: bool,
    panic_poll: bool,
    panic_drop: bool,
}
impl Future for Owned<'_> {
    type Output = Result<(), RemoteSymbolError>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        assert_eq!(self.limiter.active(), 1);
        assert!(!self.panic_poll, "poll sentinel");
        if self.ready { Poll::Ready(Ok(())) } else { Poll::Pending }
    }
}
impl Drop for Owned<'_> {
    fn drop(&mut self) {
        assert_eq!(self.limiter.active(), 1, "credit must cover inner destruction");
        assert!(matches!(self.limiter.acquire(), Err(RemoteSymbolError::Admission)));
        self.drops.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic_drop, "drop sentinel");
    }
}

#[test]
fn ready_future_destruction_precedes_capacity_reuse() {
    let limiter = Admission::new(1);
    let drops = AtomicUsize::new(0);
    let mut future = Box::pin(limiter.run(|| Owned {
        limiter: &limiter, drops: &drops, ready: true, panic_poll: false, panic_drop: false,
    }));
    assert!(matches!(poll(future.as_mut()), Poll::Ready(Ok(()))));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(limiter.active(), 0);
}

#[test]
fn dropping_pending_work_retires_inner_before_credit() {
    let limiter = Admission::new(1);
    let drops = AtomicUsize::new(0);
    let mut future = Box::pin(limiter.run(|| Owned {
        limiter: &limiter, drops: &drops, ready: false, panic_poll: false, panic_drop: false,
    }));
    assert!(poll(future.as_mut()).is_pending());
    drop(future);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(limiter.active(), 0);
}

#[test]
fn constructor_unwind_returns_credit_without_dispatching_again() {
    let limiter = Admission::new(1);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut future = Box::pin(limiter.run(|| {
            assert_eq!(limiter.active(), 1);
            panic!("factory sentinel");
            #[allow(unreachable_code)]
            async { Ok::<_, RemoteSymbolError>(()) }
        }));
        let _ = poll(future.as_mut());
    }));
    assert!(result.is_err());
    assert_eq!(limiter.active(), 0);
}

#[test]
fn poll_and_destructor_unwinds_return_credit() {
    for (panic_poll, panic_drop) in [(true, false), (false, true)] {
        let limiter = Admission::new(1);
        let drops = AtomicUsize::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut future = Box::pin(limiter.run(|| Owned {
                limiter: &limiter, drops: &drops, ready: true, panic_poll, panic_drop,
            }));
            let _ = poll(future.as_mut());
        }));
        assert!(result.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(limiter.active(), 0);
    }
}

#[test]
fn application_error_returns_credit_and_original_error() {
    let limiter = Admission::new(1);
    let mut future = Box::pin(limiter.run(|| async { Err::<(), _>(RemoteSymbolError::Refused) }));
    assert!(matches!(poll(future.as_mut()), Poll::Ready(Err(RemoteSymbolError::Refused))));
    assert_eq!(limiter.active(), 0);
}

#[test]
fn concurrent_admission_never_exceeds_the_shared_ceiling() {
    let limiter = Arc::new(Admission::new(2));
    let barrier = Arc::new(Barrier::new(9));
    let admitted = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let (limiter, barrier, admitted) = (Arc::clone(&limiter), Arc::clone(&barrier), Arc::clone(&admitted));
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            let credit = limiter.acquire();
            if credit.is_ok() { admitted.fetch_add(1, Ordering::SeqCst); }
            barrier.wait();
            barrier.wait();
            drop(credit);
        }));
    }
    barrier.wait();
    barrier.wait();
    let observed = (limiter.active(), admitted.load(Ordering::SeqCst));
    barrier.wait();
    for thread in threads { thread.join().unwrap(); }
    assert_eq!(observed, (2, 2));
    assert_eq!(limiter.active(), 0);
}

#[test]
fn maximum_limit_cannot_wrap_the_counter() {
    let limiter = Admission::new(usize::MAX);
    limiter.active.store(usize::MAX - 1, Ordering::Release);
    let credit = limiter.acquire().unwrap();
    assert_eq!(limiter.active(), usize::MAX);
    assert!(matches!(limiter.acquire(), Err(RemoteSymbolError::Admission)));
    drop(credit);
    assert_eq!(limiter.active(), usize::MAX - 1);
}

fn queued(limit: usize, max_waiters: usize) -> Admission {
    let mut admission = Admission::new(limit);
    admission.enable_queue(max_waiters);
    admission
}

#[test]
fn queued_admission_is_bounded_fifo_and_defers_factories_until_grant() {
    let limiter = queued(1, 2);
    let cx = Cx::for_testing();
    let calls = AtomicUsize::new(0);
    let mut active = Box::pin(limiter.run_with(&cx, || {
        std::future::pending::<Result<(), RemoteSymbolError>>()
    }));
    assert!(poll(active.as_mut()).is_pending());
    let mut first = Box::pin(limiter.run_with(&cx, || {
        calls.fetch_add(1, Ordering::SeqCst);
        async { Ok(1) }
    }));
    let mut second = Box::pin(limiter.run_with(&cx, || {
        calls.fetch_add(1, Ordering::SeqCst);
        async { Ok(2) }
    }));
    assert_eq!(limiter.waiting(), 0, "unpolled futures register nothing");
    assert!(poll(first.as_mut()).is_pending());
    assert!(poll(second.as_mut()).is_pending());
    assert_eq!((limiter.active(), limiter.waiting(), limiter.max_waiters()), (1, 2, 2));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut excess = Box::pin(limiter.run_with(&cx, || async { Ok(3) }));
    assert!(matches!(poll(excess.as_mut()), Poll::Ready(Err(RemoteSymbolError::Admission))));
    drop(active);
    // Free capacity is reserved for existing FIFO waiters, not a new arrival
    // or whichever waiting future the executor happens to poll first.
    let mut newcomer = Box::pin(limiter.run_with(&cx, || async { Ok(4) }));
    assert!(matches!(poll(newcomer.as_mut()), Poll::Ready(Err(RemoteSymbolError::Admission))));
    assert!(poll(second.as_mut()).is_pending());
    assert!(matches!(poll(first.as_mut()), Poll::Ready(Ok(1))));
    assert_eq!(limiter.waiting(), 1);
    assert!(matches!(poll(second.as_mut()), Poll::Ready(Ok(2))));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!((limiter.active(), limiter.waiting()), (0, 0));
}

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl std::task::Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn dropping_the_notified_head_wakes_its_successor_without_leaking_a_slot() {
    let limiter = queued(1, 2);
    let cx = Cx::for_testing();
    let mut active = Box::pin(limiter.run_with(&cx, || {
        std::future::pending::<Result<(), RemoteSymbolError>>()
    }));
    assert!(poll(active.as_mut()).is_pending());
    let mut first = Box::pin(limiter.run_with(&cx, || async { Ok(1) }));
    let mut second = Box::pin(limiter.run_with(&cx, || async { Ok(2) }));
    assert!(poll(first.as_mut()).is_pending());
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut task = Context::from_waker(&waker);
    assert!(second.as_mut().poll(&mut task).is_pending());
    drop(active);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0, "only the FIFO head is runnable");
    drop(first);
    assert!(wakes.0.load(Ordering::SeqCst) > 0, "head drop must transfer the wake");
    assert_eq!(limiter.waiting(), 1);
    assert!(matches!(second.as_mut().poll(&mut task), Poll::Ready(Ok(2))));
    assert_eq!((limiter.active(), limiter.waiting()), (0, 0));
}

#[test]
fn queued_owner_cancellation_wakes_and_removes_only_its_waiter() {
    let limiter = queued(1, 1);
    let holder = Cx::for_testing();
    let owner = Cx::for_testing();
    let mut active = Box::pin(limiter.run_with(&holder, || {
        std::future::pending::<Result<(), RemoteSymbolError>>()
    }));
    assert!(poll(active.as_mut()).is_pending());
    let invoked = AtomicUsize::new(0);
    let mut waiting = Box::pin(limiter.run_with(&owner, || {
        invoked.fetch_add(1, Ordering::SeqCst);
        async { Ok(()) }
    }));
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut task = Context::from_waker(&waker);
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    assert_eq!((limiter.active(), limiter.waiting()), (1, 1));
    owner.cancel_fast(crate::types::CancelKind::User);
    assert!(wakes.0.load(Ordering::SeqCst) > 0, "owner cancellation must wake a parked caller");
    assert!(matches!(waiting.as_mut().poll(&mut task), Poll::Ready(Err(RemoteSymbolError::Cancelled))));
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
    assert_eq!((limiter.active(), limiter.waiting()), (1, 0));
    let mut replacement = Box::pin(limiter.run_with(&holder, || async { Ok(17) }));
    assert!(poll(replacement.as_mut()).is_pending());
    drop(active);
    assert!(matches!(poll(replacement.as_mut()), Poll::Ready(Ok(17))));
    assert_eq!((limiter.active(), limiter.waiting()), (0, 0));
}

#[test]
fn queued_wait_uses_its_owner_clock_and_retires_its_deadline_registration() {
    use crate::time::{TimerDriver, TimerDriverHandle, VirtualClock};
    use crate::types::{Budget, RegionId, TaskId, Time};
    use crate::util::ArenaIndex;

    let limiter = queued(1, 1);
    let holder = Cx::for_testing();
    let mut active = Box::pin(limiter.run_with(&holder, || {
        std::future::pending::<Result<(), RemoteSymbolError>>()
    }));
    assert!(poll(active.as_mut()).is_pending());
    let clock = Arc::new(VirtualClock::new());
    let driver = Arc::new(TimerDriver::with_clock(Arc::clone(&clock)));
    let owner = Cx::new_with_drivers(
        RegionId::from_arena(ArenaIndex::new(1, 0)),
        TaskId::from_arena(ArenaIndex::new(1, 0)),
        Budget::INFINITE.with_deadline(Time::from_nanos(100)), None, None, None,
        Some(TimerDriverHandle::new(Arc::clone(&driver))), None,
    );
    let foreign_clock = Arc::new(VirtualClock::new());
    foreign_clock.advance(1_000);
    let foreign = Cx::new_with_drivers(
        RegionId::from_arena(ArenaIndex::new(2, 0)),
        TaskId::from_arena(ArenaIndex::new(2, 0)),
        Budget::INFINITE, None, None, None,
        Some(TimerDriverHandle::with_virtual_clock(foreign_clock)), None,
    );
    let _ambient = Cx::set_current(Some(foreign));
    let mut waiting = Box::pin(limiter.run_with(&owner, || async { Ok(17) }));
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut task = Context::from_waker(&waker);
    assert!(waiting.as_mut().poll(&mut task).is_pending(), "foreign time must not expire the wait");
    assert_eq!(limiter.waiting(), 1);
    clock.advance(100);
    driver.process_timers();
    assert!(wakes.0.load(Ordering::SeqCst) > 0, "deadline must wake without permit release");
    let mut expired = Box::pin(limiter.run_with(&owner, || async { Ok(17) }));
    assert!(matches!(poll(expired.as_mut()), Poll::Ready(Err(RemoteSymbolError::Deadline))));
    assert_eq!(limiter.waiting(), 1, "an expired owner never enters the queue");
    assert!(matches!(waiting.as_mut().poll(&mut task), Poll::Ready(Err(RemoteSymbolError::Deadline))));
    assert_eq!((limiter.active(), limiter.waiting()), (1, 0));
    assert_eq!(driver.pending_count(), 0);
    drop(active);
    assert_eq!(limiter.active(), 0);
}

#[test]
fn missing_queue_timer_and_zero_capacities_refuse_without_retaining_waiters() {
    use crate::types::{Budget, Time};

    let cx = Cx::for_testing();
    let zero = queued(0, 1);
    let mut denied = Box::pin(zero.run_with(&cx, || async { Ok(()) }));
    assert!(matches!(poll(denied.as_mut()), Poll::Ready(Err(RemoteSymbolError::Admission))));
    assert_eq!((zero.active(), zero.waiting()), (0, 0));

    let limiter = queued(1, 0);
    let mut active = Box::pin(limiter.run_with(&cx, || {
        std::future::pending::<Result<(), RemoteSymbolError>>()
    }));
    assert!(poll(active.as_mut()).is_pending());
    let mut denied = Box::pin(limiter.run_with(&cx, || async { Ok(()) }));
    assert!(matches!(poll(denied.as_mut()), Poll::Ready(Err(RemoteSymbolError::Admission))));
    drop(active);
    assert_eq!((limiter.active(), limiter.waiting()), (0, 0));

    let limiter = queued(1, 1);
    let mut active = Box::pin(limiter.run_with(&cx, || {
        std::future::pending::<Result<(), RemoteSymbolError>>()
    }));
    assert!(poll(active.as_mut()).is_pending());
    let deadline = Cx::for_testing_with_budget(Budget::INFINITE.with_deadline(Time::MAX));
    let mut waiting = Box::pin(limiter.run_with(&deadline, || async { Ok(()) }));
    assert!(matches!(poll(waiting.as_mut()), Poll::Ready(Err(RemoteSymbolError::Configuration))));
    assert_eq!((limiter.active(), limiter.waiting()), (1, 0));
    drop(active);
    assert_eq!(limiter.active(), 0);
}

#[test]
fn queued_credit_covers_future_destruction_and_unwind() {
    for (ready, panic_poll, panic_drop) in [(false, false, false), (true, false, false), (true, true, false), (true, false, true)] {
        let limiter = queued(1, 1);
        let cx = Cx::for_testing();
        let drops = AtomicUsize::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut future = Box::pin(limiter.run_with(&cx, || Owned {
                limiter: &limiter, drops: &drops, ready, panic_poll, panic_drop,
            }));
            let _ = poll(future.as_mut());
        }));
        assert_eq!(result.is_err(), panic_poll || panic_drop);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!((limiter.active(), limiter.waiting()), (0, 0));
        let mut reuse = Box::pin(limiter.run_with(&cx, || async { Ok(17) }));
        assert!(matches!(poll(reuse.as_mut()), Poll::Ready(Ok(17))));
    }
}

#[test]
fn parked_queue_cancellation_wakes_current_thread_and_multi_worker_runtimes() {
    use crate::runtime::RuntimeBuilder;
    use crate::types::CancelKind;
    use std::time::Duration;

    for workers in [1, 2] {
        let runtime = if workers == 1 { RuntimeBuilder::current_thread().build().unwrap() }
            else { RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap() };
        let limiter = queued(1, 1);
        let holder = Cx::for_testing();
        let owner = Cx::for_testing();
        let mut active = Box::pin(limiter.run_with(&holder, || {
            std::future::pending::<Result<(), RemoteSymbolError>>()
        }));
        assert!(poll(active.as_mut()).is_pending());
        let cancelled = owner.clone();
        let (parked, witness) = std::sync::mpsc::channel();
        let canceller = std::thread::spawn(move || {
            witness.recv_timeout(Duration::from_secs(5)).expect("actual registered waiter witness");
            cancelled.cancel_fast(CancelKind::User);
        });
        let invoked = AtomicUsize::new(0);
        let result = runtime.block_on(async {
            let native = Cx::current().expect("native context");
            let mut waiting = std::pin::pin!(limiter.run_with(&owner, || {
                invoked.fetch_add(1, Ordering::SeqCst);
                async { Ok(()) }
            }));
            let mut signalled = false;
            let operation = poll_fn(|task| {
                let result = waiting.as_mut().poll(task);
                if result.is_pending() && !signalled {
                    assert_eq!((limiter.active(), limiter.waiting()), (1, 1));
                    signalled = true;
                    parked.send(()).expect("cancellation trigger");
                }
                result
            });
            crate::time::timeout(native.now(), Duration::from_secs(3), operation).await
        });
        canceller.join().unwrap();
        assert!(matches!(result, Ok(Err(RemoteSymbolError::Cancelled))),
            "a parked owner cancellation must return its domain error before the watchdog: {result:?}");
        assert_eq!(invoked.load(Ordering::SeqCst), 0);
        assert_eq!((limiter.active(), limiter.waiting()), (1, 0));
        drop(active);
        assert_eq!((limiter.active(), limiter.waiting()), (0, 0));
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}
