use super::*;
#[cfg(not(target_arch = "wasm32"))]
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::stream::{StreamExt, iter};
use crate::time::VirtualClock;
#[cfg(not(target_arch = "wasm32"))]
use crate::types::Outcome;
use crate::types::{Budget, CancelKind, RegionId, TaskId};
use std::collections::VecDeque;
use std::future::Future;
use std::rc::Rc;
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(not(target_arch = "wasm32"))]
use std::sync::mpsc;
use std::task::{Wake, Waker};

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
    crate::test_utils::init_test_logging();
    let clock = Arc::new(VirtualClock::new());
    let driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let cx = context_with_driver(budget, driver.clone());
    (cx, clock, driver)
}

fn registrations(cx: &Cx) -> usize {
    cx.inner.read().cancel_waker_registrations.len()
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn counter() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    (count, waker)
}

struct Source {
    items: VecDeque<u8>,
    ready: bool,
    ended: bool,
    polls: usize,
}

impl Source {
    fn pending(items: impl IntoIterator<Item = u8>) -> Self {
        Self {
            items: items.into_iter().collect(),
            ready: false,
            ended: false,
            polls: 0,
        }
    }
}

impl Stream for Source {
    type Item = u8;

    fn poll_next(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<Option<u8>> {
        let this = self.get_mut();
        this.polls += 1;
        if this.ready {
            if let Some(item) = this.items.pop_front() {
                return Poll::Ready(Some(item));
            }
            if this.ended {
                return Poll::Ready(None);
            }
        }
        Poll::Pending
    }
}

#[test]
fn item_allowances_start_on_demand_and_exclude_consumer_backpressure() {
    let (cx, clock, driver) = virtual_context(Budget::INFINITE);
    let mut stream = Source::pending([7, 8]).timeout(&cx, Duration::from_millis(100));
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);

    clock.advance_to(Time::from_millis(500));
    assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
    assert_eq!(driver.next_deadline(), Some(Time::from_millis(600)));
    assert_eq!(driver.pending_count(), 1);
    assert_eq!(registrations(&cx), 1);
    clock.advance_to(Time::from_millis(550));
    stream.get_mut().ready = true;
    assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(Some(Ok(7))));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);

    // Processing the first item takes far longer than the per-item timeout.
    clock.advance_to(Time::from_millis(10_000));
    stream.get_mut().ready = false;
    assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
    assert_eq!(driver.next_deadline(), Some(Time::from_millis(10_100)));
    clock.advance_to(Time::from_millis(10_100));
    assert_eq!(driver.process_timers(), 1);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    stream.get_mut().ready = true;
    assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(Some(Ok(8))));
    assert!(driver.is_empty(), "a ready item wins the fired timer");
    assert_eq!(registrations(&cx), 0);

    stream.get_mut().ended = true;
    assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(None));
    let polls = stream.get_ref().polls;
    assert!(stream.is_terminated());
    assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(None));
    assert_eq!(stream.get_ref().polls, polls, "EOF is fused");
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
}

#[test]
fn elapsed_is_one_error_and_does_not_consume_the_pending_item() {
    let (cx, clock, driver) = virtual_context(Budget::INFINITE);
    let mut stream = Source::pending([42]).timeout(&cx, Duration::from_millis(10));
    let mut task = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
    clock.advance_to(Time::from_millis(10));
    assert_eq!(driver.process_timers(), 1);
    assert_eq!(
        Pin::new(&mut stream).poll_next(&mut task),
        Poll::Ready(Some(Err(StreamTimeoutError::Elapsed(Elapsed::new(Time::from_millis(10))))))
    );
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
    let polls = stream.get_ref().polls;
    assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(None));
    assert_eq!(stream.get_ref().polls, polls);
    let mut recovered = stream.into_inner();
    recovered.ready = true;
    assert_eq!(Pin::new(&mut recovered).poll_next(&mut task), Poll::Ready(Some(42)));
}

#[test]
fn dropping_next_does_not_restart_the_current_item_allowance() {
    let (cx, clock, driver) = virtual_context(Budget::INFINITE);
    let mut stream = Source::pending([]).timeout(&cx, Duration::from_millis(10));
    let mut task = Context::from_waker(Waker::noop());
    let mut next = Box::pin(stream.next());
    assert!(next.as_mut().poll(&mut task).is_pending());
    drop(next);
    clock.advance_to(Time::from_millis(9));
    let mut next = Box::pin(stream.next());
    assert!(next.as_mut().poll(&mut task).is_pending());
    assert_eq!(driver.next_deadline(), Some(Time::from_millis(10)));
    drop(next);
    clock.advance_to(Time::from_millis(10));
    let mut next = Box::pin(stream.next());
    assert!(matches!(next.as_mut().poll(&mut task), Poll::Ready(Some(Err(StreamTimeoutError::Elapsed(_))))));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
}

#[test]
fn drop_and_recovery_remove_only_their_own_timer_and_cancellation_observer() {
    let (cx, _, driver) = virtual_context(Budget::INFINITE);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut first = Source::pending([]).timeout(&cx, Duration::from_secs(1));
    let mut second = Source::pending([]).timeout(&cx, Duration::from_secs(1));
    assert!(Pin::new(&mut first).poll_next(&mut task).is_pending());
    assert!(Pin::new(&mut second).poll_next(&mut task).is_pending());
    assert_eq!(driver.pending_count(), 2);
    assert_eq!(registrations(&cx), 2);
    drop(first);
    assert_eq!(driver.pending_count(), 1);
    assert_eq!(registrations(&cx), 1);
    let _source = second.into_inner();
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn cancellation_preserves_the_entire_reason_and_wakes_a_quiet_source() {
    for reason in [
        CancelReason::user("stream owner stopped"),
        CancelReason::timeout()
            .with_region(RegionId::new_for_test(4, 2))
            .with_task(TaskId::new_for_test(7, 3))
            .with_message("outer timeout")
            .with_cause(CancelReason::deadline()),
        CancelReason::poll_quota(),
    ] {
        let (cx, _, driver) = virtual_context(Budget::INFINITE);
        let mut stream = Source::pending([9]).timeout(&cx, Duration::from_secs(3600));
        let (count, waker) = counter();
        let mut task = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
        assert_eq!(stream.get_ref().polls, 1);
        cx.set_cancel_reason(reason.clone());
        assert!(count.0.load(Ordering::SeqCst) > 0);
        stream.get_mut().ready = true;
        assert_eq!(
            Pin::new(&mut stream).poll_next(&mut task),
            Poll::Ready(Some(Err(StreamTimeoutError::Cancelled(reason))))
        );
        assert_eq!(stream.get_ref().polls, 1, "pre-poll cancellation consumes no item");
        assert!(driver.is_empty());
        assert_eq!(registrations(&cx), 0);
        assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(None));
        let mut recovered = stream.into_inner();
        assert_eq!(Pin::new(&mut recovered).poll_next(&mut task), Poll::Ready(Some(9)));
    }
}

struct BoundarySource<'a> {
    cx: &'a Cx,
    clock: Arc<VirtualClock>,
    value: Option<Result<u8, &'static str>>,
    cancel: bool,
}

impl Stream for BoundarySource<'_> {
    type Item = Result<u8, &'static str>;

    fn poll_next(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.clock.advance_to(Time::from_millis(100));
        if this.cancel {
            this.cx.cancel_fast(CancelKind::User);
        }
        Poll::Ready(this.value.take())
    }
}

#[test]
fn ready_values_and_source_errors_win_expiry_and_concurrent_cancellation() {
    for value in [Ok(11), Err("source error")] {
        for cancel in [false, true] {
            let (cx, clock, driver) = virtual_context(Budget::INFINITE);
            let mut stream = BoundarySource {
                cx: &cx,
                clock,
                value: Some(value),
                cancel,
            }
            .timeout(&cx, Duration::from_millis(100));
            let mut task = Context::from_waker(Waker::noop());
            assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(Some(Ok(value))));
            assert!(driver.is_empty());
            assert_eq!(registrations(&cx), 0);
            if cancel {
                assert!(matches!(
                    Pin::new(&mut stream).poll_next(&mut task),
                    Poll::Ready(Some(Err(StreamTimeoutError::Cancelled(_))))
                ));
            } else {
                assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(None));
            }
        }
    }
}

#[test]
fn cancellation_during_source_eof_is_not_reported_as_clean_eof() {
    let (cx, clock, driver) = virtual_context(Budget::INFINITE);
    let mut stream = BoundarySource {
        cx: &cx,
        clock,
        value: None,
        cancel: true,
    }
    .timeout(&cx, Duration::from_millis(100));
    let mut task = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut stream).poll_next(&mut task),
        Poll::Ready(Some(Err(StreamTimeoutError::Cancelled(reason)))) if reason.kind == CancelKind::User
    ));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
    assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(None));
}

#[test]
fn owner_deadline_wakes_the_stream_and_keeps_deadline_attribution() {
    let (cx, clock, driver) = virtual_context(Budget::INFINITE.with_deadline(Time::from_millis(10)));
    let mut stream = Source::pending([]).timeout(&cx, Duration::from_secs(1));
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
    assert_eq!(driver.next_deadline(), Some(Time::from_millis(10)));
    clock.advance_to(Time::from_millis(10));
    assert_eq!(driver.process_timers(), 1);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        Pin::new(&mut stream).poll_next(&mut task),
        Poll::Ready(Some(Err(StreamTimeoutError::Cancelled(reason)))) if reason.kind == CancelKind::Deadline
    ));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
}

#[test]
fn masked_owner_deadline_rearms_for_the_item_without_spinning() {
    let (cx, clock, driver) = virtual_context(Budget::INFINITE.with_deadline(Time::from_millis(10)));
    let mut stream = Source::pending([]).timeout(&cx, Duration::from_millis(100));
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    cx.masked(|| {
        assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
        clock.advance_to(Time::from_millis(10));
        assert_eq!(driver.process_timers(), 1);
        count.0.store(0, Ordering::SeqCst);
        for _ in 0..3 {
            assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
            assert_eq!(driver.pending_count(), 1);
            assert_eq!(driver.next_deadline(), Some(Time::from_millis(100)));
            assert_eq!(registrations(&cx), 1, "unmask retains its wake source");
            assert_eq!(count.0.load(Ordering::SeqCst), 0, "no self-wake loop");
        }
    });
    assert!(count.0.load(Ordering::SeqCst) > 0, "unmask wakes the wait");
    assert!(matches!(
        Pin::new(&mut stream).poll_next(&mut task),
        Poll::Ready(Some(Err(StreamTimeoutError::Cancelled(reason))))
            if reason.kind == CancelKind::Deadline
    ));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
}

#[test]
fn zero_duration_still_requires_timer_authority_and_preserves_ready_items() {
    let cx = Cx::for_testing();
    let mut stream = Source::pending([1]).timeout(&cx, Duration::ZERO);
    stream.get_mut().ready = true;
    let mut task = Context::from_waker(Waker::noop());
    assert_eq!(
        Pin::new(&mut stream).poll_next(&mut task),
        Poll::Ready(Some(Err(StreamTimeoutError::TimerUnavailable)))
    );
    assert_eq!(stream.get_ref().polls, 0);
    assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(None));

    let (cx, _, driver) = virtual_context(Budget::INFINITE);
    let mut ready = iter([3]).timeout(&cx, Duration::ZERO);
    assert_eq!(Pin::new(&mut ready).poll_next(&mut task), Poll::Ready(Some(Ok(3))));
    assert_eq!(Pin::new(&mut ready).poll_next(&mut task), Poll::Ready(None));
    let mut pending = Source::pending([]).timeout(&cx, Duration::ZERO);
    assert!(matches!(Pin::new(&mut pending).poll_next(&mut task), Poll::Ready(Some(Err(StreamTimeoutError::Elapsed(_))))));
    assert!(driver.is_empty());
    assert_eq!(registrations(&cx), 0);
}

#[test]
fn explicit_timer_is_not_redirected_by_the_ambient_context() {
    let (cx, clock, driver) = virtual_context(Budget::INFINITE);
    let (ambient, ambient_clock, ambient_driver) = virtual_context(Budget::INFINITE);
    ambient_clock.advance_to(Time::from_secs(1000));
    ambient.cancel_fast(CancelKind::User);
    let _ambient = Cx::set_current(Some(ambient));
    let mut stream = Source::pending([]).timeout(&cx, Duration::from_millis(100));
    let mut task = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
    assert_eq!(driver.next_deadline(), Some(Time::from_millis(100)));
    assert!(ambient_driver.is_empty());
    clock.advance_to(Time::from_millis(100));
    let _ = driver.process_timers();
    assert!(matches!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(Some(Err(StreamTimeoutError::Elapsed(_))))));
    assert!(!cx.is_cancel_requested());
    assert!(driver.is_empty());
    assert!(ambient_driver.is_empty());
}

#[pin_project::pin_project]
struct PinnedLocalSource {
    value: Option<Rc<u8>>,
    #[pin]
    _pin: std::marker::PhantomPinned,
}

impl Stream for PinnedLocalSource {
    type Item = Rc<u8>;

    fn poll_next(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.project().value.take())
    }
}

#[test]
fn pinned_local_and_borrowed_sources_do_not_gain_extra_bounds() {
    let (cx, _, driver) = virtual_context(Budget::INFINITE);
    let value = Rc::new(17);
    let source = PinnedLocalSource {
        value: Some(Rc::clone(&value)),
        _pin: std::marker::PhantomPinned,
    };
    let mut stream = std::pin::pin!(source.timeout(&cx, Duration::from_secs(1)));
    let mut task = Context::from_waker(Waker::noop());
    assert_eq!(stream.as_mut().poll_next(&mut task), Poll::Ready(Some(Ok(value))));
    assert_eq!(stream.as_mut().poll_next(&mut task), Poll::Ready(None));

    let borrowed = String::from("borrowed");
    let mut stream = iter([borrowed.as_str()]).timeout(&cx, Duration::from_secs(1));
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&stream);
    assert_eq!(Pin::new(&mut stream).poll_next(&mut task), Poll::Ready(Some(Ok("borrowed"))));
    assert!(driver.is_empty());
}

#[cfg(not(target_arch = "wasm32"))]
struct Parked {
    rescue: Arc<AtomicBool>,
    polls: Arc<AtomicUsize>,
}

#[cfg(not(target_arch = "wasm32"))]
impl Stream for Parked {
    type Item = u8;

    fn poll_next(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<Option<u8>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if self.rescue.load(Ordering::Acquire) {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_parked_stream_wakes_on_its_timer_or_explicit_context_cancellation() {
    for current_thread in [true, false] {
        for cancel in [false, true] {
            let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(5000)));
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            // This is deliberately distinct from the native polling task's
            // context: only the adapter observes this context's cancellation.
            let cx = context_with_driver(Budget::INFINITE, timer.clone());
            let rescue = Arc::new(AtomicBool::new(false));
            let polls = Arc::new(AtomicUsize::new(0));
            let saved_waker = Arc::new(crate::sync::pl::Mutex::new(None::<Waker>));
            let (parked_tx, parked_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            let worker = std::thread::spawn({
                let cx = cx.clone();
                let timer = timer.clone();
                let rescue = Arc::clone(&rescue);
                let polls = Arc::clone(&polls);
                let saved_waker = Arc::clone(&saved_waker);
                move || {
                    let builder = if current_thread {
                        RuntimeBuilder::current_thread()
                    } else {
                        RuntimeBuilder::multi_thread().worker_threads(2)
                    };
                    let runtime = builder.with_timer_driver(timer.clone()).build().unwrap();
                    let result = runtime.block_on(async {
                        let mut stream = Parked { rescue, polls }
                            .timeout(&cx, Duration::from_millis(100));
                        let mut parked_tx = Some(parked_tx);
                        let result = std::future::poll_fn(|task| {
                            let result = Pin::new(&mut stream).poll_next(task);
                            if result.is_pending() {
                                *saved_waker.lock() = Some(task.waker().clone());
                                if let Some(tx) = parked_tx.take() {
                                    tx.send((timer.pending_count(), registrations(&cx))).unwrap();
                                }
                            }
                            result
                        }).await;
                        assert!(stream.next().await.is_none(), "one terminal adapter error");
                        result
                    });
                    done_tx.send((result, runtime.is_quiescent(), timer.pending_count(), registrations(&cx))).unwrap();
                }
            });
            let parked = parked_rx.recv_timeout(Duration::from_secs(3));
            let reason = CancelReason::user("native stream cancelled")
                .with_cause(CancelReason::timeout().with_message("preserve attribution"));
            if cancel {
                cx.set_cancel_reason(reason.clone());
            } else {
                // Only the native runtime processes timers; the test advances
                // the clock without manually firing a callback or source wake.
                clock.advance_to(Time::from_millis(5100));
            }
            let completed = done_rx.recv_timeout(Duration::from_secs(3));
            let woke_without_rescue = completed.is_ok();
            if !woke_without_rescue {
                rescue.store(true, Ordering::Release);
                let wake = saved_waker.lock().take();
                if let Some(wake) = wake {
                    wake.wake();
                }
            }
            let (result, quiescent, timers, observers) = completed
                .or_else(|_| done_rx.recv_timeout(Duration::from_secs(3)))
                .expect("native stream must finish after the rescue wake");
            worker.join().unwrap();
            assert_eq!(parked.unwrap(), (1, 1), "source actually parked with both wake sources");
            assert!(woke_without_rescue, "native wait missed its timer/cancellation wake");
            if cancel {
                assert_eq!(result, Some(Err(StreamTimeoutError::Cancelled(reason))));
                assert_eq!(polls.load(Ordering::SeqCst), 1, "cancellation skips the source poll");
            } else {
                assert_eq!(result, Some(Err(StreamTimeoutError::Elapsed(Elapsed::new(Time::from_millis(5100))))));
                assert!(polls.load(Ordering::SeqCst) >= 2);
            }
            assert_eq!((timers, observers), (0, 0));
            assert!(quiescent);
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_foreign_owner_unmask_wakes_without_advancing_the_item_clock() {
    for current_thread in [true, false] {
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(5000)));
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let cx = context_with_driver(Budget::INFINITE, timer.clone());
        let reason = CancelReason::user("masked stream cancelled")
            .with_cause(CancelReason::timeout().with_message("preserve masked attribution"));
        let rescue = Arc::new(AtomicBool::new(false));
        let saved_waker = Arc::new(crate::sync::pl::Mutex::new(None::<Waker>));
        let (parked_tx, parked_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn({
            let cx = cx.clone();
            let timer = timer.clone();
            let reason = reason.clone();
            let rescue = Arc::clone(&rescue);
            let saved_waker = Arc::clone(&saved_waker);
            move || {
                let builder = if current_thread {
                    RuntimeBuilder::current_thread()
                } else {
                    RuntimeBuilder::multi_thread().worker_threads(2)
                };
                let runtime = builder.with_timer_driver(timer.clone()).build().unwrap();
                let result = runtime.block_on(async {
                    let mut stream = Parked {
                        rescue,
                        polls: Arc::new(AtomicUsize::new(0)),
                    }
                    .timeout(&cx, Duration::from_secs(3600));
                    let mut parked_tx = Some(parked_tx);
                    std::future::poll_fn(|task| {
                        if let Some(tx) = parked_tx.take() {
                            cx.masked(|| {
                                // Request before the first subscription, so
                                // only leaving the mask can wake the adapter.
                                cx.set_cancel_reason(reason.clone());
                                let result = Pin::new(&mut stream).poll_next(task);
                                assert!(result.is_pending());
                                *saved_waker.lock() = Some(task.waker().clone());
                                tx.send((timer.pending_count(), registrations(&cx)))
                                    .unwrap();
                                result
                            })
                        } else {
                            Pin::new(&mut stream).poll_next(task)
                        }
                    })
                    .await
                });
                done_tx
                    .send((result, runtime.is_quiescent(), registrations(&cx)))
                    .unwrap();
            }
        });
        let parked = parked_rx.recv_timeout(Duration::from_secs(3));
        let completed = done_rx.recv_timeout(Duration::from_secs(3));
        let woke_without_rescue = completed.is_ok();
        if !woke_without_rescue {
            rescue.store(true, Ordering::Release);
            if let Some(wake) = saved_waker.lock().take() {
                wake.wake();
            }
        }
        let (result, quiescent, observers) = completed
            .or_else(|_| done_rx.recv_timeout(Duration::from_secs(3)))
            .expect("masked native stream must finish after the rescue wake");
        worker.join().unwrap();
        assert_eq!(parked.unwrap(), (1, 1), "masked cancellation keeps its observer");
        assert!(woke_without_rescue, "unmask must wake a foreign context's wait");
        assert_eq!(result, Some(Err(StreamTimeoutError::Cancelled(reason))));
        assert_eq!(timer.now(), Time::from_millis(5000));
        assert!(timer.is_empty());
        assert_eq!(observers, 0);
        assert!(quiescent);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_spawn_join_preserves_the_stream_cancellation_result_and_drains() {
    for current_thread in [true, false] {
        let clock = Arc::new(VirtualClock::starting_at(Time::from_millis(5000)));
        let timer = TimerDriverHandle::with_virtual_clock(clock);
        let rescue = Arc::new(AtomicBool::new(false));
        let saved_waker = Arc::new(crate::sync::pl::Mutex::new(None::<Waker>));
        let polls = Arc::new(AtomicUsize::new(0));
        let (parked_tx, parked_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn({
            let timer = timer.clone();
            let rescue = Arc::clone(&rescue);
            let saved_waker = Arc::clone(&saved_waker);
            let polls = Arc::clone(&polls);
            move || {
                let builder = if current_thread {
                    RuntimeBuilder::current_thread()
                } else {
                    RuntimeBuilder::multi_thread()
                        .worker_threads(2)
                        .with_sharded_state(true)
                };
                let runtime = builder.with_timer_driver(timer.clone()).build().unwrap();
                let joined = runtime.block_on(runtime.handle().spawn(async move {
                    let root = Cx::current().expect("native root context");
                    let mut child = root
                        .spawn(move |child_cx| async move {
                            let mut stream = Parked { rescue, polls }
                                .timeout(&child_cx, Duration::from_secs(3600));
                            let mut parked_tx = Some(parked_tx);
                            let result = std::future::poll_fn(|task| {
                                let result = Pin::new(&mut stream).poll_next(task);
                                if result.is_pending() {
                                    *saved_waker.lock() = Some(task.waker().clone());
                                    if let Some(tx) = parked_tx.take() {
                                        tx.send((
                                            child_cx.clone(),
                                            timer.pending_count(),
                                            registrations(&child_cx),
                                        ))
                                        .unwrap();
                                    }
                                }
                                result
                            })
                            .await;
                            assert!(stream.next().await.is_none());
                            assert!(timer.is_empty());
                            assert_eq!(registrations(&child_cx), 0);
                            Outcome::<_, ()>::Ok(result)
                        })
                        .expect("spawn stream consumer");
                    child.join(&root).await
                }));
                let drain = runtime.shutdown_drained(Duration::from_secs(3));
                done_tx
                    .send((joined, drain, runtime.is_quiescent()))
                    .unwrap();
            }
        });
        let parked = parked_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("spawned stream must reach Pending before cancellation");
        let (owner, timers, observers) = parked;
        let reason = CancelReason::user("spawned stream cancelled")
            .with_cause(CancelReason::timeout().with_message("keep nested result"));
        // The controller is a different OS thread from every runtime worker.
        owner.set_cancel_reason(reason.clone());
        let completed = done_rx.recv_timeout(Duration::from_secs(3));
        let woke_without_rescue = completed.is_ok();
        if !woke_without_rescue {
            rescue.store(true, Ordering::Release);
            if let Some(wake) = saved_waker.lock().take() {
                wake.wake();
            }
        }
        let (joined, drain, quiescent) = completed
            .or_else(|_| done_rx.recv_timeout(Duration::from_secs(3)))
            .expect("spawned stream must finish after the rescue wake");
        worker.join().unwrap();
        assert_eq!((timers, observers), (1, 1));
        assert!(woke_without_rescue, "native cancellation must wake the parked child");
        assert!(
            matches!(
                &joined,
                Ok(Outcome::Ok(Some(Err(StreamTimeoutError::Cancelled(actual)))))
                    if actual == &reason
            ),
            "TaskHandle must preserve the acknowledged adapter error: {joined:?}"
        );
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(registrations(&owner), 0);
        assert!(timer.is_empty());
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
