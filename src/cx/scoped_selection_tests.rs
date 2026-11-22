//! Native witnesses for the final selection boundary of scoped operations.
//!
//! The clone hook releases an actual parked task and waits for its scheduler's
//! retirement barrier. It changes owner state inside poll_join, rather than
//! substituting a standalone join handle or relying on a timing-sensitive race.

use super::{Cx, ScopedFirstOkStop, ScopedFirstOkTask, ScopedTimeoutStop, ScopedTimeoutTask};
use crate::runtime::task_handle::RetirementBarrier;
use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{CancelReason, Time};
use parking_lot::Mutex;
use std::future::{Future, Ready, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

#[derive(Clone, Default)]
struct Gate(Arc<GateState>);

#[derive(Default)]
struct GateState {
    open: AtomicBool,
    parked: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl Gate {
    fn release(&self) {
        self.0.open.store(true, Ordering::SeqCst);
        let waker = self.0.waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Future for Gate {
    type Output = ();

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<()> {
        if self.0.open.load(Ordering::SeqCst) {
            return Poll::Ready(());
        }
        *self.0.waker.lock() = Some(task.waker().clone());
        self.0.parked.store(true, Ordering::SeqCst);
        if self.0.open.load(Ordering::SeqCst) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

#[derive(Default)]
struct NativeAttempt {
    release: Gate,
    descendant_parked: AtomicBool,
    descendant_cleaned: AtomicBool,
    retirement: Mutex<Option<Arc<RetirementBarrier>>>,
}

impl NativeAttempt {
    async fn run(self: Arc<Self>, body: Cx) -> u32 {
        *self.retirement.lock() = Some(
            body.inner
                .read()
                .retirement_barrier
                .clone()
                .expect("real admitted body has a retirement barrier"),
        );
        let descendant = Arc::clone(&self);
        let _child = body
            .spawn(move |child| async move {
                let mut cancelled = std::pin::pin!(child.cancelled());
                poll_fn(|task| {
                    let result = cancelled.as_mut().poll(task);
                    if result.is_pending() {
                        descendant.descendant_parked.store(true, Ordering::SeqCst);
                    }
                    result
                })
                .await;
                assert!(child.checkpoint().is_err());
                descendant.descendant_cleaned.store(true, Ordering::SeqCst);
            })
            .unwrap();
        self.release.clone().await;
        42
    }

    async fn await_parked(&self) -> Arc<RetirementBarrier> {
        let watchdog = Instant::now();
        while !self.release.0.parked.load(Ordering::SeqCst)
            || !self.descendant_parked.load(Ordering::SeqCst)
        {
            assert!(
                watchdog.elapsed() < Duration::from_secs(5),
                "native body and descendant must actually park"
            );
            crate::runtime::yield_now().await;
        }
        let barrier = self.retirement.lock().clone().unwrap();
        assert!(!barrier.is_open(), "the gated body has not retired");
        barrier
    }

    fn finish_body(&self, barrier: &RetirementBarrier) {
        self.release.release();
        let watchdog = Instant::now();
        while !barrier.is_open() {
            assert!(
                watchdog.elapsed() < Duration::from_secs(5),
                "the other native worker must retire the released body"
            );
            std::thread::yield_now();
        }
    }
}

fn poll_with<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(waker))
}

// RawWaker is necessary to place a one-shot callback inside the real join's
// clone boundary. Every pointer below owns one Arc reference; the hook remains
// test-only and forwards ordinary wakes to the actual runtime task.
#[allow(unsafe_code)]
mod clone_hook {
    use super::*;
    use std::mem::ManuallyDrop;
    use std::task::{RawWaker, RawWakerVTable};

    pub(super) struct CloneHook {
        parent: Waker,
        action: Mutex<Option<Box<dyn FnOnce() + Send>>>,
        pub(super) fired: AtomicBool,
    }

    impl CloneHook {
        pub(super) fn new(parent: Waker) -> Arc<Self> {
            Arc::new(Self {
                parent,
                action: Mutex::new(None),
                fired: AtomicBool::new(false),
            })
        }

        pub(super) fn arm(&self, action: impl FnOnce() + Send + 'static) {
            *self.action.lock() = Some(Box::new(action));
        }

        pub(super) fn waker(self: &Arc<Self>) -> Waker {
            let data = Arc::into_raw(Arc::clone(self)).cast();
            // SAFETY: the vtable consumes exactly this owned Arc reference.
            unsafe { Waker::from_raw(RawWaker::new(data, &VTABLE)) }
        }
    }

    unsafe fn clone_waker(data: *const ()) -> RawWaker {
        // SAFETY: every pointer was produced by Arc::into_raw. ManuallyDrop
        // borrows that reference; cloning creates the newly returned owner.
        let hook = ManuallyDrop::new(unsafe { Arc::<CloneHook>::from_raw(data.cast()) });
        let cloned = Arc::clone(&hook);
        let action = hook.action.lock().take();
        if let Some(action) = action {
            hook.fired.store(true, Ordering::SeqCst);
            action();
        }
        RawWaker::new(Arc::into_raw(cloned).cast(), &VTABLE)
    }

    unsafe fn wake(data: *const ()) {
        // SAFETY: wake consumes this one owned reference.
        let hook = unsafe { Arc::<CloneHook>::from_raw(data.cast()) };
        hook.parent.wake_by_ref();
    }

    unsafe fn wake_by_ref(data: *const ()) {
        // SAFETY: wake_by_ref borrows without consuming the owned reference.
        let hook = ManuallyDrop::new(unsafe { Arc::<CloneHook>::from_raw(data.cast()) });
        hook.parent.wake_by_ref();
    }

    unsafe fn drop_waker(data: *const ()) {
        // SAFETY: drop consumes this one owned reference, exactly once.
        drop(unsafe { Arc::<CloneHook>::from_raw(data.cast()) });
    }

    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_waker, wake, wake_by_ref, drop_waker);
}

fn run_native<F, Fut>(test: F)
where
    F: Fn(Cx, Arc<VirtualClock>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let test = Arc::new(test);
            for sharded in [false, true] {
                let clock = Arc::new(VirtualClock::new());
                let runtime = RuntimeBuilder::multi_thread()
                    .worker_threads(2)
                    .with_sharded_state(sharded)
                    .with_timer_driver(TimerDriverHandle::with_virtual_clock(Arc::clone(&clock)))
                    .build()
                    .unwrap();
                let test = Arc::clone(&test);
                runtime.block_on(runtime.handle().spawn(async move {
                    test(Cx::current().expect("native owner context"), clock).await;
                }));
                let report = runtime.shutdown_drained(Duration::from_secs(5));
                assert_eq!(report.outcome, RootDrainOutcome::Quiescent, "{report:?}");
                assert_eq!(report.live_tasks, 0);
                assert_eq!(report.pending_spawns, 0);
                assert_eq!(report.pending_obligations, 0);
            }
        }));
        let _ = send.send(result);
    });
    let result = receive
        .recv_timeout(Duration::from_secs(45))
        .expect("native selection regression must drain");
    worker.join().unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

#[test]
fn scoped_timeout_observes_cancel_and_deadline_inside_native_join_without_losing_value() {
    for (cancel, expire) in [(true, false), (false, true), (true, true)] {
        run_native(move |owner, clock| async move {
            let native = Arc::new(NativeAttempt::default());
            let body = Arc::clone(&native);
            let mut timeout =
                Box::pin(owner.timeout_scoped(Duration::from_secs(60), move |cx| body.run(cx)));
            let parent = poll_fn(|task| Poll::Ready(task.waker().clone())).await;
            let hook = clone_hook::CloneHook::new(parent);
            let waker = hook.waker();
            assert!(poll_with(timeout.as_mut(), &waker).is_pending());
            let barrier = native.await_parked().await;

            let reason = CancelReason::user("cancel inside native timeout join")
                .with_cause(CancelReason::shutdown());
            let stopped_owner = owner.clone();
            let stop_reason = reason.clone();
            let released = Arc::clone(&native);
            hook.arm(move || {
                if cancel {
                    stopped_owner.set_cancel_reason(stop_reason);
                }
                if expire {
                    clock.advance_to(Time::from_secs(60));
                }
                released.finish_body(&barrier);
            });
            // The same Waker keeps the cancellation observer unchanged. Its
            // next clone is the direct task's real retirement-barrier poll.
            let result = poll_with(timeout.as_mut(), &waker);
            assert!(hook.fired.load(Ordering::SeqCst));
            let report = match result {
                Poll::Ready(result) => result.unwrap(),
                Poll::Pending => timeout.await.unwrap(),
            };
            if cancel {
                assert!(
                    matches!(report.stop, ScopedTimeoutStop::Cancelled(actual) if actual == reason)
                );
                assert!(!owner.inner.read().cancel_acknowledged);
            } else {
                assert!(matches!(report.stop, ScopedTimeoutStop::TimedOut));
            }
            assert!(matches!(report.task, ScopedTimeoutTask::Joined(Ok(42))));
            assert!(report.region_id.is_some());
            let close = report.close.unwrap().unwrap();
            assert!(
                close
                    .cleanup_outcome
                    .as_ref()
                    .is_none_or(|outcome| outcome.is_ok())
            );
            assert!(close.descendant_panic.is_none());
            assert!(native.descendant_cleaned.load(Ordering::SeqCst));
            if cancel {
                assert!(owner.checkpoint().is_err());
            }
        });
    }
}

#[test]
fn scoped_first_ok_observes_cancel_inside_native_join_without_losing_success() {
    run_native(|owner, _clock| async move {
        let native = Arc::new(NativeAttempt::default());
        let body = Arc::clone(&native);
        let mut chain =
            Box::pin(owner.first_ok_scoped([move |cx| async move {
                Ok::<_, &'static str>(body.run(cx).await)
            }]));
        let parent = poll_fn(|task| Poll::Ready(task.waker().clone())).await;
        let hook = clone_hook::CloneHook::new(parent);
        let waker = hook.waker();
        assert!(poll_with(chain.as_mut(), &waker).is_pending());
        let barrier = native.await_parked().await;

        let reason = CancelReason::user("cancel inside native fallback join")
            .with_cause(CancelReason::shutdown());
        let stopped_owner = owner.clone();
        let stop_reason = reason.clone();
        let released = Arc::clone(&native);
        hook.arm(move || {
            stopped_owner.set_cancel_reason(stop_reason);
            released.finish_body(&barrier);
        });
        let result = poll_with(chain.as_mut(), &waker);
        assert!(hook.fired.load(Ordering::SeqCst));
        let report = match result {
            Poll::Ready(result) => result.unwrap(),
            Poll::Pending => chain.await.unwrap(),
        };
        assert!(matches!(report.stop, ScopedFirstOkStop::Cancelled(actual) if actual == reason));
        assert_eq!(report.attempts.len(), 1);
        assert!(matches!(
            report.attempts[0].task,
            ScopedFirstOkTask::Joined(Ok(Ok(42)))
        ));
        let close = report.attempts[0].close.as_ref().unwrap().as_ref().unwrap();
        assert!(
            close
                .cleanup_outcome
                .as_ref()
                .is_none_or(|outcome| outcome.is_ok())
        );
        assert!(close.descendant_panic.is_none());
        assert!(native.descendant_cleaned.load(Ordering::SeqCst));
        assert!(!owner.inner.read().cancel_acknowledged);
        assert!(owner.checkpoint().is_err());
    });
}

#[test]
fn scoped_first_ok_observes_cancellation_from_exhausted_native_fallback_input() {
    run_native(|owner, _clock| async move {
        let native = Arc::new(NativeAttempt::default());
        let input_native = Arc::clone(&native);
        let input_owner = owner.clone();
        let reason =
            CancelReason::user("fallback generator stopped").with_cause(CancelReason::shutdown());
        let input_reason = reason.clone();
        let mut supplied = false;
        let factories = std::iter::from_fn(move || {
            if supplied {
                assert!(
                    input_native.descendant_cleaned.load(Ordering::SeqCst),
                    "the previous subtree must drain before pulling the tail"
                );
                input_owner.set_cancel_reason(input_reason.clone());
                None
            } else {
                supplied = true;
                let body = Arc::clone(&input_native);
                Some(move |cx| async move {
                    body.run(cx).await;
                    Err::<u32, _>("application failure")
                })
            }
        });
        let mut chain = Box::pin(owner.first_ok_scoped(factories));
        let waker = poll_fn(|task| Poll::Ready(task.waker().clone())).await;
        assert!(poll_with(chain.as_mut(), &waker).is_pending());
        let _barrier = native.await_parked().await;
        native.release.release();
        let report = chain.await.unwrap();
        assert!(matches!(report.stop, ScopedFirstOkStop::Cancelled(actual) if actual == reason));
        assert_eq!(report.attempts.len(), 1);
        assert!(matches!(
            report.attempts[0].task,
            ScopedFirstOkTask::Joined(Ok(Err("application failure")))
        ));
        assert!(report.attempts[0].close.as_ref().unwrap().is_ok());
        assert!(!owner.inner.read().cancel_acknowledged);
        assert!(owner.checkpoint().is_err());
    });
}

type UnstartedFactory = fn(Cx) -> Ready<Result<u32, &'static str>>;

fn never_start(_: Cx) -> Ready<Result<u32, &'static str>> {
    panic!("input cancellation must prevent factory invocation")
}

#[test]
fn scoped_first_ok_initial_next_cancellation_precedes_empty_and_missing_runtime() {
    for has_factory in [false, true] {
        let owner = Cx::detached_cancel_context();
        let input_owner = owner.clone();
        let reason = CancelReason::user("cancel from initial iterator callback");
        let input_reason = reason.clone();
        let factories = std::iter::from_fn(move || {
            input_owner.set_cancel_reason(input_reason.clone());
            has_factory.then_some(never_start as UnstartedFactory)
        });
        let mut chain = Box::pin(owner.first_ok_scoped(factories));
        let Poll::Ready(Ok(report)) = poll_with(chain.as_mut(), Waker::noop()) else {
            panic!("input cancellation must precede empty input and missing runtime");
        };
        assert!(matches!(report.stop, ScopedFirstOkStop::Cancelled(actual) if actual == reason));
        assert!(report.attempts.is_empty());
        assert!(!owner.inner.read().cancel_acknowledged);
    }
}

struct CancelOnConversion {
    owner: Cx,
    pulls: Arc<AtomicUsize>,
}

struct CountedEmpty(Arc<AtomicUsize>);

impl Iterator for CountedEmpty {
    type Item = UnstartedFactory;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.fetch_add(1, Ordering::SeqCst);
        None
    }
}

impl IntoIterator for CancelOnConversion {
    type Item = UnstartedFactory;
    type IntoIter = CountedEmpty;

    fn into_iter(self) -> Self::IntoIter {
        self.owner
            .set_cancel_reason(CancelReason::user("cancel while converting lazy input"));
        CountedEmpty(self.pulls)
    }
}

#[test]
fn scoped_first_ok_input_conversion_cancellation_prevents_first_pull() {
    let owner = Cx::detached_cancel_context();
    let pulls = Arc::new(AtomicUsize::new(0));
    let factories = CancelOnConversion {
        owner: owner.clone(),
        pulls: Arc::clone(&pulls),
    };
    let mut chain = Box::pin(owner.first_ok_scoped(factories));
    let Poll::Ready(Ok(report)) = poll_with(chain.as_mut(), Waker::noop()) else {
        panic!("conversion cancellation must return without runtime admission");
    };
    assert!(matches!(report.stop, ScopedFirstOkStop::Cancelled(_)));
    assert!(report.attempts.is_empty());
    assert_eq!(pulls.load(Ordering::SeqCst), 0);
    assert!(!owner.inner.read().cancel_acknowledged);
}
