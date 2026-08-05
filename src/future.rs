//! Small future execution primitives with explicit wake and pinning behavior.
//!
//! The blocking entry points in this crate-private `crate::util::future` module
//! are an alongside-incumbent kernel for `CAP-FUTURES-STREAMS`. They poll on
//! the calling thread and sleep with [`std::thread::park`] after
//! `Poll::Pending`; they do not create an executor, spawn a task, or acquire
//! ambient [`Cx`](crate::Cx) authority.
//!
//! An Asupersync runtime thread is deliberately rejected. Parking such a
//! thread can prevent the scheduler work needed by the future from making
//! progress. Ordinary threads, recursive calls outside a runtime, and the
//! runtime's dedicated blocking-pool threads do not have an installed
//! [`Runtime`](crate::runtime::Runtime) handle and are admitted.

#![forbid(unsafe_code)]

use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(target_arch = "wasm32"))]
use std::task::{Wake, Waker};

/// Builds a future that delegates every poll to an `FnMut` closure.
///
/// The standard-library primitive already has the exact consumed semantics, so
/// the owned dependency-replacement layer adopts it directly rather than
/// maintaining a second implementation.
#[allow(unused_imports)]
pub(crate) use std::future::poll_fn;

/// Builds a future that never completes and never schedules a wake.
///
/// This is the standard-library primitive, adopted directly because the
/// incumbent adds no behavior beyond it.
#[allow(unused_imports)]
pub(crate) use std::future::pending;

/// Polls `future` exactly once and resolves immediately with the observation.
///
/// `Poll::Ready(value)` becomes `Some(value)`, while `Poll::Pending` becomes
/// `None` without waiting for a wake. The returned future adds no `Send`,
/// `Unpin`, or `'static` bound and allocates no heap storage.
// Preserve the consumed no-`Cx` signature without defining an `async fn`.
#[allow(clippy::manual_async_fn)]
pub(crate) fn poll_once<F>(future: F) -> impl Future<Output = Option<F::Output>>
where
    F: Future,
{
    async move {
        let mut future = std::pin::pin!(future);
        poll_fn(|context| {
            Poll::Ready(match future.as_mut().poll(context) {
                Poll::Ready(output) => Some(output),
                Poll::Pending => None,
            })
        })
        .await
    }
}

/// Future returned by [`yield_now`].
#[derive(Debug, Default)]
pub(crate) struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            context.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Yields once to the polling executor.
///
/// The first poll schedules exactly one wake and returns `Poll::Pending`.
/// Every later poll returns `Poll::Ready(())` without another wake.
#[must_use]
pub(crate) const fn yield_now() -> YieldNow {
    YieldNow { yielded: false }
}

/// Joins two futures, polling left before right until both complete.
pub(crate) fn zip<F1, F2>(future1: F1, future2: F2) -> Zip<F1, F2>
where
    F1: Future,
    F2: Future,
{
    Zip {
        future1: Some(future1),
        output1: None,
        future2: Some(future2),
        output2: None,
    }
}

/// Future returned by [`zip`].
#[pin_project::pin_project]
#[derive(Debug)]
#[must_use = "futures do nothing unless polled or awaited"]
pub(crate) struct Zip<F1, F2>
where
    F1: Future,
    F2: Future,
{
    #[pin]
    future1: Option<F1>,
    output1: Option<F1::Output>,
    #[pin]
    future2: Option<F2>,
    output2: Option<F2::Output>,
}

impl<F1, F2> Future for Zip<F1, F2>
where
    F1: Future,
    F2: Future,
{
    type Output = (F1::Output, F2::Output);

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        if let Some(future) = this.future1.as_mut().as_pin_mut() {
            if let Poll::Ready(output) = future.poll(context) {
                *this.output1 = Some(output);
                this.future1.set(None);
            }
        }

        if let Some(future) = this.future2.as_mut().as_pin_mut() {
            if let Poll::Ready(output) = future.poll(context) {
                *this.output2 = Some(output);
                this.future2.set(None);
            }
        }

        take_zip_outputs(this.output1, this.output2)
    }
}

fn take_zip_outputs<T1, T2>(
    output1: &mut Option<T1>,
    output2: &mut Option<T2>,
) -> Poll<(T1, T2)> {
    match (output1.take(), output2.take()) {
        (Some(output1), Some(output2)) => Poll::Ready((output1, output2)),
        (remaining1, remaining2) => {
            *output1 = remaining1;
            *output2 = remaining2;
            Poll::Pending
        }
    }
}

/// Returns the first future to complete, preferring `future1` when both are ready.
pub(crate) fn or<T, F1, F2>(future1: F1, future2: F2) -> Or<F1, F2>
where
    F1: Future<Output = T>,
    F2: Future<Output = T>,
{
    Or { future1, future2 }
}

/// Future returned by [`or`].
#[pin_project::pin_project]
#[derive(Debug)]
#[must_use = "futures do nothing unless polled or awaited"]
pub(crate) struct Or<F1, F2> {
    #[pin]
    future1: F1,
    #[pin]
    future2: F2,
}

impl<T, F1, F2> Future for Or<F1, F2>
where
    F1: Future<Output = T>,
    F2: Future<Output = T>,
{
    type Output = T;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        if let Poll::Ready(output) = this.future1.poll(context) {
            return Poll::Ready(output);
        }
        if let Poll::Ready(output) = this.future2.poll(context) {
            return Poll::Ready(output);
        }
        Poll::Pending
    }
}

/// Reason the owned blocking kernel refused to poll a future.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockOnError {
    /// The current thread has an installed Asupersync runtime handle.
    ///
    /// This includes scheduler workers and the thread currently driving
    /// [`Runtime::block_on`](crate::runtime::Runtime::block_on). The kernel
    /// conservatively rejects both because the public handle does not expose a
    /// reliable worker-versus-driver distinction.
    RuntimeContext,
    /// Blocking a host thread is unsupported on the current target.
    UnsupportedPlatform,
}

impl fmt::Display for BlockOnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeContext => formatter.write_str(
                "cannot block the current thread while an Asupersync runtime handle is installed",
            ),
            Self::UnsupportedPlatform => {
                formatter.write_str("blocking future execution is unsupported on this target")
            }
        }
    }
}

impl StdError for BlockOnError {}

/// Polls `future` to completion on the calling thread.
///
/// The future is pinned on this function's stack. No `Send`, `Unpin`, or
/// `'static` bound is added. After a pending poll, the thread remains parked
/// until the future's waker records a notification. Notifications are
/// coalesced, and the notification flag is checked on both sides of the park
/// boundary so a wake racing with `park` is not lost.
///
/// Use [`try_block_on`] when a runtime-context refusal must be handled instead
/// of treated as programmer error.
///
/// # Panics
///
/// Panics without polling the future when called from an Asupersync runtime
/// context or on a platform without host-thread parking. A panic produced by
/// the future itself propagates unchanged.
pub(crate) fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    try_block_on(future).unwrap_or_else(|error| panic!("{error}"))
}

/// Tries to poll `future` to completion on the calling thread.
///
/// This has the same parking, pinning, and wake behavior as [`block_on`], but
/// reports an unsupported execution context as a typed error. The future is
/// dropped without being polled when the call is refused.
///
/// # Errors
///
/// Returns [`BlockOnError::RuntimeContext`] whenever
/// [`Runtime::current_handle`](crate::runtime::Runtime::current_handle) is
/// present. Returns [`BlockOnError::UnsupportedPlatform`] on targets without
/// native host-thread parking.
pub(crate) fn try_block_on<F>(future: F) -> Result<F::Output, BlockOnError>
where
    F: Future,
{
    #[cfg(target_arch = "wasm32")]
    {
        drop(future);
        Err(BlockOnError::UnsupportedPlatform)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        if crate::runtime::Runtime::current_handle().is_some() {
            return Err(BlockOnError::RuntimeContext);
        }
        Ok(block_on_with_park(future, |_| std::thread::park()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
struct ThreadNotification {
    thread: std::thread::Thread,
    notified: AtomicBool,
}

#[cfg(not(target_arch = "wasm32"))]
impl ThreadNotification {
    fn new() -> Self {
        Self {
            thread: std::thread::current(),
            notified: AtomicBool::new(false),
        }
    }

    fn prepare_for_poll(&self) {
        // Acquire a wake that preceded this poll before discarding its
        // scheduling token. The poll observes the future's current state, so a
        // pre-poll token is no longer needed afterward.
        self.notified.swap(false, Ordering::AcqRel);
    }

    fn record_notification(&self) {
        self.notified.store(true, Ordering::Release);
    }

    fn notify(&self) {
        // Store first, then unpark. If the waiter has not parked yet, Thread's
        // one-bit token makes its next park return immediately; the atomic flag
        // also distinguishes a real wake from a spurious return.
        self.record_notification();
        self.thread.unpark();
    }

    fn wait<P>(&self, park: &mut P)
    where
        P: FnMut(&Self),
    {
        while !self.notified.swap(false, Ordering::AcqRel) {
            park(self);
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Wake for ThreadNotification {
    fn wake(self: Arc<Self>) {
        self.notify();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.notify();
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn block_on_with_park<F, P>(future: F, mut park: P) -> F::Output
where
    F: Future,
    P: FnMut(&ThreadNotification),
{
    let notification = Arc::new(ThreadNotification::new());
    let waker = Waker::from(Arc::clone(&notification));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);

    loop {
        notification.prepare_for_poll();
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => notification.wait(&mut park),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

    use super::*;
    use crate::runtime::{BlockingPool, RuntimeBuilder};
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[derive(Default)]
    struct CountingWaker {
        wakes: AtomicUsize,
    }

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct PendingDrop {
        polls: Rc<Cell<usize>>,
        drops: Rc<Cell<usize>>,
    }

    impl Future for PendingDrop {
        type Output = u8;

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.set(self.polls.get() + 1);
            Poll::Pending
        }
    }

    impl Drop for PendingDrop {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    struct ReadyDrop {
        output: u8,
        polls: Rc<Cell<usize>>,
        drops: Rc<Cell<usize>>,
    }

    impl Future for ReadyDrop {
        type Output = u8;

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.set(self.polls.get() + 1);
            Poll::Ready(self.output)
        }
    }

    impl Drop for ReadyDrop {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    struct DropCounter {
        drops: Rc<Cell<usize>>,
    }

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    #[test]
    fn poll_fn_forwards_context_and_calls_once_per_wrapper_poll() {
        let wake_state = Arc::new(CountingWaker::default());
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut context = Context::from_waker(&waker);
        let polls = Cell::new(0_usize);
        let mut future = std::pin::pin!(poll_fn(|received_context| {
            assert!(received_context.waker().will_wake(&waker));
            let current = polls.get();
            polls.set(current + 1);
            if current == 0 {
                Poll::Pending
            } else {
                Poll::Ready(41_u8)
            }
        }));

        assert_eq!(future.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(polls.get(), 1);
        assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(41));
        assert_eq!(polls.get(), 2);
        assert_eq!(wake_state.wakes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn poll_once_observes_ready_and_pending_without_waiting() {
        assert_eq!(block_on(poll_once(async { 43_u8 })), Some(43));

        let polls = Rc::new(Cell::new(0_usize));
        let drops = Rc::new(Cell::new(0_usize));
        let observed = block_on(poll_once(PendingDrop {
            polls: Rc::clone(&polls),
            drops: Rc::clone(&drops),
        }));

        assert_eq!(observed, None);
        assert_eq!(polls.get(), 1);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn yield_now_wakes_once_then_remains_ready() {
        let wake_state = Arc::new(CountingWaker::default());
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut context = Context::from_waker(&waker);
        let mut future = std::pin::pin!(yield_now());

        assert_eq!(future.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(wake_state.wakes.load(Ordering::Relaxed), 1);
        assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(()));
        assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(()));
        assert_eq!(wake_state.wakes.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn pending_never_completes_or_schedules_a_wake() {
        let wake_state = Arc::new(CountingWaker::default());
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut context = Context::from_waker(&waker);
        let mut future = std::pin::pin!(pending::<u8>());

        assert_eq!(future.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(future.as_mut().poll(&mut context), Poll::Pending);
        assert_eq!(wake_state.wakes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn zip_polls_left_then_right_and_stops_polling_completed_children() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let left_log = Rc::clone(&log);
        let left = poll_fn(move |_| {
            left_log.borrow_mut().push("left");
            Poll::Ready(47_u8)
        });

        let right_log = Rc::clone(&log);
        let right_polls = Rc::new(Cell::new(0_usize));
        let observed_right_polls = Rc::clone(&right_polls);
        let right = poll_fn(move |context| {
            right_log.borrow_mut().push("right");
            let current = right_polls.get();
            right_polls.set(current + 1);
            if current == 0 {
                context.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(53_u8)
            }
        });

        assert_eq!(block_on(zip(left, right)), (47, 53));
        assert_eq!(&*log.borrow(), &["left", "right", "right"]);
        assert_eq!(observed_right_polls.get(), 2);
    }

    #[test]
    fn dropping_pending_zip_drops_retained_output_and_unfinished_child() {
        let output_drops = Rc::new(Cell::new(0_usize));
        let pending_polls = Rc::new(Cell::new(0_usize));
        let pending_drops = Rc::new(Cell::new(0_usize));
        let wake_state = Arc::new(CountingWaker::default());
        let waker = Waker::from(Arc::clone(&wake_state));
        let mut context = Context::from_waker(&waker);

        {
            let left_output_drops = Rc::clone(&output_drops);
            let joined = zip(
                async move {
                    DropCounter {
                        drops: left_output_drops,
                    }
                },
                PendingDrop {
                    polls: Rc::clone(&pending_polls),
                    drops: Rc::clone(&pending_drops),
                },
            );
            let mut joined = std::pin::pin!(joined);

            assert!(joined.as_mut().poll(&mut context).is_pending());
            assert_eq!(output_drops.get(), 0);
            assert_eq!(pending_drops.get(), 0);
        }

        assert_eq!(output_drops.get(), 1);
        assert_eq!(pending_polls.get(), 1);
        assert_eq!(pending_drops.get(), 1);
        assert_eq!(wake_state.wakes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn or_is_left_biased_and_drops_the_loser_with_the_wrapper() {
        let left_polls = Rc::new(Cell::new(0_usize));
        let left_drops = Rc::new(Cell::new(0_usize));
        let skipped_right_polls = Rc::new(Cell::new(0_usize));
        let skipped_right_drops = Rc::new(Cell::new(0_usize));
        let result = block_on(or(
            ReadyDrop {
                output: 59,
                polls: Rc::clone(&left_polls),
                drops: Rc::clone(&left_drops),
            },
            ReadyDrop {
                output: 61,
                polls: Rc::clone(&skipped_right_polls),
                drops: Rc::clone(&skipped_right_drops),
            },
        ));

        assert_eq!(result, 59);
        assert_eq!(left_polls.get(), 1);
        assert_eq!(left_drops.get(), 1);
        assert_eq!(skipped_right_polls.get(), 0);
        assert_eq!(skipped_right_drops.get(), 1);

        let pending_polls = Rc::new(Cell::new(0_usize));
        let pending_drops = Rc::new(Cell::new(0_usize));
        let right_polls = Rc::new(Cell::new(0_usize));
        let right_drops = Rc::new(Cell::new(0_usize));
        let result = block_on(or(
            PendingDrop {
                polls: Rc::clone(&pending_polls),
                drops: Rc::clone(&pending_drops),
            },
            ReadyDrop {
                output: 67,
                polls: Rc::clone(&right_polls),
                drops: Rc::clone(&right_drops),
            },
        ));

        assert_eq!(result, 67);
        assert_eq!(pending_polls.get(), 1);
        assert_eq!(pending_drops.get(), 1);
        assert_eq!(right_polls.get(), 1);
        assert_eq!(right_drops.get(), 1);
    }

    #[test]
    fn ready_future_completes_without_parking() {
        let park_calls = Cell::new(0_usize);
        let output = block_on_with_park(async { 42_u8 }, |_| {
            park_calls.set(park_calls.get() + 1);
        });

        assert_eq!(output, 42);
        assert_eq!(park_calls.get(), 0);
    }

    #[test]
    fn borrowed_non_send_future_and_recursive_call_are_admitted() {
        let value = Rc::new(Cell::new(1_u8));
        let borrowed = &value;

        let output = block_on(async {
            borrowed.set(2);
            let inner_polls = Cell::new(0_usize);
            let inner = block_on(poll_fn(|context| {
                let current = inner_polls.get();
                inner_polls.set(current + 1);
                if current == 0 {
                    context.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    borrowed.set(3);
                    Poll::Ready(borrowed.get())
                }
            }));
            assert_eq!(inner_polls.get(), 2);
            inner + borrowed.get()
        });

        assert_eq!(output, 6);
        assert_eq!(value.get(), 3);
    }

    #[test]
    fn wakes_during_poll_are_coalesced_without_parking() {
        let polls = Cell::new(0_usize);
        let park_calls = Cell::new(0_usize);
        let output = block_on_with_park(
            poll_fn(|context| {
                let current = polls.get();
                polls.set(current + 1);
                if current == 0 {
                    for _ in 0..4 {
                        context.waker().wake_by_ref();
                    }
                    Poll::Pending
                } else {
                    Poll::Ready(7_u8)
                }
            }),
            |_| park_calls.set(park_calls.get() + 1),
        );

        assert_eq!(output, 7);
        assert_eq!(polls.get(), 2);
        assert_eq!(park_calls.get(), 0);
    }

    #[test]
    fn spurious_park_return_does_not_trigger_an_unnotified_poll() {
        let polls = Cell::new(0_usize);
        let park_calls = Cell::new(0_usize);
        let output = block_on_with_park(
            poll_fn(|_| {
                let current = polls.get();
                polls.set(current + 1);
                if current == 0 {
                    Poll::Pending
                } else {
                    Poll::Ready(11_u8)
                }
            }),
            |notification| {
                let current = park_calls.get();
                park_calls.set(current + 1);
                if current == 1 {
                    notification.record_notification();
                }
            },
        );

        assert_eq!(output, 11);
        assert_eq!(polls.get(), 2);
        assert_eq!(park_calls.get(), 2);
    }

    #[test]
    fn repeated_polls_receive_the_same_waker_identity() {
        let first_waker = RefCell::new(None::<Waker>);
        let polls = Cell::new(0_usize);

        block_on(poll_fn(|context| {
            let current = polls.get();
            polls.set(current + 1);
            if current == 0 {
                first_waker.replace(Some(context.waker().clone()));
                context.waker().wake_by_ref();
                Poll::Pending
            } else {
                assert!(
                    first_waker
                        .borrow()
                        .as_ref()
                        .is_some_and(|waker| waker.will_wake(context.waker()))
                );
                Poll::Ready(())
            }
        }));

        assert_eq!(polls.get(), 2);
    }

    #[test]
    fn wake_after_pending_makes_progress() {
        let ready = Arc::new(AtomicBool::new(false));
        let parked_waker = Arc::new(Mutex::new(None::<Waker>));
        let (polled_tx, polled_rx) = std::sync::mpsc::channel();

        let helper_ready = Arc::clone(&ready);
        let helper_waker = Arc::clone(&parked_waker);
        let helper = std::thread::spawn(move || {
            polled_rx.recv().expect("future reports its pending poll");
            helper_ready.store(true, Ordering::Release);
            helper_waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .expect("pending future installed its waker")
                .wake();
        });

        let mut reported_pending = false;
        let output = block_on(poll_fn(|context| {
            if ready.load(Ordering::Acquire) {
                return Poll::Ready(19_u8);
            }
            parked_waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .replace(context.waker().clone());
            if !reported_pending {
                reported_pending = true;
                polled_tx.send(()).expect("wake helper remains available");
            }
            Poll::Pending
        }));

        helper.join().expect("wake helper does not panic");
        assert_eq!(output, 19);
    }

    #[test]
    fn explicit_cancellation_wake_makes_progress() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let parked_waker = Arc::new(Mutex::new(None::<Waker>));
        let (polled_tx, polled_rx) = std::sync::mpsc::channel();

        let helper_cancelled = Arc::clone(&cancelled);
        let helper_waker = Arc::clone(&parked_waker);
        let helper = std::thread::spawn(move || {
            polled_rx.recv().expect("future reports its pending poll");
            helper_cancelled.store(true, Ordering::Release);
            helper_waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .expect("pending future installed its waker")
                .wake();
        });

        let mut reported_pending = false;
        let observed = block_on(poll_fn(|context| {
            if cancelled.load(Ordering::Acquire) {
                return Poll::Ready("cancelled");
            }
            parked_waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .replace(context.waker().clone());
            if !reported_pending {
                reported_pending = true;
                polled_tx.send(()).expect("cancel helper remains available");
            }
            Poll::Pending
        }));

        helper.join().expect("cancel helper does not panic");
        assert_eq!(observed, "cancelled");
    }

    #[test]
    fn future_panic_propagates_without_poisoning_kernel_state() {
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(async { panic!("future panic sentinel") });
        }));

        assert!(panic.is_err());
        assert_eq!(block_on(async { 23_u8 }), 23);
    }

    #[test]
    fn installed_runtime_context_is_refused_before_poll() {
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("runtime build");
        let polls = Cell::new(0_usize);

        let result = runtime.block_on(async {
            try_block_on(poll_fn(|_| {
                polls.set(polls.get() + 1);
                Poll::Ready(31_u8)
            }))
        });

        assert_eq!(result, Err(BlockOnError::RuntimeContext));
        assert_eq!(polls.get(), 0);
    }

    #[test]
    fn blocking_pool_thread_is_admitted() {
        let pool = BlockingPool::new(1, 1);
        let output = Arc::new(AtomicUsize::new(0));
        let task_output = Arc::clone(&output);
        let task = pool.spawn(move || {
            task_output.store(block_on(async { 37_usize }), Ordering::Release);
        });

        assert!(task.wait_timeout(Duration::from_secs(2)));
        assert_eq!(output.load(Ordering::Acquire), 37);
        assert!(pool.shutdown_and_wait(Duration::from_secs(2)));
    }
}
