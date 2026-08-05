//! Small, dependency-free future execution primitives.
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

#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(target_arch = "wasm32"))]
use std::task::{Context, Poll, Wake, Waker};

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
            let inner = block_on(std::future::poll_fn(|context| {
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
            std::future::poll_fn(|context| {
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
            std::future::poll_fn(|_| {
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

        block_on(std::future::poll_fn(|context| {
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
        let output = block_on(std::future::poll_fn(|context| {
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
        let observed = block_on(std::future::poll_fn(|context| {
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
            try_block_on(std::future::poll_fn(|_| {
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
