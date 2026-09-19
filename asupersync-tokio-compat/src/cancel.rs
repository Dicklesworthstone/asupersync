//! Cancellation-signal bridge for compatibility futures.
//!
//! Provides [`CancelAware`], a wrapper driven by an explicit [`CancelSignal`].
//! The wrapper does not inspect an Asupersync `Cx` itself. An outer adapter,
//! such as [`crate::runtime::with_tokio_context`], must observe its `Cx` and
//! call [`CancelAware::request_cancel`] when cancellation becomes visible.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};

use pin_project_lite::pin_project;

use crate::CancellationMode;

const DEFAULT_TIMEOUT_FALLBACK_POLLS: u8 = 1;

#[derive(Debug, Default)]
struct SignalState {
    requested: AtomicBool,
    // Weak registrations never keep an abandoned future or its task alive.
    waiters: Mutex<Vec<Weak<CancelWaiter>>>,
}

#[derive(Debug)]
struct CancelWaiter {
    waker: Mutex<Option<Waker>>,
}

/// Cloneable cancellation signal shared between adapters and wrapped futures.
///
/// One signal may cancel multiple futures. Cancellation wakes every registered
/// future, including an inner future that has no independent source of wakeups.
#[derive(Debug, Clone, Default)]
pub struct CancelSignal {
    state: Arc<SignalState>,
}

impl CancelSignal {
    /// Construct a fresh unset cancellation signal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation and wake all registered futures.
    ///
    /// Repeated requests are harmless. Wakers run outside signal/registration
    /// locks, so callbacks may reenter this signal. If a callback panics, the
    /// remaining waiters are still notified before the first panic is resumed.
    pub fn cancel(&self) {
        if self.state.requested.swap(true, Ordering::AcqRel) {
            return;
        }
        let waiters = {
            let mut waiters = self
                .state
                .waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *waiters)
        };
        let mut first_panic = None;
        for waiter in waiters {
            let Some(waiter) = waiter.upgrade() else {
                continue;
            };
            let waker = waiter
                .waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(waker) = waker {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake()));
                if let Err(payload) = result {
                    if first_panic.is_none() {
                        first_panic = Some(payload);
                    }
                }
            }
        }
        if let Some(payload) = first_panic {
            std::panic::resume_unwind(payload);
        }
    }

    /// Return true once cancellation has been requested.
    #[must_use]
    pub fn is_cancel_requested(&self) -> bool {
        self.state.requested.load(Ordering::Acquire)
    }

    fn register(&self, slot: &mut Option<Arc<CancelWaiter>>, waker: &Waker) {
        // Cloning and retiring a Waker can run arbitrary callbacks. Neither is
        // allowed beneath a registry or per-waiter lock.
        let waker = waker.clone();
        if let Some(waiter) = slot {
            let old = waiter
                .waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .replace(waker);
            drop(old);
            return;
        }

        let waiter = Arc::new(CancelWaiter {
            waker: Mutex::new(Some(waker)),
        });
        {
            let mut waiters = self
                .state
                .waiters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Reclaim dead registrations during admission, not by retaining
            // task-owning Wakers until an eventual cancellation request.
            waiters.retain(|entry| entry.strong_count() != 0);
            if !self.is_cancel_requested() {
                waiters.push(Arc::downgrade(&waiter));
            }
        }
        *slot = Some(waiter);
        // The caller checks the flag after registration and after polling the
        // inner future. A cancellation before admission therefore cannot be
        // lost even when it found no registered waiter to wake.
    }
}

pin_project! {
    /// Wraps a future with Asupersync cancellation awareness.
    ///
    /// Cancellation is checked after installing a wake registration and after
    /// polling the inner future, including cancellation requested by that poll.
    /// Behavior depends on [`CancellationMode`]:
    ///
    /// - **`BestEffort`**: A ready result wins; a pending future is cancelled.
    /// - **`Strict`**: A result ready when cancellation is observed is returned
    ///   as `CancelResult::CancellationIgnored`; a pending future is cancelled.
    /// - **`TimeoutFallback`**: Grants one additional pending poll, self-waking
    ///   for the final poll. This is a poll budget, not a wall-clock timeout.
    ///
    /// The inner future is dropped in place before any terminal result is
    /// returned. This does not drain separately spawned work owned elsewhere.
    pub struct CancelAware<F> {
        #[pin]
        future: Option<F>,
        cancel_signal: CancelSignal,
        registration: Option<Arc<CancelWaiter>>,
        mode: CancellationMode,
        timeout_fallback_polls_remaining: u8,
    }
}

/// Result of a cancel-aware future execution.
#[derive(Debug)]
pub enum CancelResult<T> {
    /// The future completed normally, or won a non-strict cancellation race.
    Completed(T),

    /// The future was cancelled before completing.
    Cancelled,

    /// The future completed after cancellation was requested
    /// (only in `Strict` mode).
    CancellationIgnored(T),
}

impl<F: Future> CancelAware<F> {
    /// Create a new cancel-aware wrapper around a future.
    pub fn new(future: F, mode: CancellationMode) -> Self {
        Self::with_signal(future, mode, CancelSignal::new())
    }

    /// Create a cancel-aware wrapper with an externally owned signal.
    pub const fn with_signal(
        future: F,
        mode: CancellationMode,
        cancel_signal: CancelSignal,
    ) -> Self {
        Self {
            future: Some(future),
            cancel_signal,
            registration: None,
            mode,
            timeout_fallback_polls_remaining: DEFAULT_TIMEOUT_FALLBACK_POLLS,
        }
    }

    /// Return a cloneable signal that can request cancellation from outside this future.
    #[must_use]
    pub fn cancel_signal(&self) -> CancelSignal {
        self.cancel_signal.clone()
    }

    /// Signal that cancellation has been requested.
    ///
    /// This should be called by the adapter's poll loop when it detects
    /// `cx.is_cancel_requested()`.
    pub fn request_cancel(self: Pin<&mut Self>) {
        self.project().cancel_signal.cancel();
    }
}

impl<F: Future> Future for CancelAware<F> {
    type Output = CancelResult<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        assert!(this.future.as_ref().get_ref().is_some(), "polled after completion");
        this.cancel_signal.register(this.registration, cx.waker());
        let result = this
            .future
            .as_mut()
            .as_pin_mut()
            .expect("inner future exists until completion")
            .poll(cx);
        let cancelled = this.cancel_signal.is_cancel_requested();
        let output = match result {
            Poll::Ready(output) => {
                if cancelled && *this.mode == CancellationMode::Strict {
                    CancelResult::CancellationIgnored(output)
                } else {
                    CancelResult::Completed(output)
                }
            }
            Poll::Pending if !cancelled => return Poll::Pending,
            Poll::Pending => {
                if *this.mode == CancellationMode::TimeoutFallback
                    && *this.timeout_fallback_polls_remaining != 0
                {
                    *this.timeout_fallback_polls_remaining -= 1;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                CancelResult::Cancelled
            }
        };
        // Retire the task Waker and run the pinned future's destructor before
        // reporting completion, even if the caller retains the wrapper.
        *this.registration = None;
        this.future.set(None);
        Poll::Ready(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future;
    use std::sync::atomic::AtomicUsize;
    use std::task::Wake;

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
        let waker = Waker::from(count.clone());
        (count, waker)
    }

    #[test]
    fn cancel_aware_completes_normally() {
        let mut fut = std::pin::pin!(CancelAware::new(
            future::ready(42),
            CancellationMode::BestEffort,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            fut.as_mut().poll(&mut cx),
            Poll::Ready(CancelResult::Completed(42))
        ));
    }

    #[test]
    fn cancel_aware_mode_defaults_to_best_effort() {
        assert_eq!(CancellationMode::default(), CancellationMode::BestEffort);
    }

    #[test]
    fn external_signal_cancels_pending_future() {
        let signal = CancelSignal::new();
        let mut fut = std::pin::pin!(CancelAware::with_signal(
            future::pending::<()>(),
            CancellationMode::BestEffort,
            signal.clone(),
        ));
        let mut cx = Context::from_waker(Waker::noop());
        signal.cancel();
        assert!(matches!(
            fut.as_mut().poll(&mut cx),
            Poll::Ready(CancelResult::Cancelled)
        ));
    }

    #[test]
    fn timeout_fallback_grants_one_pending_poll_before_cancel() {
        let mut fut = std::pin::pin!(CancelAware::new(
            future::pending::<()>(),
            CancellationMode::TimeoutFallback,
        ));
        let (count, waker) = counter();
        let mut cx = Context::from_waker(&waker);
        fut.as_mut().request_cancel();
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(matches!(
            fut.as_mut().poll(&mut cx),
            Poll::Ready(CancelResult::Cancelled)
        ));
    }

    #[test]
    fn cancellation_wakes_every_parked_future_once() {
        let signal = CancelSignal::new();
        let mut first = Box::pin(CancelAware::with_signal(
            future::pending::<()>(),
            CancellationMode::BestEffort,
            signal.clone(),
        ));
        let mut second = Box::pin(CancelAware::with_signal(
            future::pending::<()>(),
            CancellationMode::Strict,
            signal.clone(),
        ));
        let (a, wa) = counter();
        let (b, wb) = counter();
        assert!(first.as_mut().poll(&mut Context::from_waker(&wa)).is_pending());
        assert!(second.as_mut().poll(&mut Context::from_waker(&wb)).is_pending());
        signal.cancel();
        signal.cancel();
        // These assertions precede repolling: success cannot be supplied by
        // a test executor that gratuitously polls a future without a wake.
        assert_eq!(a.0.load(Ordering::SeqCst), 1);
        assert_eq!(b.0.load(Ordering::SeqCst), 1);
        for future in [&mut first, &mut second] {
            assert!(matches!(
                future.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(CancelResult::Cancelled)
            ));
        }
    }

    #[test]
    fn repoll_replaces_the_registered_waker() {
        let signal = CancelSignal::new();
        let mut fut = Box::pin(CancelAware::with_signal(
            future::pending::<()>(),
            CancellationMode::BestEffort,
            signal.clone(),
        ));
        let (old, old_waker) = counter();
        let (new, new_waker) = counter();
        assert!(fut.as_mut().poll(&mut Context::from_waker(&old_waker)).is_pending());
        assert!(fut.as_mut().poll(&mut Context::from_waker(&new_waker)).is_pending());
        signal.cancel();
        assert_eq!(old.0.load(Ordering::SeqCst), 0);
        assert_eq!(new.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dropped_future_does_not_retain_or_wake_its_task() {
        let signal = CancelSignal::new();
        let (count, waker) = counter();
        let mut fut = Box::pin(CancelAware::with_signal(
            future::pending::<()>(),
            CancellationMode::BestEffort,
            signal.clone(),
        ));
        assert!(fut.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        drop(fut);
        assert_eq!(Arc::strong_count(&count), 2);
        signal.cancel();
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn cancellation_requested_inside_poll_is_observed() {
        for mode in [CancellationMode::BestEffort, CancellationMode::Strict] {
            let signal = CancelSignal::new();
            let inner_signal = signal.clone();
            let inner = future::poll_fn(move |_| {
                inner_signal.cancel();
                Poll::<()>::Pending
            });
            let mut fut = std::pin::pin!(CancelAware::with_signal(inner, mode, signal));
            assert!(matches!(
                fut.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(CancelResult::Cancelled)
            ));
        }
    }

    #[test]
    fn strict_mode_detects_cancellation_during_ready_poll() {
        let signal = CancelSignal::new();
        let inner_signal = signal.clone();
        let inner = future::poll_fn(move |_| {
            inner_signal.cancel();
            Poll::Ready(42)
        });
        let mut fut = std::pin::pin!(CancelAware::with_signal(
            inner,
            CancellationMode::Strict,
            signal,
        ));
        assert!(matches!(
            fut.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(CancelResult::CancellationIgnored(42))
        ));
    }

    #[test]
    fn cancelled_inner_is_dropped_before_returning_ready() {
        struct DropProbe(Arc<AtomicBool>);
        impl Future for DropProbe {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                Poll::Pending
            }
        }
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let signal = CancelSignal::new();
        let mut fut = Box::pin(CancelAware::with_signal(
            DropProbe(dropped.clone()),
            CancellationMode::Strict,
            signal.clone(),
        ));
        signal.cancel();
        assert!(matches!(
            fut.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(CancelResult::Cancelled)
        ));
        assert!(dropped.load(Ordering::SeqCst));
        assert!(fut.as_ref().get_ref().registration.is_none());
    }

    #[test]
    fn waker_callbacks_can_reenter_the_signal() {
        struct Reenter(CancelSignal);
        impl Wake for Reenter {
            fn wake(self: Arc<Self>) {
                assert!(self.0.state.waiters.try_lock().is_ok());
                self.0.cancel();
            }
        }
        let signal = CancelSignal::new();
        let waker = Waker::from(Arc::new(Reenter(signal.clone())));
        let mut fut = Box::pin(CancelAware::with_signal(
            future::pending::<()>(),
            CancellationMode::BestEffort,
            signal.clone(),
        ));
        assert!(fut.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        signal.cancel();
    }

    #[test]
    fn panicking_waker_does_not_skip_remaining_waiters() {
        struct PanicWake;
        impl Wake for PanicWake {
            fn wake(self: Arc<Self>) {
                panic!("intentional cancellation wake panic");
            }
        }
        let signal = CancelSignal::new();
        let bad_waker = Waker::from(Arc::new(PanicWake));
        let (count, good_waker) = counter();
        let mut bad = Box::pin(CancelAware::with_signal(
            future::pending::<()>(),
            CancellationMode::Strict,
            signal.clone(),
        ));
        let mut good = Box::pin(CancelAware::with_signal(
            future::pending::<()>(),
            CancellationMode::Strict,
            signal.clone(),
        ));
        assert!(bad.as_mut().poll(&mut Context::from_waker(&bad_waker)).is_pending());
        assert!(good.as_mut().poll(&mut Context::from_waker(&good_waker)).is_pending());
        assert!(std::panic::catch_unwind(|| signal.cancel()).is_err());
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(signal.is_cancel_requested());
    }
}
