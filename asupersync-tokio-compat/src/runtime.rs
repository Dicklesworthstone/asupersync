//! Asupersync context bridge for compatibility futures.
//!
//! Provides [`AsupersyncRuntime`], which keeps an explicit Asupersync [`Cx`]
//! installed while a closure or future is polled.
//!
//! This module does **not** start or enter a Tokio runtime and does not make
//! `tokio::runtime::Handle::current()` available. A dependency that requires
//! Tokio runtime context must remain behind an independently owned Tokio
//! runtime boundary.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use asupersync::Cx;
use asupersync::cx::Cancelled;
use asupersync::types::RegionId;
use pin_project_lite::pin_project;

use crate::CancellationMode;
use crate::cancel::{CancelAware, CancelResult};

/// A scoped carrier for an Asupersync [`Cx`].
///
/// This type is not a Tokio runtime handle. It installs only Asupersync's
/// current-`Cx` binding; it neither implements Tokio's runtime handle
/// interface nor makes `tokio::runtime::Handle::current()` succeed.
#[derive(Debug, Clone)]
pub struct AsupersyncRuntime {
    cx: Cx,
    region_id: RegionId,
}

impl AsupersyncRuntime {
    /// Create a new `AsupersyncRuntime` bound to the given context.
    #[must_use]
    pub fn new(cx: &Cx) -> Self {
        Self {
            cx: cx.clone(),
            region_id: cx.region_id(),
        }
    }

    /// Access the underlying Asupersync context captured by this runtime.
    #[must_use]
    pub const fn cx(&self) -> &Cx {
        &self.cx
    }

    /// Return the region that owns tasks spawned through this runtime.
    #[must_use]
    pub const fn region_id(&self) -> RegionId {
        self.region_id
    }

    /// Run a synchronous closure with this bridge's `Cx` installed as current.
    ///
    /// This changes only [`Cx::current`]. It does not enter a Tokio runtime.
    pub fn enter<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _cx_guard = asupersync::Cx::set_current(Some(self.cx.clone()));
        f()
    }
}

pin_project! {
    // Own both the cancellation subscription and the foreign future. A pinned
    // destructor is necessary: abandoning the outer async function can happen
    // without another poll, outside the bridge's current-Cx binding.
    struct ContextBridge<'a, F> {
        runtime: AsupersyncRuntime,
        cancellation: Option<Cancelled<'a>>,
        #[pin]
        future: Option<CancelAware<F>>,
    }

    impl<F> PinnedDrop for ContextBridge<'_, F> {
        fn drop(this: Pin<&mut Self>) {
            let this = this.project();
            let runtime = this.runtime;
            let cancellation = this.cancellation;
            let mut future = this.future;
            runtime.enter(|| {
                drop(cancellation.take());
                future.set(None);
            });
        }
    }
}

impl<F: Future> Future for ContextBridge<'_, F> {
    type Output = Option<F::Output>;

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let runtime = this.runtime;
        let cancellation = this.cancellation;
        let mut future = this.future;
        runtime.enter(|| {
            // Subscribe before polling the foreign future. A pending future
            // need not have any independent readiness event to observe a Cx
            // cancellation request, and registration cannot evict its peers.
            let cancelled_before_poll = Pin::new(
                cancellation
                    .as_mut()
                    .expect("context bridge polled after completion"),
            )
            .poll(task)
            .is_ready();
            let result = {
                let mut inner = future
                    .as_mut()
                    .as_pin_mut()
                    .expect("context bridge has an active inner future");
                if cancelled_before_poll {
                    inner.as_mut().request_cancel();
                }
                inner.poll(task)
            };
            match result {
                Poll::Ready(result) => {
                    // Retire both subscriptions before returning Ready, even
                    // when the caller retains the completed outer future.
                    future.set(None);
                    drop(cancellation.take());
                    match result {
                        CancelResult::Completed(value) => {
                            if cancelled_before_poll || runtime.cx().is_cancel_requested() {
                                drop(value);
                                Poll::Ready(None)
                            } else {
                                Poll::Ready(Some(value))
                            }
                        }
                        CancelResult::CancellationIgnored(value) => {
                            drop(value);
                            Poll::Ready(None)
                        }
                        CancelResult::Cancelled => Poll::Ready(None),
                    }
                }
                Poll::Pending => {
                    // Preserve the existing best-effort final-poll behavior.
                    // If cancellation arrived inside the foreign poll, publish
                    // it to CancelAware now; its registered waker ensures that
                    // the final poll is scheduled even for a silent future.
                    if runtime.cx().is_cancel_requested() {
                        future
                            .as_mut()
                            .as_pin_mut()
                            .expect("pending bridge has an active inner future")
                            .request_cancel();
                    }
                    Poll::Pending
                }
            }
        })
    }
}

/// Run an async future factory with `Cx` installed on every poll and on drop.
///
/// Returns `None` once cancellation is observed before the future completes,
/// even if the wrapped future reports `Ready` on the first poll after that
/// cancellation becomes visible to the adapter. A pending bridge subscribes
/// to context cancellation; it does not depend on the foreign future waking
/// itself. The inner future and cancellation subscriptions are retired before
/// terminal return, with the supplied `Cx` installed during inner destruction.
/// Abandoning a pending bridge also drops its inner future under that `Cx`.
/// This does not drain work independently spawned by the foreign dependency.
///
/// This function does not install Tokio runtime context. The wrapped future
/// must be independently runnable on the caller's executor; futures that call
/// `tokio::runtime::Handle::current()` still require a separately owned and
/// entered Tokio runtime.
pub async fn with_tokio_context<F, Fut, T>(cx: &Cx, f: F) -> Option<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    if cx.is_cancel_requested() {
        return None;
    }

    let runtime = AsupersyncRuntime::new(cx);
    let future = runtime.enter(f);
    ContextBridge {
        runtime,
        cancellation: Some(cx.cancelled()),
        future: Some(CancelAware::new(future, CancellationMode::BestEffort)),
    }
    .await
}

/// Run a synchronous closure while preserving any current `Cx` binding.
pub fn with_tokio_context_sync<F, T>(f: F) -> T
where
    F: FnOnce() -> T,
{
    if let Some(cx) = Cx::current() {
        AsupersyncRuntime::new(&cx).enter(f)
    } else {
        f()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::types::CancelKind;
    use futures_lite::future::block_on;
    use std::marker::PhantomPinned;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

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

    fn current_request_id() -> Option<String> {
        Cx::current().and_then(|cx| cx.request_id())
    }

    struct DropContextProbe {
        dropped: Arc<AtomicBool>,
        correct_context: Arc<AtomicBool>,
        panic_on_drop: bool,
        _pin: PhantomPinned,
    }

    impl Future for DropContextProbe {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            assert_eq!(current_request_id().as_deref(), Some("bridge"));
            Poll::Pending
        }
    }

    impl Drop for DropContextProbe {
        fn drop(&mut self) {
            self.correct_context.store(
                current_request_id().as_deref() == Some("bridge"),
                Ordering::SeqCst,
            );
            self.dropped.store(true, Ordering::SeqCst);
            assert!(!self.panic_on_drop, "intentional foreign destructor panic");
        }
    }

    #[test]
    fn test_asupersync_runtime_creation() {
        let cx = Cx::for_testing();
        let rt = AsupersyncRuntime::new(&cx);
        assert_eq!(rt.region_id(), cx.region_id());
        assert_eq!(rt.cx().region_id(), cx.region_id());
    }

    #[test]
    fn test_enter_installs_current_cx() {
        let cx = Cx::for_testing();
        let rt = AsupersyncRuntime::new(&cx);
        let region = rt.enter(|| Cx::current().expect("current cx").region_id());
        assert_eq!(region, cx.region_id());
    }

    #[test]
    fn test_with_tokio_context_returns_value() {
        let cx = Cx::for_testing();
        let region = block_on(with_tokio_context(&cx, || async {
            Cx::current().expect("current cx").region_id()
        }));
        assert_eq!(region, Some(cx.region_id()));
    }

    #[test]
    fn test_with_tokio_context_returns_none_when_cancelled() {
        let cx = Cx::for_testing();
        cx.cancel_fast(CancelKind::User);
        let result = block_on(with_tokio_context(&cx, || async { 42_u8 }));
        assert_eq!(result, None);
    }

    #[test]
    fn test_with_tokio_context_returns_none_when_cancel_observed_before_ready() {
        struct CancelThenReady {
            cx: Cx,
            polled_once: bool,
        }

        impl Future for CancelThenReady {
            type Output = u8;

            fn poll(mut self: Pin<&mut Self>, poll_cx: &mut Context<'_>) -> Poll<Self::Output> {
                if self.polled_once {
                    Poll::Ready(42)
                } else {
                    self.polled_once = true;
                    self.cx.cancel_fast(CancelKind::User);
                    poll_cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }

        let cx = Cx::for_testing();
        let future_cx = cx.clone();
        let result = block_on(with_tokio_context(&cx, move || CancelThenReady {
            cx: future_cx,
            polled_once: false,
        }));
        assert_eq!(result, None);
    }

    #[test]
    fn test_with_tokio_context_returns_none_when_cancel_requested_during_ready_poll() {
        struct CancelAndReady {
            cx: Cx,
        }

        impl Future for CancelAndReady {
            type Output = u8;

            fn poll(self: Pin<&mut Self>, _poll_cx: &mut Context<'_>) -> Poll<Self::Output> {
                self.cx.cancel_fast(CancelKind::User);
                Poll::Ready(42)
            }
        }

        let cx = Cx::for_testing();
        let future_cx = cx.clone();
        let result = block_on(with_tokio_context(&cx, move || CancelAndReady {
            cx: future_cx,
        }));
        assert_eq!(result, None);
    }

    #[test]
    fn test_with_tokio_context_sync_preserves_current_cx() {
        let cx = Cx::for_testing();
        let _cx_guard = Cx::set_current(Some(cx.clone()));
        let region = with_tokio_context_sync(|| Cx::current().expect("current cx").region_id());
        assert_eq!(region, cx.region_id());
    }

    #[test]
    fn context_cancellation_wakes_and_releases_a_real_tokio_oneshot() {
        let cx = Cx::for_testing();
        let (sender, receiver) = tokio::sync::oneshot::channel::<u8>();
        let (count, waker) = counter();
        let mut task = Context::from_waker(&waker);
        let mut bridge = Box::pin(with_tokio_context(&cx, || receiver));
        assert!(bridge.as_mut().poll(&mut task).is_pending());
        cx.cancel_fast(CancelKind::User);
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            bridge.as_mut().poll(&mut task),
            Poll::Ready(None)
        ));
        // The wrapper is still alive. Receiver ownership must already have
        // been released, rather than waiting for drop(bridge).
        assert!(sender.send(42).is_err());
    }

    #[test]
    fn dropping_pending_bridge_releases_real_tokio_receiver() {
        let cx = Cx::for_testing();
        let (sender, receiver) = tokio::sync::oneshot::channel::<u8>();
        let mut bridge = Box::pin(with_tokio_context(&cx, || receiver));
        assert!(
            bridge
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(bridge);
        assert!(sender.send(42).is_err());
    }

    #[test]
    fn cancellation_inside_silent_pending_poll_schedules_a_final_poll() {
        let cx = Cx::for_testing();
        let (count, waker) = counter();
        let inner_cx = cx.clone();
        let mut bridge = Box::pin(with_tokio_context(&cx, || {
            std::future::poll_fn(move |_| {
                inner_cx.cancel_fast(CancelKind::User);
                Poll::<()>::Pending
            })
        }));
        let mut task = Context::from_waker(&waker);
        assert!(bridge.as_mut().poll(&mut task).is_pending());
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            bridge.as_mut().poll(&mut task),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn pre_cancelled_context_never_invokes_the_factory() {
        let cx = Cx::for_testing();
        let invoked = AtomicBool::new(false);
        cx.cancel_fast(CancelKind::User);
        let result = block_on(with_tokio_context(&cx, || {
            invoked.store(true, Ordering::SeqCst);
            std::future::ready(42)
        }));
        assert_eq!(result, None);
        assert!(!invoked.load(Ordering::SeqCst));
    }

    #[test]
    fn abandoned_non_unpin_future_drops_under_its_context_and_restores_caller() {
        let outer = Cx::for_testing();
        outer.set_request_id("outer");
        let _outer_guard = Cx::set_current(Some(outer));
        let cx = Cx::for_testing();
        cx.set_request_id("bridge");
        let dropped = Arc::new(AtomicBool::new(false));
        let correct_context = Arc::new(AtomicBool::new(false));
        let mut bridge = Box::pin(with_tokio_context(&cx, || {
            assert_eq!(current_request_id().as_deref(), Some("bridge"));
            DropContextProbe {
                dropped: dropped.clone(),
                correct_context: correct_context.clone(),
                panic_on_drop: false,
                _pin: PhantomPinned,
            }
        }));
        assert!(
            bridge
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(current_request_id().as_deref(), Some("outer"));
        drop(bridge);
        assert!(dropped.load(Ordering::SeqCst));
        assert!(correct_context.load(Ordering::SeqCst));
        assert_eq!(current_request_id().as_deref(), Some("outer"));
    }

    #[test]
    fn cancellation_runs_non_unpin_cleanup_before_returning_none() {
        let cx = Cx::for_testing();
        cx.set_request_id("bridge");
        let dropped = Arc::new(AtomicBool::new(false));
        let correct_context = Arc::new(AtomicBool::new(false));
        let mut bridge = Box::pin(with_tokio_context(&cx, || DropContextProbe {
            dropped: dropped.clone(),
            correct_context: correct_context.clone(),
            panic_on_drop: false,
            _pin: PhantomPinned,
        }));
        let mut task = Context::from_waker(Waker::noop());
        assert!(bridge.as_mut().poll(&mut task).is_pending());
        cx.cancel_fast(CancelKind::User);
        assert!(matches!(
            bridge.as_mut().poll(&mut task),
            Poll::Ready(None)
        ));
        assert!(dropped.load(Ordering::SeqCst));
        assert!(correct_context.load(Ordering::SeqCst));
    }

    #[test]
    fn panic_in_foreign_destructor_still_restores_the_callers_context() {
        let outer = Cx::for_testing();
        outer.set_request_id("outer");
        let _outer_guard = Cx::set_current(Some(outer));
        let cx = Cx::for_testing();
        cx.set_request_id("bridge");
        let dropped = Arc::new(AtomicBool::new(false));
        let correct_context = Arc::new(AtomicBool::new(false));
        let mut bridge = Box::pin(with_tokio_context(&cx, || DropContextProbe {
            dropped: dropped.clone(),
            correct_context: correct_context.clone(),
            panic_on_drop: true,
            _pin: PhantomPinned,
        }));
        assert!(
            bridge
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(bridge))).is_err()
        );
        assert!(dropped.load(Ordering::SeqCst));
        assert!(correct_context.load(Ordering::SeqCst));
        assert_eq!(current_request_id().as_deref(), Some("outer"));
    }

    #[test]
    fn completed_bridge_releases_cancellation_wakers_without_outer_drop() {
        let cx = Cx::for_testing();
        let (count, waker) = counter();
        let mut task = Context::from_waker(&waker);
        let mut bridge = Box::pin(with_tokio_context(&cx, std::future::pending::<()>));
        assert!(bridge.as_mut().poll(&mut task).is_pending());
        cx.cancel_fast(CancelKind::User);
        assert!(matches!(
            bridge.as_mut().poll(&mut task),
            Poll::Ready(None)
        ));
        assert_eq!(Arc::strong_count(&count), 2);
        let wakes = count.0.load(Ordering::SeqCst);
        cx.cancel_fast(CancelKind::User);
        assert_eq!(count.0.load(Ordering::SeqCst), wakes);
    }
}
