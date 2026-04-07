//! Load shedding middleware layer.
//!
//! The [`LoadShedLayer`] wraps a service and sheds load when the inner service
//! signals backpressure. If the inner service returns `Poll::Pending` from
//! `poll_ready`, the load shedder marks itself as overloaded and immediately
//! rejects subsequent requests until the inner service becomes ready again.

use super::{Layer, Service};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::task::{Wake, Waker};

fn tracked_probe_waker(delegate: &Waker) -> (Waker, Arc<AtomicBool>) {
    struct TrackWaker {
        woke: Arc<AtomicBool>,
        delegate: Waker,
    }

    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.woke.store(true, Ordering::SeqCst);
            self.delegate.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.woke.store(true, Ordering::SeqCst);
            self.delegate.wake_by_ref();
        }
    }

    let woke = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(TrackWaker {
        woke: Arc::clone(&woke),
        delegate: delegate.clone(),
    }));
    (waker, woke)
}

fn poll_ready_preserving_self_wake<S, Request>(
    service: &mut S,
    cx: &mut Context<'_>,
) -> Poll<Result<(), S::Error>>
where
    S: Service<Request>,
{
    let (probe_waker, woke_during_poll) = tracked_probe_waker(cx.waker());
    let mut probe_cx = Context::from_waker(&probe_waker);
    let mut readiness = service.poll_ready(&mut probe_cx);
    if matches!(readiness, Poll::Pending) && woke_during_poll.load(Ordering::SeqCst) {
        readiness = service.poll_ready(cx);
    }
    readiness
}

/// A layer that sheds load when the inner service is not ready.
///
/// This is useful for protecting services from being overwhelmed. When the
/// inner service signals backpressure via `poll_ready`, the load shedder
/// will immediately fail new requests instead of queueing them.
///
/// # Example
///
/// ```ignore
/// use asupersync::service::{ServiceBuilder, ServiceExt};
/// use asupersync::service::load_shed::LoadShedLayer;
///
/// let svc = ServiceBuilder::new()
///     .layer(LoadShedLayer::new())
///     .service(my_service);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct LoadShedLayer;

impl LoadShedLayer {
    /// Creates a new load shedding layer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for LoadShedLayer {
    type Service = LoadShed<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LoadShed::new(inner)
    }
}

/// A service that sheds load when the inner service is not ready.
///
/// The load shedder checks the inner service's readiness in `poll_ready`.
/// If the inner service returns `Poll::Pending`, the load shedder marks
/// itself as overloaded and will reject the next `call` with an [`Overloaded`]
/// error instead of processing it.
///
/// Each successful `poll_ready` authorizes exactly one subsequent `call`.
/// Calling without first observing readiness fails closed with
/// [`LoadShedError::NotReady`].
#[derive(Debug)]
pub struct LoadShed<S> {
    inner: S,
    overloaded: bool,
    ready_observed: bool,
}

impl<S: Clone> Clone for LoadShed<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            overloaded: self.overloaded,
            // Readiness is handle-local and must not be duplicated across clones.
            ready_observed: false,
        }
    }
}

impl<S> LoadShed<S> {
    /// Creates a new load shedding service.
    #[must_use]
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            overloaded: false,
            ready_observed: false,
        }
    }

    /// Returns whether the service is currently overloaded.
    #[must_use]
    pub const fn is_overloaded(&self) -> bool {
        self.overloaded
    }

    /// Returns a reference to the inner service.
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// Returns a mutable reference to the inner service.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consumes the load shedder, returning the inner service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// Error returned when a request is shed due to overload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overloaded(());

impl Overloaded {
    /// Creates a new overloaded error.
    #[must_use]
    pub const fn new() -> Self {
        Self(())
    }
}

impl Default for Overloaded {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for Overloaded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "service overloaded")
    }
}

impl std::error::Error for Overloaded {}

/// Error returned by the load shedding service.
#[derive(Debug)]
pub enum LoadShedError<E> {
    /// The caller attempted `call()` without a preceding successful `poll_ready()`.
    NotReady,
    /// The load-shed future was polled after it had already completed.
    PolledAfterCompletion,
    /// The service is overloaded and the request was shed.
    Overloaded(Overloaded),
    /// The inner service returned an error.
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for LoadShedError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReady => write!(f, "poll_ready required before call"),
            Self::PolledAfterCompletion => write!(f, "load shed future polled after completion"),
            Self::Overloaded(e) => write!(f, "{e}"),
            Self::Inner(e) => write!(f, "inner service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for LoadShedError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotReady | Self::PolledAfterCompletion => None,
            Self::Overloaded(e) => Some(e),
            Self::Inner(e) => Some(e),
        }
    }
}

impl<S, Request> Service<Request> for LoadShed<S>
where
    S: Service<Request>,
    S::Future: Unpin,
{
    type Response = S::Response;
    type Error = LoadShedError<S::Error>;
    type Future = LoadShedFuture<S::Future>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match poll_ready_preserving_self_wake::<S, Request>(&mut self.inner, cx) {
            Poll::Ready(Ok(())) => {
                self.overloaded = false;
                self.ready_observed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.overloaded = false;
                self.ready_observed = false;
                Poll::Ready(Err(LoadShedError::Inner(e)))
            }
            Poll::Pending => {
                // Inner service is not ready; mark as overloaded but return Ready
                // so the caller can call us immediately (and we'll shed)
                self.overloaded = true;
                self.ready_observed = true;
                Poll::Ready(Ok(()))
            }
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        if !std::mem::replace(&mut self.ready_observed, false) {
            return LoadShedFuture::not_ready();
        }

        if self.overloaded {
            // Stay overloaded until `poll_ready` observes the inner service as ready.
            LoadShedFuture::overloaded()
        } else {
            LoadShedFuture::inner(self.inner.call(req))
        }
    }
}

/// Future returned by the [`LoadShed`] service.
pub struct LoadShedFuture<F> {
    state: LoadShedState<F>,
}

enum LoadShedState<F> {
    /// Caller skipped `poll_ready` or reused a consumed readiness window.
    NotReady,
    /// Request was shed due to overload.
    Overloaded,
    /// Request is being processed by the inner service.
    Inner(F),
    /// Future has completed.
    Done,
}

impl<F> LoadShedFuture<F> {
    /// Creates a future that immediately returns a readiness misuse error.
    #[must_use]
    pub fn not_ready() -> Self {
        Self {
            state: LoadShedState::NotReady,
        }
    }

    /// Creates a future that immediately returns an overloaded error.
    #[must_use]
    pub fn overloaded() -> Self {
        Self {
            state: LoadShedState::Overloaded,
        }
    }

    /// Creates a future that wraps the inner service's future.
    #[must_use]
    pub fn inner(future: F) -> Self {
        Self {
            state: LoadShedState::Inner(future),
        }
    }
}

impl<F, T, E> Future for LoadShedFuture<F>
where
    F: Future<Output = Result<T, E>> + Unpin,
{
    type Output = Result<T, LoadShedError<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        match std::mem::replace(&mut this.state, LoadShedState::Done) {
            LoadShedState::NotReady => Poll::Ready(Err(LoadShedError::NotReady)),
            LoadShedState::Overloaded => {
                Poll::Ready(Err(LoadShedError::Overloaded(Overloaded::new())))
            }
            LoadShedState::Inner(mut future) => match Pin::new(&mut future).poll(cx) {
                Poll::Ready(Ok(response)) => Poll::Ready(Ok(response)),
                Poll::Ready(Err(e)) => Poll::Ready(Err(LoadShedError::Inner(e))),
                Poll::Pending => {
                    this.state = LoadShedState::Inner(future);
                    Poll::Pending
                }
            },
            LoadShedState::Done => Poll::Ready(Err(LoadShedError::PolledAfterCompletion)),
        }
    }
}

impl<F: std::fmt::Debug> std::fmt::Debug for LoadShedFuture<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadShedFuture").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::ready;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Arc::new(NoopWaker).into()
    }

    // A service that is always ready
    struct ReadyService;

    impl Service<i32> for ReadyService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: i32) -> Self::Future {
            ready(Ok(req * 2))
        }
    }

    // A service that is never ready (backpressure)
    struct NeverReadyService;

    impl Service<i32> for NeverReadyService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Pending<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn call(&mut self, _req: i32) -> Self::Future {
            std::future::pending()
        }
    }

    struct ToggleReadyService {
        ready: bool,
    }

    impl Service<i32> for ToggleReadyService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.ready {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn call(&mut self, req: i32) -> Self::Future {
            ready(Ok(req))
        }
    }

    struct SelfWakeReadyService {
        armed: bool,
    }

    impl Service<i32> for SelfWakeReadyService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.armed {
                Poll::Ready(Ok(()))
            } else {
                self.armed = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        fn call(&mut self, req: i32) -> Self::Future {
            ready(Ok(req + 1))
        }
    }

    #[derive(Clone)]
    struct CountingReadyService {
        calls: Arc<AtomicUsize>,
    }

    impl CountingReadyService {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self { calls }
        }
    }

    impl Service<i32> for CountingReadyService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: i32) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ready(Ok(req))
        }
    }

    struct PanicOnPollFuture;

    impl std::future::Future for PanicOnPollFuture {
        type Output = Result<i32, std::convert::Infallible>;

        fn poll(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<<Self as std::future::Future>::Output> {
            panic!("panic in load shed future poll");
        }
    }

    struct PanicOnPollService;

    impl Service<i32> for PanicOnPollService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = PanicOnPollFuture;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: i32) -> Self::Future {
            PanicOnPollFuture
        }
    }

    #[test]
    fn load_shed_layer_creates_service() {
        init_test("load_shed_layer_creates_service");
        let layer = LoadShedLayer::new();
        let _svc: LoadShed<ReadyService> = layer.layer(ReadyService);
        crate::test_complete!("load_shed_layer_creates_service");
    }

    #[test]
    fn load_shed_passes_through_when_ready() {
        init_test("load_shed_passes_through_when_ready");
        let mut svc = LoadShed::new(ReadyService);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // poll_ready should succeed
        let ready = svc.poll_ready(&mut cx);
        let ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);
        let overloaded = svc.is_overloaded();
        crate::assert_with_log!(!overloaded, "not overloaded", false, overloaded);

        // call should succeed
        let mut future = svc.call(21);
        let result = Pin::new(&mut future).poll(&mut cx);
        let ok = matches!(result, Poll::Ready(Ok(42)));
        crate::assert_with_log!(ok, "call ok", true, ok);
        crate::test_complete!("load_shed_passes_through_when_ready");
    }

    #[test]
    fn load_shed_call_without_poll_ready_returns_not_ready() {
        init_test("load_shed_call_without_poll_ready_returns_not_ready");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut svc = LoadShed::new(CountingReadyService::new(Arc::clone(&calls)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut future = svc.call(21);
        let result = Pin::new(&mut future).poll(&mut cx);
        let not_ready = matches!(result, Poll::Ready(Err(LoadShedError::NotReady)));
        crate::assert_with_log!(
            not_ready,
            "call without poll_ready fails closed",
            true,
            not_ready
        );
        crate::assert_with_log!(
            calls.load(Ordering::SeqCst) == 0,
            "inner service not invoked on readiness misuse",
            0,
            calls.load(Ordering::SeqCst)
        );
        crate::test_complete!("load_shed_call_without_poll_ready_returns_not_ready");
    }

    #[test]
    fn load_shed_sheds_when_not_ready() {
        init_test("load_shed_sheds_when_not_ready");
        let mut svc = LoadShed::new(NeverReadyService);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // poll_ready should return Ready (even though inner is pending)
        let ready = svc.poll_ready(&mut cx);
        let ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);
        let overloaded = svc.is_overloaded();
        crate::assert_with_log!(overloaded, "overloaded", true, overloaded);

        // call should return overloaded error
        let mut future = svc.call(42);
        let result = Pin::new(&mut future).poll(&mut cx);
        let overloaded = matches!(result, Poll::Ready(Err(LoadShedError::Overloaded(_))));
        crate::assert_with_log!(overloaded, "overloaded error", true, overloaded);
        crate::test_complete!("load_shed_sheds_when_not_ready");
    }

    #[test]
    fn load_shed_recovers_after_shed() {
        init_test("load_shed_recovers_after_shed");
        let mut svc = LoadShed::new(NeverReadyService);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Trigger overload
        let _ = svc.poll_ready(&mut cx);
        let overloaded = svc.is_overloaded();
        crate::assert_with_log!(overloaded, "overloaded", true, overloaded);

        // Shed a request
        let mut future = svc.call(42);
        let _ = Pin::new(&mut future).poll(&mut cx);

        // Overloaded flag should remain set until poll_ready observes readiness.
        let overloaded = svc.is_overloaded();
        crate::assert_with_log!(overloaded, "overload persists", true, overloaded);
        crate::test_complete!("load_shed_recovers_after_shed");
    }

    #[test]
    fn load_shed_keeps_shedding_until_ready_again() {
        init_test("load_shed_keeps_shedding_until_ready_again");
        let mut svc = LoadShed::new(ToggleReadyService { ready: false });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready(&mut cx);
        let ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok while overloaded", true, ok);

        let mut first = svc.call(1);
        let first_result = Pin::new(&mut first).poll(&mut cx);
        let first_overloaded =
            matches!(first_result, Poll::Ready(Err(LoadShedError::Overloaded(_))));
        crate::assert_with_log!(
            first_overloaded,
            "first call overloaded",
            true,
            first_overloaded
        );

        let ready = svc.poll_ready(&mut cx);
        let second_ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(
            second_ready_ok,
            "repoll while still overloaded re-arms one shed",
            true,
            second_ready_ok
        );

        let mut second = svc.call(2);
        let second_result = Pin::new(&mut second).poll(&mut cx);
        let second_overloaded = matches!(
            second_result,
            Poll::Ready(Err(LoadShedError::Overloaded(_)))
        );
        crate::assert_with_log!(
            second_overloaded,
            "second call still overloaded",
            true,
            second_overloaded
        );

        svc.inner_mut().ready = true;
        let ready = svc.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "ready once inner recovers", true, ready_ok);

        let mut success = svc.call(99);
        let success_result = Pin::new(&mut success).poll(&mut cx);
        let success_ok = matches!(success_result, Poll::Ready(Ok(99)));
        crate::assert_with_log!(success_ok, "call succeeds after recovery", true, success_ok);
        crate::test_complete!("load_shed_keeps_shedding_until_ready_again");
    }

    #[test]
    fn load_shed_preserves_same_turn_self_wake_readiness() {
        init_test("load_shed_preserves_same_turn_self_wake_readiness");
        let mut svc = LoadShed::new(SelfWakeReadyService { armed: false });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "ready after self-wake repoll", true, ready_ok);
        let overloaded = svc.is_overloaded();
        crate::assert_with_log!(
            !overloaded,
            "self-wake readiness does not leave overload armed",
            false,
            overloaded
        );

        let mut future = svc.call(41);
        let result = Pin::new(&mut future).poll(&mut cx);
        let success = matches!(result, Poll::Ready(Ok(42)));
        crate::assert_with_log!(
            success,
            "immediate follow-up call succeeds after self-wake",
            true,
            success
        );
        crate::test_complete!("load_shed_preserves_same_turn_self_wake_readiness");
    }

    #[test]
    fn load_shed_ready_window_is_consumed_by_call() {
        init_test("load_shed_ready_window_is_consumed_by_call");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut svc = LoadShed::new(CountingReadyService::new(Arc::clone(&calls)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "poll_ready authorizes one call", true, ready_ok);

        let mut first = svc.call(7);
        let first_result = Pin::new(&mut first).poll(&mut cx);
        let first_ok = matches!(first_result, Poll::Ready(Ok(7)));
        crate::assert_with_log!(first_ok, "first call succeeds", true, first_ok);

        let mut second = svc.call(8);
        let second_result = Pin::new(&mut second).poll(&mut cx);
        let second_not_ready = matches!(second_result, Poll::Ready(Err(LoadShedError::NotReady)));
        crate::assert_with_log!(
            second_not_ready,
            "second call without repoll fails closed",
            true,
            second_not_ready
        );
        crate::assert_with_log!(
            calls.load(Ordering::SeqCst) == 1,
            "only the authorized call reaches the inner service",
            1,
            calls.load(Ordering::SeqCst)
        );
        crate::test_complete!("load_shed_ready_window_is_consumed_by_call");
    }

    #[test]
    fn load_shed_clone_does_not_inherit_ready_window() {
        init_test("load_shed_clone_does_not_inherit_ready_window");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut svc = LoadShed::new(CountingReadyService::new(Arc::clone(&calls)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "original service ready", true, ready_ok);

        let mut cloned = svc.clone();
        let mut future = cloned.call(5);
        let result = Pin::new(&mut future).poll(&mut cx);
        let not_ready = matches!(result, Poll::Ready(Err(LoadShedError::NotReady)));
        crate::assert_with_log!(
            not_ready,
            "clone requires its own readiness observation",
            true,
            not_ready
        );
        crate::assert_with_log!(
            calls.load(Ordering::SeqCst) == 0,
            "clone misuse does not invoke inner service",
            0,
            calls.load(Ordering::SeqCst)
        );
        crate::test_complete!("load_shed_clone_does_not_inherit_ready_window");
    }

    #[test]
    fn overloaded_error_display() {
        init_test("overloaded_error_display");
        let err = Overloaded::new();
        let display = format!("{err}");
        let has_overloaded = display.contains("overloaded");
        crate::assert_with_log!(has_overloaded, "contains overloaded", true, has_overloaded);
        crate::test_complete!("overloaded_error_display");
    }

    #[test]
    fn load_shed_error_display() {
        init_test("load_shed_error_display");
        let err: LoadShedError<&str> = LoadShedError::NotReady;
        let display = format!("{err}");
        let has_not_ready = display.contains("poll_ready required");
        crate::assert_with_log!(has_not_ready, "not ready", true, has_not_ready);

        let err: LoadShedError<&str> = LoadShedError::PolledAfterCompletion;
        let display = format!("{err}");
        let has_polled_after_completion = display.contains("polled after completion");
        crate::assert_with_log!(
            has_polled_after_completion,
            "polled-after-completion",
            true,
            has_polled_after_completion
        );

        let err: LoadShedError<&str> = LoadShedError::Overloaded(Overloaded::new());
        let display = format!("{err}");
        let has_overloaded = display.contains("overloaded");
        crate::assert_with_log!(has_overloaded, "overloaded", true, has_overloaded);

        let err: LoadShedError<&str> = LoadShedError::Inner("inner error");
        let display = format!("{err}");
        let has_inner = display.contains("inner service error");
        crate::assert_with_log!(has_inner, "inner error", true, has_inner);
        crate::test_complete!("load_shed_error_display");
    }

    // =========================================================================
    // Wave 28: Data-type trait coverage
    // =========================================================================

    #[test]
    fn load_shed_layer_debug_clone_copy_default() {
        let layer = LoadShedLayer::new();
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("LoadShedLayer"));

        let cloned = layer;
        let _ = format!("{cloned:?}");

        let copied = layer; // Copy
        let _ = format!("{copied:?}");

        let default = LoadShedLayer;
        let _ = format!("{default:?}");
    }

    #[test]
    fn load_shed_debug() {
        let svc = LoadShed::new(42_i32);
        let dbg = format!("{svc:?}");
        assert!(dbg.contains("LoadShed"));
        assert!(dbg.contains("overloaded"));
    }

    #[test]
    fn load_shed_into_inner() {
        let svc = LoadShed::new(42_i32);
        let inner = svc.into_inner();
        assert_eq!(inner, 42);
    }

    #[test]
    fn load_shed_inner_accessor() {
        let svc = LoadShed::new(99_i32);
        assert_eq!(*svc.inner(), 99);
    }

    #[test]
    fn overloaded_debug_clone_copy() {
        let err = Overloaded::new();
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Overloaded"));

        let cloned = err;
        assert_eq!(err, cloned);

        let copied = err; // Copy
        assert_eq!(copied, Overloaded::new());
    }

    #[test]
    fn overloaded_default() {
        let err = Overloaded::default();
        assert_eq!(err, Overloaded::new());
    }

    #[test]
    fn overloaded_is_std_error() {
        let err: &dyn std::error::Error = &Overloaded::new();
        let _ = format!("{err}");
        let _ = format!("{err:?}");
        assert!(err.source().is_none());
    }

    #[test]
    fn load_shed_error_debug_all_variants() {
        let not_ready: LoadShedError<String> = LoadShedError::NotReady;
        let dbg = format!("{not_ready:?}");
        assert!(dbg.contains("NotReady"));

        let done: LoadShedError<String> = LoadShedError::PolledAfterCompletion;
        let dbg = format!("{done:?}");
        assert!(dbg.contains("PolledAfterCompletion"));

        let overloaded: LoadShedError<String> = LoadShedError::Overloaded(Overloaded::new());
        let dbg = format!("{overloaded:?}");
        assert!(dbg.contains("Overloaded"));

        let inner: LoadShedError<String> = LoadShedError::Inner("fail".to_string());
        let dbg = format!("{inner:?}");
        assert!(dbg.contains("Inner"));
    }

    #[test]
    fn load_shed_error_source() {
        use std::io;
        let not_ready: LoadShedError<io::Error> = LoadShedError::NotReady;
        let err: &dyn std::error::Error = &not_ready;
        assert!(err.source().is_none());

        let done: LoadShedError<io::Error> = LoadShedError::PolledAfterCompletion;
        let err: &dyn std::error::Error = &done;
        assert!(err.source().is_none());

        let overloaded: LoadShedError<io::Error> = LoadShedError::Overloaded(Overloaded::new());
        let err: &dyn std::error::Error = &overloaded;
        assert!(err.source().is_some()); // Overloaded implements Error

        let inner: LoadShedError<io::Error> = LoadShedError::Inner(io::Error::other("test"));
        let err: &dyn std::error::Error = &inner;
        assert!(err.source().is_some());
    }

    #[test]
    fn load_shed_future_debug() {
        let fut =
            LoadShedFuture::<std::future::Ready<Result<(), std::convert::Infallible>>>::overloaded(
            );
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("LoadShedFuture"));
    }

    #[test]
    fn load_shed_future_second_poll_fails_closed() {
        init_test("load_shed_future_second_poll_fails_closed");
        let mut fut =
            LoadShedFuture::<std::future::Ready<Result<(), std::convert::Infallible>>>::not_ready();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut fut).poll(&mut cx);
        let first_not_ready = matches!(first, Poll::Ready(Err(LoadShedError::NotReady)));
        crate::assert_with_log!(
            first_not_ready,
            "first poll not ready",
            true,
            first_not_ready
        );

        let second = Pin::new(&mut fut).poll(&mut cx);
        let second_done = matches!(
            second,
            Poll::Ready(Err(LoadShedError::PolledAfterCompletion))
        );
        crate::assert_with_log!(second_done, "second poll fails closed", true, second_done);
        crate::test_complete!("load_shed_future_second_poll_fails_closed");
    }

    #[test]
    fn load_shed_future_inner_panic_fails_closed() {
        init_test("load_shed_future_inner_panic_fails_closed");
        let mut svc = LoadShed::new(PanicOnPollService);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = svc.poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let mut fut = svc.call(3);
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = Pin::new(&mut fut).poll(&mut cx);
        }));
        assert!(panic.is_err(), "inner panic should propagate");

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(LoadShedError::PolledAfterCompletion))
        ));
        crate::test_complete!("load_shed_future_inner_panic_fails_closed");
    }
}
