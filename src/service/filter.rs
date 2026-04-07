//! Filter combinator: rejects requests that fail a predicate.
//!
//! The [`Filter`] service wraps an inner service and checks each request
//! against a predicate before forwarding it. Requests that fail the
//! predicate are rejected immediately with a [`FilterError::Rejected`].

use super::{Layer, Service};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

// ─── FilterLayer ──────────────────────────────────────────────────────────

/// A layer that applies a filter predicate to a service.
#[derive(Debug, Clone)]
pub struct FilterLayer<P> {
    predicate: P,
}

impl<P> FilterLayer<P> {
    /// Create a new filter layer with the given predicate.
    #[must_use]
    pub fn new(predicate: P) -> Self {
        Self { predicate }
    }
}

impl<S, P: Clone> Layer<S> for FilterLayer<P> {
    type Service = Filter<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        Filter::new(inner, self.predicate.clone())
    }
}

// ─── FilterError ──────────────────────────────────────────────────────────

/// Error from the filter middleware.
#[derive(Debug)]
pub enum FilterError<E> {
    /// The caller attempted `call()` without a preceding successful `poll_ready()`.
    NotReady,
    /// The filter future was polled after it had already completed.
    PolledAfterCompletion,
    /// The request was rejected by the predicate.
    Rejected,
    /// The inner service returned an error.
    Inner(E),
}

impl<E: fmt::Display> fmt::Display for FilterError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReady => write!(f, "poll_ready required before call"),
            Self::PolledAfterCompletion => write!(f, "filter future polled after completion"),
            Self::Rejected => write!(f, "request rejected by filter"),
            Self::Inner(e) => write!(f, "service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for FilterError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotReady | Self::PolledAfterCompletion | Self::Rejected => None,
            Self::Inner(e) => Some(e),
        }
    }
}

// ─── Filter service ───────────────────────────────────────────────────────

/// A service that rejects requests that fail a predicate.
///
/// The predicate `P` receives a reference to the request and returns
/// `true` to allow or `false` to reject.
pub struct Filter<S, P> {
    inner: S,
    predicate: P,
    // Tracks an inner readiness observation that has not yet been consumed by
    // an accepted request. Rejected requests preserve this window because the
    // inner service may already be holding state for the authorized call.
    ready_observed: bool,
}

impl<S, P> Filter<S, P> {
    /// Create a new filter with the given inner service and predicate.
    #[must_use]
    pub fn new(inner: S, predicate: P) -> Self {
        Self {
            inner,
            predicate,
            ready_observed: false,
        }
    }

    /// Get a reference to the inner service.
    #[must_use]
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Get a mutable reference to the inner service.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Get a reference to the predicate.
    #[must_use]
    pub fn predicate(&self) -> &P {
        &self.predicate
    }
}

impl<S: fmt::Debug, P> fmt::Debug for Filter<S, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Filter")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<S: Clone, P: Clone> Clone for Filter<S, P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            predicate: self.predicate.clone(),
            ready_observed: false,
        }
    }
}

impl<S, P, Request> Service<Request> for Filter<S, P>
where
    S: Service<Request>,
    S::Future: Unpin,
    P: Fn(&Request) -> bool,
{
    type Response = S::Response;
    type Error = FilterError<S::Error>;
    type Future = FilterFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.ready_observed {
            return Poll::Ready(Ok(()));
        }

        match self.inner.poll_ready(cx).map_err(FilterError::Inner) {
            Poll::Ready(Ok(())) => {
                self.ready_observed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                self.ready_observed = false;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        if !(self.predicate)(&req) {
            FilterFuture::rejected()
        } else if !self.ready_observed {
            FilterFuture::not_ready()
        } else {
            self.ready_observed = false;
            FilterFuture::inner(self.inner.call(req))
        }
    }
}

/// Future returned by [`Filter`].
pub struct FilterFuture<F> {
    state: FilterFutureState<F>,
}

enum FilterFutureState<F> {
    /// The caller skipped `poll_ready()` or reused a consumed readiness window.
    NotReady,
    /// The request was accepted and forwarded.
    Inner(F),
    /// The request was rejected.
    Rejected,
    /// The future has already completed.
    Done,
}

impl<F> FilterFuture<F> {
    /// Creates a future that immediately returns a readiness misuse error.
    #[must_use]
    pub fn not_ready() -> Self {
        Self {
            state: FilterFutureState::NotReady,
        }
    }

    /// Creates a future that wraps the inner service's future.
    #[must_use]
    pub fn inner(future: F) -> Self {
        Self {
            state: FilterFutureState::Inner(future),
        }
    }

    /// Creates a future that immediately returns a rejection error.
    #[must_use]
    pub fn rejected() -> Self {
        Self {
            state: FilterFutureState::Rejected,
        }
    }
}

impl<F> fmt::Debug for FilterFuture<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.state {
            FilterFutureState::NotReady => f.debug_tuple("FilterFuture::NotReady").finish(),
            FilterFutureState::Inner(_) => f.debug_tuple("FilterFuture::Inner").finish(),
            FilterFutureState::Rejected => f.debug_tuple("FilterFuture::Rejected").finish(),
            FilterFutureState::Done => f.debug_tuple("FilterFuture::Done").finish(),
        }
    }
}

impl<F, T, E> Future for FilterFuture<F>
where
    F: Future<Output = Result<T, E>> + Unpin,
{
    type Output = Result<T, FilterError<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        match std::mem::replace(&mut this.state, FilterFutureState::Done) {
            FilterFutureState::NotReady => Poll::Ready(Err(FilterError::NotReady)),
            FilterFutureState::Inner(mut fut) => match Pin::new(&mut fut).poll(cx) {
                Poll::Ready(Ok(value)) => Poll::Ready(Ok(value)),
                Poll::Ready(Err(err)) => Poll::Ready(Err(FilterError::Inner(err))),
                Poll::Pending => {
                    this.state = FilterFutureState::Inner(fut);
                    Poll::Pending
                }
            },
            FilterFutureState::Rejected => Poll::Ready(Err(FilterError::Rejected)),
            FilterFutureState::Done => Poll::Ready(Err(FilterError::PolledAfterCompletion)),
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Waker;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    struct NoopWaker;

    impl std::task::Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    // ================================================================
    // FilterLayer
    // ================================================================

    #[test]
    fn filter_layer_new() {
        init_test("filter_layer_new");
        let layer = FilterLayer::new(true);
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("FilterLayer"));
        crate::test_complete!("filter_layer_new");
    }

    #[test]
    fn filter_layer_clone() {
        let layer = FilterLayer::new(true);
        let cloned = layer.clone();
        assert!(cloned.predicate);
        assert!(layer.predicate);
    }

    // ================================================================
    // Filter
    // ================================================================

    #[derive(Debug, Clone)]
    struct MockSvc;

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
            std::future::ready(Ok(req))
        }
    }

    #[derive(Clone)]
    struct StrictReservingService {
        ready_polls: Arc<AtomicUsize>,
        available: Arc<AtomicUsize>,
        reserved: bool,
    }

    impl StrictReservingService {
        fn new(ready_polls: Arc<AtomicUsize>, available: Arc<AtomicUsize>) -> Self {
            Self {
                ready_polls,
                available,
                reserved: false,
            }
        }
    }

    impl Service<i32> for StrictReservingService {
        type Response = i32;
        type Error = &'static str;
        type Future = std::future::Ready<Result<i32, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.ready_polls.fetch_add(1, Ordering::SeqCst);

            if self.reserved {
                return Poll::Pending;
            }

            let available = self.available.load(Ordering::SeqCst);
            if available == 0 {
                return Poll::Pending;
            }

            self.available.fetch_sub(1, Ordering::SeqCst);
            self.reserved = true;
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: i32) -> Self::Future {
            if !std::mem::replace(&mut self.reserved, false) {
                return std::future::ready(Err("not ready"));
            }

            self.available.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(req))
        }
    }

    #[derive(Clone)]
    struct PanicOnPollService;

    struct PanicOnPollFuture;

    impl std::future::Future for PanicOnPollFuture {
        type Output = Result<i32, std::convert::Infallible>;

        fn poll(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<<Self as std::future::Future>::Output> {
            panic!("panic in filter future poll");
        }
    }

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
    fn filter_new() {
        init_test("filter_new");
        let filter = Filter::new(MockSvc, |(): &()| true);
        let _ = filter.inner();
        let _ = filter.predicate();
        crate::test_complete!("filter_new");
    }

    #[test]
    fn filter_inner_mut() {
        let mut filter = Filter::new(42u32, |(): &()| true);
        *filter.inner_mut() = 99;
        assert_eq!(*filter.inner(), 99);
    }

    #[test]
    fn filter_debug() {
        let filter = Filter::new(MockSvc, |(): &()| true);
        let dbg = format!("{filter:?}");
        assert!(dbg.contains("Filter"));
    }

    #[test]
    fn filter_clone() {
        let filter = Filter::new(MockSvc, true);
        let cloned = filter.clone();
        assert!(cloned.predicate);
        assert!(filter.predicate);
    }

    #[test]
    fn filter_predicate_accepts() {
        init_test("filter_predicate_accepts");
        let pred = |x: &i32| *x > 0;
        assert!(pred(&5));
        assert!(!pred(&-1));
        crate::test_complete!("filter_predicate_accepts");
    }

    #[test]
    fn filter_layer_applies() {
        init_test("filter_layer_applies");
        let layer = FilterLayer::new(|(): &()| true);
        let filter = layer.layer(MockSvc);
        let _ = filter.inner();
        crate::test_complete!("filter_layer_applies");
    }

    #[test]
    fn filter_call_without_poll_ready_returns_not_ready() {
        init_test("filter_call_without_poll_ready_returns_not_ready");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut filter = Filter::new(CountingReadyService::new(Arc::clone(&calls)), |x: &i32| {
            *x > 0
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut future = filter.call(7);
        let result = Pin::new(&mut future).poll(&mut cx);
        let not_ready = matches!(result, Poll::Ready(Err(FilterError::NotReady)));
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
        crate::test_complete!("filter_call_without_poll_ready_returns_not_ready");
    }

    #[test]
    fn filter_rejected_call_without_poll_ready_returns_rejected() {
        init_test("filter_rejected_call_without_poll_ready_returns_rejected");
        let ready_polls = Arc::new(AtomicUsize::new(0));
        let available = Arc::new(AtomicUsize::new(0));
        let inner = StrictReservingService::new(Arc::clone(&ready_polls), Arc::clone(&available));
        let mut filter = Filter::new(inner, |x: &i32| *x > 0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut rejected = filter.call(-7);
        let rejected_result = Pin::new(&mut rejected).poll(&mut cx);
        let rejected_ok = matches!(rejected_result, Poll::Ready(Err(FilterError::Rejected)));
        crate::assert_with_log!(
            rejected_ok,
            "rejected request short-circuits without poll_ready",
            true,
            rejected_ok
        );
        crate::assert_with_log!(
            ready_polls.load(Ordering::SeqCst) == 0,
            "rejected request never polls inner readiness",
            0,
            ready_polls.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            available.load(Ordering::SeqCst) == 0,
            "inner backpressure state remains untouched",
            0,
            available.load(Ordering::SeqCst)
        );

        let mut accepted = filter.call(7);
        let accepted_result = Pin::new(&mut accepted).poll(&mut cx);
        let accepted_not_ready = matches!(accepted_result, Poll::Ready(Err(FilterError::NotReady)));
        crate::assert_with_log!(
            accepted_not_ready,
            "accepted requests still require an explicit readiness observation",
            true,
            accepted_not_ready
        );
        crate::test_complete!("filter_rejected_call_without_poll_ready_returns_rejected");
    }

    #[test]
    fn filter_ready_window_is_consumed_by_call() {
        init_test("filter_ready_window_is_consumed_by_call");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut filter = Filter::new(CountingReadyService::new(Arc::clone(&calls)), |x: &i32| {
            *x > 0
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = filter.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "poll_ready authorizes one call", true, ready_ok);

        let mut first = filter.call(7);
        let first_result = Pin::new(&mut first).poll(&mut cx);
        let first_ok = matches!(first_result, Poll::Ready(Ok(7)));
        crate::assert_with_log!(first_ok, "first call succeeds", true, first_ok);

        let mut second = filter.call(8);
        let second_result = Pin::new(&mut second).poll(&mut cx);
        let second_not_ready = matches!(second_result, Poll::Ready(Err(FilterError::NotReady)));
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
        crate::test_complete!("filter_ready_window_is_consumed_by_call");
    }

    #[test]
    fn filter_clone_does_not_inherit_ready_window() {
        init_test("filter_clone_does_not_inherit_ready_window");
        let calls = Arc::new(AtomicUsize::new(0));
        let mut filter = Filter::new(CountingReadyService::new(Arc::clone(&calls)), |x: &i32| {
            *x > 0
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = filter.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "original filter ready", true, ready_ok);

        let mut cloned = filter.clone();
        let mut future = cloned.call(5);
        let result = Pin::new(&mut future).poll(&mut cx);
        let not_ready = matches!(result, Poll::Ready(Err(FilterError::NotReady)));
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
        crate::test_complete!("filter_clone_does_not_inherit_ready_window");
    }

    #[test]
    fn rejected_request_preserves_ready_window_for_next_accepted_call() {
        init_test("rejected_request_preserves_ready_window_for_next_accepted_call");
        let ready_polls = Arc::new(AtomicUsize::new(0));
        let available = Arc::new(AtomicUsize::new(1));
        let inner = StrictReservingService::new(Arc::clone(&ready_polls), Arc::clone(&available));
        let mut filter = Filter::new(inner, |x: &i32| *x > 10);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = filter.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "poll_ready authorizes one call", true, ready_ok);
        crate::assert_with_log!(
            ready_polls.load(Ordering::SeqCst) == 1,
            "inner poll_ready called once to reserve capacity",
            1,
            ready_polls.load(Ordering::SeqCst)
        );
        crate::assert_with_log!(
            available.load(Ordering::SeqCst) == 0,
            "inner reservation consumes the only available slot",
            0,
            available.load(Ordering::SeqCst)
        );

        let mut rejected = filter.call(7);
        let rejected_result = Pin::new(&mut rejected).poll(&mut cx);
        let rejected_ok = matches!(rejected_result, Poll::Ready(Err(FilterError::Rejected)));
        crate::assert_with_log!(
            rejected_ok,
            "request rejected by predicate",
            true,
            rejected_ok
        );

        let ready_again = filter.poll_ready(&mut cx);
        let ready_again_ok = matches!(ready_again, Poll::Ready(Ok(())));
        crate::assert_with_log!(
            ready_again_ok,
            "existing readiness window is preserved across rejection",
            true,
            ready_again_ok
        );
        crate::assert_with_log!(
            ready_polls.load(Ordering::SeqCst) == 1,
            "re-poll short-circuits without touching the reserved inner service",
            1,
            ready_polls.load(Ordering::SeqCst)
        );

        let mut accepted = filter.call(11);
        let accepted_result = Pin::new(&mut accepted).poll(&mut cx);
        let accepted_ok = matches!(accepted_result, Poll::Ready(Ok(11)));
        crate::assert_with_log!(
            accepted_ok,
            "accepted follow-up request consumes the preserved readiness window",
            true,
            accepted_ok
        );
        crate::assert_with_log!(
            available.load(Ordering::SeqCst) == 1,
            "inner reservation is released once an accepted request reaches the service",
            1,
            available.load(Ordering::SeqCst)
        );

        let mut third = filter.call(12);
        let third_result = Pin::new(&mut third).poll(&mut cx);
        let third_not_ready = matches!(third_result, Poll::Ready(Err(FilterError::NotReady)));
        crate::assert_with_log!(
            third_not_ready,
            "accepted request still consumes the preserved readiness ticket",
            true,
            third_not_ready
        );
        crate::test_complete!("rejected_request_preserves_ready_window_for_next_accepted_call");
    }

    // ================================================================
    // FilterError
    // ================================================================

    #[test]
    fn filter_error_rejected_display() {
        let err: FilterError<std::io::Error> = FilterError::Rejected;
        assert!(format!("{err}").contains("request rejected by filter"));
    }

    #[test]
    fn filter_error_polled_after_completion_display() {
        let err: FilterError<std::io::Error> = FilterError::PolledAfterCompletion;
        assert!(format!("{err}").contains("polled after completion"));
    }

    #[test]
    fn filter_error_not_ready_display() {
        let err: FilterError<std::io::Error> = FilterError::NotReady;
        assert!(format!("{err}").contains("poll_ready required"));
    }

    #[test]
    fn filter_error_inner_display() {
        let err: FilterError<std::io::Error> = FilterError::Inner(std::io::Error::other("fail"));
        assert!(format!("{err}").contains("service error"));
    }

    #[test]
    fn filter_error_source() {
        use std::error::Error;
        let err: FilterError<std::io::Error> = FilterError::NotReady;
        assert!(err.source().is_none());

        let err: FilterError<std::io::Error> = FilterError::PolledAfterCompletion;
        assert!(err.source().is_none());

        let err: FilterError<std::io::Error> = FilterError::Rejected;
        assert!(err.source().is_none());

        let err2: FilterError<std::io::Error> = FilterError::Inner(std::io::Error::other("fail"));
        assert!(err2.source().is_some());
    }

    #[test]
    fn filter_error_debug() {
        let err: FilterError<std::io::Error> = FilterError::Rejected;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Rejected"));
    }

    #[test]
    fn filter_error_polled_after_completion_debug() {
        let err: FilterError<std::io::Error> = FilterError::PolledAfterCompletion;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PolledAfterCompletion"));
    }

    // ================================================================
    // FilterFuture
    // ================================================================

    #[test]
    fn filter_future_inner_debug() {
        let fut = FilterFuture::inner(std::future::ready(Ok::<i32, ()>(42)));
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("Inner"));
    }

    #[test]
    fn filter_future_not_ready_debug() {
        let fut: FilterFuture<std::future::Ready<Result<i32, ()>>> = FilterFuture::not_ready();
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("NotReady"));
    }

    #[test]
    fn filter_future_rejected_debug() {
        let fut: FilterFuture<std::future::Ready<Result<i32, ()>>> = FilterFuture::rejected();
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("Rejected"));
    }

    #[test]
    fn filter_future_not_ready_repoll_fails_closed() {
        let mut fut: FilterFuture<std::future::Ready<Result<i32, ()>>> = FilterFuture::not_ready();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Err(FilterError::NotReady))));

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(FilterError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn filter_future_rejected_repoll_fails_closed() {
        let mut fut: FilterFuture<std::future::Ready<Result<i32, ()>>> = FilterFuture::rejected();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Err(FilterError::Rejected))));

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(FilterError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn filter_future_inner_repoll_fails_closed() {
        let mut fut = FilterFuture::inner(std::future::ready(Ok::<i32, ()>(42)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Ok(42))));

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(FilterError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn filter_future_inner_panic_fails_closed() {
        init_test("filter_future_inner_panic_fails_closed");
        let mut filter = Filter::new(PanicOnPollService, |_: &i32| true);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = filter.poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let mut fut = filter.call(7);
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = Pin::new(&mut fut).poll(&mut cx);
        }));
        assert!(panic.is_err(), "inner panic should propagate");

        let second = Pin::new(&mut fut).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(FilterError::PolledAfterCompletion))
        ));
        crate::test_complete!("filter_future_inner_panic_fails_closed");
    }
}
