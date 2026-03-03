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
    /// The request was rejected by the predicate.
    Rejected,
    /// The inner service returned an error.
    Inner(E),
}

impl<E: fmt::Display> fmt::Display for FilterError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => write!(f, "request rejected by filter"),
            Self::Inner(e) => write!(f, "service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for FilterError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rejected => None,
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
}

impl<S, P> Filter<S, P> {
    /// Create a new filter with the given inner service and predicate.
    #[must_use]
    pub fn new(inner: S, predicate: P) -> Self {
        Self { inner, predicate }
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
        self.inner.poll_ready(cx).map_err(FilterError::Inner)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        if (self.predicate)(&req) {
            FilterFuture::Inner(self.inner.call(req))
        } else {
            FilterFuture::Rejected
        }
    }
}

/// Future returned by [`Filter`].
pub enum FilterFuture<F> {
    /// The request was accepted and forwarded.
    Inner(F),
    /// The request was rejected.
    Rejected,
}

impl<F> fmt::Debug for FilterFuture<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inner(_) => f.debug_tuple("FilterFuture::Inner").finish(),
            Self::Rejected => f.debug_tuple("FilterFuture::Rejected").finish(),
        }
    }
}

impl<F, T, E> Future for FilterFuture<F>
where
    F: Future<Output = Result<T, E>> + Unpin,
{
    type Output = Result<T, FilterError<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Inner(fut) => Pin::new(fut).poll(cx).map_err(FilterError::Inner),
            Self::Rejected => Poll::Ready(Err(FilterError::Rejected)),
        }
    }
}

// ─── FilterAsync ──────────────────────────────────────────────────────────

/// A filter with an async predicate.
///
/// Similar to [`Filter`] but the predicate returns a future that
/// resolves to the decision. Useful for predicates that need I/O
/// (e.g., checking rate limit state, looking up ACLs).
pub struct AsyncFilter<S, P> {
    inner: S,
    predicate: P,
}

impl<S, P> AsyncFilter<S, P> {
    /// Create a new async filter.
    #[must_use]
    pub fn new(inner: S, predicate: P) -> Self {
        Self { inner, predicate }
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
}

impl<S: fmt::Debug, P> fmt::Debug for AsyncFilter<S, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncFilter")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
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
        assert_eq!(cloned.predicate, true);
    }

    // ================================================================
    // Filter
    // ================================================================

    #[derive(Debug, Clone)]
    struct MockSvc;

    #[test]
    fn filter_new() {
        init_test("filter_new");
        let filter = Filter::new(MockSvc, |_: &()| true);
        let _ = filter.inner();
        let _ = filter.predicate();
        crate::test_complete!("filter_new");
    }

    #[test]
    fn filter_inner_mut() {
        let mut filter = Filter::new(42u32, |_: &()| true);
        *filter.inner_mut() = 99;
        assert_eq!(*filter.inner(), 99);
    }

    #[test]
    fn filter_debug() {
        let filter = Filter::new(MockSvc, |_: &()| true);
        let dbg = format!("{filter:?}");
        assert!(dbg.contains("Filter"));
    }

    #[test]
    fn filter_clone() {
        let filter = Filter::new(MockSvc, true);
        let cloned = filter.clone();
        assert!(cloned.predicate);
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
        let layer = FilterLayer::new(|_: &()| true);
        let filter = layer.layer(MockSvc);
        let _ = filter.inner();
        crate::test_complete!("filter_layer_applies");
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
    fn filter_error_inner_display() {
        let err: FilterError<std::io::Error> = FilterError::Inner(std::io::Error::other("fail"));
        assert!(format!("{err}").contains("service error"));
    }

    #[test]
    fn filter_error_source() {
        use std::error::Error;
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

    // ================================================================
    // FilterFuture
    // ================================================================

    #[test]
    fn filter_future_inner_debug() {
        let fut: FilterFuture<std::future::Ready<Result<i32, ()>>> =
            FilterFuture::Inner(std::future::ready(Ok(42)));
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("Inner"));
    }

    #[test]
    fn filter_future_rejected_debug() {
        let fut: FilterFuture<std::future::Ready<Result<i32, ()>>> = FilterFuture::Rejected;
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("Rejected"));
    }

    // ================================================================
    // AsyncFilter
    // ================================================================

    #[test]
    fn async_filter_new() {
        let af = AsyncFilter::new(MockSvc, |_: &()| true);
        let _ = af.inner();
    }

    #[test]
    fn async_filter_inner_mut() {
        let mut af = AsyncFilter::new(42u32, |_: &()| true);
        *af.inner_mut() = 99;
        assert_eq!(*af.inner(), 99);
    }

    #[test]
    fn async_filter_debug() {
        let af = AsyncFilter::new(MockSvc, |_: &()| true);
        let dbg = format!("{af:?}");
        assert!(dbg.contains("AsyncFilter"));
    }
}
