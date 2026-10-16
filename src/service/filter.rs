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
/// A rejection releases the unused readiness reservation. Poll readiness again
/// before dispatching the next request, including on the same connection.
pub struct Filter<S, P> {
    inner: S,
    predicate: P,
    // Tracks an inner readiness observation that has not yet been consumed by
    // a request. Rejection releases the inner reservation as well.
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

    fn release_readiness(&mut self) -> super::ReadinessRelease {
        self.ready_observed = false;
        self.inner.release_readiness()
    }

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
            // Rejection finishes this readiness attempt. Keeping its permit
            // would let an idle rejected connection starve other handles.
            drop(self.release_readiness());
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
#[path = "filter_inline_tests.rs"]
mod tests;
