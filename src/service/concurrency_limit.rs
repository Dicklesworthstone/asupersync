//! Concurrency limiting middleware layer.
//!
//! The [`ConcurrencyLimitLayer`] wraps a service to limit the number of
//! concurrent requests. It uses a semaphore internally to track permits.

use super::{Layer, Service};
use crate::cx::Cx;
use crate::sync::semaphore::OwnedAcquireFuture;
use crate::sync::{OwnedSemaphorePermit, Semaphore};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// A layer that limits concurrent requests.
///
/// This layer wraps a service with a semaphore that limits the number of
/// concurrent in-flight requests. When the limit is reached, `poll_ready`
/// will return `Poll::Pending` until a slot becomes available.
///
/// # Example
///
/// ```ignore
/// use asupersync::service::{ServiceBuilder, ServiceExt};
/// use asupersync::service::concurrency_limit::ConcurrencyLimitLayer;
///
/// let svc = ServiceBuilder::new()
///     .layer(ConcurrencyLimitLayer::new(10))  // Max 10 concurrent
///     .service(my_service);
/// ```
#[derive(Debug, Clone)]
pub struct ConcurrencyLimitLayer {
    semaphore: Arc<Semaphore>,
}

impl ConcurrencyLimitLayer {
    /// Creates a new concurrency limit layer with the given maximum.
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max)),
        }
    }

    /// Creates a new concurrency limit layer with a shared semaphore.
    ///
    /// This is useful when you want multiple services to share the same
    /// concurrency limit.
    #[must_use]
    pub fn with_semaphore(semaphore: Arc<Semaphore>) -> Self {
        Self { semaphore }
    }

    /// Returns the maximum number of concurrent requests.
    #[must_use]
    pub fn max_concurrency(&self) -> usize {
        self.semaphore.max_permits()
    }

    /// Returns the number of currently available slots.
    #[must_use]
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }
}

impl<S> Layer<S> for ConcurrencyLimitLayer {
    type Service = ConcurrencyLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConcurrencyLimit::new(inner, self.semaphore.clone())
    }
}

/// Internal state for the concurrency limit service.
enum State {
    Idle,
    Acquiring(Pin<Box<OwnedAcquireFuture>>),
    Ready(OwnedSemaphorePermit),
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Acquiring(_) => write!(f, "Acquiring(...)"),
            Self::Ready(_) => write!(f, "Ready(...)"),
        }
    }
}

/// A service that limits concurrent requests.
///
/// This service acquires a permit from a semaphore before dispatching
/// requests. The permit is held for the duration of the request and
/// released when the response future completes.
#[derive(Debug)]
pub struct ConcurrencyLimit<S> {
    inner: S,
    semaphore: Arc<Semaphore>,
    state: State,
}

impl<S: Clone> Clone for ConcurrencyLimit<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            semaphore: self.semaphore.clone(),
            state: State::Idle,
        }
    }
}

impl<S> ConcurrencyLimit<S> {
    /// Creates a new concurrency-limited service.
    #[must_use]
    pub fn new(inner: S, semaphore: Arc<Semaphore>) -> Self {
        Self {
            inner,
            semaphore,
            state: State::Idle,
        }
    }

    /// Returns the maximum concurrency limit.
    #[inline]
    #[must_use]
    pub fn max_concurrency(&self) -> usize {
        self.semaphore.max_permits()
    }

    /// Returns the number of available slots.
    #[inline]
    #[must_use]
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Returns a reference to the inner service.
    #[inline]
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// Returns a mutable reference to the inner service.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consumes the limiter, returning the inner service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// Error returned when concurrency limit operations fail.
#[derive(Debug)]
pub enum ConcurrencyLimitError<E> {
    /// The caller attempted `call()` without a preceding successful `poll_ready()`.
    NotReady,
    /// The concurrency-limit future was polled after it had already completed.
    PolledAfterCompletion,
    /// `poll_ready` could not acquire a permit: the semaphore was closed, or
    /// the task waiting for a permit was cancelled. A limiter that is only
    /// full does not fail; `poll_ready` waits for a permit instead.
    LimitExceeded,
    /// The inner service returned an error.
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for ConcurrencyLimitError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReady => write!(f, "poll_ready required before call"),
            Self::PolledAfterCompletion => {
                write!(f, "concurrency limit future polled after completion")
            }
            Self::LimitExceeded => write!(f, "concurrency limit exceeded"),
            Self::Inner(e) => write!(f, "inner service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ConcurrencyLimitError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotReady | Self::PolledAfterCompletion | Self::LimitExceeded => None,
            Self::Inner(e) => Some(e),
        }
    }
}

impl<S, Request> Service<Request> for ConcurrencyLimit<S>
where
    S: Service<Request>,
    S::Future: Unpin,
{
    type Response = S::Response;
    type Error = ConcurrencyLimitError<S::Error>;
    type Future = ConcurrencyLimitFuture<S::Future, S::Error>;

    fn release_readiness(&mut self) -> super::ReadinessRelease {
        let state = std::mem::replace(&mut self.state, State::Idle);
        let outer = super::ReadinessRelease::new(move || drop(state));
        let inner = self.inner.release_readiness();
        super::ReadinessRelease::new(move || drop((inner, outer)))
    }

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut restarted_acquisition = false;
        loop {
            match &mut self.state {
                State::Idle => {
                    // Claim outer capacity before consulting the inner service so
                    // stateful inner poll_ready reservations cannot be stranded
                    // while this limiter still waits on its own semaphore.
                    if let Ok(permit) = OwnedSemaphorePermit::try_acquire_arc(&self.semaphore, 1) {
                        self.state = State::Ready(permit);
                        continue;
                    }

                    // Fallback to queued acquisition. When a task-local Cx is
                    // available we keep cancellation-aware waiting; otherwise we
                    // still need to register a real semaphore waiter so permit
                    // release wakes this service instead of leaving it asleep
                    // forever until some caller manually polls again.
                    let future = if let Some(runtime_cx) = Cx::current() {
                        OwnedAcquireFuture::new(self.semaphore.clone(), runtime_cx.clone(), 1)
                    } else {
                        OwnedAcquireFuture::new_uncancelable(self.semaphore.clone(), 1)
                    };
                    self.state = State::Acquiring(Box::pin(future));
                }
                State::Acquiring(future) => match future.as_mut().poll(cx) {
                    Poll::Ready(Ok(permit)) => {
                        self.state = State::Ready(permit);
                    }
                    Poll::Ready(Err(err)) => {
                        // Reset state and return error (e.g. closed/cancelled)
                        self.state = State::Idle;
                        // The acquisition carries the Cx of the task that
                        // started it. Shared through Buffer, Steer or a load
                        // balancer, the limiter is polled by other tasks too:
                        // when that first task was cancelled but this poller
                        // was not, start over under this poller's Cx (once
                        // per call) instead of failing an unrelated request.
                        if err == crate::sync::AcquireError::Cancelled
                            && !restarted_acquisition
                            && !Cx::current().is_some_and(|current| current.is_cancel_requested())
                        {
                            restarted_acquisition = true;
                            continue;
                        }
                        return Poll::Ready(Err(ConcurrencyLimitError::LimitExceeded));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                State::Ready(_) => {
                    match self
                        .inner
                        .poll_ready(cx)
                        .map_err(ConcurrencyLimitError::Inner)
                    {
                        Poll::Pending => {
                            // The inner service did not actually admit work, so
                            // release the outer capacity and let the caller wait
                            // on the inner readiness edge instead.
                            self.state = State::Idle;
                            return Poll::Pending;
                        }
                        Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
                        Poll::Ready(Err(err)) => {
                            // Release the reserved permit if the inner service
                            // becomes not-callable after we acquired capacity.
                            self.state = State::Idle;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
            }
        }
    }

    #[inline]
    fn call(&mut self, req: Request) -> Self::Future {
        // Take the permit acquired in poll_ready.
        let state = std::mem::replace(&mut self.state, State::Idle);
        let permit = match state {
            State::Ready(permit) => permit,
            other => {
                // Preserve in-flight acquisition state on contract misuse.
                self.state = other;
                return ConcurrencyLimitFuture::immediate_error(ConcurrencyLimitError::NotReady);
            }
        };
        ConcurrencyLimitFuture::new(self.inner.call(req), permit)
    }
}

/// Future returned by [`ConcurrencyLimit`] service.
///
/// This future holds a permit for the duration of the inner service call.
/// When the future completes (or is dropped), the permit is released.
#[pin_project::pin_project(project = ConcurrencyLimitFutureProj)]
pub struct ConcurrencyLimitFuture<F, E> {
    #[pin]
    state: ConcurrencyLimitFutureState<F, E>,
    completed: bool,
}

#[pin_project::pin_project(project = ConcurrencyLimitFutureStateProj)]
enum ConcurrencyLimitFutureState<F, E> {
    Inner {
        #[pin]
        future: F,
        /// Held while the inner future is pending; dropped on completion.
        permit: Option<OwnedSemaphorePermit>,
    },
    Error {
        err: Option<ConcurrencyLimitError<E>>,
    },
}

impl<F, E> ConcurrencyLimitFuture<F, E> {
    /// Creates a new concurrency-limited future.
    #[must_use]
    pub fn new(inner: F, permit: OwnedSemaphorePermit) -> Self {
        Self {
            state: ConcurrencyLimitFutureState::Inner {
                future: inner,
                permit: Some(permit),
            },
            completed: false,
        }
    }

    /// Creates a future that resolves immediately to a limiter error.
    #[must_use]
    pub fn immediate_error(err: ConcurrencyLimitError<E>) -> Self {
        Self {
            state: ConcurrencyLimitFutureState::Error { err: Some(err) },
            completed: false,
        }
    }
}

impl<F, T, E> Future for ConcurrencyLimitFuture<F, E>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = Result<T, ConcurrencyLimitError<E>>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if *this.completed {
            return Poll::Ready(Err(ConcurrencyLimitError::PolledAfterCompletion));
        }

        match this.state.project() {
            ConcurrencyLimitFutureStateProj::Inner { future, permit } => match future.poll(cx) {
                Poll::Ready(Ok(response)) => {
                    *this.completed = true;
                    let _ = permit.take();
                    Poll::Ready(Ok(response))
                }
                Poll::Ready(Err(e)) => {
                    *this.completed = true;
                    let _ = permit.take();
                    Poll::Ready(Err(ConcurrencyLimitError::Inner(e)))
                }
                Poll::Pending => Poll::Pending,
            },
            ConcurrencyLimitFutureStateProj::Error { err } => {
                *this.completed = true;
                let err = err.take().unwrap_or(ConcurrencyLimitError::LimitExceeded);
                Poll::Ready(Err(err))
            }
        }
    }
}

impl<F: std::fmt::Debug, E> std::fmt::Debug for ConcurrencyLimitFuture<F, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.state {
            ConcurrencyLimitFutureState::Inner { future, .. } => f
                .debug_struct("ConcurrencyLimitFuture")
                .field("inner", future)
                .finish_non_exhaustive(),
            ConcurrencyLimitFutureState::Error { .. } => f
                .debug_struct("ConcurrencyLimitFuture")
                .field("state", &"Error")
                .finish(),
        }
    }
}

#[cfg(test)]
#[path = "concurrency_limit_inline_tests.rs"]
mod tests;
