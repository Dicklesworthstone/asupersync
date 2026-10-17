//! Timeout middleware layer.
//!
//! The [`TimeoutLayer`] wraps a service to impose a maximum execution time
//! on each request. If the inner service doesn't complete within the timeout,
//! an [`Elapsed`] error is returned.

use super::{Layer, Service};
use crate::time::{Elapsed, Sleep};
use crate::types::Time;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

/// The time source of a layer or service: a custom getter, or the runtime's
/// clock (`None`). The runtime's clock is `wall_now`, which reads the ambient
/// timer driver, so its deadlines wait on that driver or, off the runtime, on
/// the shared fallback timer. A custom getter makes every request's `Sleep`
/// poll that getter from a thread of its own (br-asupersync-1sxucf).
const fn effective_time_getter(time_getter: Option<fn() -> Time>) -> fn() -> Time {
    match time_getter {
        Some(time_getter) => time_getter,
        None => wall_clock_now,
    }
}

fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// A layer that applies a timeout to requests.
///
/// # Example
///
/// ```ignore
/// use asupersync::service::{ServiceBuilder, ServiceExt};
/// use asupersync::service::timeout::TimeoutLayer;
/// use std::time::Duration;
///
/// let svc = ServiceBuilder::new()
///     .layer(TimeoutLayer::new(Duration::from_secs(30)))
///     .service(my_service);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct TimeoutLayer {
    duration: Duration,
    time_getter: Option<fn() -> Time>,
}

impl TimeoutLayer {
    /// Creates a new timeout layer with the given duration.
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self {
            duration: timeout,
            time_getter: None,
        }
    }

    /// Creates a new timeout layer with a custom time source.
    #[must_use]
    pub const fn with_time_getter(timeout: Duration, time_getter: fn() -> Time) -> Self {
        Self {
            duration: timeout,
            time_getter: Some(time_getter),
        }
    }

    /// Returns the timeout duration.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.duration
    }

    /// Returns the time source used by this layer.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        effective_time_getter(self.time_getter)
    }
}

impl<S> Layer<S> for TimeoutLayer {
    type Service = Timeout<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Timeout {
            inner,
            duration: self.duration,
            time_getter: self.time_getter,
            ready_observed: false,
        }
    }
}

/// A service that imposes a timeout on requests.
///
/// If the inner service doesn't complete within the timeout, the request
/// fails with a [`TimeoutError`]. Each successful `poll_ready` authorizes
/// exactly one subsequent `call`; skipping readiness fails closed with
/// [`TimeoutError::NotReady`].
#[derive(Debug)]
pub struct Timeout<S> {
    inner: S,
    duration: Duration,
    time_getter: Option<fn() -> Time>,
    ready_observed: bool,
}

impl<S: Clone> Clone for Timeout<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            duration: self.duration,
            time_getter: self.time_getter,
            // Readiness authorization is handle-local and must not be cloned.
            ready_observed: false,
        }
    }
}

impl<S> Timeout<S> {
    /// Creates a new timeout service.
    #[must_use]
    pub const fn new(inner: S, timeout: Duration) -> Self {
        Self {
            inner,
            duration: timeout,
            time_getter: None,
            ready_observed: false,
        }
    }

    /// Creates a new timeout service with a custom time source.
    #[must_use]
    pub const fn with_time_getter(inner: S, timeout: Duration, time_getter: fn() -> Time) -> Self {
        Self {
            inner,
            duration: timeout,
            time_getter: Some(time_getter),
            ready_observed: false,
        }
    }

    /// Returns the timeout duration.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.duration
    }

    /// Returns the time source used by this service.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        effective_time_getter(self.time_getter)
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

    /// Consumes the timeout, returning the inner service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// Error returned when a request times out.
#[derive(Debug)]
pub enum TimeoutError<E> {
    /// The caller attempted `call()` without a preceding successful `poll_ready()`.
    NotReady,
    /// The timeout future was polled after it had already completed.
    PolledAfterCompletion,
    /// The request timed out.
    Elapsed(Elapsed),
    /// The inner service returned an error.
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for TimeoutError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReady => write!(f, "poll_ready required before call"),
            Self::PolledAfterCompletion => write!(f, "timeout future polled after completion"),
            Self::Elapsed(e) => write!(f, "request timed out: {e}"),
            Self::Inner(e) => write!(f, "inner service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for TimeoutError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotReady | Self::PolledAfterCompletion => None,
            Self::Elapsed(e) => Some(e),
            Self::Inner(e) => Some(e),
        }
    }
}

impl<S, Request> Service<Request> for Timeout<S>
where
    S: Service<Request>,
    S::Future: Unpin,
{
    type Response = S::Response;
    type Error = TimeoutError<S::Error>;
    type Future = TimeoutFuture<S::Future>;

    fn release_readiness(&mut self) -> super::ReadinessRelease {
        self.ready_observed = false;
        self.inner.release_readiness()
    }

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.inner.poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                self.ready_observed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                self.ready_observed = false;
                Poll::Ready(Err(TimeoutError::Inner(err)))
            }
            Poll::Pending => {
                self.ready_observed = false;
                Poll::Pending
            }
        }
    }

    #[inline]
    fn call(&mut self, req: Request) -> Self::Future {
        if !std::mem::replace(&mut self.ready_observed, false) {
            return TimeoutFuture::not_ready();
        }
        let now = (self.time_getter())();
        let deadline = now.saturating_add_nanos(duration_to_nanos(self.duration));
        let inner = self.inner.call(req);
        match self.time_getter {
            Some(time_getter) => TimeoutFuture::with_time_getter(inner, deadline, time_getter),
            None => TimeoutFuture::new(inner, deadline),
        }
    }
}

/// Future returned by [`Timeout`] service.
#[derive(Debug)]
pub struct TimeoutFuture<F> {
    state: TimeoutFutureState<F>,
}

#[derive(Debug)]
enum TimeoutFutureState<F> {
    /// Caller skipped `poll_ready` or reused a consumed readiness window.
    NotReady,
    /// Active timeout-wrapped inner future.
    Running {
        inner: F,
        sleep: Sleep,
        time_getter: Option<fn() -> Time>,
    },
    /// Future has completed.
    Done,
}

impl<F> TimeoutFuture<F> {
    /// Creates a future that immediately returns a readiness misuse error.
    #[must_use]
    pub const fn not_ready() -> Self {
        Self {
            state: TimeoutFutureState::NotReady,
        }
    }

    /// Creates a new timeout future.
    #[must_use]
    pub fn new(inner: F, deadline: Time) -> Self {
        Self {
            state: TimeoutFutureState::Running {
                inner,
                sleep: Sleep::new(deadline),
                time_getter: None,
            },
        }
    }

    /// Creates a new timeout future with a custom time source.
    ///
    /// The `time_getter` is used by both timeout decisions and the underlying
    /// sleep so they agree on the current time.
    #[must_use]
    pub fn with_time_getter(inner: F, deadline: Time, time_getter: fn() -> Time) -> Self {
        Self {
            state: TimeoutFutureState::Running {
                inner,
                sleep: Sleep::with_time_getter(deadline, time_getter),
                time_getter: Some(time_getter),
            },
        }
    }

    /// Returns the deadline for this timeout.
    #[must_use]
    pub fn deadline(&self) -> Time {
        match &self.state {
            TimeoutFutureState::Running { sleep, .. } => sleep.deadline(),
            TimeoutFutureState::NotReady | TimeoutFutureState::Done => Time::ZERO,
        }
    }

    /// Polls with an explicit time value.
    ///
    /// # Arguments
    ///
    /// * `now` - The current time
    /// * `cx` - The task context
    pub fn poll_with_time<T, E>(
        &mut self,
        now: Time,
        cx: &mut Context<'_>,
    ) -> Poll<Result<T, TimeoutError<E>>>
    where
        F: Future<Output = Result<T, E>> + Unpin,
    {
        let state = std::mem::replace(&mut self.state, TimeoutFutureState::Done);
        match state {
            TimeoutFutureState::NotReady => Poll::Ready(Err(TimeoutError::NotReady)),
            TimeoutFutureState::Done => Poll::Ready(Err(TimeoutError::PolledAfterCompletion)),
            TimeoutFutureState::Running {
                mut inner,
                mut sleep,
                time_getter,
            } => {
                // Prefer completed work at the timeout boundary.
                match Pin::new(&mut inner).poll(cx) {
                    Poll::Ready(Ok(response)) => Poll::Ready(Ok(response)),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(TimeoutError::Inner(e))),
                    Poll::Pending => {
                        if sleep.poll_with_time(now).is_ready() {
                            Poll::Ready(Err(TimeoutError::Elapsed(Elapsed::new(sleep.deadline()))))
                        } else {
                            // Preserve wake registration only when the sleep
                            // uses the same time source as the explicit `now`
                            // or an ambient timer driver is available. Falling
                            // back to wall clock here can spuriously expire a
                            // manual-time poll.
                            let has_ambient_timer = crate::cx::Cx::current()
                                .and_then(|current| current.timer_driver())
                                .is_some();
                            if (time_getter.is_some() || has_ambient_timer)
                                && Pin::new(&mut sleep).poll_deadline(cx).is_ready()
                            {
                                // Registering the wake source can also complete
                                // the sleep. Never retain it for another poll.
                                return Poll::Ready(Err(TimeoutError::Elapsed(Elapsed::new(
                                    sleep.deadline(),
                                ))));
                            }
                            self.state = TimeoutFutureState::Running {
                                inner,
                                sleep,
                                time_getter,
                            };
                            Poll::Pending
                        }
                    }
                }
            }
        }
    }
}

impl<F, T, E> Future for TimeoutFuture<F>
where
    F: Future<Output = Result<T, E>> + Unpin,
{
    type Output = Result<T, TimeoutError<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let state = std::mem::replace(&mut this.state, TimeoutFutureState::Done);
        match state {
            TimeoutFutureState::NotReady => Poll::Ready(Err(TimeoutError::NotReady)),
            TimeoutFutureState::Done => Poll::Ready(Err(TimeoutError::PolledAfterCompletion)),
            TimeoutFutureState::Running {
                mut inner,
                mut sleep,
                time_getter,
            } => {
                match Pin::new(&mut inner).poll(cx) {
                    Poll::Ready(Ok(response)) => return Poll::Ready(Ok(response)),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(TimeoutError::Inner(e))),
                    Poll::Pending => {}
                }

                if let Some(time_getter) = time_getter {
                    if sleep.poll_with_time(time_getter()).is_ready() {
                        return Poll::Ready(Err(TimeoutError::Elapsed(Elapsed::new(
                            sleep.deadline(),
                        ))));
                    }

                    // Preserve wake registration even when timeout decisions use a
                    // manual or virtual clock. Time can advance between the two
                    // polls. Only the deadline timer skips cancellation; the
                    // inner future still observes it and can finish cleanup.
                    if Pin::new(&mut sleep).poll_deadline(cx).is_ready() {
                        return Poll::Ready(Err(TimeoutError::Elapsed(Elapsed::new(
                            sleep.deadline(),
                        ))));
                    }
                    this.state = TimeoutFutureState::Running {
                        inner,
                        sleep,
                        time_getter: Some(time_getter),
                    };
                    return Poll::Pending;
                }

                match Pin::new(&mut sleep).poll_deadline(cx) {
                    Poll::Ready(()) => {
                        Poll::Ready(Err(TimeoutError::Elapsed(Elapsed::new(sleep.deadline()))))
                    }
                    Poll::Pending => {
                        this.state = TimeoutFutureState::Running {
                            inner,
                            sleep,
                            time_getter: None,
                        };
                        Poll::Pending
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "timeout_inline_tests.rs"]
mod tests;
