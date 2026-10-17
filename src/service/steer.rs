//! Steer combinator: routes requests to one of several services.
//!
//! [`Steer`] dispatches each request to one of N inner services based on
//! a user-supplied routing function. This enables content-based routing,
//! A/B testing, and service selection patterns.

use super::Service;
use parking_lot::{Mutex, MutexGuard};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

// ─── Steer ────────────────────────────────────────────────────────────────

/// Wakers of the steer futures waiting for one backend's `poll_ready`.
///
/// Most services keep only the latest waker passed to `poll_ready`
/// (`RateLimit`, the semaphore behind `ConcurrencyLimit`), so with two
/// futures waiting on one backend only the later one would be woken. A
/// future that stops waiting (dispatched, failed or dropped) therefore wakes
/// the others, which re-poll and register their own wakers again.
#[derive(Default)]
struct ReadinessWaiters {
    next_id: u64,
    wakers: Vec<(u64, Waker)>,
    owners: usize,
}

impl ReadinessWaiters {
    fn register(waiters: &Mutex<Self>, id: &mut Option<u64>, waker: &Waker) {
        let mut guard = waiters.lock();
        let key = *id.get_or_insert_with(|| {
            guard.next_id = guard.next_id.wrapping_add(1);
            guard.next_id
        });
        match guard.wakers.iter_mut().find(|(entry, _)| *entry == key) {
            Some((_, stored)) if stored.will_wake(waker) => {}
            Some((_, stored)) => stored.clone_from(waker),
            None => guard.wakers.push((key, waker.clone())),
        }
    }

    fn release(waiters: &Mutex<Self>, id: Option<u64>) {
        let retired = {
            let mut guard = waiters.lock();
            std::mem::take(&mut guard.wakers)
        };
        // The excluded caller's Waker may run user code when dropped too.
        // Move every entry out before filtering or dispatching any callback.
        for (entry, waker) in retired {
            if Some(entry) != id {
                waker.wake();
            }
        }
    }
}

/// A service that routes requests to one of several inner services.
///
/// The `picker` function is called with the request to select which
/// backend receives it (by index into the `services` vec). Out-of-range
/// indexes fail closed instead of being silently wrapped.
pub struct Steer<S, F> {
    services: Vec<Arc<Mutex<S>>>,
    /// Per backend, shared by clones like the backend itself.
    waiters: Vec<Arc<Mutex<ReadinessWaiters>>>,
    picker: F,
}

impl<S, F> Steer<S, F> {
    /// Create a new steer combinator.
    ///
    /// `picker` is called with a reference to the request and must return
    /// an index into `services`. Returning an out-of-range index causes
    /// [`SteerError::InvalidRoute`] when the returned future is polled.
    ///
    /// # Panics
    ///
    /// Panics if `services` is empty.
    #[must_use]
    pub fn new(services: Vec<S>, picker: F) -> Self {
        assert!(!services.is_empty(), "steer requires at least one service");
        let waiters = services.iter().map(|_| Arc::default()).collect();
        Self {
            services: services
                .into_iter()
                .map(|service| Arc::new(Mutex::new(service)))
                .collect(),
            waiters,
            picker,
        }
    }

    /// Get the number of inner services.
    #[must_use]
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Returns false (at least one service is always present).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// Snapshot the current inner services by cloning them.
    ///
    /// This is intended for inspection and tests.
    #[must_use]
    pub fn services(&self) -> Vec<S>
    where
        S: Clone,
    {
        self.services
            .iter()
            .map(|service| service.lock().clone())
            .collect()
    }

    /// Acquire mutable guards for the inner services.
    ///
    /// This is intended for tests and synchronous maintenance operations.
    pub fn services_mut(&self) -> Vec<MutexGuard<'_, S>> {
        self.services.iter().map(|service| service.lock()).collect()
    }
}

impl<S, F: Clone> Clone for Steer<S, F> {
    fn clone(&self) -> Self {
        Self {
            services: self.services.clone(),
            waiters: self.waiters.clone(),
            picker: self.picker.clone(),
        }
    }
}

impl<S: fmt::Debug, F> fmt::Debug for Steer<S, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let services: Vec<String> = self
            .services
            .iter()
            .map(|service| format!("{:?}", *service.lock()))
            .collect();
        f.debug_struct("Steer")
            .field("services", &services)
            .finish_non_exhaustive()
    }
}

/// Future returned by [`Steer`].
pub struct SteerFuture<S, Request>
where
    S: Service<Request>,
{
    state: SteerState<S, Request>,
}

enum SteerState<S, Request>
where
    S: Service<Request>,
{
    InvalidRoute {
        index: usize,
        service_count: usize,
    },
    PollReady {
        service: Arc<Mutex<S>>,
        waiters: Arc<Mutex<ReadinessWaiters>>,
        readiness: SteerReadiness<S, Request>,
        request: Option<Request>,
    },
    Calling {
        future: S::Future,
    },
    Done,
}

impl<S, Request> SteerFuture<S, Request>
where
    S: Service<Request>,
{
    fn invalid_route(index: usize, service_count: usize) -> Self {
        Self {
            state: SteerState::InvalidRoute {
                index,
                service_count,
            },
        }
    }

    fn new(
        service: Arc<Mutex<S>>,
        waiters: Arc<Mutex<ReadinessWaiters>>,
        request: Request,
    ) -> Self {
        waiters.lock().owners += 1;
        let readiness = SteerReadiness {
            service: Arc::clone(&service),
            waiters: Arc::clone(&waiters),
            waiter: None,
            waiting: true,
            marker: std::marker::PhantomData,
        };
        Self {
            state: SteerState::PollReady {
                service,
                waiters,
                readiness,
                request: Some(request),
            },
        }
    }
}

struct SteerReadiness<S, Request>
where
    S: Service<Request>,
{
    service: Arc<Mutex<S>>,
    waiters: Arc<Mutex<ReadinessWaiters>>,
    waiter: Option<u64>,
    waiting: bool,
    marker: std::marker::PhantomData<fn(Request)>,
}

impl<S, Request> SteerReadiness<S, Request>
where
    S: Service<Request>,
{
    fn dispatched(&mut self) {
        self.waiting = false;
        self.waiters.lock().owners -= 1;
    }
}

impl<S, Request> Drop for SteerReadiness<S, Request>
where
    S: Service<Request>,
{
    fn drop(&mut self) {
        let _release_scope = super::service::ReadinessReleaseScope::new();
        let waiters = Arc::clone(&self.waiters);
        let waiter = self.waiter;
        let retire_waiter = super::ReadinessRelease::new(move || {
            ReadinessWaiters::release(&waiters, waiter);
        });
        let release = if self.waiting {
            let mut service = self.service.lock();
            let last = {
                let mut waiters = self.waiters.lock();
                waiters.owners -= 1;
                waiters.owners == 0
            };
            last.then(|| service.release_readiness())
        } else {
            None
        };
        drop(release);
        // Never wake peers while holding either coordinator lock.
        drop(retire_waiter);
    }
}

impl<S, Request> fmt::Debug for SteerFuture<S, Request>
where
    S: Service<Request>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SteerFuture").finish_non_exhaustive()
    }
}

impl<S, Request> Future for SteerFuture<S, Request>
where
    S: Service<Request>,
    S::Future: Unpin,
    Request: Unpin,
{
    type Output = Result<S::Response, SteerError<S::Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            let state = std::mem::replace(&mut this.state, SteerState::Done);
            match state {
                SteerState::InvalidRoute {
                    index,
                    service_count,
                } => {
                    return Poll::Ready(Err(SteerError::InvalidRoute {
                        index,
                        service_count,
                    }));
                }
                SteerState::PollReady {
                    service,
                    waiters,
                    mut readiness,
                    mut request,
                } => {
                    let _release_scope = super::service::ReadinessReleaseScope::new();
                    let mut inner = service.lock();
                    match inner.poll_ready(cx) {
                        Poll::Pending => {
                            drop(inner);
                            ReadinessWaiters::register(&waiters, &mut readiness.waiter, cx.waker());
                            this.state = SteerState::PollReady {
                                service,
                                waiters,
                                readiness,
                                request,
                            };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(err)) => {
                            drop(inner);
                            drop(readiness);
                            return Poll::Ready(Err(SteerError::Inner(err)));
                        }
                        Poll::Ready(Ok(())) => {
                            let Some(req) = request.take() else {
                                drop(inner);
                                drop(readiness);
                                return Poll::Ready(Err(SteerError::PolledAfterCompletion));
                            };
                            let future = inner.call(req);
                            readiness.dispatched();
                            drop(inner);
                            drop(readiness);
                            this.state = SteerState::Calling { future };
                        }
                    }
                }
                SteerState::Calling { mut future } => match Pin::new(&mut future).poll(cx) {
                    Poll::Pending => {
                        this.state = SteerState::Calling { future };
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(response)) => {
                        return Poll::Ready(Ok(response));
                    }
                    Poll::Ready(Err(err)) => {
                        return Poll::Ready(Err(SteerError::Inner(err)));
                    }
                },
                SteerState::Done => {
                    return Poll::Ready(Err(SteerError::PolledAfterCompletion));
                }
            }
        }
    }
}

impl<S, F, Request> Service<Request> for Steer<S, F>
where
    S: Service<Request>,
    S::Future: Unpin,
    F: Fn(&Request) -> usize,
    Request: Unpin,
{
    type Response = S::Response;
    type Error = SteerError<S::Error>;
    type Future = SteerFuture<S, Request>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Route selection is request-dependent. Polling every backend here can
        // strand reservations on services that never receive the request.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let idx = (self.picker)(&req);
        if idx >= self.services.len() {
            return SteerFuture::invalid_route(idx, self.services.len());
        }
        SteerFuture::new(
            Arc::clone(&self.services[idx]),
            Arc::clone(&self.waiters[idx]),
            req,
        )
    }
}

// ─── SteerError ───────────────────────────────────────────────────────────

/// Error wrapping for steer operations.
#[derive(Debug)]
pub enum SteerError<E> {
    /// Inner service error.
    Inner(E),
    /// The picker returned an index outside the available service range.
    InvalidRoute {
        /// The out-of-range index chosen by the picker.
        index: usize,
        /// The number of available services.
        service_count: usize,
    },
    /// No services available.
    NoServices,
    /// The steer future was polled after it had already completed.
    PolledAfterCompletion,
}

impl<E: fmt::Display> fmt::Display for SteerError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inner(e) => write!(f, "steer service error: {e}"),
            Self::InvalidRoute {
                index,
                service_count,
            } => write!(
                f,
                "steer picker selected invalid service index {index} (service count {service_count})"
            ),
            Self::NoServices => write!(f, "no services available"),
            Self::PolledAfterCompletion => write!(f, "steer future polled after completion"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SteerError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inner(e) => Some(e),
            Self::InvalidRoute { .. } | Self::NoServices | Self::PolledAfterCompletion => None,
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "steer_inline_tests.rs"]
mod tests;
