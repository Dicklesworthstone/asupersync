//! Reconnect middleware layer.
//!
//! The [`ReconnectLayer`] wraps a service that may fail, automatically
//! recreating it from a [`MakeService`] factory when the inner service
//! becomes unavailable.
//!
//! This is useful for database connections, RPC channels, and other
//! stateful services that can drop and need re-establishment.

use super::{Layer, Service};
use crate::sync::atomic::{AtomicBool, Ordering};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

// ─── MakeService trait ────────────────────────────────────────────────────

/// Factory for creating service instances.
///
/// When the inner service reports an error or becomes unready, the
/// [`Reconnect`] middleware calls this factory to obtain a fresh instance.
pub trait MakeService: fmt::Debug {
    /// The service type produced by this factory.
    type Service;
    /// Error type from creating a service.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Create a new service instance.
    fn make_service(&self) -> Result<Self::Service, Self::Error>;
}

// ─── ReconnectLayer ───────────────────────────────────────────────────────

/// Layer that wraps a service in a [`Reconnect`] wrapper.
#[derive(Debug, Clone)]
pub struct ReconnectLayer<M> {
    maker: M,
}

impl<M> ReconnectLayer<M> {
    /// Create a new reconnect layer with the given maker.
    #[must_use]
    pub fn new(maker: M) -> Self {
        Self { maker }
    }
}

impl<S, M> Layer<S> for ReconnectLayer<M>
where
    M: MakeService<Service = S> + Clone,
{
    type Service = Reconnect<M>;

    fn layer(&self, inner: S) -> Self::Service {
        Reconnect::new(self.maker.clone(), inner)
    }
}

// ─── ReconnectError ───────────────────────────────────────────────────────

/// Error from the reconnect middleware.
#[derive(Debug)]
pub enum ReconnectError<E, M> {
    /// The inner service returned an error.
    Inner(E),
    /// Failed to create a new service instance.
    Connect(M),
    /// The caller attempted `call()` without a preceding successful `poll_ready()`.
    NotReady,
    /// The reconnect future was polled after it had already completed.
    PolledAfterCompletion,
}

impl<E: fmt::Display, M: fmt::Display> fmt::Display for ReconnectError<E, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inner(e) => write!(f, "service error: {e}"),
            Self::Connect(e) => write!(f, "reconnect failed: {e}"),
            Self::NotReady => write!(f, "service not ready; poll_ready required before call"),
            Self::PolledAfterCompletion => {
                write!(f, "reconnect future polled after completion")
            }
        }
    }
}

impl<E: std::error::Error + 'static, M: std::error::Error + 'static> std::error::Error
    for ReconnectError<E, M>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inner(e) => Some(e),
            Self::Connect(e) => Some(e),
            Self::NotReady | Self::PolledAfterCompletion => None,
        }
    }
}

// ─── Reconnect service ────────────────────────────────────────────────────

/// A service wrapper that recreates the inner service on failure.
///
/// When `poll_ready` detects that the inner service is unavailable,
/// or when a call fails and the service is marked as needing reconnection,
/// a new service instance is created from the maker.
///
/// Each successful `poll_ready` authorizes exactly one subsequent `call`.
/// A failure from an outstanding call invalidates that authorization and wakes
/// any pending readiness wait. Failures belong to the service instance that
/// produced the call; they cannot invalidate a replacement instance.
pub struct Reconnect<M: MakeService> {
    maker: M,
    inner: Option<M::Service>,
    signal: Arc<ReconnectSignal>,
    // Diagnostic only; generation identity is the retained signal allocation.
    service_epoch: u64,
    ready_observed: bool,
    /// Number of successful reconnections.
    successes: u64,
    /// Number of failed reconnection attempts.
    failures: u64,
}

impl<M: MakeService> Reconnect<M> {
    /// Create a new reconnect wrapper with an initial service.
    #[must_use]
    pub fn new(maker: M, initial: M::Service) -> Self {
        Self {
            maker,
            inner: Some(initial),
            signal: Arc::new(ReconnectSignal::new()),
            service_epoch: 1,
            ready_observed: false,
            successes: 0,
            failures: 0,
        }
    }

    /// Create a new reconnect wrapper, lazily connecting.
    #[must_use]
    pub fn lazy(maker: M) -> Self {
        Self {
            maker,
            inner: None,
            signal: Arc::new(ReconnectSignal::new()),
            service_epoch: 0,
            ready_observed: false,
            successes: 0,
            failures: 0,
        }
    }

    /// Attempt to reconnect, replacing the inner service.
    ///
    /// Returns `Ok(())` if reconnection succeeded, or `Err` if the maker failed.
    pub fn reconnect(&mut self) -> Result<(), M::Error> {
        match self.maker.make_service() {
            Ok(svc) => {
                let release = self.replace_signal();
                let previous = self.inner.replace(svc);
                self.service_epoch = self.service_epoch.wrapping_add(1);
                self.ready_observed = false;
                self.successes += 1;
                drop(previous);
                drop(release);
                Ok(())
            }
            Err(e) => {
                self.invalidate_inner();
                self.failures += 1;
                Err(e)
            }
        }
    }

    /// Check if the inner service is connected.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.inner.is_some()
    }

    /// Get the number of successful reconnections.
    #[must_use]
    pub fn reconnect_count(&self) -> u64 {
        self.successes
    }

    /// Get the number of failed reconnection attempts.
    #[must_use]
    pub fn error_count(&self) -> u64 {
        self.failures
    }

    /// Get a reference to the inner service, if connected.
    #[must_use]
    pub fn inner(&self) -> Option<&M::Service> {
        self.inner.as_ref()
    }

    /// Get a mutable reference to the inner service, if connected.
    pub fn inner_mut(&mut self) -> Option<&mut M::Service> {
        self.inner.as_mut()
    }

    /// Get a reference to the maker.
    #[must_use]
    pub fn maker(&self) -> &M {
        &self.maker
    }

    /// Disconnect the inner service.
    pub fn disconnect(&mut self) {
        self.invalidate_inner();
    }

    fn replace_signal(&mut self) -> super::ReadinessRelease {
        let previous = std::mem::replace(&mut self.signal, Arc::new(ReconnectSignal::new()));
        previous.release_readiness()
    }

    fn invalidate_inner(&mut self) {
        let previous = self.inner.take();
        let release = self.replace_signal();
        self.ready_observed = false;
        if previous.is_some() {
            self.service_epoch = self.service_epoch.wrapping_add(1);
        }
        drop(previous);
        drop(release);
    }
}

impl<M: MakeService> Drop for Reconnect<M> {
    fn drop(&mut self) {
        // In-flight calls can retain the signal after the service is gone.
        // They must not retain the abandoned readiness task's waker as well.
        drop(self.signal.release_readiness());
    }
}

impl<M: MakeService> fmt::Debug for Reconnect<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reconnect")
            .field("connected", &self.inner.is_some())
            .field("reconnect_pending", &self.signal.failed())
            .field("service_epoch", &self.service_epoch)
            .field("ready_observed", &self.ready_observed)
            .field("successes", &self.successes)
            .field("failures", &self.failures)
            .field("maker", &self.maker)
            .finish()
    }
}

/// One retained identity per service instance. A completed call can only
/// signal its own instance, even if replacement races with its completion.
struct ReconnectSignal {
    failed: AtomicBool,
    readiness: Mutex<Option<Waker>>,
}

impl ReconnectSignal {
    const fn new() -> Self {
        Self {
            failed: AtomicBool::new(false),
            readiness: Mutex::new(None),
        }
    }

    fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn register_readiness(&self, waker: &Waker) {
        let already_registered = self
            .readiness
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|registered| registered.will_wake(waker));
        if !already_registered {
            // RawWaker clone/drop callbacks must not run under the slot lock.
            let replacement = waker.clone();
            let previous = self
                .readiness
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .replace(replacement);
            if let Some(previous) = previous {
                drop(super::ReadinessRelease::new(move || drop(previous)));
            }
        }
        // A failure may have arrived before the waiter was installed. Pairing
        // this check with request_refresh's publication closes that lost wake.
        if self.failed() {
            self.wake_readiness();
        }
    }

    fn release_readiness(&self) -> super::ReadinessRelease {
        let waker = self
            .readiness
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        waker.map_or_else(super::ReadinessRelease::default, |waker| {
            super::ReadinessRelease::new(move || drop(waker))
        })
    }

    fn wake_readiness(&self) {
        let waker = self
            .readiness
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(waker) = waker {
            // Shared adapters may still hold their service mutex. Use their
            // existing cleanup scope to notify only after those locks retire.
            drop(super::ReadinessRelease::new(move || waker.wake()));
        }
    }

    fn request_refresh(&self) {
        self.failed.store(true, Ordering::Release);
        self.wake_readiness();
    }
}

struct RefreshPendingGuard<'a> {
    signal: &'a ReconnectSignal,
    armed: bool,
}

impl<'a> RefreshPendingGuard<'a> {
    fn new(signal: &'a ReconnectSignal) -> Self {
        Self {
            signal,
            armed: true,
        }
    }

    fn defuse(mut self) {
        self.armed = false;
    }
}

impl Drop for RefreshPendingGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.signal.request_refresh();
        }
    }
}

impl<M, Request> Service<Request> for Reconnect<M>
where
    M: MakeService,
    M::Service: Service<Request> + Unpin,
    <M::Service as Service<Request>>::Future: Unpin,
    <M::Service as Service<Request>>::Error: Unpin,
    M::Error: Unpin,
{
    type Response = <M::Service as Service<Request>>::Response;
    type Error = ReconnectError<<M::Service as Service<Request>>::Error, M::Error>;
    type Future = ReconnectFuture<
        <M::Service as Service<Request>>::Future,
        <M::Service as Service<Request>>::Error,
        M::Error,
    >;

    fn release_readiness(&mut self) -> super::ReadinessRelease {
        self.ready_observed = false;
        let outer = self.signal.release_readiness();
        let inner = self.inner.as_mut().map_or_else(
            super::ReadinessRelease::default,
            <M::Service as Service<Request>>::release_readiness,
        );
        super::ReadinessRelease::new(move || drop((inner, outer)))
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.signal.failed() {
            self.invalidate_inner();
        }

        // Ensure we have a connection.
        if self.inner.is_none() {
            if let Err(err) = self.reconnect() {
                self.ready_observed = false;
                return Poll::Ready(Err(ReconnectError::Connect(err)));
            }
        }

        let svc = self
            .inner
            .as_mut()
            .expect("inner must be Some after successful reconnect");
        match svc.poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                if self.signal.failed() {
                    // A concurrent call failed while the inner readiness poll
                    // ran. Relinquish its reservation and retry on a fresh poll.
                    self.ready_observed = false;
                    drop(<M::Service as Service<Request>>::release_readiness(svc));
                    self.signal.register_readiness(cx.waker());
                    return Poll::Pending;
                }
                self.ready_observed = true;
                drop(self.signal.release_readiness());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                // Inner service is broken — drop it to trigger reconnection
                // on the next poll_ready call.
                self.invalidate_inner();
                Poll::Ready(Err(ReconnectError::Inner(e)))
            }
            Poll::Pending => {
                self.ready_observed = false;
                self.signal.register_readiness(cx.waker());
                Poll::Pending
            }
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        if !std::mem::replace(&mut self.ready_observed, false) {
            return ReconnectFuture::error(ReconnectError::NotReady);
        }

        if self.signal.failed() {
            // Readiness is a reservation, not a lease on a failed connection.
            // Do not dispatch a new request after an earlier call invalidated it.
            let release = <Self as Service<Request>>::release_readiness(self);
            self.invalidate_inner();
            drop(release);
            return ReconnectFuture::error(ReconnectError::NotReady);
        }

        let Some(inner) = self.inner.as_mut() else {
            return ReconnectFuture::error(ReconnectError::NotReady);
        };

        let guard = RefreshPendingGuard::new(&self.signal);
        let fut = inner.call(req);
        guard.defuse();
        ReconnectFuture::inner(fut, Arc::clone(&self.signal))
    }
}

/// Future returned by [`Reconnect`].
pub struct ReconnectFuture<F, E, ME> {
    state: ReconnectFutureState<F, E, ME>,
}

enum ReconnectFutureState<F, E, ME> {
    Inner {
        future: F,
        signal: Arc<ReconnectSignal>,
    },
    Error(ReconnectError<E, ME>),
    Done,
}

impl<F, E, ME> ReconnectFuture<F, E, ME> {
    fn inner(future: F, signal: Arc<ReconnectSignal>) -> Self {
        Self {
            state: ReconnectFutureState::Inner { future, signal },
        }
    }

    fn error(error: ReconnectError<E, ME>) -> Self {
        Self {
            state: ReconnectFutureState::Error(error),
        }
    }
}

impl<F, E, ME> fmt::Debug for ReconnectFuture<F, E, ME> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReconnectFuture").finish()
    }
}

impl<F, T, E, ME> Future for ReconnectFuture<F, E, ME>
where
    F: Future<Output = Result<T, E>> + Unpin,
    E: Unpin,
    ME: Unpin,
{
    type Output = Result<T, ReconnectError<E, ME>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let state = std::mem::replace(&mut this.state, ReconnectFutureState::Done);

        match state {
            ReconnectFutureState::Inner { mut future, signal } => {
                let guard = RefreshPendingGuard::new(&signal);
                match Pin::new(&mut future).poll(cx) {
                    Poll::Ready(Ok(value)) => {
                        guard.defuse();
                        Poll::Ready(Ok(value))
                    }
                    Poll::Ready(Err(error)) => {
                        // Let the guard drop naturally (armed) to trigger reconnect.
                        drop(guard);
                        Poll::Ready(Err(ReconnectError::Inner(error)))
                    }
                    Poll::Pending => {
                        guard.defuse();
                        this.state = ReconnectFutureState::Inner { future, signal };
                        Poll::Pending
                    }
                }
            }
            ReconnectFutureState::Error(error) => Poll::Ready(Err(error)),
            ReconnectFutureState::Done => Poll::Ready(Err(ReconnectError::PolledAfterCompletion)),
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "reconnect_inline_tests.rs"]
mod tests;
