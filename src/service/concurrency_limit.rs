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
    #[must_use]
    pub fn max_concurrency(&self) -> usize {
        self.semaphore.max_permits()
    }

    /// Returns the number of available slots.
    #[must_use]
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
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

    /// Consumes the limiter, returning the inner service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// Error returned when concurrency limit operations fail.
#[derive(Debug)]
pub enum ConcurrencyLimitError<E> {
    /// Failed to acquire a permit (should not happen in normal operation).
    LimitExceeded,
    /// The inner service returned an error.
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for ConcurrencyLimitError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LimitExceeded => write!(f, "concurrency limit exceeded"),
            Self::Inner(e) => write!(f, "inner service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ConcurrencyLimitError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LimitExceeded => None,
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
    type Future = ConcurrencyLimitFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self
            .inner
            .poll_ready(cx)
            .map_err(ConcurrencyLimitError::Inner)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {}
        }

        loop {
            match &mut self.state {
                State::Idle => {
                    // Try to acquire synchronously first
                    if let Ok(permit) =
                        OwnedSemaphorePermit::try_acquire(self.semaphore.clone(), 1)
                    {
                        self.state = State::Ready(permit);
                        return Poll::Ready(Ok(()));
                    }

                    // Fallback to async acquisition
                    let cx = Cx::current().expect("ConcurrencyLimit must run within a runtime context");
                    let future = OwnedSemaphorePermit::acquire(self.semaphore.clone(), &cx, 1);
                    self.state = State::Acquiring(Box::pin(future));
                }
                State::Acquiring(future) => match future.as_mut().poll(cx) {
                    Poll::Ready(Ok(permit)) => {
                        self.state = State::Ready(permit);
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(_)) => {
                        // Reset state and return error (e.g. closed/cancelled)
                        self.state = State::Idle;
                        return Poll::Ready(Err(ConcurrencyLimitError::LimitExceeded));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                State::Ready(_) => return Poll::Ready(Ok(())),
            }
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        // Take the permit that was acquired in poll_ready
        let permit = match std::mem::replace(&mut self.state, State::Idle) {
            State::Ready(permit) => permit,
            _ => panic!("poll_ready must be called before call"),
        };

        ConcurrencyLimitFuture::new(self.inner.call(req), permit)
    }
}

/// Future returned by [`ConcurrencyLimit`] service.
///
/// This future holds a permit for the duration of the inner service call.
/// When the future completes (or is dropped), the permit is released.
pub struct ConcurrencyLimitFuture<F> {
    inner: F,
    /// The permit is held until the future completes or is dropped.
    _permit: OwnedSemaphorePermit,
}

impl<F> ConcurrencyLimitFuture<F> {
    /// Creates a new concurrency-limited future.
    #[must_use]
    pub fn new(inner: F, permit: OwnedSemaphorePermit) -> Self {
        Self {
            inner,
            _permit: permit,
        }
    }
}

impl<F, T, E> Future for ConcurrencyLimitFuture<F>
where
    F: Future<Output = Result<T, E>> + Unpin,
{
    type Output = Result<T, ConcurrencyLimitError<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll(cx) {
            Poll::Ready(Ok(response)) => Poll::Ready(Ok(response)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(ConcurrencyLimitError::Inner(e))),
            Poll::Pending => Poll::Pending,
        }
        // Permit is automatically released when future is dropped
    }
}

impl<F: std::fmt::Debug> std::fmt::Debug for ConcurrencyLimitFuture<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConcurrencyLimitFuture")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::ready;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Wake, Waker};

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

    // A service that tracks concurrency
    struct TrackingService {
        current: Arc<AtomicUsize>,
        max_seen: Arc<AtomicUsize>,
    }

    impl TrackingService {
        fn new() -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
            let current = Arc::new(AtomicUsize::new(0));
            let max_seen = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    current: current.clone(),
                    max_seen: max_seen.clone(),
                },
                current,
                max_seen,
            )
        }
    }

    impl Service<()> for TrackingService {
        type Response = ();
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<(), std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            let prev = self.current.fetch_add(1, Ordering::SeqCst);
            let current = prev + 1;
            // Update max if this is a new high
            self.max_seen.fetch_max(current, Ordering::SeqCst);
            // In a real scenario, work would happen here
            self.current.fetch_sub(1, Ordering::SeqCst);
            ready(Ok(()))
        }
    }

    // Simple echo service
    struct EchoService;

    impl Service<i32> for EchoService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: i32) -> Self::Future {
            ready(Ok(req))
        }
    }

    struct ToggleReadyService {
        ready: Arc<AtomicBool>,
        error: bool,
    }

    impl ToggleReadyService {
        fn new(ready: Arc<AtomicBool>, error: bool) -> Self {
            Self { ready, error }
        }
    }

    impl Service<()> for ToggleReadyService {
        type Response = ();
        type Error = &'static str;
        type Future = std::future::Ready<Result<(), &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.error {
                Poll::Ready(Err("inner error"))
            } else if self.ready.load(Ordering::SeqCst) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            ready(Ok(()))
        }
    }

    #[test]
    fn layer_creates_service() {
        init_test("layer_creates_service");
        let layer = ConcurrencyLimitLayer::new(5);
        let max = layer.max_concurrency();
        crate::assert_with_log!(max == 5, "max", 5, max);
        let _svc: ConcurrencyLimit<EchoService> = layer.layer(EchoService);
        crate::test_complete!("layer_creates_service");
    }

    #[test]
    fn service_accessors() {
        init_test("service_accessors");
        let semaphore = Arc::new(Semaphore::new(10));
        let svc = ConcurrencyLimit::new(EchoService, semaphore);
        let max = svc.max_concurrency();
        crate::assert_with_log!(max == 10, "max", 10, max);
        let available = svc.available();
        crate::assert_with_log!(available == 10, "available", 10, available);
        let _ = svc.inner();
        crate::test_complete!("service_accessors");
    }

    #[test]
    fn poll_ready_acquires_permit() {
        init_test("poll_ready_acquires_permit");
        let layer = ConcurrencyLimitLayer::new(2);
        let mut svc = layer.layer(EchoService);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Initially 2 available
        let available = svc.available();
        crate::assert_with_log!(available == 2, "available", 2, available);

        // poll_ready should acquire a permit
        let ready = svc.poll_ready(&mut cx);
        let ready_ok = matches!(ready, Poll::Ready(Ok(())));
        crate::assert_with_log!(ready_ok, "ready ok", true, ready_ok);
        let has_permit = svc.permit.is_some();
        crate::assert_with_log!(has_permit, "permit present", true, has_permit);
        let available = svc.available();
        crate::assert_with_log!(available == 1, "available", 1, available);
        crate::test_complete!("poll_ready_acquires_permit");
    }

    #[test]
    fn call_consumes_permit() {
        init_test("call_consumes_permit");
        let layer = ConcurrencyLimitLayer::new(2);
        let mut svc = layer.layer(EchoService);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Acquire permit
        let _ = svc.poll_ready(&mut cx);
        let has_permit = svc.permit.is_some();
        crate::assert_with_log!(has_permit, "permit present", true, has_permit);

        // Call consumes permit
        let _future = svc.call(42);
        let has_permit = svc.permit.is_some();
        crate::assert_with_log!(!has_permit, "permit cleared", false, has_permit);
        crate::test_complete!("call_consumes_permit");
    }

    #[test]
    fn future_releases_permit_on_completion() {
        init_test("future_releases_permit_on_completion");
        let layer = ConcurrencyLimitLayer::new(2);
        let mut svc = layer.layer(EchoService);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Acquire and call
        let _ = svc.poll_ready(&mut cx);
        let available = svc.available();
        crate::assert_with_log!(available == 1, "available", 1, available);
        let mut future = svc.call(42);

        // Future completes
        let result = Pin::new(&mut future).poll(&mut cx);
        let ok = matches!(result, Poll::Ready(Ok(42)));
        crate::assert_with_log!(ok, "result ok", true, ok);

        // Drop future to release permit
        drop(future);
        let available = svc.available();
        crate::assert_with_log!(available == 2, "available", 2, available);
        crate::test_complete!("future_releases_permit_on_completion");
    }

    #[test]
    fn limit_enforced() {
        init_test("limit_enforced");
        let layer = ConcurrencyLimitLayer::new(1);
        let mut svc1 = layer.layer(EchoService);
        let mut svc2 = layer.layer(EchoService);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // First service acquires permit
        let ready1 = svc1.poll_ready(&mut cx);
        let ok = matches!(ready1, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready1 ok", true, ok);

        // Second service should be pending (no permits)
        let ready2 = svc2.poll_ready(&mut cx);
        let pending = ready2.is_pending();
        crate::assert_with_log!(pending, "ready2 pending", true, pending);
        crate::test_complete!("limit_enforced");
    }

    #[test]
    fn inner_pending_does_not_consume_permit() {
        init_test("inner_pending_does_not_consume_permit");
        let ready = Arc::new(AtomicBool::new(false));
        let layer = ConcurrencyLimitLayer::new(1);
        let mut svc = layer.layer(ToggleReadyService::new(ready.clone(), false));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = svc.poll_ready(&mut cx);
        crate::assert_with_log!(first.is_pending(), "pending", true, first.is_pending());
        let available = svc.available();
        crate::assert_with_log!(available == 1, "available", 1, available);

        ready.store(true, Ordering::SeqCst);
        let second = svc.poll_ready(&mut cx);
        let ok = matches!(second, Poll::Ready(Ok(())));
        crate::assert_with_log!(ok, "ready ok", true, ok);
        let available = svc.available();
        crate::assert_with_log!(available == 0, "available", 0, available);
        crate::test_complete!("inner_pending_does_not_consume_permit");
    }

    #[test]
    fn inner_error_does_not_consume_permit() {
        init_test("inner_error_does_not_consume_permit");
        let ready = Arc::new(AtomicBool::new(true));
        let layer = ConcurrencyLimitLayer::new(1);
        let mut svc = layer.layer(ToggleReadyService::new(ready, true));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = svc.poll_ready(&mut cx);
        let err = matches!(result, Poll::Ready(Err(ConcurrencyLimitError::Inner(_))));
        crate::assert_with_log!(err, "inner err", true, err);
        let available = svc.available();
        crate::assert_with_log!(available == 1, "available", 1, available);
        crate::test_complete!("inner_error_does_not_consume_permit");
    }

    #[test]
    fn error_display() {
        init_test("error_display");
        let err: ConcurrencyLimitError<&str> = ConcurrencyLimitError::LimitExceeded;
        let display = format!("{err}");
        let has_limit = display.contains("limit exceeded");
        crate::assert_with_log!(has_limit, "limit exceeded", true, has_limit);

        let err: ConcurrencyLimitError<&str> = ConcurrencyLimitError::Inner("inner error");
        let display = format!("{err}");
        let has_inner = display.contains("inner service error");
        crate::assert_with_log!(has_inner, "inner error", true, has_inner);
        crate::test_complete!("error_display");
    }
}
