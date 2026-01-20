//! Load shedding middleware layer.
//!
//! The [`LoadShedLayer`] wraps a service and sheds load when the inner service
//! signals backpressure. If the inner service returns `Poll::Pending` from
//! `poll_ready`, the load shedder marks itself as overloaded and immediately
//! rejects subsequent requests until the inner service becomes ready again.

use super::{Layer, Service};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

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
#[derive(Debug, Clone)]
pub struct LoadShed<S> {
    inner: S,
    overloaded: bool,
}

impl<S> LoadShed<S> {
    /// Creates a new load shedding service.
    #[must_use]
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            overloaded: false,
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
    /// The service is overloaded and the request was shed.
    Overloaded(Overloaded),
    /// The inner service returned an error.
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for LoadShedError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overloaded(e) => write!(f, "{e}"),
            Self::Inner(e) => write!(f, "inner service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for LoadShedError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
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

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.inner.poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                self.overloaded = false;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.overloaded = false;
                Poll::Ready(Err(LoadShedError::Inner(e)))
            }
            Poll::Pending => {
                // Inner service is not ready; mark as overloaded but return Ready
                // so the caller can call us immediately (and we'll shed)
                self.overloaded = true;
                Poll::Ready(Ok(()))
            }
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        if self.overloaded {
            // Reset overloaded flag for next check
            self.overloaded = false;
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
    /// Request was shed due to overload.
    Overloaded,
    /// Request is being processed by the inner service.
    Inner(F),
    /// Future has completed.
    Done,
}

impl<F> LoadShedFuture<F> {
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

        match &mut this.state {
            LoadShedState::Overloaded => {
                this.state = LoadShedState::Done;
                Poll::Ready(Err(LoadShedError::Overloaded(Overloaded::new())))
            }
            LoadShedState::Inner(future) => {
                let result = Pin::new(future).poll(cx);
                if result.is_ready() {
                    this.state = LoadShedState::Done;
                }
                match result {
                    Poll::Ready(Ok(response)) => Poll::Ready(Ok(response)),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(LoadShedError::Inner(e))),
                    Poll::Pending => Poll::Pending,
                }
            }
            LoadShedState::Done => {
                panic!("LoadShedFuture polled after completion")
            }
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
        let overloaded = matches!(
            result,
            Poll::Ready(Err(LoadShedError::Overloaded(_)))
        );
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

        // Overloaded flag should be cleared
        let overloaded = svc.is_overloaded();
        crate::assert_with_log!(!overloaded, "overload cleared", false, overloaded);
        crate::test_complete!("load_shed_recovers_after_shed");
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
}
