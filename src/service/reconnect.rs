//! Reconnect middleware layer.
//!
//! The [`ReconnectLayer`] wraps a service that may fail, automatically
//! recreating it from a [`MakeService`] factory when the inner service
//! becomes unavailable.
//!
//! This is useful for database connections, RPC channels, and other
//! stateful services that can drop and need re-establishment.

use super::{Layer, Service};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

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
}

impl<E: fmt::Display, M: fmt::Display> fmt::Display for ReconnectError<E, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inner(e) => write!(f, "service error: {e}"),
            Self::Connect(e) => write!(f, "reconnect failed: {e}"),
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
        }
    }
}

// ─── Reconnect service ────────────────────────────────────────────────────

/// A service wrapper that recreates the inner service on failure.
///
/// When `poll_ready` detects that the inner service is unavailable,
/// or when a call fails and the service is marked as needing reconnection,
/// a new service instance is created from the maker.
pub struct Reconnect<M: MakeService> {
    maker: M,
    inner: Option<M::Service>,
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
                self.inner = Some(svc);
                self.successes += 1;
                Ok(())
            }
            Err(e) => {
                self.inner = None;
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
        self.inner = None;
    }
}

impl<M: MakeService> fmt::Debug for Reconnect<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reconnect")
            .field("connected", &self.inner.is_some())
            .field("successes", &self.successes)
            .field("failures", &self.failures)
            .field("maker", &self.maker)
            .finish()
    }
}

impl<M, Request> Service<Request> for Reconnect<M>
where
    M: MakeService,
    M::Service: Service<Request> + Unpin,
    <M::Service as Service<Request>>::Future: Unpin,
{
    type Response = <M::Service as Service<Request>>::Response;
    type Error = ReconnectError<<M::Service as Service<Request>>::Error, M::Error>;
    type Future = ReconnectFuture<<M::Service as Service<Request>>::Future, M::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Ensure we have a connection.
        if self.inner.is_none() {
            self.reconnect().map_err(ReconnectError::Connect)?;
        }

        self.inner.as_mut().map_or(Poll::Pending, |svc| {
            svc.poll_ready(cx).map_err(ReconnectError::Inner)
        })
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let fut = self
            .inner
            .as_mut()
            .expect("poll_ready must be called before call")
            .call(req);
        ReconnectFuture {
            inner: fut,
            _maker_error: std::marker::PhantomData,
        }
    }
}

/// Future returned by [`Reconnect`].
pub struct ReconnectFuture<F, ME> {
    inner: F,
    _maker_error: std::marker::PhantomData<fn() -> ME>,
}

impl<F, ME> fmt::Debug for ReconnectFuture<F, ME> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReconnectFuture").finish()
    }
}

impl<F, T, E, ME> Future for ReconnectFuture<F, ME>
where
    F: Future<Output = Result<T, E>> + Unpin,
{
    type Output = Result<T, ReconnectError<E, ME>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner)
            .poll(cx)
            .map_err(ReconnectError::Inner)
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

    // Mock maker and service for testing.
    #[derive(Debug, Clone)]
    struct MockMaker {
        fail_count: std::cell::Cell<u32>,
    }

    impl MockMaker {
        fn new() -> Self {
            Self {
                fail_count: std::cell::Cell::new(0),
            }
        }

        fn failing(n: u32) -> Self {
            Self {
                fail_count: std::cell::Cell::new(n),
            }
        }
    }

    #[derive(Debug)]
    struct MockMakerError;

    impl fmt::Display for MockMakerError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "mock maker error")
        }
    }

    impl std::error::Error for MockMakerError {}

    #[derive(Debug)]
    struct MockSvc {
        id: u32,
    }

    impl MakeService for MockMaker {
        type Service = MockSvc;
        type Error = MockMakerError;

        fn make_service(&self) -> Result<MockSvc, MockMakerError> {
            let remaining = self.fail_count.get();
            if remaining > 0 {
                self.fail_count.set(remaining - 1);
                Err(MockMakerError)
            } else {
                Ok(MockSvc { id: 42 })
            }
        }
    }

    // ================================================================
    // MakeService / MockMaker
    // ================================================================

    #[test]
    fn mock_maker_creates_service() {
        init_test("mock_maker_creates_service");
        let maker = MockMaker::new();
        let svc = maker.make_service().unwrap();
        assert_eq!(svc.id, 42);
        crate::test_complete!("mock_maker_creates_service");
    }

    #[test]
    fn mock_maker_fails_then_succeeds() {
        init_test("mock_maker_fails_then_succeeds");
        let maker = MockMaker::failing(2);
        assert!(maker.make_service().is_err());
        assert!(maker.make_service().is_err());
        assert!(maker.make_service().is_ok());
        crate::test_complete!("mock_maker_fails_then_succeeds");
    }

    // ================================================================
    // Reconnect
    // ================================================================

    #[test]
    fn reconnect_new() {
        init_test("reconnect_new");
        let maker = MockMaker::new();
        let svc = maker.make_service().unwrap();
        let rc = Reconnect::new(maker, svc);
        assert!(rc.is_connected());
        assert_eq!(rc.reconnect_count(), 0);
        assert_eq!(rc.error_count(), 0);
        crate::test_complete!("reconnect_new");
    }

    #[test]
    fn reconnect_lazy() {
        init_test("reconnect_lazy");
        let maker = MockMaker::new();
        let rc = Reconnect::lazy(maker);
        assert!(!rc.is_connected());
        crate::test_complete!("reconnect_lazy");
    }

    #[test]
    fn reconnect_manual() {
        init_test("reconnect_manual");
        let maker = MockMaker::new();
        let mut rc = Reconnect::lazy(maker);
        assert!(!rc.is_connected());
        rc.reconnect().unwrap();
        assert!(rc.is_connected());
        assert_eq!(rc.reconnect_count(), 1);
        crate::test_complete!("reconnect_manual");
    }

    #[test]
    fn reconnect_after_disconnect() {
        init_test("reconnect_after_disconnect");
        let maker = MockMaker::new();
        let svc = maker.make_service().unwrap();
        let mut rc = Reconnect::new(maker, svc);
        assert!(rc.is_connected());
        rc.disconnect();
        assert!(!rc.is_connected());
        rc.reconnect().unwrap();
        assert!(rc.is_connected());
        assert_eq!(rc.reconnect_count(), 1);
        crate::test_complete!("reconnect_after_disconnect");
    }

    #[test]
    fn reconnect_failure_tracked() {
        init_test("reconnect_failure_tracked");
        let maker = MockMaker::failing(1);
        let mut rc = Reconnect::lazy(maker);
        assert!(rc.reconnect().is_err());
        assert_eq!(rc.error_count(), 1);
        assert!(!rc.is_connected());
        // Second attempt succeeds.
        rc.reconnect().unwrap();
        assert!(rc.is_connected());
        assert_eq!(rc.reconnect_count(), 1);
        crate::test_complete!("reconnect_failure_tracked");
    }

    #[test]
    fn reconnect_inner_ref() {
        let maker = MockMaker::new();
        let svc = maker.make_service().unwrap();
        let rc = Reconnect::new(maker, svc);
        assert!(rc.inner().is_some());
        assert_eq!(rc.inner().unwrap().id, 42);
    }

    #[test]
    fn reconnect_inner_mut() {
        let maker = MockMaker::new();
        let svc = maker.make_service().unwrap();
        let mut rc = Reconnect::new(maker, svc);
        assert!(rc.inner_mut().is_some());
    }

    #[test]
    fn reconnect_maker_ref() {
        let maker = MockMaker::new();
        let svc = maker.make_service().unwrap();
        let rc = Reconnect::new(maker, svc);
        let _ = rc.maker();
    }

    #[test]
    fn reconnect_debug() {
        let maker = MockMaker::new();
        let svc = maker.make_service().unwrap();
        let rc = Reconnect::new(maker, svc);
        let dbg = format!("{rc:?}");
        assert!(dbg.contains("Reconnect"));
        assert!(dbg.contains("connected: true"));
    }

    // ================================================================
    // ReconnectError
    // ================================================================

    #[test]
    fn reconnect_error_inner_display() {
        let err: ReconnectError<std::io::Error, std::io::Error> =
            ReconnectError::Inner(std::io::Error::other("fail"));
        assert!(format!("{err}").contains("service error"));
    }

    #[test]
    fn reconnect_error_connect_display() {
        let err: ReconnectError<std::io::Error, std::io::Error> =
            ReconnectError::Connect(std::io::Error::other("fail"));
        assert!(format!("{err}").contains("reconnect failed"));
    }

    #[test]
    fn reconnect_error_source() {
        use std::error::Error;
        let err: ReconnectError<std::io::Error, std::io::Error> =
            ReconnectError::Inner(std::io::Error::other("fail"));
        assert!(err.source().is_some());
    }

    #[test]
    fn reconnect_error_debug() {
        let err: ReconnectError<std::io::Error, std::io::Error> =
            ReconnectError::Inner(std::io::Error::other("fail"));
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Inner"));
    }

    // ================================================================
    // ReconnectLayer
    // ================================================================

    #[test]
    fn reconnect_layer_new() {
        let layer = ReconnectLayer::new(MockMaker::new());
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("ReconnectLayer"));
    }

    #[test]
    fn reconnect_layer_applies() {
        init_test("reconnect_layer_applies");
        let layer = ReconnectLayer::new(MockMaker::new());
        let initial = MockSvc { id: 1 };
        let svc = layer.layer(initial);
        assert!(svc.is_connected());
        assert_eq!(svc.inner().unwrap().id, 1);
        crate::test_complete!("reconnect_layer_applies");
    }

    // ================================================================
    // ReconnectFuture
    // ================================================================

    #[test]
    fn reconnect_future_debug() {
        let fut: ReconnectFuture<_, std::io::Error> = ReconnectFuture {
            inner: std::future::ready(Ok::<i32, std::io::Error>(42)),
            _maker_error: std::marker::PhantomData,
        };
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("ReconnectFuture"));
    }
}
