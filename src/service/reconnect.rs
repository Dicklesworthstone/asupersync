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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
pub struct Reconnect<M: MakeService> {
    maker: M,
    inner: Option<M::Service>,
    refresh_pending: Arc<AtomicBool>,
    service_epoch: Arc<AtomicU64>,
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
            refresh_pending: Arc::new(AtomicBool::new(false)),
            service_epoch: Arc::new(AtomicU64::new(1)),
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
            refresh_pending: Arc::new(AtomicBool::new(false)),
            service_epoch: Arc::new(AtomicU64::new(0)),
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
                self.inner = Some(svc);
                self.refresh_pending.store(false, Ordering::Release);
                self.service_epoch.fetch_add(1, Ordering::AcqRel);
                self.ready_observed = false;
                self.successes += 1;
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

    fn invalidate_inner(&mut self) {
        let had_inner = self.inner.take().is_some();
        self.refresh_pending.store(false, Ordering::Release);
        self.ready_observed = false;
        if had_inner {
            self.service_epoch.fetch_add(1, Ordering::AcqRel);
        }
    }
}

impl<M: MakeService> fmt::Debug for Reconnect<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reconnect")
            .field("connected", &self.inner.is_some())
            .field(
                "reconnect_pending",
                &self.refresh_pending.load(Ordering::Relaxed),
            )
            .field("service_epoch", &self.service_epoch.load(Ordering::Relaxed))
            .field("ready_observed", &self.ready_observed)
            .field("successes", &self.successes)
            .field("failures", &self.failures)
            .field("maker", &self.maker)
            .finish()
    }
}

struct RefreshPendingGuard<'a> {
    refresh_pending: &'a AtomicBool,
    service_epoch: &'a AtomicU64,
    call_epoch: u64,
    armed: bool,
}

impl<'a> RefreshPendingGuard<'a> {
    fn new(refresh_pending: &'a AtomicBool, service_epoch: &'a AtomicU64, call_epoch: u64) -> Self {
        Self {
            refresh_pending,
            service_epoch,
            call_epoch,
            armed: true,
        }
    }

    fn defuse(mut self) {
        self.armed = false;
    }
}

impl Drop for RefreshPendingGuard<'_> {
    fn drop(&mut self) {
        if self.armed && self.service_epoch.load(Ordering::Acquire) == self.call_epoch {
            self.refresh_pending.store(true, Ordering::Release);
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

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.refresh_pending.swap(false, Ordering::AcqRel) {
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
                self.ready_observed = true;
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
                Poll::Pending
            }
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        if !std::mem::replace(&mut self.ready_observed, false) {
            return ReconnectFuture::error(ReconnectError::NotReady);
        }

        let call_epoch = self.service_epoch.load(Ordering::Acquire);
        let Some(inner) = self.inner.as_mut() else {
            return ReconnectFuture::error(ReconnectError::NotReady);
        };

        let guard =
            RefreshPendingGuard::new(&self.refresh_pending, &self.service_epoch, call_epoch);
        let fut = inner.call(req);
        guard.defuse();
        ReconnectFuture::inner(
            fut,
            Arc::clone(&self.refresh_pending),
            Arc::clone(&self.service_epoch),
            call_epoch,
        )
    }
}

/// Future returned by [`Reconnect`].
pub struct ReconnectFuture<F, E, ME> {
    state: ReconnectFutureState<F, E, ME>,
}

enum ReconnectFutureState<F, E, ME> {
    Inner {
        future: F,
        refresh_pending: Arc<AtomicBool>,
        service_epoch: Arc<AtomicU64>,
        call_epoch: u64,
    },
    Error(ReconnectError<E, ME>),
    Done,
}

impl<F, E, ME> ReconnectFuture<F, E, ME> {
    fn inner(
        future: F,
        refresh_pending: Arc<AtomicBool>,
        service_epoch: Arc<AtomicU64>,
        call_epoch: u64,
    ) -> Self {
        Self {
            state: ReconnectFutureState::Inner {
                future,
                refresh_pending,
                service_epoch,
                call_epoch,
            },
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
            ReconnectFutureState::Inner {
                mut future,
                refresh_pending,
                service_epoch,
                call_epoch,
            } => {
                let guard = RefreshPendingGuard::new(&refresh_pending, &service_epoch, call_epoch);
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
                        this.state = ReconnectFutureState::Inner {
                            future,
                            refresh_pending,
                            service_epoch,
                            call_epoch,
                        };
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
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::task::{Wake, Waker};

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

    #[derive(Debug, Clone)]
    struct ReconnectingMaker {
        next_id: Arc<AtomicU32>,
    }

    impl ReconnectingMaker {
        fn new(next_id: u32) -> Self {
            Self {
                next_id: Arc::new(AtomicU32::new(next_id)),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct ReconnectingCallError;

    impl fmt::Display for ReconnectingCallError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "reconnecting call error")
        }
    }

    impl std::error::Error for ReconnectingCallError {}

    #[derive(Debug, Clone)]
    struct CountingReconnectSvc {
        id: u32,
        calls: Arc<AtomicU32>,
    }

    #[derive(Debug, Clone)]
    struct CountingReconnectMaker {
        next_id: Arc<AtomicU32>,
        calls: Arc<AtomicU32>,
    }

    impl CountingReconnectMaker {
        fn new(next_id: u32, calls: Arc<AtomicU32>) -> Self {
            Self {
                next_id: Arc::new(AtomicU32::new(next_id)),
                calls,
            }
        }
    }

    #[derive(Debug)]
    struct ReconnectingSvc {
        id: u32,
        fail_next_call: bool,
    }

    #[derive(Debug, Clone)]
    struct ManualCallController {
        state: Arc<parking_lot::Mutex<Option<Result<u32, ReconnectingCallError>>>>,
    }

    impl ManualCallController {
        fn new() -> Self {
            Self {
                state: Arc::new(parking_lot::Mutex::new(None)),
            }
        }

        fn fail(&self) {
            *self.state.lock() = Some(Err(ReconnectingCallError));
        }

        fn future(&self) -> ManualCallFuture {
            ManualCallFuture {
                state: Arc::clone(&self.state),
            }
        }
    }

    #[derive(Debug)]
    struct ManualCallFuture {
        state: Arc<parking_lot::Mutex<Option<Result<u32, ReconnectingCallError>>>>,
    }

    impl Future for ManualCallFuture {
        type Output = Result<u32, ReconnectingCallError>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            let mut state = self.state.lock();
            state.take().map_or(Poll::Pending, Poll::Ready)
        }
    }

    #[derive(Debug, Clone)]
    struct StaleFailureMaker {
        next_id: Arc<AtomicU32>,
    }

    impl StaleFailureMaker {
        fn new(next_id: u32) -> Self {
            Self {
                next_id: Arc::new(AtomicU32::new(next_id)),
            }
        }
    }

    #[derive(Debug)]
    struct StaleFailureSvc {
        id: u32,
        delayed_failure: ManualCallController,
    }

    impl MakeService for ReconnectingMaker {
        type Service = ReconnectingSvc;
        type Error = MockMakerError;

        fn make_service(&self) -> Result<Self::Service, Self::Error> {
            Ok(ReconnectingSvc {
                id: self.next_id.fetch_add(1, Ordering::SeqCst),
                fail_next_call: false,
            })
        }
    }

    impl Service<()> for ReconnectingSvc {
        type Response = u32;
        type Error = ReconnectingCallError;
        type Future = std::future::Ready<Result<u32, ReconnectingCallError>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            if self.fail_next_call {
                self.fail_next_call = false;
                std::future::ready(Err(ReconnectingCallError))
            } else {
                std::future::ready(Ok(self.id))
            }
        }
    }

    impl Service<()> for CountingReconnectSvc {
        type Response = u32;
        type Error = ReconnectingCallError;
        type Future = std::future::Ready<Result<u32, ReconnectingCallError>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(self.id))
        }
    }

    impl MakeService for CountingReconnectMaker {
        type Service = CountingReconnectSvc;
        type Error = MockMakerError;

        fn make_service(&self) -> Result<Self::Service, Self::Error> {
            Ok(CountingReconnectSvc {
                id: self.next_id.fetch_add(1, Ordering::SeqCst),
                calls: Arc::clone(&self.calls),
            })
        }
    }

    #[derive(Debug, Clone)]
    struct PanicReconnectMaker {
        next_id: Arc<AtomicU32>,
    }

    impl PanicReconnectMaker {
        fn new(next_id: u32) -> Self {
            Self {
                next_id: Arc::new(AtomicU32::new(next_id)),
            }
        }
    }

    #[derive(Debug)]
    struct PanicReconnectSvc {
        id: u32,
        panic_on_call: bool,
    }

    impl MakeService for PanicReconnectMaker {
        type Service = PanicReconnectSvc;
        type Error = MockMakerError;

        fn make_service(&self) -> Result<Self::Service, Self::Error> {
            Ok(PanicReconnectSvc {
                id: self.next_id.fetch_add(1, Ordering::SeqCst),
                panic_on_call: false,
            })
        }
    }

    impl Service<()> for PanicReconnectSvc {
        type Response = u32;
        type Error = ReconnectingCallError;
        type Future = Pin<Box<dyn Future<Output = Result<u32, ReconnectingCallError>>>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            assert!(
                !self.panic_on_call,
                "panic during reconnect call construction"
            );
            if self.id == 0 {
                Box::pin(PanicOnPollFuture)
            } else {
                Box::pin(std::future::ready(Ok(self.id)))
            }
        }
    }

    struct PanicOnPollFuture;

    impl Future for PanicOnPollFuture {
        type Output = Result<u32, ReconnectingCallError>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            panic!("panic in future poll");
        }
    }

    impl MakeService for StaleFailureMaker {
        type Service = StaleFailureSvc;
        type Error = MockMakerError;

        fn make_service(&self) -> Result<Self::Service, Self::Error> {
            Ok(StaleFailureSvc {
                id: self.next_id.fetch_add(1, Ordering::SeqCst),
                delayed_failure: ManualCallController::new(),
            })
        }
    }

    enum StaleFailureFuture {
        Ready(Option<Result<u32, ReconnectingCallError>>),
        Pending(ManualCallFuture),
    }

    impl Future for StaleFailureFuture {
        type Output = Result<u32, ReconnectingCallError>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match &mut *self {
                Self::Ready(result) => {
                    Poll::Ready(result.take().expect("ready future polled after completion"))
                }
                Self::Pending(future) => Pin::new(future).poll(cx),
            }
        }
    }

    impl Service<u8> for StaleFailureSvc {
        type Response = u32;
        type Error = ReconnectingCallError;
        type Future = StaleFailureFuture;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: u8) -> Self::Future {
            match req {
                1 => StaleFailureFuture::Pending(self.delayed_failure.future()),
                2 => StaleFailureFuture::Ready(Some(Err(ReconnectingCallError))),
                _ => StaleFailureFuture::Ready(Some(Ok(self.id))),
            }
        }
    }

    fn noop_waker() -> Waker {
        struct NoopWaker;

        impl Wake for NoopWaker {
            fn wake(self: Arc<Self>) {}
        }

        Waker::from(Arc::new(NoopWaker))
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
    fn reconnects_after_call_error() {
        init_test("reconnects_after_call_error");
        let maker = ReconnectingMaker::new(1);
        let initial = ReconnectingSvc {
            id: 0,
            fail_next_call: true,
        };
        let mut rc = Reconnect::new(maker, initial);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let ready = rc.poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let mut first_call = rc.call(());
        let first_result = Pin::new(&mut first_call).poll(&mut cx);
        assert!(matches!(
            first_result,
            Poll::Ready(Err(ReconnectError::Inner(ReconnectingCallError)))
        ));
        assert_eq!(rc.inner().map(|svc| svc.id), Some(0));
        assert_eq!(rc.reconnect_count(), 0);

        let reconnected = rc.poll_ready(&mut cx);
        assert!(matches!(reconnected, Poll::Ready(Ok(()))));
        assert_eq!(rc.inner().map(|svc| svc.id), Some(1));
        assert_eq!(rc.reconnect_count(), 1);

        let mut second_call = rc.call(());
        let second_result = Pin::new(&mut second_call).poll(&mut cx);
        assert!(matches!(second_result, Poll::Ready(Ok(1))));

        crate::test_complete!("reconnects_after_call_error");
    }

    #[test]
    fn reconnects_after_call_panic() {
        init_test("reconnects_after_call_panic");
        let maker = PanicReconnectMaker::new(1);
        let initial = PanicReconnectSvc {
            id: 0,
            panic_on_call: true,
        };
        let mut rc = Reconnect::new(maker, initial);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _f = rc.call(());
        }));
        assert!(panic.is_err(), "inner call should panic");
        assert_eq!(rc.inner().map(|svc| svc.id), Some(0));
        assert_eq!(rc.reconnect_count(), 0);

        assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(
            rc.inner().map(|svc| svc.id),
            Some(1),
            "next poll_ready should reconnect after a synchronous call panic"
        );
        assert_eq!(rc.reconnect_count(), 1);

        let mut call = rc.call(());
        assert!(matches!(
            Pin::new(&mut call).poll(&mut cx),
            Poll::Ready(Ok(1))
        ));

        crate::test_complete!("reconnects_after_call_panic");
    }

    #[test]
    fn reconnects_after_poll_panic() {
        init_test("reconnects_after_poll_panic");
        let maker = PanicReconnectMaker::new(1);
        let initial = PanicReconnectSvc {
            id: 0,
            panic_on_call: false, // will panic during poll instead
        };
        let mut rc = Reconnect::new(maker, initial);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut call = rc.call(());
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _f = Pin::new(&mut call).poll(&mut cx);
        }));
        assert!(panic.is_err(), "inner poll should panic");
        assert_eq!(rc.inner().map(|svc| svc.id), Some(0));
        assert_eq!(rc.reconnect_count(), 0);

        assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(
            rc.inner().map(|svc| svc.id),
            Some(1),
            "next poll_ready should reconnect after a future poll panic"
        );
        assert_eq!(rc.reconnect_count(), 1);

        let mut call2 = rc.call(());
        assert!(matches!(
            Pin::new(&mut call2).poll(&mut cx),
            Poll::Ready(Ok(1))
        ));

        crate::test_complete!("reconnects_after_poll_panic");
    }

    #[test]
    fn lazy_call_without_poll_ready_returns_not_ready() {
        init_test("lazy_call_without_poll_ready_returns_not_ready");
        let maker = ReconnectingMaker::new(1);
        let mut rc = Reconnect::lazy(maker);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut call = rc.call(());
        assert!(matches!(
            Pin::new(&mut call).poll(&mut cx),
            Poll::Ready(Err(ReconnectError::NotReady))
        ));
        assert!(!rc.is_connected());
        assert_eq!(rc.reconnect_count(), 0);

        assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(rc.inner().map(|svc| svc.id), Some(1));
        assert_eq!(rc.reconnect_count(), 1);

        crate::test_complete!("lazy_call_without_poll_ready_returns_not_ready");
    }

    #[test]
    fn connected_call_without_poll_ready_returns_not_ready() {
        init_test("connected_call_without_poll_ready_returns_not_ready");
        let calls = Arc::new(AtomicU32::new(0));
        let maker = CountingReconnectMaker::new(1, Arc::clone(&calls));
        let initial = CountingReconnectSvc {
            id: 7,
            calls: Arc::clone(&calls),
        };
        let mut rc = Reconnect::new(maker, initial);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut call = rc.call(());
        assert!(matches!(
            Pin::new(&mut call).poll(&mut cx),
            Poll::Ready(Err(ReconnectError::NotReady))
        ));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "readiness misuse must not invoke the connected inner service"
        );

        crate::test_complete!("connected_call_without_poll_ready_returns_not_ready");
    }

    #[test]
    fn connected_ready_window_is_consumed_by_call() {
        init_test("connected_ready_window_is_consumed_by_call");
        let calls = Arc::new(AtomicU32::new(0));
        let maker = CountingReconnectMaker::new(1, Arc::clone(&calls));
        let initial = CountingReconnectSvc {
            id: 9,
            calls: Arc::clone(&calls),
        };
        let mut rc = Reconnect::new(maker, initial);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut first = rc.call(());
        assert!(matches!(
            Pin::new(&mut first).poll(&mut cx),
            Poll::Ready(Ok(9))
        ));

        let mut second = rc.call(());
        assert!(matches!(
            Pin::new(&mut second).poll(&mut cx),
            Poll::Ready(Err(ReconnectError::NotReady))
        ));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "exactly one call should consume a connected readiness window"
        );

        crate::test_complete!("connected_ready_window_is_consumed_by_call");
    }

    #[test]
    fn call_after_disconnect_returns_not_ready() {
        init_test("call_after_disconnect_returns_not_ready");
        let maker = ReconnectingMaker::new(1);
        let initial = ReconnectingSvc {
            id: 0,
            fail_next_call: false,
        };
        let mut rc = Reconnect::new(maker, initial);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        rc.disconnect();
        assert!(!rc.is_connected());

        let mut call = rc.call(());
        assert!(matches!(
            Pin::new(&mut call).poll(&mut cx),
            Poll::Ready(Err(ReconnectError::NotReady))
        ));
        assert_eq!(rc.reconnect_count(), 0);

        assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(rc.inner().map(|svc| svc.id), Some(1));
        assert_eq!(rc.reconnect_count(), 1);

        crate::test_complete!("call_after_disconnect_returns_not_ready");
    }

    #[test]
    fn stale_call_error_does_not_drop_reconnected_service() {
        init_test("stale_call_error_does_not_drop_reconnected_service");
        let delayed_failure = ManualCallController::new();
        let maker = StaleFailureMaker::new(1);
        let initial = StaleFailureSvc {
            id: 0,
            delayed_failure: delayed_failure.clone(),
        };
        let mut rc = Reconnect::new(maker, initial);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut stale_call = rc.call(1);
        assert!(matches!(
            Pin::new(&mut stale_call).poll(&mut cx),
            Poll::Pending
        ));

        assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let mut failing_call = rc.call(2);
        assert!(matches!(
            Pin::new(&mut failing_call).poll(&mut cx),
            Poll::Ready(Err(ReconnectError::Inner(ReconnectingCallError)))
        ));

        assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(rc.inner().map(|svc| svc.id), Some(1));
        assert_eq!(rc.reconnect_count(), 1);

        delayed_failure.fail();
        assert!(matches!(
            Pin::new(&mut stale_call).poll(&mut cx),
            Poll::Ready(Err(ReconnectError::Inner(ReconnectingCallError)))
        ));

        assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(rc.inner().map(|svc| svc.id), Some(1));
        assert_eq!(
            rc.reconnect_count(),
            1,
            "stale failures from a retired service must not force another reconnect"
        );

        crate::test_complete!("stale_call_error_does_not_drop_reconnected_service");
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
    fn reconnect_error_not_ready_display() {
        let err: ReconnectError<std::io::Error, std::io::Error> = ReconnectError::NotReady;
        assert!(format!("{err}").contains("poll_ready required"));
    }

    #[test]
    fn reconnect_error_polled_after_completion_display() {
        let err: ReconnectError<std::io::Error, std::io::Error> =
            ReconnectError::PolledAfterCompletion;
        assert!(format!("{err}").contains("polled after completion"));
    }

    #[test]
    fn reconnect_error_source() {
        use std::error::Error;
        let err: ReconnectError<std::io::Error, std::io::Error> =
            ReconnectError::Inner(std::io::Error::other("fail"));
        assert!(err.source().is_some());

        let not_ready: ReconnectError<std::io::Error, std::io::Error> = ReconnectError::NotReady;
        assert!(not_ready.source().is_none());

        let done: ReconnectError<std::io::Error, std::io::Error> =
            ReconnectError::PolledAfterCompletion;
        assert!(done.source().is_none());
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
        let fut: ReconnectFuture<_, std::io::Error, std::io::Error> = ReconnectFuture::inner(
            std::future::ready(Ok::<i32, std::io::Error>(42)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            0,
        );
        let dbg = format!("{fut:?}");
        assert!(dbg.contains("ReconnectFuture"));
    }

    #[test]
    fn reconnect_call_without_poll_ready_second_poll_fails_closed() {
        init_test("reconnect_call_without_poll_ready_second_poll_fails_closed");
        let maker = ReconnectingMaker::new(1);
        let mut rc = Reconnect::lazy(maker);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut call = rc.call(());
        assert!(matches!(
            Pin::new(&mut call).poll(&mut cx),
            Poll::Ready(Err(ReconnectError::NotReady))
        ));
        assert!(matches!(
            Pin::new(&mut call).poll(&mut cx),
            Poll::Ready(Err(ReconnectError::PolledAfterCompletion))
        ));

        crate::test_complete!("reconnect_call_without_poll_ready_second_poll_fails_closed");
    }

    #[test]
    fn reconnect_success_second_poll_fails_closed() {
        init_test("reconnect_success_second_poll_fails_closed");
        let calls = Arc::new(AtomicU32::new(0));
        let maker = CountingReconnectMaker::new(1, Arc::clone(&calls));
        let initial = CountingReconnectSvc {
            id: 9,
            calls: Arc::clone(&calls),
        };
        let mut rc = Reconnect::new(maker, initial);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut call = rc.call(());
        assert!(matches!(
            Pin::new(&mut call).poll(&mut cx),
            Poll::Ready(Ok(9))
        ));
        assert!(matches!(
            Pin::new(&mut call).poll(&mut cx),
            Poll::Ready(Err(ReconnectError::PolledAfterCompletion))
        ));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "successful first poll must still invoke the inner service exactly once"
        );

        crate::test_complete!("reconnect_success_second_poll_fails_closed");
    }

    #[test]
    fn reconnect_error_second_poll_fails_closed_and_refresh_still_applies() {
        init_test("reconnect_error_second_poll_fails_closed_and_refresh_still_applies");
        let maker = ReconnectingMaker::new(1);
        let initial = ReconnectingSvc {
            id: 0,
            fail_next_call: true,
        };
        let mut rc = Reconnect::new(maker, initial);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));

        let mut call = rc.call(());
        assert!(matches!(
            Pin::new(&mut call).poll(&mut cx),
            Poll::Ready(Err(ReconnectError::Inner(ReconnectingCallError)))
        ));
        assert!(matches!(
            Pin::new(&mut call).poll(&mut cx),
            Poll::Ready(Err(ReconnectError::PolledAfterCompletion))
        ));

        assert!(
            matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))),
            "first terminal error poll must still trigger reconnect on next readiness probe"
        );
        assert_eq!(rc.inner().map(|svc| svc.id), Some(1));
        assert_eq!(rc.reconnect_count(), 1);

        crate::test_complete!("reconnect_error_second_poll_fails_closed_and_refresh_still_applies");
    }
}
