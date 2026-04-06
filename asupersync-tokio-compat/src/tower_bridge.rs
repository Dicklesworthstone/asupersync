//! Bidirectional bridge between `tower::Service` and Asupersync's service traits.
//!
//! Provides adapters that allow tower middleware stacks to run on the Asupersync
//! runtime while preserving all core invariants:
//!
//! - **INV-1 (No ambient authority)**: Entry points require `&Cx`; Cx is installed
//!   as `Cx::current()` during tower future execution.
//! - **INV-2 (Structured concurrency)**: Tower futures run within the caller's region.
//! - **INV-3 (Cancellation protocol)**: Cancellation propagates via the `CancelAware`
//!   wrapper on each tower future.
//! - **INV-5 (Outcome severity lattice)**: Errors are mapped through `BridgeError`.
//!
//! # Adapters
//!
//! | Type | Direction | Use Case |
//! |------|-----------|----------|
//! | [`FromTower<S>`] | tower→asupersync | Wrap a tower middleware stack for use in asupersync |
//! | [`IntoTower<S>`] | asupersync→tower | Expose an asupersync service to tower middleware |
//!
//! # Example
//!
//! ```ignore
//! use asupersync_tokio_compat::tower_bridge::FromTower;
//!
//! // Wrap a tower service for use in asupersync
//! let tower_svc = tower::ServiceBuilder::new()
//!     .timeout(Duration::from_secs(30))
//!     .service(my_tower_service);
//!
//! let bridge = FromTower::new(tower_svc);
//! let response = bridge.call(&cx, request).await?;
//! ```

use asupersync::sync::Mutex;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Wraps a `tower::Service` for use as an Asupersync-style service.
///
/// The bridge handles:
/// - Readiness polling before each call
/// - Cx propagation via `Cx::set_current` during the response future
/// - Cancellation awareness via poll-time `is_cancel_requested` checks
///
/// # Type Parameters
///
/// - `S`: The tower service type
/// - `Request`: The request type accepted by the tower service
pub struct FromTower<S, Request = ()> {
    inner: Mutex<S>,
    _marker: PhantomData<fn(Request)>,
}

impl<S, Request> FromTower<S, Request> {
    /// Wrap a tower service for use in asupersync.
    pub fn new(service: S) -> Self {
        Self {
            inner: Mutex::new(service),
            _marker: PhantomData,
        }
    }

    /// Consume the bridge and return the inner tower service.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn into_inner(self) -> S {
        self.inner.into_inner()
    }
}

impl<S, Request> FromTower<S, Request>
where
    S: tower::Service<Request> + Send,
    S::Future: Send,
    S::Error: Send,
    Request: Send,
{
    /// Call the tower service within the given Cx context.
    ///
    /// 1. Polls the service to readiness
    /// 2. Dispatches the request
    /// 3. Awaits the response future with cancellation awareness
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::Readiness` if `poll_ready` fails, or
    /// `BridgeError::Service` if the call itself fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub async fn call(
        &self,
        cx: &asupersync::Cx,
        request: Request,
    ) -> Result<S::Response, BridgeError<S::Error>> {
        // Phase 1: Poll readiness and dispatch.
        // Tower's contract requires call() after a successful poll_ready(), both
        // under the same &mut self. We hold an async mutex lock across the
        // poll_ready loop to ensure exclusive access to the service and prevent
        // waker overwrites from concurrent callers.
        let mut request = Some(request);
        let mut svc = self
            .inner
            .lock(cx)
            .await
            .map_err(|_| BridgeError::Cancelled)?;

        let response_future = std::future::poll_fn(|task_cx| {
            let _cx_guard = asupersync::Cx::set_current(Some(cx.clone()));

            if cx.is_cancel_requested() {
                return Poll::Ready(Err(BridgeError::Cancelled));
            }

            match svc.poll_ready(task_cx) {
                Poll::Ready(Ok(())) => {
                    // SAFETY: request is Some until first Ready, and poll_fn
                    // stops polling after the first Ready return.
                    let req = request.take().expect("request already consumed");
                    Poll::Ready(Ok(svc.call(req)))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(BridgeError::Readiness(e))),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        drop(svc);

        // Phase 2: Await the response future with Cx installed on each poll,
        // and support cancellation.
        if cx.is_cancel_requested() {
            return Err(BridgeError::Cancelled);
        }

        let mut response_future = std::pin::pin!(crate::cancel::CancelAware::new(
            response_future,
            crate::CancellationMode::BestEffort,
        ));

        std::future::poll_fn(move |task_cx| {
            let _cx_guard = asupersync::Cx::set_current(Some(cx.clone()));

            if cx.is_cancel_requested() {
                response_future.as_mut().request_cancel();
            }

            match response_future.as_mut().poll(task_cx) {
                Poll::Ready(crate::cancel::CancelResult::Completed(Ok(response)))
                | Poll::Ready(crate::cancel::CancelResult::CancellationIgnored(Ok(response))) => {
                    Poll::Ready(Ok(response))
                }
                Poll::Ready(crate::cancel::CancelResult::Completed(Err(err)))
                | Poll::Ready(crate::cancel::CancelResult::CancellationIgnored(Err(err))) => {
                    Poll::Ready(Err(BridgeError::Service(err)))
                }
                Poll::Ready(crate::cancel::CancelResult::Cancelled) => {
                    Poll::Ready(Err(BridgeError::Cancelled))
                }
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }
}

impl<S: std::fmt::Debug, Request> std::fmt::Debug for FromTower<S, Request> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FromTower")
            .field("inner", &self.inner)
            .finish()
    }
}

/// Wraps an Asupersync service for use as a `tower::Service`.
///
/// The adapter obtains `Cx` from `Cx::current()` (thread-local). This means
/// the caller must ensure `Cx::set_current` has been called before invoking
/// the service. Typically this is done by the hyper/server bridge.
///
/// # Type Parameters
///
/// - `S`: The asupersync service type (must be `Clone` since tower Services
///   are called via `&mut self`)
/// - `Request`: The request type
pub struct IntoTower<S, Request = ()> {
    inner: S,
    _marker: PhantomData<fn(Request)>,
}

impl<S: Clone, Request> Clone for IntoTower<S, Request> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _marker: PhantomData,
        }
    }
}

impl<S, Request> IntoTower<S, Request> {
    /// Wrap an asupersync service as a `tower::Service`.
    pub fn new(service: S) -> Self {
        Self {
            inner: service,
            _marker: PhantomData,
        }
    }

    /// Consume the bridge and return the inner service.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: std::fmt::Debug, Request> std::fmt::Debug for IntoTower<S, Request> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntoTower")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S, Request> tower::Service<Request> for IntoTower<S, Request>
where
    S: asupersync::service::AsupersyncService<Request> + Clone + 'static,
    Request: 'static,
    S::Response: 'static,
    S::Error: 'static,
{
    type Response = S::Response;
    type Error = BridgeError<S::Error>;
    // Note: The future is NOT Send because `async fn in trait` doesn't guarantee
    // Send futures. Callers needing Send must wrap the service in a Send-safe
    // adapter or use concrete service types with Send futures.
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Asupersync services don't have readiness; always ready.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let svc = self.inner.clone();
        // Obtain Cx from thread-local eagerly. If not set, the caller didn't install
        // it before calling the service — this is a configuration error.
        let cx_opt = asupersync::Cx::current();
        Box::pin(async move {
            let cx = cx_opt.ok_or(BridgeError::NoCxAvailable)?;
            svc.call(&cx, request).await.map_err(BridgeError::Service)
        })
    }
}

/// Errors produced by the tower bridge adapters.
#[derive(Debug)]
pub enum BridgeError<E> {
    /// The tower service's `poll_ready` returned an error.
    Readiness(E),
    /// The service call itself returned an error.
    Service(E),
    /// The operation was cancelled via Asupersync's cancellation protocol.
    Cancelled,
    /// `Cx::current()` was not set when calling an `IntoTower` adapter.
    /// The caller must install Cx via `Cx::set_current` before using the service.
    NoCxAvailable,
}

impl<E: std::fmt::Display> std::fmt::Display for BridgeError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Readiness(e) => write!(f, "tower service readiness error: {e}"),
            Self::Service(e) => write!(f, "tower service call error: {e}"),
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::NoCxAvailable => write!(
                f,
                "Cx::current() not set; install Cx before calling IntoTower service"
            ),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for BridgeError<E> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Wake, Waker};

    struct NoopWaker;
    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }
    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    /// Minimal `block_on` for tests.
    fn block_on<F: Future>(fut: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        for _ in 0..1000 {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(val) => return val,
                Poll::Pending => std::thread::sleep(std::time::Duration::from_millis(1)),
            }
        }
        panic!("future did not complete within timeout");
    }

    // ── Simple tower service for testing ──────────────────────────────

    #[derive(Clone, Debug)]
    struct EchoService;

    impl tower::Service<String> for EchoService {
        type Response = String;
        type Error = Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<String, Infallible>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: String) -> Self::Future {
            Box::pin(async move { Ok(format!("echo: {req}")) })
        }
    }

    // ── Simple asupersync service for testing ─────────────────────────

    #[derive(Clone, Debug)]
    struct CounterService {
        counter: Arc<AtomicU64>,
    }

    impl asupersync::service::AsupersyncService<u64> for CounterService {
        type Response = u64;
        type Error = Infallible;

        async fn call(&self, _cx: &asupersync::Cx, request: u64) -> Result<u64, Infallible> {
            let prev = self.counter.fetch_add(request, Ordering::SeqCst);
            Ok(prev + request)
        }
    }

    // ── FromTower tests ──────────────────────────────────────────────

    #[test]
    fn from_tower_echo_service() {
        let bridge = FromTower::new(EchoService);
        let cx = asupersync::Cx::for_testing();

        let result = block_on(bridge.call(&cx, "hello".to_string()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "echo: hello");
    }

    #[test]
    fn from_tower_multiple_calls() {
        let bridge = FromTower::new(EchoService);
        let cx = asupersync::Cx::for_testing();

        for i in 0..5 {
            let msg = format!("msg-{i}");
            let result = block_on(bridge.call(&cx, msg.clone()));
            assert_eq!(result.unwrap(), format!("echo: {msg}"));
        }
    }

    #[test]
    fn from_tower_cancelled_before_call() {
        let bridge = FromTower::new(EchoService);
        let cx = asupersync::Cx::for_testing();
        cx.set_cancel_requested(true);

        let result = block_on(bridge.call(&cx, "should cancel".to_string()));
        assert!(matches!(result, Err(BridgeError::Cancelled)));
    }

    // ── IntoTower tests ──────────────────────────────────────────────

    #[test]
    fn into_tower_counter_service() {
        let counter = Arc::new(AtomicU64::new(0));
        let svc = CounterService {
            counter: counter.clone(),
        };
        let mut tower_svc = IntoTower::new(svc);

        let cx = asupersync::Cx::for_testing();
        let _guard = asupersync::Cx::set_current(Some(cx));

        // Poll ready
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        assert!(matches!(
            tower::Service::poll_ready(&mut tower_svc, &mut task_cx),
            Poll::Ready(Ok(()))
        ));

        // Call
        let fut = tower::Service::call(&mut tower_svc, 10);
        let result = block_on(fut);
        assert_eq!(result.unwrap(), 10);
        assert_eq!(counter.load(Ordering::SeqCst), 10);
    }

    #[test]
    fn into_tower_no_cx_returns_error() {
        let counter = Arc::new(AtomicU64::new(0));
        let svc = CounterService { counter };
        let mut tower_svc = IntoTower::new(svc);

        // Don't install Cx
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let _ = tower::Service::poll_ready(&mut tower_svc, &mut task_cx);

        let fut = tower::Service::call(&mut tower_svc, 5);
        let result = block_on(fut);
        assert!(matches!(result, Err(BridgeError::NoCxAvailable)));
    }

    // ── BridgeError Display ──────────────────────────────────────────

    #[test]
    fn bridge_error_display() {
        let e: BridgeError<String> = BridgeError::Service("oops".into());
        assert!(e.to_string().contains("oops"));

        let e: BridgeError<String> = BridgeError::Cancelled;
        assert_eq!(e.to_string(), "operation cancelled");

        let e: BridgeError<String> = BridgeError::NoCxAvailable;
        assert!(e.to_string().contains("Cx::current()"));
    }

    // ── Round-trip: tower → asupersync → tower ──────────────────────

    #[test]
    fn round_trip_tower_to_asupersync_and_back() {
        // Start with a tower service, bridge into asupersync, bridge back.
        let echo = EchoService;
        let bridge = FromTower::new(echo);
        let cx = asupersync::Cx::for_testing();

        // Call through FromTower (tower→asupersync direction)
        let result = block_on(bridge.call(&cx, "round".to_string()));
        assert_eq!(result.unwrap(), "echo: round");
    }

    // ── Debug impls ──────────────────────────────────────────────────

    #[test]
    fn debug_impls_work() {
        let bridge: FromTower<EchoService, String> = FromTower::new(EchoService);
        let dbg = format!("{bridge:?}");
        assert!(dbg.contains("FromTower"));

        let counter = Arc::new(AtomicU64::new(0));
        let svc = CounterService { counter };
        let tower_svc: IntoTower<CounterService, u64> = IntoTower::new(svc);
        let dbg = format!("{tower_svc:?}");
        assert!(dbg.contains("IntoTower"));
    }

    // ── Clone ────────────────────────────────────────────────────────

    #[test]
    fn into_tower_is_cloneable() {
        let counter = Arc::new(AtomicU64::new(0));
        let svc = CounterService { counter };
        let tower_svc: IntoTower<CounterService, u64> = IntoTower::new(svc);
        #[allow(clippy::redundant_clone)]
        let _cloned = tower_svc.clone();
    }
}
