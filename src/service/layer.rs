//! Layering primitives for services.

/// A layer decorates an inner service to produce a new service.
pub trait Layer<S> {
    /// The service produced by this layer.
    type Service;

    /// Wraps an inner service with this layer.
    fn layer(&self, inner: S) -> Self::Service;
}

/// Identity layer that returns the inner service unchanged.
#[derive(Debug, Clone, Copy, Default)]
pub struct Identity;

impl<S> Layer<S> for Identity {
    type Service = S;

    fn layer(&self, inner: S) -> Self::Service {
        inner
    }
}

/// Stack two layers, applying `inner` first and then `outer`.
#[derive(Debug, Clone)]
pub struct Stack<Inner, Outer> {
    inner: Inner,
    outer: Outer,
}

impl<Inner, Outer> Stack<Inner, Outer> {
    /// Creates a new stacked layer.
    pub fn new(inner: Inner, outer: Outer) -> Self {
        Self { inner, outer }
    }

    /// Returns a reference to the inner layer.
    pub fn inner(&self) -> &Inner {
        &self.inner
    }

    /// Returns a reference to the outer layer.
    pub fn outer(&self) -> &Outer {
        &self.outer
    }
}

impl<S, Inner, Outer> Layer<S> for Stack<Inner, Outer>
where
    Inner: Layer<S>,
    Outer: Layer<Inner::Service>,
{
    type Service = Outer::Service;

    fn layer(&self, service: S) -> Self::Service {
        self.outer.layer(self.inner.layer(service))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{Service, ServiceBuilder, ServiceExt};
    use parking_lot::Mutex;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    // =========================================================================
    // Test helpers
    // =========================================================================

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Arc::new(NoopWaker).into()
    }

    /// Poll a future to completion (only works for immediately-ready futures).
    fn poll_ready_future<F: Future + Unpin>(mut f: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        match Pin::new(&mut f).poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("future was not immediately ready"),
        }
    }

    /// A simple echo service that returns the request value.
    #[derive(Clone)]
    struct EchoService;

    impl Service<u32> for EchoService {
        type Response = u32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<u32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: u32) -> Self::Future {
            std::future::ready(Ok(req))
        }
    }

    /// A service that always returns Pending from poll_ready (simulates backpressure).
    struct NeverReadyService;

    impl Service<u32> for NeverReadyService {
        type Response = u32;
        type Error = std::convert::Infallible;
        type Future = std::future::Pending<Result<u32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            std::future::pending()
        }
    }

    /// A service that fails poll_ready with an error.
    struct FailReadyService;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestError(String);

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for TestError {}

    impl Service<u32> for FailReadyService {
        type Response = u32;
        type Error = TestError;
        type Future = std::future::Ready<Result<u32, TestError>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Err(TestError("not ready".into())))
        }

        fn call(&mut self, _req: u32) -> Self::Future {
            std::future::ready(Err(TestError("should not be called".into())))
        }
    }

    /// A layer that records when it wraps a service, tracking application order.
    #[derive(Clone)]
    struct TrackingLayer {
        id: u32,
        order: Arc<Mutex<Vec<u32>>>,
    }

    impl TrackingLayer {
        fn new(id: u32, order: Arc<Mutex<Vec<u32>>>) -> Self {
            Self { id, order }
        }
    }

    struct TrackingService<S> {
        inner: S,
        id: u32,
        call_order: Arc<Mutex<Vec<u32>>>,
    }

    impl<S> Layer<S> for TrackingLayer {
        type Service = TrackingService<S>;

        fn layer(&self, inner: S) -> Self::Service {
            self.order.lock().push(self.id);
            TrackingService {
                inner,
                id: self.id,
                call_order: Arc::clone(&self.order),
            }
        }
    }

    impl<S, Request> Service<Request> for TrackingService<S>
    where
        S: Service<Request>,
        S::Future: Unpin,
    {
        type Response = S::Response;
        type Error = S::Error;
        type Future = TrackingFuture<S::Future>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(cx)
        }

        fn call(&mut self, req: Request) -> Self::Future {
            self.call_order.lock().push(self.id);
            TrackingFuture(self.inner.call(req))
        }
    }

    struct TrackingFuture<F>(F);

    impl<F: Future + Unpin> Future for TrackingFuture<F> {
        type Output = F::Output;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            Pin::new(&mut self.0).poll(cx)
        }
    }

    /// A layer that multiplies the response by a factor.
    #[derive(Clone)]
    struct MultiplyLayer(u32);

    struct MultiplyService<S> {
        inner: S,
        factor: u32,
    }

    impl<S> Layer<S> for MultiplyLayer {
        type Service = MultiplyService<S>;

        fn layer(&self, inner: S) -> Self::Service {
            MultiplyService {
                inner,
                factor: self.0,
            }
        }
    }

    impl<S> Service<u32> for MultiplyService<S>
    where
        S: Service<u32, Response = u32>,
        S::Future: Unpin,
        S::Error: From<std::convert::Infallible>,
    {
        type Response = u32;
        type Error = S::Error;
        type Future = MultiplyFuture<S::Future>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(cx)
        }

        fn call(&mut self, req: u32) -> Self::Future {
            MultiplyFuture {
                inner: self.inner.call(req),
                factor: self.factor,
            }
        }
    }

    struct MultiplyFuture<F> {
        inner: F,
        factor: u32,
    }

    impl<F, E> Future for MultiplyFuture<F>
    where
        F: Future<Output = Result<u32, E>> + Unpin,
    {
        type Output = Result<u32, E>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match Pin::new(&mut self.inner).poll(cx) {
                Poll::Ready(Ok(v)) => Poll::Ready(Ok(v * self.factor)),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    // =========================================================================
    // Identity layer tests
    // =========================================================================

    #[test]
    fn identity_layer_returns_service_unchanged() {
        let svc = Identity.layer(EchoService);
        let _ = svc;
    }

    #[test]
    fn identity_in_builder_is_noop() {
        let svc = ServiceBuilder::new().service(EchoService);
        let _ = svc;
    }

    // =========================================================================
    // Stack ordering tests
    // =========================================================================

    #[test]
    fn stack_applies_inner_then_outer() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let inner_layer = TrackingLayer::new(1, Arc::clone(&order));
        let outer_layer = TrackingLayer::new(2, Arc::clone(&order));

        let stack = Stack::new(inner_layer, outer_layer);
        let _svc = stack.layer(EchoService);

        let applied = {
            let applied = order.lock();
            applied.clone()
        };
        assert_eq!(
            &applied,
            &[1, 2],
            "inner layer (1) must apply before outer layer (2)"
        );
    }

    #[test]
    fn service_builder_applies_layers_in_order() {
        let order = Arc::new(Mutex::new(Vec::new()));

        let _svc = ServiceBuilder::new()
            .layer(TrackingLayer::new(1, Arc::clone(&order)))
            .layer(TrackingLayer::new(2, Arc::clone(&order)))
            .layer(TrackingLayer::new(3, Arc::clone(&order)))
            .service(EchoService);

        let applied = {
            let applied = order.lock();
            applied.clone()
        };
        assert_eq!(
            &applied,
            &[1, 2, 3],
            "ServiceBuilder layers apply in declaration order"
        );
    }

    #[test]
    fn stack_call_order_outer_wraps_inner() {
        // With Stack(inner=A, outer=B), calling the composed service
        // invokes B.call first (outermost), then A.call, then the base service.
        let order = Arc::new(Mutex::new(Vec::new()));

        let stack = Stack::new(
            TrackingLayer::new(1, Arc::clone(&order)),
            TrackingLayer::new(2, Arc::clone(&order)),
        );
        let mut svc = stack.layer(EchoService);

        // Clear the layer-application order, we only care about call order now.
        order.lock().clear();

        let _fut = svc.call(42);
        let calls = {
            let calls = order.lock();
            calls.clone()
        };
        // Outer (2) call runs first, then inner (1)
        assert_eq!(calls[0], 2, "outer layer's call runs first");
        assert_eq!(calls[1], 1, "inner layer's call runs second");
    }

    // =========================================================================
    // Functional composition tests
    // =========================================================================

    #[test]
    fn stacked_multiply_layers_compose_correctly() {
        // Stack: multiply-by-2 (inner) then multiply-by-3 (outer)
        // Result: echo(5) * 2 * 3 = 30
        let stack = Stack::new(MultiplyLayer(2), MultiplyLayer(3));
        let svc = stack.layer(EchoService);

        let fut = svc.oneshot(5);
        let result = poll_ready_future(fut);
        assert_eq!(result.unwrap(), 30);
    }

    #[test]
    fn service_builder_composes_multiply_layers() {
        // Builder: multiply-by-2, then multiply-by-5
        // Result: echo(7) * 2 * 5 = 70
        let svc = ServiceBuilder::new()
            .layer(MultiplyLayer(2))
            .layer(MultiplyLayer(5))
            .service(EchoService);

        let fut = svc.oneshot(7);
        let result = poll_ready_future(fut);
        assert_eq!(result.unwrap(), 70);
    }

    #[test]
    fn identity_in_stack_is_transparent() {
        let stack = Stack::new(Identity, MultiplyLayer(3));
        let svc = stack.layer(EchoService);

        let fut = svc.oneshot(4);
        let result = poll_ready_future(fut);
        assert_eq!(result.unwrap(), 12);
    }

    // =========================================================================
    // Backpressure propagation tests
    // =========================================================================

    #[test]
    fn backpressure_propagates_through_stack() {
        let stack = Stack::new(MultiplyLayer(2), MultiplyLayer(3));
        let mut svc = stack.layer(NeverReadyService);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(
            svc.poll_ready(&mut cx).is_pending(),
            "backpressure (Pending) must propagate through all layers"
        );
    }

    #[test]
    fn backpressure_propagates_through_builder_stack() {
        let mut svc = ServiceBuilder::new()
            .layer(MultiplyLayer(2))
            .layer(MultiplyLayer(3))
            .layer(MultiplyLayer(5))
            .service(NeverReadyService);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(
            svc.poll_ready(&mut cx).is_pending(),
            "backpressure propagates through deeply nested builder stack"
        );
    }

    // =========================================================================
    // Error propagation tests
    // =========================================================================

    #[test]
    fn error_propagates_through_layer_stack() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let stack = Stack::new(
            TrackingLayer::new(1, Arc::clone(&order)),
            TrackingLayer::new(2, Arc::clone(&order)),
        );
        let mut svc = stack.layer(FailReadyService);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = svc.poll_ready(&mut cx);
        assert!(
            matches!(result, Poll::Ready(Err(_))),
            "error must propagate through the stack"
        );
    }

    // =========================================================================
    // Stack accessors
    // =========================================================================

    #[test]
    fn stack_inner_outer_accessors() {
        let stack = Stack::new(MultiplyLayer(2), MultiplyLayer(3));
        assert_eq!(stack.inner().0, 2);
        assert_eq!(stack.outer().0, 3);
    }

    // =========================================================================
    // Deep nesting
    // =========================================================================

    #[test]
    fn deeply_nested_stacks_compose() {
        let svc = ServiceBuilder::new()
            .layer(MultiplyLayer(2))
            .layer(MultiplyLayer(3))
            .layer(MultiplyLayer(5))
            .layer(MultiplyLayer(7))
            .service(EchoService);

        // 1 * 2 * 3 * 5 * 7 = 210
        let fut = svc.oneshot(1);
        let result = poll_ready_future(fut);
        assert_eq!(result.unwrap(), 210);
    }

    // =========================================================================
    // Readiness propagation
    // =========================================================================

    // =========================================================================
    // Wave 43 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn identity_debug_clone_copy_default() {
        let id = Identity;
        let dbg = format!("{id:?}");
        assert_eq!(dbg, "Identity");
        let copied = id;
        let cloned = id.clone();
        assert_eq!(format!("{copied:?}"), format!("{cloned:?}"));
        let def = Identity::default();
        assert_eq!(format!("{def:?}"), "Identity");
    }

    #[test]
    fn stack_debug_clone() {
        let s = Stack::new(Identity, Identity);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Stack"), "Debug should contain 'Stack': {dbg}");
        assert!(
            dbg.contains("Identity"),
            "Debug should contain inner/outer: {dbg}"
        );
        let cloned = s.clone();
        assert_eq!(format!("{cloned:?}"), dbg);
        assert_eq!(format!("{:?}", cloned.inner()), "Identity");
        assert_eq!(format!("{:?}", cloned.outer()), "Identity");
    }

    // =========================================================================
    // Readiness propagation
    // =========================================================================

    #[test]
    fn ready_service_propagates_through_stack() {
        let stack = Stack::new(MultiplyLayer(2), MultiplyLayer(3));
        let mut svc = stack.layer(EchoService);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(
            matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))),
            "ready state propagates through the stack"
        );
    }
}
