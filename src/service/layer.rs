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
    #[inline]
    pub fn inner(&self) -> &Inner {
        &self.inner
    }

    /// Returns a reference to the outer layer.
    #[inline]
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
    struct MultiplyLayer {
        factor: u32,
        id: u32,
    }

    impl MultiplyLayer {
        fn new(factor: u32, id: u32) -> Self {
            Self { factor, id }
        }
    }

    struct MultiplyService<S> {
        inner: S,
        factor: u32,
        id: u32,
    }

    impl<S> Layer<S> for MultiplyLayer {
        type Service = MultiplyService<S>;

        fn layer(&self, inner: S) -> Self::Service {
            MultiplyService {
                inner,
                factor: self.factor,
                id: self.id,
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
        let cloned = id;
        assert_eq!(format!("{copied:?}"), format!("{cloned:?}"));
        let def = Identity;
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
        let cloned = s;
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

    // =========================================================================
    // METAMORPHIC TESTING: Service Layer Stack Composition Associativity
    // =========================================================================

    /// Configuration for metamorphic layer testing
    #[derive(Debug, Clone)]
    struct LayerMetamorphicConfig {
        /// Number of layers to test in compositions
        layer_count: usize,
        /// Test request values
        test_values: Vec<u32>,
        /// Maximum composition depth for stress testing
        max_depth: usize,
    }

    impl Default for LayerMetamorphicConfig {
        fn default() -> Self {
            Self {
                layer_count: 5,
                test_values: vec![0, 1, 42, 100, 999],
                max_depth: 8,
            }
        }
    }

    /// Transform layer that adds a constant to the response
    #[derive(Clone)]
    struct AddLayer {
        value: u32,
        id: u32,
    }

    impl AddLayer {
        fn new(value: u32, id: u32) -> Self {
            Self { value, id }
        }
    }

    impl<S> Layer<S> for AddLayer
    where
        S: Service<u32, Response = u32>,
        S::Future: Unpin,
    {
        type Service = AddService<S>;

        fn layer(&self, inner: S) -> Self::Service {
            AddService {
                inner,
                value: self.value,
                id: self.id,
            }
        }
    }

    struct AddService<S> {
        inner: S,
        value: u32,
        id: u32,
    }

    impl<S> Service<u32> for AddService<S>
    where
        S: Service<u32, Response = u32>,
        S::Future: Unpin,
    {
        type Response = u32;
        type Error = S::Error;
        type Future = AddFuture<S::Future>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(cx)
        }

        fn call(&mut self, req: u32) -> Self::Future {
            AddFuture {
                inner: self.inner.call(req),
                value: self.value,
            }
        }
    }

    struct AddFuture<F> {
        inner: F,
        value: u32,
    }

    impl<F> Future for AddFuture<F>
    where
        F: Future<Output = Result<u32, std::convert::Infallible>> + Unpin,
    {
        type Output = F::Output;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match Pin::new(&mut self.inner).poll(cx) {
                Poll::Ready(Ok(value)) => Poll::Ready(Ok(value + self.value)),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }


    /// Helper to execute a service call and get the result
    fn execute_service_call<S>(mut service: S, request: u32) -> S::Response
    where
        S: Service<u32>,
        S::Future: Unpin,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Ensure service is ready
        match service.poll_ready(&mut cx) {
            Poll::Ready(Ok(())) => {},
            Poll::Ready(Err(_)) => panic!("Service failed to become ready"),
            Poll::Pending => panic!("Service not immediately ready"),
        }

        // Call the service and await result
        poll_ready_future(service.call(request)).unwrap()
    }

    // =========================================================================
    // MR1: Stack Composition Associativity
    // =========================================================================

    #[test]
    fn metamorphic_stack_composition_associativity() {
        // MR: Stack(Stack(A, B), C) should be equivalent to Stack(A, Stack(B, C))

        let config = LayerMetamorphicConfig::default();

        // Create test layers
        let layer_a = AddLayer::new(10, 1);
        let layer_b = MultiplyLayer::new(2, 2);
        let layer_c = AddLayer::new(5, 3);

        // Test associativity: (A ∘ B) ∘ C = A ∘ (B ∘ C)
        for &test_value in &config.test_values {
            // Left-associative: Stack(Stack(A, B), C)
            let left_stack = Stack::new(Stack::new(layer_a.clone(), layer_b.clone()), layer_c.clone());
            let left_service = left_stack.layer(EchoService);
            let left_result = execute_service_call(left_service, test_value);

            // Right-associative: Stack(A, Stack(B, C))
            let right_stack = Stack::new(layer_a.clone(), Stack::new(layer_b.clone(), layer_c.clone()));
            let right_service = right_stack.layer(EchoService);
            let right_result = execute_service_call(right_service, test_value);

            assert_eq!(
                left_result, right_result,
                "Associativity failed for input {}: left={}, right={}",
                test_value, left_result, right_result
            );
        }
    }

    // =========================================================================
    // MR2: Identity Layer Composition Laws
    // =========================================================================

    #[test]
    fn metamorphic_identity_layer_composition_laws() {
        // MR: Identity should be left and right identity for layer composition
        // Stack(Identity, L) = L and Stack(L, Identity) = L

        let config = LayerMetamorphicConfig::default();
        let test_layer = AddLayer::new(42, 1);

        for &test_value in &config.test_values {
            // Original layer behavior
            let original_service = test_layer.layer(EchoService);
            let original_result = execute_service_call(original_service, test_value);

            // Left identity: Stack(Identity, L) = L
            let left_identity_stack = Stack::new(Identity, test_layer.clone());
            let left_identity_service = left_identity_stack.layer(EchoService);
            let left_identity_result = execute_service_call(left_identity_service, test_value);

            assert_eq!(
                original_result, left_identity_result,
                "Left identity law failed for input {}: original={}, left_identity={}",
                test_value, original_result, left_identity_result
            );

            // Right identity: Stack(L, Identity) = L
            let right_identity_stack = Stack::new(test_layer.clone(), Identity);
            let right_identity_service = right_identity_stack.layer(EchoService);
            let right_identity_result = execute_service_call(right_identity_service, test_value);

            assert_eq!(
                original_result, right_identity_result,
                "Right identity law failed for input {}: original={}, right_identity={}",
                test_value, original_result, right_identity_result
            );
        }
    }

    // =========================================================================
    // MR3: Layer Ordering Preservation
    // =========================================================================

    #[test]
    fn metamorphic_layer_ordering_preservation() {
        // MR: Layer application order should be preserved in nested compositions
        // The order of effects should be deterministic regardless of composition structure

        let config = LayerMetamorphicConfig::default();

        // Create layers with distinct effects
        let add_10 = AddLayer::new(10, 1);
        let multiply_3 = MultiplyLayer::new(3, 2);
        let add_5 = AddLayer::new(5, 3);

        for &test_value in &config.test_values {
            // Manual composition: ((value + 10) * 3) + 5
            let expected = ((test_value + 10) * 3) + 5;

            // Stack composition should produce the same result
            let stack = Stack::new(
                Stack::new(add_10.clone(), multiply_3.clone()),
                add_5.clone()
            );
            let service = stack.layer(EchoService);
            let result = execute_service_call(service, test_value);

            assert_eq!(
                result, expected,
                "Layer ordering not preserved for input {}: got {}, expected {}",
                test_value, result, expected
            );

            // Alternative composition structure should yield same result
            let alt_stack = Stack::new(
                add_10.clone(),
                Stack::new(multiply_3.clone(), add_5.clone())
            );
            let alt_service = alt_stack.layer(EchoService);
            let alt_result = execute_service_call(alt_service, test_value);

            assert_eq!(
                result, alt_result,
                "Different composition structures gave different results for input {}: {} vs {}",
                test_value, result, alt_result
            );
        }
    }

    // =========================================================================
    // MR4: Stack Composition Commutativity of Commutative Layers
    // =========================================================================

    #[test]
    fn metamorphic_commutative_layer_composition() {
        // MR: When layers have commutative effects, Stack(A, B) = Stack(B, A)

        let config = LayerMetamorphicConfig::default();

        // Create two addition layers (addition is commutative)
        let add_7 = AddLayer::new(7, 1);
        let add_13 = AddLayer::new(13, 2);

        for &test_value in &config.test_values {
            // Stack(add_7, add_13): (value + 7) + 13 = value + 20
            let forward_stack = Stack::new(add_7.clone(), add_13.clone());
            let forward_service = forward_stack.layer(EchoService);
            let forward_result = execute_service_call(forward_service, test_value);

            // Stack(add_13, add_7): (value + 13) + 7 = value + 20
            let reverse_stack = Stack::new(add_13.clone(), add_7.clone());
            let reverse_service = reverse_stack.layer(EchoService);
            let reverse_result = execute_service_call(reverse_service, test_value);

            assert_eq!(
                forward_result, reverse_result,
                "Commutative layers should give same result for input {}: forward={}, reverse={}",
                test_value, forward_result, reverse_result
            );

            // Verify the expected mathematical result
            let expected = test_value + 7 + 13;
            assert_eq!(forward_result, expected);
            assert_eq!(reverse_result, expected);
        }
    }

    // =========================================================================
    // MR5: Deep Stack Composition Consistency
    // =========================================================================

    #[test]
    fn metamorphic_deep_stack_composition_consistency() {
        // MR: Deep stack compositions should maintain consistency regardless of
        // intermediate grouping (generalized associativity)

        let config = LayerMetamorphicConfig::default();

        // Create a sequence of layers for deep composition
        let layers = vec![
            AddLayer::new(2, 1),
            AddLayer::new(3, 2),
            AddLayer::new(5, 3),
            AddLayer::new(7, 4),
        ];

        for &test_value in &config.test_values {
            // Build deep composition in multiple ways

            // Left-nested: (((L1, L2), L3), L4)
            let left_nested = layers.iter().cloned().reduce(|acc, layer| {
                Stack::new(acc, layer)
            }).unwrap();
            let left_service = left_nested.layer(EchoService);
            let left_result = execute_service_call(left_service, test_value);

            // Right-nested: (L1, (L2, (L3, L4)))
            let right_nested = layers.iter().rev().cloned().reduce(|acc, layer| {
                Stack::new(layer, acc)
            }).unwrap();
            let right_service = right_nested.layer(EchoService);
            let right_result = execute_service_call(right_service, test_value);

            // Balanced: ((L1, L2), (L3, L4))
            let balanced = Stack::new(
                Stack::new(layers[0].clone(), layers[1].clone()),
                Stack::new(layers[2].clone(), layers[3].clone())
            );
            let balanced_service = balanced.layer(EchoService);
            let balanced_result = execute_service_call(balanced_service, test_value);

            // All should produce the same result due to associativity
            assert_eq!(
                left_result, right_result,
                "Left vs right nesting mismatch for input {}: {} vs {}",
                test_value, left_result, right_result
            );
            assert_eq!(
                left_result, balanced_result,
                "Left vs balanced nesting mismatch for input {}: {} vs {}",
                test_value, left_result, balanced_result
            );

            // Verify mathematical correctness: value + 2 + 3 + 5 + 7 = value + 17
            let expected = test_value + 2 + 3 + 5 + 7;
            assert_eq!(left_result, expected);
        }
    }

    // =========================================================================
    // MR6: Layer Application Order Tracking
    // =========================================================================

    #[test]
    fn metamorphic_layer_application_order_tracking() {
        // MR: Layer application order should be consistent across equivalent compositions

        let order = Arc::new(Mutex::new(Vec::new()));

        let layer_a = TrackingLayer::new(1, Arc::clone(&order));
        let layer_b = TrackingLayer::new(2, Arc::clone(&order));
        let layer_c = TrackingLayer::new(3, Arc::clone(&order));

        // Test different composition structures
        let compositions = vec![
            ("left_assoc", Stack::new(Stack::new(layer_a.clone(), layer_b.clone()), layer_c.clone())),
            ("right_assoc", Stack::new(layer_a.clone(), Stack::new(layer_b.clone(), layer_c.clone()))),
        ];

        for (name, composition) in compositions {
            order.lock().clear();

            let _service = composition.layer(EchoService);
            let application_order = order.lock().clone();

            // Verify that layers are applied in the correct order: inner first, outer last
            // For Stack(A, B), A should be applied before B
            assert_eq!(
                application_order,
                vec![1, 2, 3],
                "Composition {} has wrong application order: {:?}",
                name, application_order
            );
        }
    }

    // =========================================================================
    // MR7: Error Propagation Through Stack Composition
    // =========================================================================

    #[test]
    fn metamorphic_error_propagation_stack_composition() {
        // MR: Error propagation should be consistent across equivalent stack compositions

        // Create a layer that can fail
        #[derive(Clone)]
        struct FailableLayer {
            should_fail: bool,
        }

        impl<S> Layer<S> for FailableLayer {
            type Service = FailableService<S>;

            fn layer(&self, inner: S) -> Self::Service {
                FailableService {
                    inner,
                    should_fail: self.should_fail,
                }
            }
        }

        struct FailableService<S> {
            inner: S,
            should_fail: bool,
        }

        impl<S> Service<u32> for FailableService<S>
        where
            S: Service<u32>,
        {
            type Response = S::Response;
            type Error = TestError;
            type Future = std::future::Ready<Result<S::Response, TestError>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                if self.should_fail {
                    Poll::Ready(Err(TestError("failable layer error".into())))
                } else {
                    Poll::Ready(Ok(()))
                }
            }

            fn call(&mut self, _req: u32) -> Self::Future {
                std::future::ready(Err(TestError("should not be called".into())))
            }
        }

        // Test error propagation through different stack compositions
        let fail_layer = FailableLayer { should_fail: true };
        let success_layer = AddLayer::new(10, 1);

        // Both compositions should propagate errors consistently
        let compositions = vec![
            Stack::new(fail_layer.clone(), success_layer.clone()),
            Stack::new(success_layer.clone(), fail_layer.clone()),
        ];

        for (i, composition) in compositions.into_iter().enumerate() {
            let mut service = composition.layer(EchoService);
            let waker = noop_waker();
            let mut cx = Context::from_waker(&waker);

            let result = service.poll_ready(&mut cx);
            match result {
                Poll::Ready(Err(TestError(msg))) => {
                    assert!(msg.contains("failable layer error"),
                        "Composition {} should propagate failable layer error, got: {}",
                        i, msg);
                }
                other => {
                    panic!("Composition {} should have failed poll_ready, got: {:?}", i, other);
                }
            }
        }
    }

    // =========================================================================
    // MR8: Composition Stress Test
    // =========================================================================

    #[test]
    fn metamorphic_composition_stress_test() {
        // MR: Complex layer compositions should maintain mathematical consistency

        let config = LayerMetamorphicConfig::default();

        // Create many layers for stress testing
        let mut layers: Vec<Box<dyn Layer<EchoService, Service = _> + Clone>> = vec![
            Box::new(AddLayer::new(1, 1)),
            Box::new(MultiplyLayer::new(2, 2)),
            Box::new(AddLayer::new(3, 3)),
            Box::new(AddLayer::new(4, 4)),
            Box::new(MultiplyLayer::new(1, 5)), // Multiply by 1 (identity)
            Box::new(AddLayer::new(0, 6)), // Add 0 (identity)
        ];

        for &test_value in &config.test_values {
            // Build composition by folding layers
            let composition = layers.iter().cloned().reduce(|acc, layer| {
                Box::new(Stack::new(acc, layer))
            }).unwrap();

            let service = composition.layer(EchoService);
            let result = execute_service_call(service, test_value);

            // Manually compute expected result: ((((value + 1) * 2) + 3) + 4) * 1 + 0
            let expected = ((((test_value + 1) * 2) + 3) + 4) * 1 + 0;
            assert_eq!(
                result, expected,
                "Stress test failed for input {}: got {}, expected {}",
                test_value, result, expected
            );

            // Test with reversed order to ensure different but predictable result
            let mut reversed_layers = layers.clone();
            reversed_layers.reverse();

            let reversed_composition = reversed_layers.into_iter().reduce(|acc, layer| {
                Box::new(Stack::new(acc, layer))
            }).unwrap();

            let reversed_service = reversed_composition.layer(EchoService);
            let reversed_result = execute_service_call(reversed_service, test_value);

            // Reversed: ((((value + 0) * 1) + 4) + 3) * 2 + 1
            let reversed_expected = ((((test_value + 0) * 1) + 4) + 3) * 2 + 1;
            assert_eq!(
                reversed_result, reversed_expected,
                "Reversed stress test failed for input {}: got {}, expected {}",
                test_value, reversed_result, reversed_expected
            );
        }
    }
}
