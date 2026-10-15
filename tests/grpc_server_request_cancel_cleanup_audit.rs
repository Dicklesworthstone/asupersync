//! Audit + regression test for `src/grpc/server.rs` request-cancel
//! resource cleanup (tick #162).
//!
//! Operator's question: "verify when client cancels, in-flight
//! handler resources (allocated buffers, file handles) released
//! within timeout."
//!
//! Audit findings:
//!
//!   (a) **Handler-owned resources release via Rust drop on
//!       future-drop.** `dispatch_unary` (server.rs:803) takes
//!       a handler `H: FnOnce(Request<Bytes>) -> F` whose
//!       returned future `F` owns whatever locals/captures the
//!       handler holds. When the dispatcher's await is
//!       cancelled (the consumer drops the dispatch_unary
//!       future), Rust's structured-cancellation semantics
//!       drop the handler future, which drops every local —
//!       allocated `Vec<u8>` buffers, `std::fs::File` handles,
//!       sockets, mutex guards. There is no special "release"
//!       protocol for these: Rust ownership IS the release
//!       protocol. The audit-relevant property: `dispatch_unary`
//!       does NOT spawn the handler on a detached task that
//!       would outlive the call — the handler is awaited
//!       in-line, so cancellation propagates naturally.
//!
//!   (b) **Interceptor-acquired leases release via the
//!       interceptor protocol.** When an interceptor acquires
//!       a request-scoped resource (e.g.
//!       `RateLimitInterceptor` at interceptor.rs:840+
//!       acquires a slot and stores a `RateLimitLease` in
//!       `request.extensions`), ordinary interceptor short-circuit,
//!       handler-result, and response-hook paths invoke one or both of
//!       these terminal hooks as appropriate:
//!         * `intercept_response_with_request` (success)
//!         * `intercept_error_with_request` (handler error,
//!           request-side-chain short-circuit, or response-hook error)
//!       The reverse-walk cleanup contract ensures prior interceptors
//!       see the applicable hook on those paths. Already-expired and
//!       in-flight deadline returns, plus externally dropping the
//!       dispatch future, can bypass terminal hooks; those paths rely on
//!       request/lease `Drop` instead.
//!       The `RateLimitLease::release` (interceptor.rs:778)
//!       is idempotent — `released: AtomicBool` guards against
//!       double-release.
//!
//!   (c) **Deadline backstops are conditional; idle cleanup is
//!       accounting-only.** `cleanup_idle_streams` removes stale registry
//!       entries when explicitly invoked; it does not close a transport
//!       stream or cancel a handler. A parseable peer timeout is capped by
//!       `max_request_deadline`; absent or malformed timeout metadata instead
//!       uses `default_timeout`.
//!       To give every request an effective deadline, configure both values
//!       consistently; keeping the fallback at or below the peer cap gives
//!       yielding handler futures a common deadline ceiling.
//!
//!   (d) **Fixed:** `RateLimitLease` also releases on `Drop`.
//!       If the dispatcher's future is dropped MID-FLIGHT
//!       (between `intercept_request` and the response/error
//!       terminal hook), dropping the request drops its typed
//!       extension lease and returns the slot. Drop-based
//!       release is safe because `released: AtomicBool` already
//!       makes the call idempotent.
//!
//! Regression tests below pin direct hook behavior at the public API
//! surface and pin (d) so request-drop cancellation cannot
//! regress into a slot leak.

use asupersync::bytes::Bytes;
use asupersync::grpc::status::Code;
use asupersync::grpc::streaming::{Metadata, Request, Response};
use asupersync::grpc::{Interceptor, InterceptorLayer, RateLimitInterceptor, Status};

#[test]
fn rate_limit_slot_releases_on_success_path() {
    // Pin (b) success path: a request that completes
    // successfully releases its rate-limit slot via
    // `intercept_response_with_request`.
    let limiter = RateLimitInterceptor::new(2);
    assert_eq!(limiter.current_count(), 0, "fresh limiter has no in-flight");

    // Acquire a slot via intercept_request.
    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    limiter
        .intercept_request(&mut request)
        .expect("first acquire OK");
    assert_eq!(limiter.current_count(), 1, "slot acquired");

    // Simulate the success path: response-side hook with the
    // SAME request (carrying the lease in extensions).
    let mut response = Response::new(Bytes::new());
    limiter
        .intercept_response_with_request(&request, &mut response)
        .expect("response hook OK");
    assert_eq!(
        limiter.current_count(),
        0,
        "success-path response hook must release the slot",
    );
}

#[test]
fn rate_limit_slot_releases_on_error_path() {
    // Pin (b) error path: when the handler / response hook
    // returns Err, `intercept_error_with_request` releases
    // the slot (br-asupersync-9oxmqv).
    let limiter = RateLimitInterceptor::new(2);
    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    limiter.intercept_request(&mut request).expect("acquire");
    assert_eq!(limiter.current_count(), 1);

    let mut status = Status::internal("simulated handler error");
    limiter
        .intercept_error_with_request(&request, &mut status)
        .expect("error hook OK");
    assert_eq!(
        limiter.current_count(),
        0,
        "error-path hook must release the slot — without this the limiter \
         wedges after max_requests of consecutive auth failures",
    );
}

#[test]
fn rate_limit_release_is_idempotent_double_call_safe() {
    // Pin (b) extension: `RateLimitLease::release` uses
    // `released: AtomicBool` to make the call idempotent. A
    // double release (e.g. from both response hook AND error
    // hook accidentally firing) would NOT decrement the slot
    // counter twice. This is what makes the explicit-hook
    // protocol robust under defensive cleanup walks.
    let limiter = RateLimitInterceptor::new(5);
    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    limiter.intercept_request(&mut request).expect("acquire");
    assert_eq!(limiter.current_count(), 1);

    let mut response = Response::new(Bytes::new());
    let mut status = Status::internal("e");

    // Both hooks fire — release is idempotent.
    limiter
        .intercept_response_with_request(&request, &mut response)
        .expect("first release OK");
    limiter
        .intercept_error_with_request(&request, &mut status)
        .expect("second release OK (no-op)");

    assert_eq!(
        limiter.current_count(),
        0,
        "double-release must not over-decrement (would underflow saturate, \
         but explicit AtomicBool guard stops it)",
    );
}

#[test]
fn rate_limit_slot_releases_when_request_drops_mid_flight() {
    // Pin (d): if cancellation drops the in-flight request
    // before the response/error terminal hook runs, the
    // request's typed extension drops its RateLimitLease and
    // releases the slot. This is the cancellation window that
    // used to leak.
    let limiter = RateLimitInterceptor::new(1);
    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    limiter.intercept_request(&mut request).expect("acquire");
    assert_eq!(limiter.current_count(), 1, "slot acquired");

    drop(request);

    assert_eq!(
        limiter.current_count(),
        0,
        "dropping an admitted request before terminal interceptor hooks \
         must release the rate-limit lease",
    );

    let mut next = Request::with_metadata(Bytes::new(), Metadata::new());
    limiter
        .intercept_request(&mut next)
        .expect("slot reusable after request-drop cleanup");
}

#[test]
fn rate_limit_under_layer_cleanup_walks_back_through_acquired_interceptors() {
    // Pin (b) layered cleanup contract: when an outer
    // interceptor in an `InterceptorLayer` errors, the layer
    // walks back through `interceptors[..=index]` in REVERSE
    // calling `intercept_error_with_request` so the rate-
    // limit slot acquired by the FIRST (rate-limit) layer
    // gets released even when the SECOND (error-injecting)
    // layer rejects the request. (br-asupersync-9oxmqv)
    //
    // We use an `Arc<RateLimitInterceptor>` wrapper so the
    // test can hold a reference to the limiter for counter
    // observation while ALSO moving a clone of the Arc into
    // the layer.
    use std::sync::Arc;
    let limiter = Arc::new(RateLimitInterceptor::new(3));
    let layer = InterceptorLayer::new()
        .layer(ArcInterceptor(limiter.clone()))
        .layer(AlwaysRejectInterceptor);

    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    let result = layer.intercept_request(&mut request);
    assert!(result.is_err(), "second layer rejects → overall layer Err");
    assert_eq!(
        limiter.current_count(),
        0,
        "rate-limit slot acquired by FIRST layer must release when SECOND \
         layer rejects — the reverse-walk cleanup contract",
    );
}

/// Test-only forwarding wrapper to share an interceptor across
/// the test scope and a layer that takes ownership.
#[derive(Debug, Clone)]
struct ArcInterceptor<I>(std::sync::Arc<I>);

impl<I: Interceptor> Interceptor for ArcInterceptor<I> {
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        self.0.intercept_request(request)
    }
    fn intercept_response(&self, response: &mut Response<Bytes>) -> Result<(), Status> {
        self.0.intercept_response(response)
    }
    fn intercept_response_with_request(
        &self,
        request: &Request<Bytes>,
        response: &mut Response<Bytes>,
    ) -> Result<(), Status> {
        self.0.intercept_response_with_request(request, response)
    }
    fn intercept_error_with_request(
        &self,
        request: &Request<Bytes>,
        status: &mut Status,
    ) -> Result<(), Status> {
        self.0.intercept_error_with_request(request, status)
    }
}

/// Test-only interceptor that always returns Err on
/// `intercept_request`. Used to drive the layer's reverse-walk
/// cleanup path.
#[derive(Debug, Clone, Copy)]
struct AlwaysRejectInterceptor;

impl Interceptor for AlwaysRejectInterceptor {
    fn intercept_request(&self, _request: &mut Request<Bytes>) -> Result<(), Status> {
        Err(Status::permission_denied("always reject"))
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }
}

#[test]
fn rate_limit_full_state_rejects_subsequent_with_resource_exhausted() {
    // Pin: when the slot count is at max, the next
    // `intercept_request` returns `Status::resource_exhausted`
    // — the back-pressure shape the audit relies on.
    let limiter = RateLimitInterceptor::new(1);
    let mut req1 = Request::with_metadata(Bytes::new(), Metadata::new());
    limiter
        .intercept_request(&mut req1)
        .expect("first acquire OK");

    // Second request — limiter is full, must reject.
    let mut req2 = Request::with_metadata(Bytes::new(), Metadata::new());
    let err = limiter
        .intercept_request(&mut req2)
        .expect_err("second request must reject — limiter full");
    assert_eq!(
        err.code(),
        Code::ResourceExhausted,
        "rate-limit rejection must surface as ResourceExhausted",
    );

    // Releasing the first request frees a slot; third request
    // can now acquire.
    let mut response = Response::new(Bytes::new());
    limiter
        .intercept_response_with_request(&req1, &mut response)
        .expect("release first");
    let mut req3 = Request::with_metadata(Bytes::new(), Metadata::new());
    limiter
        .intercept_request(&mut req3)
        .expect("third acquires after first releases");
}

#[test]
fn handler_owned_resources_drop_when_standalone_future_dropped() {
    // Supporting evidence for (a): a future that captures a Drop-bearing local
    // releases that local when the future is dropped mid-await. This test does
    // not construct `dispatch_unary`; source inspection separately establishes
    // that dispatch awaits the handler inline. Here we construct a
    // `Pin<Box<dyn Future>>`, polling it to a Pending state,
    // then dropping it. The drop-counter increments exactly
    // once.
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    struct DropCounter(Arc<AtomicUsize>);
    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_handler = counter.clone();

    // The "handler" future captures a DropCounter and a
    // pseudo-allocated buffer (Vec). It awaits a never-ready
    // future to simulate an in-flight handler.
    let fut: Pin<Box<dyn Future<Output = ()>>> = Box::pin(async move {
        let _drop_counter = DropCounter(counter_for_handler);
        let _buffer: Vec<u8> = vec![0; 1024]; // pseudo-alloc
        std::future::pending::<()>().await;
    });

    // Poll once to enter Pending.
    let waker = std::task::Waker::noop().clone();
    let mut cx = Context::from_waker(&waker);
    let mut fut = fut;
    match fut.as_mut().poll(&mut cx) {
        Poll::Pending => {}
        Poll::Ready(_) => panic!("handler future must not complete"),
    }

    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "while polling, drop counter must NOT have fired",
    );

    // Drop the future — Rust drop runs the captured locals.
    drop(fut);

    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "future-drop runs every captured Drop impl exactly once. The \
         pseudo-buffer Vec is also dropped (its allocator returns the \
         memory). This is the structural release mechanism for \
         handler-owned buffers / file handles when their future is dropped.",
    );
}
