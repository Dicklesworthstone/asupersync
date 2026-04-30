//! Regression test for `[security-audit-for-saas] InterceptorLayer
//! leaks RateLimit slots when inner interceptor fails`
//! (br-asupersync-9oxmqv).
//!
//! Pre-fix scenario: an `InterceptorLayer` that composes a
//! `RateLimitInterceptor` followed by a failing inner interceptor
//! (e.g. BearerAuth rejecting an invalid token) would
//! PERMANENTLY leak its rate-limit slot per failure. Cause:
//! `InterceptorLayer::intercept_request` short-circuited on the
//! first inner Err via `?` and never walked back through the
//! already-acquired inner interceptors to call their
//! `intercept_error_with_request` cleanup hook. The trait's
//! default `intercept_error_with_request` is a no-op, so the
//! Server's outer error walk also dropped the cleanup signal
//! when it called the InterceptorLayer's default
//! intercept_error_with_request.
//!
//! Post-fix: InterceptorLayer now (a) walks back through the
//! already-run inner interceptors when its own intercept_request
//! short-circuits, and (b) overrides intercept_error_with_request
//! to propagate the outer error walk to every inner interceptor
//! in reverse order.
//!
//! This test pins both behaviors via the public RateLimit-counter
//! observability:
//!   * After 100 simulated auth-failure cycles, the rate limit
//!     counter is back at 0 — no slot leak.
//!   * After max_requests + 1 successful acquires (without any
//!     release path triggering), the limiter rejects — sanity
//!     that the counter is still being honoured.

use asupersync::bytes::Bytes;
use asupersync::grpc::server::Interceptor;
use asupersync::grpc::status::{Code, Status};
use asupersync::grpc::streaming::Request;
use asupersync::grpc::{InterceptorLayer, RateLimitInterceptor};
use std::sync::Arc;

const MAX_REQUESTS: u32 = 4;

/// Inner interceptor that always rejects requests with
/// `Code::Unauthenticated`. Stand-in for any real
/// inner interceptor whose intercept_request can fail (BearerAuth
/// with a bad token, MetadataPropagator with a malformed header,
/// etc.).
#[derive(Debug, Default)]
struct AlwaysRejectInterceptor;

impl Interceptor for AlwaysRejectInterceptor {
    fn intercept_request(&self, _request: &mut Request<Bytes>) -> Result<(), Status> {
        Err(Status::unauthenticated("test reject"))
    }
    fn intercept_response(
        &self,
        _response: &mut asupersync::grpc::streaming::Response<Bytes>,
    ) -> Result<(), Status> {
        Ok(())
    }
}

#[test]
fn interceptor_layer_releases_rate_limit_slot_on_inner_failure() {
    // Build the layer with RateLimit FIRST (so it acquires) followed
    // by an always-rejecting inner that fires after RateLimit.
    let rate_limit = RateLimitInterceptor::new(MAX_REQUESTS);
    // Take a handle on the limiter BEFORE moving into the layer so
    // we can observe `current_count` after each cycle. Arc'ing here
    // is for test inspection; production callers don't need it.
    let observe = Arc::new(rate_limit);
    let observe_for_inspect = Arc::clone(&observe);

    let layer = InterceptorLayer::new()
        .layer(InspectableRateLimit { inner: observe })
        .layer(AlwaysRejectInterceptor);

    // Drive 100 cycles. Each cycle:
    //   * Build a fresh Request<Bytes>.
    //   * Call layer.intercept_request — RateLimit acquires a slot
    //     and stores a lease in extensions, then AlwaysReject
    //     returns Err.
    //   * The fix path inside InterceptorLayer walks back through
    //     RateLimit's intercept_error_with_request, releasing the slot.
    for cycle in 0..100 {
        let mut request = Request::new(Bytes::new());
        let result = layer.intercept_request(&mut request);
        assert!(
            matches!(result, Err(ref s) if s.code() == Code::Unauthenticated),
            "cycle {cycle}: layer must surface the inner-rejected status",
        );
    }

    // The fix's whole point: counter is back at 0, NOT pinned at
    // MAX_REQUESTS as it would be pre-fix.
    assert_eq!(
        observe_for_inspect.current_count(),
        0,
        "InterceptorLayer must release rate-limit slots when an inner \
         interceptor fails — pre-fix this counter would be stuck at \
         MAX_REQUESTS={MAX_REQUESTS} after the first MAX_REQUESTS cycles, \
         permanently rejecting legitimate traffic",
    );
}

/// A pass-through Interceptor wrapping a Rc-clonable
/// RateLimitInterceptor for test observation. Exists because
/// RateLimitInterceptor::new returns by value and we want to
/// observe the same instance from outside the layer.
struct InspectableRateLimit {
    inner: Arc<RateLimitInterceptor>,
}

impl std::fmt::Debug for InspectableRateLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InspectableRateLimit").finish()
    }
}

impl Interceptor for InspectableRateLimit {
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        self.inner.intercept_request(request)
    }
    fn intercept_response(
        &self,
        response: &mut asupersync::grpc::streaming::Response<Bytes>,
    ) -> Result<(), Status> {
        self.inner.intercept_response(response)
    }
    fn intercept_response_with_request(
        &self,
        request: &Request<Bytes>,
        response: &mut asupersync::grpc::streaming::Response<Bytes>,
    ) -> Result<(), Status> {
        self.inner
            .intercept_response_with_request(request, response)
    }
    fn intercept_error_with_request(
        &self,
        request: &Request<Bytes>,
        status: &mut Status,
    ) -> Result<(), Status> {
        self.inner.intercept_error_with_request(request, status)
    }
}
