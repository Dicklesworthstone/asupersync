//! Multi-stack regression test pinning that the
//! `InterceptorLayer` cleanup contract holds across more
//! interesting compositions than the single-failure
//! `grpc_interceptor_layer_slot_release.rs` test.
//!
//! Audit finding (tick #132 follow-up to #130 br-asupersync-9oxmqv):
//!
//! Audited every interceptor in `src/grpc/interceptor.rs` that has
//! its own `intercept_request` for the Err-path state-leak class:
//!
//!   * `RateLimitInterceptor`     — STATEFUL (slot counter).
//!     Already fixed via `intercept_error_with_request` override
//!     and the `InterceptorLayer` cleanup walk. Pinned by the
//!     sibling test `grpc_interceptor_layer_slot_release.rs`.
//!   * `TimeoutInterceptor`       — STATELESS. Only mutates
//!     `request.metadata.grpc-timeout`.
//!   * `BearerAuthInterceptor`    — STATELESS. Inserts an
//!     `authorization` metadata header.
//!   * `BearerAuthValidator`      — STATELESS. Pure validator.
//!   * `MetadataPropagator`       — STATELESS. Per-request copy.
//!   * `TracingInterceptor`       — STATELESS at the request level
//!     (the AtomicU64 counter is its own state but is a monotone
//!     counter, not a lease).
//!   * `LoggingInterceptor`       — STATELESS.
//!   * `FnInterceptor`            — STATELESS by definition (closure).
//!
//! There is no `ConcurrencyLimitInterceptor` (the operator's
//! tick #132 named one — `RateLimitInterceptor` is the de-facto
//! concurrency limiter) and no `RetryInterceptor` is implemented
//! (so no Err-path retry-budget leak surface exists).
//!
//! This test extends the slot-release coverage to compositions the
//! single-test file does not exercise:
//!
//!   1. Multi-stack with failure at the LAST inner interceptor —
//!      RateLimit at the FRONT acquires; auth-validator at the BACK
//!      rejects; cleanup must walk all the way back.
//!   2. Multi-stack with failure at a MIDDLE inner interceptor —
//!      RateLimit at the FRONT, Timeout in the middle (always Ok),
//!      AlwaysReject at the BACK; same expected behavior — RateLimit
//!      gets cleanup signal even with intervening successful
//!      stateless layers.
//!   3. Multi-stack with success path — all three intercept_request
//!      return Ok, slot is held until response-side runs. Then on
//!      response, RateLimit's lease is released via
//!      `intercept_response_with_request`. Pin the same final
//!      counter == 0.

use asupersync::bytes::Bytes;
use asupersync::grpc::server::Interceptor;
use asupersync::grpc::status::{Code, Status};
use asupersync::grpc::streaming::{Metadata, Request, Response};
use asupersync::grpc::{InterceptorLayer, RateLimitInterceptor, TimeoutInterceptor};
use std::sync::Arc;

const MAX_REQUESTS: u32 = 4;

#[derive(Debug, Default)]
struct AlwaysRejectInterceptor;

impl Interceptor for AlwaysRejectInterceptor {
    fn intercept_request(&self, _request: &mut Request<Bytes>) -> Result<(), Status> {
        Err(Status::unauthenticated("test reject"))
    }
    fn intercept_response(&self, _r: &mut Response<Bytes>) -> Result<(), Status> {
        Ok(())
    }
}

/// Wrapper to share an Arc<RateLimitInterceptor> with the test so
/// `current_count` is observable AFTER the layer takes ownership.
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
    fn intercept_response(&self, response: &mut Response<Bytes>) -> Result<(), Status> {
        self.inner.intercept_response(response)
    }
    fn intercept_response_with_request(
        &self,
        request: &Request<Bytes>,
        response: &mut Response<Bytes>,
    ) -> Result<(), Status> {
        self.inner.intercept_response_with_request(request, response)
    }
    fn intercept_error_with_request(
        &self,
        request: &Request<Bytes>,
        status: &mut Status,
    ) -> Result<(), Status> {
        self.inner.intercept_error_with_request(request, status)
    }
}

fn build_observable_layer<I: Interceptor + 'static>(
    extra: I,
) -> (Arc<RateLimitInterceptor>, InterceptorLayer) {
    let limiter = Arc::new(RateLimitInterceptor::new(MAX_REQUESTS));
    let layer = InterceptorLayer::new()
        .layer(InspectableRateLimit {
            inner: Arc::clone(&limiter),
        })
        .layer(extra);
    (limiter, layer)
}

#[test]
fn multistack_failure_at_last_inner_releases_rate_limit_slot() {
    // Stack: [RateLimit, AlwaysReject]. Already covered by the
    // sibling test, but re-asserted here as the baseline of this
    // file's invariant suite.
    let (limiter, layer) = build_observable_layer(AlwaysRejectInterceptor);

    for _ in 0..(MAX_REQUESTS as usize * 4) {
        let mut req = Request::new(Bytes::new());
        let res = layer.intercept_request(&mut req);
        assert!(matches!(res, Err(ref s) if s.code() == Code::Unauthenticated));
    }

    assert_eq!(
        limiter.current_count(),
        0,
        "after 4× MAX_REQUESTS auth failures, RateLimit slot must be back at 0",
    );
}

#[test]
fn multistack_failure_after_intervening_stateless_layer_releases_slot() {
    // Stack: [RateLimit, Timeout (stateless, always Ok), AlwaysReject].
    // Pin that the cleanup walk traverses ALL preceding layers, not
    // just the immediately-preceding one — Timeout is between
    // RateLimit and AlwaysReject and must not absorb the cleanup
    // signal.
    let limiter = Arc::new(RateLimitInterceptor::new(MAX_REQUESTS));
    let layer = InterceptorLayer::new()
        .layer(InspectableRateLimit {
            inner: Arc::clone(&limiter),
        })
        .layer(TimeoutInterceptor::new(5_000)) // 5s
        .layer(AlwaysRejectInterceptor);

    for _ in 0..(MAX_REQUESTS as usize * 4) {
        let mut req = Request::new(Bytes::new());
        let res = layer.intercept_request(&mut req);
        assert!(
            matches!(res, Err(ref s) if s.code() == Code::Unauthenticated),
            "must propagate the auth-reject status through the intervening Timeout layer",
        );
    }

    assert_eq!(
        limiter.current_count(),
        0,
        "intervening stateless interceptor (Timeout) must not absorb the cleanup walk",
    );
}

#[test]
fn multistack_success_path_releases_slot_via_response_side_walk() {
    // Stack: [RateLimit, Timeout]. No failing inner — every request
    // succeeds. The slot release goes through
    // intercept_response_with_request (the RESPONSE-side walk, not
    // the error-side walk). Pin that path also fires the lease
    // release correctly when the chain runs to completion.
    let limiter = Arc::new(RateLimitInterceptor::new(MAX_REQUESTS));
    let layer = InterceptorLayer::new()
        .layer(InspectableRateLimit {
            inner: Arc::clone(&limiter),
        })
        .layer(TimeoutInterceptor::new(5_000));

    for _ in 0..(MAX_REQUESTS as usize * 4) {
        let mut req = Request::new(Bytes::new());
        layer
            .intercept_request(&mut req)
            .expect("success path through stateless Timeout");
        // Slot was acquired; without the response-side walk it
        // would NEVER release.
        let mut resp = Response::with_metadata(Bytes::new(), Metadata::new());
        layer
            .intercept_response_with_request(&req, &mut resp)
            .expect("response-side walk");
    }

    assert_eq!(
        limiter.current_count(),
        0,
        "success path must drain every acquired slot via the response-side walk",
    );
}

#[test]
fn multistack_alternating_success_failure_does_not_drift_counter() {
    // Pin that ALTERNATING success and failure paths through the
    // same stack don't accumulate residual slots in the limiter.
    // A regression that released slots on ONE path but not the
    // other would leave the counter > 0 after equal numbers of
    // each.
    let limiter = Arc::new(RateLimitInterceptor::new(MAX_REQUESTS));

    let success_layer = InterceptorLayer::new().layer(InspectableRateLimit {
        inner: Arc::clone(&limiter),
    });
    let failure_layer = InterceptorLayer::new()
        .layer(InspectableRateLimit {
            inner: Arc::clone(&limiter),
        })
        .layer(AlwaysRejectInterceptor);

    for cycle in 0_u32..32 {
        if cycle.is_multiple_of(2) {
            // Success path: acquire + release via response walk.
            let mut req = Request::new(Bytes::new());
            success_layer
                .intercept_request(&mut req)
                .expect("success acquire");
            let mut resp = Response::with_metadata(Bytes::new(), Metadata::new());
            success_layer
                .intercept_response_with_request(&req, &mut resp)
                .expect("success release");
        } else {
            // Failure path: acquire + release via error walk.
            let mut req = Request::new(Bytes::new());
            let res = failure_layer.intercept_request(&mut req);
            assert!(matches!(res, Err(_)));
        }
    }

    assert_eq!(
        limiter.current_count(),
        0,
        "alternating success/failure must end with 0 in-flight slots",
    );
}
