//! Audit + regression test for `src/grpc/server.rs` onion-order
//! request-vs-response visibility (tick #197, extends ticks
//! #153 + #185 + #188).
//!
//! Operator's question: "verify interceptor onion-order request
//! vs response."
//!
//! Audit context — the canonical onion middleware shape pinned
//! in tick #188:
//!
//!     [outer-req] [inner-req] handler [inner-resp] [outer-resp]
//!     ─────────────────────→        ─────────────────────→
//!                       ↑                   ↑
//!                  insertion             reverse
//!
//!   On the request side, the OUTER (earlier-inserted) layer
//!   runs FIRST and the INNER (later-inserted) layer runs LAST.
//!   On the response side, the INNER (later-inserted) layer
//!   runs FIRST and the OUTER (earlier-inserted) layer runs
//!   LAST. The outer layer wraps the entire chain.
//!
//! Audit findings:
//!
//!   (a) **Mutation visibility request-side: outer → inner.**
//!       An OUTER interceptor that mutates the request (e.g.
//!       inserts an x-trace-id, stamps an AuthContext) — the
//!       INNER interceptor sees the MUTATED request. Pinned
//!       below by inserting metadata in the outer layer's
//!       request-side hook and asserting the inner layer
//!       observes it.
//!
//!   (b) **Mutation visibility response-side: inner → outer.**
//!       The INNER interceptor's response-side hook runs FIRST
//!       (reverse-walk, audited tick #188). An inner-layer
//!       response mutation is visible to the outer layer's
//!       response-side hook.
//!
//!   (c) **Outer wraps inner**: in the request-then-response
//!       round-trip log, OUTER's request runs FIRST and
//!       OUTER's response runs LAST. The outer layer is the
//!       canonical "wrap the entire chain" middleware.
//!
//!   (d) **Inner is wrapped by outer**: INNER's request runs
//!       AFTER outer's; INNER's response runs BEFORE outer's.
//!       Symmetric.
//!
//! Regression tests below pin (a)-(d) at the InterceptorLayer
//! surface.

use asupersync::bytes::Bytes;
use asupersync::grpc::streaming::{Metadata, MetadataValue, Request, Response};
use asupersync::grpc::{Interceptor, InterceptorLayer, Status};
use std::sync::Arc;

/// Outer interceptor: stamps `x-outer-stamped` on request,
/// `x-outer-response-stamped` on response.
#[derive(Debug)]
struct OuterStamp {
    /// Records what the outer interceptor SAW on the request
    /// side AFTER any earlier layer ran (which here is none —
    /// outer is first).
    seen_request: Arc<std::sync::Mutex<Option<bool>>>,
    /// Records what the outer interceptor SAW on the response
    /// side. Should observe the inner layer's response stamp
    /// (since inner runs FIRST on response side per
    /// reverse-walk).
    seen_response_inner_stamp: Arc<std::sync::Mutex<Option<bool>>>,
}

impl Interceptor for OuterStamp {
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        // Outer runs FIRST on request — the request should
        // NOT yet have the inner's stamp.
        let inner_stamp_present = request.metadata().get("x-inner-stamped").is_some();
        *self.seen_request.lock().unwrap() = Some(inner_stamp_present);
        // Stamp the outer marker — inner will observe.
        let _ = request.metadata_mut().insert("x-outer-stamped", "true");
        Ok(())
    }

    fn intercept_response(&self, response: &mut Response<Bytes>) -> Result<(), Status> {
        // Outer runs LAST on response — the response SHOULD
        // already have the inner's stamp.
        let inner_stamp = response
            .metadata()
            .get("x-inner-response-stamped")
            .is_some();
        *self.seen_response_inner_stamp.lock().unwrap() = Some(inner_stamp);
        let _ = response
            .metadata_mut()
            .insert("x-outer-response-stamped", "true");
        Ok(())
    }
}

/// Inner interceptor: stamps `x-inner-stamped` on request,
/// `x-inner-response-stamped` on response.
#[derive(Debug)]
struct InnerStamp {
    /// Records whether the inner interceptor observed outer's
    /// request stamp. Should be true.
    saw_outer_request_stamp: Arc<std::sync::Mutex<Option<bool>>>,
    /// Records whether the inner interceptor observed outer's
    /// response stamp BEFORE its own response runs. Should be
    /// false (outer runs LAST on response side).
    saw_outer_response_stamp: Arc<std::sync::Mutex<Option<bool>>>,
}

impl Interceptor for InnerStamp {
    fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
        // Inner runs SECOND on request — outer's stamp MUST
        // be present.
        let outer_present = request.metadata().get("x-outer-stamped").is_some();
        *self.saw_outer_request_stamp.lock().unwrap() = Some(outer_present);
        let _ = request.metadata_mut().insert("x-inner-stamped", "true");
        Ok(())
    }

    fn intercept_response(&self, response: &mut Response<Bytes>) -> Result<(), Status> {
        // Inner runs FIRST on response (reverse-walk) — outer's
        // response stamp MUST NOT yet be present.
        let outer_response = response
            .metadata()
            .get("x-outer-response-stamped")
            .is_some();
        *self.saw_outer_response_stamp.lock().unwrap() = Some(outer_response);
        let _ = response
            .metadata_mut()
            .insert("x-inner-response-stamped", "true");
        Ok(())
    }
}

#[test]
fn outer_layer_runs_first_on_request_side() {
    // Pin (a)+(c): the outer layer's request-side hook fires
    // BEFORE the inner layer's. Outer observes a "clean"
    // request (no inner stamp); inner observes outer's stamp.
    let outer_seen_inner = Arc::new(std::sync::Mutex::new(None::<bool>));
    let inner_saw_outer = Arc::new(std::sync::Mutex::new(None::<bool>));

    let layer = InterceptorLayer::new()
        .layer(OuterStamp {
            seen_request: outer_seen_inner.clone(),
            seen_response_inner_stamp: Arc::new(std::sync::Mutex::new(None)),
        })
        .layer(InnerStamp {
            saw_outer_request_stamp: inner_saw_outer.clone(),
            saw_outer_response_stamp: Arc::new(std::sync::Mutex::new(None)),
        });

    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    layer.intercept_request(&mut request).expect("OK");

    assert_eq!(
        *outer_seen_inner.lock().unwrap(),
        Some(false),
        "outer ran FIRST — should NOT have observed inner's stamp",
    );
    assert_eq!(
        *inner_saw_outer.lock().unwrap(),
        Some(true),
        "inner ran AFTER outer — should HAVE observed outer's stamp",
    );

    // Both stamps end up on the final request.
    assert!(
        matches!(
            request.metadata().get("x-outer-stamped"),
            Some(MetadataValue::Ascii(v)) if v == "true",
        ),
        "outer's stamp on final request",
    );
    assert!(
        matches!(
            request.metadata().get("x-inner-stamped"),
            Some(MetadataValue::Ascii(v)) if v == "true",
        ),
        "inner's stamp on final request",
    );
}

#[test]
fn inner_layer_runs_first_on_response_side() {
    // Pin (b)+(d): the inner layer's response-side hook fires
    // BEFORE the outer layer's. Inner observes a "clean"
    // response (no outer stamp); outer observes inner's stamp.
    let outer_response_seen = Arc::new(std::sync::Mutex::new(None::<bool>));
    let inner_response_saw_outer = Arc::new(std::sync::Mutex::new(None::<bool>));

    let layer = InterceptorLayer::new()
        .layer(OuterStamp {
            seen_request: Arc::new(std::sync::Mutex::new(None)),
            seen_response_inner_stamp: outer_response_seen.clone(),
        })
        .layer(InnerStamp {
            saw_outer_request_stamp: Arc::new(std::sync::Mutex::new(None)),
            saw_outer_response_stamp: inner_response_saw_outer.clone(),
        });

    let mut response = Response::new(Bytes::new());
    layer.intercept_response(&mut response).expect("OK");

    assert_eq!(
        *inner_response_saw_outer.lock().unwrap(),
        Some(false),
        "inner ran FIRST on response — should NOT have observed \
         outer's response stamp yet",
    );
    assert_eq!(
        *outer_response_seen.lock().unwrap(),
        Some(true),
        "outer ran LAST on response — should HAVE observed inner's \
         response stamp (the wrap-the-chain semantic)",
    );

    // Both response stamps present.
    assert!(matches!(
        response.metadata().get("x-outer-response-stamped"),
        Some(MetadataValue::Ascii(v)) if v == "true",
    ));
    assert!(matches!(
        response.metadata().get("x-inner-response-stamped"),
        Some(MetadataValue::Ascii(v)) if v == "true",
    ));
}

#[test]
fn full_round_trip_outer_wraps_chain_visibility() {
    // Pin (a)+(b)+(c)+(d): full round-trip — outer's
    // request-side runs first, inner's request runs after,
    // inner's response runs first (reverse), outer's response
    // runs last. Outer LITERALLY wraps the entire chain.
    let outer_seen_inner_req = Arc::new(std::sync::Mutex::new(None::<bool>));
    let outer_seen_inner_resp = Arc::new(std::sync::Mutex::new(None::<bool>));
    let inner_saw_outer_req = Arc::new(std::sync::Mutex::new(None::<bool>));
    let inner_saw_outer_resp = Arc::new(std::sync::Mutex::new(None::<bool>));

    let layer = InterceptorLayer::new()
        .layer(OuterStamp {
            seen_request: outer_seen_inner_req.clone(),
            seen_response_inner_stamp: outer_seen_inner_resp.clone(),
        })
        .layer(InnerStamp {
            saw_outer_request_stamp: inner_saw_outer_req.clone(),
            saw_outer_response_stamp: inner_saw_outer_resp.clone(),
        });

    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    layer.intercept_request(&mut request).expect("OK");
    let mut response = Response::new(Bytes::new());
    layer.intercept_response(&mut response).expect("OK");

    // Outer's pre/post visibility:
    //   - request side: did NOT see inner (outer runs first)
    //   - response side: DID see inner (inner runs first on response)
    assert_eq!(*outer_seen_inner_req.lock().unwrap(), Some(false));
    assert_eq!(*outer_seen_inner_resp.lock().unwrap(), Some(true));

    // Inner's pre/post visibility:
    //   - request side: DID see outer (outer ran already)
    //   - response side: did NOT see outer (outer runs after on response)
    assert_eq!(*inner_saw_outer_req.lock().unwrap(), Some(true));
    assert_eq!(*inner_saw_outer_resp.lock().unwrap(), Some(false));
}

#[test]
fn three_layer_onion_request_mutations_propagate_innerward() {
    // Pin (a) extension: a 3-layer chain. Each layer stamps
    // a marker on request side. The INNERMOST layer should
    // observe BOTH outer markers. The MIDDLE layer should
    // observe only the OUTERMOST marker. The OUTERMOST
    // should observe NEITHER (it ran first).
    let outer_observed = Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));
    let middle_observed = Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));
    let inner_observed = Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));

    #[derive(Debug)]
    struct StampLayer {
        name: &'static str,
        observed_log: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }
    impl Interceptor for StampLayer {
        fn intercept_request(&self, request: &mut Request<Bytes>) -> Result<(), Status> {
            for marker in &["x-outer-mark", "x-middle-mark"] {
                if request.metadata().get(*marker).is_some() {
                    self.observed_log.lock().unwrap().push(*marker);
                }
            }
            let stamp = match self.name {
                "outer" => "x-outer-mark",
                "middle" => "x-middle-mark",
                "inner" => "x-inner-mark",
                _ => unreachable!(),
            };
            let _ = request.metadata_mut().insert(stamp, "1");
            Ok(())
        }
        fn intercept_response(&self, _: &mut Response<Bytes>) -> Result<(), Status> {
            Ok(())
        }
    }

    let layer = InterceptorLayer::new()
        .layer(StampLayer {
            name: "outer",
            observed_log: outer_observed.clone(),
        })
        .layer(StampLayer {
            name: "middle",
            observed_log: middle_observed.clone(),
        })
        .layer(StampLayer {
            name: "inner",
            observed_log: inner_observed.clone(),
        });

    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    layer.intercept_request(&mut request).expect("OK");

    assert!(
        outer_observed.lock().unwrap().is_empty(),
        "outer ran FIRST — observed no prior stamps",
    );
    assert_eq!(
        *middle_observed.lock().unwrap(),
        vec!["x-outer-mark"],
        "middle observed outer's stamp ONLY (not inner — inner hasn't run yet)",
    );
    assert_eq!(
        *inner_observed.lock().unwrap(),
        vec!["x-outer-mark", "x-middle-mark"],
        "inner observed BOTH outer + middle stamps (it ran last)",
    );
}
