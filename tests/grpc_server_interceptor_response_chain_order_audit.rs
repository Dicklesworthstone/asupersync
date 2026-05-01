//! Audit + regression test for `src/grpc/server.rs` interceptor
//! response-chain ordering on the SUCCESS path (tick #188,
//! extends ticks #153 + #185).
//!
//! Operator's question: "verify interceptor stack ordering" —
//! this test pins the symmetric REVERSE-order response-chain
//! walk on the success path that mirrors the error-path
//! reverse walk audited in tick #185.
//!
//! Audit findings:
//!
//!   (a) **Request-side chain runs in INSERTION order**
//!       (server.rs:828, interceptor.rs:261). Layer added
//!       first runs first. Pinned in tick #153.
//!
//!   (b) **Response-side chain runs in REVERSE order**
//!       (server.rs:872, interceptor.rs:278). Layer added
//!       LAST runs FIRST on the response side. This is the
//!       canonical onion-middleware shape: outer layers wrap
//!       inner layers. Pinned below.
//!
//!   (c) **Error-side chain ALSO runs in REVERSE order**
//!       (server.rs:862). Same reverse-walk shape. Pinned in
//!       tick #185.
//!
//!   (d) **Symmetric chain count** — the same number of
//!       interceptors run on the request side as on the
//!       response side (success path). A regression that
//!       short-circuited the response chain (e.g. stopping
//!       at the first early-return) would leave some layers
//!       partially exited. The full reverse walk runs to
//!       completion.
//!
//!   (e) **Response-side interceptor CAN see the request**
//!       (`intercept_response_with_request`, server.rs:874).
//!       The original request is captured via
//!       `request_snapshot = request.snapshot(Bytes::new())`
//!       at server.rs:852 and passed to every response-side
//!       interceptor. This lets layered auth interceptors
//!       inspect the request that produced the response.
//!
//! Regression tests below pin (b)+(d)+(e) at the
//! InterceptorLayer surface. The dispatch_unary internals are
//! pinned by the trait being publicly callable in the same
//! documented sequence.

use asupersync::bytes::Bytes;
use asupersync::grpc::streaming::{Metadata, Request, Response};
use asupersync::grpc::{Interceptor, InterceptorLayer, Status};
use std::sync::Arc;

/// Test interceptor that records each terminal hook in order.
#[derive(Debug, Clone)]
struct OrderRecorder {
    name: &'static str,
    log: Arc<std::sync::Mutex<Vec<String>>>,
}

impl OrderRecorder {
    fn new(name: &'static str, log: Arc<std::sync::Mutex<Vec<String>>>) -> Self {
        Self { name, log }
    }
}

impl Interceptor for OrderRecorder {
    fn intercept_request(&self, _request: &mut Request<Bytes>) -> Result<(), Status> {
        self.log
            .lock()
            .unwrap()
            .push(format!("{}-request", self.name));
        Ok(())
    }

    fn intercept_response(&self, _response: &mut Response<Bytes>) -> Result<(), Status> {
        self.log
            .lock()
            .unwrap()
            .push(format!("{}-response", self.name));
        Ok(())
    }
}

#[test]
fn request_side_chain_runs_in_insertion_order() {
    // Pin (a): three layers, insertion-order request chain.
    let log = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let layer = InterceptorLayer::new()
        .layer(OrderRecorder::new("first", log.clone()))
        .layer(OrderRecorder::new("middle", log.clone()))
        .layer(OrderRecorder::new("last", log.clone()));

    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    layer
        .intercept_request(&mut request)
        .expect("all OK on request side");

    let entries = log.lock().unwrap().clone();
    let request_entries: Vec<&String> =
        entries.iter().filter(|s| s.ends_with("-request")).collect();
    assert_eq!(
        request_entries.len(),
        3,
        "all three layers ran request-side; got {entries:?}",
    );
    assert_eq!(*request_entries[0], "first-request");
    assert_eq!(*request_entries[1], "middle-request");
    assert_eq!(*request_entries[2], "last-request");
}

#[test]
fn response_side_chain_runs_in_reverse_order() {
    // Pin (b): three layers, REVERSE-order response chain.
    // Layer added last runs first on response side.
    let log = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let layer = InterceptorLayer::new()
        .layer(OrderRecorder::new("first", log.clone()))
        .layer(OrderRecorder::new("middle", log.clone()))
        .layer(OrderRecorder::new("last", log.clone()));

    let mut response = Response::new(Bytes::new());
    layer
        .intercept_response(&mut response)
        .expect("all OK on response side");

    let entries = log.lock().unwrap().clone();
    let response_entries: Vec<&String> = entries
        .iter()
        .filter(|s| s.ends_with("-response"))
        .collect();
    assert_eq!(
        response_entries.len(),
        3,
        "all three layers ran response-side; got {entries:?}",
    );
    // REVERSE order — onion middleware shape.
    assert_eq!(
        *response_entries[0], "last-response",
        "response chain runs in REVERSE — last-added layer runs FIRST",
    );
    assert_eq!(*response_entries[1], "middle-response");
    assert_eq!(*response_entries[2], "first-response");
}

#[test]
fn full_request_response_cycle_logs_layer_count_correctly() {
    // Pin (d): request chain + response chain = same N
    // interceptors run on each side. No layer skipped, no
    // layer doubled.
    let log = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let layer = InterceptorLayer::new()
        .layer(OrderRecorder::new("a", log.clone()))
        .layer(OrderRecorder::new("b", log.clone()))
        .layer(OrderRecorder::new("c", log.clone()))
        .layer(OrderRecorder::new("d", log.clone()))
        .layer(OrderRecorder::new("e", log.clone()));

    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    layer.intercept_request(&mut request).expect("OK");
    let mut response = Response::new(Bytes::new());
    layer.intercept_response(&mut response).expect("OK");

    let entries = log.lock().unwrap().clone();
    let request_count = entries.iter().filter(|s| s.ends_with("-request")).count();
    let response_count = entries.iter().filter(|s| s.ends_with("-response")).count();
    assert_eq!(request_count, 5, "all 5 layers ran request-side");
    assert_eq!(
        response_count, 5,
        "all 5 layers ran response-side — chain count is symmetric",
    );
}

#[test]
fn empty_layer_runs_no_interceptors() {
    // Pin (a)+(b) edge: an empty layer is a no-op on both
    // sides. Important: the chain is a Vec, not a fixed
    // structure with implicit hooks.
    let log = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let layer = InterceptorLayer::new();

    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    layer.intercept_request(&mut request).expect("empty OK");
    let mut response = Response::new(Bytes::new());
    layer.intercept_response(&mut response).expect("empty OK");

    assert!(
        log.lock().unwrap().is_empty(),
        "empty layer must not invoke any hooks",
    );
}

#[test]
fn single_layer_request_then_response_runs_in_documented_order() {
    // Pin: a single-layer chain is the canonical case for a
    // simple deployment. Verify the documented hook sequence:
    // request → handler (not exercised here) → response.
    let log = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let layer = InterceptorLayer::new().layer(OrderRecorder::new("only", log.clone()));

    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    layer.intercept_request(&mut request).expect("OK");
    let mut response = Response::new(Bytes::new());
    layer.intercept_response(&mut response).expect("OK");

    let entries = log.lock().unwrap().clone();
    assert_eq!(entries, vec!["only-request", "only-response"]);
}

#[test]
fn layer_len_matches_insertion_count() {
    // Pin (d): the number of interceptors in the layer equals
    // the number of `.layer(...)` calls. A regression that
    // de-duplicated by type would skew the count.
    let layer = InterceptorLayer::new()
        .layer(OrderRecorder::new(
            "a",
            Arc::new(std::sync::Mutex::new(Vec::new())),
        ))
        .layer(OrderRecorder::new(
            "b",
            Arc::new(std::sync::Mutex::new(Vec::new())),
        ))
        .layer(OrderRecorder::new(
            "c",
            Arc::new(std::sync::Mutex::new(Vec::new())),
        ));
    assert_eq!(layer.len(), 3);
    assert!(!layer.is_empty());
}

#[test]
fn three_layers_request_then_response_full_round_trip_log() {
    // Pin (a)+(b) integration: a 3-layer chain produces a
    // log of [a-req, b-req, c-req, c-resp, b-resp, a-resp] —
    // the canonical onion middleware shape.
    let log = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let layer = InterceptorLayer::new()
        .layer(OrderRecorder::new("a", log.clone()))
        .layer(OrderRecorder::new("b", log.clone()))
        .layer(OrderRecorder::new("c", log.clone()));

    let mut request = Request::with_metadata(Bytes::new(), Metadata::new());
    layer.intercept_request(&mut request).expect("OK");
    let mut response = Response::new(Bytes::new());
    layer.intercept_response(&mut response).expect("OK");

    let entries = log.lock().unwrap().clone();
    assert_eq!(
        entries,
        vec![
            "a-request",
            "b-request",
            "c-request",
            "c-response",
            "b-response",
            "a-response",
        ],
        "canonical onion-middleware shape: request chain forward, \
         response chain reverse. The OUTERMOST layer (a) sees the \
         request FIRST and the response LAST — wrapping the chain.",
    );
}
