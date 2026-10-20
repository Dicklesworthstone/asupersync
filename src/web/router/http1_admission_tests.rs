//! Static H1 admission must agree with dispatch without entering user code.

use super::{MethodRouter, Router, post, split_http_request_target};
use crate::Cx;
use crate::http::h1::stream::RequestHead;
use crate::http::h1::types::{Method, Version};
use crate::service::Layer;
use crate::web::extract::{BodyLimits, Request};
use crate::web::handler::{FnHandler, Handler};
use crate::web::{RequestBodyPolicy, Response, StatusCode};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn head(method: Method, uri: &str) -> RequestHead {
    RequestHead {
        method,
        uri: uri.to_string(),
        version: Version::Http11,
        headers: vec![("host".to_string(), "localhost".to_string())],
    }
}

fn route(limit: usize) -> MethodRouter {
    post(FnHandler::new(|| "accepted"))
        .with_body_policy(RequestBodyPolicy::new().max_total_body_size(limit))
}

#[test]
fn static_admission_selects_the_same_route_before_method_not_allowed() {
    let router = Router::new()
        .without_default_trace()
        .route("/files/*", route(80))
        .route("/files/:id", route(40))
        .route("/files/fixed", route(20))
        .route("/files/:other", route(10));
    for (uri, expected) in [
        ("/files/fixed?version=2", 20),
        ("http://localhost/files/fixed?version=2", 20),
        ("/files/object", 40),
        ("/files/nested/object", 80),
    ] {
        assert_eq!(
            router
                .http1_streaming_body_policy(&head(Method::Delete, uri))
                .unwrap(),
            Some(expected),
        );
        let (path, _) = split_http_request_target(uri);
        let response = router.handle(Request::new("DELETE", path.clone()));
        assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED);
        let response = router.handle(
            Request::new("DELETE", path).with_header("content-length", (expected + 1).to_string()),
        );
        assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    }
}

#[test]
fn static_admission_follows_longest_mount_and_its_fallback_policy() {
    let router = Router::new()
        .without_default_trace()
        .with_server_body_policy(RequestBodyPolicy::new().max_total_body_size(100))
        .nest(
            "/api",
            Router::new().with_body_policy(RequestBodyPolicy::new().max_total_body_size(50)),
        )
        .nest(
            "/api/private",
            Router::new()
                .with_body_policy(RequestBodyPolicy::new().max_total_body_size(7))
                .fallback(FnHandler::new(|| StatusCode::ACCEPTED)),
        )
        .nest(
            "/api/private/",
            Router::new().with_body_policy(RequestBodyPolicy::new().max_total_body_size(2)),
        );
    for (path, limit, status) in [
        ("/api/missing", 50, StatusCode::NOT_FOUND),
        ("/api/private/missing", 7, StatusCode::ACCEPTED),
    ] {
        assert_eq!(
            router
                .http1_streaming_body_policy(&head(Method::Post, path))
                .unwrap(),
            Some(limit),
        );
        assert_eq!(router.handle(Request::new("POST", path)).status, status);
        assert_eq!(
            router
                .handle(
                    Request::new("POST", path)
                        .with_header("content-length", (limit + 1).to_string()),
                )
                .status,
            StatusCode::PAYLOAD_TOO_LARGE,
        );
    }
}

#[test]
fn specific_mount_selection_and_outer_ceilings_match_dispatch() {
    let router = || {
        Router::new()
            .without_default_trace()
            .with_server_body_policy(RequestBodyPolicy::new().max_total_body_size(50))
            .route("/api/*", route(80))
            .nest("/api", Router::new().route("/fixed", route(3)))
    };
    for (specific, expected) in [(false, 50), (true, 3)] {
        let router = router().prefer_specific_mounts(specific);
        assert_eq!(
            router
                .http1_streaming_body_policy(&head(Method::Post, "/api/fixed"))
                .unwrap(),
            Some(expected),
        );
        assert_eq!(
            router
                .handle(
                    Request::new("POST", "/api/fixed")
                        .with_header("content-length", (expected + 1).to_string()),
                )
                .status,
            StatusCode::PAYLOAD_TOO_LARGE,
        );
    }
}

#[test]
fn unconfigured_legacy_state_does_not_invent_a_total_limit() {
    let upload = head(Method::Post, "/nested/upload");
    let unconfigured = || {
        Router::new()
            .with_state(BodyLimits::new().max_raw_body_size(3))
            .nest(
                "/nested",
                Router::new()
                    .with_state(BodyLimits::new().max_raw_body_size(30))
                    .route("/upload", post(FnHandler::new(|| "accepted"))),
            )
    };
    assert_eq!(
        unconfigured().http1_streaming_body_policy(&upload).unwrap(),
        None,
    );
    assert_eq!(
        unconfigured()
            .with_server_body_policy(RequestBodyPolicy::new().max_total_body_size(4))
            .http1_streaming_body_policy(&upload)
            .unwrap(),
        Some(4),
    );
    for limit in [0, 64 * 1024 * 1024] {
        assert_eq!(
            Router::new()
                .route("/nested/upload", route(limit))
                .http1_streaming_body_policy(&upload)
                .unwrap(),
            Some(limit as u64),
        );
    }
}

#[test]
fn head_only_admission_enters_neither_handler_nor_middleware() {
    struct CountingLayer(Arc<AtomicUsize>);
    struct CountingHandler<H> {
        calls: Arc<AtomicUsize>,
        inner: H,
    }
    impl<H: Handler> Layer<H> for CountingLayer {
        type Service = CountingHandler<H>;

        fn layer(&self, inner: H) -> Self::Service {
            CountingHandler {
                calls: Arc::clone(&self.0),
                inner,
            }
        }
    }
    impl<H: Handler> Handler for CountingHandler<H> {
        fn call(
            &self,
            cx: &Cx,
            request: Request,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.call(cx, request)
        }
    }

    let middleware_calls = Arc::new(AtomicUsize::new(0));
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let called = Arc::clone(&handler_calls);
    let router = Router::new()
        .without_default_trace()
        .route(
            "/upload",
            post(FnHandler::new(move || {
                called.fetch_add(1, Ordering::SeqCst);
                "accepted"
            }))
            .with_body_policy(RequestBodyPolicy::new().max_total_body_size(4)),
        )
        .layer(CountingLayer(Arc::clone(&middleware_calls)));
    let mut upload = head(Method::Post, "/upload");
    upload
        .headers
        .push(("expect".to_string(), "100-continue".to_string()));
    upload
        .headers
        .push(("content-length".to_string(), "5".to_string()));
    assert_eq!(
        router.http1_streaming_body_policy(&upload).unwrap(),
        Some(4)
    );
    assert_eq!(middleware_calls.load(Ordering::SeqCst), 0);
    assert_eq!(handler_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        router.handle(Request::new("POST", "/upload")).status,
        StatusCode::OK
    );
    assert_eq!(middleware_calls.load(Ordering::SeqCst), 1);
    assert_eq!(handler_calls.load(Ordering::SeqCst), 1);
}
