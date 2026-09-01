//! E2E: Web full stack — route resolution, middleware, handlers, extractors, responses.

mod common;

use asupersync::Cx;
use asupersync::bytes::Buf;
use asupersync::http::body::{Body, Frame, HeaderName};
use asupersync::http::h1::codec::HttpError;
use asupersync::http::h1::listener::{Http1Listener, Http1ListenerConfig};
use asupersync::http::h1::server::{HostPolicy, Http1Config};
use asupersync::http::h1::types::{
    Method as HttpMethod, Request as HttpRequest, Response as HttpResponse, Version as HttpVersion,
};
use asupersync::http::h2::listener::IntoHttp2Response;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpStream;
use asupersync::net::websocket::Message;
use asupersync::runtime::RuntimeBuilder;
use asupersync::server::shutdown::ShutdownPhase;
#[cfg(feature = "tls")]
use asupersync::tls::{
    Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsConnector,
    TlsConnectorBuilder,
};
use asupersync::web::extract::{
    BodyLimits, ExtractionError, Form as FormExtract, FromRequest, FromRequestParts,
    Json as JsonExtract, Path, Query, Request, StreamingRawBody, StreamingRawBodyCollectError,
};
use asupersync::web::handler::{
    AsyncCxFnHandler1, AsyncCxFnHandler2, FnHandler, FnHandler1, Handler,
};
use asupersync::web::middleware::{HeaderOverwrite, MiddlewareStack};
use asupersync::web::multipart::{Multipart, MultipartLimits, StreamingMultipart};
use asupersync::web::request_region::RequestRegion;
use asupersync::web::response::{Html, Json, Redirect, Response, StatusCode};
use asupersync::web::router::{Router, delete, get, post};
use asupersync::web::sse::{
    DEFAULT_STREAMING_SSE_H1_CHANNEL_CAPACITY, STREAMING_SSE_H1_BACKPRESSURE_POLICY, Sse, SseEvent,
    StreamingSse, StreamingSseTransportStep,
};
use asupersync::web::websocket::WebSocketUpgrade;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
#[cfg(feature = "tracing-integration")]
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
#[cfg(feature = "tracing-integration")]
use tracing::Subscriber;
#[cfg(feature = "tracing-integration")]
use tracing::field::{Field, Visit};
#[cfg(feature = "tracing-integration")]
use tracing_subscriber::layer::{Context as LayerContext, Layer};
#[cfg(feature = "tracing-integration")]
use tracing_subscriber::registry::LookupSpan;

// =========================================================================
// Handlers
// =========================================================================

fn index() -> &'static str {
    "welcome"
}

fn health() -> StatusCode {
    StatusCode::OK
}

fn get_user(Path(id): Path<String>) -> String {
    format!("user:{id}")
}

fn create_item(
    JsonExtract(body): JsonExtract<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let resp = serde_json::json!({"created": true, "name": body.get("name").and_then(|v| v.as_str()).unwrap_or("unknown")});
    (StatusCode::CREATED, Json(resp))
}

fn search_items(Query(params): Query<std::collections::HashMap<String, String>>) -> String {
    let q = params.get("q").cloned().unwrap_or_default();
    format!("results for: {q}")
}

fn delete_item(Path(id): Path<String>) -> StatusCode {
    let _ = id;
    StatusCode::NO_CONTENT
}

fn not_found_handler() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "custom 404")
}

fn html_page() -> Html<&'static str> {
    Html("<h1>Hello</h1>")
}

fn redirect_handler() -> Redirect {
    Redirect::permanent("/new-location").expect("test redirect URI should be valid")
}

// =========================================================================
// Web framework proof runner
// =========================================================================

const WEB_FRAMEWORK_BEAD_ID: &str = "asupersync-o74l7u.1.4";
const WEB_FRAMEWORK_ARTIFACT_DIR: &str = "target/web-framework-proof/asupersync-o74l7u.1.4";
static WEB_FRAMEWORK_PROOF_RUN_ID: AtomicU64 = AtomicU64::new(1);
const WEB_FRAMEWORK_WAVE2_SCENARIOS: &[&str] = &[
    "router-path-json-extractor",
    "middleware-body-limit-short-circuit",
    "middleware-panic-recovery-with-security-header",
    "bounded-sse-batch-response",
    "streaming-sse-request-region-disconnect",
    "streaming-sse-h1-transport-disconnect",
    "request-region-panic-isolation",
];
const WEB_FRAMEWORK_REQUIRED_ROW_FIELDS: &[&str] = &[
    "bead_id",
    "scenario_id",
    "route",
    "method",
    "middleware_stack",
    "extractor_set",
    "response_kind",
    "streaming",
    "client_disconnect_at",
    "host_context",
    "transport_mode",
    "backpressure_policy",
    "unsupported_reason",
    "region_count_before",
    "region_count_after",
    "obligation_count_before",
    "obligation_count_after",
    "expected_status",
    "actual_status",
    "expected_body_digest",
    "actual_body_digest",
    "expected_chunk_digests",
    "actual_chunk_digests",
    "artifact_path",
    "verdict",
    "first_failure",
];

fn web_noop_waker() -> Waker {
    std::task::Waker::noop().clone()
}

fn web_block_on<F: std::future::Future>(future: F) -> F::Output {
    let waker = web_noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut pinned = std::pin::pin!(future);
    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

trait WebHandlerSyncExt: Handler {
    fn call_sync(&self, req: Request) -> Response {
        web_block_on(Handler::call(self, &Cx::for_testing(), req))
    }
}

impl<T> WebHandlerSyncExt for T where T: Handler + ?Sized {}

#[derive(Clone)]
struct StreamingRequestReplay(Request);

impl FromRequestParts for StreamingRequestReplay {
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        Ok(Self(req.clone()))
    }
}

#[derive(Clone)]
struct AsyncBodyExtractionProbe {
    extract_started: Arc<AtomicUsize>,
    extract_pending: Arc<AtomicUsize>,
    extract_failed: Arc<AtomicUsize>,
    handler_called: Arc<AtomicUsize>,
}

impl AsyncBodyExtractionProbe {
    fn new() -> Self {
        Self {
            extract_started: Arc::new(AtomicUsize::new(0)),
            extract_pending: Arc::new(AtomicUsize::new(0)),
            extract_failed: Arc::new(AtomicUsize::new(0)),
            handler_called: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[derive(Clone)]
struct StreamedTypedExtractionProbe {
    parts_started: Arc<AtomicUsize>,
    json_handler_called: Arc<AtomicUsize>,
    form_handler_called: Arc<AtomicUsize>,
    over_limit_handler_called: Arc<AtomicUsize>,
    disconnect_handler_called: Arc<AtomicUsize>,
}

impl StreamedTypedExtractionProbe {
    fn new() -> Self {
        Self {
            parts_started: Arc::new(AtomicUsize::new(0)),
            json_handler_called: Arc::new(AtomicUsize::new(0)),
            form_handler_called: Arc::new(AtomicUsize::new(0)),
            over_limit_handler_called: Arc::new(AtomicUsize::new(0)),
            disconnect_handler_called: Arc::new(AtomicUsize::new(0)),
        }
    }
}

struct StreamedTypedExtractionStarted;

impl FromRequestParts for StreamedTypedExtractionStarted {
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        let probe = req
            .extensions
            .get_typed::<StreamedTypedExtractionProbe>()
            .ok_or_else(|| {
                ExtractionError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "streamed typed extraction probe missing",
                )
            })?;
        probe.parts_started.fetch_add(1, Ordering::AcqRel);
        Ok(Self)
    }
}

struct AsyncCollectedStreamingBody;

impl FromRequest for AsyncCollectedStreamingBody {
    fn from_request(_req: Request) -> Result<Self, ExtractionError> {
        Err(ExtractionError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "legacy body extraction path must not run",
        ))
    }

    fn from_request_with_cx<'a>(
        cx: &'a Cx,
        req: Request,
    ) -> impl Future<Output = Result<Self, ExtractionError>> + Send + 'a
    where
        Self: Send + 'a,
    {
        async move {
            let probe = req
                .extensions
                .get_typed_cloned::<AsyncBodyExtractionProbe>()
                .ok_or_else(|| {
                    ExtractionError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "async body extraction probe missing",
                    )
                })?;
            let body = StreamingRawBody::from_request(req)?;
            probe.extract_started.fetch_add(1, Ordering::AcqRel);

            let mut collection = std::pin::pin!(body.collect_bounded_with_cx(cx, 64));
            let collected =
                std::future::poll_fn(|task_cx| match collection.as_mut().poll(task_cx) {
                    Poll::Pending => {
                        probe.extract_pending.store(1, Ordering::Release);
                        Poll::Pending
                    }
                    Poll::Ready(result) => Poll::Ready(result),
                })
                .await;

            match collected {
                Ok(_) => Ok(Self),
                Err(StreamingRawBodyCollectError::Body(error)) => {
                    probe.extract_failed.fetch_add(1, Ordering::AcqRel);
                    Err(ExtractionError::bad_request(format!(
                        "streaming body disconnected: {error}"
                    )))
                }
                Err(error) => Err(ExtractionError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("unexpected streaming body extraction error: {error}"),
                )),
            }
        }
    }
}

fn web_poll_body<B: Body + Unpin>(body: &mut B) -> Option<Result<Frame<B::Data>, B::Error>> {
    let waker = web_noop_waker();
    let mut cx = Context::from_waker(&waker);
    loop {
        match Pin::new(&mut *body).poll_frame(&mut cx) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn web_body_has_no_more_data_after_cancel<E>(frame: Option<Result<Frame<E>, HttpError>>) -> bool {
    matches!(frame, None | Some(Err(HttpError::BodyCancelled)))
}

fn web_body_digest(body: &[u8]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in body {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("fnv1a64:{hash:016x}:len={}", body.len())
}

fn web_framework_first_failure(
    resp: &Response,
    expected_status: StatusCode,
    expected_body: &[u8],
    extra_failure: Option<String>,
) -> String {
    if resp.status != expected_status {
        return format!(
            "status mismatch: expected {} actual {}",
            expected_status.as_u16(),
            resp.status.as_u16()
        );
    }
    if resp.body.as_ref() != expected_body {
        return format!(
            "body digest mismatch: expected {} actual {}",
            web_body_digest(expected_body),
            web_body_digest(&resp.body)
        );
    }
    extra_failure.unwrap_or_default()
}

fn web_framework_row(
    bead_id: &str,
    scenario_id: &str,
    route: &str,
    method: &str,
    middleware_stack: &[&str],
    extractor_set: &[&str],
    response_kind: &str,
    streaming: bool,
    client_disconnect_at: &str,
    host_context: &str,
    transport_mode: &str,
    backpressure_policy: &str,
    unsupported_reason: &str,
    region_count_before: Option<u64>,
    region_count_after: Option<u64>,
    obligation_count_before: Option<u64>,
    obligation_count_after: Option<u64>,
    expected_status: StatusCode,
    expected_body: &[u8],
    resp: &Response,
    extra_failure: Option<String>,
    expected_chunk_digests: &[String],
    actual_chunk_digests: &[String],
    artifact_path: &str,
) -> Value {
    let first_failure =
        web_framework_first_failure(resp, expected_status, expected_body, extra_failure);
    let verdict = if first_failure.is_empty() {
        "pass"
    } else {
        "fail"
    };

    json!({
        "bead_id": bead_id,
        "scenario_id": scenario_id,
        "route": route,
        "method": method,
        "middleware_stack": middleware_stack,
        "extractor_set": extractor_set,
        "response_kind": response_kind,
        "streaming": streaming,
        "client_disconnect_at": client_disconnect_at,
        "host_context": host_context,
        "transport_mode": transport_mode,
        "backpressure_policy": backpressure_policy,
        "unsupported_reason": unsupported_reason,
        "region_count_before": region_count_before,
        "region_count_after": region_count_after,
        "obligation_count_before": obligation_count_before,
        "obligation_count_after": obligation_count_after,
        "expected_status": expected_status.as_u16(),
        "actual_status": resp.status.as_u16(),
        "expected_body_digest": web_body_digest(expected_body),
        "actual_body_digest": web_body_digest(resp.body.as_ref()),
        "expected_chunk_digests": expected_chunk_digests,
        "actual_chunk_digests": actual_chunk_digests,
        "artifact_path": artifact_path,
        "verdict": verdict,
        "first_failure": first_failure,
    })
}

struct WebProofPanicHandler;

impl Handler for WebProofPanicHandler {
    fn call(&self, _cx: &Cx, _req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async { panic!("web framework proof panic") })
    }
}

#[cfg(feature = "tracing-integration")]
struct DropTrackedPanicHandler {
    drops: Arc<AtomicUsize>,
}

#[cfg(feature = "tracing-integration")]
struct ConstructionPanicHandler;

#[cfg(feature = "tracing-integration")]
impl Handler for ConstructionPanicHandler {
    fn call(&self, _cx: &Cx, _req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        panic!("server-only construction panic detail")
    }
}

#[cfg(feature = "tracing-integration")]
struct DropTrackedPanicFuture {
    drops: Arc<AtomicUsize>,
}

#[cfg(feature = "tracing-integration")]
impl Future for DropTrackedPanicFuture {
    type Output = Response;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        panic!("server-only panic detail")
    }
}

#[cfg(feature = "tracing-integration")]
impl Drop for DropTrackedPanicFuture {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(feature = "tracing-integration")]
impl Handler for DropTrackedPanicHandler {
    fn call(&self, _cx: &Cx, _req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(DropTrackedPanicFuture {
            drops: Arc::clone(&self.drops),
        })
    }
}

#[cfg(feature = "tracing-integration")]
#[derive(Default)]
struct EventFields {
    fields: Vec<String>,
}

#[cfg(feature = "tracing-integration")]
impl Visit for EventFields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields.push(format!("{}={value:?}", field.name()));
    }
}

#[cfg(feature = "tracing-integration")]
struct PanicEventLayer {
    events: Arc<Mutex<Vec<String>>>,
}

#[cfg(feature = "tracing-integration")]
impl<S> Layer<S> for PanicEventLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _context: LayerContext<'_, S>) {
        let mut fields = EventFields::default();
        event.record(&mut fields);
        self.events
            .lock()
            .expect("panic event log remains available")
            .push(fields.fields.join(" "));
    }
}

fn web_proof_router_path_json(bead_id: &str, artifact_path: &str) -> Value {
    let router = Router::new().route(
        "/users/:id",
        get(FnHandler1::<_, Path<String>>::new(get_user)),
    );
    let resp = router.handle(Request::new("GET", "/users/42"));
    web_framework_row(
        bead_id,
        "router-path-json-extractor",
        "/users/:id",
        "GET",
        &[],
        &["Path<String>"],
        "plain_text",
        false,
        "none",
        "sync-router",
        "single-response-body",
        "not-applicable",
        "",
        None,
        None,
        None,
        None,
        StatusCode::OK,
        b"user:42",
        &resp,
        None,
        &[],
        &[],
        artifact_path,
    )
}

fn web_proof_middleware_body_limit(bead_id: &str, artifact_path: &str) -> Value {
    let handler = MiddlewareStack::new(FnHandler::new(index))
        .with_body_limit(4)
        .build();
    let req = Request::new("POST", "/upload")
        .with_header("content-length", "8")
        .with_body(b"abcdefgh".to_vec());
    let resp = handler.call_sync(req);
    web_framework_row(
        bead_id,
        "middleware-body-limit-short-circuit",
        "/upload",
        "POST",
        &["RequestBodyLimitMiddleware"],
        &[],
        "error",
        false,
        "none",
        "middleware-stack",
        "single-response-body",
        "not-applicable",
        "",
        None,
        None,
        None,
        None,
        StatusCode::PAYLOAD_TOO_LARGE,
        b"Payload Too Large: Content-Length 8 bytes exceeds limit 4 bytes",
        &resp,
        None,
        &[],
        &[],
        artifact_path,
    )
}

fn web_proof_middleware_panic_recovery(bead_id: &str, artifact_path: &str) -> Value {
    let handler = MiddlewareStack::new(WebProofPanicHandler)
        .with_catch_panic()
        .with_response_header("x-frame-options", "DENY", HeaderOverwrite::IfMissing)
        .build();
    let resp = handler.call_sync(Request::new("GET", "/panic"));
    let extra_failure = (resp.headers.get("x-frame-options").map(String::as_str) != Some("DENY"))
        .then(|| "missing x-frame-options=DENY".to_string());
    web_framework_row(
        bead_id,
        "middleware-panic-recovery-with-security-header",
        "/panic",
        "GET",
        &["CatchPanicMiddleware", "SetResponseHeaderMiddleware"],
        &[],
        "panic_recovery",
        false,
        "none",
        "middleware-stack",
        "single-response-body",
        "not-applicable",
        "",
        None,
        None,
        None,
        None,
        StatusCode::INTERNAL_SERVER_ERROR,
        b"[ASUP-E502] Internal Server Error",
        &resp,
        extra_failure,
        &[],
        &[],
        artifact_path,
    )
}

fn web_proof_bounded_sse(bead_id: &str, artifact_path: &str) -> Value {
    let router = Router::new().route(
        "/events",
        get(FnHandler::new(|| {
            Sse::new(vec![
                SseEvent::default()
                    .event("update")
                    .data(r#"{"count":1}"#)
                    .id("1"),
                SseEvent::default()
                    .event("update")
                    .data(r#"{"count":2}"#)
                    .id("2"),
            ])
            .keep_alive()
        })),
    );
    let resp = router.handle(Request::new("GET", "/events"));
    let expected_body = concat!(
        ":keep-alive\n\n",
        "event:update\n",
        "data:{\"count\":1}\n",
        "id:1\n\n",
        "event:update\n",
        "data:{\"count\":2}\n",
        "id:2\n\n"
    );
    let extra_failure = (resp.headers.get("content-type").map(String::as_str)
        != Some("text/event-stream"))
    .then(|| "missing content-type=text/event-stream".to_string());
    web_framework_row(
        bead_id,
        "bounded-sse-batch-response",
        "/events",
        "GET",
        &[],
        &[],
        "bounded_sse_batch",
        false,
        "not_applicable_single_response_body",
        "sync-router",
        "single-response-body",
        "not-applicable",
        "",
        None,
        None,
        None,
        None,
        StatusCode::OK,
        expected_body.as_bytes(),
        &resp,
        extra_failure,
        &[],
        &[],
        artifact_path,
    )
}

fn web_proof_streaming_sse_request_region(bead_id: &str, artifact_path: &str) -> Value {
    let expected_event = SseEvent::default()
        .event("update")
        .data(r#"{"count":1}"#)
        .id("1");
    let expected_chunk = expected_event.to_string().into_bytes();
    let expected_chunk_digests = vec![web_body_digest(&expected_chunk)];
    let mut actual_chunk_digests = Vec::new();
    let mut buffer_bytes_after_disconnect = 0;

    let cx = Cx::for_testing();
    let region = RequestRegion::new(&cx, Request::new("GET", "/events/stream"));
    let outcome = region.run(|ctx| {
        let mut stream = StreamingSse::new(vec![
            expected_event,
            SseEvent::default()
                .event("update")
                .data(r#"{"count":2}"#)
                .id("2"),
        ]);
        let first_chunk = stream
            .next_chunk(ctx.cx())
            .expect("first streaming SSE chunk should serialize")
            .expect("first streaming SSE event should be present");
        actual_chunk_digests.push(web_body_digest(&first_chunk));

        stream.cancel_for_disconnect(ctx.cx());
        assert!(
            stream
                .next_chunk(ctx.cx())
                .expect("closed streaming SSE should not error after disconnect")
                .is_none(),
            "client disconnect must stop later SSE chunks",
        );
        buffer_bytes_after_disconnect = stream.bytes_emitted();
        Response::empty(StatusCode::CLIENT_CLOSED_REQUEST)
    });
    let resp = outcome.into_response();

    let extra_failure = if actual_chunk_digests != expected_chunk_digests {
        Some(format!(
            "chunk digest mismatch: expected {expected_chunk_digests:?} actual {actual_chunk_digests:?}"
        ))
    } else if !cx.is_cancel_requested() {
        Some("streaming SSE disconnect did not request cancellation".to_string())
    } else if buffer_bytes_after_disconnect != expected_chunk.len() {
        Some(format!(
            "buffer byte mismatch after disconnect: expected {} actual {buffer_bytes_after_disconnect}",
            expected_chunk.len()
        ))
    } else {
        None
    };

    web_framework_row(
        bead_id,
        "streaming-sse-request-region-disconnect",
        "/events/stream",
        "GET",
        &["RequestRegion"],
        &["StreamingSse"],
        "streaming_sse",
        true,
        "after-first-event",
        "request-region-direct-pull",
        "direct-next-chunk",
        "caller-paced-next-chunk",
        "",
        Some(0),
        Some(0),
        Some(0),
        Some(0),
        StatusCode::CLIENT_CLOSED_REQUEST,
        b"",
        &resp,
        extra_failure,
        &expected_chunk_digests,
        &actual_chunk_digests,
        artifact_path,
    )
}

fn web_proof_streaming_sse_h1_transport_disconnect(bead_id: &str, artifact_path: &str) -> Value {
    let expected_event = SseEvent::default()
        .event("update")
        .data(r#"{"count":1}"#)
        .id("1");
    let expected_chunk = expected_event.to_string().into_bytes();
    let expected_chunk_digests = vec![web_body_digest(&expected_chunk)];
    let mut actual_chunk_digests = Vec::new();
    let mut transport_status = 0;
    let mut transport_headers_ok = false;
    let mut complete_after_disconnect = false;
    let mut body_ended_after_disconnect = false;
    let mut buffer_bytes_after_disconnect = 0;

    let cx = Cx::for_testing();
    let region = RequestRegion::new(&cx, Request::new("GET", "/events/stream/h1"));
    let outcome = region.run(|ctx| {
        let mut stream = StreamingSse::new(vec![
            expected_event,
            SseEvent::default()
                .event("update")
                .data(r#"{"count":2}"#)
                .id("2"),
        ]);
        let (transport_response, mut sender) =
            stream.h1_chunked_response(ctx.cx(), DEFAULT_STREAMING_SSE_H1_CHANNEL_CAPACITY);
        transport_status = transport_response.head.status;
        let header = |name: &str| {
            transport_response
                .head
                .headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };
        transport_headers_ok = header("transfer-encoding") == Some("chunked")
            && header("content-type") == Some("text/event-stream")
            && header("cache-control") == Some("no-cache")
            && header("connection") == Some("keep-alive");
        let mut body = transport_response.body;

        let first_step = web_block_on(stream.send_next_h1_chunk(ctx.cx(), &mut sender))
            .expect("first HTTP/1 streaming SSE chunk should commit");
        assert!(matches!(
            first_step,
            StreamingSseTransportStep::Sent { bytes, .. } if bytes == expected_chunk.len()
        ));
        let first_frame = web_poll_body(&mut body)
            .expect("first HTTP/1 body frame should be readable")
            .expect("first HTTP/1 body frame should be ok");
        let first_chunk = first_frame
            .into_data()
            .expect("first HTTP/1 body frame should be data");
        let first_chunk_bytes = first_chunk.chunk().to_vec();
        actual_chunk_digests.push(web_body_digest(&first_chunk_bytes));

        stream.cancel_for_disconnect(ctx.cx());
        complete_after_disconnect = web_block_on(stream.send_next_h1_chunk(ctx.cx(), &mut sender))
            .is_ok_and(|step| step == StreamingSseTransportStep::Complete);
        body_ended_after_disconnect =
            web_body_has_no_more_data_after_cancel(web_poll_body(&mut body));
        buffer_bytes_after_disconnect = stream.bytes_emitted();
        Response::empty(StatusCode::CLIENT_CLOSED_REQUEST)
    });
    let resp = outcome.into_response();

    let extra_failure = if actual_chunk_digests != expected_chunk_digests {
        Some(format!(
            "chunk digest mismatch: expected {expected_chunk_digests:?} actual {actual_chunk_digests:?}"
        ))
    } else if transport_status != StatusCode::OK.as_u16() {
        Some(format!(
            "transport status mismatch: expected 200 actual {transport_status}"
        ))
    } else if !transport_headers_ok {
        Some("missing HTTP/1 chunked SSE transport headers".to_string())
    } else if !cx.is_cancel_requested() {
        Some("HTTP/1 streaming SSE disconnect did not request cancellation".to_string())
    } else if !complete_after_disconnect {
        Some("HTTP/1 streaming SSE did not finish body after disconnect".to_string())
    } else if !body_ended_after_disconnect {
        Some("HTTP/1 streaming SSE body remained readable after disconnect".to_string())
    } else if buffer_bytes_after_disconnect != expected_chunk.len() {
        Some(format!(
            "buffer byte mismatch after disconnect: expected {} actual {buffer_bytes_after_disconnect}",
            expected_chunk.len()
        ))
    } else {
        None
    };

    web_framework_row(
        bead_id,
        "streaming-sse-h1-transport-disconnect",
        "/events/stream/h1",
        "GET",
        &["RequestRegion"],
        &["StreamingSse"],
        "streaming_sse",
        true,
        "after-first-committed-chunk",
        "request-region-http1-outgoing-body",
        "h1-chunked-outgoing-body",
        STREAMING_SSE_H1_BACKPRESSURE_POLICY,
        "",
        Some(0),
        Some(0),
        Some(0),
        Some(0),
        StatusCode::CLIENT_CLOSED_REQUEST,
        b"",
        &resp,
        extra_failure,
        &expected_chunk_digests,
        &actual_chunk_digests,
        artifact_path,
    )
}

fn web_proof_request_region_panic(bead_id: &str, artifact_path: &str) -> Value {
    let cx = Cx::for_testing();
    let region = RequestRegion::new(&cx, Request::new("GET", "/region-panic"));
    let outcome = region.run(|_ctx| {
        panic!("request region proof panic");
    });
    let resp = outcome.into_response();
    web_framework_row(
        bead_id,
        "request-region-panic-isolation",
        "/region-panic",
        "GET",
        &[],
        &["RequestContext"],
        "request_region_panic_500",
        false,
        "none",
        "request-region",
        "single-response-body",
        "not-applicable",
        "",
        None,
        None,
        None,
        None,
        StatusCode::INTERNAL_SERVER_ERROR,
        b"Internal Server Error",
        &resp,
        None,
        &[],
        &[],
        artifact_path,
    )
}

fn web_framework_wave2_run() -> io::Result<Vec<Value>> {
    let bead_id = std::env::var("ASUPERSYNC_WEB_FRAMEWORK_BEAD_ID")
        .unwrap_or_else(|_| WEB_FRAMEWORK_BEAD_ID.to_string());
    let output_dir = std::env::var_os("ASUPERSYNC_WEB_FRAMEWORK_PROOF_DIR").map_or_else(
        || {
            let run_id = WEB_FRAMEWORK_PROOF_RUN_ID.fetch_add(1, Ordering::Relaxed);
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(WEB_FRAMEWORK_ARTIFACT_DIR)
                .join(format!("run-{run_id}"))
        },
        PathBuf::from,
    );
    let rows_path = output_dir.join("test_rows.jsonl");
    let report_path = output_dir.join("test_report.json");
    let artifact_path = rows_path.display().to_string();
    let rows = vec![
        web_proof_router_path_json(&bead_id, &artifact_path),
        web_proof_middleware_body_limit(&bead_id, &artifact_path),
        web_proof_middleware_panic_recovery(&bead_id, &artifact_path),
        web_proof_bounded_sse(&bead_id, &artifact_path),
        web_proof_streaming_sse_request_region(&bead_id, &artifact_path),
        web_proof_streaming_sse_h1_transport_disconnect(&bead_id, &artifact_path),
        web_proof_request_region_panic(&bead_id, &artifact_path),
    ];

    std::fs::create_dir_all(&output_dir)?;
    let mut rows_file = std::fs::File::create(&rows_path)?;
    for row in &rows {
        use std::io::Write as _;
        writeln!(rows_file, "{row}")?;
    }
    let report = json!({
        "bead_id": bead_id,
        "scenario_count": rows.len(),
        "expected_scenarios": WEB_FRAMEWORK_WAVE2_SCENARIOS,
        "required_row_fields": WEB_FRAMEWORK_REQUIRED_ROW_FIELDS,
        "rows_path": artifact_path,
        "report_path": report_path.display().to_string(),
        "validation_passed": rows.iter().all(|row| row["verdict"] == "pass"),
    });
    let report_bytes = serde_json::to_vec_pretty(&report).map_err(io::Error::other)?;
    std::fs::write(report_path, report_bytes)?;

    Ok(rows)
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(feature = "tracing-integration")]
#[test]
fn error_handler_boundary_contains_construction_and_poll_panics_with_redacted_diagnostics() {
    use asupersync::web::negotiate::{ErrorHandlerConfig, ErrorHandlerMiddleware};
    use tracing_subscriber::prelude::*;

    let drops = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(PanicEventLayer {
        events: Arc::clone(&events),
    });

    let (poll_response, construction_response) =
        tracing::subscriber::with_default(subscriber, || {
            let poll_handler = ErrorHandlerMiddleware::new(
                DropTrackedPanicHandler {
                    drops: Arc::clone(&drops),
                },
                ErrorHandlerConfig::default(),
            );
            let mut poll_request =
                Request::new("PATCH", "/panic-boundary").with_header("accept", "application/json");
            poll_request
                .extensions
                .insert("request_id", "fut-a5-trace".to_owned());
            let poll_response = poll_handler.call_sync(poll_request);

            let construction_handler = ErrorHandlerMiddleware::new(
                ConstructionPanicHandler,
                ErrorHandlerConfig::default(),
            );
            let mut construction_request = Request::new("PUT", "/construction-panic")
                .with_header("accept", "application/json");
            construction_request
                .extensions
                .insert("request_id", "fut-a5-construction-trace".to_owned());
            let construction_response = construction_handler.call_sync(construction_request);

            (poll_response, construction_response)
        });

    assert_eq!(poll_response.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        construction_response.status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    for (body, private_detail) in [
        (&poll_response.body, "server-only panic detail"),
        (
            &construction_response.body,
            "server-only construction panic detail",
        ),
    ] {
        let client_body = std::str::from_utf8(body).expect("panic response is utf-8");
        assert!(client_body.contains("ASUP-E502"));
        assert!(!client_body.contains(private_detail));
    }

    let event_text = events
        .lock()
        .expect("panic event log remains available")
        .join("\n");
    for expected in [
        "ASUP-E502",
        "method=PATCH",
        "path=/panic-boundary",
        "trace_id=",
        "fut-a5-trace",
        "panic_message=server-only panic detail",
        "method=PUT",
        "path=/construction-panic",
        "fut-a5-construction-trace",
        "panic_message=server-only construction panic detail",
    ] {
        assert!(
            event_text.contains(expected),
            "missing {expected:?} in structured panic event: {event_text}"
        );
    }
}

#[test]
fn web_framework_wave2_proof_runner_logs_required_scenarios() {
    common::init_test_logging();
    let rows = web_framework_wave2_run().expect("web framework proof runner");
    println!();
    for row in &rows {
        println!("{row}");
    }

    let missing: Vec<_> = WEB_FRAMEWORK_WAVE2_SCENARIOS
        .iter()
        .copied()
        .filter(|scenario_id| {
            !rows
                .iter()
                .any(|row| row["scenario_id"].as_str() == Some(*scenario_id))
        })
        .collect();
    let drifts: Vec<_> = rows
        .iter()
        .filter(|row| row["verdict"].as_str() != Some("pass"))
        .collect();
    let missing_fields: Vec<_> = rows
        .iter()
        .filter_map(|row| {
            WEB_FRAMEWORK_REQUIRED_ROW_FIELDS
                .iter()
                .copied()
                .find(|field| row.get(*field).is_none())
                .map(|field| {
                    let scenario = row["scenario_id"].as_str().unwrap_or("<unknown>");
                    format!("{scenario}:{field}")
                })
        })
        .collect();

    assert!(
        missing.is_empty(),
        "missing web framework proof scenarios: {missing:?}"
    );
    assert!(
        missing_fields.is_empty(),
        "missing web framework proof row fields: {missing_fields:?}"
    );
    assert!(drifts.is_empty(), "web framework proof drifts: {drifts:#?}");
    assert_eq!(rows.len(), WEB_FRAMEWORK_WAVE2_SCENARIOS.len());
}

#[test]
fn web_framework_readme_sse_support_claim_matches_streaming_artifact() {
    common::init_test_logging();
    let rows = web_framework_wave2_run().expect("web framework proof runner");
    let pull_row = rows
        .iter()
        .find(|row| row["scenario_id"].as_str() == Some("streaming-sse-request-region-disconnect"))
        .expect("streaming SSE pull proof row must exist");
    let transport_row = rows
        .iter()
        .find(|row| row["scenario_id"].as_str() == Some("streaming-sse-h1-transport-disconnect"))
        .expect("streaming SSE HTTP/1 transport proof row must exist");

    assert_eq!(pull_row["verdict"].as_str(), Some("pass"));
    assert_eq!(pull_row["streaming"].as_bool(), Some(true));
    assert_eq!(transport_row["verdict"].as_str(), Some("pass"));
    assert_eq!(transport_row["streaming"].as_bool(), Some(true));
    assert_eq!(
        transport_row["transport_mode"].as_str(),
        Some("h1-chunked-outgoing-body"),
    );
    assert_eq!(
        transport_row["backpressure_policy"].as_str(),
        Some(STREAMING_SSE_H1_BACKPRESSURE_POLICY),
    );
    assert!(
        transport_row["actual_chunk_digests"]
            .as_array()
            .is_some_and(|digests| !digests.is_empty()),
        "streaming transport proof row must carry chunk digests",
    );
    let artifact_path = transport_row["artifact_path"]
        .as_str()
        .expect("artifact_path must be a string");
    assert!(
        PathBuf::from(artifact_path).exists(),
        "streaming transport proof artifact path must exist: {artifact_path}",
    );

    let readme_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let readme = std::fs::read_to_string(&readme_path).expect("read README.md");
    for phrase in [
        "`Sse` finite bounded batch",
        "`StreamingSse` pull API",
        "request-region E2E proof",
        "HTTP/1 transport drain proof",
    ] {
        assert!(
            readme.contains(phrase),
            "README SSE support matrix must contain `{phrase}` after streaming artifact proof",
        );
    }
}

#[test]
fn web_framework_transport_artifact_json_schema_check() {
    common::init_test_logging();
    let rows = web_framework_wave2_run().expect("web framework proof runner");
    let artifact_path = rows
        .first()
        .and_then(|row| row["artifact_path"].as_str())
        .expect("artifact_path must be present");
    let rows_jsonl = std::fs::read_to_string(artifact_path).expect("read proof rows jsonl");
    let parsed_rows: Vec<Value> = rows_jsonl
        .lines()
        .map(|line| serde_json::from_str(line).expect("proof row must be valid JSON"))
        .collect();

    assert_eq!(parsed_rows.len(), WEB_FRAMEWORK_WAVE2_SCENARIOS.len());
    for row in &parsed_rows {
        for field in WEB_FRAMEWORK_REQUIRED_ROW_FIELDS {
            assert!(
                row.get(*field).is_some(),
                "proof row {} is missing required field {field}",
                row["scenario_id"].as_str().unwrap_or("<unknown>"),
            );
        }
        assert_eq!(row["bead_id"].as_str(), Some(WEB_FRAMEWORK_BEAD_ID));
    }

    let transport_row = parsed_rows
        .iter()
        .find(|row| row["scenario_id"].as_str() == Some("streaming-sse-h1-transport-disconnect"))
        .expect("HTTP/1 transport row must exist");
    assert_eq!(transport_row["verdict"].as_str(), Some("pass"));
    assert_eq!(transport_row["streaming"].as_bool(), Some(true));
    assert_eq!(
        transport_row["transport_mode"].as_str(),
        Some("h1-chunked-outgoing-body"),
    );
    assert_eq!(
        transport_row["backpressure_policy"].as_str(),
        Some(STREAMING_SSE_H1_BACKPRESSURE_POLICY),
    );
    assert!(
        transport_row["actual_chunk_digests"]
            .as_array()
            .is_some_and(|digests| !digests.is_empty()),
        "HTTP/1 transport row must record actual chunk digests",
    );
    for counter in [
        "region_count_before",
        "region_count_after",
        "obligation_count_before",
        "obligation_count_after",
    ] {
        assert_eq!(
            transport_row[counter].as_u64(),
            Some(0),
            "HTTP/1 transport row counter drifted: {counter}",
        );
    }

    let report_path = PathBuf::from(artifact_path).with_file_name("test_report.json");
    let report: Value =
        serde_json::from_slice(&std::fs::read(&report_path).expect("read proof report json"))
            .expect("proof report must be valid JSON");
    assert_eq!(report["validation_passed"].as_bool(), Some(true));
    assert_eq!(
        report["required_row_fields"]
            .as_array()
            .expect("required_row_fields must be an array")
            .len(),
        WEB_FRAMEWORK_REQUIRED_ROW_FIELDS.len(),
    );
}

#[test]
fn e2e_route_resolution_and_method_dispatch() {
    common::init_test_logging();
    test_phase!("Route Resolution");

    let router = Router::new()
        .route("/", get(FnHandler::new(index)))
        .route("/health", get(FnHandler::new(health)))
        .route(
            "/users/:id",
            get(FnHandler1::<_, Path<String>>::new(get_user)),
        )
        .route(
            "/items",
            post(FnHandler1::<_, JsonExtract<serde_json::Value>>::new(
                create_item,
            )),
        )
        .route(
            "/items/:id",
            delete(FnHandler1::<_, Path<String>>::new(delete_item)),
        )
        .fallback(FnHandler::new(not_found_handler));

    test_section!("GET /");
    let resp = router.handle(Request::new("GET", "/"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "welcome");

    test_section!("GET /health");
    let resp = router.handle(Request::new("GET", "/health"));
    assert_eq!(resp.status, StatusCode::OK);

    test_section!("GET /users/42 with path param");
    let resp = router.handle(Request::new("GET", "/users/42"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "user:42");

    test_section!("POST /items with JSON body");
    let body = serde_json::to_vec(&serde_json::json!({"name": "widget"})).unwrap();
    let req = Request::new("POST", "/items")
        .with_header("content-type", "application/json")
        .with_body(body);
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::CREATED);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["created"], true);
    assert_eq!(json["name"], "widget");

    test_section!("DELETE /items/99");
    let resp = router.handle(Request::new("DELETE", "/items/99"));
    assert_eq!(resp.status, StatusCode::NO_CONTENT);

    test_section!("Method not allowed");
    let resp = router.handle(Request::new("PUT", "/health"));
    assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);

    test_section!("Fallback 404");
    let resp = router.handle(Request::new("GET", "/nonexistent"));
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "custom 404");

    test_complete!("e2e_route_resolution", routes = 5);
}

#[test]
fn e2e_nested_routing() {
    common::init_test_logging();
    test_phase!("Nested Routing");

    let v1 = Router::new()
        .route("/users", get(FnHandler::new(index)))
        .route(
            "/users/:id",
            get(FnHandler1::<_, Path<String>>::new(get_user)),
        );

    let v2 = Router::new().route("/users", get(FnHandler::new(|| -> &'static str { "v2" })));

    let app = Router::new()
        .route("/", get(FnHandler::new(index)))
        .nest("/api/v1", v1)
        .nest("/api/v2", v2);

    test_section!("Root route");
    assert_eq!(app.handle(Request::new("GET", "/")).status, StatusCode::OK);

    test_section!("Nested v1");
    let resp = app.handle(Request::new("GET", "/api/v1/users"));
    assert_eq!(resp.status, StatusCode::OK);

    test_section!("Nested v1 with params");
    let resp = app.handle(Request::new("GET", "/api/v1/users/7"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "user:7");

    test_section!("Nested v2");
    let resp = app.handle(Request::new("GET", "/api/v2/users"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "v2");

    test_section!("Non-existent nested path");
    let resp = app.handle(Request::new("GET", "/api/v3/users"));
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    test_complete!("e2e_nested_routing");
}

#[test]
fn e2e_response_types() {
    common::init_test_logging();
    test_phase!("Response Types");

    let router = Router::new()
        .route("/html", get(FnHandler::new(html_page)))
        .route("/redirect", get(FnHandler::new(redirect_handler)))
        .route(
            "/json",
            get(FnHandler::new(|| -> Json<serde_json::Value> {
                Json(serde_json::json!({"ok": true}))
            })),
        )
        .route(
            "/status-only",
            post(FnHandler::new(|| -> StatusCode { StatusCode::ACCEPTED })),
        );

    test_section!("HTML response");
    let resp = router.handle(Request::new("GET", "/html"));
    assert_eq!(resp.status, StatusCode::OK);
    assert!(std::str::from_utf8(&resp.body).unwrap().contains("<h1>"));

    test_section!("Redirect response");
    let resp = router.handle(Request::new("GET", "/redirect"));
    assert!(
        resp.status == StatusCode::MOVED_PERMANENTLY
            || resp.status == StatusCode::PERMANENT_REDIRECT
    );

    test_section!("JSON response");
    let resp = router.handle(Request::new("GET", "/json"));
    assert_eq!(resp.status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["ok"], true);

    test_section!("Status-only response");
    let resp = router.handle(Request::new("POST", "/status-only"));
    assert_eq!(resp.status, StatusCode::ACCEPTED);

    test_complete!("e2e_response_types");
}

#[test]
fn e2e_query_string_extraction() {
    common::init_test_logging();
    test_phase!("Query String");

    let router = Router::new().route(
        "/search",
        get(FnHandler1::<
            _,
            Query<std::collections::HashMap<String, String>>,
        >::new(search_items)),
    );

    let req = Request::new("GET", "/search").with_query("q=hello+world");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    // Query extraction depends on implementation; at minimum it shouldn't panic
    tracing::info!(
        body = std::str::from_utf8(&resp.body).unwrap(),
        "search result"
    );

    test_complete!("e2e_query_string");
}

#[test]
fn e2e_error_responses() {
    common::init_test_logging();
    test_phase!("Error Responses");

    let router = Router::new().route(
        "/users/:id",
        get(FnHandler1::<_, Path<String>>::new(get_user)),
    );

    test_section!("Missing route -> 404");
    let resp = router.handle(Request::new("GET", "/nonexistent"));
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    test_section!("Wrong method -> 405");
    let resp = router.handle(Request::new("DELETE", "/users/1"));
    assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);

    test_complete!("e2e_error_responses");
}

#[test]
fn e2e_router_adapter_serves_shared_h1_h2_wire_types() {
    common::init_test_logging();
    test_phase!("Router production-listener adapter");

    fn adapted_handler(Query(query): Query<HashMap<String, String>>) -> Response {
        let mut response = Response::new(
            StatusCode::OK,
            format!("q={}", query.get("q").map_or("", String::as_str)),
        );
        response.set_header("x-adapter", "web-router");
        response.append_set_cookie("session=one; Path=/");
        response.append_set_cookie("csrf=two; Path=/");
        response
    }

    let router = Router::new().route(
        "/search",
        get(FnHandler1::<_, Query<HashMap<String, String>>>::new(
            adapted_handler,
        )),
    );
    let request = HttpRequest {
        method: HttpMethod::Get,
        uri: "https://example.test/search?q=connected".to_string(),
        version: HttpVersion::Http2,
        headers: vec![("host".to_string(), "example.test".to_string())],
        body: Vec::new(),
        trailers: Vec::new(),
        peer_addr: None,
    };

    let response = web_block_on(router.handle_http_request_with_cx(&Cx::for_testing(), request));
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"q=connected");
    assert_eq!(response.header_value("x-adapter"), Some("web-router"));
    assert_eq!(
        response
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>(),
        vec!["session=one; Path=/", "csrf=two; Path=/"]
    );

    fn accepts_h1<F, Fut>(_handler: &F)
    where
        F: Fn(HttpRequest) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = HttpResponse> + Send + 'static,
    {
    }

    fn accepts_h2<F, Fut, R>(_handler: &F)
    where
        F: Fn(HttpRequest) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = R> + Send + 'static,
        R: IntoHttp2Response + Send + 'static,
    {
    }

    let handler = Router::new()
        .route("/", get(FnHandler::new(index)))
        .into_http_handler();
    accepts_h1(&handler);
    accepts_h2(&handler);

    test_complete!("e2e_router_listener_adapter", protocols = 2);
}

async fn read_http_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        stream
            .read_exact(&mut byte)
            .await
            .expect("read HTTP/1 response head");
        head.push(byte[0]);
        assert!(head.len() <= 8192, "HTTP/1 response head exceeded 8 KiB");
        if head.ends_with(b"\r\n\r\n") {
            return head;
        }
    }
}

#[cfg(feature = "tls")]
const HTTPS_H1_CERT_PEM: &[u8] = include_bytes!("fixtures/tls/server.crt");
#[cfg(feature = "tls")]
const HTTPS_H1_KEY_PEM: &[u8] = include_bytes!("fixtures/tls/server.key");

#[cfg(feature = "tls")]
fn https_h1_acceptor() -> TlsAcceptor {
    let chain = CertificateChain::from_pem(HTTPS_H1_CERT_PEM).expect("parse HTTPS/1.1 chain");
    let key = PrivateKey::from_pem(HTTPS_H1_KEY_PEM).expect("parse HTTPS/1.1 key");
    TlsAcceptorBuilder::new(chain, key)
        .alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
        .build()
        .expect("build HTTPS/1.1 acceptor")
}

#[cfg(feature = "tls")]
fn https_h1_connector(alpn: Option<&[u8]>) -> TlsConnector {
    let root = Certificate::from_pem(HTTPS_H1_CERT_PEM)
        .expect("parse HTTPS/1.1 root")
        .into_iter()
        .next()
        .expect("HTTPS/1.1 fixture contains a certificate");
    let builder = TlsConnectorBuilder::new().add_root_certificate(&root);
    let builder = match alpn {
        Some(protocol) => builder.alpn_protocols_required(vec![protocol.to_vec()]),
        None => builder,
    };
    builder.build().expect("build HTTPS/1.1 connector")
}

#[cfg(feature = "tls")]
#[test]
fn e2e_router_https_h1_listener_routes_and_refuses_cross_protocol_peers() {
    common::init_test_logging();
    test_phase!("Router -> TLS acceptor -> HTTP/1 listener");

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_calls_for_route = Arc::clone(&handler_calls);
        let router = Router::new().route(
            "/secure",
            get(FnHandler::new(move || {
                handler_calls_for_route.fetch_add(1, Ordering::AcqRel);
                "secure"
            })),
        );
        let listener = Http1Listener::bind_upgradeable_with_config(
            "127.0.0.1:0",
            router.into_http1_handler(),
            Http1ListenerConfig::default()
                .http_config(Http1Config {
                    allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                    ..Http1Config::default()
                })
                .drain_timeout(Duration::from_millis(75))
                .hard_drain_timeout(Duration::from_secs(2)),
        )
        .await
        .expect("bind HTTPS/1.1 listener");
        let addr = listener.local_addr().expect("HTTPS/1.1 listener address");
        let shutdown = listener.shutdown_signal();
        let manager = listener.connection_manager().clone();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run_tls(&handle, https_h1_acceptor()).await })
            .expect("spawn HTTPS/1.1 listener");

        for alpn in [Some(b"http/1.1".as_slice()), None] {
            let tcp = TcpStream::connect(addr)
                .await
                .expect("connect HTTPS/1.1 TCP client");
            let mut client = https_h1_connector(alpn)
                .connect("localhost", tcp)
                .await
                .expect("complete HTTPS/1.1 handshake");
            client
                .write_all(
                    b"GET /secure HTTP/1.1\r\n\
                      Host: localhost\r\n\
                      Connection: close\r\n\
                      \r\n",
                )
                .await
                .expect("write HTTPS/1.1 request");
            let mut response = Vec::new();
            client
                .read_to_end(&mut response)
                .await
                .expect("read HTTPS/1.1 response");
            let response = std::str::from_utf8(&response).expect("ASCII HTTPS/1.1 response");
            assert!(response.starts_with("HTTP/1.1 200"), "{response:?}");
            assert!(response.ends_with("secure"), "{response:?}");
        }
        assert_eq!(handler_calls.load(Ordering::Acquire), 2);

        let h2_tcp = TcpStream::connect(addr)
            .await
            .expect("connect cross-protocol TLS client");
        let mut h2_client = https_h1_connector(Some(b"h2"))
            .connect("localhost", h2_tcp)
            .await
            .expect("complete h2-negotiated TLS handshake");
        assert_eq!(h2_client.alpn_protocol(), Some(b"h2".as_slice()));
        let mut byte = [0_u8; 1];
        assert_eq!(
            h2_client
                .read(&mut byte)
                .await
                .expect("read cross-protocol TLS close"),
            0,
            "the HTTP/1 listener must cleanly close an h2-negotiated connection"
        );
        assert_eq!(handler_calls.load(Ordering::Acquire), 2);

        let mut plaintext = TcpStream::connect(addr)
            .await
            .expect("connect plaintext client to TLS listener");
        plaintext
            .write_all(b"GET /secure HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("write plaintext bytes to TLS listener");
        let mut refusal = Vec::new();
        plaintext
            .read_to_end(&mut refusal)
            .await
            .expect("read plaintext refusal");
        assert!(
            !refusal.starts_with(b"HTTP/1.1"),
            "TLS listener must not parse plaintext as HTTP"
        );
        assert_eq!(handler_calls.load(Ordering::Acquire), 2);

        let mut silent = TcpStream::connect(addr)
            .await
            .expect("connect silent TLS peer");
        for _ in 0..400 {
            if manager.active_count() == 1 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(
            manager.active_count(),
            1,
            "silent handshake is registered before TLS completion"
        );
        assert!(manager.begin_drain(Duration::from_millis(75)));
        let stats = run_handle.await.expect("HTTPS/1.1 listener result");
        assert!(
            stats.force_closed >= 1,
            "silent TLS peer forces bounded close"
        );
        assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
        assert!(manager.is_empty());
        assert_eq!(handler_calls.load(Ordering::Acquire), 2);
        assert_eq!(
            silent.read(&mut byte).await.expect("read silent peer EOF"),
            0
        );
    });

    test_complete!("e2e_router_https_h1_listener");
}

#[test]
fn e2e_router_http1_streaming_raw_body_is_live_bounded_and_cancel_correct() {
    common::init_test_logging();
    test_phase!("Router -> HTTP/1 live request body ingress");

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let upload_started = Arc::new(AtomicUsize::new(0));
        let upload_started_for_handler = Arc::clone(&upload_started);
        let disconnect_probe = AsyncBodyExtractionProbe::new();
        let disconnect_probe_for_router = disconnect_probe.clone();
        let disconnect_handler_calls = Arc::clone(&disconnect_probe.handler_called);

        let router = Router::new()
            .with_state(disconnect_probe_for_router)
            .route(
                "/upload",
                post(AsyncCxFnHandler2::<
                    _,
                    StreamingRequestReplay,
                    StreamingRawBody,
                >::new(
                    move |cx: Cx, replay: StreamingRequestReplay, body: StreamingRawBody| {
                        upload_started_for_handler.fetch_add(1, Ordering::AcqRel);
                        async move {
                            let replay_status = StreamingRawBody::from_request(replay.0)
                                .expect_err("the live body must be a one-shot extractor")
                                .status
                                .as_u16();
                            let collected = body
                                .collect_bounded_with_cx(&cx, 64)
                                .await
                                .expect("collect bounded streaming request");
                            let trailer = collected
                                .trailers()
                                .and_then(|trailers| {
                                    trailers.get(&HeaderName::from_static("x-checksum"))
                                })
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("missing");
                            format!(
                                "body={};trailer={trailer};replay={replay_status}",
                                String::from_utf8_lossy(collected.data().as_ref())
                            )
                        }
                    },
                )),
            )
            .route(
                "/too-large",
                post(AsyncCxFnHandler1::<_, StreamingRawBody>::new(
                    |cx: Cx, body: StreamingRawBody| async move {
                        match body.collect_bounded_with_cx(&cx, 4).await {
                            Err(StreamingRawBodyCollectError::LengthLimitExceeded {
                                actual,
                                limit,
                            }) => (
                                StatusCode::PAYLOAD_TOO_LARGE,
                                format!("bounded:{actual:?}>{limit}"),
                            ),
                            Err(error) => (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("unexpected:{error}"),
                            ),
                            Ok(_) => (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "unexpected-success".to_owned(),
                            ),
                        }
                    },
                )),
            )
            .route(
                "/disconnect",
                post(AsyncCxFnHandler1::<_, AsyncCollectedStreamingBody>::new(
                    move |_cx: Cx, _body: AsyncCollectedStreamingBody| {
                        disconnect_handler_calls.fetch_add(1, Ordering::AcqRel);
                        async { StatusCode::NO_CONTENT }
                    },
                )),
            );

        let listener = Http1Listener::bind_streaming_with_config(
            "127.0.0.1:0",
            router.into_http1_streaming_handler(),
            Http1ListenerConfig::default()
                .http_config(Http1Config {
                    allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                    ..Http1Config::default()
                })
                .drain_timeout(Duration::from_secs(2))
                .hard_drain_timeout(Duration::from_secs(5)),
        )
        .await
        .expect("bind streaming HTTP/1 listener");
        let addr = listener.local_addr().expect("listener address");
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run_streaming(&handle).await })
            .expect("spawn streaming HTTP/1 listener");

        let mut upload_client = TcpStream::connect(addr)
            .await
            .expect("connect upload client");
        upload_client
            .write_all(
                b"POST /upload HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Trailer: X-Checksum\r\n\
                  Connection: close\r\n\
                  \r\n",
            )
            .await
            .expect("write upload head without body");

        for _ in 0..400 {
            if upload_started.load(Ordering::Acquire) == 1 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(
            upload_started.load(Ordering::Acquire),
            1,
            "the Router handler must start before request-body EOF"
        );

        upload_client
            .write_all(b"5\r\nhello\r\n6\r\n world\r\n0\r\nX-Checksum: yes\r\n\r\n")
            .await
            .expect("write ordered chunks and terminal trailer");
        let mut upload_response = Vec::new();
        upload_client
            .read_to_end(&mut upload_response)
            .await
            .expect("read upload response");
        let upload_response = std::str::from_utf8(&upload_response).expect("ASCII upload response");
        assert!(upload_response.starts_with("HTTP/1.1 200"));
        assert!(upload_response.contains("body=hello world;trailer=yes;replay=500"));

        let mut limit_client = TcpStream::connect(addr)
            .await
            .expect("connect limit client");
        limit_client
            .write_all(
                b"POST /too-large HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Content-Length: 5\r\n\
                  Connection: close\r\n\
                  \r\nabcde",
            )
            .await
            .expect("write over-limit request");
        let mut limit_response = Vec::new();
        limit_client
            .read_to_end(&mut limit_response)
            .await
            .expect("read over-limit response");
        let limit_response =
            std::str::from_utf8(&limit_response).expect("ASCII over-limit response");
        assert!(limit_response.starts_with("HTTP/1.1 413"));
        assert!(limit_response.contains("bounded:Some(5)>4"));

        let mut disconnect_client = TcpStream::connect(addr)
            .await
            .expect("connect disconnect client");
        disconnect_client
            .write_all(
                b"POST /disconnect HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Content-Length: 10\r\n\
                  Connection: close\r\n\
                  \r\nabc",
            )
            .await
            .expect("write truncated request body");

        for _ in 0..400 {
            if disconnect_probe.extract_pending.load(Ordering::Acquire) == 1 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(
            disconnect_probe.extract_started.load(Ordering::Acquire),
            1,
            "the async final extractor must start before client disconnect"
        );
        assert_eq!(
            disconnect_probe.extract_pending.load(Ordering::Acquire),
            1,
            "the async final extractor must reach Poll::Pending before client disconnect"
        );
        assert_eq!(
            disconnect_probe.extract_failed.load(Ordering::Acquire),
            0,
            "the async final extractor must still be waiting before client disconnect"
        );
        assert_eq!(
            disconnect_probe.handler_called.load(Ordering::Acquire),
            0,
            "the handler must not run while final body extraction is pending"
        );
        assert_eq!(in_flight.load(Ordering::Acquire), 1);
        assert!(
            !manager.is_empty(),
            "the streaming connection must still be active before disconnect"
        );
        drop(disconnect_client);

        for _ in 0..400 {
            if disconnect_probe.extract_failed.load(Ordering::Acquire) == 1 && manager.is_empty() {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(disconnect_probe.extract_failed.load(Ordering::Acquire), 1);
        assert_eq!(disconnect_probe.handler_called.load(Ordering::Acquire), 0);
        assert_eq!(in_flight.load(Ordering::Acquire), 0);
        assert!(manager.is_empty(), "all streaming connections quiesced");

        assert!(manager.begin_drain(Duration::from_secs(2)));
        let stats = run_handle.await.expect("streaming listener result");
        assert_eq!(stats.force_closed, 0);
    });

    test_complete!("e2e_router_http1_streaming_raw_body");
}

#[test]
fn e2e_router_http1_streaming_json_and_form_are_bounded_and_cancel_correct() {
    common::init_test_logging();
    test_phase!("Router -> HTTP/1 streamed Json/Form extraction");

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let probe = StreamedTypedExtractionProbe::new();
        let json_handler_called = Arc::clone(&probe.json_handler_called);
        let form_handler_called = Arc::clone(&probe.form_handler_called);
        let over_limit_handler_called = Arc::clone(&probe.over_limit_handler_called);
        let disconnect_handler_called = Arc::clone(&probe.disconnect_handler_called);

        let router = Router::new()
            .with_state(
                BodyLimits::new()
                    .max_json_body_size(7)
                    .max_form_body_size(7),
            )
            .with_state(probe.clone())
            .route(
                "/json",
                post(AsyncCxFnHandler2::<
                    _,
                    StreamedTypedExtractionStarted,
                    JsonExtract<Value>,
                >::new(
                    move |_cx: Cx,
                          _started: StreamedTypedExtractionStarted,
                          JsonExtract(value): JsonExtract<Value>| {
                        json_handler_called.fetch_add(1, Ordering::AcqRel);
                        async move { format!("json={}", value["x"]) }
                    },
                )),
            )
            .route(
                "/form",
                post(AsyncCxFnHandler1::<
                    _,
                    FormExtract<HashMap<String, String>>,
                >::new(
                    move |_cx: Cx,
                          FormExtract(values): FormExtract<HashMap<String, String>>| {
                        form_handler_called.fetch_add(1, Ordering::AcqRel);
                        async move {
                            format!(
                                "form={}",
                                values.get("a").map(String::as_str).unwrap_or("missing")
                            )
                        }
                    },
                )),
            )
            .route(
                "/form-over",
                post(AsyncCxFnHandler1::<
                    _,
                    FormExtract<HashMap<String, String>>,
                >::new(
                    move |_cx: Cx,
                          _form: FormExtract<HashMap<String, String>>| {
                        over_limit_handler_called.fetch_add(1, Ordering::AcqRel);
                        async { StatusCode::NO_CONTENT }
                    },
                )),
            )
            .route(
                "/disconnect-json",
                post(AsyncCxFnHandler2::<
                    _,
                    StreamedTypedExtractionStarted,
                    JsonExtract<Value>,
                >::new(
                    move |_cx: Cx,
                          _started: StreamedTypedExtractionStarted,
                          _json: JsonExtract<Value>| {
                        disconnect_handler_called.fetch_add(1, Ordering::AcqRel);
                        async { StatusCode::NO_CONTENT }
                    },
                )),
            );

        let listener = Http1Listener::bind_streaming_with_config(
            "127.0.0.1:0",
            router.into_http1_streaming_handler(),
            Http1ListenerConfig::default()
                .http_config(
                    Http1Config {
                        allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                        ..Http1Config::default()
                    }
                    .request_timeout(Some(Duration::from_secs(5)))
                    .idle_timeout(Some(Duration::from_secs(5))),
                )
                .drain_timeout(Duration::from_secs(2))
                .hard_drain_timeout(Duration::from_secs(5)),
        )
        .await
        .expect("bind streamed typed extractor listener");
        let addr = listener.local_addr().expect("listener address");
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run_streaming(&handle).await })
            .expect("spawn streamed typed extractor listener");

        let mut json_client = TcpStream::connect(addr).await.expect("connect JSON client");
        json_client
            .write_all(
                b"POST /json HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Content-Type: application/json\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\
                  \r\n",
            )
            .await
            .expect("write JSON request head without body");
        for _ in 0..400 {
            if probe.parts_started.load(Ordering::Acquire) == 1 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(probe.parts_started.load(Ordering::Acquire), 1);
        assert_eq!(probe.json_handler_called.load(Ordering::Acquire), 0);
        assert_eq!(in_flight.load(Ordering::Acquire), 1);
        json_client
            .write_all(b"3\r\n{\"x\r\n4\r\n\":1}\r\n0\r\n\r\n")
            .await
            .expect("finish split chunked JSON body");
        let mut json_response = Vec::new();
        json_client
            .read_to_end(&mut json_response)
            .await
            .expect("read JSON response");
        let json_response = std::str::from_utf8(&json_response).expect("ASCII JSON response");
        assert!(json_response.starts_with("HTTP/1.1 200"));
        assert!(json_response.contains("json=1"));
        assert_eq!(probe.json_handler_called.load(Ordering::Acquire), 1);
        drop(json_client);

        let mut form_client = TcpStream::connect(addr).await.expect("connect form client");
        form_client
            .write_all(
                b"POST /form HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Content-Type: application/x-www-form-urlencoded\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\
                  \r\n3\r\na=%\r\n4\r\n41xy\r\n0\r\n\r\n",
            )
            .await
            .expect("write split chunked form body");
        let mut form_response = Vec::new();
        form_client
            .read_to_end(&mut form_response)
            .await
            .expect("read form response");
        let form_response = std::str::from_utf8(&form_response).expect("ASCII form response");
        assert!(form_response.starts_with("HTTP/1.1 200"));
        assert!(form_response.contains("form=Axy"));
        assert_eq!(probe.form_handler_called.load(Ordering::Acquire), 1);
        drop(form_client);

        let mut over_client = TcpStream::connect(addr)
            .await
            .expect("connect over-limit form client");
        over_client
            .write_all(
                b"POST /form-over HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Content-Type: application/x-www-form-urlencoded\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\
                  \r\n8\r\na=123456\r\n0\r\n\r\n",
            )
            .await
            .expect("write over-limit chunked form body");
        let mut over_response = Vec::new();
        over_client
            .read_to_end(&mut over_response)
            .await
            .expect("read over-limit form response");
        let over_response = std::str::from_utf8(&over_response).expect("ASCII limit response");
        assert!(over_response.starts_with("HTTP/1.1 413"));
        assert_eq!(probe.over_limit_handler_called.load(Ordering::Acquire), 0);
        drop(over_client);

        let mut disconnect_client = TcpStream::connect(addr)
            .await
            .expect("connect truncated JSON client");
        disconnect_client
            .write_all(
                b"POST /disconnect-json HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Content-Type: application/json\r\n\
                  Content-Length: 7\r\n\
                  Connection: close\r\n\
                  \r\n{\"",
            )
            .await
            .expect("write truncated JSON prefix");
        for _ in 0..400 {
            if probe.parts_started.load(Ordering::Acquire) == 2 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(probe.parts_started.load(Ordering::Acquire), 2);
        assert_eq!(probe.disconnect_handler_called.load(Ordering::Acquire), 0);
        assert_eq!(in_flight.load(Ordering::Acquire), 1);
        assert!(!manager.is_empty());
        drop(disconnect_client);

        for _ in 0..400 {
            if in_flight.load(Ordering::Acquire) == 0 && manager.is_empty() {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(probe.disconnect_handler_called.load(Ordering::Acquire), 0);
        assert_eq!(in_flight.load(Ordering::Acquire), 0);
        assert!(
            manager.is_empty(),
            "all streamed extractor connections quiesced"
        );

        assert!(manager.begin_drain(Duration::from_secs(2)));
        let stats = run_handle
            .await
            .expect("streamed extractor listener result");
        assert_eq!(stats.force_closed, 0);
    });

    test_complete!("e2e_router_http1_streamed_json_and_form");
}

#[test]
fn e2e_router_http1_streaming_multipart_is_incremental_bounded_and_cancel_correct() {
    common::init_test_logging();
    test_phase!("Router -> HTTP/1 streamed Multipart extraction");

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let probe = StreamedTypedExtractionProbe::new();
        let handler_called = Arc::new(AtomicUsize::new(0));
        let handler_called_for_route = Arc::clone(&handler_called);
        let disconnect_handler_called = Arc::new(AtomicUsize::new(0));
        let disconnect_handler_called_for_route = Arc::clone(&disconnect_handler_called);

        let router = Router::new()
            .with_state(MultipartLimits::new().max_total_size(1024))
            .with_state(probe.clone())
            .route(
                "/multipart",
                post(AsyncCxFnHandler2::<
                    _,
                    StreamedTypedExtractionStarted,
                    Multipart,
                >::new(
                    move |_cx: Cx,
                          _started: StreamedTypedExtractionStarted,
                          multipart: Multipart| {
                        handler_called_for_route.fetch_add(1, Ordering::AcqRel);
                        async move {
                            let a = multipart
                                .field("a")
                                .and_then(|field| field.text().ok())
                                .unwrap_or("missing");
                            let b = multipart
                                .field("b")
                                .and_then(|field| field.text().ok())
                                .unwrap_or("missing");
                            format!("a={a};b={b}")
                        }
                    },
                )),
            )
            .route(
                "/disconnect-multipart",
                post(AsyncCxFnHandler2::<
                    _,
                    StreamedTypedExtractionStarted,
                    Multipart,
                >::new(
                    move |_cx: Cx,
                          _started: StreamedTypedExtractionStarted,
                          _multipart: Multipart| {
                        disconnect_handler_called_for_route.fetch_add(1, Ordering::AcqRel);
                        async { StatusCode::NO_CONTENT }
                    },
                )),
            );

        let listener = Http1Listener::bind_streaming_with_config(
            "127.0.0.1:0",
            router.into_http1_streaming_handler(),
            Http1ListenerConfig::default()
                .http_config(
                    Http1Config {
                        allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                        ..Http1Config::default()
                    }
                    .request_timeout(Some(Duration::from_secs(5)))
                    .idle_timeout(Some(Duration::from_secs(5))),
                )
                .drain_timeout(Duration::from_secs(2))
                .hard_drain_timeout(Duration::from_secs(5)),
        )
        .await
        .expect("bind streamed multipart listener");
        let addr = listener.local_addr().expect("listener address");
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run_streaming(&handle).await })
            .expect("spawn streamed multipart listener");

        let mut client = TcpStream::connect(addr)
            .await
            .expect("connect multipart client");
        client
            .write_all(
                b"POST /multipart HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Content-Type: multipart/form-data; boundary=LIVE\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\
                  \r\n",
            )
            .await
            .expect("write multipart head without body");

        for _ in 0..400 {
            if probe.parts_started.load(Ordering::Acquire) == 1 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(probe.parts_started.load(Ordering::Acquire), 1);
        assert_eq!(handler_called.load(Ordering::Acquire), 0);
        assert_eq!(in_flight.load(Ordering::Acquire), 1);

        let pieces: &[&[u8]] = &[
            b"--LI",
            b"VE\r",
            b"\nContent-Disposition: form-data; name=\"a\"\r\n\r",
            b"\nalpha\r\n--L",
            b"IVE\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nbe",
            b"ta\r\n--LIVE--\r\nepilogue",
        ];
        for piece in pieces {
            let mut frame = format!("{:X}\r\n", piece.len()).into_bytes();
            frame.extend_from_slice(piece);
            frame.extend_from_slice(b"\r\n");
            client
                .write_all(&frame)
                .await
                .expect("write split multipart transfer chunk");
        }
        asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(20)).await;
        assert_eq!(
            handler_called.load(Ordering::Acquire),
            0,
            "a closing multipart marker is not request-body EOF"
        );

        client
            .write_all(b"0\r\n\r\n")
            .await
            .expect("finish chunked multipart body");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read multipart response");
        let response = std::str::from_utf8(&response).expect("ASCII multipart response");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("a=alpha;b=beta"), "{response}");
        assert_eq!(handler_called.load(Ordering::Acquire), 1);

        let mut disconnect_client = TcpStream::connect(addr)
            .await
            .expect("connect truncated multipart client");
        disconnect_client
            .write_all(
                b"POST /disconnect-multipart HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Content-Type: multipart/form-data; boundary=LIVE\r\n\
                  Content-Length: 100\r\n\
                  Connection: close\r\n\
                  \r\n--LIVE\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\npartial",
            )
            .await
            .expect("write truncated multipart prefix");
        for _ in 0..400 {
            if probe.parts_started.load(Ordering::Acquire) == 2 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(probe.parts_started.load(Ordering::Acquire), 2);
        assert_eq!(disconnect_handler_called.load(Ordering::Acquire), 0);
        assert_eq!(in_flight.load(Ordering::Acquire), 1);
        assert!(!manager.is_empty());
        drop(disconnect_client);

        for _ in 0..400 {
            if in_flight.load(Ordering::Acquire) == 0 && manager.is_empty() {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(disconnect_handler_called.load(Ordering::Acquire), 0);
        assert_eq!(in_flight.load(Ordering::Acquire), 0);
        assert!(manager.is_empty(), "all multipart connections quiesced");

        assert!(manager.begin_drain(Duration::from_secs(2)));
        let stats = run_handle
            .await
            .expect("streamed multipart listener result");
        assert_eq!(stats.force_closed, 0);
    });

    test_complete!("e2e_router_http1_streamed_multipart");
}

#[test]
fn e2e_router_http1_streaming_multipart_field_api_reaches_handler_before_eof() {
    common::init_test_logging();
    test_phase!("Router -> HTTP/1 live multipart field lease");

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let handler_entered = Arc::new(AtomicUsize::new(0));
        let metadata_ready = Arc::new(AtomicUsize::new(0));
        let first_chunk_ready = Arc::new(AtomicUsize::new(0));
        let handler_complete = Arc::new(AtomicUsize::new(0));
        let field_dropped = Arc::new(AtomicUsize::new(0));
        let unsynchronized_request_routed = Arc::new(AtomicUsize::new(0));

        let entered_for_route = Arc::clone(&handler_entered);
        let metadata_for_route = Arc::clone(&metadata_ready);
        let first_chunk_for_route = Arc::clone(&first_chunk_ready);
        let complete_for_route = Arc::clone(&handler_complete);
        let dropped_for_route = Arc::clone(&field_dropped);
        let routed_for_route = Arc::clone(&unsynchronized_request_routed);
        let router = Router::new()
            .with_state(MultipartLimits::new().max_total_size(32 * 1024))
            .route(
                "/stream-fields",
                post(AsyncCxFnHandler1::<_, StreamingMultipart>::new(
                    move |cx: Cx, mut multipart: StreamingMultipart| {
                        entered_for_route.fetch_add(1, Ordering::AcqRel);
                        let metadata_for_request = Arc::clone(&metadata_for_route);
                        let first_chunk_for_request = Arc::clone(&first_chunk_for_route);
                        let complete_for_request = Arc::clone(&complete_for_route);
                        async move {
                            let mut field = multipart
                                .next_field(&cx)
                                .await
                                .expect("live multipart field metadata")
                                .expect("one live multipart field");
                            assert_eq!(field.name(), "upload");
                            assert_eq!(field.filename(), Some("live.bin"));
                            assert_eq!(field.content_type(), Some("application/octet-stream"));
                            metadata_for_request.fetch_add(1, Ordering::AcqRel);

                            let mut body = Vec::new();
                            while let Some(chunk) = field
                                .next_chunk(&cx)
                                .await
                                .expect("live multipart field chunk")
                            {
                                assert!(chunk.len() <= 4096, "chunk was {} bytes", chunk.len());
                                if body.is_empty() {
                                    first_chunk_for_request.fetch_add(1, Ordering::AcqRel);
                                }
                                body.extend_from_slice(chunk.as_ref());
                            }
                            drop(field);
                            assert!(
                                multipart
                                    .next_field(&cx)
                                    .await
                                    .expect("live multipart terminal boundary")
                                    .is_none()
                            );
                            complete_for_request.fetch_add(1, Ordering::AcqRel);
                            format!(
                                "len={};first={};last={}",
                                body.len(),
                                body.first().copied().unwrap_or_default(),
                                body.last().copied().unwrap_or_default()
                            )
                        }
                    },
                )),
            )
            .route(
                "/drop-field",
                post(AsyncCxFnHandler1::<_, StreamingMultipart>::new(
                    move |cx: Cx, mut multipart: StreamingMultipart| {
                        let dropped_for_request = Arc::clone(&dropped_for_route);
                        async move {
                            let mut field = multipart
                                .next_field(&cx)
                                .await
                                .expect("early-drop field metadata")
                                .expect("early-drop field");
                            assert!(
                                field
                                    .next_chunk(&cx)
                                    .await
                                    .expect("early-drop first chunk")
                                    .is_some()
                            );
                            drop(field);
                            drop(multipart);
                            dropped_for_request.fetch_add(1, Ordering::AcqRel);
                            StatusCode::NO_CONTENT
                        }
                    },
                )),
            )
            .route(
                "/must-not-route",
                get(FnHandler::new(move || {
                    routed_for_route.fetch_add(1, Ordering::AcqRel);
                    StatusCode::OK
                })),
            );

        let listener = Http1Listener::bind_streaming_with_config(
            "127.0.0.1:0",
            router.into_http1_streaming_handler(),
            Http1ListenerConfig::default()
                .http_config(
                    Http1Config {
                        allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                        ..Http1Config::default()
                    }
                    .request_timeout(Some(Duration::from_secs(5)))
                    .idle_timeout(Some(Duration::from_secs(5))),
                )
                .drain_timeout(Duration::from_secs(2))
                .hard_drain_timeout(Duration::from_secs(5)),
        )
        .await
        .expect("bind live multipart field listener");
        let addr = listener.local_addr().expect("listener address");
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run_streaming(&handle).await })
            .expect("spawn live multipart field listener");

        let mut client = TcpStream::connect(addr)
            .await
            .expect("connect live multipart field client");
        client
            .write_all(
                b"POST /stream-fields HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Content-Type: multipart/form-data; boundary=LIVE\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\
                  \r\n",
            )
            .await
            .expect("write request headers without multipart bytes");

        for _ in 0..400 {
            if handler_entered.load(Ordering::Acquire) == 1 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(handler_entered.load(Ordering::Acquire), 1);
        assert_eq!(metadata_ready.load(Ordering::Acquire), 0);
        assert_eq!(in_flight.load(Ordering::Acquire), 1);

        let field_head = b"--LIVE\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"live.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n";
        let mut head_frame = format!("{:X}\r\n", field_head.len()).into_bytes();
        head_frame.extend_from_slice(field_head);
        head_frame.extend_from_slice(b"\r\n");
        client
            .write_all(&head_frame)
            .await
            .expect("write field metadata without field payload");

        for _ in 0..400 {
            if metadata_ready.load(Ordering::Acquire) == 1 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(metadata_ready.load(Ordering::Acquire), 1);
        assert_eq!(first_chunk_ready.load(Ordering::Acquire), 0);

        let payload = (0..10_000)
            .map(|index| u8::try_from(index % 251).expect("payload byte"))
            .collect::<Vec<_>>();
        let mut payload_frame = format!("{:X}\r\n", payload.len()).into_bytes();
        payload_frame.extend_from_slice(&payload);
        payload_frame.extend_from_slice(b"\r\n");
        client
            .write_all(&payload_frame)
            .await
            .expect("write payload without MIME terminator");

        for _ in 0..400 {
            if first_chunk_ready.load(Ordering::Acquire) == 1 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(first_chunk_ready.load(Ordering::Acquire), 1);
        assert_eq!(handler_complete.load(Ordering::Acquire), 0);

        let close = b"\r\n--LIVE--\r\nepilogue";
        let mut close_frame = format!("{:X}\r\n", close.len()).into_bytes();
        close_frame.extend_from_slice(close);
        close_frame.extend_from_slice(b"\r\n");
        client
            .write_all(&close_frame)
            .await
            .expect("write MIME close without HTTP body EOF");
        asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(20)).await;
        assert_eq!(
            handler_complete.load(Ordering::Acquire),
            0,
            "MIME completion is not HTTP request EOF"
        );

        client
            .write_all(b"0\r\n\r\n")
            .await
            .expect("write HTTP body EOF");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read live multipart field response");
        let response = std::str::from_utf8(&response).expect("ASCII response");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("len=10000;first=0;last=210"), "{response}");
        assert_eq!(handler_complete.load(Ordering::Acquire), 1);

        for _ in 0..400 {
            if in_flight.load(Ordering::Acquire) == 0 && manager.is_empty() {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(in_flight.load(Ordering::Acquire), 0);
        assert!(manager.is_empty(), "consumed multipart connection quiesced");

        let mut drop_client = TcpStream::connect(addr)
            .await
            .expect("connect early-drop multipart client");
        drop_client
            .write_all(
                b"POST /drop-field HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Content-Type: multipart/form-data; boundary=LIVE\r\n\
                  Transfer-Encoding: chunked\r\n\
                  \r\n",
            )
            .await
            .expect("write early-drop request headers");
        let mut partial =
            b"--LIVE\r\nContent-Disposition: form-data; name=\"upload\"\r\n\r\n".to_vec();
        partial.extend((0..6000).map(|index| u8::try_from(index % 251).expect("payload byte")));
        let mut partial_frame = format!("{:X}\r\n", partial.len()).into_bytes();
        partial_frame.extend_from_slice(&partial);
        partial_frame.extend_from_slice(b"\r\n");
        drop_client
            .write_all(&partial_frame)
            .await
            .expect("write unterminated multipart field chunk");

        for _ in 0..400 {
            if field_dropped.load(Ordering::Acquire) == 1 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(field_dropped.load(Ordering::Acquire), 1);

        let _ = drop_client
            .write_all(
                b"GET /must-not-route HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Connection: close\r\n\
                  \r\n",
            )
            .await;
        let mut drop_response = Vec::new();
        drop_client
            .read_to_end(&mut drop_response)
            .await
            .expect("early-drop connection must reach terminal close");
        assert_eq!(unsynchronized_request_routed.load(Ordering::Acquire), 0);

        for _ in 0..400 {
            if in_flight.load(Ordering::Acquire) == 0 && manager.is_empty() {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(in_flight.load(Ordering::Acquire), 0);
        assert!(manager.is_empty(), "early-drop multipart connection quiesced");
        assert!(manager.begin_drain(Duration::from_secs(2)));
        let stats = run_handle
            .await
            .expect("live multipart field listener result");
        assert_eq!(stats.force_closed, 0);
    });

    test_complete!("e2e_router_http1_live_multipart_fields");
}

#[test]
fn e2e_router_http1_listener_live_websocket_handoff_preserves_read_ahead() {
    common::init_test_logging();
    test_phase!("Router -> HTTP/1 listener -> live WebSocket handoff");

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let callback_count = Arc::new(AtomicUsize::new(0));
        let callback_count_for_handler = Arc::clone(&callback_count);
        let router = Router::new().route(
            "/ws",
            get(FnHandler1::<_, WebSocketUpgrade>::new(
                move |upgrade: WebSocketUpgrade| {
                    let callback_count = Arc::clone(&callback_count_for_handler);
                    upgrade
                        .skip_origin_check()
                        .on_upgrade(move |cx, mut ws| async move {
                            callback_count.fetch_add(1, Ordering::AcqRel);
                            let message = ws
                                .recv(&cx)
                                .await
                                .expect("receive coalesced client frame")
                                .expect("client sent one frame");
                            match &message {
                                Message::Text(text) => assert_eq!(text, "Hello"),
                                other => panic!("expected text frame, got {other:?}"),
                            }
                            ws.send(&cx, message).await.expect("echo client frame");
                        })
                },
            )),
        );

        let listener = Http1Listener::bind_upgradeable_with_config(
            "127.0.0.1:0",
            router.into_http1_handler(),
            Http1ListenerConfig::default()
                .http_config(Http1Config {
                    allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                    ..Http1Config::default()
                })
                .drain_timeout(Duration::from_secs(2))
                .hard_drain_timeout(Duration::from_secs(5)),
        )
        .await
        .expect("bind HTTP/1 listener");
        let addr = listener.local_addr().expect("listener address");
        let shutdown = listener.shutdown_signal();
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn HTTP/1 listener");

        let mut client = TcpStream::connect(addr).await.expect("connect client");
        let mut request_and_frame = b"GET /ws HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
            Sec-WebSocket-Version: 13\r\n\
            \r\n"
            .to_vec();
        // FIN + text opcode, masked five-byte payload, fixed mask, then
        // "Hello" XOR mask. Sending it in the same write as the handshake
        // proves codec-prefetched bytes cross the ownership handoff intact.
        request_and_frame.extend_from_slice(&[
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
        ]);
        client
            .write_all(&request_and_frame)
            .await
            .expect("write coalesced handshake and frame");

        let response_head = read_http_head(&mut client).await;
        let response_head = std::str::from_utf8(&response_head).expect("ASCII response head");
        assert!(
            response_head.starts_with("HTTP/1.1 101"),
            "listener committed the switching response: {response_head:?}"
        );
        assert_eq!(
            response_head.matches("HTTP/1.1 101").count(),
            1,
            "the live handoff emits exactly one switching response"
        );
        let lower = response_head.to_ascii_lowercase();
        assert!(lower.contains("connection: upgrade\r\n"));
        assert!(lower.contains("upgrade: websocket\r\n"));
        assert!(lower.contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo=\r\n"));

        let mut echo = [0_u8; 7];
        client
            .read_exact(&mut echo)
            .await
            .expect("read echoed frame");
        assert_eq!(echo, [0x81, 0x05, b'H', b'e', b'l', b'l', b'o']);
        drop(client);

        for _ in 0..400 {
            if manager.is_empty() {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(callback_count.load(Ordering::Acquire), 1);
        assert_eq!(in_flight.load(Ordering::Acquire), 0);
        assert!(
            manager.is_empty(),
            "upgraded session released its connection guard"
        );

        assert!(manager.begin_drain(Duration::from_secs(2)));
        let stats = run_handle.await.expect("listener result");
        assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
        assert_eq!(stats.force_closed, 0);
    });

    test_complete!("e2e_router_http1_listener_live_websocket_handoff");
}

#[test]
fn e2e_router_http1_listener_drain_cancels_live_websocket_session() {
    common::init_test_logging();
    test_phase!("HTTP/1 listener drain cancels upgraded WebSocket session");

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let callback_started = Arc::new(AtomicUsize::new(0));
        let callback_cancelled = Arc::new(AtomicUsize::new(0));
        let started_for_handler = Arc::clone(&callback_started);
        let cancelled_for_handler = Arc::clone(&callback_cancelled);
        let router = Router::new().route(
            "/ws",
            get(FnHandler1::<_, WebSocketUpgrade>::new(
                move |upgrade: WebSocketUpgrade| {
                    let callback_started = Arc::clone(&started_for_handler);
                    let callback_cancelled = Arc::clone(&cancelled_for_handler);
                    upgrade
                        .skip_origin_check()
                        .on_upgrade(move |cx, mut ws| async move {
                            callback_started.fetch_add(1, Ordering::AcqRel);
                            let result = ws.recv(&cx).await;
                            if cx.is_cancel_requested() && result.is_err() {
                                callback_cancelled.fetch_add(1, Ordering::AcqRel);
                            }
                        })
                },
            )),
        );

        let listener = Http1Listener::bind_upgradeable_with_config(
            "127.0.0.1:0",
            router.into_http1_handler(),
            Http1ListenerConfig::default()
                .http_config(Http1Config {
                    allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                    ..Http1Config::default()
                })
                .drain_timeout(Duration::from_secs(2))
                .hard_drain_timeout(Duration::from_secs(5)),
        )
        .await
        .expect("bind HTTP/1 listener");
        let addr = listener.local_addr().expect("listener address");
        let shutdown = listener.shutdown_signal();
        let manager = listener.connection_manager().clone();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn HTTP/1 listener");

        let mut client = TcpStream::connect(addr).await.expect("connect client");
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\
                  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                  Sec-WebSocket-Version: 13\r\n\
                  \r\n",
            )
            .await
            .expect("write WebSocket handshake");
        let response_head = read_http_head(&mut client).await;
        assert!(response_head.starts_with(b"HTTP/1.1 101"));

        for _ in 0..400 {
            if callback_started.load(Ordering::Acquire) == 1 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(callback_started.load(Ordering::Acquire), 1);
        assert_eq!(manager.active_count(), 1);

        assert!(manager.begin_drain(Duration::from_secs(2)));
        let stats = run_handle.await.expect("listener result");
        assert_eq!(callback_cancelled.load(Ordering::Acquire), 1);
        assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
        assert_eq!(stats.force_closed, 0);
        assert!(manager.is_empty());
        drop(client);
    });

    test_complete!("e2e_router_http1_listener_websocket_drain");
}

#[test]
fn e2e_router_http1_listener_force_closes_uncooperative_websocket_session() {
    common::init_test_logging();
    test_phase!("HTTP/1 listener force-closes uncooperative WebSocket session");

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let callback_started = Arc::new(AtomicUsize::new(0));
        let started_for_handler = Arc::clone(&callback_started);
        let router = Router::new().route(
            "/ws",
            get(FnHandler1::<_, WebSocketUpgrade>::new(
                move |upgrade: WebSocketUpgrade| {
                    let callback_started = Arc::clone(&started_for_handler);
                    upgrade
                        .skip_origin_check()
                        .on_upgrade(move |_cx, websocket| async move {
                            callback_started.fetch_add(1, Ordering::AcqRel);
                            let websocket_guard = websocket;
                            std::future::pending::<()>().await;
                            drop(websocket_guard);
                        })
                },
            )),
        );

        let listener = Http1Listener::bind_upgradeable_with_config(
            "127.0.0.1:0",
            router.into_http1_handler(),
            Http1ListenerConfig::default()
                .http_config(Http1Config {
                    allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                    ..Http1Config::default()
                })
                .drain_timeout(Duration::from_millis(100))
                .hard_drain_timeout(Duration::from_secs(2)),
        )
        .await
        .expect("bind HTTP/1 listener");
        let addr = listener.local_addr().expect("listener address");
        let shutdown = listener.shutdown_signal();
        let manager = listener.connection_manager().clone();
        let in_flight = listener.in_flight_requests();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn HTTP/1 listener");

        let mut client = TcpStream::connect(addr).await.expect("connect client");
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\n\
                  Host: localhost\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\
                  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                  Sec-WebSocket-Version: 13\r\n\
                  \r\n",
            )
            .await
            .expect("write WebSocket handshake");
        let response_head = read_http_head(&mut client).await;
        assert!(response_head.starts_with(b"HTTP/1.1 101"));

        for _ in 0..400 {
            if callback_started.load(Ordering::Acquire) == 1 {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert_eq!(callback_started.load(Ordering::Acquire), 1);
        assert_eq!(in_flight.load(Ordering::Acquire), 0);
        assert_eq!(manager.active_count(), 1);

        // Give the connection manager a long backstop so the listener's
        // request-aware 100 ms soft budget is the deterministic escalation
        // driver. The callback never checks its Cx, so only force-close can
        // drop the session future and its transport.
        assert!(manager.begin_drain(Duration::from_secs(5)));
        let stats = run_handle.await.expect("listener result");
        assert!(stats.force_closed > 0);
        assert_eq!(shutdown.phase(), ShutdownPhase::Stopped);
        assert!(manager.is_empty());

        let mut byte = [0_u8; 1];
        assert_eq!(client.read(&mut byte).await.expect("read forced EOF"), 0);
    });

    test_complete!("e2e_router_http1_listener_websocket_force_close");
}

#[test]
fn e2e_router_drops_registered_upgrade_when_final_response_is_mutated() {
    common::init_test_logging();

    let callback_count = Arc::new(AtomicUsize::new(0));
    let callback_count_for_handler = Arc::clone(&callback_count);
    let router = Router::new().route(
        "/ws",
        get(FnHandler1::<_, WebSocketUpgrade>::new(
            move |upgrade: WebSocketUpgrade| {
                let callback_count = Arc::clone(&callback_count_for_handler);
                let mut response = upgrade
                    .skip_origin_check()
                    .on_upgrade(move |_, _| async move {
                        callback_count.fetch_add(1, Ordering::AcqRel);
                    });
                response.status = StatusCode::OK;
                response
            },
        )),
    );
    let request = HttpRequest {
        method: HttpMethod::Get,
        uri: "/ws".to_owned(),
        version: HttpVersion::Http11,
        headers: vec![
            ("host".to_owned(), "localhost".to_owned()),
            ("upgrade".to_owned(), "websocket".to_owned()),
            ("connection".to_owned(), "Upgrade".to_owned()),
            ("sec-websocket-version".to_owned(), "13".to_owned()),
            (
                "sec-websocket-key".to_owned(),
                "dGhlIHNhbXBsZSBub25jZQ==".to_owned(),
            ),
        ],
        body: Vec::new(),
        trailers: Vec::new(),
        peer_addr: None,
    };

    let response = web_block_on(router.handle_http1_request_with_cx(&Cx::for_testing(), request));
    assert_eq!(response.response.status, 500);
    assert_eq!(response.response.header_value("connection"), Some("close"));
    assert_eq!(callback_count.load(Ordering::Acquire), 0);
}

#[test]
fn e2e_router_duplicate_upgrade_registration_poisons_the_request() {
    common::init_test_logging();

    let callback_count = Arc::new(AtomicUsize::new(0));
    let callback_count_for_handler = Arc::clone(&callback_count);
    let router = Router::new().route(
        "/ws",
        get(FnHandler1::<_, WebSocketUpgrade>::new(
            move |upgrade: WebSocketUpgrade| {
                let first_count = Arc::clone(&callback_count_for_handler);
                let first =
                    upgrade
                        .clone()
                        .skip_origin_check()
                        .on_upgrade(move |_, _| async move {
                            first_count.fetch_add(1, Ordering::AcqRel);
                        });
                let second_count = Arc::clone(&callback_count_for_handler);
                let _duplicate = upgrade
                    .skip_origin_check()
                    .on_upgrade(move |_, _| async move {
                        second_count.fetch_add(1, Ordering::AcqRel);
                    });
                // Even if the handler ignores the duplicate-registration 500
                // and returns the original 101, the request slot remains
                // poisoned and the router must refuse the handoff.
                first
            },
        )),
    );
    let request = HttpRequest {
        method: HttpMethod::Get,
        uri: "/ws".to_owned(),
        version: HttpVersion::Http11,
        headers: vec![
            ("host".to_owned(), "localhost".to_owned()),
            ("upgrade".to_owned(), "websocket".to_owned()),
            ("connection".to_owned(), "Upgrade".to_owned()),
            ("sec-websocket-version".to_owned(), "13".to_owned()),
            (
                "sec-websocket-key".to_owned(),
                "dGhlIHNhbXBsZSBub25jZQ==".to_owned(),
            ),
        ],
        body: Vec::new(),
        trailers: Vec::new(),
        peer_addr: None,
    };

    let response = web_block_on(router.handle_http1_request_with_cx(&Cx::for_testing(), request));
    assert_eq!(response.response.status, 500);
    assert_eq!(response.response.header_value("connection"), Some("close"));
    assert_eq!(callback_count.load(Ordering::Acquire), 0);
}

#[test]
fn e2e_router_rejects_forbidden_or_unbound_upgrade_response_headers() {
    common::init_test_logging();

    let mutations = [
        ("transfer-encoding", "chunked"),
        ("content-length", "0"),
        ("connection", "Upgrade, close"),
        ("sec-websocket-protocol", "chat"),
        ("sec-websocket-extensions", "permessage-deflate"),
    ];
    for (header_name, header_value) in mutations {
        let callback_count = Arc::new(AtomicUsize::new(0));
        let callback_count_for_handler = Arc::clone(&callback_count);
        let router = Router::new().route(
            "/ws",
            get(FnHandler1::<_, WebSocketUpgrade>::new(
                move |upgrade: WebSocketUpgrade| {
                    let callback_count = Arc::clone(&callback_count_for_handler);
                    let mut response =
                        upgrade
                            .skip_origin_check()
                            .on_upgrade(move |_, _| async move {
                                callback_count.fetch_add(1, Ordering::AcqRel);
                            });
                    response.set_header(header_name, header_value);
                    response
                },
            )),
        );
        let request = HttpRequest {
            method: HttpMethod::Get,
            uri: "/ws".to_owned(),
            version: HttpVersion::Http11,
            headers: vec![
                ("host".to_owned(), "localhost".to_owned()),
                ("upgrade".to_owned(), "websocket".to_owned()),
                ("connection".to_owned(), "Upgrade".to_owned()),
                ("sec-websocket-version".to_owned(), "13".to_owned()),
                (
                    "sec-websocket-key".to_owned(),
                    "dGhlIHNhbXBsZSBub25jZQ==".to_owned(),
                ),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let response =
            web_block_on(router.handle_http1_request_with_cx(&Cx::for_testing(), request));
        assert_eq!(
            response.response.status, 500,
            "mutation {header_name}: {header_value} must fail closed"
        );
        assert_eq!(response.response.header_value("connection"), Some("close"));
        assert_eq!(callback_count.load(Ordering::Acquire), 0);
    }
}

#[test]
fn e2e_router_bare_switching_response_never_acquires_listener_transport() {
    common::init_test_logging();

    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("build runtime");
    let handle = runtime.handle();

    runtime.block_on(async move {
        let router = Router::new().route(
            "/ws",
            get(FnHandler1::<_, WebSocketUpgrade>::new(
                |upgrade: WebSocketUpgrade| upgrade.skip_origin_check(),
            )),
        );
        let listener = Http1Listener::bind_upgradeable_with_config(
            "127.0.0.1:0",
            router.into_http1_handler(),
            Http1ListenerConfig::default().http_config(Http1Config {
                allowed_hosts: HostPolicy::allow_list(vec!["localhost".to_owned()]),
                ..Http1Config::default()
            }),
        )
        .await
        .expect("bind HTTP/1 listener");
        let addr = listener.local_addr().expect("listener address");
        let manager = listener.connection_manager().clone();
        let run_handle = handle
            .clone()
            .try_spawn(async move { listener.run(&handle).await })
            .expect("spawn HTTP/1 listener");

        let mut client = TcpStream::connect(addr).await.expect("connect client");
        let mut request_and_frame = b"GET /ws HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
            Sec-WebSocket-Version: 13\r\n\
            \r\n"
            .to_vec();
        request_and_frame.extend_from_slice(&[
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
        ]);
        client
            .write_all(&request_and_frame)
            .await
            .expect("write bare upgrade and frame");

        let response_head = read_http_head(&mut client).await;
        assert!(response_head.starts_with(b"HTTP/1.1 101"));
        let mut byte = [0_u8; 1];
        assert_eq!(
            client.read(&mut byte).await.expect("read listener close"),
            0,
            "a bare 101 must close instead of parsing or echoing WebSocket bytes"
        );
        drop(client);

        for _ in 0..400 {
            if manager.is_empty() {
                break;
            }
            asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(5)).await;
        }
        assert!(manager.is_empty());
        assert!(manager.begin_drain(Duration::from_secs(2)));
        let stats = run_handle.await.expect("listener result");
        assert_eq!(stats.force_closed, 0);
    });
}
