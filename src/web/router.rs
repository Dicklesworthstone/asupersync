//! HTTP router with method-based dispatch.
//!
//! # Routing
//!
//! Routes map URL patterns to handlers. Path parameters are denoted with `:param`.
//!
//! ```ignore
//! let app = Router::new()
//!     .route("/", get(index))
//!     .route("/users", get(list_users).post(create_user))
//!     .route("/users/:id", get(get_user).delete(delete_user))
//!     .nest("/api/v1", api_v1_routes());
//! ```

use std::collections::HashMap;
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use std::task::{Context as TaskContext, Poll, Waker};
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use std::time::Duration;

use smallvec::SmallVec;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use super::WebBodyDiagnostic;
use super::extract::{BodyLimits, Extensions, ExtractionError, Request, parse_content_length};
#[cfg(not(target_arch = "wasm32"))]
use super::extract::{
    StreamingRawBodyControl, insert_streaming_raw_body, tighten_streaming_raw_body,
};
use super::handler::Handler;
use super::middleware::{
    RequestLogSink, RequestTracePolicy, resolve_trace_id, trace_request, wall_clock_now,
};
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use super::request_region::{
    RequestBudgetSource, ServerHopOutcome, ServerProducerCancellation, ServerRequestRegion,
    classify_server_producer_cancellation,
};
#[cfg(not(target_arch = "wasm32"))]
use super::response::{
    Http1StreamPlan, Http1StreamSlot, Http2StreamPlan, Http2StreamSlot, sanitize_header_name,
};
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use super::response::{
    Http3ProducerTerminal, Http3StreamPlan, Http3StreamProducer, Http3StreamSlot,
};
use super::response::{IntoResponse, Response, StatusCode};
#[cfg(not(target_arch = "wasm32"))]
use super::websocket::Http1UpgradeSlot;
use super::{EnforcedRequestBodyPolicy, RequestBodyPolicy, multipart::MultipartLimits};
use crate::Cx;
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use crate::bytes::Bytes;
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use crate::http::body::{Body, Frame as BodyFrame};
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use crate::http::h1::OutgoingBody;
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h1::server::{Http1Response, Http1Upgrade};
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h1::stream::{Http1ProducedResponse, StreamingServerRequest};
use crate::http::h1::types::{Request as HttpRequest, Response as HttpResponse};
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h2::listener::Http2ProducedResponse;
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use crate::http::h3::{
    H3Error, H3RequestHead, H3ResponseHead, NativeH3Event, NativeH3ResponseWriter, NativeH3Session,
    NativeH3WriteEvent, h3_data_frame_wire_len,
};
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use crate::net::quic_native::{
    NativeQuicConnectionError, QuicConnection, QuicConnectionState, QuicStreamError, StreamId,
};
use crate::service::Layer;
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use crate::tracing_compat::error;
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use crate::types::CancelKind;
use crate::types::{
    Budget, Time,
    id::{next_bootstrap_region_id, next_bootstrap_task_id},
};

// ─── Method Constants ────────────────────────────────────────────────────────

const METHOD_GET: &str = "GET";
const METHOD_POST: &str = "POST";
const METHOD_PUT: &str = "PUT";
const METHOD_DELETE: &str = "DELETE";
const METHOD_PATCH: &str = "PATCH";
const METHOD_HEAD: &str = "HEAD";
const METHOD_OPTIONS: &str = "OPTIONS";
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
const METHOD_CONNECT: &str = "CONNECT";

/// Public route metadata returned by [`Router::routes`].
///
/// Each value represents one concrete method handler. A route registered with
/// `get(...).post(...)` therefore produces two entries with the same pattern
/// and different methods.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RouteInfo {
    /// HTTP method handled by this route entry.
    pub method: String,
    /// Full route pattern, including any nested router mount prefix.
    pub pattern: String,
    /// Stable diagnostic name reported by the registered handler.
    pub handler_name: &'static str,
    /// Full mount prefix when the route came from a nested router.
    ///
    /// Top-level routes use `None`.
    pub mount_prefix: Option<String>,
}

/// Discoverable request-body policy for one concrete route method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteBodyPolicyInfo {
    /// HTTP method handled by this route entry.
    pub method: String,
    /// Full route pattern, including nested router mount prefixes.
    pub pattern: String,
    /// Stable diagnostic name reported by the registered handler.
    pub handler_name: &'static str,
    /// Full mount prefix when the route came from a nested router.
    pub mount_prefix: Option<String>,
    /// Route-local policy, when one was configured on the [`MethodRouter`].
    pub route_policy: Option<RequestBodyPolicy>,
    /// Monotonic merge of server, router, nested-router, and route policies.
    /// `None` means no first-class policy was configured and legacy extractor
    /// defaults plus transport-specific ingress limits remain authoritative.
    pub effective_policy: Option<RequestBodyPolicy>,
}

// ─── MethodRouter ────────────────────────────────────────────────────────────

/// A set of handlers for different HTTP methods on a single route.
pub struct MethodRouter {
    handlers: HashMap<String, Box<dyn Handler>>,
    method_not_allowed: Box<dyn Handler>,
    body_policy: Option<RequestBodyPolicy>,
}

impl MethodRouter {
    /// Create an empty method router.
    fn new() -> Self {
        Self {
            handlers: HashMap::with_capacity(4),
            method_not_allowed: Box::new(MethodNotAllowedHandler::new(String::new())),
            body_policy: None,
        }
    }

    /// Add a handler for a specific method.
    fn on(mut self, method: &str, handler: impl Handler) -> Self {
        self.handlers
            .insert(method.to_uppercase(), Box::new(handler));
        self.method_not_allowed = Box::new(MethodNotAllowedHandler::new(self.allow_header()));
        self
    }

    /// Register a GET handler.
    #[must_use]
    pub fn get(self, handler: impl Handler) -> Self {
        self.on(METHOD_GET, handler)
    }

    /// Register a POST handler.
    #[must_use]
    pub fn post(self, handler: impl Handler) -> Self {
        self.on(METHOD_POST, handler)
    }

    /// Register a PUT handler.
    #[must_use]
    pub fn put(self, handler: impl Handler) -> Self {
        self.on(METHOD_PUT, handler)
    }

    /// Register a DELETE handler.
    #[must_use]
    pub fn delete(self, handler: impl Handler) -> Self {
        self.on(METHOD_DELETE, handler)
    }

    /// Register a PATCH handler.
    #[must_use]
    pub fn patch(self, handler: impl Handler) -> Self {
        self.on(METHOD_PATCH, handler)
    }

    /// Register a HEAD handler.
    #[must_use]
    pub fn head(self, handler: impl Handler) -> Self {
        self.on(METHOD_HEAD, handler)
    }

    /// Register an OPTIONS handler.
    #[must_use]
    pub fn options(self, handler: impl Handler) -> Self {
        self.on(METHOD_OPTIONS, handler)
    }

    /// Apply a monotonic request-body policy to every method on this route.
    ///
    /// The policy is met with the enclosing server and router policies during
    /// dispatch, so it may tighten but never loosen an outer ceiling.
    #[must_use]
    pub fn with_body_policy(mut self, policy: RequestBodyPolicy) -> Self {
        self.body_policy = Some(policy.resolved());
        self
    }

    /// Return the route-local request-body policy, when configured.
    #[must_use]
    pub const fn body_policy(&self) -> Option<RequestBodyPolicy> {
        self.body_policy
    }

    /// Re-wrap every registered method handler through `wrap`.
    ///
    /// Used by [`Router::layer`] to apply middleware onion-style
    /// (br-asupersync-server-stack-hardening-eeexl1.3).
    fn map_handlers(&mut self, wrap: &dyn Fn(Box<dyn Handler>) -> Box<dyn Handler>) {
        let handlers = std::mem::take(&mut self.handlers);
        self.handlers = handlers
            .into_iter()
            .map(|(method, handler)| (method, wrap(handler)))
            .collect();
        let method_not_allowed = std::mem::replace(
            &mut self.method_not_allowed,
            Box::new(MethodNotAllowedHandler::new(String::new())),
        );
        self.method_not_allowed = wrap(method_not_allowed);
    }

    /// Return registered methods in deterministic HTTP-conventional order.
    #[must_use]
    pub fn methods(&self) -> Vec<String> {
        sorted_methods(self.handlers.keys().map(String::as_str))
    }

    fn allow_header(&self) -> String {
        self.methods().join(", ")
    }

    fn route_entries(&self, pattern: &str, mount_prefix: Option<&str>) -> Vec<RouteInfo> {
        let mut entries = self
            .handlers
            .iter()
            .map(|(method, handler)| RouteInfo {
                method: method.clone(),
                pattern: pattern.to_string(),
                handler_name: handler.handler_name(),
                mount_prefix: mount_prefix.map(ToOwned::to_owned),
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            compare_methods(&left.method, &right.method)
                .then_with(|| left.handler_name.cmp(right.handler_name))
        });
        entries
    }

    /// Dispatch a request to the appropriate method handler.
    async fn dispatch(&self, cx: &Cx, mut req: Request) -> Response {
        if let Err(response) = apply_request_body_policy(
            &mut req,
            None,
            self.body_policy.map(RequestBodyPolicyState::from_policy),
        ) {
            return response;
        }
        // Fast path: method is already uppercase (true for virtually all HTTP traffic).
        if let Some(handler) = self.handlers.get(&req.method) {
            return handler.call(cx, req).await;
        }
        // Slow path: case-insensitive fallback (allocates only if needed).
        let upper = req.method.to_uppercase();
        match self.handlers.get(&upper) {
            Some(handler) => handler.call(cx, req).await,
            None => self.method_not_allowed.call(cx, req).await,
        }
    }
}

struct MethodNotAllowedHandler {
    allow: String,
}

impl MethodNotAllowedHandler {
    fn new(allow: String) -> Self {
        Self { allow }
    }
}

impl Handler for MethodNotAllowedHandler {
    fn call(
        &self,
        _cx: &Cx,
        _req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let allow = self.allow.clone();
        Box::pin(async move {
            let mut resp = StatusCode::METHOD_NOT_ALLOWED.into_response();
            if !allow.is_empty() {
                resp.set_header("allow", allow);
            }
            resp
        })
    }
}

fn sorted_methods<'a>(methods: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut methods = methods
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<String>>();
    methods.sort_by(|left, right| compare_methods(left, right));
    methods
}

fn compare_methods(left: &str, right: &str) -> std::cmp::Ordering {
    method_sort_key(left).cmp(&method_sort_key(right))
}

fn method_sort_key(method: &str) -> (u8, &str) {
    match method {
        METHOD_GET => (0, method),
        METHOD_POST => (1, method),
        METHOD_PUT => (2, method),
        METHOD_DELETE => (3, method),
        METHOD_PATCH => (4, method),
        METHOD_HEAD => (5, method),
        METHOD_OPTIONS => (6, method),
        _ => (7, method),
    }
}

// ─── Convenience Functions ───────────────────────────────────────────────────

/// Create a method router with a GET handler.
pub fn get(handler: impl Handler) -> MethodRouter {
    MethodRouter::new().get(handler)
}

/// Create a method router with a POST handler.
pub fn post(handler: impl Handler) -> MethodRouter {
    MethodRouter::new().post(handler)
}

/// Create a method router with a PUT handler.
pub fn put(handler: impl Handler) -> MethodRouter {
    MethodRouter::new().put(handler)
}

/// Create a method router with a DELETE handler.
pub fn delete(handler: impl Handler) -> MethodRouter {
    MethodRouter::new().delete(handler)
}

/// Create a method router with a PATCH handler.
pub fn patch(handler: impl Handler) -> MethodRouter {
    MethodRouter::new().patch(handler)
}

// ─── Route Pattern ───────────────────────────────────────────────────────────

/// A compiled route pattern with parameter names.
#[derive(Debug, Clone)]
struct RoutePattern {
    /// The original pattern string (e.g., "/users/:id/posts/:post_id").
    #[allow(dead_code)] // retained for debug diagnostics
    raw: String,
    /// Segments: either literal strings or parameter names.
    segments: Vec<Segment>,
}

#[derive(Debug, Clone)]
struct RouteMatch {
    params: HashMap<String, String>,
    specificity: RouteSpecificity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RouteSpecificity {
    exact_path: bool,
    literal_segments: usize,
    param_segments: usize,
    total_segments: usize,
}

#[derive(Debug, Clone)]
enum Segment {
    Literal(String),
    Param(String),
    Wildcard,
}

impl RoutePattern {
    /// Parse a route pattern string.
    fn parse(pattern: &str) -> Self {
        let segments = pattern
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.strip_prefix(':').map_or_else(
                    || {
                        if s == "*" {
                            Segment::Wildcard
                        } else {
                            Segment::Literal(s.to_string())
                        }
                    },
                    |param| Segment::Param(param.to_string()),
                )
            })
            .collect();

        Self {
            raw: pattern.to_string(),
            segments,
        }
    }

    /// Try to match a path against this pattern, extracting parameters.
    fn matches(&self, path: &str) -> Option<RouteMatch> {
        // br-asupersync-router-empty-seg: reject paths containing
        // empty segments ("//"). Per RFC 3986, an empty segment is
        // semantically distinct from no segment, and silently
        // collapsing it would let "/users//foo" match a "/users/:id"
        // route as :id="foo" (or :id="" under a different
        // implementation, which is even worse). Both options leak
        // path-confusion attacks: an attacker could craft a URL
        // that bypasses path-prefix-based access controls (e.g.,
        // "/api//admin" might evade a filter that expects
        // "/api/admin" while still routing to the admin handler).
        // strip_prefix() in this same module already rejects empty
        // segments at mount boundaries (see
        // strip_prefix_rejects_empty_segment_at_mount_boundary
        // test); the matcher must agree to keep the routing
        // surface consistent.
        if path.contains("//") {
            return None;
        }
        let path_segments: SmallVec<[&str; 8]> =
            path.split('/').filter(|s| !s.is_empty()).collect();

        // Check for wildcard at the end.
        let has_wildcard = self
            .segments
            .last()
            .is_some_and(|s| matches!(s, Segment::Wildcard));

        if has_wildcard {
            if path_segments.len() < self.segments.len() - 1 {
                return None;
            }
        } else if path_segments.len() != self.segments.len() {
            return None;
        }

        let mut params = HashMap::with_capacity(2);

        for (i, segment) in self.segments.iter().enumerate() {
            match segment {
                Segment::Literal(lit) => {
                    if path_segments.get(i) != Some(&lit.as_str()) {
                        return None;
                    }
                }
                Segment::Param(name) => {
                    if let Some(&value) = path_segments.get(i) {
                        params.insert(name.clone(), value.to_string());
                    } else {
                        return None;
                    }
                }
                Segment::Wildcard => {
                    // Wildcard matches the rest of the path.
                    let rest = path_segments[i..].join("/");
                    params.insert("*".to_string(), rest);
                    return Some(RouteMatch {
                        params,
                        specificity: self.specificity(),
                    });
                }
            }
        }

        Some(RouteMatch {
            params,
            specificity: self.specificity(),
        })
    }

    fn specificity(&self) -> RouteSpecificity {
        let mut literal_segments = 0;
        let mut param_segments = 0;
        let mut exact_path = true;

        for segment in &self.segments {
            match segment {
                Segment::Literal(_) => literal_segments += 1,
                Segment::Param(_) => param_segments += 1,
                Segment::Wildcard => exact_path = false,
            }
        }

        RouteSpecificity {
            exact_path,
            literal_segments,
            param_segments,
            total_segments: self.segments.len(),
        }
    }
}

// ─── Router ──────────────────────────────────────────────────────────────────

/// HTTP request router.
///
/// Routes are matched by specificity: exact paths beat wildcard routes, literal
/// segments beat parameter segments, and registration order only breaks ties
/// between equally specific patterns.
///
/// # Path Parameters
///
/// Use `:param` syntax for path parameters:
///
/// ```ignore
/// Router::new()
///     .route("/users/:id", get(get_user))
///     .route("/users/:id/posts/:post_id", get(get_post))
/// ```
///
/// # Nesting
///
/// Use `nest()` to mount a sub-router at a prefix:
///
/// ```ignore
/// let api = Router::new()
///     .route("/users", get(list_users));
///
/// let app = Router::new()
///     .nest("/api/v1", api);
/// ```
pub struct Router {
    routes: Vec<(RoutePattern, MethodRouter)>,
    nested: Vec<(String, Self)>,
    fallback: Option<Box<dyn Handler>>,
    extensions: Extensions,
    server_body_policy: Option<RequestBodyPolicy>,
    body_policy: Option<RequestBodyPolicy>,
    default_trace: Option<DefaultTrace>,
}

/// Boxed response future returned by [`Router::into_http_handler`].
///
/// The HTTP/1.1 and HTTP/2 listeners deliberately share the same wire-level
/// request and response types, so one router adapter serves both stacks.
pub type HttpHandlerFuture = Pin<Box<dyn Future<Output = HttpResponse> + Send + 'static>>;

/// Boxed response future returned by [`Router::into_http1_handler`].
#[cfg(not(target_arch = "wasm32"))]
pub type Http1HandlerFuture = Pin<Box<dyn Future<Output = Http1Response> + Send + 'static>>;

/// Boxed response future returned by [`Router::into_http1_produced_handler`].
#[cfg(not(target_arch = "wasm32"))]
pub type Http1ProducedHandlerFuture =
    Pin<Box<dyn Future<Output = Http1ProducedResponse> + Send + 'static>>;

/// Boxed response future returned by [`Router::into_http2_produced_handler`].
#[cfg(not(target_arch = "wasm32"))]
pub type Http2ProducedHandlerFuture =
    Pin<Box<dyn Future<Output = Http2ProducedResponse> + Send + 'static>>;

/// Resource limits for the established-session HTTP/3 router bridge.
///
/// The first bridge profile assembles a complete request before dispatching it
/// to [`Router`]. Keeping the limit here makes that buffering explicit and
/// prevents a peer from growing application memory without bound.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NativeH3RouterConfig {
    /// Maximum request body bytes buffered per HTTP/3 request stream.
    max_buffered_body_bytes: usize,
    /// Maximum request-body bytes retained across incomplete streams and
    /// caller-scoped handler dispatches.
    max_total_buffered_body_bytes: usize,
    /// Maximum request streams allowed to wait for FIN at once.
    max_pending_requests: usize,
    /// Maximum completed requests admitted to caller-scoped handler dispatch.
    max_in_flight_dispatches: usize,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl Default for NativeH3RouterConfig {
    fn default() -> Self {
        Self {
            // Match the default per-request body limit of the h1/h2 listener
            // surfaces, then apply an explicit aggregate ceiling below.
            max_buffered_body_bytes: 16 * 1024 * 1024,
            max_total_buffered_body_bytes: 64 * 1024 * 1024,
            max_pending_requests: 128,
            max_in_flight_dispatches: 128,
        }
    }
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl NativeH3RouterConfig {
    /// Set the maximum buffered body size for one incomplete request.
    #[must_use]
    pub fn max_buffered_body_bytes(mut self, bytes: usize) -> Self {
        self.max_buffered_body_bytes = bytes;
        self
    }

    /// Set the aggregate retained-body budget across incomplete requests and
    /// in-flight handler dispatches.
    #[must_use]
    pub fn max_total_buffered_body_bytes(mut self, bytes: usize) -> Self {
        self.max_total_buffered_body_bytes = bytes;
        self
    }

    /// Set the maximum number of requests that may wait for FIN concurrently.
    #[must_use]
    pub fn max_pending_requests(mut self, requests: usize) -> Self {
        self.max_pending_requests = requests;
        self
    }

    /// Set the maximum number of completed requests whose handlers may be in
    /// flight concurrently.
    #[must_use]
    pub fn max_in_flight_dispatches(mut self, dispatches: usize) -> Self {
        self.max_in_flight_dispatches = dispatches;
        self
    }
}

/// Why the HTTP/3 router bridge reset one request stream without dispatching
/// or sending a response.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeH3RouterRefusal {
    /// CONNECT and extended CONNECT are not representable by this buffered
    /// request/response adapter.
    ConnectUnsupported,
    /// Request trailers are outside the first bridge profile.
    RequestTrailersUnsupported,
    /// The accumulated request body exceeded the configured per-stream limit.
    RequestBodyTooLarge {
        /// Configured maximum number of buffered bytes.
        limit: usize,
    },
    /// The connection-wide buffered-body budget is exhausted.
    ConnectionBodyBudgetExhausted {
        /// Configured maximum aggregate buffered bytes.
        limit: usize,
    },
    /// Too many request streams are already waiting for FIN.
    TooManyPendingRequests {
        /// Configured maximum number of pending requests.
        limit: usize,
    },
    /// Too many completed requests already have caller-scoped handlers in
    /// flight.
    TooManyInFlightDispatches {
        /// Configured maximum number of concurrent handler dispatches.
        limit: usize,
    },
    /// Content-Length was malformed, duplicated, or did not match the body.
    InvalidContentLength,
    /// TE contained a value other than the sole HTTP/3-permitted `trailers`.
    InvalidTransferEncoding,
    /// The caller cancelled an admitted handler scope before it produced a
    /// response.
    DispatchCancelled,
    /// The session emitted a request event in an order the bridge cannot
    /// safely represent.
    InvalidRequestProgression(&'static str),
    /// A router handler produced a response forbidden on HTTP/3, such as 101
    /// or a connection-specific header.
    InvalidResponse(H3Error),
}

/// Result of applying one decoded [`NativeH3Event`] to a [`NativeH3Router`].
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeH3RouterEvent {
    /// A request is buffered but has not reached FIN, so no handler ran.
    RequestBuffered {
        /// QUIC request stream.
        stream_id: StreamId,
        /// Body bytes buffered so far.
        body_bytes: usize,
    },
    /// A produced response was validated and installed for incremental send.
    ResponseStarted {
        /// QUIC request stream.
        stream_id: StreamId,
        /// Final HTTP response status.
        status: u16,
    },
    /// The completed request was dispatched and a final response was queued
    /// on the same stream.
    ResponseSent {
        /// QUIC request stream.
        stream_id: StreamId,
        /// Final HTTP response status.
        status: u16,
    },
    /// One request stream was reset fail-closed and the connection remains
    /// available to the caller.
    RequestRefused {
        /// QUIC request stream.
        stream_id: StreamId,
        /// Typed refusal reason.
        reason: NativeH3RouterRefusal,
    },
    /// A later event for a stream that was already refused was discarded. In
    /// particular, queued DATA/FIN cannot accidentally dispatch the handler
    /// after an early HEADERS refusal.
    RequestDiscarded {
        /// QUIC request stream.
        stream_id: StreamId,
    },
    /// The peer reset a request before it could be dispatched.
    StreamReset {
        /// QUIC request stream.
        stream_id: StreamId,
        /// Peer application error code.
        error_code: u64,
        /// Peer-declared final stream size.
        final_size: u64,
    },
    /// A control or non-request event that the caller may interpret.
    Session(NativeH3Event),
}

/// Result of ingesting one session event without awaiting an application
/// handler or monopolizing the QUIC/H3 drivers.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[derive(Debug)]
#[non_exhaustive]
pub enum NativeH3RouterIngress {
    /// The event was handled synchronously.
    Event(NativeH3RouterEvent),
    /// A completed request is ready for caller-scoped asynchronous dispatch.
    Dispatch(NativeH3RouterDispatch),
}

/// One completed request detached from the mutable session/connection borrows.
///
/// Run this future in the caller's request scope, continue driving other H3
/// streams, then pass the result to
/// [`NativeH3Router::complete_dispatch_with_cx`]. If the scope cancels the
/// dispatch, retain [`NativeH3RouterDispatch::cancellation_token`] and pass it
/// to [`NativeH3Router::cancel_dispatch_with_cx`] so the request stream is
/// terminalized explicitly.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[must_use = "an HTTP/3 dispatch must be run or explicitly cancelled"]
pub struct NativeH3RouterDispatch {
    token: NativeH3RouterDispatchToken,
    router: Arc<Router>,
    request: Request,
    suppress_body_for_head: bool,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl std::fmt::Debug for NativeH3RouterDispatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeH3RouterDispatch")
            .field("stream_id", &self.token.stream_id)
            .finish_non_exhaustive()
    }
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl NativeH3RouterDispatch {
    /// Request stream whose handler will run.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.token.stream_id
    }

    /// Produce the opaque bridge-bound token needed to terminalize this
    /// dispatch if its caller-owned request scope is cancelled.
    #[must_use]
    pub fn cancellation_token(&self) -> NativeH3RouterDispatchToken {
        self.token.clone()
    }

    /// Run the Router handler without borrowing the H3 session or QUIC
    /// connection. The supplied context must belong to the caller's
    /// request-task scope so cancellation and effect authority do not leak
    /// from the connection driver.
    pub async fn run(self, cx: &Cx) -> NativeH3RouterPreparedResponse {
        let response = self.router.handle_with_cx(cx, self.request).await;
        let status = response.status.as_u16();
        NativeH3RouterPreparedResponse {
            token: self.token,
            response: h3_response_from_web(response, self.suppress_body_for_head)
                .map(|(head, body)| (status, head, body)),
        }
    }

    /// Run the Router with opt-in request-scoped HTTP/3 producer authority.
    ///
    /// Ordinary handlers remain on the exact buffered completion path.
    /// Registering [`crate::web::Http3StreamResponder`] returns a distinct
    /// consuming response that must be started through
    /// [`NativeH3Router::start_produced_dispatch_with_cx`].
    pub async fn run_produced(self, cx: &Cx) -> NativeH3RouterProducedDispatch {
        let Self {
            token,
            router,
            mut request,
            suppress_body_for_head,
        } = self;
        let slot = Http3StreamSlot::default();
        request.extensions.insert_typed(slot.clone());
        let response = router.handle_with_cx(cx, request).await;
        let binding = slot.bind_response(&response, suppress_body_for_head);
        match binding {
            Ok(Some(plan)) => {
                let status = response.status.as_u16();
                NativeH3RouterProducedDispatch::Produced(NativeH3RouterPreparedProducedResponse {
                    token,
                    status,
                    head: h3_response_from_web(response, suppress_body_for_head).map(
                        |(head, body)| {
                            debug_assert!(body.is_empty());
                            head
                        },
                    ),
                    plan,
                    suppress_body_for_head,
                })
            }
            Ok(None) => {
                let status = response.status.as_u16();
                NativeH3RouterProducedDispatch::Buffered(NativeH3RouterPreparedResponse {
                    token,
                    response: h3_response_from_web(response, suppress_body_for_head)
                        .map(|(head, body)| (status, head, body)),
                })
            }
            Err(reason) => {
                let response = http1_stream_refusal_response(reason);
                let status = response.status.as_u16();
                NativeH3RouterProducedDispatch::Buffered(NativeH3RouterPreparedResponse {
                    token,
                    response: h3_response_from_web(response, suppress_body_for_head)
                        .map(|(head, body)| (status, head, body)),
                })
            }
        }
    }
}

/// Opaque proof that a cancellation belongs to one specific H3 Router bridge.
///
/// QUIC stream IDs repeat across connections, so a bare [`StreamId`] is not a
/// sufficient completion or cancellation capability.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[derive(Clone)]
#[must_use = "retain this token until the dispatch is completed or cancelled"]
pub struct NativeH3RouterDispatchToken {
    bridge_identity: Arc<()>,
    stream_id: StreamId,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl std::fmt::Debug for NativeH3RouterDispatchToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeH3RouterDispatchToken")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl NativeH3RouterDispatchToken {
    /// Request stream owned by this bridge-bound token.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }
}

/// Handler output ready to flush through an established H3 session.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[must_use = "a prepared HTTP/3 response must be completed or its dispatch cancelled"]
pub struct NativeH3RouterPreparedResponse {
    token: NativeH3RouterDispatchToken,
    response: Result<(u16, H3ResponseHead, Bytes), H3Error>,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl NativeH3RouterPreparedResponse {
    /// Request stream that owns this response.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.token.stream_id
    }
}

/// Result of an HTTP/3 dispatch that offered produced-response authority.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[must_use = "complete the buffered response or start/cancel the produced response"]
pub enum NativeH3RouterProducedDispatch {
    /// No producer was registered; use the existing borrowed completion API.
    Buffered(NativeH3RouterPreparedResponse),
    /// A single bounded producer was registered; use the consuming start API.
    Produced(NativeH3RouterPreparedProducedResponse),
}

/// Validated Router output plus a single-use HTTP/3 producer plan.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[must_use = "a produced HTTP/3 response must be started or its dispatch cancelled"]
pub struct NativeH3RouterPreparedProducedResponse {
    token: NativeH3RouterDispatchToken,
    status: u16,
    head: Result<H3ResponseHead, H3Error>,
    plan: Http3StreamPlan,
    suppress_body_for_head: bool,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl NativeH3RouterPreparedProducedResponse {
    /// Request stream that owns this response.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.token.stream_id
    }

    /// Opaque token for explicit cancellation before the consuming start.
    #[must_use]
    pub fn cancellation_token(&self) -> NativeH3RouterDispatchToken {
        self.token.clone()
    }
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeH3ProducerOutcome {
    Finished {
        total_bytes: u64,
        terminal: Http3ProducerTerminal,
    },
    Failed,
    Cancelled,
    DeadlineExceeded,
    ConnectionLost,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[derive(Default)]
struct NativeH3ProducerLifecycleState {
    outcome: Option<NativeH3ProducerOutcome>,
    waker: Option<Waker>,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[derive(Clone, Default)]
struct NativeH3ProducerLifecycle {
    state: Arc<parking_lot::Mutex<NativeH3ProducerLifecycleState>>,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl NativeH3ProducerLifecycle {
    fn publish(&self, outcome: NativeH3ProducerOutcome) {
        let waker = {
            let mut state = self.state.lock();
            if state.outcome.is_some() {
                return;
            }
            state.outcome = Some(outcome);
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn poll_outcome(&self, task_cx: &mut TaskContext<'_>) -> Poll<NativeH3ProducerOutcome> {
        let mut state = self.state.lock();
        if let Some(outcome) = state.outcome {
            return Poll::Ready(outcome);
        }
        let should_replace = state
            .waker
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(task_cx.waker()));
        if should_replace {
            state.waker = Some(task_cx.waker().clone());
        }
        Poll::Pending
    }
}

/// Caller-owned supervised work item for one HTTP/3 response producer.
///
/// Poll or spawn this future in the request scope returned by the event loop.
/// Dropping it requests cancellation and publishes a terminal outcome so the
/// Router bridge can reap the stream without leaking in-flight ownership.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[must_use = "the HTTP/3 producer must be polled or dropped explicitly"]
pub struct NativeH3RouterProducer {
    inner: Pin<Box<dyn Future<Output = NativeH3ProducerOutcome> + Send + 'static>>,
    lifecycle: NativeH3ProducerLifecycle,
    producer_cx: Cx,
    completed: bool,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl std::fmt::Debug for NativeH3RouterProducer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeH3RouterProducer")
            .field("completed", &self.completed)
            .finish_non_exhaustive()
    }
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl Future for NativeH3RouterProducer {
    type Output = ();

    fn poll(self: Pin<&mut Self>, task_cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.inner.as_mut().poll(task_cx) {
            Poll::Ready(outcome) => {
                this.lifecycle.publish(outcome);
                this.completed = true;
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl Drop for NativeH3RouterProducer {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.producer_cx.cancel_with(
            CancelKind::ParentCancelled,
            Some("HTTP/3 response producer future dropped"),
        );
        self.lifecycle.publish(NativeH3ProducerOutcome::Cancelled);
    }
}

/// One bounded progress edge from the caller-driven produced-response driver.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[must_use = "run returned producer work and continue polling until terminal"]
pub enum NativeH3ProducedEvent {
    /// Final response HEADERS were queued; no producer exists for this HEAD.
    HeadQueued {
        /// Request stream.
        stream_id: StreamId,
        /// Final status.
        status: u16,
    },
    /// Final response HEADERS were queued and the producer may now run.
    ProducerReady {
        /// Request stream.
        stream_id: StreamId,
        /// Supervised producer future owned by the caller's request scope.
        producer: NativeH3RouterProducer,
    },
    /// One bounded DATA frame was queued.
    DataQueued {
        /// Request stream.
        stream_id: StreamId,
        /// Application payload bytes in the frame.
        payload_bytes: usize,
    },
    /// A FIN-only or trailing HEADERS+FIN terminal write was queued.
    TerminalQueued {
        /// Request stream.
        stream_id: StreamId,
    },
    /// The producer exited and every STREAM frame left packet assembly.
    ResponseSent {
        /// Request stream.
        stream_id: StreamId,
        /// Final status.
        status: u16,
    },
    /// A cancelled or failed produced response was reset and reaped.
    RequestReset {
        /// Request stream.
        stream_id: StreamId,
    },
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
enum NativeH3BodyTerminal {
    Eof,
    Trailers(Vec<(String, String)>),
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
struct ActiveNativeH3ProducedResponse {
    status: u16,
    writer: NativeH3ResponseWriter,
    plan: Option<Http3StreamPlan>,
    body: Option<OutgoingBody>,
    lifecycle: Option<NativeH3ProducerLifecycle>,
    producer_cx: Option<Cx>,
    max_data_wire_bytes: u64,
    emitted_bytes: u64,
    terminal: Option<NativeH3BodyTerminal>,
    head_only: bool,
    reset_queued: bool,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
struct PendingNativeH3Request {
    head: H3RequestHead,
    body: Vec<u8>,
}

/// Caller-driven bridge from an established native HTTP/3 session to a web
/// [`Router`].
///
/// Feed events returned by [`NativeH3Session::next_event`] into
/// [`NativeH3Router::ingest_event_with_cx`]. HEADERS and DATA are accumulated
/// by stream. FIN produces a detached [`NativeH3RouterDispatch`] so handlers
/// can run in caller-owned request scopes while the QUIC/H3 drivers continue
/// serving other streams. Completed output is queued through
/// [`NativeH3Router::complete_dispatch_with_cx`] on the originating stream. A
/// request reset before FIN never reaches a handler.
///
/// Each bridge is connection-scoped: completion and cancellation methods must
/// receive the same established `NativeH3Session`/`QuicConnection` pair that
/// produced its events. When a [`NativeH3RouterEvent::StreamReset`] arrives for
/// an in-flight dispatch, the event loop must cancel/drop that handler scope
/// and acknowledge it with [`NativeH3Router::cancel_dispatch_with_cx`]; the
/// bridge cannot own or cancel the caller's task handle itself.
///
/// The opt-in produced-response path owns bounded DATA/trailer/FIN scheduling
/// over an already-established connection. This adapter deliberately does not
/// own a UDP listener, TLS/ALPN handshake, QUIC event loop, streaming request
/// bodies, CONNECT, WebSocket, or server-push surface.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
pub struct NativeH3Router {
    identity: Arc<()>,
    router: Arc<Router>,
    config: NativeH3RouterConfig,
    pending: BTreeMap<StreamId, PendingNativeH3Request>,
    discarding: BTreeSet<StreamId>,
    discard_order: std::collections::VecDeque<StreamId>,
    retained_request_body_bytes: usize,
    in_flight: BTreeMap<StreamId, usize>,
    reset_during_dispatch: BTreeSet<StreamId>,
    produced: BTreeMap<StreamId, ActiveNativeH3ProducedResponse>,
    produced_poll_after: Option<StreamId>,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
const MAX_DISCARDED_H3_STREAMS: usize = 4096;

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl NativeH3Router {
    /// Wrap a router with the default per-request buffering limit.
    #[must_use]
    pub fn new(router: Router) -> Self {
        Self::with_config(router, NativeH3RouterConfig::default())
    }

    /// Wrap a router with explicit established-session bridge limits.
    #[must_use]
    pub fn with_config(router: Router, config: NativeH3RouterConfig) -> Self {
        Self::with_shared_config(Arc::new(router), config)
    }

    /// Create one connection-scoped bridge over a shared route graph.
    #[must_use]
    pub fn from_shared(router: Arc<Router>) -> Self {
        Self::with_shared_config(router, NativeH3RouterConfig::default())
    }

    /// Create one connection-scoped bridge over a shared route graph with
    /// explicit buffering limits.
    #[must_use]
    pub fn with_shared_config(router: Arc<Router>, config: NativeH3RouterConfig) -> Self {
        Self {
            identity: Arc::new(()),
            router,
            config,
            pending: BTreeMap::new(),
            discarding: BTreeSet::new(),
            discard_order: std::collections::VecDeque::new(),
            retained_request_body_bytes: 0,
            in_flight: BTreeMap::new(),
            reset_during_dispatch: BTreeSet::new(),
            produced: BTreeMap::new(),
            produced_poll_after: None,
        }
    }

    /// Number of request streams currently waiting for FIN.
    #[must_use]
    pub fn pending_request_count(&self) -> usize {
        self.pending.len()
    }

    /// Number of completed requests currently owned by caller-scoped handler
    /// dispatches.
    #[must_use]
    pub fn in_flight_dispatch_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Ingest one decoded HTTP/3 session event with an explicit capability
    /// context, without awaiting application code.
    ///
    /// Per-request representation failures reset only that request stream and
    /// return [`NativeH3RouterEvent::RequestRefused`]. Transport/session
    /// failures are returned to the caller by the underlying session API.
    pub fn ingest_event_with_cx(
        &mut self,
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        event: NativeH3Event,
    ) -> Result<NativeH3RouterIngress, crate::http::h3::NativeH3SessionError> {
        match event {
            NativeH3Event::RequestHeaders { stream_id, head } => {
                if self.discarding.contains(&stream_id) {
                    return Ok(NativeH3RouterIngress::Event(
                        NativeH3RouterEvent::RequestDiscarded { stream_id },
                    ));
                }
                if head.pseudo.method.as_deref() == Some(METHOD_CONNECT) {
                    return self
                        .refuse_request(
                            cx,
                            session,
                            connection,
                            stream_id,
                            NativeH3RouterRefusal::ConnectUnsupported,
                            true,
                        )
                        .map(NativeH3RouterIngress::Event);
                }
                if self.pending.contains_key(&stream_id) {
                    return self
                        .refuse_request(
                            cx,
                            session,
                            connection,
                            stream_id,
                            NativeH3RouterRefusal::InvalidRequestProgression(
                                "duplicate request HEADERS before FIN",
                            ),
                            true,
                        )
                        .map(NativeH3RouterIngress::Event);
                }
                if self.pending.len() >= self.config.max_pending_requests {
                    return self
                        .refuse_request(
                            cx,
                            session,
                            connection,
                            stream_id,
                            NativeH3RouterRefusal::TooManyPendingRequests {
                                limit: self.config.max_pending_requests,
                            },
                            true,
                        )
                        .map(NativeH3RouterIngress::Event);
                }
                self.pending.insert(
                    stream_id,
                    PendingNativeH3Request {
                        head,
                        body: Vec::new(),
                    },
                );
                Ok(NativeH3RouterIngress::Event(
                    NativeH3RouterEvent::RequestBuffered {
                        stream_id,
                        body_bytes: 0,
                    },
                ))
            }
            NativeH3Event::Data { stream_id, bytes } => {
                if self.discarding.contains(&stream_id) {
                    return Ok(NativeH3RouterIngress::Event(
                        NativeH3RouterEvent::RequestDiscarded { stream_id },
                    ));
                }
                let Some(current_len) = self
                    .pending
                    .get(&stream_id)
                    .map(|request| request.body.len())
                else {
                    return self
                        .refuse_request(
                            cx,
                            session,
                            connection,
                            stream_id,
                            NativeH3RouterRefusal::InvalidRequestProgression(
                                "request DATA arrived before HEADERS",
                            ),
                            true,
                        )
                        .map(NativeH3RouterIngress::Event);
                };
                let Some(new_len) = current_len.checked_add(bytes.len()) else {
                    return self
                        .refuse_request(
                            cx,
                            session,
                            connection,
                            stream_id,
                            NativeH3RouterRefusal::RequestBodyTooLarge {
                                limit: self.config.max_buffered_body_bytes,
                            },
                            true,
                        )
                        .map(NativeH3RouterIngress::Event);
                };
                if new_len > self.config.max_buffered_body_bytes {
                    return self
                        .refuse_request(
                            cx,
                            session,
                            connection,
                            stream_id,
                            NativeH3RouterRefusal::RequestBodyTooLarge {
                                limit: self.config.max_buffered_body_bytes,
                            },
                            true,
                        )
                        .map(NativeH3RouterIngress::Event);
                }
                let Some(total_len) = self.retained_request_body_bytes.checked_add(bytes.len())
                else {
                    return self
                        .refuse_request(
                            cx,
                            session,
                            connection,
                            stream_id,
                            NativeH3RouterRefusal::ConnectionBodyBudgetExhausted {
                                limit: self.config.max_total_buffered_body_bytes,
                            },
                            true,
                        )
                        .map(NativeH3RouterIngress::Event);
                };
                if total_len > self.config.max_total_buffered_body_bytes {
                    return self
                        .refuse_request(
                            cx,
                            session,
                            connection,
                            stream_id,
                            NativeH3RouterRefusal::ConnectionBodyBudgetExhausted {
                                limit: self.config.max_total_buffered_body_bytes,
                            },
                            true,
                        )
                        .map(NativeH3RouterIngress::Event);
                }
                let request = self
                    .pending
                    .get_mut(&stream_id)
                    .expect("pending request checked above");
                request.body.extend_from_slice(bytes.as_ref());
                self.retained_request_body_bytes = total_len;
                Ok(NativeH3RouterIngress::Event(
                    NativeH3RouterEvent::RequestBuffered {
                        stream_id,
                        body_bytes: new_len,
                    },
                ))
            }
            NativeH3Event::Trailers { stream_id, .. } => {
                if self.discarding.contains(&stream_id) {
                    return Ok(NativeH3RouterIngress::Event(
                        NativeH3RouterEvent::RequestDiscarded { stream_id },
                    ));
                }
                self.refuse_request(
                    cx,
                    session,
                    connection,
                    stream_id,
                    NativeH3RouterRefusal::RequestTrailersUnsupported,
                    true,
                )
                .map(NativeH3RouterIngress::Event)
            }
            NativeH3Event::Finished { stream_id } => {
                if self.discarding.remove(&stream_id) {
                    return Ok(NativeH3RouterIngress::Event(
                        NativeH3RouterEvent::RequestDiscarded { stream_id },
                    ));
                }
                let Some(request) = self.take_pending_request(stream_id) else {
                    return self
                        .refuse_request(
                            cx,
                            session,
                            connection,
                            stream_id,
                            NativeH3RouterRefusal::InvalidRequestProgression(
                                "request FIN arrived before HEADERS",
                            ),
                            false,
                        )
                        .map(NativeH3RouterIngress::Event);
                };
                if let Err(reason) =
                    validate_h3_request_semantics(&request.head, request.body.len())
                {
                    return self
                        .refuse_request(cx, session, connection, stream_id, reason, false)
                        .map(NativeH3RouterIngress::Event);
                }
                if self.in_flight.len() >= self.config.max_in_flight_dispatches {
                    return self
                        .refuse_request(
                            cx,
                            session,
                            connection,
                            stream_id,
                            NativeH3RouterRefusal::TooManyInFlightDispatches {
                                limit: self.config.max_in_flight_dispatches,
                            },
                            false,
                        )
                        .map(NativeH3RouterIngress::Event);
                }
                let is_head = request.head.pseudo.method.as_deref() == Some(METHOD_HEAD);
                let retained_body_bytes = request.body.len();
                let request = web_request_from_h3(request.head, request.body);
                // take_pending_request released these bytes while validating
                // the completed request. Charge them again before handing the
                // owned body to application code, and retain the charge until
                // completion/reset/cancellation is acknowledged.
                self.retained_request_body_bytes += retained_body_bytes;
                self.in_flight.insert(stream_id, retained_body_bytes);
                Ok(NativeH3RouterIngress::Dispatch(NativeH3RouterDispatch {
                    token: NativeH3RouterDispatchToken {
                        bridge_identity: Arc::clone(&self.identity),
                        stream_id,
                    },
                    router: Arc::clone(&self.router),
                    request,
                    suppress_body_for_head: is_head,
                }))
            }
            NativeH3Event::StreamReset {
                stream_id,
                error_code,
                final_size,
            } => {
                if self.pending.contains_key(&stream_id)
                    || self.in_flight.contains_key(&stream_id)
                    || self.produced.contains_key(&stream_id)
                {
                    record_native_h3_body_diagnostic(
                        stream_id,
                        WebBodyDiagnostic::ClientAbort,
                        "peer reset the HTTP/3 request/response stream",
                    );
                }
                self.take_pending_request(stream_id);
                self.discarding.remove(&stream_id);
                if let Some(state) = self.produced.get_mut(&stream_id) {
                    cancel_native_h3_produced(
                        cx,
                        session,
                        connection,
                        state,
                        "peer reset HTTP/3 produced response stream",
                    )?;
                } else if self.in_flight.contains_key(&stream_id) {
                    // Keep the dispatch counted until its caller-owned scope
                    // observes the reset and acknowledges completion or
                    // cancellation. Otherwise reset churn could bypass the
                    // in-flight admission cap while handlers keep running.
                    self.reset_during_dispatch.insert(stream_id);
                }
                Ok(NativeH3RouterIngress::Event(
                    NativeH3RouterEvent::StreamReset {
                        stream_id,
                        error_code,
                        final_size,
                    },
                ))
            }
            event => Ok(NativeH3RouterIngress::Event(NativeH3RouterEvent::Session(
                event,
            ))),
        }
    }

    /// Flush a completed handler result without having held the session or
    /// connection mutable across the handler await. `session` and `connection`
    /// must be the originating bridge's established pair.
    pub fn complete_dispatch_with_cx(
        &mut self,
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        prepared: &NativeH3RouterPreparedResponse,
    ) -> Result<NativeH3RouterEvent, crate::http::h3::NativeH3SessionError> {
        if !Arc::ptr_eq(&self.identity, &prepared.token.bridge_identity) {
            return Err(crate::http::h3::NativeH3SessionError::InvalidState(
                "HTTP/3 Router completion belongs to a different bridge",
            ));
        }
        let stream_id = prepared.token.stream_id;
        if self.reset_during_dispatch.remove(&stream_id) {
            self.release_in_flight(stream_id);
            return Ok(NativeH3RouterEvent::RequestDiscarded { stream_id });
        }
        if !self.in_flight.contains_key(&stream_id) {
            return Err(crate::http::h3::NativeH3SessionError::InvalidState(
                "HTTP/3 Router dispatch is not in flight",
            ));
        }
        match &prepared.response {
            Ok((status, head, body)) => {
                // NativeH3Session queues the complete HEADERS/DATA/FIN wire
                // image with one atomic transport write. Retain in-flight
                // ownership on failure so the caller can retry this prepared
                // response or cancel it explicitly.
                if let Err(error) =
                    session.send_response(cx, connection, stream_id, head, body.clone())
                {
                    if let Some(diagnostic) =
                        native_h3_completion_error_diagnostic(connection, &error)
                    {
                        record_native_h3_body_diagnostic(
                            stream_id,
                            diagnostic,
                            "buffered response could not be committed",
                        );
                    }
                    if connection.state() != QuicConnectionState::Established {
                        self.release_in_flight(stream_id);
                    }
                    return Err(error);
                }
                self.release_in_flight(stream_id);
                Ok(NativeH3RouterEvent::ResponseSent {
                    stream_id,
                    status: *status,
                })
            }
            Err(error) => {
                let event = self.refuse_request(
                    cx,
                    session,
                    connection,
                    stream_id,
                    NativeH3RouterRefusal::InvalidResponse(error.clone()),
                    false,
                )?;
                self.release_in_flight(stream_id);
                Ok(event)
            }
        }
    }

    /// Consume and install one produced response without starting its factory.
    ///
    /// Final response validation and writer construction happen first. The
    /// producer channel and supervised future are created only after
    /// [`Self::poll_produced_response_with_cx`] successfully queues HEADERS.
    pub fn start_produced_dispatch_with_cx(
        &mut self,
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        prepared: NativeH3RouterPreparedProducedResponse,
    ) -> Result<NativeH3RouterEvent, crate::http::h3::NativeH3SessionError> {
        let NativeH3RouterPreparedProducedResponse {
            token,
            status,
            head,
            plan,
            suppress_body_for_head,
        } = prepared;
        if !Arc::ptr_eq(&self.identity, &token.bridge_identity) {
            return Err(crate::http::h3::NativeH3SessionError::InvalidState(
                "HTTP/3 Router produced response belongs to a different bridge",
            ));
        }
        let stream_id = token.stream_id;
        if let Some(state) = self.produced.get_mut(&stream_id) {
            cancel_native_h3_produced(
                cx,
                session,
                connection,
                state,
                "HTTP/3 produced response explicitly cancelled",
            )?;
            return Ok(NativeH3RouterEvent::RequestRefused {
                stream_id,
                reason: NativeH3RouterRefusal::DispatchCancelled,
            });
        }
        if self.reset_during_dispatch.remove(&stream_id) {
            self.release_in_flight(stream_id);
            return Ok(NativeH3RouterEvent::RequestDiscarded { stream_id });
        }
        if !self.in_flight.contains_key(&stream_id) {
            return Err(crate::http::h3::NativeH3SessionError::InvalidState(
                "HTTP/3 Router dispatch is not in flight",
            ));
        }
        if self.produced.contains_key(&stream_id) {
            return Err(crate::http::h3::NativeH3SessionError::InvalidState(
                "HTTP/3 Router produced response is already active",
            ));
        }
        let head = match head {
            Ok(head) => head,
            Err(error) => {
                let event = self.refuse_request(
                    cx,
                    session,
                    connection,
                    stream_id,
                    NativeH3RouterRefusal::InvalidResponse(error),
                    false,
                );
                self.release_in_flight(stream_id);
                return event;
            }
        };
        let writer = match session.start_response_writer(
            connection,
            stream_id,
            &head,
            suppress_body_for_head,
        ) {
            Ok(writer) => writer,
            Err(error) => {
                return Err(self.fail_produced_start(cx, session, connection, stream_id, error));
            }
        };
        let max_data_wire_bytes = if suppress_body_for_head {
            0
        } else {
            if plan.max_frame_bytes.get() > writer.max_frame_payload_size() {
                let error =
                    crate::http::h3::NativeH3SessionError::Protocol(H3Error::FrameTooLarge {
                        payload_size: plan.max_frame_bytes.get(),
                        max_size: writer.max_frame_payload_size(),
                    });
                return Err(self.fail_produced_start(cx, session, connection, stream_id, error));
            }
            match h3_data_frame_wire_len(plan.max_frame_bytes.get()) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return Err(self.fail_produced_start(cx, session, connection, stream_id, error));
                }
            }
        };
        self.produced.insert(
            stream_id,
            ActiveNativeH3ProducedResponse {
                status,
                writer,
                plan: (!suppress_body_for_head).then_some(plan),
                body: None,
                lifecycle: None,
                producer_cx: None,
                max_data_wire_bytes,
                emitted_bytes: 0,
                terminal: None,
                head_only: suppress_body_for_head,
                reset_queued: false,
            },
        );
        Ok(NativeH3RouterEvent::ResponseStarted { stream_id, status })
    }

    /// Poll one fair, bounded progress edge across active produced responses.
    ///
    /// The method never polls arbitrary application producer code. Instead it
    /// returns a caller-owned [`NativeH3RouterProducer`] after HEADERS commit;
    /// the caller runs that future in its request scope while this method
    /// continues to drive only bounded channel and transport state.
    pub fn poll_produced_response_with_cx(
        &mut self,
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        task_cx: &mut TaskContext<'_>,
    ) -> Poll<Result<NativeH3ProducedEvent, crate::http::h3::NativeH3SessionError>> {
        if connection.state() != QuicConnectionState::Established {
            let peer_closed = connection.close_was_peer_initiated();
            for (stream_id, state) in &mut self.produced {
                if peer_closed && !state.reset_queued {
                    record_native_h3_body_diagnostic(
                        *stream_id,
                        WebBodyDiagnostic::ClientAbort,
                        "peer closed the QUIC connection during an HTTP/3 response",
                    );
                }
                mark_native_h3_produced_cancelled(
                    state,
                    "HTTP/3 connection closed during produced response",
                );
            }
        }
        let mut stream_ids = self.produced.keys().copied().collect::<Vec<_>>();
        if let Some(after) = self.produced_poll_after
            && let Some(split) = stream_ids.iter().position(|stream_id| *stream_id > after)
        {
            stream_ids.rotate_left(split);
        }
        for stream_id in stream_ids {
            let poll = {
                let state = self
                    .produced
                    .get_mut(&stream_id)
                    .expect("stream id came from active produced map");
                poll_one_native_h3_produced(cx, session, connection, state, task_cx)
            };
            match poll {
                Poll::Ready(Ok(NativeH3ProducedStep::Event(event))) => {
                    self.produced_poll_after = Some(stream_id);
                    return Poll::Ready(Ok(event));
                }
                Poll::Ready(Ok(NativeH3ProducedStep::Reap(event))) => {
                    self.produced.remove(&stream_id);
                    self.release_in_flight(stream_id);
                    self.produced_poll_after = Some(stream_id);
                    return Poll::Ready(Ok(event));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }

    /// Terminalize an admitted dispatch whose request scope was cancelled or
    /// whose result will otherwise not be completed. `cx` must remain the live
    /// connection-driver context; the handler scope's cancelled context may
    /// refuse the transport reset before it is queued.
    pub fn cancel_dispatch_with_cx(
        &mut self,
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        token: &NativeH3RouterDispatchToken,
    ) -> Result<NativeH3RouterEvent, crate::http::h3::NativeH3SessionError> {
        if !Arc::ptr_eq(&self.identity, &token.bridge_identity) {
            return Err(crate::http::h3::NativeH3SessionError::InvalidState(
                "HTTP/3 Router cancellation belongs to a different bridge",
            ));
        }
        let stream_id = token.stream_id;
        if self.reset_during_dispatch.remove(&stream_id) {
            self.release_in_flight(stream_id);
            return Ok(NativeH3RouterEvent::RequestDiscarded { stream_id });
        }
        if !self.in_flight.contains_key(&stream_id) {
            return Err(crate::http::h3::NativeH3SessionError::InvalidState(
                "HTTP/3 Router dispatch is not in flight",
            ));
        }
        if connection.state() != QuicConnectionState::Established {
            if let Some(diagnostic) = native_h3_closed_connection_diagnostic(connection) {
                record_native_h3_body_diagnostic(
                    stream_id,
                    diagnostic,
                    "peer closed the QUIC connection before HTTP/3 dispatch cancellation",
                );
            }
            if let Some(mut state) = self.produced.remove(&stream_id) {
                mark_native_h3_produced_cancelled(
                    &mut state,
                    "HTTP/3 connection closed before dispatch cancellation",
                );
            }
            self.take_pending_request(stream_id);
            self.release_in_flight(stream_id);
            return Ok(NativeH3RouterEvent::RequestRefused {
                stream_id,
                reason: NativeH3RouterRefusal::DispatchCancelled,
            });
        }
        if let Some(state) = self.produced.get_mut(&stream_id) {
            cancel_native_h3_produced(
                cx,
                session,
                connection,
                state,
                "HTTP/3 produced response explicitly cancelled",
            )?;
            return Ok(NativeH3RouterEvent::RequestRefused {
                stream_id,
                reason: NativeH3RouterRefusal::DispatchCancelled,
            });
        }
        let event = self.refuse_request(
            cx,
            session,
            connection,
            stream_id,
            NativeH3RouterRefusal::DispatchCancelled,
            false,
        )?;
        self.release_in_flight(stream_id);
        Ok(event)
    }

    fn refuse_request(
        &mut self,
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        stream_id: StreamId,
        reason: NativeH3RouterRefusal,
        discard_until_terminal: bool,
    ) -> Result<NativeH3RouterEvent, crate::http::h3::NativeH3SessionError> {
        self.take_pending_request(stream_id);
        session.cancel_request(cx, connection, stream_id)?;
        if discard_until_terminal {
            self.remember_discarding(stream_id);
        }
        Ok(NativeH3RouterEvent::RequestRefused { stream_id, reason })
    }

    fn take_pending_request(&mut self, stream_id: StreamId) -> Option<PendingNativeH3Request> {
        let request = self.pending.remove(&stream_id)?;
        self.retained_request_body_bytes = self
            .retained_request_body_bytes
            .saturating_sub(request.body.len());
        Some(request)
    }

    fn release_in_flight(&mut self, stream_id: StreamId) {
        if let Some(body_bytes) = self.in_flight.remove(&stream_id) {
            self.retained_request_body_bytes =
                self.retained_request_body_bytes.saturating_sub(body_bytes);
        }
    }

    fn fail_produced_start(
        &mut self,
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        stream_id: StreamId,
        error: crate::http::h3::NativeH3SessionError,
    ) -> crate::http::h3::NativeH3SessionError {
        if let Some(diagnostic) = native_h3_completion_error_diagnostic(connection, &error) {
            record_native_h3_body_diagnostic(
                stream_id,
                diagnostic,
                "produced response could not start",
            );
        }
        let reset_error = session.cancel_request(cx, connection, stream_id).err();
        self.release_in_flight(stream_id);
        reset_error.unwrap_or(error)
    }

    fn remember_discarding(&mut self, stream_id: StreamId) {
        if self.discarding.insert(stream_id) {
            self.discard_order.push_back(stream_id);
        }
        while self.discard_order.len() > MAX_DISCARDED_H3_STREAMS {
            if let Some(expired) = self.discard_order.pop_front() {
                self.discarding.remove(&expired);
            }
        }
    }
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl Drop for NativeH3Router {
    fn drop(&mut self) {
        for state in self.produced.values() {
            if let Some(producer_cx) = &state.producer_cx {
                producer_cx.cancel_with(
                    CancelKind::ParentCancelled,
                    Some("HTTP/3 Router bridge dropped an active produced response"),
                );
            }
        }
    }
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
enum NativeH3ProducedStep {
    Event(NativeH3ProducedEvent),
    Reap(NativeH3ProducedEvent),
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
const H3_PRODUCER_DRAIN_GRACE: Duration = Duration::from_millis(100);

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn record_native_h3_body_diagnostic(
    stream_id: StreamId,
    diagnostic: WebBodyDiagnostic,
    cause: &'static str,
) {
    let _ = (stream_id, diagnostic, cause);
    error!(
        stream_id = stream_id.0,
        diagnostic = diagnostic.code(),
        cause,
        "[{}] h3 body stream terminated without a clean response-body boundary",
        diagnostic.code()
    );
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn native_h3_produced_error_diagnostic(
    error: &crate::http::h3::NativeH3SessionError,
) -> Option<WebBodyDiagnostic> {
    use crate::http::h3::NativeH3SessionError;

    match error {
        NativeH3SessionError::Transport(NativeQuicConnectionError::Stream(
            QuicStreamError::SendStopped { .. } | QuicStreamError::ReceiveReset { .. },
        ))
        | NativeH3SessionError::CriticalStreamClosed { .. } => Some(WebBodyDiagnostic::ClientAbort),
        NativeH3SessionError::Protocol(_) | NativeH3SessionError::InvalidState(_) => {
            Some(WebBodyDiagnostic::ResponseProducerFailure)
        }
        NativeH3SessionError::Transport(_) | NativeH3SessionError::TruncatedStream { .. } => None,
    }
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn native_h3_completion_error_diagnostic(
    connection: &QuicConnection,
    error: &crate::http::h3::NativeH3SessionError,
) -> Option<WebBodyDiagnostic> {
    if connection.state() != QuicConnectionState::Established
        && matches!(
            error,
            crate::http::h3::NativeH3SessionError::InvalidState(_)
        )
    {
        return native_h3_closed_connection_diagnostic(connection);
    }
    native_h3_produced_error_diagnostic(error)
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn native_h3_closed_connection_diagnostic(
    connection: &QuicConnection,
) -> Option<WebBodyDiagnostic> {
    (connection.state() != QuicConnectionState::Established
        && connection.close_was_peer_initiated())
    .then_some(WebBodyDiagnostic::ClientAbort)
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn make_native_h3_producer(
    connection_cx: &Cx,
    plan: Http3StreamPlan,
) -> (
    OutgoingBody,
    Cx,
    NativeH3ProducerLifecycle,
    NativeH3RouterProducer,
) {
    let region = ServerRequestRegion::mint_from_connection(
        "h3-produced",
        connection_cx.budget(),
        connection_cx.now(),
        connection_cx,
    );
    let producer_cx = region.cx().clone();
    let (body, sender, producer_factory): (_, _, Http3StreamProducer) =
        plan.into_parts(&producer_cx);
    let lifecycle = NativeH3ProducerLifecycle::default();
    let producer_cx_for_factory = producer_cx.clone();
    let connection_cx = connection_cx.clone();
    let run = Box::pin(async move {
        let producer_outcome_cx = producer_cx_for_factory.clone();
        let producer =
            async move { producer_factory(producer_cx_for_factory.clone(), sender).await };
        match region
            .run_with_protocol_drain(
                RequestBudgetSource::Inherited,
                Some(connection_cx),
                H3_PRODUCER_DRAIN_GRACE,
                producer,
            )
            .await
        {
            ServerHopOutcome::Ok(Ok(sender)) if sender.is_finished() => {
                NativeH3ProducerOutcome::Finished {
                    total_bytes: sender.total_bytes(),
                    terminal: sender.terminal(),
                }
            }
            ServerHopOutcome::Ok(Err(crate::http::h1::HttpError::BodyCancelled)) => {
                match classify_server_producer_cancellation(&producer_outcome_cx) {
                    ServerProducerCancellation::DeadlineExceeded => {
                        NativeH3ProducerOutcome::DeadlineExceeded
                    }
                    ServerProducerCancellation::Cancelled => NativeH3ProducerOutcome::Cancelled,
                }
            }
            ServerHopOutcome::Ok(Ok(_))
            | ServerHopOutcome::Ok(Err(_))
            | ServerHopOutcome::Panicked(_) => NativeH3ProducerOutcome::Failed,
            ServerHopOutcome::Cancelled => NativeH3ProducerOutcome::Cancelled,
            ServerHopOutcome::DeadlineExceeded => NativeH3ProducerOutcome::DeadlineExceeded,
            ServerHopOutcome::ConnectionLost => NativeH3ProducerOutcome::ConnectionLost,
        }
    });
    let producer = NativeH3RouterProducer {
        inner: run,
        lifecycle: lifecycle.clone(),
        producer_cx: producer_cx.clone(),
        completed: false,
    };
    (body, producer_cx, lifecycle, producer)
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn h3_trailers_from_body_map(
    trailers: crate::http::HeaderMap,
) -> Result<Vec<(String, String)>, crate::http::h3::NativeH3SessionError> {
    trailers
        .iter()
        .map(|(name, value)| {
            let value = value.to_str().map_err(|_| {
                crate::http::h3::NativeH3SessionError::Protocol(H3Error::InvalidFrame(
                    "HTTP/3 trailer value is not valid UTF-8",
                ))
            })?;
            Ok((name.as_str().to_string(), value.to_string()))
        })
        .collect()
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn cancel_native_h3_produced(
    cx: &Cx,
    session: &mut NativeH3Session,
    connection: &mut QuicConnection,
    state: &mut ActiveNativeH3ProducedResponse,
    message: &'static str,
) -> Result<(), crate::http::h3::NativeH3SessionError> {
    let reset = if state.reset_queued {
        Ok(())
    } else {
        session.cancel_request(cx, connection, state.writer.stream_id())
    };
    mark_native_h3_produced_cancelled(state, message);
    reset
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn fail_native_h3_produced_poll(
    cx: &Cx,
    session: &mut NativeH3Session,
    connection: &mut QuicConnection,
    state: &mut ActiveNativeH3ProducedResponse,
    message: &'static str,
    error: crate::http::h3::NativeH3SessionError,
) -> crate::http::h3::NativeH3SessionError {
    if let Some(diagnostic) = native_h3_produced_error_diagnostic(&error) {
        record_native_h3_body_diagnostic(state.writer.stream_id(), diagnostic, message);
    }
    cancel_native_h3_produced(cx, session, connection, state, message)
        .err()
        .unwrap_or(error)
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn mark_native_h3_produced_cancelled(
    state: &mut ActiveNativeH3ProducedResponse,
    message: &'static str,
) {
    if let Some(producer_cx) = &state.producer_cx {
        producer_cx.cancel_with(CancelKind::ParentCancelled, Some(message));
    }
    state.reset_queued = true;
    state.plan = None;
    state.body = None;
    state.terminal = None;
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn poll_one_native_h3_produced(
    cx: &Cx,
    session: &mut NativeH3Session,
    connection: &mut QuicConnection,
    state: &mut ActiveNativeH3ProducedResponse,
    task_cx: &mut TaskContext<'_>,
) -> Poll<Result<NativeH3ProducedStep, crate::http::h3::NativeH3SessionError>> {
    let stream_id = state.writer.stream_id();
    loop {
        if state.reset_queued {
            let exited = state
                .lifecycle
                .as_ref()
                .is_none_or(|lifecycle| lifecycle.poll_outcome(task_cx).is_ready());
            if exited {
                return Poll::Ready(Ok(NativeH3ProducedStep::Reap(
                    NativeH3ProducedEvent::RequestReset { stream_id },
                )));
            }
            return Poll::Pending;
        }

        if state.writer.has_pending_write() {
            match state.writer.poll_flush_one(cx, connection, task_cx) {
                Poll::Ready(Ok(Some(NativeH3WriteEvent::Head { .. }))) => {
                    if state.head_only {
                        return Poll::Ready(Ok(NativeH3ProducedStep::Event(
                            NativeH3ProducedEvent::HeadQueued {
                                stream_id,
                                status: state.status,
                            },
                        )));
                    }
                    let plan = state.plan.take().ok_or(
                        crate::http::h3::NativeH3SessionError::InvalidState(
                            "HTTP/3 response producer plan disappeared before HEADERS commit",
                        ),
                    );
                    let plan = match plan {
                        Ok(plan) => plan,
                        Err(error) => {
                            return Poll::Ready(Err(fail_native_h3_produced_poll(
                                cx,
                                session,
                                connection,
                                state,
                                "HTTP/3 response producer plan disappeared",
                                error,
                            )));
                        }
                    };
                    let (body, producer_cx, lifecycle, producer) =
                        make_native_h3_producer(cx, plan);
                    state.body = Some(body);
                    state.producer_cx = Some(producer_cx);
                    state.lifecycle = Some(lifecycle);
                    return Poll::Ready(Ok(NativeH3ProducedStep::Event(
                        NativeH3ProducedEvent::ProducerReady {
                            stream_id,
                            producer,
                        },
                    )));
                }
                Poll::Ready(Ok(Some(NativeH3WriteEvent::Data { payload_bytes }))) => {
                    return Poll::Ready(Ok(NativeH3ProducedStep::Event(
                        NativeH3ProducedEvent::DataQueued {
                            stream_id,
                            payload_bytes,
                        },
                    )));
                }
                Poll::Ready(Ok(Some(
                    NativeH3WriteEvent::Trailers | NativeH3WriteEvent::Finished,
                ))) => {
                    return Poll::Ready(Ok(NativeH3ProducedStep::Event(
                        NativeH3ProducedEvent::TerminalQueued { stream_id },
                    )));
                }
                Poll::Ready(Ok(None)) => {}
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(fail_native_h3_produced_poll(
                        cx,
                        session,
                        connection,
                        state,
                        "HTTP/3 response transport write failed",
                        error,
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if state.writer.is_finished() {
            match connection.poll_stream_queue_drained(cx, stream_id, task_cx) {
                Poll::Ready(Ok(())) => {
                    return Poll::Ready(Ok(NativeH3ProducedStep::Reap(
                        NativeH3ProducedEvent::ResponseSent {
                            stream_id,
                            status: state.status,
                        },
                    )));
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(fail_native_h3_produced_poll(
                        cx,
                        session,
                        connection,
                        state,
                        "HTTP/3 response terminal drain failed",
                        crate::http::h3::NativeH3SessionError::Transport(error),
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        let producer_outcome = match state.lifecycle.as_ref() {
            Some(lifecycle) => match lifecycle.poll_outcome(task_cx) {
                Poll::Ready(outcome) => Some(outcome),
                Poll::Pending => None,
            },
            None => {
                let error = crate::http::h3::NativeH3SessionError::InvalidState(
                    "HTTP/3 producer state is unavailable after HEADERS commit",
                );
                return Poll::Ready(Err(fail_native_h3_produced_poll(
                    cx,
                    session,
                    connection,
                    state,
                    "HTTP/3 response producer state disappeared",
                    error,
                )));
            }
        };

        if let Some(
            outcome @ (NativeH3ProducerOutcome::Failed
            | NativeH3ProducerOutcome::Cancelled
            | NativeH3ProducerOutcome::DeadlineExceeded
            | NativeH3ProducerOutcome::ConnectionLost),
        ) = producer_outcome
        {
            match outcome {
                NativeH3ProducerOutcome::Failed => record_native_h3_body_diagnostic(
                    stream_id,
                    WebBodyDiagnostic::ResponseProducerFailure,
                    "response producer returned an error or panicked",
                ),
                NativeH3ProducerOutcome::ConnectionLost => record_native_h3_body_diagnostic(
                    stream_id,
                    WebBodyDiagnostic::ClientAbort,
                    "response producer lost its client connection",
                ),
                NativeH3ProducerOutcome::DeadlineExceeded => {
                    error!(
                        stream_id = stream_id.0,
                        diagnostic = "ASUP-E501",
                        "[ASUP-E501] h3 response producer exceeded the request deadline"
                    );
                }
                NativeH3ProducerOutcome::Cancelled => {}
                NativeH3ProducerOutcome::Finished { .. } => unreachable!(),
            }
            if let Err(error) = cancel_native_h3_produced(
                cx,
                session,
                connection,
                state,
                "HTTP/3 response producer failed or was cancelled",
            ) {
                return Poll::Ready(Err(error));
            }
            continue;
        }

        if let Some(terminal) = state.terminal.take() {
            let Some(NativeH3ProducerOutcome::Finished {
                total_bytes,
                terminal: producer_terminal,
            }) = producer_outcome
            else {
                state.terminal = Some(terminal);
                return Poll::Pending;
            };
            let terminal_matches = matches!(
                (&terminal, producer_terminal),
                (NativeH3BodyTerminal::Eof, Http3ProducerTerminal::Finished)
                    | (
                        NativeH3BodyTerminal::Trailers(_),
                        Http3ProducerTerminal::Trailers
                    )
            );
            if total_bytes != state.emitted_bytes || !terminal_matches {
                record_native_h3_body_diagnostic(
                    stream_id,
                    WebBodyDiagnostic::ResponseProducerFailure,
                    "response producer terminal accounting mismatch",
                );
                if let Err(error) = cancel_native_h3_produced(
                    cx,
                    session,
                    connection,
                    state,
                    "HTTP/3 response producer terminal accounting mismatch",
                ) {
                    return Poll::Ready(Err(error));
                }
                continue;
            }
            let queued = match terminal {
                NativeH3BodyTerminal::Eof => state.writer.finish(),
                NativeH3BodyTerminal::Trailers(fields) => state.writer.queue_trailers(&fields),
            };
            if let Err(error) = queued {
                return Poll::Ready(Err(fail_native_h3_produced_poll(
                    cx,
                    session,
                    connection,
                    state,
                    "HTTP/3 response terminal frame was invalid",
                    error,
                )));
            }
            continue;
        }

        if let Some(NativeH3ProducerOutcome::Finished { total_bytes, .. }) = producer_outcome
            && total_bytes < state.emitted_bytes
        {
            record_native_h3_body_diagnostic(
                stream_id,
                WebBodyDiagnostic::ResponseProducerFailure,
                "response producer byte accounting regressed",
            );
            if let Err(error) = cancel_native_h3_produced(
                cx,
                session,
                connection,
                state,
                "HTTP/3 response producer byte accounting regressed",
            ) {
                return Poll::Ready(Err(error));
            }
            continue;
        }

        let terminal_only = matches!(
            producer_outcome,
            Some(NativeH3ProducerOutcome::Finished { total_bytes, .. })
                if total_bytes == state.emitted_bytes
        );
        let readiness = if terminal_only {
            match connection.poll_stream_queue_drained(cx, stream_id, task_cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(0)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            connection.poll_stream_write_ready(cx, stream_id, state.max_data_wire_bytes, task_cx)
        };
        match readiness {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(error)) => {
                return Poll::Ready(Err(fail_native_h3_produced_poll(
                    cx,
                    session,
                    connection,
                    state,
                    "HTTP/3 response DATA readiness failed",
                    crate::http::h3::NativeH3SessionError::Transport(error),
                )));
            }
            Poll::Pending => return Poll::Pending,
        }

        let body = state
            .body
            .as_mut()
            .ok_or(crate::http::h3::NativeH3SessionError::InvalidState(
                "HTTP/3 response body receiver disappeared",
            ));
        let body = match body {
            Ok(body) => body,
            Err(error) => {
                return Poll::Ready(Err(fail_native_h3_produced_poll(
                    cx,
                    session,
                    connection,
                    state,
                    "HTTP/3 response body receiver disappeared",
                    error,
                )));
            }
        };
        match Pin::new(body).poll_frame(task_cx) {
            Poll::Ready(Some(Ok(BodyFrame::Data(data)))) => {
                let bytes = data.into_inner();
                let new_total = match state
                    .emitted_bytes
                    .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                {
                    Some(total) => total,
                    None => {
                        record_native_h3_body_diagnostic(
                            stream_id,
                            WebBodyDiagnostic::ResponseProducerFailure,
                            "response byte accounting overflowed",
                        );
                        if let Err(error) = cancel_native_h3_produced(
                            cx,
                            session,
                            connection,
                            state,
                            "HTTP/3 response byte accounting overflow",
                        ) {
                            return Poll::Ready(Err(error));
                        }
                        continue;
                    }
                };
                if terminal_only
                    || matches!(
                        producer_outcome,
                        Some(NativeH3ProducerOutcome::Finished { total_bytes, .. })
                            if new_total > total_bytes
                    )
                {
                    record_native_h3_body_diagnostic(
                        stream_id,
                        WebBodyDiagnostic::ResponseProducerFailure,
                        "response produced bytes after terminal accounting",
                    );
                    if let Err(error) = cancel_native_h3_produced(
                        cx,
                        session,
                        connection,
                        state,
                        "HTTP/3 response produced bytes after terminal accounting",
                    ) {
                        return Poll::Ready(Err(error));
                    }
                    continue;
                }
                state.emitted_bytes = new_total;
                if let Err(error) = state.writer.queue_data(bytes) {
                    if let Some(diagnostic) = native_h3_produced_error_diagnostic(&error) {
                        record_native_h3_body_diagnostic(
                            stream_id,
                            diagnostic,
                            "response DATA frame could not be queued",
                        );
                    }
                    if let Err(reset_error) = cancel_native_h3_produced(
                        cx,
                        session,
                        connection,
                        state,
                        "HTTP/3 response DATA frame was invalid",
                    ) {
                        return Poll::Ready(Err(reset_error));
                    }
                    if matches!(error, crate::http::h3::NativeH3SessionError::Transport(_)) {
                        return Poll::Ready(Err(error));
                    }
                    continue;
                }
            }
            Poll::Ready(Some(Ok(BodyFrame::Trailers(trailers)))) => {
                match h3_trailers_from_body_map(trailers) {
                    Ok(fields) => state.terminal = Some(NativeH3BodyTerminal::Trailers(fields)),
                    Err(_) => {
                        record_native_h3_body_diagnostic(
                            stream_id,
                            WebBodyDiagnostic::ResponseProducerFailure,
                            "response trailers were invalid",
                        );
                        if let Err(error) = cancel_native_h3_produced(
                            cx,
                            session,
                            connection,
                            state,
                            "HTTP/3 response trailers were invalid",
                        ) {
                            return Poll::Ready(Err(error));
                        }
                    }
                }
            }
            Poll::Ready(Some(Err(crate::http::h1::HttpError::BodyCancelled))) => {
                // The lifecycle future carries the authoritative cancellation
                // cause. It was polled above and registered this task's waker;
                // wait for that outcome rather than mislabeling a deadline or
                // peer reset as a producer failure.
                return Poll::Pending;
            }
            Poll::Ready(Some(Err(_error))) => {
                record_native_h3_body_diagnostic(
                    stream_id,
                    WebBodyDiagnostic::ResponseProducerFailure,
                    "response body channel failed",
                );
                if let Err(error) = cancel_native_h3_produced(
                    cx,
                    session,
                    connection,
                    state,
                    "HTTP/3 response body channel failed",
                ) {
                    return Poll::Ready(Err(error));
                }
            }
            Poll::Ready(None) => state.terminal = Some(NativeH3BodyTerminal::Eof),
            Poll::Pending => return Poll::Pending,
        }
    }
}

/// Default-on request trace configuration for [`Router`]
/// (br-asupersync-server-stack-hardening-eeexl1.3 AC3).
struct DefaultTrace {
    policy: RequestTracePolicy,
    time_getter: fn() -> Time,
    counter: Arc<AtomicU64>,
    sink: Option<RequestLogSink>,
}

impl Default for DefaultTrace {
    fn default() -> Self {
        Self {
            // Log-only default: structured request log lines without
            // response-header mutation. Opt into duration/trace headers via
            // `Router::with_default_trace_policy`.
            policy: RequestTracePolicy {
                duration_header: None,
                trace_header: None,
            },
            time_getter: wall_clock_now,
            counter: Arc::new(AtomicU64::new(1)),
            sink: None,
        }
    }
}

impl Default for Router {
    fn default() -> Self {
        Self {
            routes: Vec::new(),
            nested: Vec::new(),
            fallback: None,
            extensions: Extensions::new(),
            server_body_policy: None,
            body_policy: None,
            default_trace: Some(DefaultTrace::default()),
        }
    }
}

impl Router {
    /// Create a new empty router.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a route with the given pattern and method router.
    #[must_use]
    pub fn route(mut self, pattern: &str, method_router: MethodRouter) -> Self {
        self.routes
            .push((RoutePattern::parse(pattern), method_router));
        self
    }

    /// Mount a sub-router at the given prefix.
    #[must_use]
    pub fn nest(mut self, prefix: &str, router: Self) -> Self {
        self.nested.push((prefix.to_string(), router));
        self
    }

    /// Set a fallback handler for unmatched routes.
    #[must_use]
    pub fn fallback(mut self, handler: impl Handler) -> Self {
        self.fallback = Some(Box::new(handler));
        self
    }

    /// Wrap every route registered **so far** — including nested routers and
    /// the fallback — with the given middleware layer.
    ///
    /// Any [`Layer`] from `asupersync::web::middleware` (or any custom
    /// `Layer<Box<dyn Handler>>` whose output is a [`Handler`]) can be used;
    /// web and service middleware share that one composition trait
    /// (br-asupersync-server-stack-hardening-eeexl1.3).
    ///
    /// # Onion ordering
    ///
    /// Each `.layer(...)` call wraps everything registered so far, so the
    /// **last-added layer is the outermost**: it sees the request first and
    /// the response last. This matches [`MiddlewareStack`] and
    /// `ServiceBuilder` composition in this crate:
    ///
    /// ```text
    /// Router::new()
    ///     .route("/a", get(handler))
    ///     .layer(auth)        // added first  → inner
    ///     .layer(request_id)  // added last   → outer
    ///
    ///            ┌──────────── request_id ────────────┐
    ///            │        ┌─────── auth ───────┐      │
    /// Request ──▶│ before │ before ┌─────────┐ │      │
    ///            │        │        │ handler │ │      │
    /// Response ◀─│ after  │ after  └─────────┘ │      │
    ///            │        └────────────────────┘      │
    ///            └─────────────────────────────────────┘
    /// ```
    ///
    /// # Scope
    ///
    /// Routes registered **after** a `.layer(...)` call are *not* wrapped by
    /// it. Register routes first, then layers, or interleave deliberately when
    /// some routes should bypass a middleware.
    ///
    /// Stateful layers (rate limit, circuit breaker, bulkhead, load shed,
    /// request-ID) hold their shared state in the layer value itself, so one
    /// `.layer(...)` call shares a single limiter/breaker/counter across all
    /// wrapped routes.
    ///
    /// [`MiddlewareStack`]: super::middleware::MiddlewareStack
    #[must_use]
    pub fn layer<L>(mut self, layer: L) -> Self
    where
        L: Layer<Box<dyn Handler>>,
        L::Service: Handler,
    {
        let wrap =
            move |handler: Box<dyn Handler>| -> Box<dyn Handler> { Box::new(layer.layer(handler)) };
        self.apply_wrap(&wrap);
        self
    }

    /// Apply a handler wrapper to all routes, the fallback, and nested routers.
    fn apply_wrap(&mut self, wrap: &dyn Fn(Box<dyn Handler>) -> Box<dyn Handler>) {
        for (_, method_router) in &mut self.routes {
            method_router.map_handlers(wrap);
        }
        if let Some(fallback) = self.fallback.take() {
            self.fallback = Some(wrap(fallback));
        }
        for (_, nested) in &mut self.nested {
            nested.apply_wrap(wrap);
        }
    }

    /// Attach clonable shared typed state for request extraction.
    ///
    /// Handlers can retrieve this state with [`super::extract::State<T>`].
    #[must_use]
    pub fn with_state<T>(mut self, state: T) -> Self
    where
        T: Clone + Send + Sync + 'static,
    {
        self.extensions.insert_typed(state);
        self
    }

    /// Set the outer server request-body policy for this router tree.
    ///
    /// This is the application dispatch boundary, not a replacement for
    /// protocol pre-buffer limits such as
    /// [`crate::http::h1::Http1Config::max_body_size`]. Keep the transport
    /// ceiling at least as strict as this value. On the live HTTP/1 Router
    /// path the resolved policy is also pushed into the shared body writer
    /// before application extraction; every nested router and route can only
    /// tighten it.
    #[must_use]
    pub fn with_server_body_policy(mut self, policy: RequestBodyPolicy) -> Self {
        self.server_body_policy = Some(policy.resolved());
        self
    }

    /// Set the default request-body policy for routes in this router.
    #[must_use]
    pub fn with_body_policy(mut self, policy: RequestBodyPolicy) -> Self {
        self.body_policy = Some(policy.resolved());
        self
    }

    /// Return the configured outer server request-body policy.
    #[must_use]
    pub const fn server_body_policy(&self) -> Option<RequestBodyPolicy> {
        self.server_body_policy
    }

    /// Return the configured router-default request-body policy.
    #[must_use]
    pub const fn body_policy(&self) -> Option<RequestBodyPolicy> {
        self.body_policy
    }

    /// Disable the default request trace.
    ///
    /// By default, every dispatched request emits structured start/completion
    /// log events carrying outcome severity, duration, and the request id
    /// (generated when the request carries none). Cancelled requests log as
    /// `499` with their cancel reason. This opt-out silences that
    /// instrumentation entirely.
    #[must_use]
    pub fn without_default_trace(mut self) -> Self {
        self.default_trace = None;
        self
    }

    /// Customize the default request-trace policy, e.g. to stamp
    /// `x-response-time-ms` / `x-trace-id` response headers (off by default).
    #[must_use]
    pub fn with_default_trace_policy(mut self, policy: RequestTracePolicy) -> Self {
        self.default_trace
            .get_or_insert_with(DefaultTrace::default)
            .policy = policy;
        self
    }

    /// Use a custom time source for the default request trace
    /// (deterministic tests).
    #[must_use]
    pub fn with_default_trace_time_getter(mut self, time_getter: fn() -> Time) -> Self {
        self.default_trace
            .get_or_insert_with(DefaultTrace::default)
            .time_getter = time_getter;
        self
    }

    /// Attach a structured record sink observing every traced exchange.
    ///
    /// Golden tests use this to pin the request log schema; production
    /// deployments normally rely on the `tracing` events instead.
    #[must_use]
    pub fn with_default_trace_record_sink(mut self, sink: RequestLogSink) -> Self {
        self.default_trace
            .get_or_insert_with(DefaultTrace::default)
            .sink = Some(sink);
        self
    }

    /// Handle an incoming request.
    ///
    /// Top-level routes are selected by path specificity. Nested routers are
    /// selected by longest matching prefix after top-level route selection.
    #[must_use]
    pub fn handle(&self, req: Request) -> Response {
        let cx = Cx::new(
            next_bootstrap_region_id(),
            next_bootstrap_task_id(),
            Budget::INFINITE,
        );
        futures_lite::future::block_on(self.handle_with_cx(&cx, req))
    }

    /// Convert this router into a production-listener handler.
    ///
    /// The returned cloneable handler is accepted directly by both
    /// [`crate::http::h1::listener::Http1Listener`] and
    /// [`crate::http::h2::listener::Http2Listener`]. The listeners install a
    /// request-scoped [`Cx`] before polling the handler; this adapter reuses
    /// that context so router handlers inherit the listener's deadline,
    /// cancellation, panic-isolation, and graceful-drain semantics.
    ///
    /// If the handler is polled outside a listener request region, it fails
    /// closed with `500 Internal Server Error` instead of minting a fresh
    /// capability context.
    ///
    /// ```ignore
    /// let app = Router::new().route("/health", get(health));
    /// let listener = Http1Listener::bind("127.0.0.1:8080", app.into_http_handler()).await?;
    /// listener.run(&runtime_handle).await?;
    /// ```
    #[must_use]
    pub fn into_http_handler(
        self,
    ) -> impl Fn(HttpRequest) -> HttpHandlerFuture + Clone + Send + Sync + 'static {
        let router = Arc::new(self);
        move |request| {
            let router = Arc::clone(&router);
            Box::pin(async move {
                let Some(cx) = Cx::current() else {
                    return HttpResponse::new(
                        500,
                        "Internal Server Error",
                        b"request context unavailable".to_vec(),
                    )
                    .with_header("content-type", "text/plain; charset=utf-8");
                };
                router.handle_http_request_with_cx(&cx, request).await
            })
        }
    }

    /// Connect this router to an established native HTTP/3 session.
    ///
    /// The returned caller-driven bridge consumes decoded session events and
    /// queues final responses on the supplied native QUIC connection. It does
    /// not create a listener, handshake TLS/ALPN, or own an event loop.
    #[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
    #[must_use]
    pub fn into_native_h3_router(self) -> NativeH3Router {
        NativeH3Router::new(self)
    }

    /// Connect this router to an established native HTTP/3 session with
    /// explicit buffering limits.
    #[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
    #[must_use]
    pub fn into_native_h3_router_with_config(self, config: NativeH3RouterConfig) -> NativeH3Router {
        NativeH3Router::with_config(self, config)
    }

    /// Convert this router into an HTTP/1-only handler that supports live
    /// WebSocket ownership handoff.
    ///
    /// Ordinary responses are byte-for-byte identical to
    /// [`Router::into_http_handler`]. A handler that calls
    /// [`crate::web::websocket::WebSocketUpgrade::on_upgrade`] registers a
    /// request-scoped one-shot action; the production HTTP/1 listener commits
    /// that action only after the final valid `101` is completely flushed.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn into_http1_handler(
        self,
    ) -> impl Fn(HttpRequest) -> Http1HandlerFuture + Clone + Send + Sync + 'static {
        let router = Arc::new(self);
        move |request| {
            let router = Arc::clone(&router);
            Box::pin(async move {
                let Some(cx) = Cx::current() else {
                    return Http1Response::new(
                        HttpResponse::new(
                            500,
                            "Internal Server Error",
                            b"request context unavailable".to_vec(),
                        )
                        .with_header("content-type", "text/plain; charset=utf-8"),
                    );
                };
                router.handle_http1_request_with_cx(&cx, request).await
            })
        }
    }

    /// Convert this router into an HTTP/1 handler with live request-body ingress.
    ///
    /// The listener supplies the authoritative request-region [`Cx`] and
    /// publishes the validated request head before body EOF. Handlers may take
    /// [`crate::web::StreamingRawBody`] as their final extractor to consume the
    /// live, bounded body queue. Existing buffered extractors deliberately fail
    /// closed on this entry point instead of observing an empty compatibility
    /// body.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn into_http1_streaming_handler(
        self,
    ) -> impl Fn(Cx, StreamingServerRequest) -> HttpHandlerFuture + Clone + Send + Sync + 'static
    {
        let router = Arc::new(self);
        move |cx, request| {
            let router = Arc::clone(&router);
            Box::pin(async move {
                router
                    .handle_http1_streaming_request_with_cx(&cx, request)
                    .await
            })
        }
    }

    /// Convert this router into a production HTTP/1 produced-response handler.
    ///
    /// Existing handlers, middleware, route matching, request tracing, and
    /// extractors remain unchanged. A route may extract
    /// [`crate::web::Http1StreamResponder`] to register one bounded chunked or
    /// exact `Content-Length` producer. Body-allowed routes that do not
    /// register a producer and do not set framing headers are adapted as one
    /// bounded chunk containing their buffered response body. `1xx`, `204`,
    /// `205`, `304`, explicit framing headers on ordinary buffered responses,
    /// and explicit `Transfer-Encoding` responses fail closed with `500` on
    /// this adapter; use [`Router::into_http_handler`] when those responses are
    /// required.
    ///
    /// This adapter intentionally exposes the current produced-listener
    /// contract: listener-owned HTTP/1.1 chunked or fixed-length framing, one
    /// request per connection, and `Connection: close`. It does not provide
    /// HTTP/2 or HTTP/3 response streaming, WebSocket handoff, implicit
    /// fixed-length conversion for buffered routes, or full-duplex
    /// request/response progress. The Router trace covers handler dispatch and
    /// final response-head binding; producer lifetime remains observable
    /// through the HTTP/1 listener/request lifecycle rather than that handler
    /// duration record.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn into_http1_produced_handler(
        self,
    ) -> impl Fn(Cx, StreamingServerRequest) -> Http1ProducedHandlerFuture + Clone + Send + Sync + 'static
    {
        let router = Arc::new(self);
        move |cx, request| {
            let router = Arc::clone(&router);
            Box::pin(async move {
                router
                    .handle_http1_produced_request_with_cx(&cx, request)
                    .await
            })
        }
    }

    /// Convert this router into a production HTTP/2 produced-response handler.
    ///
    /// Existing buffered routes retain the ordinary H2 response path. A route
    /// may extract [`crate::web::Http2StreamResponder`] to register one bounded
    /// body producer; the listener starts it only after the response head is
    /// validated and polls at most one frame when that stream has send credit.
    /// The adapter is accepted by [`crate::http::h2::listener::Http2Listener`]
    /// through [`crate::http::h2::listener::Http2Listener::run_produced`].
    ///
    /// This is response-side H2 streaming only. Request bodies remain buffered,
    /// server push authoring is unchanged, and this API makes no HTTP/3 or
    /// full-duplex claim.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn into_http2_produced_handler(
        self,
    ) -> impl Fn(HttpRequest) -> Http2ProducedHandlerFuture + Clone + Send + Sync + 'static {
        let router = Arc::new(self);
        move |request| {
            let router = Arc::clone(&router);
            Box::pin(async move {
                let Some(cx) = Cx::current() else {
                    return http2_produced_refusal("request context unavailable");
                };
                router
                    .handle_http2_produced_request_with_cx(&cx, request)
                    .await
            })
        }
    }

    /// Dispatch one listener request through this router with an explicit
    /// capability context.
    ///
    /// This is the non-ambient entry point for embedding the router in custom
    /// transports. Production HTTP listeners normally use
    /// [`Router::into_http_handler`] so their request-region `Cx` is forwarded
    /// automatically.
    pub async fn handle_http_request_with_cx(&self, cx: &Cx, request: HttpRequest) -> HttpResponse {
        let request = web_request_from_http(request);
        http_response_from_web(self.handle_with_cx(cx, request).await)
    }

    /// Dispatch one HTTP/1 request while retaining an explicit upgrade action.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn handle_http1_request_with_cx(
        &self,
        cx: &Cx,
        request: HttpRequest,
    ) -> Http1Response {
        let slot = Http1UpgradeSlot::default();
        let mut request = web_request_from_http(request);
        request.extensions.insert_typed(slot.clone());
        let response = http_response_from_web(self.handle_with_cx(cx, request).await);
        let upgrade = match slot.take() {
            Ok(None) => return Http1Response::new(response),
            Ok(Some(upgrade)) => upgrade,
            Err(()) => {
                return Http1Response::new(
                    HttpResponse::new(
                        500,
                        "Internal Server Error",
                        b"duplicate WebSocket upgrade callback registration".to_vec(),
                    )
                    .with_header("content-type", "text/plain; charset=utf-8")
                    .with_header("connection", "close"),
                );
            }
        };
        if valid_websocket_handoff_response(&response, &upgrade) {
            Http1Response::new(response).with_upgrade(upgrade)
        } else {
            Http1Response::new(
                HttpResponse::new(
                    500,
                    "Internal Server Error",
                    b"registered WebSocket upgrade did not produce a valid final 101".to_vec(),
                )
                .with_header("content-type", "text/plain; charset=utf-8")
                .with_header("connection", "close"),
            )
        }
    }

    /// Dispatch a live HTTP/1 request through this router with its listener Cx.
    ///
    /// Only the validated request head is copied into the legacy [`Request`]
    /// fields. The live body is installed in a private one-shot extension and
    /// remains owned by a guard for the whole dispatch, so an unclaimed body is
    /// dropped promptly even if middleware retains a cloned request.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn handle_http1_streaming_request_with_cx(
        &self,
        cx: &Cx,
        request: StreamingServerRequest,
    ) -> HttpResponse {
        let Some((request, _body_control)) = web_request_from_streaming_http(request) else {
            return HttpResponse::new(
                500,
                "Internal Server Error",
                b"streaming request body slot collision".to_vec(),
            )
            .with_header("content-type", "text/plain; charset=utf-8")
            .with_header("connection", "close");
        };
        http_response_from_web(self.handle_with_cx(cx, request).await)
    }

    /// Dispatch a live HTTP/1 request and bind any registered web response
    /// producer to the listener-owned request context.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn handle_http1_produced_request_with_cx(
        &self,
        cx: &Cx,
        request: StreamingServerRequest,
    ) -> Http1ProducedResponse {
        let Some((mut request, _body_control)) = web_request_from_streaming_http(request) else {
            return http1_produced_refusal("streaming request body slot collision");
        };
        let slot = Http1StreamSlot::default();
        request.extensions.insert_typed(slot.clone());

        let (mut response, binding) = self
            .handle_http1_produced_web_response_with_cx(cx, request, &slot)
            .await;
        let plan = match binding {
            Ok(Some(plan)) => plan,
            Ok(None) | Err(_) => Http1StreamPlan::buffered(std::mem::take(&mut response.body)),
        };
        plan.into_produced(response)
    }

    /// Dispatch one HTTP/2 request and bind any registered produced body to
    /// the listener-owned request context.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn handle_http2_produced_request_with_cx(
        &self,
        cx: &Cx,
        request: HttpRequest,
    ) -> Http2ProducedResponse {
        let mut request = web_request_from_http(request);
        let slot = Http2StreamSlot::default();
        request.extensions.insert_typed(slot.clone());

        let (response, binding) = self
            .handle_http2_produced_web_response_with_cx(cx, request, &slot)
            .await;
        match binding {
            Ok(Some(plan)) => plan.into_produced(response),
            Ok(None) | Err(_) => Http2ProducedResponse::buffered(http_response_from_web(response)),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn handle_http1_produced_web_response_with_cx(
        &self,
        cx: &Cx,
        mut request: Request,
        slot: &Http1StreamSlot,
    ) -> (Response, Result<Option<Http1StreamPlan>, &'static str>) {
        let binding = Arc::new(parking_lot::Mutex::new(None));
        let response = if let Some(trace) = &self.default_trace {
            Self::ensure_request_id(&mut request, &trace.counter);
            let binding_for_dispatch = Arc::clone(&binding);
            let (trace_policy, trace_policy_refusal) = http1_produced_trace_policy(&trace.policy);
            trace_request(
                &trace_policy,
                trace.time_getter,
                trace.sink.as_ref(),
                cx,
                request,
                move |request| async move {
                    let response = match trace_policy_refusal {
                        Some(reason) => http1_stream_refusal_response(reason),
                        None => self.handle_inner(cx, request).await,
                    };
                    let result = slot.bind_response(&response);
                    let refusal = result.as_ref().err().copied();
                    *binding_for_dispatch.lock() = Some(result);
                    refusal.map_or(response, http1_stream_refusal_response)
                },
            )
            .await
        } else {
            let response = self.handle_inner(cx, request).await;
            let result = slot.bind_response(&response);
            let refusal = result.as_ref().err().copied();
            *binding.lock() = Some(result);
            refusal.map_or(response, http1_stream_refusal_response)
        };
        let binding = Arc::try_unwrap(binding)
            .ok()
            .expect("produced-response dispatch releases its binding cell")
            .into_inner()
            .expect("produced-response dispatch always seals its request slot");
        (response, binding)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn handle_http2_produced_web_response_with_cx(
        &self,
        cx: &Cx,
        mut request: Request,
        slot: &Http2StreamSlot,
    ) -> (Response, Result<Option<Http2StreamPlan>, &'static str>) {
        let suppress_response_body = request.method.eq_ignore_ascii_case("HEAD");
        let binding = Arc::new(parking_lot::Mutex::new(None));
        let response = if let Some(trace) = &self.default_trace {
            Self::ensure_request_id(&mut request, &trace.counter);
            let binding_for_dispatch = Arc::clone(&binding);
            let (trace_policy, trace_policy_refusal) = http2_produced_trace_policy(&trace.policy);
            trace_request(
                &trace_policy,
                trace.time_getter,
                trace.sink.as_ref(),
                cx,
                request,
                move |request| async move {
                    let response = match trace_policy_refusal {
                        Some(reason) => http1_stream_refusal_response(reason),
                        None => self.handle_inner(cx, request).await,
                    };
                    let result = slot.bind_response(&response, suppress_response_body);
                    let refusal = result.as_ref().err().copied();
                    *binding_for_dispatch.lock() = Some(result);
                    refusal.map_or(response, http1_stream_refusal_response)
                },
            )
            .await
        } else {
            let response = self.handle_inner(cx, request).await;
            let result = slot.bind_response(&response, suppress_response_body);
            let refusal = result.as_ref().err().copied();
            *binding.lock() = Some(result);
            refusal.map_or(response, http1_stream_refusal_response)
        };
        let binding = Arc::try_unwrap(binding)
            .ok()
            .expect("HTTP/2 produced-response dispatch releases its binding cell")
            .into_inner()
            .expect("HTTP/2 produced-response dispatch seals its request slot");
        (response, binding)
    }

    /// Handle an incoming request with an explicit capability context.
    ///
    /// This is the async path used by runtime-integrated handlers and lab
    /// harnesses that already own a [`Cx`].
    ///
    /// Unless [`Router::without_default_trace`] was called, dispatch runs
    /// inside the default request trace: structured start/completion log
    /// events with outcome severity and duration, a generated request id when
    /// the request carries none, and `499` logging for cancelled requests.
    /// Nested routers do not re-trace — only the outermost router (the one
    /// whose `handle_with_cx` is invoked) instruments the exchange.
    #[must_use]
    pub async fn handle_with_cx(&self, cx: &Cx, mut req: Request) -> Response {
        if let Some(trace) = &self.default_trace {
            Self::ensure_request_id(&mut req, &trace.counter);
            return trace_request(
                &trace.policy,
                trace.time_getter,
                trace.sink.as_ref(),
                cx,
                req,
                |req| self.handle_inner(cx, req),
            )
            .await;
        }
        self.handle_inner(cx, req).await
    }

    /// Generate a request id when the request carries none, mirroring it
    /// into the `x-request-id` header so a downstream
    /// [`super::middleware::RequestIdMiddleware`] reuses the same id instead
    /// of minting a divergent one.
    fn ensure_request_id(req: &mut Request, counter: &AtomicU64) {
        if resolve_trace_id(req).is_none() {
            let id = format!("req-{}", counter.fetch_add(1, Ordering::Relaxed));
            req.extensions.insert("request_id", id.clone());
            req.headers.insert("x-request-id".to_string(), id);
        }
    }

    /// Route-match and dispatch without trace instrumentation.
    async fn handle_inner(&self, cx: &Cx, mut req: Request) -> Response {
        let inherited_policy = explicit_policy_state_from_extensions(&req.extensions);
        let local_extension_policy = explicit_policy_state_from_extensions(&self.extensions);
        req.extensions.extend_from(&self.extensions);
        let local_policy = meet_optional_policy_state(
            local_extension_policy,
            meet_optional_policy_state(
                self.server_body_policy
                    .map(RequestBodyPolicyState::from_policy),
                self.body_policy.map(RequestBodyPolicyState::from_policy),
            ),
        );
        if let Err(response) = apply_request_body_policy(&mut req, inherited_policy, local_policy) {
            return response;
        }

        // Pick the most specific top-level route. First-registered only wins
        // among equal-specificity routes; broad wildcard routes must not shadow
        // narrower protected paths.
        let mut best_route: Option<(RouteSpecificity, &MethodRouter, HashMap<String, String>)> =
            None;
        for (pattern, method_router) in &self.routes {
            if let Some(route_match) = pattern.matches(&req.path) {
                match &best_route {
                    Some((best_specificity, _, _))
                        if *best_specificity >= route_match.specificity => {}
                    _ => {
                        best_route =
                            Some((route_match.specificity, method_router, route_match.params));
                    }
                }
            }
        }
        if let Some((_, method_router, params)) = best_route {
            req.path_params = params;
            return method_router.dispatch(cx, req).await;
        }

        // Check nested routers.
        let mut best_nested_match: Option<(usize, &Self, String)> = None;
        for (prefix, router) in &self.nested {
            if let Some(sub_path) = strip_prefix(&req.path, prefix) {
                let normalized_len = prefix.trim_end_matches('/').len();
                match &best_nested_match {
                    Some((best_len, _, _)) if *best_len >= normalized_len => {}
                    _ => best_nested_match = Some((normalized_len, router, sub_path)),
                }
            }
        }
        if let Some((_, router, sub_path)) = best_nested_match {
            req.path = sub_path;
            // Nested routers dispatch without re-tracing: the outermost
            // router already instruments the exchange.
            return Box::pin(router.handle_inner(cx, req)).await;
        }

        // Fallback.
        if let Some(handler) = &self.fallback {
            return handler.call(cx, req).await;
        }

        StatusCode::NOT_FOUND.into_response()
    }

    /// Return the number of registered routes (not counting nested).
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Return the number of top-level nested routers.
    #[must_use]
    pub fn nested_router_count(&self) -> usize {
        self.nested.len()
    }

    /// Return whether this router has a fallback handler.
    #[must_use]
    pub fn has_fallback(&self) -> bool {
        self.fallback.is_some()
    }

    /// Return a deterministic list of registered route method handlers.
    ///
    /// Nested router entries are reported with their full mount prefix in
    /// [`RouteInfo::pattern`] and [`RouteInfo::mount_prefix`]. The final list is
    /// sorted by full pattern, then by HTTP-conventional method order.
    #[must_use]
    pub fn routes(&self) -> Vec<RouteInfo> {
        let mut entries = Vec::new();
        self.collect_routes("", None, &mut entries);
        entries.sort_by(|left, right| {
            left.pattern
                .cmp(&right.pattern)
                .then_with(|| compare_methods(&left.method, &right.method))
                .then_with(|| left.handler_name.cmp(right.handler_name))
        });
        entries
    }

    /// Return deterministic route-policy metadata for diagnostics and tooling.
    ///
    /// `effective_policy` includes every explicit server, router,
    /// nested-router, and route policy. Router-owned legacy extensions join
    /// that value only after the first explicit [`RequestBodyPolicy`] boundary;
    /// before then they retain the ordinary inner-router last-write-wins
    /// behavior. `None` explicitly distinguishes an unconfigured route from a
    /// configured compatibility-default policy. Request-local middleware
    /// injection is necessarily excluded because it is not known until dispatch.
    #[must_use]
    pub fn route_body_policies(&self) -> Vec<RouteBodyPolicyInfo> {
        let mut entries = Vec::new();
        self.collect_route_body_policies("", None, None, None, &mut entries);
        entries.sort_by(|left, right| {
            left.pattern
                .cmp(&right.pattern)
                .then_with(|| compare_methods(&left.method, &right.method))
                .then_with(|| left.handler_name.cmp(right.handler_name))
        });
        entries
    }

    fn collect_routes(
        &self,
        prefix: &str,
        mount_prefix: Option<&str>,
        entries: &mut Vec<RouteInfo>,
    ) {
        for (pattern, method_router) in &self.routes {
            let full_pattern = join_route_pattern(prefix, &pattern.raw);
            entries.extend(method_router.route_entries(&full_pattern, mount_prefix));
        }

        for (nested_prefix, router) in &self.nested {
            let full_prefix = join_route_pattern(prefix, nested_prefix);
            router.collect_routes(&full_prefix, Some(&full_prefix), entries);
        }
    }

    fn collect_route_body_policies(
        &self,
        prefix: &str,
        mount_prefix: Option<&str>,
        inherited_policy: Option<RequestBodyPolicyState>,
        inherited_legacy: Option<RequestBodyPolicyState>,
        entries: &mut Vec<RouteBodyPolicyInfo>,
    ) {
        let legacy_policy = override_legacy_policy_state(
            inherited_legacy,
            legacy_policy_state_from_extensions(&self.extensions),
        );
        let explicit_policy = meet_optional_policy_state(
            inherited_policy,
            meet_optional_policy_state(
                explicit_policy_state_from_extensions(&self.extensions),
                meet_optional_policy_state(
                    self.server_body_policy
                        .map(RequestBodyPolicyState::from_policy),
                    self.body_policy.map(RequestBodyPolicyState::from_policy),
                ),
            ),
        );
        let router_policy = explicit_policy
            .map(|policy| legacy_policy.map_or(policy, |legacy| policy.tightened_with(legacy)));

        for (pattern, method_router) in &self.routes {
            let full_pattern = join_route_pattern(prefix, &pattern.raw);
            let effective_policy = meet_optional_policy_state(
                router_policy,
                method_router
                    .body_policy
                    .map(RequestBodyPolicyState::from_policy),
            )
            .map(|policy| legacy_policy.map_or(policy, |legacy| policy.tightened_with(legacy)))
            .map(RequestBodyPolicyState::resolved);
            for route in method_router.route_entries(&full_pattern, mount_prefix) {
                entries.push(RouteBodyPolicyInfo {
                    method: route.method,
                    pattern: route.pattern,
                    handler_name: route.handler_name,
                    mount_prefix: route.mount_prefix,
                    route_policy: method_router.body_policy,
                    effective_policy,
                });
            }
        }

        for (nested_prefix, router) in &self.nested {
            let full_prefix = join_route_pattern(prefix, nested_prefix);
            router.collect_route_body_policies(
                &full_prefix,
                Some(&full_prefix),
                router_policy,
                legacy_policy,
                entries,
            );
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RequestBodyPolicyState {
    max_total_body_size: Option<usize>,
    body_limits: Option<BodyLimits>,
    multipart_limits: Option<MultipartLimits>,
}

impl RequestBodyPolicyState {
    fn from_policy(policy: RequestBodyPolicy) -> Self {
        Self {
            max_total_body_size: Some(policy.max_total_body_size),
            body_limits: Some(policy.body_limits),
            multipart_limits: Some(policy.multipart_limits),
        }
    }

    fn tightened_with(self, other: Self) -> Self {
        Self {
            max_total_body_size: meet_optional(self.max_total_body_size, other.max_total_body_size),
            body_limits: meet_optional_with(
                self.body_limits,
                other.body_limits,
                BodyLimits::tightened_with,
            ),
            multipart_limits: meet_optional_with(
                self.multipart_limits,
                other.multipart_limits,
                MultipartLimits::tightened_with,
            ),
        }
    }

    fn resolved(self) -> RequestBodyPolicy {
        let max_total_body_size = self.max_total_body_size.unwrap_or(usize::MAX);
        RequestBodyPolicy {
            max_total_body_size,
            body_limits: self
                .body_limits
                .unwrap_or_default()
                .max_total_body_size(max_total_body_size),
            multipart_limits: self
                .multipart_limits
                .unwrap_or_default()
                .max_total_body_size(max_total_body_size),
        }
    }

    fn is_empty(self) -> bool {
        self.max_total_body_size.is_none()
            && self.body_limits.is_none()
            && self.multipart_limits.is_none()
    }
}

fn meet_optional<T: Ord + Copy>(current: Option<T>, next: Option<T>) -> Option<T> {
    meet_optional_with(current, next, std::cmp::min)
}

fn meet_optional_with<T: Copy>(
    current: Option<T>,
    next: Option<T>,
    meet: impl FnOnce(T, T) -> T,
) -> Option<T> {
    match (current, next) {
        (Some(current), Some(next)) => Some(meet(current, next)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn meet_optional_policy_state(
    current: Option<RequestBodyPolicyState>,
    next: Option<RequestBodyPolicyState>,
) -> Option<RequestBodyPolicyState> {
    meet_optional_with(current, next, RequestBodyPolicyState::tightened_with)
}

fn explicit_policy_state_from_extensions(
    extensions: &Extensions,
) -> Option<RequestBodyPolicyState> {
    if let Some(state) = extensions.get_typed_cloned::<RequestBodyPolicyState>() {
        return Some(state);
    }
    extensions
        .get_typed_cloned::<RequestBodyPolicy>()
        .map(RequestBodyPolicyState::from_policy)
}

fn legacy_policy_state_from_extensions(extensions: &Extensions) -> Option<RequestBodyPolicyState> {
    let mut state = RequestBodyPolicyState::default();
    if let Some(body_limits) = extensions.get_typed_cloned::<BodyLimits>() {
        state.body_limits = Some(body_limits);
    }
    if let Some(multipart_limits) = extensions.get_typed_cloned::<MultipartLimits>() {
        state.multipart_limits = Some(multipart_limits);
    }
    if state.is_empty() {
        return None;
    }
    Some(state)
}

fn override_legacy_policy_state(
    inherited: Option<RequestBodyPolicyState>,
    local: Option<RequestBodyPolicyState>,
) -> Option<RequestBodyPolicyState> {
    match (inherited, local) {
        (Some(inherited), Some(local)) => Some(RequestBodyPolicyState {
            max_total_body_size: None,
            body_limits: local.body_limits.or(inherited.body_limits),
            multipart_limits: local.multipart_limits.or(inherited.multipart_limits),
        }),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn request_body_policy_refusal(limit: usize) -> Response {
    ExtractionError::coded(
        StatusCode::PAYLOAD_TOO_LARGE,
        super::WebBodyDiagnostic::TotalBodyLimit,
        format!("request body too large (limit {limit})"),
    )
    .into_response()
}

fn apply_request_body_policy(
    request: &mut Request,
    inherited: Option<RequestBodyPolicyState>,
    local: Option<RequestBodyPolicyState>,
) -> Result<(), Response> {
    let Some(explicit_policy) = meet_optional_policy_state(
        inherited.or_else(|| explicit_policy_state_from_extensions(&request.extensions)),
        local,
    ) else {
        return Ok(());
    };
    let state = legacy_policy_state_from_extensions(&request.extensions)
        .map_or(explicit_policy, |legacy| {
            explicit_policy.tightened_with(legacy)
        });
    let effective = state.resolved();
    if let Some(raw_content_length) = request.header("content-length") {
        let declared =
            parse_content_length(raw_content_length).map_err(ExtractionError::into_response)?;
        if declared > effective.max_total_body_size {
            return Err(request_body_policy_refusal(effective.max_total_body_size));
        }
    }
    if request.body.len() > effective.max_total_body_size {
        return Err(request_body_policy_refusal(effective.max_total_body_size));
    }
    #[cfg(not(target_arch = "wasm32"))]
    tighten_streaming_raw_body(request, effective.max_total_body_size);
    request.extensions.insert_typed(state);
    request
        .extensions
        .insert_typed(EnforcedRequestBodyPolicy { policy: effective });
    request.extensions.insert_typed(effective);
    request.extensions.insert_typed(effective.body_limits);
    request.extensions.insert_typed(effective.multipart_limits);
    Ok(())
}

fn join_route_pattern(prefix: &str, pattern: &str) -> String {
    let prefix = normalize_route_pattern(prefix);
    let pattern = normalize_route_pattern(pattern);

    if prefix == "/" {
        return pattern;
    }
    if pattern == "/" {
        return prefix;
    }

    format!(
        "{}/{}",
        prefix.trim_end_matches('/'),
        pattern.trim_start_matches('/')
    )
}

/// Translate the completed wire request shared by the HTTP/1.1 and HTTP/2
/// listeners into the web framework's extractor request.
fn web_request_from_http(request: HttpRequest) -> Request {
    let (path, query) = split_http_request_target(&request.uri);
    let mut web_request = Request::new(request.method.as_str(), path);
    web_request.query = query;
    web_request.body = request.body.into();

    // The web extractor surface intentionally exposes a single value per
    // header. Preserve its existing builder semantics: when validated wire
    // input repeats a field, the last value wins. Protocol validation (Host,
    // Content-Length, transfer coding, etc.) remains the listener's job and
    // runs before this adapter.
    for (name, value) in request.headers {
        web_request.headers.insert(name.to_ascii_lowercase(), value);
    }
    web_request
}

#[cfg(not(target_arch = "wasm32"))]
fn web_request_from_streaming_http(
    request: StreamingServerRequest,
) -> Option<(Request, StreamingRawBodyControl)> {
    let (path, query) = split_http_request_target(&request.head.uri);
    let mut web_request = Request::new(request.head.method.as_str(), path);
    web_request.query = query;

    for (name, value) in request.head.headers {
        web_request.headers.insert(name.to_ascii_lowercase(), value);
    }

    let control = insert_streaming_raw_body(&mut web_request, request.body).ok()?;
    Some((web_request, control))
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn web_request_from_h3(head: H3RequestHead, body: Vec<u8>) -> Request {
    // H3RequestHead has already passed pseudo-header and ordinary-header
    // validation in NativeH3Session. CONNECT is rejected by the bridge before
    // this conversion, so the remaining profile always has method and path.
    let method = head
        .pseudo
        .method
        .expect("validated non-CONNECT HTTP/3 request has :method");
    let target = head
        .pseudo
        .path
        .expect("validated non-CONNECT HTTP/3 request has :path");
    let (path, query) = split_http_request_target(&target);
    let mut request = Request::new(method, path);
    request.query = query;
    request.body = body.into();

    // Match the h2 listener: expose :authority as Host only when the peer did
    // not send an explicit Host field. The extractor surface is single-valued,
    // so repeated ordinary fields retain the existing last-value-wins rule.
    if let Some(authority) = head.pseudo.authority
        && !head
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        request.headers.insert("host".to_string(), authority);
    }
    for (name, value) in head.headers {
        request.headers.insert(name.to_ascii_lowercase(), value);
    }
    request
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn validate_h3_request_semantics(
    head: &H3RequestHead,
    body_len: usize,
) -> Result<(), NativeH3RouterRefusal> {
    let mut content_length = None;
    for (name, value) in &head.headers {
        if name == "content-length" {
            if content_length.is_some()
                || value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(NativeH3RouterRefusal::InvalidContentLength);
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| NativeH3RouterRefusal::InvalidContentLength)?,
            );
        } else if name == "te" && !value.trim().eq_ignore_ascii_case("trailers") {
            return Err(NativeH3RouterRefusal::InvalidTransferEncoding);
        }
    }
    if content_length.is_some_and(|declared| declared != body_len) {
        return Err(NativeH3RouterRefusal::InvalidContentLength);
    }
    Ok(())
}

/// Translate the web framework response into the wire response shared by h1
/// and h2. Stable sorting makes ordinary header order reproducible; Set-Cookie
/// stays append-only and ordered because combining those fields is invalid.
#[cfg(not(target_arch = "wasm32"))]
fn http1_stream_refusal_response(message: &'static str) -> Response {
    Response::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        crate::bytes::Bytes::from_static(message.as_bytes()),
    )
    .header("content-type", "text/plain; charset=utf-8")
}

#[cfg(not(target_arch = "wasm32"))]
fn http1_produced_trace_policy(
    policy: &RequestTracePolicy,
) -> (RequestTracePolicy, Option<&'static str>) {
    fn transport_owned(name: &str) -> bool {
        let normalized = sanitize_header_name(name.to_owned());
        [
            "content-length",
            "transfer-encoding",
            "connection",
            "trailer",
        ]
        .iter()
        .any(|reserved| normalized.eq_ignore_ascii_case(reserved))
    }

    let mut safe = policy.clone();
    let mut refused = false;
    if safe.duration_header.as_deref().is_some_and(transport_owned) {
        safe.duration_header = None;
        refused = true;
    }
    if safe.trace_header.as_deref().is_some_and(transport_owned) {
        safe.trace_header = None;
        refused = true;
    }
    (
        safe,
        refused.then_some("HTTP/1 produced-response trace policy uses a transport-owned header"),
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn http2_produced_trace_policy(
    policy: &RequestTracePolicy,
) -> (RequestTracePolicy, Option<&'static str>) {
    fn transport_owned(name: &str) -> bool {
        let normalized = sanitize_header_name(name.to_owned());
        ["content-length", "transfer-encoding"]
            .iter()
            .any(|reserved| normalized.eq_ignore_ascii_case(reserved))
    }

    let mut safe = policy.clone();
    let mut refused = false;
    if safe.duration_header.as_deref().is_some_and(transport_owned) {
        safe.duration_header = None;
        refused = true;
    }
    if safe.trace_header.as_deref().is_some_and(transport_owned) {
        safe.trace_header = None;
        refused = true;
    }
    (
        safe,
        refused.then_some("HTTP/2 produced-response trace policy uses a framing header"),
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn http1_produced_refusal(message: &'static str) -> Http1ProducedResponse {
    let mut response = http1_stream_refusal_response(message);
    let plan = Http1StreamPlan::buffered(std::mem::take(&mut response.body));
    plan.into_produced(response)
}

#[cfg(not(target_arch = "wasm32"))]
fn http2_produced_refusal(message: &'static str) -> Http2ProducedResponse {
    Http2ProducedResponse::buffered(http_response_from_web(http1_stream_refusal_response(
        message,
    )))
}

fn http_response_from_web(response: Response) -> HttpResponse {
    let status = response.status.as_u16();
    let mut headers = response.headers.into_iter().collect::<Vec<_>>();
    headers.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    headers.extend(
        response
            .set_cookies
            .into_iter()
            .map(|value| ("set-cookie".to_string(), value)),
    );

    HttpResponse::builder(status)
        .headers(headers)
        .body(response.body.as_ref().to_vec())
        .build()
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn h3_response_from_web(
    mut response: Response,
    suppress_body_for_head: bool,
) -> Result<(H3ResponseHead, Bytes), H3Error> {
    if (100..200).contains(&response.status.as_u16()) {
        return Err(H3Error::InvalidResponsePseudoHeader(
            "informational status is not a final Router response",
        ));
    }

    if matches!(response.status.as_u16(), 204 | 205 | 304) && !response.body.is_empty() {
        return Err(H3Error::InvalidFrame(
            "HTTP/3 response status forbids a message body",
        ));
    }

    let body_len = response.body.len();
    let content_length = response.headers.get("content-length").cloned();
    if let Some(value) = content_length.as_deref()
        && (value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(H3Error::InvalidFrame(
            "invalid HTTP/3 response content-length",
        ));
    }
    if let Some(value) = response.headers.get("te")
        && !value.trim().eq_ignore_ascii_case("trailers")
    {
        return Err(H3Error::InvalidFrame("invalid HTTP/3 response TE value"));
    }
    if response.status.as_u16() == 204 && content_length.is_some() {
        return Err(H3Error::InvalidFrame(
            "HTTP 204 response must not include content-length",
        ));
    }
    if suppress_body_for_head {
        if content_length.is_none() && body_len != 0 {
            response
                .headers
                .insert("content-length".to_string(), body_len.to_string());
        }
        response.headers.remove("te");
        response.headers.remove("trailer");
        response.body = Bytes::new();
    } else if response.status.as_u16() != 304
        && let Some(value) = content_length
    {
        let declared = value
            .parse::<usize>()
            .map_err(|_| H3Error::InvalidFrame("invalid HTTP/3 response content-length"))?;
        if declared != body_len {
            return Err(H3Error::InvalidFrame(
                "HTTP/3 response content-length does not match body length",
            ));
        }
    }

    let mut headers = response.headers.into_iter().collect::<Vec<_>>();
    headers.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    headers.extend(
        response
            .set_cookies
            .into_iter()
            .map(|value| ("set-cookie".to_string(), value)),
    );
    let head = H3ResponseHead::new(response.status.as_u16(), headers)?;
    Ok((head, response.body))
}

#[cfg(not(target_arch = "wasm32"))]
fn valid_websocket_handoff_response(response: &HttpResponse, upgrade: &Http1Upgrade) -> bool {
    fn has_token(response: &HttpResponse, name: &str, expected: &str) -> bool {
        response
            .headers
            .iter()
            .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .flat_map(|(_, value)| value.split(','))
            .map(str::trim)
            .any(|token| token.eq_ignore_ascii_case(expected))
    }

    response.status == 101
        && response.body.is_empty()
        && response.trailers.is_empty()
        && !response.headers.iter().any(|(name, _)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                || name.eq_ignore_ascii_case("content-length")
        })
        && has_token(response, "connection", "upgrade")
        && !has_token(response, "connection", "close")
        && has_token(response, "upgrade", "websocket")
        && response.header_value("sec-websocket-accept").is_some()
        && upgrade.websocket_negotiation_matches(response)
}

/// Split origin-form and absolute-form request targets without decoding the
/// path. Routing stays byte-for-byte compatible with the existing web router,
/// while query extractors receive only the portion after `?`.
fn split_http_request_target(target: &str) -> (String, Option<String>) {
    let target = if let Some(scheme_end) = absolute_uri_scheme_end(target) {
        let authority_start = scheme_end + 3;
        match target[authority_start..].find(['/', '?']) {
            Some(relative) => {
                let suffix = &target[authority_start + relative..];
                if suffix.starts_with('?') {
                    // Absolute URI with an empty path.
                    &target[authority_start + relative..]
                } else {
                    suffix
                }
            }
            None => "",
        }
    } else {
        target
    };

    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query.to_string())),
        None => (target, None),
    };
    let path = if path.is_empty() { "/" } else { path };
    (path.to_string(), query)
}

/// Return the end of a leading RFC 3986 scheme when the target is an absolute
/// URI using `://`. Origin-form paths can legally contain that byte sequence
/// later in the path and must not be mistaken for absolute-form targets.
fn absolute_uri_scheme_end(target: &str) -> Option<usize> {
    let scheme_end = target.find("://")?;
    let scheme = &target[..scheme_end];
    let mut chars = scheme.chars();
    if !chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
    {
        return None;
    }
    chars
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
        .then_some(scheme_end)
}

fn normalize_route_pattern(pattern: &str) -> String {
    if pattern.is_empty() || pattern == "/" {
        "/".to_string()
    } else if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("/{pattern}")
    }
}

/// Strip a prefix from a path, returning the remainder.
fn strip_prefix(path: &str, prefix: &str) -> Option<String> {
    let normalized_path = if path.is_empty() { "/" } else { path };

    if prefix.trim_matches('/').is_empty() {
        return normalized_path
            .starts_with('/')
            .then(|| normalized_path.to_string());
    }

    let requires_slash_boundary = prefix.ends_with('/');
    let normalized_prefix = prefix.trim_end_matches('/');

    if normalized_path == normalized_prefix {
        if requires_slash_boundary {
            return None;
        }
        return Some("/".to_string());
    }

    let rest = normalized_path.strip_prefix(normalized_prefix)?;
    let rest = rest.strip_prefix('/')?;
    if rest.starts_with('/') {
        return None;
    }

    Some(if rest.is_empty() {
        "/".to_string()
    } else {
        format!("/{rest}")
    })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::bytes::Bytes;
    use crate::web::extract::Extension;
    use crate::web::handler::{FnHandler, FnHandler1};

    fn ok_handler() -> &'static str {
        "ok"
    }

    fn not_found_handler() -> StatusCode {
        StatusCode::NOT_FOUND
    }

    fn created_handler() -> StatusCode {
        StatusCode::CREATED
    }

    fn body_policy_summary(Extension(policy): Extension<RequestBodyPolicy>) -> String {
        format!(
            "total={};json={};form={};raw={};multipart={};field={};parts={};request_timeout={};idle_timeout={}",
            policy.max_total_body_size,
            policy.body_limits.max_json_body_size,
            policy.body_limits.max_form_body_size,
            policy.body_limits.max_raw_body_size,
            policy.multipart_limits.max_total_size,
            policy.multipart_limits.max_part_body_size,
            policy.multipart_limits.max_parts,
            policy.multipart_limits.request_timeout_secs,
            policy.multipart_limits.idle_timeout_secs,
        )
    }

    fn body_limits_summary(Extension(limits): Extension<BodyLimits>) -> String {
        format!(
            "json={};form={};raw={}",
            limits.max_json_body_size, limits.max_form_body_size, limits.max_raw_body_size,
        )
    }

    #[cfg(not(target_arch = "wasm32"))]
    struct BodyPolicyWriterProbe {
        writer: parking_lot::Mutex<Option<crate::http::h1::IncomingRequestBodyWriter>>,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl crate::web::Handler for BodyPolicyWriterProbe {
        fn call(
            &self,
            cx: &crate::Cx,
            _request: Request,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
            let cx = cx.clone();
            let writer = self.writer.lock().take();
            Box::pin(async move {
                let Some(mut writer) = writer else {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                };
                match writer
                    .push_bytes(&cx, b"4\r\nABCD\r\n4\r\nEFGH\r\n0\r\n\r\n")
                    .await
                {
                    Err(crate::http::h1::IncomingBodyError::BodyTooLarge {
                        actual: Some(8),
                        limit: 6,
                    }) => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
                    Ok(()) | Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            })
        }
    }

    #[test]
    fn body_policy_server_router_and_route_merge_monotonically() {
        let server = RequestBodyPolicy::new()
            .max_total_body_size(90)
            .body_limits(
                BodyLimits::new()
                    .max_json_body_size(80)
                    .max_form_body_size(70)
                    .max_raw_body_size(60),
            )
            .multipart_limits(
                MultipartLimits::new()
                    .max_total_size(85)
                    .max_part_body_size(75)
                    .max_parts(50)
                    .request_timeout_secs(40)
                    .idle_timeout_secs(20),
            );
        let router = RequestBodyPolicy::new()
            .max_total_body_size(100)
            .body_limits(
                BodyLimits::new()
                    .max_json_body_size(50)
                    .max_form_body_size(80)
                    .max_raw_body_size(70),
            )
            .multipart_limits(
                MultipartLimits::new()
                    .max_total_size(95)
                    .max_part_body_size(65)
                    .max_parts(60)
                    .request_timeout_secs(30)
                    .idle_timeout_secs(25),
            );
        let route = RequestBodyPolicy::new()
            .max_total_body_size(110)
            .body_limits(
                BodyLimits::new()
                    .max_json_body_size(70)
                    .max_form_body_size(40)
                    .max_raw_body_size(80),
            )
            .multipart_limits(
                MultipartLimits::new()
                    .max_total_size(105)
                    .max_part_body_size(30)
                    .max_parts(70)
                    .request_timeout_secs(50)
                    .idle_timeout_secs(10),
            );
        let router = Router::new()
            .route(
                "/upload",
                post(FnHandler1::<_, Extension<RequestBodyPolicy>>::new(
                    body_policy_summary,
                ))
                .with_body_policy(route),
            )
            .with_body_policy(router)
            .with_server_body_policy(server);

        let response = router.handle(Request::new("POST", "/upload"));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            std::str::from_utf8(response.body.as_ref()).expect("policy response is UTF-8"),
            "total=90;json=50;form=40;raw=60;multipart=85;field=30;parts=50;request_timeout=30;idle_timeout=10"
        );

        let policies = router.route_body_policies();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].pattern, "/upload");
        assert_eq!(policies[0].method, "POST");
        assert_eq!(policies[0].route_policy, Some(route.resolved()));
        let effective = policies[0]
            .effective_policy
            .expect("configured route has effective policy");
        assert_eq!(effective.max_total_body_size, 90);
        assert_eq!(effective.body_limits.max_json_body_size, 50);
        assert_eq!(effective.multipart_limits.max_part_body_size, 30);
    }

    #[test]
    fn nested_body_policy_cannot_loosen_parent_server_policy() {
        let outer = RequestBodyPolicy::new().max_total_body_size(64);
        let attempted_loosen = RequestBodyPolicy::new()
            .max_total_body_size(128)
            .body_limits(BodyLimits::new().max_json_body_size(128));
        let nested = Router::new()
            .route(
                "/upload",
                post(FnHandler1::<_, Extension<RequestBodyPolicy>>::new(
                    body_policy_summary,
                ))
                .with_body_policy(attempted_loosen),
            )
            .with_server_body_policy(attempted_loosen)
            .with_body_policy(attempted_loosen);
        let router = Router::new()
            .nest("/api", nested)
            .with_server_body_policy(outer);

        let response = router.handle(Request::new("POST", "/api/upload"));
        let body = std::str::from_utf8(response.body.as_ref()).expect("policy response is UTF-8");
        assert!(body.starts_with("total=64;"), "unexpected policy: {body}");

        let policies = router.route_body_policies();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].pattern, "/api/upload");
        assert_eq!(
            policies[0]
                .effective_policy
                .expect("configured nested route has effective policy")
                .max_total_body_size,
            64
        );
    }

    #[test]
    fn route_only_policy_runtime_and_metadata_agree_above_defaults() {
        let route = RequestBodyPolicy::new()
            .max_total_body_size(64 * 1024 * 1024)
            .body_limits(
                BodyLimits::new()
                    .max_json_body_size(32 * 1024 * 1024)
                    .max_form_body_size(4 * 1024 * 1024)
                    .max_raw_body_size(24 * 1024 * 1024),
            );
        let router = Router::new().route(
            "/upload",
            post(FnHandler1::<_, Extension<RequestBodyPolicy>>::new(
                body_policy_summary,
            ))
            .with_body_policy(route),
        );

        let response = router.handle(Request::new("POST", "/upload"));
        let body = std::str::from_utf8(response.body.as_ref()).expect("policy response is UTF-8");
        assert!(
            body.starts_with("total=67108864;json=33554432;form=4194304;raw=25165824;"),
            "route-only runtime policy was unexpectedly clamped: {body}"
        );
        let metadata = router.route_body_policies();
        assert_eq!(metadata[0].effective_policy, Some(route.resolved()));
    }

    #[test]
    fn partial_legacy_limits_preserve_the_other_inherited_plane() {
        let outer_multipart = MultipartLimits::new()
            .max_total_size(12 * 1024 * 1024)
            .max_part_body_size(6 * 1024 * 1024)
            .max_parts(17);
        let nested_body = BodyLimits::new()
            .max_json_body_size(8 * 1024 * 1024)
            .max_form_body_size(1024 * 1024)
            .max_raw_body_size(8 * 1024 * 1024);
        let nested = Router::new()
            .route(
                "/upload",
                post(FnHandler1::<_, Extension<RequestBodyPolicy>>::new(
                    body_policy_summary,
                ))
                .with_body_policy(RequestBodyPolicy::new()),
            )
            .with_state(nested_body);
        let router = Router::new()
            .nest("/api", nested)
            .with_state(outer_multipart);

        let response = router.handle(Request::new("POST", "/api/upload"));
        let body = std::str::from_utf8(response.body.as_ref()).expect("policy response is UTF-8");
        assert!(body.contains("json=8388608;form=1048576;raw=8388608;"));
        assert!(body.contains("multipart=12582912;field=6291456;parts=17;"));

        let metadata = router.route_body_policies();
        let effective = metadata[0]
            .effective_policy
            .expect("route policy promotes legacy limits");
        assert_eq!(effective.body_limits, nested_body);
        assert_eq!(effective.multipart_limits, outer_multipart);
    }

    #[test]
    fn legacy_body_limits_remain_supported_without_explicit_policy() {
        let legacy = BodyLimits::new()
            .max_json_body_size(32 * 1024 * 1024)
            .max_form_body_size(4 * 1024 * 1024)
            .max_raw_body_size(24 * 1024 * 1024);
        let router = Router::new()
            .route(
                "/legacy",
                post(FnHandler1::<_, Extension<BodyLimits>>::new(
                    body_limits_summary,
                )),
            )
            .with_state(legacy);

        let response = router.handle(Request::new("POST", "/legacy"));
        let body = std::str::from_utf8(response.body.as_ref()).expect("policy response is UTF-8");
        assert!(
            body == "json=33554432;form=4194304;raw=25165824",
            "legacy limits were not preserved: {body}"
        );
        assert_eq!(router.route_body_policies()[0].effective_policy, None);
    }

    #[test]
    fn body_policy_legacy_only_nested_body_limits_keep_inner_precedence() {
        let outer = BodyLimits::new().max_json_body_size(4);
        let inner = BodyLimits::new().max_json_body_size(64);
        let nested = Router::new()
            .route(
                "/legacy",
                post(FnHandler1::<_, Extension<BodyLimits>>::new(
                    body_limits_summary,
                )),
            )
            .with_state(inner);
        let router = Router::new().with_state(outer).nest("/api", nested);

        let response = router.handle(Request::new("POST", "/api/legacy"));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            std::str::from_utf8(response.body.as_ref()).expect("legacy response is UTF-8"),
            "json=64;form=2097152;raw=10485760"
        );
        assert_eq!(router.route_body_policies()[0].effective_policy, None);
    }

    #[test]
    fn explicit_policy_and_legacy_limits_meet_instead_of_shadowing() {
        let explicit = RequestBodyPolicy::new()
            .max_total_body_size(100)
            .body_limits(BodyLimits::new().max_json_body_size(80));
        let legacy = BodyLimits::new().max_json_body_size(50);
        let router = Router::new()
            .route(
                "/mixed",
                post(FnHandler1::<_, Extension<RequestBodyPolicy>>::new(
                    body_policy_summary,
                )),
            )
            .with_state(explicit)
            .with_state(legacy);

        let response = router.handle(Request::new("POST", "/mixed"));
        let body = std::str::from_utf8(response.body.as_ref()).expect("policy response is UTF-8");
        assert!(
            body.starts_with("total=100;json=50;"),
            "unexpected policy: {body}"
        );
        assert_eq!(
            router.route_body_policies()[0]
                .effective_policy
                .expect("mixed policy is discoverable")
                .body_limits
                .max_json_body_size,
            50
        );
    }

    #[test]
    fn body_diagnostic_route_total_policy_rejects_actual_and_declared_lengths() {
        let policy = RequestBodyPolicy::new().max_total_body_size(4);
        let router = Router::new().route(
            "/ignore",
            post(FnHandler::new(ok_handler)).with_body_policy(policy),
        );

        let actual =
            router.handle(Request::new("POST", "/ignore").with_body(Bytes::from_static(b"12345")));
        assert_eq!(actual.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            actual.body.as_ref(),
            b"[ASUP-E505] request body too large (limit 4)"
        );

        let declared =
            router.handle(Request::new("POST", "/ignore").with_header("content-length", "5"));
        assert_eq!(declared.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            declared.body.as_ref(),
            b"[ASUP-E505] request body too large (limit 4)"
        );

        let mut mixed_case = Request::new("POST", "/ignore");
        mixed_case
            .headers
            .insert("Content-Length".to_string(), "5".to_string());
        let mixed_case = router.handle(mixed_case);
        assert_eq!(mixed_case.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(mixed_case.body.starts_with(b"[ASUP-E505] "));

        for invalid in ["5, 6", "+5", "184467440737095516160"] {
            let response = router
                .handle(Request::new("POST", "/ignore").with_header("content-length", invalid));
            assert_eq!(response.status, StatusCode::BAD_REQUEST, "value={invalid}");
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn body_policy_route_tightens_live_writer_before_handler_extraction() {
        use crate::http::h1::types::{Method, Version};
        use crate::http::h1::{RequestHead, StreamingServerRequest};

        let cx = crate::Cx::for_testing();
        let head = RequestHead {
            method: Method::Post,
            uri: "/streamed".to_string(),
            version: Version::Http11,
            headers: vec![("transfer-encoding".to_string(), "chunked".to_string())],
        };
        let (writer, request) = StreamingServerRequest::channel(head, &cx, 8);
        let router = Router::new().route(
            "/streamed",
            post(BodyPolicyWriterProbe {
                writer: parking_lot::Mutex::new(Some(writer)),
            })
            .with_body_policy(RequestBodyPolicy::new().max_total_body_size(6)),
        );

        let response = futures_lite::future::block_on(
            router.handle_http1_streaming_request_with_cx(&cx, request),
        );
        assert_eq!(response.status, 413);
    }

    #[test]
    fn route_body_policy_rejects_declared_json_length_before_parsing() {
        let route_policy = RequestBodyPolicy::new()
            .max_total_body_size(4)
            .body_limits(BodyLimits::new().max_json_body_size(4));
        let router = Router::new().route(
            "/json",
            post(FnHandler1::<
                _,
                super::super::extract::Json<serde_json::Value>,
            >::new(|_json| StatusCode::OK))
            .with_body_policy(route_policy),
        );
        let request = Request::new("POST", "/json")
            .with_header("content-type", "application/json")
            .with_header("content-length", "5");

        let response = router.handle(request);
        assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn route_exact_match() {
        let router = Router::new().route("/", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("GET", "/"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            router.route_body_policies()[0].effective_policy,
            None,
            "unconfigured routes must not report a phantom first-class policy"
        );
    }

    #[test]
    fn route_not_found() {
        let router = Router::new().route("/", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("GET", "/missing"));
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn listener_request_conversion_preserves_consumed_fields() {
        use crate::http::h1::types::{Method, Version};

        let request = HttpRequest {
            method: Method::Extension("PURGE".to_string()),
            uri: "https://example.test/cache/42?tenant=blue&fresh=true".to_string(),
            version: Version::Http2,
            headers: vec![
                ("X-Mode".to_string(), "first".to_string()),
                (
                    "Content-Type".to_string(),
                    "application/octet-stream".to_string(),
                ),
                ("x-mode".to_string(), "last".to_string()),
            ],
            body: b"payload".to_vec(),
            trailers: vec![("x-checksum".to_string(), "abc".to_string())],
            peer_addr: Some("127.0.0.1:43210".parse().expect("peer address")),
        };

        let request = web_request_from_http(request);
        assert_eq!(request.method, "PURGE");
        assert_eq!(request.path, "/cache/42");
        assert_eq!(request.query.as_deref(), Some("tenant=blue&fresh=true"));
        assert_eq!(
            request.header("content-type"),
            Some("application/octet-stream")
        );
        assert_eq!(request.header("x-mode"), Some("last"));
        assert_eq!(request.body.as_ref(), b"payload");
    }

    #[test]
    fn listener_target_conversion_handles_origin_and_empty_absolute_paths() {
        assert_eq!(
            split_http_request_target("/items?q=rust"),
            ("/items".to_string(), Some("q=rust".to_string()))
        );
        assert_eq!(
            split_http_request_target("http://example.test?ready=true"),
            ("/".to_string(), Some("ready=true".to_string()))
        );
        assert_eq!(
            split_http_request_target("https://example.test"),
            ("/".to_string(), None)
        );
        assert_eq!(split_http_request_target("*"), ("*".to_string(), None));
        assert_eq!(
            split_http_request_target("/redirect/http://upstream.test?q=kept"),
            (
                "/redirect/http://upstream.test".to_string(),
                Some("q=kept".to_string())
            )
        );
    }

    #[test]
    fn listener_response_conversion_preserves_ordered_set_cookie_fields() {
        let mut response = Response::new(StatusCode::CREATED, "created");
        response.set_header("x-zeta", "z");
        response.set_header("content-type", "text/plain");
        response.append_set_cookie("session=one; Path=/");
        response.append_set_cookie("csrf=two; Path=/");

        let response = http_response_from_web(response);
        assert_eq!(response.status, 201);
        assert_eq!(response.reason, "Created");
        assert_eq!(response.body, b"created");
        assert_eq!(
            response.headers,
            vec![
                ("content-type".to_string(), "text/plain".to_string()),
                ("x-zeta".to_string(), "z".to_string()),
                ("set-cookie".to_string(), "session=one; Path=/".to_string()),
                ("set-cookie".to_string(), "csrf=two; Path=/".to_string()),
            ]
        );
    }

    #[test]
    #[cfg(feature = "http3")]
    fn body_diagnostic_native_h3_error_classifier_is_causal() {
        use crate::http::h3::NativeH3SessionError;

        let peer_stop = NativeH3SessionError::Transport(NativeQuicConnectionError::Stream(
            QuicStreamError::SendStopped { code: 0x10c },
        ));
        assert_eq!(
            native_h3_produced_error_diagnostic(&peer_stop),
            Some(WebBodyDiagnostic::ClientAbort)
        );

        let local_cancel = NativeH3SessionError::Transport(NativeQuicConnectionError::Cancelled);
        assert_eq!(native_h3_produced_error_diagnostic(&local_cancel), None);

        let producer_state = NativeH3SessionError::InvalidState("duplicate terminal frame");
        assert_eq!(
            native_h3_produced_error_diagnostic(&producer_state),
            Some(WebBodyDiagnostic::ResponseProducerFailure)
        );

        let producer_frame = NativeH3SessionError::Protocol(H3Error::InvalidFrame(
            "response DATA exceeds the configured frame limit",
        ));
        assert_eq!(
            native_h3_produced_error_diagnostic(&producer_frame),
            Some(WebBodyDiagnostic::ResponseProducerFailure)
        );
    }

    #[test]
    #[cfg(feature = "http3")]
    fn body_diagnostic_h3_dispatch_completion_distinguishes_peer_and_local_close() {
        use crate::http::h3::NativeH3SessionError;
        use crate::net::atp::protocol::quic_frames::QuicFrame;
        use crate::net::atp::protocol::varint::VarInt;
        use crate::net::quic_native::{NativeQuicConnectionConfig, PacketNumberSpace};

        fn established_server(cx: &Cx) -> QuicConnection {
            let mut connection = QuicConnection::server(NativeQuicConnectionConfig::default());
            connection.begin_handshake(cx).expect("begin handshake");
            connection
                .mark_handshake_keys_available(cx)
                .expect("install handshake keys");
            connection
                .mark_app_keys_available(cx)
                .expect("install application keys");
            connection.confirm_handshake(cx).expect("confirm handshake");
            connection
        }

        let cx = Cx::for_testing();
        let completion_error = NativeH3SessionError::InvalidState(
            "QUIC connection is not established for HTTP/3 messages",
        );

        let mut peer_closed = established_server(&cx);
        peer_closed
            .inner_mut()
            .process_frame(
                &cx,
                &QuicFrame::ConnectionClose {
                    error_code: VarInt::from_u64_unchecked(0x10c),
                    frame_type: None,
                    reason_phrase: Bytes::from_static(b"peer shutdown"),
                },
                PacketNumberSpace::ApplicationData,
            )
            .expect("peer CONNECTION_CLOSE enters draining");
        assert_eq!(
            native_h3_completion_error_diagnostic(&peer_closed, &completion_error),
            Some(WebBodyDiagnostic::ClientAbort),
            "a peer close after dispatch but before response start is E509"
        );

        let mut locally_closed = established_server(&cx);
        locally_closed
            .begin_close(&cx, 0, 0x10c)
            .expect("local shutdown enters draining");
        assert_eq!(
            native_h3_completion_error_diagnostic(&locally_closed, &completion_error),
            None,
            "a local close after dispatch must not be relabeled as a client abort"
        );
    }

    #[test]
    #[cfg(feature = "http3")]
    fn body_diagnostic_h3_cancel_after_close_reaps_dispatch_ownership() {
        use crate::http::h3::{H3Settings, NativeH3Session};
        use crate::net::atp::protocol::quic_frames::QuicFrame;
        use crate::net::atp::protocol::varint::VarInt;
        use crate::net::quic_native::{
            NativeQuicConnectionConfig, PacketNumberSpace, StreamDirection, StreamRole,
        };

        fn established_server(cx: &Cx) -> QuicConnection {
            let mut connection = QuicConnection::server(NativeQuicConnectionConfig::default());
            connection.begin_handshake(cx).expect("begin handshake");
            connection
                .mark_handshake_keys_available(cx)
                .expect("install handshake keys");
            connection
                .mark_app_keys_available(cx)
                .expect("install application keys");
            connection.confirm_handshake(cx).expect("confirm handshake");
            connection
        }

        let cx = Cx::for_testing();
        let stream_id = StreamId::local(StreamRole::Client, StreamDirection::Bidirectional, 0);

        let mut peer_connection = established_server(&cx);
        let mut peer_session = NativeH3Session::server();
        peer_session
            .initialize(&cx, &mut peer_connection, H3Settings::default())
            .expect("initialize peer-close session");
        let peer_writer = peer_session
            .start_response_writer(
                &peer_connection,
                stream_id,
                &H3ResponseHead::new(200, Vec::new()).expect("valid response head"),
                false,
            )
            .expect("prepare response writer");
        let mut peer_bridge = NativeH3Router::new(Router::new());
        peer_bridge.in_flight.insert(stream_id, 0);
        peer_bridge.produced.insert(
            stream_id,
            ActiveNativeH3ProducedResponse {
                status: 200,
                writer: peer_writer,
                plan: None,
                body: None,
                lifecycle: None,
                producer_cx: None,
                max_data_wire_bytes: 0,
                emitted_bytes: 0,
                terminal: None,
                head_only: false,
                reset_queued: false,
            },
        );
        let peer_token = NativeH3RouterDispatchToken {
            bridge_identity: Arc::clone(&peer_bridge.identity),
            stream_id,
        };
        peer_connection
            .inner_mut()
            .process_frame(
                &cx,
                &QuicFrame::ConnectionClose {
                    error_code: VarInt::from_u64_unchecked(0x10c),
                    frame_type: None,
                    reason_phrase: Bytes::from_static(b"peer shutdown"),
                },
                PacketNumberSpace::ApplicationData,
            )
            .expect("peer CONNECTION_CLOSE enters draining");
        assert_eq!(
            native_h3_closed_connection_diagnostic(&peer_connection),
            Some(WebBodyDiagnostic::ClientAbort)
        );
        assert_eq!(
            peer_bridge
                .cancel_dispatch_with_cx(&cx, &mut peer_session, &mut peer_connection, &peer_token,)
                .expect("closed peer dispatch cancellation is terminal"),
            NativeH3RouterEvent::RequestRefused {
                stream_id,
                reason: NativeH3RouterRefusal::DispatchCancelled,
            }
        );
        assert_eq!(peer_bridge.in_flight_dispatch_count(), 0);
        assert!(!peer_bridge.produced.contains_key(&stream_id));

        let mut local_connection = established_server(&cx);
        let mut local_session = NativeH3Session::server();
        local_session
            .initialize(&cx, &mut local_connection, H3Settings::default())
            .expect("initialize local-close session");
        let mut local_bridge = NativeH3Router::new(Router::new());
        local_bridge.in_flight.insert(stream_id, 0);
        let local_token = NativeH3RouterDispatchToken {
            bridge_identity: Arc::clone(&local_bridge.identity),
            stream_id,
        };
        local_connection
            .begin_close(&cx, 0, 0x10c)
            .expect("local shutdown enters draining");
        assert_eq!(
            native_h3_closed_connection_diagnostic(&local_connection),
            None
        );
        assert_eq!(
            local_bridge
                .cancel_dispatch_with_cx(
                    &cx,
                    &mut local_session,
                    &mut local_connection,
                    &local_token,
                )
                .expect("closed local dispatch cancellation is terminal"),
            NativeH3RouterEvent::RequestRefused {
                stream_id,
                reason: NativeH3RouterRefusal::DispatchCancelled,
            }
        );
        assert_eq!(local_bridge.in_flight_dispatch_count(), 0);
    }

    #[test]
    #[cfg(feature = "http3")]
    fn h3_request_semantics_reject_malformed_length_and_te_before_dispatch() {
        use crate::http::h3::H3PseudoHeaders;

        let head = |headers| {
            H3RequestHead::new(
                H3PseudoHeaders {
                    method: Some("POST".to_string()),
                    scheme: Some("https".to_string()),
                    authority: Some("example.test".to_string()),
                    path: Some("/".to_string()),
                    ..H3PseudoHeaders::default()
                },
                headers,
            )
            .expect("syntactically valid H3 request")
        };

        assert_eq!(
            validate_h3_request_semantics(
                &head(vec![("content-length".to_string(), "4".to_string())]),
                3,
            ),
            Err(NativeH3RouterRefusal::InvalidContentLength)
        );
        assert_eq!(
            validate_h3_request_semantics(
                &head(vec![
                    ("content-length".to_string(), "3".to_string()),
                    ("content-length".to_string(), "3".to_string()),
                ]),
                3,
            ),
            Err(NativeH3RouterRefusal::InvalidContentLength)
        );
        assert_eq!(
            validate_h3_request_semantics(&head(vec![("te".to_string(), "gzip".to_string())]), 0,),
            Err(NativeH3RouterRefusal::InvalidTransferEncoding)
        );
        validate_h3_request_semantics(
            &head(vec![
                ("content-length".to_string(), "3".to_string()),
                ("te".to_string(), "trailers".to_string()),
            ]),
            3,
        )
        .expect("valid HTTP/3 request semantics");
    }

    #[test]
    #[cfg(feature = "http3")]
    fn h3_response_semantics_suppress_head_and_refuse_invalid_final_output() {
        let response = Response::new(StatusCode::OK, "body");
        let (head, body) = h3_response_from_web(response, true).expect("valid HEAD response");
        assert!(body.is_empty());
        assert_eq!(
            head.headers,
            vec![("content-length".to_string(), "4".to_string())]
        );

        let mut mismatch = Response::new(StatusCode::OK, "body");
        mismatch.set_header("content-length", "3");
        assert_eq!(
            h3_response_from_web(mismatch, false),
            Err(H3Error::InvalidFrame(
                "HTTP/3 response content-length does not match body length"
            ))
        );

        let mut invalid_te = Response::new(StatusCode::OK, "body");
        invalid_te.set_header("te", "gzip");
        assert_eq!(
            h3_response_from_web(invalid_te, false),
            Err(H3Error::InvalidFrame("invalid HTTP/3 response TE value"))
        );

        assert_eq!(
            h3_response_from_web(
                Response::new(StatusCode::from_u16(103), Bytes::new()),
                false
            ),
            Err(H3Error::InvalidResponsePseudoHeader(
                "informational status is not a final Router response"
            ))
        );

        for status in [204, 205, 304] {
            assert_eq!(
                h3_response_from_web(
                    Response::new(StatusCode::from_u16(status), "must-not-ship"),
                    false,
                ),
                Err(H3Error::InvalidFrame(
                    "HTTP/3 response status forbids a message body"
                ))
            );
        }

        let mut no_content = Response::new(StatusCode::from_u16(204), Bytes::new());
        no_content.set_header("content-length", "0");
        assert_eq!(
            h3_response_from_web(no_content, false),
            Err(H3Error::InvalidFrame(
                "HTTP 204 response must not include content-length"
            ))
        );

        let mut not_modified = Response::new(StatusCode::from_u16(304), Bytes::new());
        not_modified.set_header("content-length", "123");
        let (head, body) =
            h3_response_from_web(not_modified, false).expect("valid 304 metadata length");
        assert_eq!(head.status, 304);
        assert_eq!(
            head.headers,
            vec![("content-length".to_string(), "123".to_string())]
        );
        assert!(body.is_empty());
    }

    #[test]
    fn explicit_listener_dispatch_runs_router_extractors_and_response_mapping() {
        use crate::http::h1::types::{Method, Version};
        use crate::web::extract::{Path, Query};
        use crate::web::handler::FnHandler2;

        fn handler(
            Path(id): Path<String>,
            Query(query): Query<HashMap<String, String>>,
        ) -> Response {
            let mut response = Response::new(
                StatusCode::OK,
                format!("id={id};q={}", query.get("q").map_or("", String::as_str)),
            );
            response.append_set_cookie("seen=true; Path=/");
            response
        }

        let router = Router::new().route(
            "/items/:id",
            get(FnHandler2::<_, Path<String>, Query<HashMap<String, String>>>::new(handler)),
        );
        let request = HttpRequest {
            method: Method::Get,
            uri: "http://example.test/items/7?q=wire".to_string(),
            version: Version::Http11,
            headers: vec![("host".to_string(), "example.test".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let response = futures_lite::future::block_on(
            router.handle_http_request_with_cx(&Cx::for_testing(), request),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"id=7;q=wire");
        assert_eq!(
            response
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            vec!["seen=true; Path=/"]
        );
    }

    #[test]
    fn listener_handler_is_shared_by_h1_and_h2_and_fails_closed_without_cx() {
        use crate::http::h2::listener::IntoHttp2Response;

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
            .route("/", get(FnHandler::new(ok_handler)))
            .into_http_handler();
        accepts_h1(&handler);
        accepts_h2(&handler);

        let response = futures_lite::future::block_on(handler(HttpRequest::get("/").build()));
        assert_eq!(response.status, 500);
        assert_eq!(response.body, b"request context unavailable");
    }

    #[test]
    fn route_method_not_allowed() {
        let router = Router::new().route("/", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("POST", "/"));
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(resp.header_value("allow"), Some("GET"));
    }

    #[test]
    fn route_with_params() {
        use crate::web::extract::Path;
        use crate::web::handler::FnHandler1;

        fn get_user(Path(id): Path<String>) -> String {
            format!("user:{id}")
        }

        let router = Router::new().route(
            "/users/:id",
            get(FnHandler1::<_, Path<String>>::new(get_user)),
        );

        let resp = router.handle(Request::new("GET", "/users/42"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn route_with_typed_path_and_query_extractors() {
        use crate::web::extract::{Path, Query};
        use crate::web::handler::FnHandler2;

        #[derive(serde::Deserialize)]
        struct UserPath {
            id: u64,
        }

        #[derive(serde::Deserialize)]
        struct Pagination {
            page: u32,
            active: bool,
        }

        fn handler(Path(path): Path<UserPath>, Query(query): Query<Pagination>) -> String {
            format!("id:{} page:{} active:{}", path.id, query.page, query.active)
        }

        let router = Router::new().route(
            "/users/:id",
            get(FnHandler2::<_, Path<UserPath>, Query<Pagination>>::new(
                handler,
            )),
        );

        let req = Request::new("GET", "/users/42").with_query("page=3&active=true");
        let resp = router.handle(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"id:42 page:3 active:true");
    }

    #[test]
    fn route_with_typed_query_error_returns_400() {
        use crate::web::extract::Query;
        use crate::web::handler::FnHandler1;

        #[derive(serde::Deserialize)]
        #[allow(dead_code)] // fields read via deserialization
        struct Pagination {
            page: u32,
        }

        fn handler(Query(_query): Query<Pagination>) -> &'static str {
            "ok"
        }

        let router = Router::new().route(
            "/items",
            get(FnHandler1::<_, Query<Pagination>>::new(handler)),
        );

        let req = Request::new("GET", "/items").with_query("page=not-a-number");
        let resp = router.handle(req);
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn route_with_typed_state() {
        use crate::web::extract::State;
        use crate::web::handler::FnHandler1;

        #[derive(Clone)]
        struct AppState {
            greeting: &'static str,
        }

        fn greet(State(state): State<AppState>) -> String {
            state.greeting.to_string()
        }

        let router = Router::new()
            .route("/", get(FnHandler1::<_, State<AppState>>::new(greet)))
            .with_state(AppState { greeting: "hello" });

        let resp = router.handle(Request::new("GET", "/"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"hello");
    }

    #[test]
    fn route_with_typed_state_missing_returns_500() {
        use crate::web::extract::State;
        use crate::web::handler::FnHandler1;

        #[derive(Clone)]
        struct AppState;

        fn handler(State(_state): State<AppState>) -> &'static str {
            "ok"
        }

        let router = Router::new().route("/", get(FnHandler1::<_, State<AppState>>::new(handler)));

        let resp = router.handle(Request::new("GET", "/"));
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn route_with_multiple_typed_states() {
        use crate::web::extract::State;
        use crate::web::handler::FnHandler2;

        #[derive(Clone)]
        struct AppState {
            name: &'static str,
        }

        #[derive(Clone)]
        struct FeatureFlags {
            beta: bool,
        }

        fn handler(State(app): State<AppState>, State(flags): State<FeatureFlags>) -> String {
            format!("{}:{}", app.name, flags.beta)
        }

        let router = Router::new()
            .route(
                "/",
                get(FnHandler2::<_, State<AppState>, State<FeatureFlags>>::new(
                    handler,
                )),
            )
            .with_state(AppState { name: "router" })
            .with_state(FeatureFlags { beta: true });

        let resp = router.handle(Request::new("GET", "/"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"router:true");
    }

    #[test]
    fn route_with_state_same_type_last_insert_wins() {
        use crate::web::extract::State;
        use crate::web::handler::FnHandler1;

        #[derive(Clone)]
        struct AppState {
            value: &'static str,
        }

        fn handler(State(app): State<AppState>) -> String {
            app.value.to_string()
        }

        let router = Router::new()
            .route("/", get(FnHandler1::<_, State<AppState>>::new(handler)))
            .with_state(AppState { value: "first" })
            .with_state(AppState { value: "second" });

        let resp = router.handle(Request::new("GET", "/"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"second");
    }

    #[test]
    fn route_multiple_methods() {
        fn post_handler() -> StatusCode {
            StatusCode::CREATED
        }

        let router = Router::new().route(
            "/items",
            get(FnHandler::new(ok_handler)).post(FnHandler::new(post_handler)),
        );

        let resp_get = router.handle(Request::new("GET", "/items"));
        assert_eq!(resp_get.status, StatusCode::OK);

        let resp_post = router.handle(Request::new("POST", "/items"));
        assert_eq!(resp_post.status, StatusCode::CREATED);

        let resp_patch = router.handle(Request::new("PATCH", "/items"));
        assert_eq!(resp_patch.status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(resp_patch.header_value("allow"), Some("GET, POST"));
    }

    #[test]
    fn route_priority_literal_before_param() {
        use crate::web::extract::Path;
        use crate::web::handler::FnHandler1;

        fn param_handler(Path(_id): Path<String>) -> StatusCode {
            StatusCode::CREATED
        }

        let router = Router::new()
            .route("/users/me", get(FnHandler::new(ok_handler)))
            .route(
                "/users/:id",
                get(FnHandler1::<_, Path<String>>::new(param_handler)),
            );

        let resp = router.handle(Request::new("GET", "/users/me"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn route_priority_param_before_literal() {
        use crate::web::extract::Path;
        use crate::web::handler::FnHandler1;

        fn param_handler(Path(_id): Path<String>) -> StatusCode {
            StatusCode::CREATED
        }

        let router = Router::new()
            .route(
                "/users/:id",
                get(FnHandler1::<_, Path<String>>::new(param_handler)),
            )
            .route("/users/me", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("GET", "/users/me"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn route_priority_literal_before_wildcard() {
        use crate::web::extract::Path;
        use crate::web::handler::FnHandler1;

        fn wildcard_handler(
            Path(_params): Path<std::collections::HashMap<String, String>>,
        ) -> StatusCode {
            StatusCode::ACCEPTED
        }

        let router = Router::new()
            .route("/files/static", get(FnHandler::new(ok_handler)))
            .route(
                "/files/*",
                get(FnHandler1::<
                    _,
                    Path<std::collections::HashMap<String, String>>,
                >::new(wildcard_handler)),
            );

        let resp = router.handle(Request::new("GET", "/files/static"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn route_priority_wildcard_cannot_shadow_literal() {
        use crate::web::extract::Path;
        use crate::web::handler::FnHandler1;

        fn wildcard_handler(
            Path(_params): Path<std::collections::HashMap<String, String>>,
        ) -> StatusCode {
            StatusCode::ACCEPTED
        }

        let router = Router::new()
            .route(
                "/files/*",
                get(FnHandler1::<
                    _,
                    Path<std::collections::HashMap<String, String>>,
                >::new(wildcard_handler))
                .post(FnHandler1::<
                    _,
                    Path<std::collections::HashMap<String, String>>,
                >::new(wildcard_handler)),
            )
            .route("/files/static", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("GET", "/files/static"));
        assert_eq!(resp.status, StatusCode::OK);

        let resp = router.handle(Request::new("POST", "/files/static"));
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn route_priority_wildcard_cannot_shadow_parameter_auth_path() {
        use crate::web::extract::Path;
        use crate::web::handler::FnHandler1;

        fn public_wildcard(
            Path(_params): Path<std::collections::HashMap<String, String>>,
        ) -> StatusCode {
            StatusCode::OK
        }

        fn protected_param(Path(_tenant): Path<String>) -> StatusCode {
            StatusCode::UNAUTHORIZED
        }

        let router = Router::new()
            .route(
                "/admin/*",
                get(FnHandler1::<
                    _,
                    Path<std::collections::HashMap<String, String>>,
                >::new(public_wildcard))
                .post(FnHandler1::<
                    _,
                    Path<std::collections::HashMap<String, String>>,
                >::new(public_wildcard)),
            )
            .route(
                "/admin/:tenant/secret",
                get(FnHandler1::<_, Path<String>>::new(protected_param)),
            );

        let resp = router.handle(Request::new("GET", "/admin/acme/secret"));
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);

        let resp = router.handle(Request::new("POST", "/admin/acme/secret"));
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn nested_router() {
        let api = Router::new().route("/users", get(FnHandler::new(ok_handler)));

        let app = Router::new().nest("/api/v1", api);

        let resp = app.handle(Request::new("GET", "/api/v1/users"));
        assert_eq!(resp.status, StatusCode::OK);

        let resp = app.handle(Request::new("GET", "/other"));
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn nested_router_top_level_priority() {
        let api = Router::new().route("/users", get(FnHandler::new(created_handler)));

        let app = Router::new()
            .route("/api/v1/users", get(FnHandler::new(ok_handler)))
            .nest("/api/v1", api);

        let resp = app.handle(Request::new("POST", "/api/v1/users"));
        assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn nested_router_typed_state_override_prefers_nested_router() {
        use crate::web::extract::State;
        use crate::web::handler::FnHandler1;

        #[derive(Clone)]
        struct AppState {
            greeting: &'static str,
        }

        fn handler(State(state): State<AppState>) -> String {
            state.greeting.to_string()
        }

        let api = Router::new()
            .route("/", get(FnHandler1::<_, State<AppState>>::new(handler)))
            .with_state(AppState { greeting: "nested" });

        let app = Router::new()
            .with_state(AppState { greeting: "parent" })
            .nest("/api", api);

        let resp = app.handle(Request::new("GET", "/api/"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.as_ref(), b"nested");
    }

    #[test]
    fn nested_router_trailing_slash_prefix() {
        let api = Router::new().route("/users", get(FnHandler::new(ok_handler)));

        let app = Router::new().nest("/api/v1/", api);

        let resp = app.handle(Request::new("GET", "/api/v1/users/"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn nested_router_trailing_slash_prefix_rejects_slashless_boundary() {
        let api = Router::new().route("/", get(FnHandler::new(created_handler)));

        let app = Router::new()
            .nest("/api/v1/", api)
            .fallback(FnHandler::new(ok_handler));

        let resp = app.handle(Request::new("GET", "/api/v1"));
        assert_eq!(resp.status, StatusCode::OK);

        let resp = app.handle(Request::new("GET", "/api/v1/"));
        assert_eq!(resp.status, StatusCode::CREATED);
    }

    #[test]
    fn nested_router_prefers_most_specific_prefix() {
        let broad = Router::new().route("/health", get(FnHandler::new(ok_handler)));
        let specific = Router::new().route("/users", get(FnHandler::new(created_handler)));

        // Register broader prefix first: the router should still pick `/api/v1`.
        let app = Router::new().nest("/api", broad).nest("/api/v1", specific);

        let resp = app.handle(Request::new("GET", "/api/v1/users"));
        assert_eq!(resp.status, StatusCode::CREATED);
    }

    #[test]
    fn fallback_handler() {
        let router = Router::new()
            .route("/", get(FnHandler::new(ok_handler)))
            .fallback(FnHandler::new(not_found_handler));

        let resp = router.handle(Request::new("GET", "/missing"));
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn route_pattern_matching() {
        let pattern = RoutePattern::parse("/users/:id");
        let params = pattern.matches("/users/42").unwrap().params;
        assert_eq!(params.get("id").unwrap(), "42");

        assert!(pattern.matches("/users").is_none());
        assert!(pattern.matches("/users/42/extra").is_none());
    }

    #[test]
    fn route_pattern_multiple_params() {
        let pattern = RoutePattern::parse("/users/:uid/posts/:pid");
        let params = pattern.matches("/users/1/posts/99").unwrap().params;
        assert_eq!(params.get("uid").unwrap(), "1");
        assert_eq!(params.get("pid").unwrap(), "99");
    }

    #[test]
    fn route_pattern_wildcard() {
        let pattern = RoutePattern::parse("/files/*");
        let params = pattern.matches("/files/a/b/c").unwrap().params;
        assert_eq!(params.get("*").unwrap(), "a/b/c");
    }

    #[test]
    fn route_pattern_wildcard_empty_rest() {
        use crate::web::extract::Path;
        use crate::web::handler::FnHandler1;

        fn wildcard_handler(
            Path(params): Path<std::collections::HashMap<String, String>>,
        ) -> String {
            params.get("*").cloned().unwrap_or_default()
        }

        let router = Router::new().route(
            "/files/*",
            get(FnHandler1::<
                _,
                Path<std::collections::HashMap<String, String>>,
            >::new(wildcard_handler)),
        );

        let resp = router.handle(Request::new("GET", "/files"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "");
    }

    #[test]
    fn route_pattern_literal_only() {
        let pattern = RoutePattern::parse("/health");
        assert!(pattern.matches("/health").is_some());
        assert!(pattern.matches("/other").is_none());
    }

    #[test]
    fn route_trailing_slash_matches() {
        let router = Router::new().route("/users", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("GET", "/users/"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn router_route_count() {
        let router = Router::new()
            .route("/a", get(FnHandler::new(ok_handler)))
            .route("/b", get(FnHandler::new(ok_handler)));
        assert_eq!(router.route_count(), 2);
    }

    #[test]
    fn router_routes_lists_direct_and_nested_entries_deterministically() {
        let api = Router::new()
            .route(
                "/users",
                post(FnHandler::new(created_handler)).get(FnHandler::new(ok_handler)),
            )
            .route("/", delete(FnHandler::new(not_found_handler)));

        let router = Router::new()
            .route(
                "/items",
                post(FnHandler::new(created_handler)).get(FnHandler::new(ok_handler)),
            )
            .route("/items/:id", delete(FnHandler::new(not_found_handler)))
            .nest("/api", api);

        let routes = router.routes();
        let serialized = serde_json::to_value(&routes).expect("route info must serialize");
        assert_eq!(serialized[0]["method"], "DELETE");
        assert_eq!(serialized[0]["pattern"], "/api");
        assert_eq!(serialized[0]["handler_name"], "FnHandler");
        assert_eq!(serialized[0]["mount_prefix"], "/api");

        let got = routes
            .into_iter()
            .map(|route| {
                (
                    route.method,
                    route.pattern,
                    route.handler_name,
                    route.mount_prefix,
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            got,
            vec![
                (
                    "DELETE".to_string(),
                    "/api".to_string(),
                    "FnHandler",
                    Some("/api".to_string())
                ),
                (
                    "GET".to_string(),
                    "/api/users".to_string(),
                    "FnHandler",
                    Some("/api".to_string())
                ),
                (
                    "POST".to_string(),
                    "/api/users".to_string(),
                    "FnHandler",
                    Some("/api".to_string())
                ),
                ("GET".to_string(), "/items".to_string(), "FnHandler", None),
                ("POST".to_string(), "/items".to_string(), "FnHandler", None),
                (
                    "DELETE".to_string(),
                    "/items/:id".to_string(),
                    "FnHandler",
                    None
                ),
            ]
        );
    }

    #[test]
    fn strip_prefix_basic() {
        assert_eq!(
            strip_prefix("/api/v1/users", "/api/v1"),
            Some("/users".to_string())
        );
        assert_eq!(strip_prefix("/api/v1", "/api/v1"), Some("/".to_string()));
        assert_eq!(strip_prefix("/api/v1/", "/api/v1"), Some("/".to_string()));
        assert!(strip_prefix("/other", "/api/v1").is_none());
    }

    #[test]
    fn strip_prefix_boundary_mismatch() {
        assert!(strip_prefix("/apix/users", "/api").is_none());
        assert!(strip_prefix("/apiary", "/api").is_none());
    }

    #[test]
    fn strip_prefix_trailing_slash_prefix_requires_declared_boundary() {
        assert_eq!(
            strip_prefix("/api/v1/users", "/api/v1/"),
            Some("/users".to_string())
        );
        assert_eq!(strip_prefix("/api/v1/", "/api/v1/"), Some("/".to_string()));
        assert!(strip_prefix("/api/v1", "/api/v1/").is_none());
    }

    #[test]
    fn strip_prefix_rejects_empty_segment_at_mount_boundary() {
        assert!(strip_prefix("/api//users", "/api").is_none());
        assert!(strip_prefix("/api//users", "/api/").is_none());
    }

    /// AUDIT MODULE: Route precedence verification
    ///
    /// AUDIT FINDING: SOUND - Router correctly prioritizes literal segments over
    /// parameter segments. Specificity ordering ensures "/users/me" wins over
    /// "/users/:id" regardless of registration order, preventing parameter capture
    /// of literal paths.
    mod route_precedence_audit {
        use super::*;
        use crate::web::handler::FnHandler;

        fn literal_handler() -> StatusCode {
            StatusCode::OK
        }

        fn param_handler() -> StatusCode {
            StatusCode::ACCEPTED
        }

        fn wildcard_handler() -> StatusCode {
            StatusCode::CREATED
        }

        /// AUDIT: Verify literal route "/users/me" wins over parameter route "/users/:id"
        ///
        /// This is the core requirement - literal segments must take precedence
        /// over parameter segments to prevent unintended parameter capture.
        #[test]
        fn audit_literal_beats_parameter_core_requirement() {
            // Test case 1: Literal route registered first
            let router1 = Router::new()
                .route("/users/me", get(FnHandler::new(literal_handler)))
                .route("/users/:id", get(FnHandler::new(param_handler)))
                .route("/users/*", get(FnHandler::new(wildcard_handler)));

            let resp1 = router1.handle(Request::new("GET", "/users/me"));
            assert_eq!(
                resp1.status,
                StatusCode::OK,
                "Literal route '/users/me' must win over '/users/:id' when registered first"
            );

            // Test case 2: Parameter route registered first
            let router2 = Router::new()
                .route("/users/:id", get(FnHandler::new(param_handler)))
                .route("/users/*", get(FnHandler::new(wildcard_handler)))
                .route("/users/me", get(FnHandler::new(literal_handler)));

            let resp2 = router2.handle(Request::new("GET", "/users/me"));
            assert_eq!(
                resp2.status,
                StatusCode::OK,
                "Literal route '/users/me' must win over '/users/:id' regardless of registration order"
            );

            // AUDIT VERIFICATION: Registration order does not affect precedence
            // Literal segments always beat parameter segments due to specificity
            let resp3 = router2.handle(Request::new("GET", "/users/someone"));
            assert_eq!(
                resp3.status,
                StatusCode::ACCEPTED,
                "Parameter route should still handle non-literal single-segment users"
            );

            let resp4 = router2.handle(Request::new("GET", "/users/some/path"));
            assert_eq!(
                resp4.status,
                StatusCode::CREATED,
                "Wildcard route should remain the least-specific fallback"
            );
        }

        /// AUDIT: Verify multiple literal segments beat mixed patterns
        ///
        /// Routes with more literal segments should win over those with fewer,
        /// even when the total segment count is the same.
        #[test]
        fn audit_multiple_literal_segments_precedence() {
            use crate::web::extract::Path;
            use crate::web::handler::FnHandler1;

            fn param_handler(Path(_params): Path<HashMap<String, String>>) -> StatusCode {
                StatusCode::ACCEPTED
            }

            let router = Router::new()
                .route(
                    "/api/:version/users",
                    get(FnHandler1::<_, Path<HashMap<String, String>>>::new(
                        param_handler,
                    )),
                )
                .route("/api/v1/users", get(FnHandler::new(literal_handler)))
                .route(
                    "/api/:version/:resource",
                    get(FnHandler1::<_, Path<HashMap<String, String>>>::new(
                        param_handler,
                    )),
                );

            // Should match the most specific route (most literal segments)
            let resp = router.handle(Request::new("GET", "/api/v1/users"));
            assert_eq!(
                resp.status,
                StatusCode::OK,
                "Route with more literal segments '/api/v1/users' must win over '/api/:version/users'"
            );
        }

        /// AUDIT: Verify specificity calculation correctness
        ///
        /// Test the underlying specificity calculation to ensure proper ordering.
        #[test]
        fn audit_route_specificity_calculation() {
            let literal_route = RoutePattern::parse("/users/me/profile");
            let mixed_route = RoutePattern::parse("/users/:id/profile");
            let param_route = RoutePattern::parse("/users/:id/:section");
            let wildcard_route = RoutePattern::parse("/users/*");

            let literal_spec = literal_route.specificity();
            let mixed_spec = mixed_route.specificity();
            let param_spec = param_route.specificity();
            let wildcard_spec = wildcard_route.specificity();

            // Verify literal segments count
            assert_eq!(
                literal_spec.literal_segments, 3,
                "Literal route should have 3 literal segments"
            );
            assert_eq!(
                mixed_spec.literal_segments, 2,
                "Mixed route should have 2 literal segments"
            );
            assert_eq!(
                param_spec.literal_segments, 1,
                "Param route should have 1 literal segment"
            );
            assert_eq!(
                wildcard_spec.literal_segments, 1,
                "Wildcard route should have 1 literal segment"
            );

            // Verify parameter segments count
            assert_eq!(
                literal_spec.param_segments, 0,
                "Literal route should have 0 parameter segments"
            );
            assert_eq!(
                mixed_spec.param_segments, 1,
                "Mixed route should have 1 parameter segment"
            );
            assert_eq!(
                param_spec.param_segments, 2,
                "Param route should have 2 parameter segments"
            );
            assert_eq!(
                wildcard_spec.param_segments, 0,
                "Wildcard route should have 0 parameter segments (wildcard is separate)"
            );

            // Verify precedence ordering
            assert!(
                literal_spec > mixed_spec,
                "Literal route must be more specific than mixed route"
            );
            assert!(
                mixed_spec > param_spec,
                "Mixed route must be more specific than parameter route"
            );
            assert!(
                param_spec > wildcard_spec,
                "Parameter route must be more specific than wildcard route"
            );
        }

        /// AUDIT: Verify complex precedence scenarios
        ///
        /// Test edge cases with multiple competing routes to ensure consistent behavior.
        #[test]
        fn audit_complex_precedence_scenarios() {
            fn route_a() -> &'static str {
                "route_a"
            }
            fn route_b() -> &'static str {
                "route_b"
            }
            fn route_c() -> &'static str {
                "route_c"
            }

            let router = Router::new()
                // Exact match should win
                .route("/api/v1/users/me", get(FnHandler::new(route_a)))
                // Less specific - one parameter
                .route("/api/v1/users/:id", get(FnHandler::new(route_b)))
                // Even less specific - two parameters
                .route("/api/:version/users/:id", get(FnHandler::new(route_c)))
                // Wildcard should be least specific
                .route("/api/*", get(FnHandler::new(|| "wildcard")));

            let resp = router.handle(Request::new("GET", "/api/v1/users/me"));
            assert_eq!(resp.status, StatusCode::OK);
            let body = String::from_utf8(resp.body.to_vec()).unwrap();
            assert_eq!(body, "route_a", "Most specific literal route should win");

            // Test that parameter route still works for other values
            let resp2 = router.handle(Request::new("GET", "/api/v1/users/123"));
            assert_eq!(resp2.status, StatusCode::OK);
            let body2 = String::from_utf8(resp2.body.to_vec()).unwrap();
            assert_eq!(
                body2, "route_b",
                "Parameter route should handle non-literal values"
            );

            let resp3 = router.handle(Request::new("GET", "/api/v2/users/123"));
            assert_eq!(resp3.status, StatusCode::OK);
            let body3 = String::from_utf8(resp3.body.to_vec()).unwrap();
            assert_eq!(
                body3, "route_c",
                "Less-specific parameter route should handle non-v1 versions"
            );
        }

        /// AUDIT: Verify edge case with similar literal paths
        ///
        /// Ensure the router correctly distinguishes between similar literal paths.
        #[test]
        fn audit_similar_literal_paths_distinction() {
            let router = Router::new()
                .route("/users/me", get(FnHandler::new(|| "me")))
                .route("/users/menu", get(FnHandler::new(|| "menu")))
                .route("/users/metrics", get(FnHandler::new(|| "metrics")));

            // Each literal path should match only itself
            let resp_me = router.handle(Request::new("GET", "/users/me"));
            assert_eq!(String::from_utf8(resp_me.body.to_vec()).unwrap(), "me");

            let resp_menu = router.handle(Request::new("GET", "/users/menu"));
            assert_eq!(String::from_utf8(resp_menu.body.to_vec()).unwrap(), "menu");

            let resp_metrics = router.handle(Request::new("GET", "/users/metrics"));
            assert_eq!(
                String::from_utf8(resp_metrics.body.to_vec()).unwrap(),
                "metrics"
            );
        }

        /// AUDIT: Verify precedence with mixed HTTP methods
        ///
        /// Route precedence should work consistently across different HTTP methods.
        #[test]
        fn audit_precedence_across_http_methods() {
            use crate::web::extract::Path;
            use crate::web::handler::FnHandler1;

            fn literal_get() -> &'static str {
                "literal_get"
            }
            fn literal_post() -> &'static str {
                "literal_post"
            }
            fn param_get(Path(_): Path<String>) -> &'static str {
                "param_get"
            }
            fn param_post(Path(_): Path<String>) -> &'static str {
                "param_post"
            }

            let router = Router::new()
                .route(
                    "/users/:id",
                    get(FnHandler1::<_, Path<String>>::new(param_get)).post(FnHandler1::<
                        _,
                        Path<String>,
                    >::new(
                        param_post
                    )),
                )
                .route(
                    "/users/me",
                    get(FnHandler::new(literal_get)).post(FnHandler::new(literal_post)),
                );

            // GET method should prefer literal route
            let resp_get = router.handle(Request::new("GET", "/users/me"));
            assert_eq!(
                String::from_utf8(resp_get.body.to_vec()).unwrap(),
                "literal_get"
            );

            // POST method should prefer literal route
            let resp_post = router.handle(Request::new("POST", "/users/me"));
            assert_eq!(
                String::from_utf8(resp_post.body.to_vec()).unwrap(),
                "literal_post"
            );
        }

        /// AUDIT: Verify that parameter routes still capture when appropriate
        ///
        /// Ensure parameter routes work correctly when no literal match exists.
        #[test]
        fn audit_parameter_routes_capture_when_appropriate() {
            use crate::web::extract::Path;
            use crate::web::handler::FnHandler1;

            fn param_handler(Path(id): Path<String>) -> String {
                format!("captured:{}", id)
            }

            let router = Router::new()
                .route(
                    "/users/me",
                    get(FnHandler::new(|| "literal:me".to_string())),
                )
                .route(
                    "/users/:id",
                    get(FnHandler1::<_, Path<String>>::new(param_handler)),
                );

            // Literal should win for exact match
            let resp_me = router.handle(Request::new("GET", "/users/me"));
            assert_eq!(
                String::from_utf8(resp_me.body.to_vec()).unwrap(),
                "literal:me"
            );

            // Parameter should capture other values
            let resp_123 = router.handle(Request::new("GET", "/users/123"));
            assert_eq!(
                String::from_utf8(resp_123.body.to_vec()).unwrap(),
                "captured:123"
            );

            let resp_admin = router.handle(Request::new("GET", "/users/admin"));
            assert_eq!(
                String::from_utf8(resp_admin.body.to_vec()).unwrap(),
                "captured:admin"
            );
        }
    }

    // ─── Router::layer (br-asupersync-server-stack-hardening-eeexl1.3) ──────

    mod layering {
        use super::*;
        use std::sync::{Arc, Mutex};

        /// Test layer that records enter/exit events around the inner handler.
        #[derive(Clone)]
        struct RecordingLayer {
            name: &'static str,
            log: Arc<Mutex<Vec<String>>>,
        }

        impl RecordingLayer {
            fn new(name: &'static str, log: Arc<Mutex<Vec<String>>>) -> Self {
                Self { name, log }
            }
        }

        struct RecordingMiddleware<H> {
            inner: H,
            name: &'static str,
            log: Arc<Mutex<Vec<String>>>,
        }

        impl<H: Handler> Layer<H> for RecordingLayer {
            type Service = RecordingMiddleware<H>;

            fn layer(&self, inner: H) -> Self::Service {
                RecordingMiddleware {
                    inner,
                    name: self.name,
                    log: Arc::clone(&self.log),
                }
            }
        }

        impl<H: Handler> Handler for RecordingMiddleware<H> {
            fn call(
                &self,
                cx: &Cx,
                req: Request,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>>
            {
                let cx = cx.clone();
                Box::pin(async move {
                    self.log
                        .lock()
                        .expect("log lock")
                        .push(format!("enter:{}", self.name));
                    let resp = self.inner.call(&cx, req).await;
                    self.log
                        .lock()
                        .expect("log lock")
                        .push(format!("exit:{}", self.name));
                    resp
                })
            }
        }

        fn recording_handler(log: Arc<Mutex<Vec<String>>>) -> impl Handler {
            struct H(Arc<Mutex<Vec<String>>>);
            impl Handler for H {
                fn call(
                    &self,
                    _cx: &Cx,
                    _req: Request,
                ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>>
                {
                    Box::pin(async move {
                        self.0.lock().expect("log lock").push("handler".to_string());
                        StatusCode::OK.into_response()
                    })
                }
            }
            H(log)
        }

        /// Golden execution-order trace for three stacked layers.
        ///
        /// Documented contract: the LAST-added layer is the OUTERMOST — it
        /// sees the request first and the response last.
        #[test]
        fn layer_execution_order_golden() {
            let log = Arc::new(Mutex::new(Vec::new()));
            let router = Router::new()
                .route("/traced", get(recording_handler(Arc::clone(&log))))
                .layer(RecordingLayer::new("auth", Arc::clone(&log)))
                .layer(RecordingLayer::new("trace", Arc::clone(&log)))
                .layer(RecordingLayer::new("request_id", Arc::clone(&log)));

            let resp = router.handle(Request::new("GET", "/traced"));
            assert_eq!(resp.status, StatusCode::OK);

            let golden = vec![
                "enter:request_id".to_string(),
                "enter:trace".to_string(),
                "enter:auth".to_string(),
                "handler".to_string(),
                "exit:auth".to_string(),
                "exit:trace".to_string(),
                "exit:request_id".to_string(),
            ];
            assert_eq!(
                *log.lock().expect("log lock"),
                golden,
                "onion ordering: last-added layer must be outermost"
            );
        }

        #[test]
        fn routes_added_after_layer_are_not_wrapped() {
            let log = Arc::new(Mutex::new(Vec::new()));
            let router = Router::new()
                .route("/wrapped", get(FnHandler::new(ok_handler)))
                .layer(RecordingLayer::new("mw", Arc::clone(&log)))
                .route("/bare", get(FnHandler::new(ok_handler)));

            let _ = router.handle(Request::new("GET", "/bare"));
            assert!(
                log.lock().expect("log lock").is_empty(),
                "route added after .layer() must not be wrapped"
            );

            let _ = router.handle(Request::new("GET", "/wrapped"));
            assert_eq!(
                *log.lock().expect("log lock"),
                vec!["enter:mw".to_string(), "exit:mw".to_string()],
                "route added before .layer() must be wrapped"
            );
        }

        #[test]
        fn layer_wraps_fallback() {
            let log = Arc::new(Mutex::new(Vec::new()));
            let router = Router::new()
                .fallback(FnHandler::new(not_found_handler))
                .layer(RecordingLayer::new("mw", Arc::clone(&log)));

            let resp = router.handle(Request::new("GET", "/nope"));
            assert_eq!(resp.status, StatusCode::NOT_FOUND);
            assert_eq!(
                *log.lock().expect("log lock"),
                vec!["enter:mw".to_string(), "exit:mw".to_string()],
                "fallback handler must be wrapped by .layer()"
            );
        }

        #[test]
        fn layer_wraps_method_not_allowed() {
            let log = Arc::new(Mutex::new(Vec::new()));
            let router = Router::new()
                .route("/traced", get(FnHandler::new(ok_handler)))
                .layer(RecordingLayer::new("mw", Arc::clone(&log)));

            let resp = router.handle(Request::new("POST", "/traced"));
            assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(resp.header_value("allow"), Some("GET"));
            assert_eq!(
                *log.lock().expect("log lock"),
                vec!["enter:mw".to_string(), "exit:mw".to_string()],
                "method-not-allowed must be wrapped by .layer()"
            );
        }

        #[test]
        fn cors_layer_handles_preflight_without_options_route() {
            use crate::web::middleware::{CorsLayer, CorsPolicy};

            let router = Router::new()
                .route("/cors", get(FnHandler::new(ok_handler)))
                .layer(CorsLayer::new(CorsPolicy::default()));

            let resp = router.handle(
                Request::new("OPTIONS", "/cors")
                    .with_header("Origin", "https://example.com")
                    .with_header("Access-Control-Request-Method", "POST")
                    .with_header("Access-Control-Request-Headers", "content-type"),
            );

            assert_eq!(resp.status, StatusCode::NO_CONTENT);
            assert_eq!(
                resp.headers.get("access-control-allow-origin"),
                Some(&"*".to_string())
            );
            assert!(resp.headers.contains_key("access-control-allow-methods"));
            assert!(resp.headers.contains_key("access-control-allow-headers"));
        }

        #[test]
        fn layer_wraps_nested_routers() {
            let log = Arc::new(Mutex::new(Vec::new()));
            let api = Router::new().route("/users", get(FnHandler::new(ok_handler)));
            let router = Router::new()
                .nest("/api", api)
                .layer(RecordingLayer::new("mw", Arc::clone(&log)));

            let resp = router.handle(Request::new("GET", "/api/users"));
            assert_eq!(resp.status, StatusCode::OK);
            assert_eq!(
                *log.lock().expect("log lock"),
                vec!["enter:mw".to_string(), "exit:mw".to_string()],
                "nested router handlers must be wrapped by .layer()"
            );
        }

        #[test]
        fn builtin_middleware_layers_compose_on_router() {
            use crate::web::middleware::{
                AuthLayer, AuthPolicy, HeaderOverwrite, SetResponseHeaderLayer,
            };

            let router = Router::new()
                .route("/secure", get(FnHandler::new(ok_handler)))
                .layer(AuthLayer::new(AuthPolicy::exact_bearer("tok")))
                .layer(SetResponseHeaderLayer::new(
                    "x-frame-options",
                    "DENY",
                    HeaderOverwrite::Always,
                ));

            // Unauthorized: auth (inner) rejects; header layer (outer) still stamps.
            let resp = router.handle(Request::new("GET", "/secure"));
            assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
            assert_eq!(
                resp.headers.get("x-frame-options").map(String::as_str),
                Some("DENY")
            );

            // Authorized request flows through to the handler.
            let resp = router
                .handle(Request::new("GET", "/secure").with_header("authorization", "Bearer tok"));
            assert_eq!(resp.status, StatusCode::OK);
            assert_eq!(
                resp.headers.get("x-frame-options").map(String::as_str),
                Some("DENY")
            );
        }

        // ─── Extension<T> lifecycle ──────────────────────────────────────────

        mod extension_lifecycle {
            use super::*;
            use crate::web::extract::Extension;
            use crate::web::handler::FnHandler1;
            use std::sync::atomic::{AtomicU64, Ordering};
            use std::sync::{Arc, Mutex, Weak};

            #[derive(Clone)]
            struct RequestStamp {
                serial: u64,
            }

            /// Middleware that stamps each request with a unique serial.
            #[derive(Clone)]
            struct StampLayer {
                counter: Arc<AtomicU64>,
            }

            struct StampMiddleware<H> {
                inner: H,
                counter: Arc<AtomicU64>,
            }

            impl<H: Handler> Layer<H> for StampLayer {
                type Service = StampMiddleware<H>;

                fn layer(&self, inner: H) -> Self::Service {
                    StampMiddleware {
                        inner,
                        counter: Arc::clone(&self.counter),
                    }
                }
            }

            impl<H: Handler> Handler for StampMiddleware<H> {
                fn call(
                    &self,
                    cx: &Cx,
                    mut req: Request,
                ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>>
                {
                    let serial = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
                    req.extensions.insert_typed(RequestStamp { serial });
                    self.inner.call(cx, req)
                }
            }

            fn stamp_echo_handler() -> impl Handler {
                FnHandler1::<_, Extension<RequestStamp>>::new(
                    |Extension(stamp): Extension<RequestStamp>| format!("serial:{}", stamp.serial),
                )
            }

            /// Insert-in-middleware → extract-in-handler, and cross-request
            /// isolation: every request sees only its own stamp.
            #[test]
            fn middleware_insert_handler_extract_no_cross_request_bleed() {
                let router = Router::new()
                    .route("/stamped", get(stamp_echo_handler()))
                    .layer(StampLayer {
                        counter: Arc::new(AtomicU64::new(0)),
                    });

                let r1 = router.handle(Request::new("GET", "/stamped"));
                let r2 = router.handle(Request::new("GET", "/stamped"));
                let r3 = router.handle(Request::new("GET", "/stamped"));
                assert_eq!(String::from_utf8(r1.body.to_vec()).unwrap(), "serial:1");
                assert_eq!(String::from_utf8(r2.body.to_vec()).unwrap(), "serial:2");
                assert_eq!(String::from_utf8(r3.body.to_vec()).unwrap(), "serial:3");
            }

            /// A handler that asks for a missing extension gets a 500: wiring
            /// bugs must be loud, not silently defaulted.
            #[test]
            fn missing_extension_is_internal_server_error() {
                let router = Router::new().route("/stamped", get(stamp_echo_handler()));
                let resp = router.handle(Request::new("GET", "/stamped"));
                assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
            }

            #[derive(Clone)]
            struct ProbeExt(#[allow(dead_code)] Arc<()>);

            /// Extensions drop with the request: once the request region's
            /// handler run completes, no copy of the extension value survives.
            #[test]
            fn extension_dropped_when_request_region_completes() {
                use crate::web::request_region::{RegionOutcome, RequestRegion};

                let probe = Arc::new(());
                let weak: Weak<()> = Arc::downgrade(&probe);

                let mut req = Request::new("GET", "/probe");
                req.extensions.insert_typed(ProbeExt(probe));

                let handler = FnHandler1::<_, Extension<ProbeExt>>::new(
                    |Extension(_probe): Extension<ProbeExt>| "ok",
                );

                let cx = Cx::for_testing();
                let region = RequestRegion::new(&cx, req);
                let outcome = futures_lite::future::block_on(region.run_handler(&handler));
                assert!(matches!(outcome, RegionOutcome::Ok(_)));

                assert!(
                    weak.upgrade().is_none(),
                    "extension value must drop with the request when the region run completes"
                );
            }

            /// Routed dispatch drops middleware-inserted extensions request by
            /// request: nothing accumulates across calls.
            #[test]
            fn per_request_extensions_do_not_accumulate() {
                let weaks: Arc<Mutex<Vec<Weak<()>>>> = Arc::new(Mutex::new(Vec::new()));

                #[derive(Clone)]
                struct ProbeLayer {
                    weaks: Arc<Mutex<Vec<Weak<()>>>>,
                }

                struct ProbeMiddleware<H> {
                    inner: H,
                    weaks: Arc<Mutex<Vec<Weak<()>>>>,
                }

                impl<H: Handler> Layer<H> for ProbeLayer {
                    type Service = ProbeMiddleware<H>;

                    fn layer(&self, inner: H) -> Self::Service {
                        ProbeMiddleware {
                            inner,
                            weaks: Arc::clone(&self.weaks),
                        }
                    }
                }

                impl<H: Handler> Handler for ProbeMiddleware<H> {
                    fn call(
                        &self,
                        cx: &Cx,
                        mut req: Request,
                    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>>
                    {
                        let probe = Arc::new(());
                        self.weaks
                            .lock()
                            .expect("weaks lock")
                            .push(Arc::downgrade(&probe));
                        req.extensions.insert_typed(ProbeExt(probe));
                        self.inner.call(cx, req)
                    }
                }

                let router = Router::new()
                    .route(
                        "/probe",
                        get(FnHandler1::<_, Extension<ProbeExt>>::new(
                            |Extension(_p): Extension<ProbeExt>| "ok",
                        )),
                    )
                    .layer(ProbeLayer {
                        weaks: Arc::clone(&weaks),
                    });

                for _ in 0..3 {
                    let resp = router.handle(Request::new("GET", "/probe"));
                    assert_eq!(resp.status, StatusCode::OK);
                }

                let weaks = weaks.lock().expect("weaks lock");
                assert_eq!(weaks.len(), 3);
                assert!(
                    weaks.iter().all(|w| w.upgrade().is_none()),
                    "every request's extension must be dropped once its dispatch completes"
                );
            }
        }
    }

    // ─── Default request trace (br-asupersync-server-stack-hardening-eeexl1.3 AC3) ──

    mod default_trace {
        use super::*;
        use crate::CancelReason;
        use crate::web::middleware::{RequestLogRecord, RequestLogSink};
        use std::sync::{Arc, Mutex};

        fn fixed_time() -> Time {
            Time::from_millis(7_000)
        }

        fn collecting_sink() -> (RequestLogSink, Arc<Mutex<Vec<RequestLogRecord>>>) {
            let records = Arc::new(Mutex::new(Vec::new()));
            let sink_records = Arc::clone(&records);
            let sink: RequestLogSink = Arc::new(move |record: &RequestLogRecord| {
                sink_records
                    .lock()
                    .expect("records lock")
                    .push(record.clone());
            });
            (sink, records)
        }

        fn boom_handler() -> Response {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }

        /// Golden of the structured request log emitted by the default-on
        /// trace, scrubbed for determinism: a fixed time getter zeroes
        /// durations, and generated request ids are sequential.
        #[test]
        fn default_trace_golden_scrubbed() {
            let (sink, records) = collecting_sink();
            let router = Router::new()
                .route("/ok", get(FnHandler::new(ok_handler)))
                .route("/boom", get(FnHandler::new(boom_handler)))
                .with_default_trace_time_getter(fixed_time)
                .with_default_trace_record_sink(sink);

            let _ = router.handle(Request::new("GET", "/ok"));
            let _ = router.handle(Request::new("GET", "/boom"));
            let _ = router.handle(Request::new("POST", "/ok"));
            let _ = router.handle(Request::new("GET", "/missing"));

            let got =
                serde_json::to_value(&*records.lock().expect("records lock")).expect("serialize");
            let want = serde_json::json!([
                {
                    "method": "GET",
                    "path": "/ok",
                    "status": 200,
                    "severity": "ok",
                    "duration_ms": 0,
                    "request_id": "req-1",
                    "cancelled": false,
                    "cancel_reason": null
                },
                {
                    "method": "GET",
                    "path": "/boom",
                    "status": 500,
                    "severity": "server_error",
                    "duration_ms": 0,
                    "request_id": "req-2",
                    "cancelled": false,
                    "cancel_reason": null
                },
                {
                    "method": "POST",
                    "path": "/ok",
                    "status": 405,
                    "severity": "client_error",
                    "duration_ms": 0,
                    "request_id": "req-3",
                    "cancelled": false,
                    "cancel_reason": null
                },
                {
                    "method": "GET",
                    "path": "/missing",
                    "status": 404,
                    "severity": "client_error",
                    "duration_ms": 0,
                    "request_id": "req-4",
                    "cancelled": false,
                    "cancel_reason": null
                }
            ]);
            assert_eq!(got, want, "request log schema golden drifted");
        }

        /// Cancelled requests log as 499 with the cancel reason — the
        /// outcome-severity contract for client-abandoned work.
        #[test]
        fn cancelled_request_logs_499_with_reason() {
            let (sink, records) = collecting_sink();
            let router = Router::new()
                .route("/slow", get(FnHandler::new(ok_handler)))
                .with_default_trace_time_getter(fixed_time)
                .with_default_trace_record_sink(sink);

            let cx = Cx::for_testing();
            cx.set_cancel_requested(true);
            cx.set_cancel_reason(CancelReason::user("client disconnected"));
            let _resp = futures_lite::future::block_on(
                router.handle_with_cx(&cx, Request::new("GET", "/slow")),
            );

            let records = records.lock().expect("records lock");
            assert_eq!(records.len(), 1);
            let record = &records[0];
            assert_eq!(record.status, 499, "cancelled requests must log as 499");
            assert_eq!(record.severity, "cancelled");
            assert!(record.cancelled);
            let reason = record.cancel_reason.as_deref().expect("cancel reason");
            assert!(
                reason.contains("client disconnected"),
                "cancel reason must carry the message, got: {reason}"
            );
        }

        /// Opt-out: `without_default_trace` silences the instrumentation.
        #[test]
        fn without_default_trace_emits_nothing() {
            let (sink, records) = collecting_sink();
            let router = Router::new()
                .with_default_trace_record_sink(sink)
                .without_default_trace()
                .route("/ok", get(FnHandler::new(ok_handler)));

            let resp = router.handle(Request::new("GET", "/ok"));
            assert_eq!(resp.status, StatusCode::OK);
            assert!(
                records.lock().expect("records lock").is_empty(),
                "opted-out router must not emit trace records"
            );
        }

        /// A client-supplied request id is propagated, never replaced.
        #[test]
        fn client_request_id_is_propagated() {
            let (sink, records) = collecting_sink();
            let router = Router::new()
                .route("/ok", get(FnHandler::new(ok_handler)))
                .with_default_trace_time_getter(fixed_time)
                .with_default_trace_record_sink(sink);

            let _ = router
                .handle(Request::new("GET", "/ok").with_header("x-request-id", "client-abc-123"));

            let records = records.lock().expect("records lock");
            assert_eq!(records[0].request_id.as_deref(), Some("client-abc-123"));
        }

        /// Response headers stay untouched under the log-only default policy.
        #[test]
        fn default_policy_does_not_mutate_response_headers() {
            let router = Router::new().route("/ok", get(FnHandler::new(ok_handler)));
            let resp = router.handle(Request::new("GET", "/ok"));
            assert!(!resp.headers.contains_key("x-response-time-ms"));
            assert!(!resp.headers.contains_key("x-trace-id"));
        }

        /// Opting into headers via the policy stamps duration + trace id.
        #[test]
        fn opt_in_policy_stamps_headers() {
            let router = Router::new()
                .route("/ok", get(FnHandler::new(ok_handler)))
                .with_default_trace_policy(RequestTracePolicy::default())
                .with_default_trace_time_getter(fixed_time);

            let resp = router.handle(Request::new("GET", "/ok"));
            assert_eq!(
                resp.headers.get("x-response-time-ms").map(String::as_str),
                Some("0")
            );
            assert_eq!(
                resp.headers.get("x-trace-id").map(String::as_str),
                Some("req-1")
            );
        }
    }
}
