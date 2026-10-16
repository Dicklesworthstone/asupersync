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
#[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
use crate::http::h1::stream::RequestHead;
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h1::stream::{Http1ProducedResponse, StreamingServerRequest};
use crate::http::h1::types::{Request as HttpRequest, Response as HttpResponse};
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h2::listener::Http2ProducedResponse;
#[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
use crate::http::h2::listener::Http2StreamingListenerConfig;
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
use crate::types::{
    Budget, Time,
    id::{next_bootstrap_region_id, next_bootstrap_task_id},
};
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use crate::types::{CancelKind, CancelReason};

#[cfg(all(feature = "http3", feature = "tls", not(target_arch = "wasm32")))]
mod h3_listener;
#[cfg(all(feature = "http3", feature = "tls", not(target_arch = "wasm32")))]
pub use h3_listener::{
    NativeH3Listener, NativeH3ListenerConfig, NativeH3ListenerError, NativeH3ListenerReport,
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
    allow_state: Arc<std::sync::RwLock<String>>,
    body_policy: Option<RequestBodyPolicy>,
}

impl Default for MethodRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl MethodRouter {
    /// Create an empty method router. Add only the methods this route accepts.
    #[must_use]
    pub fn new() -> Self {
        let allow_state = Arc::new(std::sync::RwLock::new(String::new()));
        Self {
            handlers: HashMap::with_capacity(4),
            method_not_allowed: Box::new(MethodNotAllowedHandler::new(Arc::clone(&allow_state))),
            allow_state,
            body_policy: None,
        }
    }

    /// Add a handler for a specific method.
    fn on(mut self, method: &str, handler: impl Handler) -> Self {
        self.handlers
            .insert(method.to_uppercase(), Box::new(handler));
        if let Ok(mut guard) = self.allow_state.write() {
            *guard = self.allow_header();
        }
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

    /// Add `other`'s methods to this route. For a method both register, this
    /// route's handler is kept: the first registration of a pattern and
    /// method answers, as it did when each registration was a separate route
    /// matched in order. A body policy is kept from this router, or taken
    /// from `other` if this one has none.
    ///
    /// Preserves existing middleware wrapping on `method_not_allowed`
    /// (br-asupersync-vftw38 item 8).
    fn merge(&mut self, other: Self) {
        for (method, handler) in other.handlers {
            self.handlers.entry(method).or_insert(handler);
        }
        if self.body_policy.is_none() {
            self.body_policy = other.body_policy;
        }
        if let Ok(mut guard) = self.allow_state.write() {
            *guard = self.allow_header();
        }
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
            Box::new(MethodNotAllowedHandler::new(Arc::clone(&self.allow_state))),
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
        if let Some(handler) = self.handlers.get(&upper) {
            return handler.call(cx, req).await;
        }
        // A server answers HEAD as it would GET (RFC 9110 §9.1, §9.3.2); the
        // HTTP transports send the response without its content.
        if upper == METHOD_HEAD
            && let Some(handler) = self.handlers.get(METHOD_GET)
        {
            return handler.call(cx, req).await;
        }
        self.method_not_allowed.call(cx, req).await
    }
}

struct MethodNotAllowedHandler {
    allow: Arc<std::sync::RwLock<String>>,
}

impl MethodNotAllowedHandler {
    fn new(allow: Arc<std::sync::RwLock<String>>) -> Self {
        Self { allow }
    }
}

impl Handler for MethodNotAllowedHandler {
    fn call(
        &self,
        _cx: &Cx,
        _req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let allow = self
            .allow
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default();
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

impl RouteSpecificity {
    /// A mount whose router resolves nothing for the rest of the path still
    /// claims its own prefix, like a `prefix/*` route.
    const UNRESOLVED: Self = Self {
        exact_path: false,
        literal_segments: 0,
        param_segments: 0,
        total_segments: 0,
    };

    /// What a nested router resolved, seen from the parent: the mount
    /// prefix's literal segments come first.
    fn under_mount(self, prefix_segments: usize) -> Self {
        Self {
            exact_path: self.exact_path,
            literal_segments: self.literal_segments + prefix_segments,
            param_segments: self.param_segments,
            total_segments: self.total_segments + prefix_segments,
        }
    }
}

/// Where a router sends a path: one of its own routes, or a nested router
/// with the rest of the path.
enum RouteSelection<'a> {
    Route(&'a MethodRouter, HashMap<String, String>),
    Mount(&'a Router, String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Param(String),
    Wildcard,
}

impl RoutePattern {
    /// Check whether two route patterns have equivalent segment shapes,
    /// so registering e.g. `/users/:id` and `/users/:user_id` merges methods
    /// rather than creating a duplicate shadowed route (br-asupersync-vftw38 item 7).
    fn is_equivalent(&self, other: &Self) -> bool {
        if self.segments.len() != other.segments.len() {
            return false;
        }
        self.segments.iter().zip(&other.segments).all(|(s1, s2)| match (s1, s2) {
            (Segment::Literal(a), Segment::Literal(b)) => a == b,
            (Segment::Param(_), Segment::Param(_)) => true,
            (Segment::Wildcard, Segment::Wildcard) => true,
            _ => false,
        })
    }

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
        // Targets without a leading slash (like "admin/x" or asterisk-form "*")
        // do not match origin-form resource routes (br-asupersync-vftw38 item 12).
        if !path.starts_with('/') {
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
    /// Mounts compete with routes by specificity
    /// ([`Router::prefer_specific_mounts`]).
    prefer_specific_mounts: bool,
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
    /// `:authority` and Host named different targets, Host was repeated or
    /// empty, or an `http`/`https` request named neither (RFC 9114 section
    /// 4.3.1).
    InvalidAuthority,
    /// The caller cancelled an admitted handler scope before it produced a
    /// response.
    DispatchCancelled,
    /// The listener is draining after GOAWAY and admits no new request. No
    /// handler saw it, so the stream is reset with H3_REQUEST_REJECTED.
    Draining,
    /// The connection is retiring and admits no new request. No handler saw
    /// it, so the stream is reset with H3_REQUEST_REJECTED.
    ConnectionRetiring,
    /// The listener's concurrent-request limit is reached. No handler saw the
    /// request, so the stream is reset with H3_REQUEST_REJECTED.
    TooManyConcurrentRequests {
        /// Configured maximum number of concurrent requests.
        limit: usize,
    },
    /// The request did not finish arriving before its assembly deadline.
    RequestAssemblyTimeout,
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
    #[cfg(feature = "tls")]
    streaming_body_limit: Option<u64>,
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

    /// Declared length already validated at streaming HEADERS admission.
    #[cfg(feature = "tls")]
    fn declared_content_length(&self) -> Option<u64> {
        self.request
            .header("content-length")
            .and_then(|value| value.parse().ok())
    }

    /// Effective static policy and transport ceiling for the live body.
    #[cfg(feature = "tls")]
    fn max_request_body_size(&self) -> u64 {
        self.streaming_body_limit.unwrap_or(u64::MAX)
    }

    /// Install the live body created by the actual admitted request task.
    #[cfg(feature = "tls")]
    async fn run_produced_streaming(
        mut self,
        cx: &Cx,
        body: crate::http::h1::stream::IncomingRequestBody,
    ) -> NativeH3RouterProducedDispatch {
        let Ok(_body_control) = insert_streaming_raw_body(&mut self.request, body) else {
            let response = http1_stream_refusal_response("streaming request body slot collision");
            let status = response.status.as_u16();
            return NativeH3RouterProducedDispatch::Buffered(NativeH3RouterPreparedResponse {
                token: self.token,
                response: h3_response_from_web(response, self.suppress_body_for_head)
                    .map(|(head, body)| (status, head, body)),
            });
        };
        // This guard outlives handler dispatch even when an extension clone
        // survives it. A body taken by a producer or child stays owned there.
        self.run_produced(cx).await
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
            ..
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
    // The managed listener keeps this scheduler-admitted request task alive
    // from handler entry through producer completion. Caller-driven bridges
    // retain their existing independently minted producer context.
    owned_request_cx: Option<Cx>,
    max_data_wire_bytes: u64,
    // The unsent rest of the producer's latest DATA frame.
    pending_data: Option<Bytes>,
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
    #[cfg(feature = "tls")]
    streaming_owned: BTreeSet<StreamId>,
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
            #[cfg(feature = "tls")]
            streaming_owned: BTreeSet::new(),
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

    /// Reserve a listener-owned dispatch at HEADERS, before creating a body
    /// channel or a request region. The ordinary established-session bridge
    /// keeps its complete-body ingress contract.
    #[cfg(feature = "tls")]
    fn begin_streaming_request_with_cx(
        &mut self,
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        stream_id: StreamId,
        head: H3RequestHead,
        retained_bytes: usize,
    ) -> Result<NativeH3RouterIngress, crate::http::h3::NativeH3SessionError> {
        if self.discarding.contains(&stream_id) {
            return Ok(NativeH3RouterIngress::Event(
                NativeH3RouterEvent::RequestDiscarded { stream_id },
            ));
        }
        let admitted = (|| {
            if head.pseudo.method.as_deref() == Some(METHOD_CONNECT) {
                return Err(NativeH3RouterRefusal::ConnectUnsupported);
            }
            if self.pending.contains_key(&stream_id)
                || self.in_flight.contains_key(&stream_id)
                || self.produced.contains_key(&stream_id)
            {
                return Err(NativeH3RouterRefusal::InvalidRequestProgression(
                    "duplicate request HEADERS",
                ));
            }
            let declared = validate_h3_request_head_semantics(&head)?;
            let suppress_body_for_head = head.pseudo.method.as_deref() == Some(METHOD_HEAD);
            let request = web_request_from_h3(head, Vec::new());
            let body_limit = self
                .router
                .h3_streaming_body_policy_limit(&request)?
                .map_or(self.config.max_buffered_body_bytes, |limit| {
                    limit.min(self.config.max_buffered_body_bytes)
                });
            if declared.is_some_and(|length| length > body_limit) {
                return Err(NativeH3RouterRefusal::RequestBodyTooLarge { limit: body_limit });
            }
            if self.in_flight.len() >= self.config.max_in_flight_dispatches {
                return Err(NativeH3RouterRefusal::TooManyInFlightDispatches {
                    limit: self.config.max_in_flight_dispatches,
                });
            }
            let aggregate = self.retained_request_body_bytes.checked_add(retained_bytes);
            if aggregate.is_none_or(|bytes| bytes > self.config.max_total_buffered_body_bytes) {
                return Err(NativeH3RouterRefusal::ConnectionBodyBudgetExhausted {
                    limit: self.config.max_total_buffered_body_bytes,
                });
            }
            Ok((request, suppress_body_for_head, body_limit))
        })();
        let (request, suppress_body_for_head, body_limit) = match admitted {
            Ok(admitted) => admitted,
            Err(
                reason @ (NativeH3RouterRefusal::InvalidContentLength
                | NativeH3RouterRefusal::InvalidTransferEncoding
                | NativeH3RouterRefusal::InvalidAuthority),
            ) => {
                // RFC 9114 section 4.1.2 distinguishes malformed HTTP
                // messages from an application's voluntary cancellation.
                connection.reset_stream(cx, stream_id, 0x10e)?;
                connection.stop_stream_receiving(cx, stream_id, 0x10e)?;
                self.remember_discarding(stream_id);
                return Ok(NativeH3RouterIngress::Event(
                    NativeH3RouterEvent::RequestRefused { stream_id, reason },
                ));
            }
            Err(reason) => {
                return self
                    .refuse_request(cx, session, connection, stream_id, reason, true)
                    .map(NativeH3RouterIngress::Event);
            }
        };
        // Charge the queue plus the listener's one retained DATA chunk for the
        // entire dispatch. A slow consumer or a reset cannot reclaim this
        // admission credit while its request task is still owned.
        self.retained_request_body_bytes += retained_bytes;
        self.in_flight.insert(stream_id, retained_bytes);
        self.streaming_owned.insert(stream_id);
        Ok(NativeH3RouterIngress::Dispatch(NativeH3RouterDispatch {
            token: NativeH3RouterDispatchToken {
                bridge_identity: Arc::clone(&self.identity),
                stream_id,
            },
            router: Arc::clone(&self.router),
            request,
            suppress_body_for_head,
            streaming_body_limit: Some(u64::try_from(body_limit).unwrap_or(u64::MAX)),
        }))
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
                    #[cfg(feature = "tls")]
                    streaming_body_limit: None,
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
                owned_request_cx: None,
                max_data_wire_bytes,
                pending_data: None,
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
        self.cancel_dispatch_with_optional_reason(cx, session, connection, token, None)
    }

    /// Refuses an admitted dispatch before any handler has run, resetting its
    /// stream with the code for `reason`. Load and lifecycle reasons such as
    /// [`NativeH3RouterRefusal::TooManyConcurrentRequests`] and
    /// [`NativeH3RouterRefusal::Draining`] reset with H3_REQUEST_REJECTED, which
    /// tells the client a retry is safe (RFC 9114 section 4.1.1). Ownership
    /// checks and stream cleanup are identical to [`Self::cancel_dispatch_with_cx`];
    /// a dispatch that already produced a response is cancelled as that method
    /// would cancel it, since its handler has run.
    pub fn refuse_dispatch_with_cx(
        &mut self,
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        token: &NativeH3RouterDispatchToken,
        reason: NativeH3RouterRefusal,
    ) -> Result<NativeH3RouterEvent, crate::http::h3::NativeH3SessionError> {
        self.terminate_dispatch(cx, session, connection, token, None, reason)
    }

    /// Cancels a dispatch while retaining the request owner's cancellation cause.
    ///
    /// Produced responses observe `ParentCancelled` with `cause` attached, so a
    /// request deadline remains distinguishable from a client reset or shutdown.
    /// `cx` must be the live connection-driver context used to queue the reset,
    /// rather than the cancelled request context. Ownership checks and stream
    /// cleanup are identical to [`Self::cancel_dispatch_with_cx`].
    pub fn cancel_dispatch_with_reason(
        &mut self,
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        token: &NativeH3RouterDispatchToken,
        cause: CancelReason,
    ) -> Result<NativeH3RouterEvent, crate::http::h3::NativeH3SessionError> {
        self.cancel_dispatch_with_optional_reason(cx, session, connection, token, Some(cause))
    }

    fn cancel_dispatch_with_optional_reason(
        &mut self,
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        token: &NativeH3RouterDispatchToken,
        cause: Option<CancelReason>,
    ) -> Result<NativeH3RouterEvent, crate::http::h3::NativeH3SessionError> {
        self.terminate_dispatch(
            cx,
            session,
            connection,
            token,
            cause,
            NativeH3RouterRefusal::DispatchCancelled,
        )
    }

    /// Terminates an in-flight dispatch. `refusal` is the reason, and so the
    /// reset code, used when no response has been produced yet.
    fn terminate_dispatch(
        &mut self,
        cx: &Cx,
        session: &mut NativeH3Session,
        connection: &mut QuicConnection,
        token: &NativeH3RouterDispatchToken,
        cause: Option<CancelReason>,
        refusal: NativeH3RouterRefusal,
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
                mark_native_h3_produced_cancelled_with_reason(
                    &mut state,
                    "HTTP/3 connection closed before dispatch cancellation",
                    cause,
                );
            }
            self.take_pending_request(stream_id);
            self.release_in_flight(stream_id);
            return Ok(NativeH3RouterEvent::RequestRefused {
                stream_id,
                reason: refusal,
            });
        }
        if let Some(state) = self.produced.get_mut(&stream_id) {
            cancel_native_h3_produced_with_reason(
                cx,
                session,
                connection,
                state,
                "HTTP/3 produced response explicitly cancelled",
                cause,
            )?;
            return Ok(NativeH3RouterEvent::RequestRefused {
                stream_id,
                reason: NativeH3RouterRefusal::DispatchCancelled,
            });
        }
        let event = self.refuse_request(cx, session, connection, stream_id, refusal, false)?;
        self.release_in_flight(stream_id);
        Ok(event)
    }

    /// Preserve a framed input failure through produced-response cleanup.
    /// Native QUIC reset calls can replace an earlier application error code,
    /// so mark the response as reset before any generic cancellation path runs.
    #[cfg(feature = "tls")]
    fn cancel_streaming_dispatch_with_error(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        token: &NativeH3RouterDispatchToken,
        error_code: u64,
    ) -> Result<(), crate::http::h3::NativeH3SessionError> {
        let stream_id = token.stream_id;
        if !Arc::ptr_eq(&self.identity, &token.bridge_identity)
            || !self.streaming_owned.contains(&stream_id)
        {
            return Err(crate::http::h3::NativeH3SessionError::InvalidState(
                "HTTP/3 streaming cancellation does not own this dispatch",
            ));
        }
        let already_reset = self.reset_during_dispatch.contains(&stream_id)
            || self
                .produced
                .get(&stream_id)
                .is_some_and(|state| state.reset_queued);
        let (reset, stopped) =
            if !already_reset && connection.state() == QuicConnectionState::Established {
                (
                    connection.reset_stream(cx, stream_id, error_code),
                    connection.stop_stream_receiving(cx, stream_id, error_code),
                )
            } else {
                (Ok(()), Ok(()))
            };
        if let Some(state) = self.produced.get_mut(&stream_id) {
            mark_native_h3_produced_cancelled(state, "HTTP/3 request body failed");
        }
        self.reset_during_dispatch.insert(stream_id);
        self.remember_discarding(stream_id);
        reset?;
        stopped?;
        Ok(())
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
        session.reset_request(cx, connection, stream_id, refusal_reset_code(&reason))?;
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
        #[cfg(feature = "tls")]
        if self.streaming_owned.contains(&stream_id) {
            // Response completion and cancellation can precede request-task
            // and child-region cleanup. Their body queues still own memory.
            return;
        }
        if let Some(body_bytes) = self.in_flight.remove(&stream_id) {
            self.retained_request_body_bytes =
                self.retained_request_body_bytes.saturating_sub(body_bytes);
        }
    }

    #[cfg(feature = "tls")]
    fn release_streaming_dispatch_after_close(&mut self, stream_id: StreamId) {
        if self.streaming_owned.remove(&stream_id) {
            self.reset_during_dispatch.remove(&stream_id);
            self.release_in_flight(stream_id);
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
    owned_request_cx: Option<Cx>,
) -> (
    OutgoingBody,
    Cx,
    NativeH3ProducerLifecycle,
    NativeH3RouterProducer,
) {
    let region = if let Some(request_cx) = owned_request_cx {
        let now = request_cx.now();
        ServerRequestRegion::from_body_cx("h3-produced", request_cx, now)
    } else {
        ServerRequestRegion::mint_from_connection(
            "h3-produced",
            connection_cx.budget(),
            connection_cx.now(),
            connection_cx,
        )
    };
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
            ServerHopOutcome::Ok(Ok(_) | Err(_)) | ServerHopOutcome::Panicked(_) => {
                NativeH3ProducerOutcome::Failed
            }
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
    cancel_native_h3_produced_with_reason(cx, session, connection, state, message, None)
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn cancel_native_h3_produced_with_reason(
    cx: &Cx,
    session: &mut NativeH3Session,
    connection: &mut QuicConnection,
    state: &mut ActiveNativeH3ProducedResponse,
    message: &'static str,
    cause: Option<CancelReason>,
) -> Result<(), crate::http::h3::NativeH3SessionError> {
    let reset = if state.reset_queued {
        Ok(())
    } else {
        session.cancel_request(cx, connection, state.writer.stream_id())
    };
    mark_native_h3_produced_cancelled_with_reason(state, message, cause);
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
    mark_native_h3_produced_cancelled_with_reason(state, message, None);
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn mark_native_h3_produced_cancelled_with_reason(
    state: &mut ActiveNativeH3ProducedResponse,
    message: &'static str,
    cause: Option<CancelReason>,
) {
    if !state.reset_queued
        && let Some(producer_cx) = &state.producer_cx
    {
        let mut reason = CancelReason::parent_cancelled()
            .with_region(producer_cx.region_id())
            .with_task(producer_cx.task_id())
            .with_message(message);
        // Preserve an already-observed request timeout even when the caller
        // uses the legacy cancellation entry point. Repeated cleanup must not
        // replace the first reset's attribution with a generic parent reason.
        if let Some(cause) = cause.or_else(|| producer_cx.cancel_reason()) {
            reason =
                reason.with_cause_limited(cause, &crate::types::CancelAttributionConfig::default());
        }
        producer_cx.cancel_with_reason(reason);
    }
    state.reset_queued = true;
    state.plan = None;
    state.body = None;
    state.pending_data = None;
    state.terminal = None;
}

/// Wire length of a DATA frame carrying one byte: type, length, payload.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
const SMALLEST_H3_DATA_FRAME_WIRE_BYTES: u64 = 3;

/// Largest payload, at most `len`, whose DATA frame fits in `capacity` bytes.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn h3_data_payload_within(capacity: u64, len: usize) -> usize {
    let (mut low, mut high) = (0, len);
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        if h3_data_frame_wire_len(middle).is_ok_and(|wire| wire <= capacity) {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    low
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
                        make_native_h3_producer(cx, plan, state.owned_request_cx.take());
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

        if let Some(mut data) = state.pending_data.take() {
            // Send what the peer's credit admits now. Waiting for room for the
            // whole frame stalls when the peer's window is smaller than the
            // frame: it has nothing left to read, so it never grants more
            // (br-asupersync-f82gek).
            let capacity = match connection.poll_stream_write_ready(
                cx,
                stream_id,
                SMALLEST_H3_DATA_FRAME_WIRE_BYTES,
                task_cx,
            ) {
                Poll::Ready(Ok(capacity)) => capacity,
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
                Poll::Pending => {
                    state.pending_data = Some(data);
                    return Poll::Pending;
                }
            };
            // An oversized frame goes to queue_data whole, which refuses it.
            let admitted = if data.len() > state.writer.max_frame_payload_size() {
                data.len()
            } else {
                h3_data_payload_within(capacity, data.len())
            };
            let chunk = data.split_to(admitted);
            if !data.is_empty() {
                state.pending_data = Some(data);
            }
            if let Err(error) = state.writer.queue_data(chunk) {
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
            // Pull the next frame once the smallest DATA frame fits; the
            // frame is then sent in pieces as credit arrives.
            connection.poll_stream_write_ready(
                cx,
                stream_id,
                state
                    .max_data_wire_bytes
                    .min(SMALLEST_H3_DATA_FRAME_WIRE_BYTES),
                task_cx,
            )
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
                // Queued at the top of the loop, in pieces the peer's credit admits.
                state.pending_data = Some(bytes);
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
            prefer_specific_mounts: false,
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
        let pattern = RoutePattern::parse(pattern);
        // The same pattern registered again (`.route("/a", get(..))` then
        // `.route("/a", post(..))`) adds its methods to the existing route.
        // Kept separate, the first registration always matched and answered
        // the second one's methods with 405.
        // Equivalent patterns (e.g. `/users/:id` and `/users/:user_id`) also
        // merge rather than shadowing each other (br-asupersync-vftw38 item 7).
        if let Some((_, existing)) = self
            .routes
            .iter_mut()
            .find(|(registered, _)| registered.is_equivalent(&pattern))
        {
            existing.merge(method_router);
            return self;
        }
        self.routes.push((pattern, method_router));
        self
    }

    /// Mount a sub-router at the given prefix.
    ///
    /// The prefix is normalized to always begin with `/` (br-asupersync-vftw38 item 9).
    /// If another router was already mounted at this exact prefix, their routes and
    /// mounts merge rather than the first shadowing the second (br-asupersync-vftw38 item 7).
    #[must_use]
    pub fn nest(mut self, prefix: &str, router: Self) -> Self {
        let prefix = normalize_nest_prefix(prefix);
        if let Some((_, existing)) = self
            .nested
            .iter_mut()
            .find(|(existing_prefix, _)| existing_prefix == &prefix)
        {
            existing.merge_router(router);
            return self;
        }
        self.nested.push((prefix, router));
        self
    }

    /// Merge another router's routes, nested mounts, and fallback into this router
    /// (br-asupersync-vftw38 item 7).
    fn merge_router(&mut self, other: Self) {
        for (pattern, method_router) in other.routes {
            if let Some((_, existing)) = self
                .routes
                .iter_mut()
                .find(|(registered, _)| registered.is_equivalent(&pattern))
            {
                existing.merge(method_router);
            } else {
                self.routes.push((pattern, method_router));
            }
        }
        for (prefix, nested) in other.nested {
            if let Some((_, existing)) = self
                .nested
                .iter_mut()
                .find(|(existing_prefix, _)| existing_prefix == &prefix)
            {
                existing.merge_router(nested);
            } else {
                self.nested.push((prefix, nested));
            }
        }
        if self.fallback.is_none() {
            self.fallback = other.fallback;
        }
        self.extensions.extend_from(&other.extensions);
        if self.body_policy.is_none() {
            self.body_policy = other.body_policy;
        }
        if self.server_body_policy.is_none() {
            self.server_body_policy = other.server_body_policy;
        }
    }

    /// Let this router's mounts compete with its own routes by specificity.
    ///
    /// By default a mount is consulted only when none of this router's routes
    /// matches (see [`Self::handle`]), so `.route("/*", spa).nest("/api", api)`
    /// sends `/api/users` to `spa`, and `.route("/:page", ..)` captures
    /// `/admin` ahead of `.nest("/admin", ..)` and the layers on it. When
    /// enabled, a mount counts its prefix's literal segments in front of the
    /// route its router matches, and the more specific of the two wins: those
    /// paths go to `api` and to the `/admin` router. A path under a mount that
    /// its router does not route counts like a `prefix/*` route and gets that
    /// router's fallback or 404; the prefix itself (`/admin`) counts as an
    /// exact route of the prefix, even when the mounted router routes no `/`.
    /// A route still wins a tie with a mount.
    ///
    /// The setting applies to this router's own choice between its routes and
    /// mounts; enable it on nested routers that have mounts of their own
    /// (br-asupersync-vftw38 item 4).
    #[must_use]
    pub fn prefer_specific_mounts(mut self, enabled: bool) -> Self {
        self.prefer_specific_mounts = enabled;
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
    /// selected by longest matching prefix after top-level route selection,
    /// unless [`Self::prefer_specific_mounts`] lets them compete with routes.
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
    /// // The default host policy answers every request 421: name the hosts.
    /// let config = Http1ListenerConfig::default().http_config(
    ///     Http1Config::default().host_policy(HostPolicy::AllowList(vec!["localhost".to_owned()])),
    /// );
    /// let listener =
    ///     Http1Listener::bind_with_config("127.0.0.1:8080", app.into_http_handler(), config).await?;
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

    /// Convert this router into an HTTP/2 handler with live request bodies.
    ///
    /// Use with [`crate::http::h2::listener::Http2Listener::bind_streaming`]
    /// and `run_streaming`. The listener installs the actual request task's
    /// [`Cx`]. Handlers can extract [`crate::web::StreamingRawBody`] or use an
    /// asynchronous body collector. Synchronous buffered extractors refuse a
    /// live body. To apply static route limits before allocating a body or
    /// request region, use [`Self::into_http2_streaming_parts`].
    #[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
    #[must_use]
    pub fn into_http2_streaming_handler(
        self,
    ) -> impl Fn(StreamingServerRequest) -> HttpHandlerFuture + Clone + Send + Sync + 'static {
        let router = Arc::new(self);
        move |request| {
            let router = Arc::clone(&router);
            Box::pin(async move {
                let Some(cx) = Cx::current() else {
                    return http_response_from_web(http1_stream_refusal_response(
                        "request context unavailable",
                    ));
                };
                router
                    .handle_http2_streaming_request_with_cx(&cx, request)
                    .await
            })
        }
    }

    /// Bind static route admission and live-body dispatch to the same router.
    ///
    /// Pass the returned handler and configuration to
    /// [`crate::http::h2::listener::Http2Listener::bind_streaming_with_config`].
    /// Static body limits are resolved at HEADERS using ordinary route and
    /// nested-mount precedence, before the listener creates a request region.
    /// Request-local middleware may tighten the limit during dispatch.
    #[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
    #[must_use]
    pub fn into_http2_streaming_parts(
        self,
        config: Http2StreamingListenerConfig,
    ) -> (
        impl Fn(StreamingServerRequest) -> HttpHandlerFuture + Clone + Send + Sync + 'static,
        Http2StreamingListenerConfig,
    ) {
        let router = Arc::new(self);
        let admission = Arc::clone(&router);
        let config = config
            .with_request_body_policy(move |head| admission.http2_streaming_body_policy(head));
        let handler = move |request| -> HttpHandlerFuture {
            let router = Arc::clone(&router);
            Box::pin(async move {
                let Some(cx) = Cx::current() else {
                    return http_response_from_web(http1_stream_refusal_response(
                        "request context unavailable",
                    ));
                };
                router
                    .handle_http2_streaming_request_with_cx(&cx, request)
                    .await
            })
        };
        (handler, config)
    }

    /// Resolve a validated HTTP/2 request head's static route body limit.
    ///
    /// This runs no handler or middleware and creates no live body. `None`
    /// leaves the listener's total body ceiling in force. The listener is
    /// responsible for validating protocol headers and enforcing declared
    /// lengths against the returned ceiling before admission.
    #[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
    pub fn http2_streaming_body_policy(
        &self,
        head: &RequestHead,
    ) -> Result<Option<u64>, HttpResponse> {
        let (path, _) = split_http_request_target(&head.uri);
        let request = Request::new(head.method.as_str(), path);
        self.streaming_body_policy_limit(&request)
            .map(|limit| limit.map(|bytes| bytes as u64))
            .map_err(http_response_from_web)
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

    /// Dispatch a live HTTP/2 request with the listener's actual request Cx.
    ///
    /// The body remains in the private one-shot extractor slot throughout
    /// dispatch. An unclaimed body is dropped when dispatch ends, including
    /// when middleware retains a clone of the compatibility request.
    #[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
    pub async fn handle_http2_streaming_request_with_cx(
        &self,
        cx: &Cx,
        request: StreamingServerRequest,
    ) -> HttpResponse {
        let Some((request, _body_control)) = web_request_from_streaming_http(request) else {
            return http_response_from_web(http1_stream_refusal_response(
                "streaming request body slot collision",
            ));
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

    #[cfg(all(feature = "http3", feature = "tls", not(target_arch = "wasm32")))]
    fn h3_streaming_body_policy_limit(
        &self,
        request: &Request,
    ) -> Result<Option<usize>, NativeH3RouterRefusal> {
        self.streaming_body_policy_limit(request).map_err(|_| {
            NativeH3RouterRefusal::InvalidRequestProgression(
                "HTTP/3 static body policy admission failed",
            )
        })
    }

    /// Resolve static body policy for HEADERS-only admission. Run the
    /// ordinary policy merger on an empty, header-free probe, following the
    /// exact route/nest precedence used by dispatch. No handler, request body,
    /// request region, or request-local middleware is created in this phase.
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
    ))]
    fn streaming_body_policy_limit(&self, request: &Request) -> Result<Option<usize>, Response> {
        fn extend_policy_extensions(target: &mut Extensions, source: &Extensions) {
            // Carry only policy types: copying unrelated extensions could
            // retain a body slot or another application's live resource.
            if let Some(value) = source.get_typed_cloned::<BodyLimits>() {
                target.insert_typed(value);
            }
            if let Some(value) = source.get_typed_cloned::<MultipartLimits>() {
                target.insert_typed(value);
            }
            if let Some(value) = source.get_typed_cloned::<RequestBodyPolicy>() {
                target.insert_typed(value);
            }
            if let Some(value) = source.get_typed_cloned::<RequestBodyPolicyState>() {
                target.insert_typed(value);
            }
        }

        fn apply_probe_policy(
            probe: &mut Request,
            inherited: Option<RequestBodyPolicyState>,
            local: Option<RequestBodyPolicyState>,
        ) -> Result<(), Response> {
            // With no body or Content-Length this should always succeed, even
            // at a zero-byte ceiling. Preserve a fail-closed boundary if the
            // shared policy implementation gains another admission check.
            apply_request_body_policy(probe, inherited, local)
        }

        let mut probe = Request::new(request.method.clone(), request.path.clone());
        extend_policy_extensions(&mut probe.extensions, &request.extensions);
        let mut router = self;
        loop {
            let inherited = explicit_policy_state_from_extensions(&probe.extensions);
            let extension_policy = explicit_policy_state_from_extensions(&router.extensions);
            extend_policy_extensions(&mut probe.extensions, &router.extensions);
            let local = meet_optional_policy_state(
                extension_policy,
                meet_optional_policy_state(
                    router
                        .server_body_policy
                        .map(RequestBodyPolicyState::from_policy),
                    router.body_policy.map(RequestBodyPolicyState::from_policy),
                ),
            );
            apply_probe_policy(&mut probe, inherited, local)?;

            // Admission selects exactly what dispatch will (`Self::select`).
            match router.select(&probe.path) {
                Some(RouteSelection::Route(method_router, _)) => {
                    // MethodRouter applies this before method lookup, including a
                    // 405 response. Admission must select the same policy.
                    apply_probe_policy(
                        &mut probe,
                        None,
                        method_router
                            .body_policy
                            .map(RequestBodyPolicyState::from_policy),
                    )?;
                    break;
                }
                Some(RouteSelection::Mount(nested, path)) => {
                    router = nested;
                    probe.path = path;
                }
                // The selected router's fallback/404 uses its inherited
                // policy; it does not retry a shorter mount or outer fallback.
                None => break,
            }
        }
        Ok(explicit_policy_state_from_extensions(&probe.extensions)
            .map(|state| state.resolved().max_total_body_size))
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

        match self.select(&req.path) {
            Some(RouteSelection::Route(method_router, params)) => {
                req.path_params = params;
                return method_router.dispatch(cx, req).await;
            }
            Some(RouteSelection::Mount(router, sub_path)) => {
                req.path = sub_path;
                // Nested routers dispatch without re-tracing: the outermost
                // router already instruments the exchange.
                return Box::pin(router.handle_inner(cx, req)).await;
            }
            None => {}
        }

        // Fallback.
        if let Some(handler) = &self.fallback {
            return handler.call(cx, req).await;
        }

        StatusCode::NOT_FOUND.into_response()
    }

    /// Choose where `path` goes: the most specific of this router's routes, or
    /// else its longest matching mount.
    ///
    /// With [`Self::prefer_specific_mounts`], the mount wins when what it
    /// resolves is more specific than the route: it counts its prefix's
    /// literal segments in front of the route its router matches (or,
    /// matching none, acts like a `prefix/*` route). First-registered only
    /// wins among equal-specificity routes, and a route wins a tie with a
    /// mount.
    fn select(&self, path: &str) -> Option<RouteSelection<'_>> {
        match (self.best_route(path), self.best_mount(path)) {
            (Some((route, method_router, params)), Some((segments, router, sub_path))) => {
                if self.prefer_specific_mounts
                    && Self::mount_specificity(router, segments, &sub_path) > route
                {
                    Some(RouteSelection::Mount(router, sub_path))
                } else {
                    Some(RouteSelection::Route(method_router, params))
                }
            }
            (Some((_, method_router, params)), None) => {
                Some(RouteSelection::Route(method_router, params))
            }
            (None, Some((_, router, sub_path))) => Some(RouteSelection::Mount(router, sub_path)),
            (None, None) => None,
        }
    }

    /// The specificity of whatever this router (and its mounts) resolves
    /// `path` to, following [`Self::select`]; `UNRESOLVED` when only a
    /// fallback or 404 would answer.
    fn resolved_specificity(&self, path: &str) -> RouteSpecificity {
        let route = self.best_route(path).map(|(specificity, _, _)| specificity);
        if route.is_some() && !self.prefer_specific_mounts {
            return route.unwrap_or(RouteSpecificity::UNRESOLVED);
        }
        let mount = self.best_mount(path).map(|(segments, router, sub_path)| {
            Self::mount_specificity(router, segments, &sub_path)
        });
        route.max(mount).unwrap_or(RouteSpecificity::UNRESOLVED)
    }

    /// What a mount resolves `sub_path` to, seen from this router: what its
    /// router resolves, under the mount's prefix. A request for the prefix
    /// itself (`sub_path` "/") that the mounted router does not route still
    /// names that prefix exactly, so it counts as an exact route of the
    /// prefix: `/:page` does not take `/admin` from `.nest("/admin", ..)`, and
    /// an explicit `/admin` route still wins the tie (br-asupersync-x4kh5w
    /// finding 4).
    fn mount_specificity(
        router: &Self,
        prefix_segments: usize,
        sub_path: &str,
    ) -> RouteSpecificity {
        let resolved = router.resolved_specificity(sub_path);
        if resolved == RouteSpecificity::UNRESOLVED && sub_path == "/" && prefix_segments > 0 {
            return RouteSpecificity {
                exact_path: true,
                ..RouteSpecificity::UNRESOLVED
            }
            .under_mount(prefix_segments);
        }
        resolved.under_mount(prefix_segments)
    }

    /// The most specific matching route; the first registered among equals.
    fn best_route(
        &self,
        path: &str,
    ) -> Option<(RouteSpecificity, &MethodRouter, HashMap<String, String>)> {
        let mut best: Option<(RouteSpecificity, &MethodRouter, HashMap<String, String>)> = None;
        for (pattern, method_router) in &self.routes {
            if let Some(route_match) = pattern.matches(path) {
                match &best {
                    Some((specificity, _, _)) if *specificity >= route_match.specificity => {}
                    _ => best = Some((route_match.specificity, method_router, route_match.params)),
                }
            }
        }
        best
    }

    /// The longest matching mount: its prefix's segment count, its router and
    /// the rest of the path.
    fn best_mount(&self, path: &str) -> Option<(usize, &Self, String)> {
        let mut best: Option<(usize, &str, &Self, String)> = None;
        for (prefix, router) in &self.nested {
            if let Some(sub_path) = strip_prefix(path, prefix) {
                let length = prefix.trim_end_matches('/').len();
                match &best {
                    Some((best_length, _, _, _)) if *best_length >= length => {}
                    _ => best = Some((length, prefix, router, sub_path)),
                }
            }
        }
        best.map(|(_, prefix, router, sub_path)| {
            let segments = prefix.split('/').filter(|s| !s.is_empty()).count();
            (segments, router, sub_path)
        })
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

/// Copies validated wire header fields into the extractor request's
/// single-valued header map.
///
/// A repeated field keeps its last value, the builder's existing rule, except
/// `cookie`: HTTP/2 and HTTP/3 clients may send each cookie as its own field
/// (RFC 9113 §8.2.3, RFC 9114 §4.2.1), and those sections require the pieces
/// to be joined with "; " before the request reaches an application. Keeping
/// only the last piece dropped every other cookie, the session cookie
/// included, so a logged-in user looked logged out (br-asupersync-a1q12q).
/// Protocol validation (Host, Content-Length, transfer coding, etc.) remains
/// the listener's job and runs before this.
fn insert_wire_headers(request: &mut Request, headers: Vec<(String, String)>) {
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        if name == "cookie"
            && let Some(joined) = request.headers.get_mut("cookie")
        {
            joined.push_str("; ");
            joined.push_str(&value);
            continue;
        }
        request.headers.insert(name, value);
    }
}

/// Translate the completed wire request shared by the HTTP/1.1 and HTTP/2
/// listeners into the web framework's extractor request.
fn web_request_from_http(request: HttpRequest) -> Request {
    let (path, query) = split_http_request_target(&request.uri);
    let mut web_request = Request::new(request.method.as_str(), path);
    web_request.query = query;
    web_request.body = request.body.into();
    insert_wire_headers(&mut web_request, request.headers);
    web_request
}

#[cfg(not(target_arch = "wasm32"))]
fn web_request_from_streaming_http(
    request: StreamingServerRequest,
) -> Option<(Request, StreamingRawBodyControl)> {
    let (path, query) = split_http_request_target(&request.head.uri);
    let mut web_request = Request::new(request.head.method.as_str(), path);
    web_request.query = query;
    insert_wire_headers(&mut web_request, request.head.headers);

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
    // not send an explicit Host field. Repeated fields follow
    // insert_wire_headers (last value wins, Cookie pieces are joined).
    if let Some(authority) = head.pseudo.authority
        && !head
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        request.headers.insert("host".to_string(), authority);
    }
    insert_wire_headers(&mut request, head.headers);
    request
}

/// The RFC 9114 reset code for a refused request. Load and lifecycle
/// refusals come before any handler runs, so H3_REQUEST_REJECTED tells the
/// client a retry is safe (section 4.1.1). A malformed request is
/// H3_MESSAGE_ERROR (section 4.1.2). Anything else, including a request a
/// handler may have seen or that would fail again, is H3_REQUEST_CANCELLED.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn refusal_reset_code(reason: &NativeH3RouterRefusal) -> u64 {
    use crate::http::h3_quic::{H3_REQUEST_CANCELLED, H3_REQUEST_REJECTED};
    const H3_MESSAGE_ERROR: u64 = 0x010e;
    match reason {
        NativeH3RouterRefusal::TooManyPendingRequests { .. }
        | NativeH3RouterRefusal::TooManyInFlightDispatches { .. }
        | NativeH3RouterRefusal::ConnectionBodyBudgetExhausted { .. }
        | NativeH3RouterRefusal::Draining
        | NativeH3RouterRefusal::ConnectionRetiring
        | NativeH3RouterRefusal::TooManyConcurrentRequests { .. } => H3_REQUEST_REJECTED,
        NativeH3RouterRefusal::InvalidContentLength
        | NativeH3RouterRefusal::InvalidTransferEncoding
        | NativeH3RouterRefusal::InvalidAuthority => H3_MESSAGE_ERROR,
        NativeH3RouterRefusal::ConnectUnsupported
        | NativeH3RouterRefusal::RequestTrailersUnsupported
        | NativeH3RouterRefusal::RequestBodyTooLarge { .. }
        | NativeH3RouterRefusal::DispatchCancelled
        | NativeH3RouterRefusal::RequestAssemblyTimeout
        | NativeH3RouterRefusal::InvalidRequestProgression(_)
        | NativeH3RouterRefusal::InvalidResponse(_) => H3_REQUEST_CANCELLED,
    }
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn validate_h3_request_head_semantics(
    head: &H3RequestHead,
) -> Result<Option<usize>, NativeH3RouterRefusal> {
    let mut content_length = None;
    let mut host = None;
    for (name, value) in &head.headers {
        if name == "host" {
            // One non-empty Host at most: the handler sees a single value, so
            // a repeated field would let a later copy override the checked one.
            if value.is_empty() || host.replace(value.as_str()).is_some() {
                return Err(NativeH3RouterRefusal::InvalidAuthority);
            }
        } else if name == "content-length" {
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
    // Host takes precedence over :authority for the handler, so a mismatch
    // would let it route on a target that TLS SNI or an upstream check never
    // saw. Host names compare case-insensitively.
    let consistent = match (head.pseudo.authority.as_deref(), host) {
        (Some(authority), Some(host)) => authority.eq_ignore_ascii_case(host),
        (None, None) => !matches!(head.pseudo.scheme.as_deref(), Some("http" | "https")),
        _ => true,
    };
    if !consistent {
        return Err(NativeH3RouterRefusal::InvalidAuthority);
    }
    Ok(content_length)
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
fn validate_h3_request_semantics(
    head: &H3RequestHead,
    body_len: usize,
) -> Result<(), NativeH3RouterRefusal> {
    let content_length = validate_h3_request_head_semantics(head)?;
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
    let duration_refused = safe.duration_header.as_deref().is_some_and(transport_owned);
    if duration_refused {
        safe.duration_header = None;
    }
    let trace_refused = safe.trace_header.as_deref().is_some_and(transport_owned);
    if trace_refused {
        safe.trace_header = None;
    }
    let refused = duration_refused || trace_refused;
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
    let duration_refused = safe.duration_header.as_deref().is_some_and(transport_owned);
    if duration_refused {
        safe.duration_header = None;
    }
    let trace_refused = safe.trace_header.as_deref().is_some_and(transport_owned);
    if trace_refused {
        safe.trace_header = None;
    }
    let refused = duration_refused || trace_refused;
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

fn normalize_nest_prefix(prefix: &str) -> String {
    if prefix.is_empty() || prefix == "/" {
        "/".to_string()
    } else if prefix.starts_with('/') {
        prefix.to_string()
    } else {
        format!("/{prefix}")
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
    let trimmed = prefix.trim_end_matches('/');
    let normalized_prefix_buf;
    let normalized_prefix = if trimmed.starts_with('/') {
        trimmed
    } else {
        normalized_prefix_buf = format!("/{trimmed}");
        &normalized_prefix_buf
    };

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
#[path = "router_inline_tests.rs"]
mod tests;
