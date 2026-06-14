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

use smallvec::SmallVec;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::extract::{Extensions, Request};
use super::handler::Handler;
use super::middleware::{
    RequestLogSink, RequestTracePolicy, resolve_trace_id, trace_request, wall_clock_now,
};
use super::response::{IntoResponse, Response, StatusCode};
use crate::Cx;
use crate::service::Layer;
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

// ─── MethodRouter ────────────────────────────────────────────────────────────

/// A set of handlers for different HTTP methods on a single route.
pub struct MethodRouter {
    handlers: HashMap<String, Box<dyn Handler>>,
    method_not_allowed: Box<dyn Handler>,
}

impl MethodRouter {
    /// Create an empty method router.
    fn new() -> Self {
        Self {
            handlers: HashMap::with_capacity(4),
            method_not_allowed: Box::new(MethodNotAllowedHandler::new(String::new())),
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
    async fn dispatch(&self, cx: &Cx, req: Request) -> Response {
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
    default_trace: Option<DefaultTrace>,
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
        req.extensions.extend_from(&self.extensions);

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
    use crate::web::handler::FnHandler;

    fn ok_handler() -> &'static str {
        "ok"
    }

    fn not_found_handler() -> StatusCode {
        StatusCode::NOT_FOUND
    }

    fn created_handler() -> StatusCode {
        StatusCode::CREATED
    }

    #[test]
    fn route_exact_match() {
        let router = Router::new().route("/", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("GET", "/"));
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn route_not_found() {
        let router = Router::new().route("/", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("GET", "/missing"));
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
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
