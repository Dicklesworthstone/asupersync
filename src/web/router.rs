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

use super::extract::{Extensions, Request};
use super::handler::Handler;
use super::response::{IntoResponse, Response, StatusCode};
use crate::Cx;
use crate::types::{
    Budget,
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

// ─── MethodRouter ────────────────────────────────────────────────────────────

/// A set of handlers for different HTTP methods on a single route.
pub struct MethodRouter {
    handlers: HashMap<String, Box<dyn Handler>>,
}

impl MethodRouter {
    /// Create an empty method router.
    fn new() -> Self {
        Self {
            handlers: HashMap::with_capacity(4),
        }
    }

    /// Add a handler for a specific method.
    fn on(mut self, method: &str, handler: impl Handler) -> Self {
        self.handlers
            .insert(method.to_uppercase(), Box::new(handler));
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
            None => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        }
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
#[derive(Default)]
pub struct Router {
    routes: Vec<(RoutePattern, MethodRouter)>,
    nested: Vec<(String, Self)>,
    fallback: Option<Box<dyn Handler>>,
    extensions: Extensions,
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
    #[must_use]
    pub async fn handle_with_cx(&self, cx: &Cx, mut req: Request) -> Response {
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
            return Box::pin(router.handle_with_cx(cx, req)).await;
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
}
