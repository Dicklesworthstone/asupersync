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
    fn dispatch(&self, req: Request) -> Response {
        // Fast path: method is already uppercase (true for virtually all HTTP traffic).
        if let Some(handler) = self.handlers.get(&req.method) {
            return handler.call(req);
        }
        // Slow path: case-insensitive fallback (allocates only if needed).
        let upper = req.method.to_uppercase();
        self.handlers.get(&upper).map_or_else(
            || StatusCode::METHOD_NOT_ALLOWED.into_response(),
            |handler| handler.call(req),
        )
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
    fn matches(&self, path: &str) -> Option<HashMap<String, String>> {
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
                    return Some(params);
                }
            }
        }

        Some(params)
    }
}

// ─── Router ──────────────────────────────────────────────────────────────────

/// HTTP request router.
///
/// Routes are matched in the order they are registered. The first matching
/// route handles the request.
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
}

impl Router {
    /// Create a new empty router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            nested: Vec::new(),
            fallback: None,
            extensions: Extensions::new(),
        }
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
    /// Routes are checked in registration order. Nested routers are checked
    /// after top-level routes.
    #[must_use]
    pub fn handle(&self, mut req: Request) -> Response {
        req.extensions.extend_from(&self.extensions);

        // Check top-level routes.
        for (pattern, method_router) in &self.routes {
            if let Some(params) = pattern.matches(&req.path) {
                req.path_params = params;
                return method_router.dispatch(req);
            }
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
            return router.handle(req);
        }

        // Fallback.
        if let Some(handler) = &self.fallback {
            return handler.call(req);
        }

        StatusCode::NOT_FOUND.into_response()
    }

    /// Return the number of registered routes (not counting nested).
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

/// Strip a prefix from a path, returning the remainder.
fn strip_prefix(path: &str, prefix: &str) -> Option<String> {
    let normalized_prefix = prefix.trim_end_matches('/');
    let normalized_path = if path.is_empty() { "/" } else { path };

    if normalized_path == normalized_prefix {
        return Some("/".to_string());
    }

    normalized_path
        .strip_prefix(normalized_prefix)
        .and_then(|rest| {
            if rest.starts_with('/') || rest.is_empty() {
                Some(if rest.is_empty() {
                    "/".to_string()
                } else {
                    rest.to_string()
                })
            } else {
                None
            }
        })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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
        assert_eq!(resp.status, StatusCode::CREATED);
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
    fn route_priority_wildcard_before_literal() {
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
                >::new(wildcard_handler)),
            )
            .route("/files/static", get(FnHandler::new(ok_handler)));

        let resp = router.handle(Request::new("GET", "/files/static"));
        assert_eq!(resp.status, StatusCode::ACCEPTED);
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
        let params = pattern.matches("/users/42").unwrap();
        assert_eq!(params.get("id").unwrap(), "42");

        assert!(pattern.matches("/users").is_none());
        assert!(pattern.matches("/users/42/extra").is_none());
    }

    #[test]
    fn route_pattern_multiple_params() {
        let pattern = RoutePattern::parse("/users/:uid/posts/:pid");
        let params = pattern.matches("/users/1/posts/99").unwrap();
        assert_eq!(params.get("uid").unwrap(), "1");
        assert_eq!(params.get("pid").unwrap(), "99");
    }

    #[test]
    fn route_pattern_wildcard() {
        let pattern = RoutePattern::parse("/files/*");
        let params = pattern.matches("/files/a/b/c").unwrap();
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
        assert!(strip_prefix("/other", "/api/v1").is_none());
    }

    #[test]
    fn strip_prefix_boundary_mismatch() {
        assert!(strip_prefix("/apix/users", "/api").is_none());
        assert!(strip_prefix("/apiary", "/api").is_none());
    }
}
