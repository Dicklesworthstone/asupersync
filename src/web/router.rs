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

use super::extract::Request;
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
            handlers: HashMap::new(),
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
        let path_segments: SmallVec<[&str; 8]> = path.split('/').filter(|s| !s.is_empty()).collect();

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

        let mut params = HashMap::new();

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
}

impl Router {
    /// Create a new empty router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            nested: Vec::new(),
            fallback: None,
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

    /// Handle an incoming request.
    ///
    /// Routes are checked in registration order. Nested routers are checked
    /// after top-level routes.
    #[must_use]
    pub fn handle(&self, mut req: Request) -> Response {
        // Check top-level routes.
        for (pattern, method_router) in &self.routes {
            if let Some(params) = pattern.matches(&req.path) {
                req.path_params = params;
                return method_router.dispatch(req);
            }
        }

        // Check nested routers.
        for (prefix, router) in &self.nested {
            if let Some(sub_path) = strip_prefix(&req.path, prefix) {
                req.path = sub_path;
                return router.handle(req);
            }
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
    fn nested_router_trailing_slash_prefix() {
        let api = Router::new().route("/users", get(FnHandler::new(ok_handler)));

        let app = Router::new().nest("/api/v1/", api);

        let resp = app.handle(Request::new("GET", "/api/v1/users/"));
        assert_eq!(resp.status, StatusCode::OK);
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
