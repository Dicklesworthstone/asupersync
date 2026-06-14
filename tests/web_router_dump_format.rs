//! Golden snapshot test for web router route table dump format.
//!
//! Tests the textual representation of routing tables with nested routers,
//! middleware patterns, and parameter extraction to ensure stable ordering
//! and consistent formatting.

use asupersync::web::handler::FnHandler;
use asupersync::web::response::StatusCode;
use asupersync::web::router::{RouteInfo, Router};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

#[test]
fn web_router_route_table_dump_format_comprehensive() {
    let router = build_comprehensive_router();
    let dump = generate_router_dump(&router);
    insta::assert_snapshot!("web_router_route_table_dump_format_comprehensive", dump);
}

/// Build a comprehensive router with various patterns for testing
fn build_comprehensive_router() -> Router {
    use asupersync::web::router::{get, post, put};

    // Create sub-routers for nesting
    let api_v1_routes = Router::new()
        .route("/users", get(FnHandler::new(|| StatusCode::OK)))
        .route("/users/:id", get(FnHandler::new(|| StatusCode::OK)))
        .route("/users/:id/posts", get(FnHandler::new(|| StatusCode::OK)))
        .route(
            "/users/:id/posts/:post_id",
            get(FnHandler::new(|| StatusCode::OK)),
        )
        .route("/users/:id/profile", put(FnHandler::new(|| StatusCode::OK)))
        .route("/search", get(FnHandler::new(|| StatusCode::OK)));

    let admin_routes = Router::new()
        .route("/dashboard", get(FnHandler::new(|| StatusCode::OK)))
        .route("/users", get(FnHandler::new(|| StatusCode::OK)))
        .route("/users/:id/ban", post(FnHandler::new(|| StatusCode::OK)))
        .route("/config", get(FnHandler::new(|| StatusCode::OK)))
        .route("/config/:section", put(FnHandler::new(|| StatusCode::OK)));

    let health_routes = Router::new()
        .route("/ping", get(FnHandler::new(|| StatusCode::OK)))
        .route("/ready", get(FnHandler::new(|| StatusCode::OK)))
        .route("/metrics", get(FnHandler::new(|| StatusCode::OK)));

    // Create main router with various patterns
    Router::new()
        // Root routes
        .route("/", get(FnHandler::new(|| StatusCode::OK)))
        .route("/favicon.ico", get(FnHandler::new(|| StatusCode::OK)))
        // Static file patterns
        .route("/static/*", get(FnHandler::new(|| StatusCode::OK)))
        .route("/assets/css/:file", get(FnHandler::new(|| StatusCode::OK)))
        .route("/assets/js/:file", get(FnHandler::new(|| StatusCode::OK)))
        // Authentication routes
        .route(
            "/login",
            get(FnHandler::new(|| StatusCode::OK)).post(FnHandler::new(|| StatusCode::OK)),
        )
        .route("/logout", post(FnHandler::new(|| StatusCode::OK)))
        .route(
            "/register",
            get(FnHandler::new(|| StatusCode::OK)).post(FnHandler::new(|| StatusCode::OK)),
        )
        // Content routes with parameters
        .route("/blog", get(FnHandler::new(|| StatusCode::OK)))
        .route("/blog/:slug", get(FnHandler::new(|| StatusCode::OK)))
        .route(
            "/blog/:year/:month/:day/:slug",
            get(FnHandler::new(|| StatusCode::OK)),
        )
        .route(
            "/categories/:category",
            get(FnHandler::new(|| StatusCode::OK)),
        )
        .route("/tags/:tag", get(FnHandler::new(|| StatusCode::OK)))
        // RESTful resource patterns
        .route(
            "/posts",
            get(FnHandler::new(|| StatusCode::OK)).post(FnHandler::new(|| StatusCode::OK)),
        )
        .route(
            "/posts/:id",
            get(FnHandler::new(|| StatusCode::OK))
                .put(FnHandler::new(|| StatusCode::OK))
                .delete(FnHandler::new(|| StatusCode::OK)),
        )
        .route(
            "/posts/:id/comments",
            get(FnHandler::new(|| StatusCode::OK)).post(FnHandler::new(|| StatusCode::OK)),
        )
        .route(
            "/posts/:id/comments/:comment_id",
            get(FnHandler::new(|| StatusCode::OK))
                .put(FnHandler::new(|| StatusCode::OK))
                .delete(FnHandler::new(|| StatusCode::OK)),
        )
        // Form submission routes
        .route(
            "/contact",
            get(FnHandler::new(|| StatusCode::OK)).post(FnHandler::new(|| StatusCode::OK)),
        )
        .route(
            "/newsletter/subscribe",
            post(FnHandler::new(|| StatusCode::OK)),
        )
        .route(
            "/newsletter/unsubscribe",
            post(FnHandler::new(|| StatusCode::OK)),
        )
        // File upload/download patterns
        .route("/upload", post(FnHandler::new(|| StatusCode::OK)))
        .route("/download/:file_id", get(FnHandler::new(|| StatusCode::OK)))
        .route(
            "/files/:bucket/:key",
            get(FnHandler::new(|| StatusCode::OK)).delete(FnHandler::new(|| StatusCode::OK)),
        )
        // WebSocket upgrade endpoints
        .route("/ws", get(FnHandler::new(|| StatusCode::OK)))
        .route("/ws/chat/:room", get(FnHandler::new(|| StatusCode::OK)))
        .route(
            "/ws/notifications/:user_id",
            get(FnHandler::new(|| StatusCode::OK)),
        )
        // Nested sub-applications
        .nest("/api/v1", api_v1_routes)
        .nest("/admin", admin_routes)
        .nest("/health", health_routes)
        // Fallback handler
        .fallback(FnHandler::new(|| StatusCode::NOT_FOUND))
}

/// Generate a textual dump of the router structure with stable ordering
fn generate_router_dump(router: &Router) -> String {
    let mut output = String::new();

    writeln!(&mut output, "=== Web Router Route Table Dump ===").unwrap();
    writeln!(&mut output).unwrap();

    // Analyze and dump router structure
    let analysis = analyze_router_structure(router);

    writeln!(&mut output, "Summary:").unwrap();
    writeln!(
        &mut output,
        "  Total route entries: {}",
        analysis.total_route_entries
    )
    .unwrap();
    writeln!(
        &mut output,
        "  Direct route entries: {}",
        analysis.direct_route_entries
    )
    .unwrap();
    writeln!(
        &mut output,
        "  Nested route entries: {}",
        analysis.nested_route_entries
    )
    .unwrap();
    writeln!(
        &mut output,
        "  Direct route patterns: {}",
        analysis.direct_route_patterns
    )
    .unwrap();
    writeln!(&mut output, "  Nested routers: {}", analysis.nested_routers).unwrap();
    writeln!(
        &mut output,
        "  Parameter route entries: {}",
        analysis.parameter_route_entries
    )
    .unwrap();
    writeln!(
        &mut output,
        "  Wildcard route entries: {}",
        analysis.wildcard_route_entries
    )
    .unwrap();
    writeln!(&mut output, "  Has fallback: {}", analysis.has_fallback).unwrap();
    writeln!(&mut output).unwrap();

    writeln!(&mut output, "Routes by HTTP Method:").unwrap();
    for (method, count) in &analysis.methods_count {
        writeln!(&mut output, "  {}: {} route entries", method, count).unwrap();
    }
    writeln!(&mut output).unwrap();

    writeln!(&mut output, "Route Entries (stable sort):").unwrap();
    dump_router_routes(&mut output, router);

    writeln!(&mut output).unwrap();
    writeln!(&mut output, "Parameter Extraction Patterns:").unwrap();
    for pattern in &analysis.parameter_patterns {
        writeln!(&mut output, "  {}", pattern).unwrap();
    }

    writeln!(&mut output).unwrap();
    writeln!(&mut output, "Nested Router Structure:").unwrap();
    dump_nested_structure(&mut output, router);

    output
}

/// Analyze router structure for summary statistics.
fn analyze_router_structure(router: &Router) -> RouterAnalysis {
    let routes = router.routes();
    let mut analysis = RouterAnalysis {
        total_route_entries: routes.len(),
        direct_route_entries: routes
            .iter()
            .filter(|route| route.mount_prefix.is_none())
            .count(),
        nested_route_entries: routes
            .iter()
            .filter(|route| route.mount_prefix.is_some())
            .count(),
        direct_route_patterns: router.route_count(),
        nested_routers: router.nested_router_count(),
        parameter_route_entries: 0,
        wildcard_route_entries: 0,
        has_fallback: router.has_fallback(),
        methods_count: BTreeMap::new(),
        parameter_patterns: BTreeSet::new(),
    };

    for route in routes {
        if route.pattern.contains(':') {
            analysis.parameter_route_entries += 1;
            analysis
                .parameter_patterns
                .insert(extract_parameter_pattern(&route.pattern));
        }
        if route.pattern.contains('*') {
            analysis.wildcard_route_entries += 1;
        }

        *analysis.methods_count.entry(route.method).or_insert(0) += 1;
    }

    analysis
}

/// Dump router routes with stable ordering.
fn dump_router_routes(output: &mut String, router: &Router) {
    for route in router.routes() {
        let mount = route.mount_prefix.as_deref().unwrap_or("-");
        writeln!(
            output,
            "  [{}] {} -> {} (mount: {})",
            route.method, route.pattern, route.handler_name, mount
        )
        .unwrap();
    }
}

/// Dump nested router structure from route metadata.
fn dump_nested_structure(output: &mut String, router: &Router) {
    let mut nested: BTreeMap<String, Vec<RouteInfo>> = BTreeMap::new();

    for route in router.routes() {
        if let Some(prefix) = &route.mount_prefix {
            nested.entry(prefix.clone()).or_default().push(route);
        }
    }

    for (prefix, routes) in nested {
        writeln!(output, "{} -> {} route entries", prefix, routes.len()).unwrap();
        for route in routes {
            writeln!(output, "  [{}] {}", route.method, route.pattern).unwrap();
        }
    }
}

/// Extract parameter pattern from route
fn extract_parameter_pattern(pattern: &str) -> String {
    let params: Vec<&str> = pattern
        .split('/')
        .filter(|segment| segment.starts_with(':'))
        .collect();
    format!("params[{}]: {}", params.len(), params.join(", "))
}

/// Router analysis structure
#[derive(Debug)]
struct RouterAnalysis {
    total_route_entries: usize,
    direct_route_entries: usize,
    nested_route_entries: usize,
    direct_route_patterns: usize,
    nested_routers: usize,
    parameter_route_entries: usize,
    wildcard_route_entries: usize,
    has_fallback: bool,
    methods_count: BTreeMap<String, usize>,
    parameter_patterns: BTreeSet<String>,
}
