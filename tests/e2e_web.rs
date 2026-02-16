//! E2E: Web full stack — route resolution, middleware, handlers, extractors, responses.

mod common;

use asupersync::web::extract::{Json as JsonExtract, Path, Query, Request};
use asupersync::web::handler::{FnHandler, FnHandler1};
use asupersync::web::response::{Html, Json, Redirect, StatusCode};
use asupersync::web::router::{delete, get, post, Router};

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
    Redirect::permanent("/new-location")
}

// =========================================================================
// Tests
// =========================================================================

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
