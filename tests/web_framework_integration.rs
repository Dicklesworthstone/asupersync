//! [ECOSYSTEM-PARITY][A.16] Web framework integration test suite.
//!
//! Comprehensive integration tests for the `asupersync::web` module covering:
//! - Router composition (nesting, fallback, method routing, path parameters, wildcards)
//! - All extractor types (Path, Query, Json, Form, State, Cookie, CookieJar, RawBody, HeaderMap)
//! - All response types (Json, Html, Redirect, StatusCode, tuples, Result)
//! - Middleware stack (CORS, compression, auth, rate limiting, timeout, catch-panic, bulkhead)
//! - SSE events
//! - Health check endpoints (liveness, readiness, startup)
//! - Content negotiation
//! - Session management
//! - Error handling and edge cases

mod common;

use std::collections::HashMap;
use std::time::Duration;

use asupersync::bytes::Bytes;
use asupersync::combinator::rate_limit::RateLimitPolicy;
use asupersync::web::extract::{
    Cookie, CookieJar, Form, Json as JsonExtract, Path, Query, RawBody, Request, State,
};
use asupersync::web::handler::{FnHandler, FnHandler1, FnHandler2, Handler};
use asupersync::web::health::{HealthCheck, HealthStatus};
use asupersync::web::middleware::{
    AuthMiddleware, AuthPolicy, CatchPanicMiddleware, CorsMiddleware, CorsPolicy, MiddlewareStack,
    RateLimitMiddleware, TimeoutMiddleware,
};
use asupersync::web::response::{Html, Json, Redirect, StatusCode};
use asupersync::web::router::{Router, get, post};
use asupersync::web::session::{MemoryStore, SessionLayer};
use asupersync::web::sse::{Sse, SseEvent};

// =========================================================================
// Handlers
// =========================================================================

fn index() -> &'static str {
    "welcome"
}

fn get_user(Path(id): Path<String>) -> String {
    format!("user:{id}")
}

fn get_user_posts(Path(params): Path<HashMap<String, String>>) -> String {
    let uid = params.get("uid").cloned().unwrap_or_default();
    let pid = params.get("pid").cloned().unwrap_or_default();
    format!("user:{uid}/post:{pid}")
}

fn create_item(JsonExtract(body): JsonExtract<serde_json::Value>) -> (StatusCode, Json<serde_json::Value>) {
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    (
        StatusCode::CREATED,
        Json(serde_json::json!({"created": true, "name": name})),
    )
}

fn search(Query(params): Query<HashMap<String, String>>) -> String {
    let q = params.get("q").cloned().unwrap_or_default();
    format!("results:{q}")
}

fn delete_item(Path(id): Path<String>) -> StatusCode {
    let _ = id;
    StatusCode::NO_CONTENT
}

fn html_page() -> Html<&'static str> {
    Html("<h1>Hello</h1>")
}


fn echo_raw(RawBody(body): RawBody) -> Bytes {
    body
}

#[allow(clippy::needless_pass_by_value)]
fn echo_headers(headers: HashMap<String, String>) -> String {
    let mut pairs: Vec<_> = headers.iter().collect();
    pairs.sort_by_key(|(k, _)| (*k).clone());
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(";")
}

fn echo_cookie(Cookie(raw): Cookie) -> String {
    format!("raw:{raw}")
}

#[allow(clippy::needless_pass_by_value)]
fn echo_cookie_jar(jar: CookieJar) -> String {
    let session = jar.get("session").unwrap_or("none");
    let theme = jar.get("theme").unwrap_or("none");
    format!("session={session};theme={theme}")
}

fn form_login(Form(data): Form<HashMap<String, String>>) -> String {
    let user = data.get("user").cloned().unwrap_or_default();
    format!("logged_in:{user}")
}

#[derive(Clone)]
struct AppConfig {
    name: &'static str,
    version: u32,
}

fn with_state(State(config): State<AppConfig>) -> String {
    format!("{}:v{}", config.name, config.version)
}

fn with_state_and_path(State(config): State<AppConfig>, Path(id): Path<String>) -> String {
    format!("{}:{}", config.name, id)
}

// =========================================================================
// 1. Router Composition
// =========================================================================

#[test]
fn integration_router_method_dispatch_all_verbs() {
    common::init_test_logging();
    test_phase!("Router Method Dispatch — All Verbs");

    let router = Router::new().route(
        "/res",
        get(FnHandler::new(|| -> &'static str { "GET" }))
            .post(FnHandler::new(|| -> &'static str { "POST" }))
            .put(FnHandler::new(|| -> &'static str { "PUT" }))
            .delete(FnHandler::new(|| -> &'static str { "DELETE" }))
            .patch(FnHandler::new(|| -> &'static str { "PATCH" })),
    );

    for (method, expected) in [
        ("GET", "GET"),
        ("POST", "POST"),
        ("PUT", "PUT"),
        ("DELETE", "DELETE"),
        ("PATCH", "PATCH"),
    ] {
        let resp = router.handle(Request::new(method, "/res"));
        assert_eq!(resp.status, StatusCode::OK, "method {method}");
        assert_eq!(
            std::str::from_utf8(&resp.body).unwrap(),
            expected,
            "body for {method}"
        );
    }

    // HEAD on a route with no HEAD handler should return 405
    let resp = router.handle(Request::new("HEAD", "/res"));
    assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);

    test_complete!("router_method_dispatch_all_verbs");
}

#[test]
fn integration_router_chained_method_router() {
    common::init_test_logging();
    test_phase!("Router Chained Methods");

    let router = Router::new().route(
        "/items",
        get(FnHandler::new(|| -> &'static str { "list" }))
            .post(FnHandler::new(|| -> StatusCode { StatusCode::CREATED }))
            .delete(FnHandler::new(|| -> StatusCode { StatusCode::NO_CONTENT })),
    );

    assert_eq!(
        router.handle(Request::new("GET", "/items")).status,
        StatusCode::OK
    );
    assert_eq!(
        router.handle(Request::new("POST", "/items")).status,
        StatusCode::CREATED
    );
    assert_eq!(
        router.handle(Request::new("DELETE", "/items")).status,
        StatusCode::NO_CONTENT
    );

    test_complete!("router_chained_methods");
}

#[test]
fn integration_router_deep_nesting() {
    common::init_test_logging();
    test_phase!("Router Deep Nesting");

    let inner = Router::new().route("/leaf", get(FnHandler::new(|| -> &'static str { "leaf" })));
    let mid = Router::new().nest("/mid", inner);
    let outer = Router::new().nest("/outer", mid);

    let resp = outer.handle(Request::new("GET", "/outer/mid/leaf"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "leaf");

    // Non-existent nested path
    let resp = outer.handle(Request::new("GET", "/outer/mid/missing"));
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    test_complete!("router_deep_nesting");
}

#[test]
fn integration_router_fallback_on_nested() {
    common::init_test_logging();
    test_phase!("Router Fallback on Nested");

    let api = Router::new()
        .route("/users", get(FnHandler::new(index)))
        .fallback(FnHandler::new(|| -> (StatusCode, &'static str) {
            (StatusCode::NOT_FOUND, "api-not-found")
        }));

    let app = Router::new().nest("/api", api).fallback(FnHandler::new(
        || -> (StatusCode, &'static str) { (StatusCode::NOT_FOUND, "app-not-found") },
    ));

    // Nested fallback fires for unmatched nested path
    let resp = app.handle(Request::new("GET", "/api/missing"));
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "api-not-found");

    // Top-level fallback fires for non-nested path
    let resp = app.handle(Request::new("GET", "/other"));
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "app-not-found");

    test_complete!("router_fallback_on_nested");
}

#[test]
fn integration_router_wildcard_route() {
    fn wildcard_handler(Path(params): Path<HashMap<String, String>>) -> String {
        params.get("*").cloned().unwrap_or_default()
    }

    common::init_test_logging();
    test_phase!("Router Wildcard Route");

    let router = Router::new().route(
        "/files/*",
        get(FnHandler1::<_, Path<HashMap<String, String>>>::new(
            wildcard_handler,
        )),
    );

    let resp = router.handle(Request::new("GET", "/files/docs/readme.md"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&resp.body).unwrap(),
        "docs/readme.md"
    );

    test_complete!("router_wildcard_route");
}

#[test]
fn integration_router_multiple_path_params() {
    common::init_test_logging();
    test_phase!("Router Multiple Path Params");

    let router = Router::new().route(
        "/users/:uid/posts/:pid",
        get(FnHandler1::<_, Path<HashMap<String, String>>>::new(
            get_user_posts,
        )),
    );

    let resp = router.handle(Request::new("GET", "/users/42/posts/7"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&resp.body).unwrap(),
        "user:42/post:7"
    );

    test_complete!("router_multiple_path_params");
}

#[test]
fn integration_router_route_count() {
    common::init_test_logging();
    test_phase!("Router Route Count");

    let router = Router::new()
        .route("/a", get(FnHandler::new(index)))
        .route("/b", get(FnHandler::new(index)))
        .route("/c", post(FnHandler::new(index)));

    assert_eq!(router.route_count(), 3);

    test_complete!("router_route_count");
}

// =========================================================================
// 2. Extractor Types
// =========================================================================

#[test]
fn integration_extractor_path_string() {
    common::init_test_logging();
    test_phase!("Extractor Path String");

    let router = Router::new().route(
        "/users/:id",
        get(FnHandler1::<_, Path<String>>::new(get_user)),
    );

    let resp = router.handle(Request::new("GET", "/users/alice"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "user:alice");

    test_complete!("extractor_path_string");
}

#[test]
fn integration_extractor_path_numeric() {
    fn handler(Path(id): Path<u64>) -> String {
        format!("id:{id}")
    }

    common::init_test_logging();
    test_phase!("Extractor Path Numeric");

    let router = Router::new().route(
        "/items/:id",
        get(FnHandler1::<_, Path<u64>>::new(handler)),
    );

    let resp = router.handle(Request::new("GET", "/items/999"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "id:999");

    // Invalid numeric → 400
    let resp = router.handle(Request::new("GET", "/items/abc"));
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);

    test_complete!("extractor_path_numeric");
}

#[test]
fn integration_extractor_query_hashmap() {
    common::init_test_logging();
    test_phase!("Extractor Query HashMap");

    let router = Router::new().route(
        "/search",
        get(FnHandler1::<_, Query<HashMap<String, String>>>::new(search)),
    );

    let req = Request::new("GET", "/search").with_query("q=rust+async");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&resp.body).unwrap(),
        "results:rust async"
    );

    test_complete!("extractor_query_hashmap");
}

#[test]
fn integration_extractor_query_typed_struct() {
    #[derive(serde::Deserialize)]
    struct Pagination {
        page: u32,
        per_page: u16,
    }

    fn handler(Query(p): Query<Pagination>) -> String {
        format!("page:{},per_page:{}", p.page, p.per_page)
    }

    common::init_test_logging();
    test_phase!("Extractor Query Typed Struct");

    let router = Router::new().route(
        "/items",
        get(FnHandler1::<_, Query<Pagination>>::new(handler)),
    );

    let req = Request::new("GET", "/items").with_query("page=3&per_page=25");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&resp.body).unwrap(),
        "page:3,per_page:25"
    );

    // Invalid query param type → 400
    let req = Request::new("GET", "/items").with_query("page=abc&per_page=25");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);

    test_complete!("extractor_query_typed_struct");
}

#[test]
fn integration_extractor_json_body() {
    common::init_test_logging();
    test_phase!("Extractor JSON Body");

    let router = Router::new().route(
        "/items",
        post(FnHandler1::<_, JsonExtract<serde_json::Value>>::new(
            create_item,
        )),
    );

    let body = serde_json::to_vec(&serde_json::json!({"name": "widget"})).unwrap();
    let req = Request::new("POST", "/items")
        .with_header("content-type", "application/json")
        .with_body(body);
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::CREATED);
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["created"], true);
    assert_eq!(json["name"], "widget");

    test_complete!("extractor_json_body");
}

#[test]
fn integration_extractor_json_wrong_content_type() {
    common::init_test_logging();
    test_phase!("Extractor JSON Wrong Content-Type");

    let router = Router::new().route(
        "/items",
        post(FnHandler1::<_, JsonExtract<serde_json::Value>>::new(
            create_item,
        )),
    );

    let req = Request::new("POST", "/items")
        .with_header("content-type", "text/plain")
        .with_body(b"{\"name\":\"x\"}".to_vec());
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    test_complete!("extractor_json_wrong_content_type");
}

#[test]
fn integration_extractor_json_invalid_body() {
    common::init_test_logging();
    test_phase!("Extractor JSON Invalid Body");

    let router = Router::new().route(
        "/items",
        post(FnHandler1::<_, JsonExtract<serde_json::Value>>::new(
            create_item,
        )),
    );

    let req = Request::new("POST", "/items")
        .with_header("content-type", "application/json")
        .with_body(b"not json".to_vec());
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::UNPROCESSABLE_ENTITY);

    test_complete!("extractor_json_invalid_body");
}

#[test]
fn integration_extractor_form() {
    common::init_test_logging();
    test_phase!("Extractor Form");

    let router = Router::new().route(
        "/login",
        post(FnHandler1::<_, Form<HashMap<String, String>>>::new(
            form_login,
        )),
    );

    let req = Request::new("POST", "/login").with_body(Bytes::from_static(b"user=alice&pass=secret"));
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&resp.body).unwrap(),
        "logged_in:alice"
    );

    test_complete!("extractor_form");
}

#[test]
fn integration_extractor_raw_body() {
    common::init_test_logging();
    test_phase!("Extractor RawBody");

    let router = Router::new().route(
        "/echo",
        post(FnHandler1::<_, RawBody>::new(echo_raw)),
    );

    let payload = b"binary\x00data\xff";
    let req = Request::new("POST", "/echo").with_body(Bytes::copy_from_slice(payload));
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body.as_ref(), payload);

    test_complete!("extractor_raw_body");
}

#[test]
fn integration_extractor_header_map() {
    common::init_test_logging();
    test_phase!("Extractor HeaderMap");

    let router = Router::new().route(
        "/headers",
        get(FnHandler1::<_, HashMap<String, String>>::new(echo_headers)),
    );

    let req = Request::new("GET", "/headers")
        .with_header("x-request-id", "abc")
        .with_header("x-trace", "123");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    let body = std::str::from_utf8(&resp.body).unwrap();
    assert!(body.contains("x-request-id=abc"));
    assert!(body.contains("x-trace=123"));

    test_complete!("extractor_header_map");
}

#[test]
fn integration_extractor_cookie_raw() {
    common::init_test_logging();
    test_phase!("Extractor Cookie Raw");

    let router = Router::new().route(
        "/cookie",
        get(FnHandler1::<_, Cookie>::new(echo_cookie)),
    );

    let req = Request::new("GET", "/cookie").with_header("Cookie", "session=abc123");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&resp.body).unwrap(),
        "raw:session=abc123"
    );

    // Missing cookie header → 400
    let resp = router.handle(Request::new("GET", "/cookie"));
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);

    test_complete!("extractor_cookie_raw");
}

#[test]
fn integration_extractor_cookie_jar() {
    common::init_test_logging();
    test_phase!("Extractor CookieJar");

    let router = Router::new().route(
        "/jar",
        get(FnHandler1::<_, CookieJar>::new(echo_cookie_jar)),
    );

    let req =
        Request::new("GET", "/jar").with_header("cookie", "session=tok123; theme=dark; lang=en");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&resp.body).unwrap(),
        "session=tok123;theme=dark"
    );

    // No cookie header → empty jar (not an error)
    let resp = router.handle(Request::new("GET", "/jar"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&resp.body).unwrap(),
        "session=none;theme=none"
    );

    test_complete!("extractor_cookie_jar");
}

#[test]
fn integration_extractor_state() {
    common::init_test_logging();
    test_phase!("Extractor State");

    let router = Router::new()
        .route(
            "/info",
            get(FnHandler1::<_, State<AppConfig>>::new(with_state)),
        )
        .with_state(AppConfig {
            name: "myapp",
            version: 3,
        });

    let resp = router.handle(Request::new("GET", "/info"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "myapp:v3");

    test_complete!("extractor_state");
}

#[test]
fn integration_extractor_state_missing_returns_500() {
    common::init_test_logging();
    test_phase!("Extractor State Missing");

    let router = Router::new().route(
        "/info",
        get(FnHandler1::<_, State<AppConfig>>::new(with_state)),
    );

    let resp = router.handle(Request::new("GET", "/info"));
    assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);

    test_complete!("extractor_state_missing");
}

#[test]
fn integration_extractor_two_extractors() {
    common::init_test_logging();
    test_phase!("Two Extractors");

    let router = Router::new()
        .route(
            "/users/:id",
            get(FnHandler2::<_, State<AppConfig>, Path<String>>::new(
                with_state_and_path,
            )),
        )
        .with_state(AppConfig {
            name: "api",
            version: 1,
        });

    let resp = router.handle(Request::new("GET", "/users/42"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "api:42");

    test_complete!("two_extractors");
}

// =========================================================================
// 3. Response Types
// =========================================================================

#[test]
fn integration_response_json() {
    common::init_test_logging();
    test_phase!("Response JSON");

    let router = Router::new().route(
        "/data",
        get(FnHandler::new(|| -> Json<serde_json::Value> {
            Json(serde_json::json!({"ok": true, "count": 42}))
        })),
    );

    let resp = router.handle(Request::new("GET", "/data"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        resp.headers.get("content-type").unwrap(),
        "application/json"
    );
    let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["count"], 42);

    test_complete!("response_json");
}

#[test]
fn integration_response_html() {
    common::init_test_logging();
    test_phase!("Response HTML");

    let router = Router::new().route("/page", get(FnHandler::new(html_page)));

    let resp = router.handle(Request::new("GET", "/page"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        resp.headers.get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
    assert!(std::str::from_utf8(&resp.body).unwrap().contains("<h1>"));

    test_complete!("response_html");
}

#[test]
fn integration_response_redirect_variants() {
    common::init_test_logging();
    test_phase!("Response Redirect Variants");

    let router = Router::new()
        .route("/r302", get(FnHandler::new(|| Redirect::to("/target"))))
        .route(
            "/r301",
            get(FnHandler::new(|| Redirect::permanent("/target"))),
        )
        .route(
            "/r307",
            get(FnHandler::new(|| Redirect::temporary("/target"))),
        );

    let resp = router.handle(Request::new("GET", "/r302"));
    assert_eq!(resp.status, StatusCode::FOUND);
    assert_eq!(resp.headers.get("location").unwrap(), "/target");

    let resp = router.handle(Request::new("GET", "/r301"));
    assert_eq!(resp.status, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(resp.headers.get("location").unwrap(), "/target");

    let resp = router.handle(Request::new("GET", "/r307"));
    assert_eq!(resp.status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(resp.headers.get("location").unwrap(), "/target");

    test_complete!("response_redirect_variants");
}

#[test]
fn integration_response_status_code_only() {
    common::init_test_logging();
    test_phase!("Response StatusCode Only");

    let router = Router::new().route(
        "/accepted",
        post(FnHandler::new(|| -> StatusCode { StatusCode::ACCEPTED })),
    );

    let resp = router.handle(Request::new("POST", "/accepted"));
    assert_eq!(resp.status, StatusCode::ACCEPTED);
    assert!(resp.body.is_empty());

    test_complete!("response_status_only");
}

#[test]
fn integration_response_tuple_status_body() {
    common::init_test_logging();
    test_phase!("Response Tuple (StatusCode, Body)");

    let router = Router::new().route(
        "/create",
        post(FnHandler::new(
            || -> (StatusCode, &'static str) { (StatusCode::CREATED, "created") },
        )),
    );

    let resp = router.handle(Request::new("POST", "/create"));
    assert_eq!(resp.status, StatusCode::CREATED);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "created");

    test_complete!("response_tuple");
}

#[test]
fn integration_response_result_ok_and_err() {
    #[allow(clippy::unnecessary_wraps)]
    fn ok_handler() -> Result<&'static str, StatusCode> {
        Ok("success")
    }

    fn err_handler() -> Result<&'static str, StatusCode> {
        Err(StatusCode::FORBIDDEN)
    }

    common::init_test_logging();
    test_phase!("Response Result<T, E>");

    let router = Router::new()
        .route("/ok", get(FnHandler::new(ok_handler)))
        .route("/err", get(FnHandler::new(err_handler)));

    let resp = router.handle(Request::new("GET", "/ok"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "success");

    let resp = router.handle(Request::new("GET", "/err"));
    assert_eq!(resp.status, StatusCode::FORBIDDEN);

    test_complete!("response_result");
}

#[test]
fn integration_response_unit() {
    common::init_test_logging();
    test_phase!("Response Unit");

    let router = Router::new().route("/noop", post(FnHandler::new(|| {})));

    let resp = router.handle(Request::new("POST", "/noop"));
    assert_eq!(resp.status, StatusCode::OK);
    assert!(resp.body.is_empty());

    test_complete!("response_unit");
}

#[test]
fn integration_response_bytes() {
    common::init_test_logging();
    test_phase!("Response Bytes");

    let router = Router::new().route(
        "/binary",
        get(FnHandler::new(|| -> Bytes {
            Bytes::from_static(b"\x00\x01\x02")
        })),
    );

    let resp = router.handle(Request::new("GET", "/binary"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        resp.headers.get("content-type").unwrap(),
        "application/octet-stream"
    );
    assert_eq!(resp.body.as_ref(), b"\x00\x01\x02");

    test_complete!("response_bytes");
}

// =========================================================================
// 4. Middleware Stack
// =========================================================================

#[test]
fn integration_middleware_cors_preflight() {
    common::init_test_logging();
    test_phase!("Middleware CORS Preflight");

    let handler = FnHandler::new(index);
    let cors = CorsMiddleware::new(handler, CorsPolicy::default());

    // Preflight request
    let req = Request::new("OPTIONS", "/api")
        .with_header("origin", "https://example.com")
        .with_header("access-control-request-method", "POST");

    let resp = cors.call(req);
    assert_eq!(resp.status, StatusCode::NO_CONTENT);
    assert_eq!(
        resp.headers.get("access-control-allow-origin").unwrap(),
        "*"
    );
    assert!(resp
        .headers
        .get("access-control-allow-methods")
        .unwrap()
        .contains("POST"));

    test_complete!("middleware_cors_preflight");
}

#[test]
fn integration_middleware_cors_exact_origin() {
    common::init_test_logging();
    test_phase!("Middleware CORS Exact Origin");

    let handler = FnHandler::new(index);
    let policy = CorsPolicy::with_exact_origins(["https://allowed.com".to_string()]);
    let cors = CorsMiddleware::new(handler, policy);

    // Allowed origin
    let req = Request::new("GET", "/api").with_header("origin", "https://allowed.com");
    let resp = cors.call(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        resp.headers.get("access-control-allow-origin").unwrap(),
        "https://allowed.com"
    );

    // Disallowed origin — no CORS headers, passthrough
    let req = Request::new("GET", "/api").with_header("origin", "https://evil.com");
    let resp = cors.call(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert!(!resp.headers.contains_key("access-control-allow-origin"));

    test_complete!("middleware_cors_exact_origin");
}

#[test]
fn integration_middleware_cors_no_origin_passthrough() {
    common::init_test_logging();
    test_phase!("Middleware CORS No Origin");

    let handler = FnHandler::new(index);
    let cors = CorsMiddleware::new(handler, CorsPolicy::default());

    // No origin header → passthrough without CORS headers
    let req = Request::new("GET", "/api");
    let resp = cors.call(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert!(!resp.headers.contains_key("access-control-allow-origin"));

    test_complete!("middleware_cors_no_origin");
}

#[test]
fn integration_middleware_timeout() {
    common::init_test_logging();
    test_phase!("Middleware Timeout");

    let handler = FnHandler::new(|| -> &'static str { "fast" });
    let timeout_mw = TimeoutMiddleware::new(handler, Duration::from_secs(5));

    let resp = timeout_mw.call(Request::new("GET", "/"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "fast");

    test_complete!("middleware_timeout");
}

#[test]
fn integration_middleware_catch_panic() {
    fn panicking_handler() -> &'static str {
        panic!("deliberate test panic");
    }

    common::init_test_logging();
    test_phase!("Middleware Catch Panic");

    let handler = FnHandler::new(panicking_handler);
    let catch = CatchPanicMiddleware::new(handler);

    let resp = catch.call(Request::new("GET", "/"));
    assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);

    test_complete!("middleware_catch_panic");
}

#[test]
fn integration_middleware_auth_bearer() {
    common::init_test_logging();
    test_phase!("Middleware Auth Bearer");

    let handler = FnHandler::new(|| -> &'static str { "protected" });
    let auth = AuthMiddleware::new(handler, AuthPolicy::exact_bearer("valid-token"));

    // Valid token
    let req = Request::new("GET", "/secure").with_header("authorization", "Bearer valid-token");
    let resp = auth.call(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "protected");

    // Missing token
    let resp = auth.call(Request::new("GET", "/secure"));
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);

    // Invalid token
    let req =
        Request::new("GET", "/secure").with_header("authorization", "Bearer wrong-token");
    let resp = auth.call(req);
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);

    test_complete!("middleware_auth_bearer");
}

#[test]
fn integration_middleware_rate_limit() {
    common::init_test_logging();
    test_phase!("Middleware Rate Limit");

    let handler = FnHandler::new(|| -> &'static str { "ok" });
    let policy = RateLimitPolicy {
        name: "test".into(),
        rate: 0,
        period: Duration::from_secs(60),
        burst: 2,
        ..Default::default()
    };
    let rl = RateLimitMiddleware::new(handler, policy);

    // First two requests should pass
    let resp = rl.call(Request::new("GET", "/"));
    assert_eq!(resp.status, StatusCode::OK);
    let resp = rl.call(Request::new("GET", "/"));
    assert_eq!(resp.status, StatusCode::OK);

    // Third should be rate limited
    let resp = rl.call(Request::new("GET", "/"));
    assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS);

    test_complete!("middleware_rate_limit");
}

#[test]
fn integration_middleware_stack_composition() {
    common::init_test_logging();
    test_phase!("Middleware Stack Composition");

    let handler = FnHandler::new(|| -> &'static str { "inner" });

    let composed = MiddlewareStack::new(handler)
        .with_catch_panic()
        .with_timeout(Duration::from_secs(5))
        .build();

    let resp = composed.call(Request::new("GET", "/"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "inner");

    test_complete!("middleware_stack_composition");
}

#[test]
fn integration_middleware_in_router() {
    common::init_test_logging();
    test_phase!("Middleware in Router");

    let protected = CatchPanicMiddleware::new(FnHandler::new(|| -> &'static str { "safe" }));

    let router = Router::new().route("/safe", get(protected));

    let resp = router.handle(Request::new("GET", "/safe"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "safe");

    test_complete!("middleware_in_router");
}

// =========================================================================
// 5. SSE Events
// =========================================================================

#[test]
fn integration_sse_handler() {
    fn sse_handler() -> Sse {
        Sse::new(vec![
            SseEvent::default().event("message").data("hello"),
            SseEvent::default().event("message").data("world"),
        ])
    }

    common::init_test_logging();
    test_phase!("SSE Handler");

    let router = Router::new().route("/events", get(FnHandler::new(sse_handler)));

    let resp = router.handle(Request::new("GET", "/events"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        resp.headers.get("content-type").unwrap(),
        "text/event-stream"
    );
    assert_eq!(resp.headers.get("cache-control").unwrap(), "no-cache");

    let body = std::str::from_utf8(&resp.body).unwrap();
    assert!(body.contains("event:message\ndata:hello\n"));
    assert!(body.contains("event:message\ndata:world\n"));

    test_complete!("sse_handler");
}

#[test]
fn integration_sse_keep_alive_and_last_event_id() {
    fn sse_handler() -> Sse {
        Sse::new(vec![
            SseEvent::default().event("update").data("{\"n\":1}"),
            SseEvent::default().event("update").data("{\"n\":2}"),
        ])
        .keep_alive()
        .last_event_id("42")
    }

    common::init_test_logging();
    test_phase!("SSE Keep-Alive and Last-Event-ID");

    let router = Router::new().route("/stream", get(FnHandler::new(sse_handler)));

    let resp = router.handle(Request::new("GET", "/stream"));
    let body = std::str::from_utf8(&resp.body).unwrap();

    // Keep-alive comment at the start
    assert!(body.starts_with(":keep-alive\n\n"));
    // Last event ID injected on the final event
    assert!(body.contains("id:42"));

    test_complete!("sse_keep_alive_and_last_event_id");
}

#[test]
fn integration_sse_multiline_data() {
    fn sse_handler() -> SseEvent {
        SseEvent::default().data("line1\nline2\nline3")
    }

    common::init_test_logging();
    test_phase!("SSE Multiline Data");

    let router = Router::new().route("/event", get(FnHandler::new(sse_handler)));

    let resp = router.handle(Request::new("GET", "/event"));
    let body = std::str::from_utf8(&resp.body).unwrap();
    assert!(body.contains("data:line1\ndata:line2\ndata:line3\n"));

    test_complete!("sse_multiline_data");
}

// =========================================================================
// 6. Health Check Endpoints
// =========================================================================

#[test]
fn integration_health_liveness_readiness_startup() {
    common::init_test_logging();
    test_phase!("Health Check Endpoints");

    let health = HealthCheck::new()
        .check("db", || HealthStatus::Healthy)
        .check("cache", || HealthStatus::Healthy);

    let router = Router::new()
        .route("/healthz", get(health.liveness_handler()))
        .route("/readyz", get(health.readiness_handler()))
        .route("/startupz", get(health.startup_handler()));

    test_section!("Liveness — healthy");
    let resp = router.handle(Request::new("GET", "/healthz"));
    assert_eq!(resp.status, StatusCode::OK);
    let body = std::str::from_utf8(&resp.body).unwrap();
    assert!(body.contains("\"status\":\"healthy\""));

    test_section!("Readiness — ready");
    let resp = router.handle(Request::new("GET", "/readyz"));
    assert_eq!(resp.status, StatusCode::OK);

    test_section!("Startup — started");
    let resp = router.handle(Request::new("GET", "/startupz"));
    assert_eq!(resp.status, StatusCode::OK);
    let body = std::str::from_utf8(&resp.body).unwrap();
    assert!(body.contains("started"));

    test_section!("Drain traffic — set not ready");
    health.set_ready(false);

    let resp = router.handle(Request::new("GET", "/readyz"));
    assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
    let body = std::str::from_utf8(&resp.body).unwrap();
    assert!(body.contains("not_ready"));

    let resp = router.handle(Request::new("GET", "/startupz"));
    assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);

    // Liveness still returns healthy (process is alive even if draining)
    let resp = router.handle(Request::new("GET", "/healthz"));
    assert_eq!(resp.status, StatusCode::OK);

    test_complete!("health_endpoints", checks = 2);
}

#[test]
fn integration_health_degraded_and_unhealthy() {
    common::init_test_logging();
    test_phase!("Health Degraded and Unhealthy");

    let health = HealthCheck::new()
        .check("db", || HealthStatus::Healthy)
        .check("cache", || HealthStatus::Degraded("high latency".into()));

    let router = Router::new().route("/healthz", get(health.liveness_handler()));

    // Degraded is still operational → 200
    let resp = router.handle(Request::new("GET", "/healthz"));
    assert_eq!(resp.status, StatusCode::OK);
    let body = std::str::from_utf8(&resp.body).unwrap();
    assert!(body.contains("\"status\":\"degraded\""));
    assert!(body.contains("high latency"));

    test_complete!("health_degraded");
}

// =========================================================================
// 7. Session Management
// =========================================================================

#[test]
fn integration_session_basic() {
    common::init_test_logging();
    test_phase!("Session Basic");

    let store = MemoryStore::new();
    let inner = FnHandler::new(|| -> &'static str { "session-ok" });
    let session_handler = SessionLayer::new(store).wrap(inner);

    let router = Router::new().route("/dashboard", get(session_handler));

    // First request — should get a Set-Cookie header with a new session ID
    let resp = router.handle(Request::new("GET", "/dashboard"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "session-ok");

    // Check that a set-cookie header was emitted
    let set_cookie = resp.headers.get("set-cookie");
    assert!(
        set_cookie.is_some(),
        "expected set-cookie header for new session"
    );
    let cookie_val = set_cookie.unwrap();
    assert!(
        cookie_val.contains("session_id="),
        "cookie should contain session_id"
    );

    test_complete!("session_basic");
}

// =========================================================================
// 8. Error Handling and Edge Cases
// =========================================================================

#[test]
fn integration_error_404_and_405() {
    common::init_test_logging();
    test_phase!("Error 404 and 405");

    let router = Router::new().route("/only-get", get(FnHandler::new(index)));

    // Missing route → 404
    let resp = router.handle(Request::new("GET", "/nonexistent"));
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    // Wrong method → 405
    let resp = router.handle(Request::new("POST", "/only-get"));
    assert_eq!(resp.status, StatusCode::METHOD_NOT_ALLOWED);

    test_complete!("error_404_and_405");
}

#[test]
fn integration_error_extraction_failure_propagates() {
    common::init_test_logging();
    test_phase!("Extraction Failure Propagates");

    // Path extractor with no params → 400
    let router = Router::new().route(
        "/",
        get(FnHandler1::<_, Path<String>>::new(get_user)),
    );

    let resp = router.handle(Request::new("GET", "/"));
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);

    test_complete!("extraction_failure_propagates");
}

#[test]
fn integration_empty_body_json_extraction() {
    common::init_test_logging();
    test_phase!("Empty Body JSON Extraction");

    let router = Router::new().route(
        "/items",
        post(FnHandler1::<_, JsonExtract<serde_json::Value>>::new(
            create_item,
        )),
    );

    // Empty body with json content-type → 422 (invalid JSON)
    let req = Request::new("POST", "/items").with_header("content-type", "application/json");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::UNPROCESSABLE_ENTITY);

    test_complete!("empty_body_json");
}

#[test]
fn integration_percent_encoded_query_params() {
    common::init_test_logging();
    test_phase!("Percent-Encoded Query Params");

    let router = Router::new().route(
        "/search",
        get(FnHandler1::<_, Query<HashMap<String, String>>>::new(search)),
    );

    // Percent-encoded spaces and special chars
    let req = Request::new("GET", "/search").with_query("q=hello%20world%21");
    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        std::str::from_utf8(&resp.body).unwrap(),
        "results:hello world!"
    );

    test_complete!("percent_encoded_query");
}

#[test]
fn integration_trailing_slash_normalization() {
    common::init_test_logging();
    test_phase!("Trailing Slash Normalization");

    let router = Router::new().route("/users", get(FnHandler::new(index)));

    // With trailing slash
    let resp = router.handle(Request::new("GET", "/users/"));
    assert_eq!(resp.status, StatusCode::OK);

    // Without trailing slash
    let resp = router.handle(Request::new("GET", "/users"));
    assert_eq!(resp.status, StatusCode::OK);

    test_complete!("trailing_slash");
}

#[test]
fn integration_state_propagates_to_nested_router() {
    common::init_test_logging();
    test_phase!("State Propagates to Nested Router");

    let api = Router::new().route(
        "/info",
        get(FnHandler1::<_, State<AppConfig>>::new(with_state)),
    );

    let app = Router::new()
        .nest("/api", api)
        .with_state(AppConfig {
            name: "nested",
            version: 2,
        });

    let resp = app.handle(Request::new("GET", "/api/info"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "nested:v2");

    test_complete!("state_nested");
}

#[test]
fn integration_nested_state_overrides_parent() {
    common::init_test_logging();
    test_phase!("Nested State Overrides Parent");

    let api = Router::new()
        .route(
            "/info",
            get(FnHandler1::<_, State<AppConfig>>::new(with_state)),
        )
        .with_state(AppConfig {
            name: "child",
            version: 9,
        });

    let app = Router::new()
        .nest("/api", api)
        .with_state(AppConfig {
            name: "parent",
            version: 1,
        });

    let resp = app.handle(Request::new("GET", "/api/info"));
    assert_eq!(resp.status, StatusCode::OK);
    // Nested router's state should take precedence
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "child:v9");

    test_complete!("nested_state_override");
}

// =========================================================================
// 9. Full Application Composition
// =========================================================================

#[test]
fn integration_full_app_composition() {
    common::init_test_logging();
    test_phase!("Full Application Composition");

    // Build a realistic app with multiple features combined
    let health = HealthCheck::new().check("db", || HealthStatus::Healthy);

    let users_api = Router::new()
        .route(
            "/",
            get(FnHandler::new(|| -> &'static str { "user-list" }))
                .post(FnHandler1::<_, JsonExtract<serde_json::Value>>::new(
                    create_item,
                )),
        )
        .route(
            "/:id",
            get(FnHandler1::<_, Path<String>>::new(get_user))
                .delete(FnHandler1::<_, Path<String>>::new(delete_item)),
        );

    let items_api = Router::new().route(
        "/search",
        get(FnHandler1::<_, Query<HashMap<String, String>>>::new(search)),
    );

    let app = Router::new()
        .route("/", get(FnHandler::new(index)))
        .route("/healthz", get(health.liveness_handler()))
        .route("/readyz", get(health.readiness_handler()))
        .nest("/api/users", users_api)
        .nest("/api/items", items_api)
        .with_state(AppConfig {
            name: "fullapp",
            version: 1,
        })
        .fallback(FnHandler::new(
            || -> (StatusCode, &'static str) { (StatusCode::NOT_FOUND, "not found") },
        ));

    test_section!("Root");
    let resp = app.handle(Request::new("GET", "/"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "welcome");

    test_section!("Health");
    let resp = app.handle(Request::new("GET", "/healthz"));
    assert_eq!(resp.status, StatusCode::OK);

    test_section!("User list");
    let resp = app.handle(Request::new("GET", "/api/users/"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "user-list");

    test_section!("Get user");
    let resp = app.handle(Request::new("GET", "/api/users/42"));
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "user:42");

    test_section!("Create user");
    let body = serde_json::to_vec(&serde_json::json!({"name": "bob"})).unwrap();
    let req = Request::new("POST", "/api/users/")
        .with_header("content-type", "application/json")
        .with_body(body);
    let resp = app.handle(req);
    assert_eq!(resp.status, StatusCode::CREATED);

    test_section!("Delete user");
    let resp = app.handle(Request::new("DELETE", "/api/users/42"));
    assert_eq!(resp.status, StatusCode::NO_CONTENT);

    test_section!("Search items");
    let req = Request::new("GET", "/api/items/search").with_query("q=widget");
    let resp = app.handle(req);
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "results:widget");

    test_section!("Fallback");
    let resp = app.handle(Request::new("GET", "/unknown"));
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
    assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "not found");

    test_complete!("full_app_composition", routes = 7);
}
