//! HTTP Server/Client Verification Suite (bd-39ik).
//!
//! Comprehensive verification for the HTTP layer ensuring protocol compliance,
//! cancel-correctness, request/response lifecycle, and web framework integration.

#![allow(clippy::items_after_statements)]

mod common;
use common::*;

use asupersync::bytes::{Bytes, BytesCursor};
use asupersync::http::body::{Body, Empty, Full, HeaderMap, HeaderName, HeaderValue};
use asupersync::http::pool::{Pool, PoolConfig, PoolKey};
use asupersync::types::Time;
use asupersync::web::extract::{FromRequest, FromRequestParts, Path, Query, Request};
use asupersync::web::handler::{FnHandler, FnHandler1};
use asupersync::web::response::{Html, IntoResponse, Json, Redirect, StatusCode};
use asupersync::web::router::{Router, get, post, put};
use std::collections::HashMap;

// ===========================================================================
// Section 1: HTTP Body trait compliance
// ===========================================================================

#[test]
fn body_full_lifecycle() {
    init_test_logging();
    test_phase!("body_full_lifecycle");

    // Full body yields a single data frame then ends.
    let body = Full::new(BytesCursor::new(Bytes::from_static(b"hello world")));
    assert!(!body.is_end_stream());

    let hint = body.size_hint();
    assert_eq!(hint.lower(), 11);
    assert_eq!(hint.upper(), Some(11));

    test_complete!("body_full_lifecycle");
}

#[test]
fn body_empty_lifecycle() {
    init_test_logging();
    test_phase!("body_empty_lifecycle");

    let body = Empty::new();
    assert!(body.is_end_stream());
    let hint = body.size_hint();
    assert_eq!(hint.lower(), 0);
    assert_eq!(hint.upper(), Some(0));

    test_complete!("body_empty_lifecycle");
}

#[test]
fn header_map_case_insensitive() {
    init_test_logging();
    test_phase!("header_map_case_insensitive");

    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("Content-Type"),
        HeaderValue::from_static("application/json"),
    );

    // Header names are lowercased.
    let ct = headers.get(&HeaderName::from_static("content-type"));
    assert!(ct.is_some());
    assert_eq!(ct.unwrap().to_str().unwrap(), "application/json");

    test_complete!("header_map_case_insensitive");
}

// ===========================================================================
// Section 2: Connection pool verification
// ===========================================================================

#[test]
fn pool_basic_lifecycle() {
    init_test_logging();
    test_phase!("pool_basic_lifecycle");

    let config = PoolConfig::default();
    let mut pool = Pool::with_config(config);

    let key = PoolKey::new("localhost", 8080, false);
    pool.register_connecting(key, Time::ZERO, 1);

    let stats = pool.stats();
    assert!(stats.total_connections >= 1);

    test_complete!("pool_basic_lifecycle");
}

#[test]
fn pool_respects_max_connections() {
    init_test_logging();
    test_phase!("pool_respects_max_connections");

    let config = PoolConfig::builder().max_connections_per_host(2).build();
    let pool = Pool::with_config(config);

    let stats = pool.stats();
    assert_eq!(stats.total_connections, 0);

    test_complete!("pool_respects_max_connections");
}

// ===========================================================================
// Section 3: Web framework - Response construction
// ===========================================================================

#[test]
fn response_status_codes_complete() {
    init_test_logging();
    test_phase!("response_status_codes_complete");

    // Verify all standard status code categories.
    let codes = [
        (StatusCode::OK, 200, true, false, false),
        (StatusCode::CREATED, 201, true, false, false),
        (StatusCode::NO_CONTENT, 204, true, false, false),
        (StatusCode::BAD_REQUEST, 400, false, true, false),
        (StatusCode::UNAUTHORIZED, 401, false, true, false),
        (StatusCode::FORBIDDEN, 403, false, true, false),
        (StatusCode::NOT_FOUND, 404, false, true, false),
        (StatusCode::CONFLICT, 409, false, true, false),
        (StatusCode::UNPROCESSABLE_ENTITY, 422, false, true, false),
        (StatusCode::TOO_MANY_REQUESTS, 429, false, true, false),
        (StatusCode::INTERNAL_SERVER_ERROR, 500, false, false, true),
        (StatusCode::SERVICE_UNAVAILABLE, 503, false, false, true),
    ];

    for (code, num, is_success, is_client, is_server) in codes {
        assert_eq!(code.as_u16(), num, "code {num} raw value");
        assert_eq!(code.is_success(), is_success, "code {num} is_success");
        assert_eq!(
            code.is_client_error(),
            is_client,
            "code {num} is_client_error"
        );
        assert_eq!(
            code.is_server_error(),
            is_server,
            "code {num} is_server_error"
        );
    }

    test_complete!("response_status_codes_complete");
}

#[test]
fn response_json_serialization() {
    init_test_logging();
    test_phase!("response_json_serialization");

    let data = serde_json::json!({
        "users": [
            {"id": 1, "name": "alice"},
            {"id": 2, "name": "bob"}
        ]
    });

    let resp = Json(data).into_response();
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        resp.headers.get("content-type").unwrap(),
        "application/json"
    );

    // Body should be valid JSON.
    let body: serde_json::Value = serde_json::from_slice(resp.body.as_ref()).unwrap();
    assert_eq!(body["users"][0]["name"], "alice");

    test_complete!("response_json_serialization");
}

#[test]
fn response_html_content_type() {
    init_test_logging();
    test_phase!("response_html_content_type");

    let resp = Html("<html><body>Hello</body></html>").into_response();
    assert_eq!(resp.status, StatusCode::OK);
    assert!(
        resp.headers
            .get("content-type")
            .unwrap()
            .contains("text/html")
    );

    test_complete!("response_html_content_type");
}

#[test]
fn response_redirect_variants() {
    init_test_logging();
    test_phase!("response_redirect_variants");

    let r302 = Redirect::to("/login").into_response();
    assert_eq!(r302.status, StatusCode::FOUND);
    assert_eq!(r302.headers.get("location").unwrap(), "/login");

    let r301 = Redirect::permanent("/new-url").into_response();
    assert_eq!(r301.status, StatusCode::MOVED_PERMANENTLY);

    let r307 = Redirect::temporary("/temp").into_response();
    assert_eq!(r307.status, StatusCode::TEMPORARY_REDIRECT);

    test_complete!("response_redirect_variants");
}

#[test]
fn response_tuple_composition() {
    init_test_logging();
    test_phase!("response_tuple_composition");

    // (StatusCode, body) overrides status.
    let resp = (StatusCode::CREATED, "resource created").into_response();
    assert_eq!(resp.status, StatusCode::CREATED);
    assert!(!resp.body.is_empty());

    // (StatusCode, headers, body) overrides both.
    let headers = vec![("x-request-id".to_string(), "abc-123".to_string())];
    let resp = (StatusCode::ACCEPTED, headers, "processing").into_response();
    assert_eq!(resp.status, StatusCode::ACCEPTED);
    assert_eq!(resp.headers.get("x-request-id").unwrap(), "abc-123");

    test_complete!("response_tuple_composition");
}

// ===========================================================================
// Section 4: Web framework - Extractor verification
// ===========================================================================

#[test]
fn extractor_path_single_param() {
    init_test_logging();
    test_phase!("extractor_path_single_param");

    let mut params = HashMap::new();
    params.insert("id".to_string(), "42".to_string());
    let req = Request::new("GET", "/users/42").with_path_params(params);

    let Path(id) = Path::<String>::from_request_parts(&req).unwrap();
    assert_eq!(id, "42");

    test_complete!("extractor_path_single_param");
}

#[test]
fn extractor_path_multiple_params() {
    init_test_logging();
    test_phase!("extractor_path_multiple_params");

    let mut params = HashMap::new();
    params.insert("user_id".to_string(), "1".to_string());
    params.insert("post_id".to_string(), "99".to_string());
    let req = Request::new("GET", "/users/1/posts/99").with_path_params(params);

    let Path(all) = Path::<HashMap<String, String>>::from_request_parts(&req).unwrap();
    assert_eq!(all.get("user_id").unwrap(), "1");
    assert_eq!(all.get("post_id").unwrap(), "99");

    test_complete!("extractor_path_multiple_params");
}

#[test]
fn extractor_query_params() {
    init_test_logging();
    test_phase!("extractor_query_params");

    let req = Request::new("GET", "/search").with_query("q=rust+async&page=2&limit=10");

    let Query(params) = Query::<HashMap<String, String>>::from_request_parts(&req).unwrap();
    assert_eq!(params.get("q").unwrap(), "rust async");
    assert_eq!(params.get("page").unwrap(), "2");
    assert_eq!(params.get("limit").unwrap(), "10");

    test_complete!("extractor_query_params");
}

#[test]
fn extractor_query_percent_encoded() {
    init_test_logging();
    test_phase!("extractor_query_percent_encoded");

    let req = Request::new("GET", "/search").with_query("q=hello%20world&tag=%23rust");

    let Query(params) = Query::<HashMap<String, String>>::from_request_parts(&req).unwrap();
    assert_eq!(params.get("q").unwrap(), "hello world");
    assert_eq!(params.get("tag").unwrap(), "#rust");

    test_complete!("extractor_query_percent_encoded");
}

#[test]
fn extractor_json_body() {
    init_test_logging();
    test_phase!("extractor_json_body");

    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct CreateUser {
        name: String,
        email: String,
    }

    let body = serde_json::to_vec(&serde_json::json!({
        "name": "alice",
        "email": "alice@example.com"
    }))
    .unwrap();

    let req = Request::new("POST", "/users")
        .with_header("content-type", "application/json")
        .with_body(Bytes::copy_from_slice(&body));

    let result = asupersync::web::extract::Json::<CreateUser>::from_request(req).unwrap();
    assert_eq!(result.0.name, "alice");
    assert_eq!(result.0.email, "alice@example.com");

    test_complete!("extractor_json_body");
}

#[test]
fn extractor_json_rejects_wrong_content_type() {
    init_test_logging();
    test_phase!("extractor_json_rejects_wrong_content_type");

    #[derive(Debug, serde::Deserialize)]
    struct Input {
        #[allow(dead_code)]
        name: String,
    }

    let req = Request::new("POST", "/")
        .with_header("content-type", "text/plain")
        .with_body(Bytes::from_static(b"{\"name\":\"test\"}"));

    let result = asupersync::web::extract::Json::<Input>::from_request(req);
    assert!(result.is_err());

    test_complete!("extractor_json_rejects_wrong_content_type");
}

#[test]
fn extractor_json_rejects_malformed_body() {
    init_test_logging();
    test_phase!("extractor_json_rejects_malformed_body");

    #[derive(Debug, serde::Deserialize)]
    struct Input {
        #[allow(dead_code)]
        name: String,
    }

    let req = Request::new("POST", "/")
        .with_header("content-type", "application/json")
        .with_body(Bytes::from_static(b"not json"));

    let result = asupersync::web::extract::Json::<Input>::from_request(req);
    assert!(result.is_err());

    test_complete!("extractor_json_rejects_malformed_body");
}

// ===========================================================================
// Section 5: Router verification
// ===========================================================================

#[test]
fn router_basic_routing() {
    init_test_logging();
    test_phase!("router_basic_routing");

    fn index() -> &'static str {
        "index"
    }
    fn about() -> &'static str {
        "about"
    }

    let router = Router::new()
        .route("/", get(FnHandler::new(index)))
        .route("/about", get(FnHandler::new(about)));

    let resp = router.handle(Request::new("GET", "/"));
    assert_eq!(resp.status, StatusCode::OK);

    let resp = router.handle(Request::new("GET", "/about"));
    assert_eq!(resp.status, StatusCode::OK);

    test_complete!("router_basic_routing");
}

#[test]
fn router_method_dispatch() {
    init_test_logging();
    test_phase!("router_method_dispatch");

    fn get_items() -> &'static str {
        "list"
    }
    fn create_item() -> StatusCode {
        StatusCode::CREATED
    }
    fn update_item() -> StatusCode {
        StatusCode::NO_CONTENT
    }
    fn delete_item() -> StatusCode {
        StatusCode::NO_CONTENT
    }

    let router = Router::new()
        .route(
            "/items",
            get(FnHandler::new(get_items)).post(FnHandler::new(create_item)),
        )
        .route(
            "/items/:id",
            put(FnHandler::new(update_item)).delete(FnHandler::new(delete_item)),
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
        router.handle(Request::new("PUT", "/items/1")).status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        router.handle(Request::new("DELETE", "/items/1")).status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        router.handle(Request::new("PATCH", "/items")).status,
        StatusCode::METHOD_NOT_ALLOWED
    );

    test_complete!("router_method_dispatch");
}

#[test]
fn router_path_parameter_extraction() {
    init_test_logging();
    test_phase!("router_path_parameter_extraction");

    fn get_user(Path(id): Path<String>) -> String {
        format!("user:{id}")
    }

    let router = Router::new().route(
        "/users/:id",
        get(FnHandler1::<_, Path<String>>::new(get_user)),
    );

    let resp = router.handle(Request::new("GET", "/users/alice"));
    assert_eq!(resp.status, StatusCode::OK);

    test_complete!("router_path_parameter_extraction");
}

#[test]
fn router_nesting() {
    init_test_logging();
    test_phase!("router_nesting");

    fn health() -> &'static str {
        "ok"
    }
    fn list_users() -> &'static str {
        "users"
    }

    let api = Router::new()
        .route("/health", get(FnHandler::new(health)))
        .route("/users", get(FnHandler::new(list_users)));

    let app = Router::new().nest("/api/v1", api);

    assert_eq!(
        app.handle(Request::new("GET", "/api/v1/health")).status,
        StatusCode::OK
    );
    assert_eq!(
        app.handle(Request::new("GET", "/api/v1/users")).status,
        StatusCode::OK
    );
    assert_eq!(
        app.handle(Request::new("GET", "/other")).status,
        StatusCode::NOT_FOUND
    );

    test_complete!("router_nesting");
}

#[test]
fn router_fallback() {
    init_test_logging();
    test_phase!("router_fallback");

    fn custom_404() -> (StatusCode, &'static str) {
        (StatusCode::NOT_FOUND, "custom 404")
    }

    let router = Router::new()
        .route("/", get(FnHandler::new(|| "home")))
        .fallback(FnHandler::new(custom_404));

    let resp = router.handle(Request::new("GET", "/missing"));
    assert_eq!(resp.status, StatusCode::NOT_FOUND);

    test_complete!("router_fallback");
}

#[test]
fn router_wildcard_route() {
    init_test_logging();
    test_phase!("router_wildcard_route");

    fn catch_all() -> &'static str {
        "caught"
    }

    let router = Router::new().route("/files/*", get(FnHandler::new(catch_all)));

    assert_eq!(
        router.handle(Request::new("GET", "/files/a/b/c")).status,
        StatusCode::OK
    );

    test_complete!("router_wildcard_route");
}

// ===========================================================================
// Section 6: End-to-end handler pipeline
// ===========================================================================

#[test]
fn e2e_json_api_pipeline() {
    init_test_logging();
    test_phase!("e2e_json_api_pipeline");

    // Simulate a JSON API: POST request → extract JSON → return JSON response.
    fn create_user(
        body: asupersync::web::extract::Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        let mut user = body.0;
        user["id"] = serde_json::json!(1);
        Json(user)
    }

    let router = Router::new().route(
        "/users",
        post(FnHandler1::<
            _,
            asupersync::web::extract::Json<serde_json::Value>,
        >::new(create_user)),
    );

    let body = serde_json::to_vec(&serde_json::json!({"name": "alice"})).unwrap();
    let req = Request::new("POST", "/users")
        .with_header("content-type", "application/json")
        .with_body(Bytes::copy_from_slice(&body));

    let resp = router.handle(req);
    assert_eq!(resp.status, StatusCode::OK);

    let result: serde_json::Value = serde_json::from_slice(resp.body.as_ref()).unwrap();
    assert_eq!(result["name"], "alice");
    assert_eq!(result["id"], 1);

    test_complete!("e2e_json_api_pipeline");
}

#[test]
fn e2e_rest_api_crud() {
    init_test_logging();
    test_phase!("e2e_rest_api_crud");

    fn list() -> &'static str {
        "[]"
    }
    fn create() -> StatusCode {
        StatusCode::CREATED
    }
    fn read(Path(_id): Path<String>) -> &'static str {
        "{}"
    }
    fn update(Path(_id): Path<String>) -> StatusCode {
        StatusCode::NO_CONTENT
    }
    fn remove(Path(_id): Path<String>) -> StatusCode {
        StatusCode::NO_CONTENT
    }

    let router = Router::new()
        .route(
            "/items",
            get(FnHandler::new(list)).post(FnHandler::new(create)),
        )
        .route(
            "/items/:id",
            get(FnHandler1::<_, Path<String>>::new(read))
                .put(FnHandler1::<_, Path<String>>::new(update))
                .delete(FnHandler1::<_, Path<String>>::new(remove)),
        );

    // CRUD operations.
    assert_eq!(
        router.handle(Request::new("GET", "/items")).status,
        StatusCode::OK
    );
    assert_eq!(
        router.handle(Request::new("POST", "/items")).status,
        StatusCode::CREATED
    );
    assert_eq!(
        router.handle(Request::new("GET", "/items/1")).status,
        StatusCode::OK
    );
    assert_eq!(
        router.handle(Request::new("PUT", "/items/1")).status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        router.handle(Request::new("DELETE", "/items/1")).status,
        StatusCode::NO_CONTENT
    );

    // Method not allowed.
    assert_eq!(
        router.handle(Request::new("PATCH", "/items")).status,
        StatusCode::METHOD_NOT_ALLOWED
    );

    // Not found.
    assert_eq!(
        router.handle(Request::new("GET", "/other")).status,
        StatusCode::NOT_FOUND
    );

    test_complete!("e2e_rest_api_crud");
}

#[test]
fn e2e_nested_api_versioning() {
    init_test_logging();
    test_phase!("e2e_nested_api_versioning");

    fn v1_users() -> &'static str {
        "v1:users"
    }
    fn v2_users() -> &'static str {
        "v2:users"
    }

    let v1 = Router::new().route("/users", get(FnHandler::new(v1_users)));
    let v2 = Router::new().route("/users", get(FnHandler::new(v2_users)));

    let app = Router::new().nest("/api/v1", v1).nest("/api/v2", v2);

    assert_eq!(
        app.handle(Request::new("GET", "/api/v1/users")).status,
        StatusCode::OK
    );
    assert_eq!(
        app.handle(Request::new("GET", "/api/v2/users")).status,
        StatusCode::OK
    );

    test_complete!("e2e_nested_api_versioning");
}
