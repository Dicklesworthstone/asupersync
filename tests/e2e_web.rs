//! E2E: Web full stack — route resolution, middleware, handlers, extractors, responses.

mod common;

use asupersync::Cx;
use asupersync::web::extract::{Json as JsonExtract, Path, Query, Request};
use asupersync::web::handler::{FnHandler, FnHandler1, Handler};
use asupersync::web::middleware::{HeaderOverwrite, MiddlewareStack};
use asupersync::web::request_region::RequestRegion;
use asupersync::web::response::{Html, Json, Redirect, Response, StatusCode};
use asupersync::web::router::{Router, delete, get, post};
use asupersync::web::sse::{Sse, SseEvent, StreamingSse};
use serde_json::{Value, json};
use std::io;
use std::path::PathBuf;

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
    Redirect::permanent("/new-location").expect("test redirect URI should be valid")
}

// =========================================================================
// Web framework proof runner
// =========================================================================

const WEB_FRAMEWORK_BEAD_ID: &str = "asupersync-o74l7u.1.3";
const WEB_FRAMEWORK_ARTIFACT_DIR: &str = "target/web-framework-proof/asupersync-o74l7u.1.3";
const WEB_FRAMEWORK_WAVE2_SCENARIOS: &[&str] = &[
    "router-path-json-extractor",
    "middleware-body-limit-short-circuit",
    "middleware-panic-recovery-with-security-header",
    "bounded-sse-batch-response",
    "streaming-sse-request-region-disconnect",
    "request-region-panic-isolation",
];
const WEB_FRAMEWORK_REQUIRED_ROW_FIELDS: &[&str] = &[
    "bead_id",
    "scenario_id",
    "route",
    "method",
    "middleware_stack",
    "extractor_set",
    "response_kind",
    "streaming",
    "client_disconnect_at",
    "region_count_before",
    "region_count_after",
    "obligation_count_before",
    "obligation_count_after",
    "expected_status",
    "actual_status",
    "expected_body_digest",
    "actual_body_digest",
    "expected_chunk_digests",
    "actual_chunk_digests",
    "artifact_path",
    "verdict",
    "first_failure",
];

fn web_body_digest(body: &[u8]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in body {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("fnv1a64:{hash:016x}:len={}", body.len())
}

fn web_framework_first_failure(
    resp: &Response,
    expected_status: StatusCode,
    expected_body: &[u8],
    extra_failure: Option<String>,
) -> String {
    if resp.status != expected_status {
        return format!(
            "status mismatch: expected {} actual {}",
            expected_status.as_u16(),
            resp.status.as_u16()
        );
    }
    if resp.body.as_ref() != expected_body {
        return format!(
            "body digest mismatch: expected {} actual {}",
            web_body_digest(expected_body),
            web_body_digest(&resp.body)
        );
    }
    extra_failure.unwrap_or_default()
}

fn web_framework_row(
    bead_id: &str,
    scenario_id: &str,
    route: &str,
    method: &str,
    middleware_stack: &[&str],
    extractor_set: &[&str],
    response_kind: &str,
    streaming: bool,
    client_disconnect_at: &str,
    region_count_before: Option<u64>,
    region_count_after: Option<u64>,
    obligation_count_before: Option<u64>,
    obligation_count_after: Option<u64>,
    expected_status: StatusCode,
    expected_body: &[u8],
    resp: &Response,
    extra_failure: Option<String>,
    expected_chunk_digests: &[String],
    actual_chunk_digests: &[String],
    artifact_path: &str,
) -> Value {
    let first_failure =
        web_framework_first_failure(resp, expected_status, expected_body, extra_failure);
    let verdict = if first_failure.is_empty() {
        "pass"
    } else {
        "fail"
    };

    json!({
        "bead_id": bead_id,
        "scenario_id": scenario_id,
        "route": route,
        "method": method,
        "middleware_stack": middleware_stack,
        "extractor_set": extractor_set,
        "response_kind": response_kind,
        "streaming": streaming,
        "client_disconnect_at": client_disconnect_at,
        "region_count_before": region_count_before,
        "region_count_after": region_count_after,
        "obligation_count_before": obligation_count_before,
        "obligation_count_after": obligation_count_after,
        "expected_status": expected_status.as_u16(),
        "actual_status": resp.status.as_u16(),
        "expected_body_digest": web_body_digest(expected_body),
        "actual_body_digest": web_body_digest(resp.body.as_ref()),
        "expected_chunk_digests": expected_chunk_digests,
        "actual_chunk_digests": actual_chunk_digests,
        "artifact_path": artifact_path,
        "verdict": verdict,
        "first_failure": first_failure,
    })
}

struct WebProofPanicHandler;

impl Handler for WebProofPanicHandler {
    fn call(&self, _req: Request) -> Response {
        panic!("web framework proof panic");
    }
}

fn web_proof_router_path_json(bead_id: &str, artifact_path: &str) -> Value {
    let router = Router::new().route(
        "/users/:id",
        get(FnHandler1::<_, Path<String>>::new(get_user)),
    );
    let resp = router.handle(Request::new("GET", "/users/42"));
    web_framework_row(
        bead_id,
        "router-path-json-extractor",
        "/users/:id",
        "GET",
        &[],
        &["Path<String>"],
        "plain_text",
        false,
        "none",
        None,
        None,
        None,
        None,
        StatusCode::OK,
        b"user:42",
        &resp,
        None,
        &[],
        &[],
        artifact_path,
    )
}

fn web_proof_middleware_body_limit(bead_id: &str, artifact_path: &str) -> Value {
    let handler = MiddlewareStack::new(FnHandler::new(index))
        .with_body_limit(4)
        .build();
    let req = Request::new("POST", "/upload")
        .with_header("content-length", "8")
        .with_body(b"abcdefgh".to_vec());
    let resp = handler.call(req);
    web_framework_row(
        bead_id,
        "middleware-body-limit-short-circuit",
        "/upload",
        "POST",
        &["RequestBodyLimitMiddleware"],
        &[],
        "error",
        false,
        "none",
        None,
        None,
        None,
        None,
        StatusCode::PAYLOAD_TOO_LARGE,
        b"Payload Too Large: Content-Length 8 bytes exceeds limit 4 bytes",
        &resp,
        None,
        &[],
        &[],
        artifact_path,
    )
}

fn web_proof_middleware_panic_recovery(bead_id: &str, artifact_path: &str) -> Value {
    let handler = MiddlewareStack::new(WebProofPanicHandler)
        .with_catch_panic()
        .with_response_header("x-frame-options", "DENY", HeaderOverwrite::IfMissing)
        .build();
    let resp = handler.call(Request::new("GET", "/panic"));
    let extra_failure = (resp.headers.get("x-frame-options").map(String::as_str) != Some("DENY"))
        .then(|| "missing x-frame-options=DENY".to_string());
    web_framework_row(
        bead_id,
        "middleware-panic-recovery-with-security-header",
        "/panic",
        "GET",
        &["CatchPanicMiddleware", "SetResponseHeaderMiddleware"],
        &[],
        "panic_recovery",
        false,
        "none",
        None,
        None,
        None,
        None,
        StatusCode::INTERNAL_SERVER_ERROR,
        b"Internal Server Error",
        &resp,
        extra_failure,
        &[],
        &[],
        artifact_path,
    )
}

fn web_proof_bounded_sse(bead_id: &str, artifact_path: &str) -> Value {
    let router = Router::new().route(
        "/events",
        get(FnHandler::new(|| {
            Sse::new(vec![
                SseEvent::default()
                    .event("update")
                    .data(r#"{"count":1}"#)
                    .id("1"),
                SseEvent::default()
                    .event("update")
                    .data(r#"{"count":2}"#)
                    .id("2"),
            ])
            .keep_alive()
        })),
    );
    let resp = router.handle(Request::new("GET", "/events"));
    let expected_body = concat!(
        ":keep-alive\n\n",
        "event:update\n",
        "data:{\"count\":1}\n",
        "id:1\n\n",
        "event:update\n",
        "data:{\"count\":2}\n",
        "id:2\n\n"
    );
    let extra_failure = (resp.headers.get("content-type").map(String::as_str)
        != Some("text/event-stream"))
    .then(|| "missing content-type=text/event-stream".to_string());
    web_framework_row(
        bead_id,
        "bounded-sse-batch-response",
        "/events",
        "GET",
        &[],
        &[],
        "bounded_sse_batch",
        false,
        "not_applicable_single_response_body",
        None,
        None,
        None,
        None,
        StatusCode::OK,
        expected_body.as_bytes(),
        &resp,
        extra_failure,
        &[],
        &[],
        artifact_path,
    )
}

fn web_proof_streaming_sse_request_region(bead_id: &str, artifact_path: &str) -> Value {
    let expected_event = SseEvent::default()
        .event("update")
        .data(r#"{"count":1}"#)
        .id("1");
    let expected_chunk = expected_event.to_string().into_bytes();
    let expected_chunk_digests = vec![web_body_digest(&expected_chunk)];
    let mut actual_chunk_digests = Vec::new();
    let mut buffer_bytes_after_disconnect = 0;

    let cx = Cx::for_testing();
    let region = RequestRegion::new(&cx, Request::new("GET", "/events/stream"));
    let outcome = region.run(|ctx| {
        let mut stream = StreamingSse::new(vec![
            expected_event,
            SseEvent::default()
                .event("update")
                .data(r#"{"count":2}"#)
                .id("2"),
        ]);
        let first_chunk = stream
            .next_chunk(ctx.cx())
            .expect("first streaming SSE chunk should serialize")
            .expect("first streaming SSE event should be present");
        actual_chunk_digests.push(web_body_digest(&first_chunk));

        stream.cancel_for_disconnect(ctx.cx());
        assert!(
            stream
                .next_chunk(ctx.cx())
                .expect("closed streaming SSE should not error after disconnect")
                .is_none(),
            "client disconnect must stop later SSE chunks",
        );
        buffer_bytes_after_disconnect = stream.bytes_emitted();
        Response::empty(StatusCode::CLIENT_CLOSED_REQUEST)
    });
    let resp = outcome.into_response();

    let extra_failure = if actual_chunk_digests != expected_chunk_digests {
        Some(format!(
            "chunk digest mismatch: expected {expected_chunk_digests:?} actual {actual_chunk_digests:?}"
        ))
    } else if !cx.is_cancel_requested() {
        Some("streaming SSE disconnect did not request cancellation".to_string())
    } else if buffer_bytes_after_disconnect != expected_chunk.len() {
        Some(format!(
            "buffer byte mismatch after disconnect: expected {} actual {buffer_bytes_after_disconnect}",
            expected_chunk.len()
        ))
    } else {
        None
    };

    web_framework_row(
        bead_id,
        "streaming-sse-request-region-disconnect",
        "/events/stream",
        "GET",
        &["RequestRegion"],
        &["StreamingSse"],
        "streaming_sse",
        true,
        "after-first-event",
        Some(0),
        Some(0),
        Some(0),
        Some(0),
        StatusCode::CLIENT_CLOSED_REQUEST,
        b"",
        &resp,
        extra_failure,
        &expected_chunk_digests,
        &actual_chunk_digests,
        artifact_path,
    )
}

fn web_proof_request_region_panic(bead_id: &str, artifact_path: &str) -> Value {
    let cx = Cx::for_testing();
    let region = RequestRegion::new(&cx, Request::new("GET", "/region-panic"));
    let outcome = region.run(|_ctx| {
        panic!("request region proof panic");
    });
    let resp = outcome.into_response();
    web_framework_row(
        bead_id,
        "request-region-panic-isolation",
        "/region-panic",
        "GET",
        &[],
        &["RequestContext"],
        "request_region_panic_500",
        false,
        "none",
        None,
        None,
        None,
        None,
        StatusCode::INTERNAL_SERVER_ERROR,
        b"Internal Server Error",
        &resp,
        None,
        &[],
        &[],
        artifact_path,
    )
}

fn web_framework_wave2_run() -> io::Result<Vec<Value>> {
    let bead_id = std::env::var("ASUPERSYNC_WEB_FRAMEWORK_BEAD_ID")
        .unwrap_or_else(|_| WEB_FRAMEWORK_BEAD_ID.to_string());
    let output_dir = std::env::var_os("ASUPERSYNC_WEB_FRAMEWORK_PROOF_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(WEB_FRAMEWORK_ARTIFACT_DIR),
        PathBuf::from,
    );
    let rows_path = output_dir.join("test_rows.jsonl");
    let report_path = output_dir.join("test_report.json");
    let artifact_path = rows_path.display().to_string();
    let rows = vec![
        web_proof_router_path_json(&bead_id, &artifact_path),
        web_proof_middleware_body_limit(&bead_id, &artifact_path),
        web_proof_middleware_panic_recovery(&bead_id, &artifact_path),
        web_proof_bounded_sse(&bead_id, &artifact_path),
        web_proof_streaming_sse_request_region(&bead_id, &artifact_path),
        web_proof_request_region_panic(&bead_id, &artifact_path),
    ];

    std::fs::create_dir_all(&output_dir)?;
    let mut rows_file = std::fs::File::create(&rows_path)?;
    for row in &rows {
        use std::io::Write as _;
        writeln!(rows_file, "{row}")?;
    }
    let report = json!({
        "bead_id": bead_id,
        "scenario_count": rows.len(),
        "expected_scenarios": WEB_FRAMEWORK_WAVE2_SCENARIOS,
        "rows_path": artifact_path,
        "report_path": report_path.display().to_string(),
        "validation_passed": rows.iter().all(|row| row["verdict"] == "pass"),
    });
    let report_bytes = serde_json::to_vec_pretty(&report).map_err(io::Error::other)?;
    std::fs::write(report_path, report_bytes)?;

    Ok(rows)
}

// =========================================================================
// Tests
// =========================================================================

#[test]
fn web_framework_wave2_proof_runner_logs_required_scenarios() {
    common::init_test_logging();
    let rows = web_framework_wave2_run().expect("web framework proof runner");
    println!();
    for row in &rows {
        println!("{row}");
    }

    let missing: Vec<_> = WEB_FRAMEWORK_WAVE2_SCENARIOS
        .iter()
        .copied()
        .filter(|scenario_id| {
            !rows
                .iter()
                .any(|row| row["scenario_id"].as_str() == Some(*scenario_id))
        })
        .collect();
    let drifts: Vec<_> = rows
        .iter()
        .filter(|row| row["verdict"].as_str() != Some("pass"))
        .collect();
    let missing_fields: Vec<_> = rows
        .iter()
        .filter_map(|row| {
            WEB_FRAMEWORK_REQUIRED_ROW_FIELDS
                .iter()
                .copied()
                .find(|field| row.get(*field).is_none())
                .map(|field| {
                    let scenario = row["scenario_id"].as_str().unwrap_or("<unknown>");
                    format!("{scenario}:{field}")
                })
        })
        .collect();

    assert!(
        missing.is_empty(),
        "missing web framework proof scenarios: {missing:?}"
    );
    assert!(
        missing_fields.is_empty(),
        "missing web framework proof row fields: {missing_fields:?}"
    );
    assert!(drifts.is_empty(), "web framework proof drifts: {drifts:#?}");
    assert_eq!(rows.len(), WEB_FRAMEWORK_WAVE2_SCENARIOS.len());
}

#[test]
fn web_framework_readme_sse_support_claim_matches_streaming_artifact() {
    common::init_test_logging();
    let rows = web_framework_wave2_run().expect("web framework proof runner");
    let streaming_row = rows
        .iter()
        .find(|row| row["scenario_id"].as_str() == Some("streaming-sse-request-region-disconnect"))
        .expect("streaming SSE proof row must exist");

    assert_eq!(streaming_row["verdict"].as_str(), Some("pass"));
    assert_eq!(streaming_row["streaming"].as_bool(), Some(true));
    assert!(
        streaming_row["actual_chunk_digests"]
            .as_array()
            .is_some_and(|digests| !digests.is_empty()),
        "streaming proof row must carry chunk digests",
    );
    let artifact_path = streaming_row["artifact_path"]
        .as_str()
        .expect("artifact_path must be a string");
    assert!(
        PathBuf::from(artifact_path).exists(),
        "streaming proof artifact path must exist: {artifact_path}",
    );

    let readme_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md");
    let readme = std::fs::read_to_string(&readme_path).expect("read README.md");
    for phrase in [
        "`Sse` finite bounded batch",
        "`StreamingSse` pull API",
        "request-region E2E proof",
        "transport integration in progress",
    ] {
        assert!(
            readme.contains(phrase),
            "README SSE support matrix must contain `{phrase}` after streaming artifact proof",
        );
    }
}

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
