#![allow(warnings)]
//! Golden snapshot for the web middleware request/response chain.

use asupersync::combinator::rate_limit::{RateLimitPolicy, WaitStrategy};
use asupersync::types::Time;
use asupersync::web::extract::Request;
use asupersync::web::handler::Handler;
use asupersync::web::middleware::{
    AuthMiddleware, AuthPolicy, RateLimitMiddleware, RequestIdMiddleware, RequestTraceMiddleware,
    RequestTracePolicy,
};
use asupersync::web::response::{Response, StatusCode};
use insta::assert_json_snapshot;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

fn fixed_time() -> Time {
    Time::from_millis(42_000)
}

struct EchoChainHandler;

impl Handler for EchoChainHandler {
    fn call(&self, req: Request) -> Response {
        let payload = json!({
            "method": req.method,
            "path": req.path,
            "authorization": req.header("authorization"),
            "request_id": req.extensions.get("request_id"),
            "trace_id": req.extensions.get("trace_id"),
        });
        let body = serde_json::to_vec_pretty(&payload).expect("echo payload should serialize");
        Response::new(StatusCode::OK, body).header("x-handler", "echo")
    }
}

#[derive(Debug, Serialize)]
struct MiddlewareGolden {
    scenarios: Vec<MiddlewareScenario>,
}

#[derive(Debug, Serialize)]
struct MiddlewareScenario {
    name: &'static str,
    exchanges: Vec<MiddlewareExchange>,
}

#[derive(Debug, Serialize)]
struct MiddlewareExchange {
    label: &'static str,
    request: RequestSnapshot,
    response: ResponseSnapshot,
}

#[derive(Debug, Serialize)]
struct RequestSnapshot {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct ResponseSnapshot {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
}

fn snapshot_request(req: &Request) -> RequestSnapshot {
    RequestSnapshot {
        method: req.method.clone(),
        path: req.path.clone(),
        headers: req
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
    }
}

fn snapshot_response(resp: Response) -> ResponseSnapshot {
    ResponseSnapshot {
        status: resp.status.as_u16(),
        headers: resp.headers.into_iter().collect(),
        body: String::from_utf8_lossy(resp.body.as_ref()).into_owned(),
    }
}

fn build_pipeline(counter_start: u64) -> impl Handler {
    let rate_limit = RateLimitPolicy {
        name: "golden-web-pipeline".to_string(),
        rate: 1,
        period: Duration::from_secs(1),
        burst: 1,
        wait_strategy: WaitStrategy::Reject,
        default_cost: 1,
        ..RateLimitPolicy::default()
    };

    let rate_limited =
        RateLimitMiddleware::with_time_getter(EchoChainHandler, rate_limit, fixed_time);
    let authed = AuthMiddleware::new(rate_limited, AuthPolicy::exact_bearer("token-123"));
    let traced =
        RequestTraceMiddleware::with_time_getter(authed, RequestTracePolicy::default(), fixed_time);

    RequestIdMiddleware::shared(
        traced,
        "x-request-id",
        Arc::new(AtomicU64::new(counter_start)),
    )
}

#[test]
fn request_response_chain() {
    let happy_pipeline = build_pipeline(41);
    let happy_request =
        Request::new("GET", "/golden/happy").with_header("authorization", "Bearer token-123");
    let happy_response = happy_pipeline.call(happy_request.clone());

    let auth_fail_pipeline = build_pipeline(70);
    let auth_fail_request =
        Request::new("GET", "/golden/auth-fail").with_header("x-request-id", "client-auth-7");
    let auth_fail_response = auth_fail_pipeline.call(auth_fail_request.clone());

    let rate_limit_pipeline = build_pipeline(90);
    let rate_limit_warmup =
        Request::new("GET", "/golden/rate-limit").with_header("authorization", "Bearer token-123");
    let rate_limit_warmup_response = rate_limit_pipeline.call(rate_limit_warmup.clone());
    let rate_limit_request =
        Request::new("GET", "/golden/rate-limit").with_header("authorization", "Bearer token-123");
    let rate_limit_response = rate_limit_pipeline.call(rate_limit_request.clone());

    let golden = MiddlewareGolden {
        scenarios: vec![
            MiddlewareScenario {
                name: "happy_path",
                exchanges: vec![MiddlewareExchange {
                    label: "authorized_request",
                    request: snapshot_request(&happy_request),
                    response: snapshot_response(happy_response),
                }],
            },
            MiddlewareScenario {
                name: "auth_fail",
                exchanges: vec![MiddlewareExchange {
                    label: "missing_bearer_token",
                    request: snapshot_request(&auth_fail_request),
                    response: snapshot_response(auth_fail_response),
                }],
            },
            MiddlewareScenario {
                name: "rate_limit",
                exchanges: vec![
                    MiddlewareExchange {
                        label: "warmup_allowed",
                        request: snapshot_request(&rate_limit_warmup),
                        response: snapshot_response(rate_limit_warmup_response),
                    },
                    MiddlewareExchange {
                        label: "second_request_rejected",
                        request: snapshot_request(&rate_limit_request),
                        response: snapshot_response(rate_limit_response),
                    },
                ],
            },
        ],
    };

    assert_json_snapshot!("request_response_chain", golden);
}
