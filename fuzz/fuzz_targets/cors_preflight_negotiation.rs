#![no_main]

//! Structure-aware CORS preflight negotiation fuzzer for `src/web/middleware.rs`.
//!
//! This target exercises the `CorsMiddleware` decision boundary between:
//! - simple requests vs. preflight requests,
//! - allowed vs. blocked origins,
//! - static allow-lists vs. wildcard header negotiation.
//!
//! The generated inputs are request/policy shapes rather than raw bytes so the
//! fuzzer spends cycles on meaningful Origin / Access-Control-Request-* edge
//! cases instead of random header soup.

use arbitrary::Arbitrary;
use asupersync::web::{
    FnHandler, Handler,
    extract::Request,
    middleware::{CorsAllowOrigin, CorsMiddleware, CorsPolicy},
    response::{Response, StatusCode},
};
use libfuzzer_sys::fuzz_target;

const MAX_LIST_LEN: usize = 6;
const MAX_TOKEN_LEN: usize = 24;

#[derive(Arbitrary, Debug, Clone)]
struct CorsFuzzInput {
    origin_mode: OriginMode,
    header_mode: HeaderMode,
    allow_credentials: bool,
    allowed_origins: Vec<OriginSpec>,
    allow_methods: Vec<MethodSpec>,
    explicit_allow_headers: Vec<HeaderToken>,
    request_method: MethodSpec,
    request_origin: RequestOriginMode,
    access_control_request_method: Option<MethodSpec>,
    access_control_request_headers: Vec<HeaderToken>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum OriginMode {
    Any,
    Exact,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum HeaderMode {
    Default,
    Any,
    Explicit,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum RequestOriginMode {
    Missing,
    Allowed,
    AllowedCaseMutated,
    Blocked,
}

#[derive(Arbitrary, Debug, Clone)]
struct OriginSpec {
    secure: bool,
    host: String,
    port: Option<u16>,
}

impl OriginSpec {
    fn render(&self) -> String {
        let scheme = if self.secure { "https" } else { "http" };
        let mut host = sanitize_host(&self.host);
        if host.is_empty() {
            host = "example".to_string();
        }
        let mut origin = format!("{scheme}://{host}.example");
        if let Some(port) = self.port {
            let port = 1 + (port % 49151);
            origin.push(':');
            origin.push_str(&port.to_string());
        }
        origin
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum MethodSpec {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
    Other(String),
}

impl MethodSpec {
    fn render(&self) -> String {
        match self {
            Self::Get => "GET".to_string(),
            Self::Post => "POST".to_string(),
            Self::Put => "PUT".to_string(),
            Self::Patch => "PATCH".to_string(),
            Self::Delete => "DELETE".to_string(),
            Self::Head => "HEAD".to_string(),
            Self::Options => "OPTIONS".to_string(),
            Self::Other(raw) => {
                let token = sanitize_token(raw, "X-FUZZ-METHOD");
                token.to_ascii_uppercase()
            }
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct HeaderToken {
    raw: String,
}

impl HeaderToken {
    fn render(&self) -> String {
        sanitize_token(&self.raw, "x-fuzz-header")
    }
}

fn inner_handler() -> Response {
    let mut resp = Response::empty(StatusCode::ACCEPTED);
    resp.set_header("x-inner", "called");
    resp.set_header("vary", "accept-language");
    resp
}

fn sanitize_host(raw: &str) -> String {
    raw.chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
        .take(MAX_TOKEN_LEN)
        .collect()
}

fn sanitize_token(raw: &str, fallback: &str) -> String {
    let value: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
        .take(MAX_TOKEN_LEN)
        .collect();
    if value.is_empty() {
        fallback.to_string()
    } else {
        value
    }
}

fn toggle_ascii_case(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_lowercase() {
                ch.to_ascii_uppercase()
            } else if ch.is_ascii_uppercase() {
                ch.to_ascii_lowercase()
            } else {
                ch
            }
        })
        .collect()
}

fn push_unique_case_insensitive(values: &mut Vec<String>, candidate: String) {
    if !values
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&candidate))
    {
        values.push(candidate);
    }
}

fn build_methods(input: &[MethodSpec]) -> Vec<String> {
    let mut methods = Vec::new();
    for method in input.iter().take(MAX_LIST_LEN) {
        push_unique_case_insensitive(&mut methods, method.render());
    }
    if methods.is_empty() {
        vec!["GET".to_string(), "POST".to_string(), "OPTIONS".to_string()]
    } else {
        methods
    }
}

fn build_headers(input: &[HeaderToken]) -> Vec<String> {
    let mut headers = Vec::new();
    for header in input.iter().take(MAX_LIST_LEN) {
        push_unique_case_insensitive(&mut headers, header.render());
    }
    if headers.is_empty() {
        vec!["X-Fuzz-Header".to_string()]
    } else {
        headers
    }
}

fn build_allowed_origins(input: &[OriginSpec]) -> Vec<String> {
    let mut origins = Vec::new();
    for origin in input.iter().take(MAX_LIST_LEN) {
        push_unique_case_insensitive(&mut origins, origin.render());
    }
    if origins.is_empty() {
        vec!["https://allowed.example".to_string()]
    } else {
        origins
    }
}

fn blocked_origin(allowed: &[String]) -> String {
    let mut blocked = "https://blocked.example".to_string();
    while allowed
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(&blocked))
    {
        blocked.push_str("-x");
    }
    blocked
}

fn request_origin(input: RequestOriginMode, allowed: &[String]) -> Option<String> {
    match input {
        RequestOriginMode::Missing => None,
        RequestOriginMode::Allowed => Some(
            allowed
                .first()
                .cloned()
                .unwrap_or_else(|| "https://allowed.example".to_string()),
        ),
        RequestOriginMode::AllowedCaseMutated => Some(toggle_ascii_case(
            allowed
                .first()
                .map(String::as_str)
                .unwrap_or("https://allowed.example"),
        )),
        RequestOriginMode::Blocked => Some(blocked_origin(allowed)),
    }
}

fn expected_allow_origin(policy: &CorsPolicy, origin: &str) -> Option<String> {
    match &policy.allow_origin {
        CorsAllowOrigin::Any => Some("*".to_string()),
        CorsAllowOrigin::Exact(origins) => origins
            .iter()
            .find(|candidate| candidate.eq_ignore_ascii_case(origin))
            .cloned(),
    }
}

fn vary_contains(resp: &Response, token: &str) -> bool {
    resp.headers.get("vary").is_some_and(|value| {
        value
            .split(',')
            .map(|part| part.trim())
            .any(|part| part.eq_ignore_ascii_case(token))
    })
}

fuzz_target!(|input: CorsFuzzInput| {
    let allowed_origins = build_allowed_origins(&input.allowed_origins);
    let allow_methods = build_methods(&input.allow_methods);

    // `Any + credentials` intentionally debug-asserts in CorsMiddleware::new,
    // so the fuzzer keeps credentialed cases on the exact-origin axis.
    let allow_credentials =
        input.allow_credentials && matches!(input.origin_mode, OriginMode::Exact);

    let allow_origin = if matches!(input.origin_mode, OriginMode::Any) {
        CorsAllowOrigin::Any
    } else {
        CorsAllowOrigin::Exact(allowed_origins.clone())
    };

    let allow_headers = match input.header_mode {
        HeaderMode::Default => CorsPolicy::default().allow_headers,
        HeaderMode::Any => vec!["*".to_string()],
        HeaderMode::Explicit => build_headers(&input.explicit_allow_headers),
    };

    let policy = CorsPolicy {
        allow_origin,
        allow_methods,
        allow_headers,
        expose_headers: Vec::new(),
        max_age: CorsPolicy::default().max_age,
        allow_credentials,
    };

    let request_method = input.request_method.render();
    let request_origin = request_origin(input.request_origin, &allowed_origins);
    let ac_request_method = input
        .access_control_request_method
        .as_ref()
        .map(MethodSpec::render);
    let requested_headers = build_headers(&input.access_control_request_headers);

    let mut req = Request::new(&request_method, "/cors-fuzz");
    if let Some(origin) = &request_origin {
        req = req.with_header("Origin", origin);
    }
    if let Some(method) = &ac_request_method {
        req = req.with_header("Access-Control-Request-Method", method);
    }
    if !requested_headers.is_empty() {
        req = req.with_header(
            "Access-Control-Request-Headers",
            requested_headers.join(", "),
        );
    }

    let mw = CorsMiddleware::new(FnHandler::new(inner_handler), policy.clone());
    let resp = mw.call(req);

    let expected_origin = request_origin
        .as_deref()
        .and_then(|origin| expected_allow_origin(&policy, origin));
    let is_preflight = request_method.eq_ignore_ascii_case("OPTIONS")
        && request_origin.is_some()
        && ac_request_method.is_some()
        && expected_origin.is_some();

    if is_preflight {
        assert_eq!(resp.status, StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers.get("access-control-allow-origin"),
            expected_origin.as_ref()
        );
        assert_eq!(
            resp.headers.get("access-control-allow-methods"),
            Some(&policy.allow_methods.join(", "))
        );
        assert_eq!(
            resp.headers.get("access-control-allow-headers"),
            Some(&policy.allow_headers.join(", "))
        );
        assert!(
            !resp.headers.contains_key("x-inner"),
            "preflight must short-circuit the inner handler"
        );
        assert!(vary_contains(&resp, "origin"));
        assert!(vary_contains(&resp, "access-control-request-method"));
        assert!(vary_contains(&resp, "access-control-request-headers"));
        if policy.allow_credentials {
            assert_eq!(
                resp.headers.get("access-control-allow-credentials"),
                Some(&"true".to_string())
            );
        } else {
            assert!(
                !resp
                    .headers
                    .contains_key("access-control-allow-credentials")
            );
        }
    } else {
        assert_eq!(resp.status, StatusCode::ACCEPTED);
        assert_eq!(resp.headers.get("x-inner"), Some(&"called".to_string()));

        match expected_origin {
            Some(expected_origin) => {
                assert_eq!(
                    resp.headers.get("access-control-allow-origin"),
                    Some(&expected_origin)
                );
                assert!(vary_contains(&resp, "origin"));
                assert!(vary_contains(&resp, "accept-language"));
                assert!(
                    !resp.headers.contains_key("access-control-allow-methods"),
                    "non-preflight requests must not advertise preflight methods"
                );
                assert!(
                    !resp.headers.contains_key("access-control-allow-headers"),
                    "non-preflight requests must not advertise preflight headers"
                );
                if policy.allow_credentials {
                    assert_eq!(
                        resp.headers.get("access-control-allow-credentials"),
                        Some(&"true".to_string())
                    );
                } else {
                    assert!(
                        !resp
                            .headers
                            .contains_key("access-control-allow-credentials")
                    );
                }
            }
            None => {
                assert!(
                    !resp.headers.contains_key("access-control-allow-origin"),
                    "blocked or origin-less requests must not get CORS allow-origin"
                );
                assert!(
                    !resp.headers.contains_key("access-control-allow-methods"),
                    "blocked requests must not get preflight method negotiation"
                );
                assert!(
                    !resp.headers.contains_key("access-control-allow-headers"),
                    "blocked requests must not get preflight header negotiation"
                );
                assert!(
                    !resp
                        .headers
                        .contains_key("access-control-allow-credentials")
                );
            }
        }
    }
});
