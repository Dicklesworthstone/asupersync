#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::web::{middleware::CorsMiddleware, Request, Response, Handler};

/// Fuzz input for CORS Origin parsing under multi-Origin headers (RFC 6454)
#[derive(Arbitrary, Debug)]
struct CorsOriginFuzzInput {
    /// HTTP method
    method: HttpMethod,
    /// Request path
    path: String,
    /// Origin header scenarios to test RFC 6454 compliance
    origin_scenario: OriginHeaderScenario,
    /// Additional headers that might interact with Origin processing
    extra_headers: Vec<(String, String)>,
    /// CORS policy configuration
    cors_policy_type: CorsPolicyType,
}

#[derive(Arbitrary, Debug, Clone)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Options,
    Head,
    Patch,
}

impl HttpMethod {
    fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Head => "HEAD",
            HttpMethod::Patch => "PATCH",
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum OriginHeaderScenario {
    /// No Origin header (normal non-CORS request)
    NoOrigin,
    /// Single valid Origin header
    SingleOrigin { origin: String },
    /// Multiple Origin headers - RFC 6454 violation that should be handled gracefully
    MultipleOrigins { origins: Vec<String> },
    /// Single Origin with special characters/encoding
    MalformedOrigin { origin: String },
    /// Empty Origin header value
    EmptyOrigin,
    /// Origin with path (should be stripped per spec)
    OriginWithPath { scheme: String, host: String, port: Option<u16>, path: String },
    /// Origin with fragments/queries (invalid per RFC 6454)
    OriginWithExtras { base_origin: String, extras: String },
    /// Case variations (origins should be case-insensitive for host part)
    CaseVariation { origin: String },
}

#[derive(Arbitrary, Debug, Clone)]
enum CorsPolicyType {
    /// Allow any origin (*)
    AllowAny,
    /// Explicit allowlist
    ExactOrigins { allowed: Vec<String> },
    /// Allow with credentials
    AllowWithCredentials { allowed: Vec<String> },
}

/// Simple test handler that returns OK
struct TestHandler;

impl Handler for TestHandler {
    fn call(&self, _req: Request) -> Response {
        Response::new(asupersync::web::StatusCode::OK, b"ok".to_vec())
    }
}

fuzz_target!(|input: CorsOriginFuzzInput| {
    // Property 1: RFC 6454 compliance - multiple Origin headers should be handled safely
    test_multi_origin_rfc6454_compliance(&input);

    // Property 2: Origin parsing should not panic on malformed inputs
    test_origin_parsing_robustness(&input);

    // Property 3: CORS policy enforcement should be consistent
    test_cors_policy_consistency(&input);

    // Property 4: Header case-insensitivity requirements
    test_header_case_insensitivity(&input);
});

fn test_multi_origin_rfc6454_compliance(input: &CorsOriginFuzzInput) {
    let cors_policy = build_cors_policy(&input.cors_policy_type);
    let middleware = CorsMiddleware::new(TestHandler, cors_policy);

    let mut req = Request::new(input.method.as_str(), &input.path);

    // Add Origin headers based on scenario
    match &input.origin_scenario {
        OriginHeaderScenario::MultipleOrigins { origins } => {
            // RFC 6454 Section 7: "If the request contains multiple Origin header fields,
            // or if the Origin header field is malformed, then the user agent MUST NOT
            // include an Origin header field in the request."
            // Server should handle multiple Origin headers gracefully
            for origin in origins {
                req = req.with_header("Origin", origin);
            }
        }
        OriginHeaderScenario::SingleOrigin { origin } => {
            req = req.with_header("Origin", origin);
        }
        OriginHeaderScenario::MalformedOrigin { origin } => {
            req = req.with_header("Origin", origin);
        }
        OriginHeaderScenario::EmptyOrigin => {
            req = req.with_header("Origin", "");
        }
        OriginHeaderScenario::OriginWithPath { scheme, host, port, path } => {
            let origin = match port {
                Some(p) => format!("{}://{}:{}{}", scheme, host, p, path),
                None => format!("{}://{}{}", scheme, host, path),
            };
            req = req.with_header("Origin", &origin);
        }
        OriginHeaderScenario::OriginWithExtras { base_origin, extras } => {
            let origin = format!("{}{}", base_origin, extras);
            req = req.with_header("Origin", &origin);
        }
        OriginHeaderScenario::CaseVariation { origin } => {
            req = req.with_header("Origin", origin);
        }
        OriginHeaderScenario::NoOrigin => {
            // No Origin header added
        }
    }

    // Add extra headers
    for (name, value) in &input.extra_headers {
        req = req.with_header(name, value);
    }

    // Call middleware - should never panic
    let response = middleware.call(req);

    // Basic invariants that should always hold
    assert!(matches!(response.status,
        asupersync::web::StatusCode::OK |
        asupersync::web::StatusCode::NO_CONTENT |
        asupersync::web::StatusCode::FORBIDDEN
    ), "Response status should be valid HTTP status");
}

fn test_origin_parsing_robustness(input: &CorsOriginFuzzInput) {
    // Test that origin parsing doesn't panic on any input
    let cors_policy = build_cors_policy(&input.cors_policy_type);
    let middleware = CorsMiddleware::new(TestHandler, cors_policy);

    let mut req = Request::new(input.method.as_str(), &input.path);

    // Test with potentially malicious origin values
    match &input.origin_scenario {
        OriginHeaderScenario::MalformedOrigin { origin } => {
            req = req.with_header("Origin", origin);

            // Should handle malformed origins gracefully without panicking
            let _response = middleware.call(req);
        }
        _ => {
            // Test other scenarios for robustness
            if let Some((_, first_extra)) = input.extra_headers.first() {
                req = req.with_header("Origin", first_extra);
                let _response = middleware.call(req);
            }
        }
    }
}

fn test_cors_policy_consistency(input: &CorsOriginFuzzInput) {
    // Test that the same origin produces consistent results
    if let OriginHeaderScenario::SingleOrigin { origin } = &input.origin_scenario {
        let cors_policy = build_cors_policy(&input.cors_policy_type);
        let middleware = CorsMiddleware::new(TestHandler, cors_policy);

        let req1 = Request::new(input.method.as_str(), &input.path)
            .with_header("Origin", origin);
        let req2 = Request::new(input.method.as_str(), &input.path)
            .with_header("Origin", origin);

        let resp1 = middleware.call(req1);
        let resp2 = middleware.call(req2);

        // Same request should produce same CORS headers
        assert_eq!(
            resp1.headers.get("access-control-allow-origin"),
            resp2.headers.get("access-control-allow-origin"),
            "CORS policy should be deterministic for same origin"
        );
    }
}

fn test_header_case_insensitivity(input: &CorsOriginFuzzInput) {
    // Test that header names are case-insensitive per HTTP spec
    if let OriginHeaderScenario::SingleOrigin { origin } = &input.origin_scenario {
        let cors_policy = build_cors_policy(&input.cors_policy_type);
        let middleware = CorsMiddleware::new(TestHandler, cors_policy);

        let req_lower = Request::new(input.method.as_str(), &input.path)
            .with_header("origin", origin);
        let req_upper = Request::new(input.method.as_str(), &input.path)
            .with_header("ORIGIN", origin);
        let req_mixed = Request::new(input.method.as_str(), &input.path)
            .with_header("OrIgIn", origin);

        let resp_lower = middleware.call(req_lower);
        let resp_upper = middleware.call(req_upper);
        let resp_mixed = middleware.call(req_mixed);

        // All variations should be treated identically
        assert_eq!(
            resp_lower.headers.get("access-control-allow-origin"),
            resp_upper.headers.get("access-control-allow-origin"),
            "Origin header should be case-insensitive"
        );
        assert_eq!(
            resp_lower.headers.get("access-control-allow-origin"),
            resp_mixed.headers.get("access-control-allow-origin"),
            "Origin header should be case-insensitive"
        );
    }
}

fn build_cors_policy(policy_type: &CorsPolicyType) -> asupersync::web::middleware::CorsPolicy {
    use asupersync::web::middleware::{CorsPolicy, CorsAllowOrigin};

    match policy_type {
        CorsPolicyType::AllowAny => CorsPolicy::default(),
        CorsPolicyType::ExactOrigins { allowed } => {
            CorsPolicy::with_exact_origins(allowed.clone())
        }
        CorsPolicyType::AllowWithCredentials { allowed } => {
            CorsPolicy {
                allow_origin: CorsAllowOrigin::Exact(allowed.clone()),
                allow_credentials: true,
                ..Default::default()
            }
        }
    }
}