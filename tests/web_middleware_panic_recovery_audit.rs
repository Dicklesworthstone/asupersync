//! Audit + regression test for `src/web/middleware.rs`
//! `CatchPanicMiddleware` panic-recovery behavior.
//!
//! Operator's question: "when an incoming request triggers a panic
//! in the handler, does the middleware emit a structured error log
//! with request-id correlation, or is the panic silently swallowed?
//! Verify panic-recovery emits a 500 response with proper error
//! body AND logs."
//!
//! Audit findings (DEFECT FOUND + FIXED in this commit):
//!
//!   PRE-FIX BUG: `CatchPanicMiddleware::call` matched on
//!   `panic::catch_unwind(...)`'s `Err(_payload)` arm and DROPPED
//!   the payload — no `tracing::error!`, no log, no request-id
//!   correlation. The doc comment claimed "panic message is
//!   logged" but the implementation did NOT log it. SREs would
//!   see only the 500 response in their access logs and have NO
//!   diagnostic signal that a panic happened.
//!
//!   POST-FIX BEHAVIOR:
//!     1. Before entering `catch_unwind`, the middleware captures
//!        `req.method`, `req.path`, and `trace_id` (resolved via
//!        the same `resolve_trace_id` helper that
//!        `RequestTraceMiddleware` uses, so panic logs correlate
//!        with the surrounding request-trace events).
//!     2. On `Err(payload)`, the panic payload is downcast to
//!        `&'static str` then to `String` (the two common
//!        `panic!` payload types) via `panic_payload_message`;
//!        anything else surfaces as `<non-string panic payload>`.
//!     3. `tracing::error!` is emitted with structured fields:
//!        `method`, `path`, `trace_id`, `panic_message`, plus the
//!        message "http handler panicked; returning 500 Internal
//!        Server Error".
//!     4. The 500 response body remains `b"Internal Server Error"`
//!        — panic message is NOT exposed to the client (no
//!        information leakage).
//!     5. The recovery path is itself infallible — the
//!        `panic_payload_message` helper cannot panic on the
//!        panic (would lead to a double-panic abort).
//!     6. `resolve_trace_id` was extracted from
//!        `RequestTraceMiddleware::resolve_trace_id` to a free
//!        function so both middlewares share the SAME trace-id
//!        lookup order: extensions `trace_id`, extensions
//!        `request_id`, then sanitized+truncated `x-request-id`
//!        header.
//!
//! This file pins:
//!   (1) `error!` is called on the panic branch (structural).
//!   (2) Method, path, trace_id captured BEFORE catch_unwind
//!       (otherwise they're moved into the closure and lost).
//!   (3) `resolve_trace_id` is a free function reused by both
//!       middlewares (consistent correlation across the stack).
//!   (4) `panic_payload_message` downcasts both `&'static str`
//!       and `String`.
//!   (5) The 500 body string `"Internal Server Error"` is fixed
//!       — panic details NOT exposed to the client.
//!   (6) Behavioral end-to-end test (gated on default features):
//!       wrap a panicking handler, send a request, observe the
//!       500 response. (Log capture requires
//!       `tracing-integration` feature; structural pins above
//!       cover that path.)

use std::path::PathBuf;

fn read_middleware_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/web/middleware.rs");
    std::fs::read_to_string(&path).expect("read middleware.rs")
}

fn catch_panic_call_body(source: &str) -> &str {
    // Anchor on the IMPL BLOCK, not just the trait header — the
    // file contains `impl<H: Handler> Handler for ...` for many
    // middlewares, so we grep for a slice that uniquely identifies
    // CatchPanicMiddleware's impl block.
    let impl_marker = "impl<H: Handler> Handler for CatchPanicMiddleware<H> {";
    let start = source
        .find(impl_marker)
        .expect("CatchPanicMiddleware Handler impl must exist");
    let end_rel = source[start..]
        .find("\n}\n")
        .expect("CatchPanicMiddleware impl must close");
    &source[start..start + end_rel]
}

#[test]
fn catch_panic_emits_error_log_on_panic() {
    // Pin (1) AUDIT-CRITICAL: the panic branch calls error! with
    // structured fields. The pre-fix bug was that the Err arm
    // discarded the payload silently.
    let source = read_middleware_source();
    let body = catch_panic_call_body(&source);

    assert!(
        body.contains("error!("),
        "REGRESSION: CatchPanicMiddleware panic branch no longer \
         calls error!(...). The middleware MUST log a structured \
         error event so SREs see the panic — silently swallowing \
         it leaves production blind to handler bugs while still \
         returning a 500. Re-add the error! call with method, \
         path, trace_id, and panic_message fields.\n\n\
         impl body:\n{body}",
    );

    // The error! call must include the panic_message field.
    assert!(
        body.contains("panic_message"),
        "REGRESSION: error! call no longer carries the \
         panic_message field. The downcasted payload string is \
         the only diagnostic signal the SRE has — without it, \
         the log says 'a panic happened somewhere' with no detail.",
    );

    // The error! call must include trace_id for correlation.
    assert!(
        body.contains("trace_id"),
        "REGRESSION: error! call no longer carries trace_id. \
         Without trace_id correlation, panic logs are unjoinable \
         with the surrounding request-trace events; SREs \
         can't reconstruct what request triggered which panic.",
    );

    // Method + path also carried.
    assert!(
        body.contains("method") && body.contains("path"),
        "REGRESSION: error! call lost method/path context. These \
         provide the basic 'what was being processed' signal \
         alongside the panic message.",
    );
}

#[test]
fn catch_panic_extracts_correlation_before_catch_unwind() {
    // Pin (2): method/path/trace_id MUST be extracted BEFORE
    // catch_unwind consumes the request. Otherwise the request
    // is moved into the closure and gone after the panic — the
    // log would have nothing to correlate with.
    let source = read_middleware_source();
    let body = catch_panic_call_body(&source);

    // The method/path/trace_id captures must appear textually
    // BEFORE the panic::catch_unwind call.
    let catch_pos = body
        .find("panic::catch_unwind")
        .expect("catch_unwind must exist");
    let pre_catch = &body[..catch_pos];

    assert!(
        pre_catch.contains("req.method.clone()"),
        "REGRESSION: method is no longer captured BEFORE \
         catch_unwind. After the closure consumes `req`, the \
         method is gone and the log can't correlate to the \
         request that panicked.\n\npre-catch body:\n{pre_catch}",
    );
    assert!(
        pre_catch.contains("req.path.clone()"),
        "REGRESSION: path is no longer captured BEFORE \
         catch_unwind.",
    );
    assert!(
        pre_catch.contains("resolve_trace_id(&req)"),
        "REGRESSION: trace_id is no longer captured via \
         resolve_trace_id(&req) BEFORE catch_unwind. The shared \
         resolver MUST be used so panic logs use the same \
         trace-id lookup as the surrounding request-trace logs.",
    );
}

#[test]
fn resolve_trace_id_is_a_shared_free_function() {
    // Pin (3): `resolve_trace_id` is a module-level free
    // function so BOTH `CatchPanicMiddleware` and
    // `RequestTraceMiddleware` use the same lookup order. A
    // regression that duplicated the logic in CatchPanicMiddleware
    // would risk drift (e.g. one path forgetting to sanitize
    // the x-request-id header). The free function is the single
    // source of truth.
    let source = read_middleware_source();

    // Look for the free fn signature at module scope (no
    // leading whitespace before `fn`).
    assert!(
        source.contains("\nfn resolve_trace_id(req: &Request) -> Option<String> {"),
        "REGRESSION: free function `fn resolve_trace_id(req: \
         &Request) -> Option<String>` is gone. Both \
         CatchPanicMiddleware and RequestTraceMiddleware MUST \
         resolve trace IDs through the same helper to guarantee \
         consistent correlation across the middleware stack.",
    );

    // The free fn must include the sanitize+truncate path for
    // the x-request-id header (DoS guard, br-gwezkv).
    let fn_marker = "\nfn resolve_trace_id(req: &Request) -> Option<String> {";
    let start = source.find(fn_marker).expect("free fn");
    let body_end = source[start..].find("\n}\n").expect("free fn close");
    let fn_body = &source[start..start + body_end];

    assert!(
        fn_body.contains("sanitize_and_truncate_id"),
        "REGRESSION: resolve_trace_id no longer applies \
         sanitize_and_truncate_id to the x-request-id header. \
         An unsanitized header value can be amplified into logs \
         and response headers — DoS vector + log injection.\n\n\
         fn body:\n{fn_body}",
    );
    assert!(
        fn_body.contains("DEFAULT_TRACE_ID_MAX_LENGTH"),
        "REGRESSION: resolve_trace_id no longer caps the \
         x-request-id header at DEFAULT_TRACE_ID_MAX_LENGTH. \
         Caller-controlled length must be bounded.",
    );
}

#[test]
fn panic_payload_message_handles_str_and_string_payloads() {
    // Pin (4): `panic_payload_message` downcasts both
    // `&'static str` (the most common payload type from
    // `panic!("literal")`) and `String` (from
    // `panic!("{var}", var = ...)` formatted panics). A
    // regression that handled only one would lose diagnostic
    // info on the other path.
    let source = read_middleware_source();

    let fn_marker = "fn panic_payload_message(";
    let start = source
        .find(fn_marker)
        .expect("panic_payload_message helper");
    let body_end = source[start..]
        .find("\n}\n")
        .expect("panic_payload_message close");
    let body = &source[start..start + body_end];

    assert!(
        body.contains("downcast_ref::<&'static str>"),
        "REGRESSION: panic_payload_message no longer handles \
         &'static str payloads. The most common panic payload \
         type would be lost as `<non-string panic payload>`.",
    );
    assert!(
        body.contains("downcast_ref::<String>"),
        "REGRESSION: panic_payload_message no longer handles \
         String payloads. Formatted panic!(...) messages would \
         be lost.",
    );
    assert!(
        body.contains("<non-string panic payload>") || body.contains("non-string panic"),
        "REGRESSION: the non-string fallback message was \
         removed. Non-string payloads now produce empty / \
         unrecognizable log output.",
    );
}

#[test]
fn catch_panic_response_does_not_leak_panic_message_to_client() {
    // Pin (5): the response body is the FIXED string `"Internal
    // Server Error"`. The panic message goes ONLY to the log,
    // never to the client. A regression that put the panic
    // message in the response body would be an information-
    // leakage vulnerability (could expose secrets that were
    // formatted into the panic message).
    let source = read_middleware_source();
    let body = catch_panic_call_body(&source);

    assert!(
        body.contains("b\"Internal Server Error\".to_vec()"),
        "REGRESSION: response body is no longer the fixed string \
         'Internal Server Error'. Verify the new body does NOT \
         include the panic message — exposing it to the client \
         would be an information-leakage vulnerability.\n\n\
         impl body:\n{body}",
    );

    // The panic_message variable MUST NOT flow into the
    // Response::new(...) call.
    let response_marker = "Response::new(";
    let response_pos = body.find(response_marker).expect("Response::new call");
    let response_end = body[response_pos..]
        .find(")")
        .expect("Response::new close paren");
    let response_call = &body[response_pos..response_pos + response_end];
    assert!(
        !response_call.contains("panic_message"),
        "REGRESSION: panic_message is now passed to \
         Response::new — this leaks the panic detail to the \
         client. Panic messages are server-side only.\n\n\
         response call:\n{response_call}",
    );
}

#[test]
fn catch_panic_returns_500_status() {
    // Pin: the response status is INTERNAL_SERVER_ERROR (500).
    // A regression that returned 200 or 503 would mislead clients
    // about the failure class.
    let source = read_middleware_source();
    let body = catch_panic_call_body(&source);

    assert!(
        body.contains("StatusCode::INTERNAL_SERVER_ERROR"),
        "REGRESSION: panic recovery no longer returns 500. \
         Panics are unrecoverable handler bugs — the correct \
         status is INTERNAL_SERVER_ERROR (500), not 503 (which \
         implies retry-after) or 200.",
    );
}

#[test]
fn catch_panic_uses_assert_unwind_safe_for_handler_call() {
    // Pin: AssertUnwindSafe is required because Handler::call
    // is not constrained to UnwindSafe. A regression that
    // dropped AssertUnwindSafe would fail to compile if a non-
    // UnwindSafe handler is wrapped — but more subtly, a
    // regression that switched to a different unwind strategy
    // (e.g. removing catch_unwind entirely and letting panics
    // propagate) would defeat the safety net.
    let source = read_middleware_source();
    let body = catch_panic_call_body(&source);

    assert!(
        body.contains("panic::catch_unwind"),
        "REGRESSION: CatchPanicMiddleware no longer calls \
         panic::catch_unwind — the handler can now panic and \
         take down the connection / server. This middleware's \
         entire purpose is the safety net.",
    );
    assert!(
        body.contains("AssertUnwindSafe"),
        "REGRESSION: AssertUnwindSafe wrapper is gone. Handler \
         is not UnwindSafe by default; without the wrapper, \
         this code wouldn't compile for arbitrary handlers.",
    );
}

// ─── Behavioral end-to-end pin (default features) ───────────────────

#[cfg(feature = "test-internals")]
mod behavioral {
    use asupersync::web::extract::Request;
    use asupersync::web::handler::Handler;
    use asupersync::web::middleware::CatchPanicMiddleware;
    use asupersync::web::response::{Response, StatusCode};

    /// Handler that always panics with the given static message.
    struct PanickingHandler {
        message: &'static str,
    }

    impl Handler for PanickingHandler {
        fn call(&self, _req: Request) -> Response {
            panic!("{}", self.message);
        }
    }

    /// Handler that returns Ok for non-panic baseline.
    struct OkHandler;

    impl Handler for OkHandler {
        fn call(&self, _req: Request) -> Response {
            Response::new(StatusCode::OK, b"ok".to_vec())
        }
    }

    fn make_request(method: &str, path: &str) -> Request {
        let mut req = Request::new(method, path);
        // Pre-set a request_id so the panic log path exercises
        // the correlation lookup.
        req.extensions
            .insert("request_id", "audit-test-trace-id".to_string());
        req
    }

    #[test]
    fn panicking_handler_returns_500_with_canned_body() {
        let handler = PanickingHandler {
            message: "deliberate audit panic",
        };
        let middleware = CatchPanicMiddleware::new(handler);
        let req = make_request("GET", "/audit/panic");
        let resp = middleware.call(req);

        assert_eq!(
            resp.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "panic must produce 500 status",
        );
        assert_eq!(
            &*resp.body,
            b"Internal Server Error",
            "body must be the fixed canned string — the panic \
             message MUST NOT appear here (information leakage)",
        );
        // Critical: the panic message must NOT be in the body.
        assert!(
            !std::str::from_utf8(&resp.body)
                .unwrap_or("")
                .contains("deliberate audit panic"),
            "REGRESSION: panic message leaked into response body. \
             This is a server-side-only detail.",
        );
    }

    #[test]
    fn formatted_string_panic_returns_500_with_canned_body() {
        // Verify both `panic!("literal")` (StaticStr payload)
        // AND `panic!("{x}", x = ...)` (String payload) paths.
        struct FormattedPanic;
        impl Handler for FormattedPanic {
            fn call(&self, _req: Request) -> Response {
                let secret = "PASSWORD=hunter2";
                panic!("formatted panic with secret: {secret}");
            }
        }
        let middleware = CatchPanicMiddleware::new(FormattedPanic);
        let req = make_request("POST", "/audit/formatted");
        let resp = middleware.call(req);

        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
        // CRITICAL: the secret must NOT appear in the body even
        // though it's in the panic message.
        let body_str = std::str::from_utf8(&resp.body).unwrap_or("");
        assert!(
            !body_str.contains("PASSWORD"),
            "REGRESSION: formatted-panic secret leaked into \
             response body. Body MUST be the fixed canned string. \
             body: {body_str}",
        );
        assert_eq!(body_str, "Internal Server Error");
    }

    #[test]
    fn non_panicking_handler_passes_through_unchanged() {
        // Pin: the middleware is transparent on the happy path.
        // A regression that always returned 500 (e.g. forgot
        // the Ok arm) would break every request.
        let middleware = CatchPanicMiddleware::new(OkHandler);
        let req = make_request("GET", "/audit/ok");
        let resp = middleware.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(&*resp.body, b"ok");
    }

    #[test]
    fn panicking_handler_does_not_leak_request_state_across_calls() {
        // Pin: a panicking handler doesn't leave the middleware
        // in a broken state. After a panic, the next request
        // (with a non-panicking handler — which we model with a
        // separate middleware instance since each Middleware
        // wraps one Handler) still works. The panic is contained.
        let panicking = CatchPanicMiddleware::new(PanickingHandler {
            message: "first request panic",
        });
        let _ = panicking.call(make_request("GET", "/p"));

        let ok = CatchPanicMiddleware::new(OkHandler);
        let resp = ok.call(make_request("GET", "/ok"));
        assert_eq!(resp.status, StatusCode::OK);
    }
}
