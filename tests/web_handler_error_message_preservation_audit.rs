//! Audit + regression test for `src/web/handler.rs` and
//! `src/web/response.rs` handler-error message preservation.
//!
//! Operator's question: "when handler returns Err with custom
//! Display, does the framework preserve the message (correct) or
//! replace with 'Internal Server Error' (incorrect — info loss)?
//! Per asupersync philosophy, errors must be surfaced. Trace
//! through the IntoResponse impl."
//!
//! Audit chain (response.rs:258-337, handler.rs:48-195):
//!
//!   (a) **`IntoResponse` trait** (response.rs:258-261) has a
//!       SINGLE required method `fn into_response(self) -> Response`.
//!       NO default body. NO fallback. The trait does not provide
//!       an "if implementer doesn't override, return 500" path.
//!
//!   (b) **`IntoResponse for Result<T, E>`**
//!       (response.rs:330-337) requires BOTH `T: IntoResponse`
//!       AND `E: IntoResponse`. The Err arm calls
//!       `err.into_response()` — verbatim delegation to the
//!       user's impl. No hardcoded 500. No "Internal Server
//!       Error" substitution.
//!
//!   (c) **No blanket `impl IntoResponse for E: Display/Error`**
//!       exists in the crate. A user's custom error type cannot
//!       implicitly satisfy `IntoResponse` via Display alone —
//!       they MUST write an explicit impl. This is a deliberate
//!       design choice: errors are explicit at the response
//!       boundary, not auto-converted.
//!
//!   (d) **Handler call sites** (handler.rs FnHandler /
//!       FnHandler1 / FnHandler2 / FnHandler3 / FnHandler4) call
//!       `(func)(...).into_response()`. The
//!       `Res: IntoResponse` bound flows through to the user's
//!       `Result<T, E>` return type, which then dispatches to
//!       the user's `IntoResponse for E` impl on the Err path.
//!
//!   (e) **The only `INTERNAL_SERVER_ERROR` references in
//!       handler.rs** are at handler.rs:260 (block_on_current_with_cx
//!       returning None — runtime contention, NOT a handler
//!       error) and handler.rs:276 (RuntimeBuilder::build
//!       failure — process-level setup error, NOT a handler
//!       error). Neither is on the user-error path.
//!
//! Verdict: **SOUND**. The framework does NOT replace handler
//! errors with "Internal Server Error". The Err message is
//! preserved verbatim by the user's IntoResponse impl, which the
//! framework calls by delegation. The type system enforces that
//! the user makes an explicit choice: there is no implicit
//! coercion path that loses information.
//!
//! A regression that:
//!   - added a blanket `impl<E: Display> IntoResponse for E` that
//!     emitted a hardcoded "Internal Server Error" body,
//!   - added a default body in the IntoResponse trait,
//!   - changed the Err arm of `IntoResponse for Result<T, E>` to
//!     ignore the user's impl,
//!   - introduced a wrapper type that lost Display content,
//!     would all be caught here.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).expect("read source file")
}

#[test]
fn into_response_trait_has_no_default_body() {
    // Pin (a): `fn into_response(self) -> Response;` is a
    // required method with no default. A regression that added
    // a default `{ Response::empty(StatusCode::INTERNAL_SERVER_ERROR) }`
    // would silently swallow custom error types that "forgot" to
    // override. The required-method discipline forces the user
    // to be explicit.
    let source = read("src/web/response.rs");

    let trait_marker = "pub trait IntoResponse {";
    let start = source.find(trait_marker).expect("IntoResponse trait");
    let end_rel = source[start..].find("\n}\n").expect("trait close");
    let body = &source[start..start + end_rel];

    // The required method MUST appear as a forward-declaration
    // (`fn ... -> Response;`) — NOT a default body
    // (`fn ... -> Response { ... }`).
    assert!(
        body.contains("fn into_response(self) -> Response;"),
        "REGRESSION: IntoResponse no longer declares \
         `fn into_response(self) -> Response;` as a required \
         method. A default body would silently swallow custom \
         error types. trait body:\n{body}",
    );
    assert!(
        !body.contains("fn into_response(self) -> Response {"),
        "REGRESSION: IntoResponse trait now has a DEFAULT body \
         for into_response. Custom error types that don't \
         override would silently use the default — info loss. \
         Required-method discipline must be preserved.",
    );
}

#[test]
fn result_impl_delegates_to_err_into_response() {
    // Pin (b) AUDIT-CRITICAL: `IntoResponse for Result<T, E>`
    // delegates to the user's E::into_response on the Err path.
    // A regression that hardcoded a 500 here would override the
    // user's custom error type.
    let source = read("src/web/response.rs");

    let impl_marker = "impl<T: IntoResponse, E: IntoResponse> IntoResponse for Result<T, E> {";
    let start = source.find(impl_marker).expect("Result IntoResponse impl");
    let end_rel = source[start..].find("\n}\n").expect("impl close");
    let body = &source[start..start + end_rel];

    // The Err arm must be `Err(err) => err.into_response()` —
    // NOT a hardcoded Response::new(500, ...) or
    // StatusCode::INTERNAL_SERVER_ERROR.
    assert!(
        body.contains("Err(err) => err.into_response()"),
        "REGRESSION: Result<T, E>::into_response no longer \
         delegates to err.into_response() on the Err path. The \
         user's custom error type's IntoResponse impl is the \
         single source of truth for error → response conversion. \
         A regression that hardcoded a 500 here would override \
         the user's intent and lose error message detail.\n\n\
         impl body:\n{body}",
    );
    assert!(
        !body.contains("INTERNAL_SERVER_ERROR"),
        "REGRESSION: Result<T, E>::into_response now references \
         INTERNAL_SERVER_ERROR. The Err path MUST be pure \
         delegation — let the user decide their error format. \
         impl body:\n{body}",
    );
    assert!(
        !body.contains("Internal Server Error"),
        "REGRESSION: Result<T, E>::into_response now contains \
         the literal 'Internal Server Error' string. This \
         silently overrides the user's error body. Restore the \
         delegation pattern.",
    );
}

#[test]
fn result_impl_requires_e_into_response_bound() {
    // Pin (c): the impl bound is `E: IntoResponse`, not
    // `E: Display` or `E: std::error::Error`. The type system
    // forces the user to opt in explicitly. A regression to
    // `E: Display` (with auto-conversion via to_string) or
    // `E: std::error::Error` (with auto-conversion via
    // Display + status 500) would let users accidentally rely
    // on a behavior they didn't choose.
    let source = read("src/web/response.rs");

    assert!(
        source.contains("impl<T: IntoResponse, E: IntoResponse> IntoResponse for Result<T, E> {"),
        "REGRESSION: the IntoResponse for Result<T, E> bound is \
         no longer `E: IntoResponse`. If a more permissive bound \
         (E: Display, E: Error) was added, the framework now \
         silently auto-converts errors and may drop Display \
         detail or override the user's intended status code. \
         Restore the explicit E: IntoResponse bound.",
    );
}

#[test]
fn no_blanket_impl_for_display_or_error() {
    // Pin (c) defense-in-depth: there is no blanket
    // `impl<E: Display> IntoResponse for E` or
    // `impl<E: std::error::Error> IntoResponse for E`. If such
    // an impl were added, every Display type would silently
    // gain an IntoResponse via the blanket — possibly with a
    // different (info-losing) format than the user intended.
    let source = read("src/web/response.rs");

    let suspect_blankets = [
        "impl<E: Display> IntoResponse",
        "impl<E: std::fmt::Display> IntoResponse",
        "impl<E: std::error::Error> IntoResponse",
        "impl<E: Error> IntoResponse",
        "impl<E> IntoResponse for E\nwhere\n    E: Display",
        "impl<E> IntoResponse for E\nwhere\n    E: std::error::Error",
    ];
    for pat in &suspect_blankets {
        assert!(
            !source.contains(pat),
            "REGRESSION: a blanket `{pat}` impl was added to \
             response.rs. This silently converts every Display \
             type to a Response with a framework-chosen format, \
             defeating the asupersync philosophy that errors \
             must be surfaced through explicit user impls. \
             Remove the blanket and require explicit \
             IntoResponse impls.",
        );
    }
}

#[test]
fn no_internal_server_error_substitution_in_handler_err_path() {
    // Pin (d)+(e): the FnHandler / FnHandler1..4 call sites do
    // NOT contain a hardcoded "Internal Server Error" message
    // for the user-handler-error path. The two
    // INTERNAL_SERVER_ERROR references in handler.rs are
    // runtime-level (block_on contention, runtime build
    // failure) — NOT user-error paths.
    let source = read("src/web/handler.rs");

    // Find every `INTERNAL_SERVER_ERROR` occurrence and verify
    // it is in a runtime / block_on context, not a handler-Err
    // arm.
    let mut search_pos = 0;
    while let Some(rel) = source[search_pos..].find("INTERNAL_SERVER_ERROR") {
        let abs = search_pos + rel;
        // Take a 400-char window before the marker as context.
        let ctx_start = abs.saturating_sub(400);
        let ctx = &source[ctx_start..abs];

        let is_runtime_path = ctx.contains("block_on_current_with_cx")
            || ctx.contains("RuntimeBuilder::current_thread")
            || ctx.contains("Runtime::current_handle");

        assert!(
            is_runtime_path,
            "REGRESSION: a new `INTERNAL_SERVER_ERROR` reference \
             appeared in handler.rs OUTSIDE the runtime / \
             block_on path. If this is in a user-handler-error \
             arm (e.g. an FnHandler dispatch), the framework is \
             now silently overriding user error messages with \
             'Internal Server Error' — info loss. Audit the new \
             site and revert if it's on the user-error \
             path.\n\ncontext (preceding 400 chars):\n{ctx}",
        );

        search_pos = abs + 1;
    }

    // Also: there must be no string literal "Internal Server
    // Error" anywhere in handler.rs (the canned body string is
    // owned by CatchPanicMiddleware in middleware.rs, NOT by
    // the dispatch path).
    assert!(
        !source.contains("\"Internal Server Error\""),
        "REGRESSION: the literal string \"Internal Server \
         Error\" appeared in handler.rs. This is a canned body \
         that — if used on the handler-Err path — would lose \
         the user's Display message. Verify the new site is \
         NOT on the handler dispatch path.",
    );
}

#[test]
fn fn_handler_call_dispatches_via_into_response() {
    // Pin (d): every FnHandler<N>::call path ends in
    // `.into_response()` — the conversion delegated to the
    // return type's IntoResponse impl. A regression that
    // pattern-matched on a Result return type and short-
    // circuited to a hardcoded 500 would bypass the user's
    // custom impl.
    let source = read("src/web/handler.rs");

    // Each FnHandler*::call (0..4 extractors) must end its
    // success path with `.into_response()`. We grep for the
    // pattern.
    let success_dispatch = "(func)";
    let occurrences: Vec<&str> = source
        .match_indices(success_dispatch)
        .map(|(idx, _)| {
            // Take the WHOLE LINE containing the dispatch site
            // (char-boundary safe; line-start scan goes up to
            // previous \n or BOF). The dispatch is always on a
            // single line, so this captures the full
            // `.into_response()` chain or the
            // `run_async_cx_handler(|cx| ...)` wrap.
            let line_start = source[..idx].rfind('\n').map_or(0, |p| p + 1);
            let line_end = source[idx..]
                .find('\n')
                .map_or(source.len(), |rel| idx + rel);
            &source[line_start..line_end]
        })
        .collect();

    // We expect at least 5 dispatches (FnHandler + FnHandler1..4)
    // — but the count may grow with async variants. Pin the
    // delegation pattern: every `(self.func)` invocation in a
    // sync handler dispatch is followed by `.into_response()`
    // somewhere in the next 200 chars.
    assert!(
        !occurrences.is_empty(),
        "REGRESSION: no `(func)` dispatch sites found in \
         handler.rs — the structure of FnHandler is gone."
    );
    for (i, snippet) in occurrences.iter().enumerate() {
        // Sync dispatches end directly in `.into_response()`.
        // Async dispatches go through
        // `run_async_cx_handler`, which itself
        // calls `.into_response()` (verified by a separate
        // pin in this file). Either pattern is acceptable.
        let direct = snippet.contains(".into_response()");
        let via_async_helper = snippet.contains("run_async_cx_handler");
        assert!(
            direct || via_async_helper,
            "REGRESSION: FnHandler dispatch site #{i} no longer \
             flows through .into_response() (sync) or \
             run_async_cx_handler (async). A \
             regression that hardcoded a Response here would \
             bypass the user's IntoResponse impl and lose \
             error message detail.\n\nsnippet:\n{snippet}",
        );
    }

    // Also pin: run_async_cx_handler itself ends
    // in .into_response() so the async path also delegates.
    let helper_marker = "fn run_async_cx_handler";
    let start = source.find(helper_marker).expect("async helper");
    let body_end = source[start..].find("\n}\n").expect("async helper close");
    let helper_body = &source[start..start + body_end];
    assert!(
        helper_body.contains(".into_response()")
            || helper_body.contains("IntoResponse::into_response"),
        "REGRESSION: run_async_cx_handler no \
         longer calls .into_response() on the handler's result. \
         The async dispatch path now bypasses the user's \
         IntoResponse impl. helper body:\n{helper_body}",
    );
}

// ─── Behavioral end-to-end pin (default features) ───────────────────

#[cfg(feature = "test-internals")]
mod behavioral {
    use asupersync::Cx;
    use asupersync::web::extract::Request;
    use asupersync::web::handler::{FnHandler, Handler};
    use asupersync::web::response::{IntoResponse, Response, StatusCode};
    use std::fmt;

    /// A custom error type with a Display impl that includes
    /// detail the framework MUST preserve.
    #[derive(Debug)]
    struct DomainError {
        code: u16,
        detail: String,
    }

    impl fmt::Display for DomainError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "DOMAIN_ERROR[{}]: {}", self.code, self.detail)
        }
    }

    /// Explicit IntoResponse impl that preserves the Display
    /// message in the body. This is the user's choice — the
    /// framework MUST honor it.
    impl IntoResponse for DomainError {
        fn into_response(self) -> Response {
            let body = self.to_string().into_bytes();
            Response::new(StatusCode::BAD_REQUEST, body)
        }
    }

    fn make_request() -> Request {
        Request::new("GET", "/audit/error")
    }

    trait SyncHandlerExt {
        fn call_sync(&self, req: Request) -> Response;
    }

    impl<H: Handler> SyncHandlerExt for H {
        fn call_sync(&self, req: Request) -> Response {
            futures_lite::future::block_on(Handler::call(self, &Cx::for_testing(), req))
        }
    }

    #[test]
    fn handler_returning_err_with_custom_display_preserves_message() {
        // Pin AUDIT-CRITICAL: a handler that returns
        // `Err(DomainError { ... })` has its Display message
        // preserved in the response body — NOT replaced by
        // "Internal Server Error".
        let handler = FnHandler::new(|| -> Result<&'static str, DomainError> {
            Err(DomainError {
                code: 4711,
                detail: "user-controlled detail must survive".to_string(),
            })
        });
        let resp = handler.call_sync(make_request());

        // Status reflects the user's choice (BAD_REQUEST), NOT
        // a framework-imposed 500.
        assert_eq!(
            resp.status,
            StatusCode::BAD_REQUEST,
            "user's chosen status code MUST be preserved; the \
             framework MUST NOT impose 500 on every Err",
        );

        // Body MUST contain the Display message verbatim.
        let body = std::str::from_utf8(&resp.body).expect("utf8");
        assert!(
            body.contains("DOMAIN_ERROR[4711]"),
            "REGRESSION: the user's Display prefix \
             'DOMAIN_ERROR[4711]' was stripped from the response \
             body. Errors must be surfaced — info loss is a \
             violation of asupersync philosophy. body: {body}",
        );
        assert!(
            body.contains("user-controlled detail must survive"),
            "REGRESSION: the user's Display detail was stripped \
             from the response body. body: {body}",
        );

        // The body MUST NOT be the canned "Internal Server
        // Error" string.
        assert!(
            !body.contains("Internal Server Error"),
            "REGRESSION: the framework substituted the canned \
             'Internal Server Error' string for the user's \
             custom Display message. Audit the IntoResponse \
             dispatch chain. body: {body}",
        );
    }

    #[test]
    fn handler_returning_ok_dispatches_through_t_into_response() {
        // Pin: the Ok arm dispatches through T::into_response
        // (not E). A regression that mishandled the Ok path
        // (e.g. always producing 500) would catastrophically
        // break every handler.
        let handler = FnHandler::new(|| -> Result<&'static str, DomainError> { Ok("hello") });
        let resp = handler.call_sync(make_request());

        assert_eq!(resp.status, StatusCode::OK);
        let body = std::str::from_utf8(&resp.body).expect("utf8");
        assert_eq!(body, "hello");
    }

    #[test]
    fn handler_with_status_code_tuple_preserves_user_status() {
        // Pin: a handler returning `(StatusCode, String)`
        // preserves both the user's status and the message
        // body — the (StatusCode, T) IntoResponse impl
        // delegates to T::into_response then overrides the
        // status. A regression that overrode the body too
        // would lose the message.
        let handler = FnHandler::new(|| -> (StatusCode, String) {
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeded 10 MiB cap".to_string(),
            )
        });
        let resp = handler.call_sync(make_request());

        assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE);
        let body = std::str::from_utf8(&resp.body).expect("utf8");
        assert!(
            body.contains("request body exceeded 10 MiB cap"),
            "tuple (StatusCode, String) IntoResponse must \
             preserve the body; got {body}",
        );
    }

    #[test]
    fn nested_result_preserves_error_through_chain() {
        // Pin: a handler whose return type is
        // `Result<Result<T, EInner>, EOuter>` resolves through
        // both impls correctly. The inner Err must propagate
        // its IntoResponse, not be re-wrapped or lost.
        let handler = FnHandler::new(
            || -> Result<Result<&'static str, DomainError>, DomainError> {
                Ok(Err(DomainError {
                    code: 4242,
                    detail: "nested error".to_string(),
                }))
            },
        );
        let resp = handler.call_sync(make_request());

        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
        let body = std::str::from_utf8(&resp.body).expect("utf8");
        assert!(
            body.contains("DOMAIN_ERROR[4242]") && body.contains("nested error"),
            "nested Err must preserve Display through both \
             Result impls; got {body}",
        );
    }
}
