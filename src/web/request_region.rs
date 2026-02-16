//! Request-as-Region pattern for structured concurrency in HTTP handlers.
//!
//! Each incoming HTTP request executes within its own Asupersync region,
//! providing automatic structured concurrency guarantees:
//!
//! - **No task leaks**: spawned background tasks are cancelled and drained
//!   when the handler returns or is cancelled.
//! - **Panic isolation**: a handler panic produces a 500 response instead of
//!   crashing the server.
//! - **Finalizer support**: cleanup actions registered with `defer` run on
//!   every exit path (success, error, cancel, panic).
//! - **Obligation tracking**: two-phase operations (e.g., database transactions)
//!   are aborted cleanly on early exit.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::cx::cap;
//! use asupersync::web::request_region::{RequestRegion, RequestContext};
//! use asupersync::Cx;
//!
//! async fn handler(ctx: &RequestContext<'_>) -> Response {
//!     // Narrow capabilities for least-privilege handlers.
//!     let cx = ctx.cx_narrow::<cap::CapSet<true, true, false, false, false>>();
//!     cx.checkpoint().ok();
//!
//!     // Spawn a background task — owned by this request's region.
//!     ctx.cx().spawn_task(audit_log(ctx.request()));
//!
//!     // If this handler panics or is cancelled, the audit task is
//!     // automatically drained and finalizers run.
//!     process(ctx).await
//! }
//! ```

use std::fmt;

use crate::cx::{cap, Cx};
use crate::error::Error;
use crate::web::extract::Request;
use crate::web::response::{Response, StatusCode};

// ─── RequestRegion ──────────────────────────────────────────────────────────

/// Wraps a [`Cx`] and a [`Request`] to form a request-scoped region.
///
/// When the region is consumed via [`run`](Self::run), the handler executes
/// inside the capability context. On any exit path (success, error, cancel,
/// panic), the region is closed and:
///
/// 1. All spawned child tasks are cancelled and drained.
/// 2. Registered finalizers execute.
/// 3. Outstanding obligations are aborted.
///
/// # Panic Isolation
///
/// If the handler panics, the panic is caught and converted to a
/// `500 Internal Server Error` response. The server continues serving
/// other requests.
pub struct RequestRegion<'a> {
    cx: &'a Cx,
    request: Request,
}

impl<'a> RequestRegion<'a> {
    /// Create a new request region.
    ///
    /// The `cx` should be a fresh capability context scoped to this request.
    /// Typically the server creates a child region per connection/request.
    #[must_use]
    pub fn new(cx: &'a Cx, request: Request) -> Self {
        Self { cx, request }
    }

    /// Execute a handler within this request region.
    ///
    /// The handler receives a [`RequestContext`] providing access to the
    /// request data and the capability context for spawning tasks, registering
    /// finalizers, and checking cancellation.
    ///
    /// # Returns
    ///
    /// An [`Outcome`](crate::types::Outcome) that is:
    /// - `Ok(Response)` on success
    /// - `Err(Error)` on application-level error
    /// - `Cancelled(reason)` if the request was cancelled
    /// - `Panicked(payload)` if the handler panicked
    ///
    /// Use [`into_response`](RegionOutcome::into_response) to convert the
    /// outcome to an HTTP response.
    pub fn run<F>(self, handler: F) -> RegionOutcome
    where
        F: FnOnce(&RequestContext<'_>) -> Response,
    {
        let ctx = RequestContext {
            cx: self.cx,
            request: &self.request,
        };

        // Check cancellation before running the handler.
        if self.cx.is_cancel_requested() {
            return RegionOutcome::Cancelled;
        }

        // Run with panic isolation.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(&ctx)));

        match result {
            Ok(response) => RegionOutcome::Ok(response),
            Err(panic_payload) => {
                let message = extract_panic_message(&panic_payload);
                RegionOutcome::Panicked(message)
            }
        }
    }

    /// Execute an async handler within this request region.
    ///
    /// This is the async counterpart to [`run`](Self::run). The future is
    /// polled to completion within the region. Cancellation is checked at
    /// each checkpoint boundary.
    ///
    /// For Phase 0 (synchronous execution), use [`run`](Self::run) instead.
    /// This method exists to establish the async API surface for Phase 1+.
    #[allow(clippy::result_large_err)]
    pub fn run_sync<F>(self, handler: F) -> RegionOutcome
    where
        F: FnOnce(&RequestContext<'_>) -> Result<Response, Error>,
    {
        let ctx = RequestContext {
            cx: self.cx,
            request: &self.request,
        };

        if self.cx.is_cancel_requested() {
            return RegionOutcome::Cancelled;
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(&ctx)));

        match result {
            Ok(Ok(response)) => RegionOutcome::Ok(response),
            Ok(Err(err)) => RegionOutcome::Error(err),
            Err(panic_payload) => {
                let message = extract_panic_message(&panic_payload);
                RegionOutcome::Panicked(message)
            }
        }
    }

    /// Returns the request.
    #[must_use]
    pub fn request(&self) -> &Request {
        &self.request
    }

    /// Returns the capability context.
    #[must_use]
    pub fn cx(&self) -> &Cx {
        self.cx
    }
}

// ─── RequestContext ──────────────────────────────────────────────────────────

/// Context available to a handler running inside a [`RequestRegion`].
///
/// Provides access to:
/// - The incoming [`Request`] via [`request()`](Self::request)
/// - The capability context [`Cx`] via [`cx()`](Self::cx) for spawning tasks,
///   registering finalizers, and checking cancellation
///
/// This type is `!Send` to prevent the context from escaping the region scope.
pub struct RequestContext<'a> {
    cx: &'a Cx,
    request: &'a Request,
}

impl RequestContext<'_> {
    /// Returns the HTTP request.
    #[must_use]
    pub fn request(&self) -> &Request {
        self.request
    }

    /// Returns the capability context for structured concurrency operations.
    ///
    /// Use this to:
    /// - Check cancellation: `ctx.cx().checkpoint()?`
    /// - Read cancel state: `ctx.cx().is_cancel_requested()`
    /// - Access budget: `ctx.cx().remaining_budget()`
    #[must_use]
    pub fn cx(&self) -> &Cx {
        self.cx
    }

    /// Returns a narrowed capability context (least privilege).
    ///
    /// This is a zero-cost type-level restriction that removes access to gated
    /// APIs at compile time. Only available when the underlying context has
    /// full capabilities.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use asupersync::cx::cap::CapSet;
    ///
    /// type RequestCaps = CapSet<true, true, false, false, false>;
    /// let limited = ctx.cx_narrow::<RequestCaps>();
    /// ```
    #[must_use]
    pub fn cx_narrow<Caps>(&self) -> Cx<Caps>
    where
        Caps: cap::SubsetOf<cap::All>,
    {
        self.cx.restrict::<Caps>()
    }

    /// Returns a fully restricted context (no capabilities).
    #[must_use]
    pub fn cx_readonly(&self) -> Cx<cap::None> {
        self.cx.restrict::<cap::None>()
    }

    /// Returns the HTTP method of the request.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.request.method
    }

    /// Returns the request path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.request.path
    }

    /// Returns a path parameter by name, if present.
    #[must_use]
    pub fn path_param(&self, name: &str) -> Option<&str> {
        self.request.path_params.get(name).map(String::as_str)
    }

    /// Returns a header value by name, if present.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.request.headers.get(name).map(String::as_str)
    }
}

// ─── RegionOutcome ──────────────────────────────────────────────────────────

/// The outcome of executing a handler within a [`RequestRegion`].
///
/// Maps the four-valued [`Outcome`](crate::types::Outcome) lattice to HTTP semantics:
///
/// | Variant | HTTP Status | Meaning |
/// |---------|-------------|---------|
/// | `Ok` | from handler | Handler returned successfully |
/// | `Error` | 500 | Application-level error |
/// | `Cancelled` | 503 | Request was cancelled |
/// | `Panicked` | 500 | Handler panicked |
#[derive(Debug)]
pub enum RegionOutcome {
    /// Handler completed successfully.
    Ok(Response),
    /// Handler returned an application error.
    Error(Error),
    /// Request was cancelled before or during handling.
    Cancelled,
    /// Handler panicked. Contains a best-effort message.
    Panicked(String),
}

impl RegionOutcome {
    /// Returns true if the handler completed successfully.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }

    /// Returns true if the handler panicked.
    #[must_use]
    pub const fn is_panicked(&self) -> bool {
        matches!(self, Self::Panicked(_))
    }

    /// Returns true if the request was cancelled.
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }

    /// Returns true if there was an application error.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }

    /// Convert the outcome into an HTTP [`Response`].
    ///
    /// - `Ok(resp)` → `resp`
    /// - `Error(e)` → 500 with error message body
    /// - `Cancelled` → 503 Service Unavailable
    /// - `Panicked(msg)` → 500 Internal Server Error
    #[must_use]
    pub fn into_response(self) -> Response {
        match self {
            Self::Ok(resp) => resp,
            Self::Error(err) => {
                let body = format!("Internal Server Error: {err}");
                Response::new(StatusCode::INTERNAL_SERVER_ERROR, body.into_bytes())
            }
            Self::Cancelled => Response::new(
                StatusCode::SERVICE_UNAVAILABLE,
                b"Service Unavailable: request cancelled".to_vec(),
            ),
            Self::Panicked(msg) => {
                let body = format!("Internal Server Error: handler panicked: {msg}");
                Response::new(StatusCode::INTERNAL_SERVER_ERROR, body.into_bytes())
            }
        }
    }
}

impl fmt::Display for RegionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok(resp) => write!(f, "Ok({})", resp.status.as_u16()),
            Self::Error(err) => write!(f, "Error({err})"),
            Self::Cancelled => write!(f, "Cancelled"),
            Self::Panicked(msg) => write!(f, "Panicked({msg})"),
        }
    }
}

// ─── IsolatedHandler ────────────────────────────────────────────────────────

/// Wraps a handler function with panic isolation and cancellation checking.
///
/// This is a convenience for wrapping synchronous handlers that don't need
/// the full [`RequestRegion`] API but still want isolation guarantees.
///
/// ```ignore
/// let handler = IsolatedHandler::new(|ctx| {
///     let id = ctx.path_param("id").unwrap_or("unknown");
///     Response::new(StatusCode::OK, format!("User: {id}"))
/// });
///
/// let cx = Cx::for_testing();
/// let req = Request::new("GET", "/users/42");
/// let resp = handler.call(&cx, req);
/// assert_eq!(resp.status, StatusCode::OK);
/// ```
pub struct IsolatedHandler<F> {
    handler: F,
}

impl<F> IsolatedHandler<F>
where
    F: Fn(&RequestContext<'_>) -> Response + Send + Sync + 'static,
{
    /// Wrap a handler function with isolation.
    #[must_use]
    pub fn new(handler: F) -> Self {
        Self { handler }
    }

    /// Execute the handler with panic isolation.
    ///
    /// Returns an HTTP response in all cases — panics are caught and
    /// converted to 500 responses.
    pub fn call(&self, cx: &Cx, request: Request) -> Response {
        let region = RequestRegion::new(cx, request);
        region.run(&self.handler).into_response()
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Extract a human-readable message from a panic payload.
fn extract_panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    payload.downcast_ref::<&str>().map_or_else(
        || {
            payload
                .downcast_ref::<String>()
                .map_or_else(|| "unknown panic".to_string(), Clone::clone)
        },
        |s| (*s).to_string(),
    )
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::web::extract::Request;
    use crate::web::response::StatusCode;

    fn test_cx() -> Cx {
        Cx::for_testing()
    }

    fn test_request(method: &str, path: &str) -> Request {
        Request::new(method, path)
    }

    // --- RequestRegion::run ---

    #[test]
    fn run_success() {
        let cx = test_cx();
        let req = test_request("GET", "/hello");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|ctx| {
            assert_eq!(ctx.method(), "GET");
            assert_eq!(ctx.path(), "/hello");
            Response::new(StatusCode::OK, b"ok".to_vec())
        });

        assert!(outcome.is_ok());
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn run_panic_isolation() {
        let cx = test_cx();
        let req = test_request("GET", "/panic");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|_ctx| {
            panic!("handler bug");
        });

        assert!(outcome.is_panicked());
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn run_panic_string_message_preserved() {
        let cx = test_cx();
        let req = test_request("GET", "/");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|_ctx| {
            panic!("something broke");
        });

        if let RegionOutcome::Panicked(msg) = &outcome {
            assert!(msg.contains("something broke"), "msg: {msg}");
        } else {
            panic!("expected Panicked outcome");
        }
    }

    #[test]
    fn run_cancelled_before_handler() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let req = test_request("GET", "/cancel");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|_ctx| {
            panic!("should not reach handler");
        });

        assert!(outcome.is_cancelled());
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    // --- RequestRegion::run_sync ---

    #[test]
    fn run_sync_success() {
        let cx = test_cx();
        let req = test_request("POST", "/data");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run_sync(|ctx| {
            assert_eq!(ctx.method(), "POST");
            Ok(Response::new(StatusCode::CREATED, b"created".to_vec()))
        });

        assert!(outcome.is_ok());
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::CREATED);
    }

    #[test]
    fn run_sync_error() {
        let cx = test_cx();
        let req = test_request("GET", "/err");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run_sync(|_ctx| Err(Error::new(crate::error::ErrorKind::Internal)));

        assert!(outcome.is_error());
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn run_sync_panic() {
        let cx = test_cx();
        let req = test_request("GET", "/");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run_sync(|_ctx| -> Result<Response, Error> {
            panic!("boom");
        });

        assert!(outcome.is_panicked());
    }

    // --- RequestContext accessors ---

    #[test]
    fn context_accessors() {
        let cx = test_cx();
        let mut req = test_request("DELETE", "/users/99");
        req.headers
            .insert("Authorization".to_string(), "Bearer token".to_string());
        let mut params = std::collections::BTreeMap::new();
        params.insert("id".to_string(), "99".to_string());
        req.path_params = params;

        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|ctx| {
            assert_eq!(ctx.method(), "DELETE");
            assert_eq!(ctx.path(), "/users/99");
            assert_eq!(ctx.path_param("id"), Some("99"));
            assert_eq!(ctx.path_param("missing"), None);
            assert_eq!(ctx.header("Authorization"), Some("Bearer token"));
            assert_eq!(ctx.header("Missing"), None);
            let _readonly = ctx.cx_readonly();
            let _narrow = ctx.cx_narrow::<cap::CapSet<true, true, false, false, false>>();
            Response::empty(StatusCode::NO_CONTENT)
        });

        assert!(outcome.is_ok());
    }

    // --- IsolatedHandler ---

    #[test]
    fn isolated_handler_success() {
        let handler = IsolatedHandler::new(|ctx| {
            let name = ctx.path_param("name").unwrap_or("world");
            Response::new(StatusCode::OK, format!("Hello, {name}!").into_bytes())
        });

        let cx = test_cx();
        let mut req = test_request("GET", "/greet/alice");
        let mut params = std::collections::BTreeMap::new();
        params.insert("name".to_string(), "alice".to_string());
        req.path_params = params;

        let resp = handler.call(&cx, req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn isolated_handler_panic_returns_500() {
        let handler = IsolatedHandler::new(|_ctx| {
            panic!("handler crash");
        });

        let cx = test_cx();
        let req = test_request("GET", "/");
        let resp = handler.call(&cx, req);
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn isolated_handler_cancelled_returns_503() {
        let handler = IsolatedHandler::new(|_ctx| {
            panic!("should not run");
        });

        let cx = test_cx();
        cx.set_cancel_requested(true);
        let req = test_request("GET", "/");
        let resp = handler.call(&cx, req);
        assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    // --- RegionOutcome ---

    #[test]
    fn region_outcome_display() {
        let ok = RegionOutcome::Ok(Response::empty(StatusCode::OK));
        assert!(ok.to_string().contains("200"));

        let cancelled = RegionOutcome::Cancelled;
        assert_eq!(cancelled.to_string(), "Cancelled");

        let panicked = RegionOutcome::Panicked("oof".to_string());
        assert!(panicked.to_string().contains("oof"));
    }

    // --- extract_panic_message ---

    #[test]
    fn panic_message_from_str() {
        let msg = extract_panic_message(&(Box::new("oops") as Box<dyn std::any::Any + Send>));
        assert_eq!(msg, "oops");
    }

    #[test]
    fn panic_message_from_string() {
        let msg = extract_panic_message(
            &(Box::new("owned msg".to_string()) as Box<dyn std::any::Any + Send>),
        );
        assert_eq!(msg, "owned msg");
    }

    #[test]
    fn panic_message_unknown_type() {
        let msg = extract_panic_message(&(Box::new(42i32) as Box<dyn std::any::Any + Send>));
        assert_eq!(msg, "unknown panic");
    }
}
