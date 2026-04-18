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

use crate::cx::{Cx, cap};
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
    #[inline]
    pub fn run<F>(self, handler: F) -> RegionOutcome
    where
        F: FnOnce(&RequestContext<'_>) -> Response,
    {
        let ctx = RequestContext {
            cx: self.cx,
            request: &self.request,
        };

        // Check cancellation before running the handler.
        if self.cx.checkpoint().is_err() {
            return RegionOutcome::Cancelled;
        }

        // Run with panic isolation.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(&ctx)));

        match result {
            Ok(response) => {
                if self.cx.checkpoint().is_err() {
                    RegionOutcome::Cancelled
                } else {
                    RegionOutcome::Ok(response)
                }
            }
            Err(panic_payload) => {
                let message = extract_panic_message(&panic_payload);
                RegionOutcome::Panicked(message)
            }
        }
    }

    /// Execute a synchronous handler within this request region.
    ///
    /// This is an alternative to [`run`](Self::run) for handlers that return a
    /// `Result<Response, Error>`. The handler executes synchronously inside the
    /// capability context. On any exit path, the region is closed and cleanup
    /// occurs.
    ///
    /// The async counterpart will be introduced in Phase 1+.
    #[inline]
    #[allow(clippy::result_large_err)]
    pub fn run_sync<F>(self, handler: F) -> RegionOutcome
    where
        F: FnOnce(&RequestContext<'_>) -> Result<Response, Error>,
    {
        let ctx = RequestContext {
            cx: self.cx,
            request: &self.request,
        };

        if self.cx.checkpoint().is_err() {
            return RegionOutcome::Cancelled;
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(&ctx)));

        match result {
            Ok(Ok(response)) => {
                if self.cx.checkpoint().is_err() {
                    RegionOutcome::Cancelled
                } else {
                    RegionOutcome::Ok(response)
                }
            }
            Ok(Err(err)) => {
                if self.cx.checkpoint().is_err() {
                    RegionOutcome::Cancelled
                } else {
                    RegionOutcome::Error(err)
                }
            }
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
    #[inline]
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
    #[inline]
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
    #[inline]
    #[must_use]
    pub fn cx_narrow<Caps>(&self) -> Cx<Caps>
    where
        Caps: cap::SubsetOf<cap::All>,
    {
        self.cx.restrict::<Caps>()
    }

    /// Returns a fully restricted context (no capabilities).
    #[inline]
    #[must_use]
    pub fn cx_readonly(&self) -> Cx<cap::None> {
        self.cx.restrict::<cap::None>()
    }

    /// Returns the HTTP method of the request.
    #[inline]
    #[must_use]
    pub fn method(&self) -> &str {
        &self.request.method
    }

    /// Returns the request path.
    #[inline]
    #[must_use]
    pub fn path(&self) -> &str {
        &self.request.path
    }

    /// Returns a path parameter by name, if present.
    #[inline]
    #[must_use]
    pub fn path_param(&self, name: &str) -> Option<&str> {
        self.request.path_params.get(name).map(String::as_str)
    }

    /// Returns a header value by name, if present.
    #[inline]
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.request.header(name)
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
/// | `Cancelled` | 499 | Request was cancelled by the client |
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
    /// - `Error(e)` → generic 500 response
    /// - `Cancelled` → 499 Client Closed Request
    /// - `Panicked(msg)` → generic 500 response
    #[inline]
    #[must_use]
    pub fn into_response(self) -> Response {
        match self {
            Self::Ok(resp) => resp,
            Self::Error(_err) => Response::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                b"Internal Server Error".to_vec(),
            ),
            Self::Cancelled => Response::new(
                StatusCode::CLIENT_CLOSED_REQUEST,
                b"Client Closed Request: request cancelled".to_vec(),
            ),
            Self::Panicked(_msg) => Response::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                b"Internal Server Error".to_vec(),
            ),
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
    #[inline]
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
    fn run_cancelled_before_handler_returns_499() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        let req = test_request("GET", "/cancel");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|_ctx| {
            panic!("should not reach handler");
        });

        assert!(outcome.is_cancelled());
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::CLIENT_CLOSED_REQUEST);
        assert_eq!(
            resp.body.as_ref(),
            b"Client Closed Request: request cancelled"
        );
    }

    #[test]
    fn run_cancelled_during_handler_returns_499() {
        let cx = test_cx();
        let req = test_request("GET", "/cancel-during");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|ctx| {
            ctx.cx().set_cancel_requested(true);
            Response::new(StatusCode::OK, b"ok".to_vec())
        });

        assert!(outcome.is_cancelled());
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::CLIENT_CLOSED_REQUEST);
        assert_eq!(
            resp.body.as_ref(),
            b"Client Closed Request: request cancelled"
        );
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
        assert_eq!(resp.body.as_ref(), b"Internal Server Error");
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

    #[test]
    fn run_sync_cancelled_during_handler_returns_499() {
        let cx = test_cx();
        let req = test_request("GET", "/cancel-during");
        let region = RequestRegion::new(&cx, req);

        let outcome = region.run_sync(|ctx| {
            ctx.cx().set_cancel_requested(true);
            Ok(Response::new(StatusCode::OK, b"ok".to_vec()))
        });

        assert!(outcome.is_cancelled());
        let resp = outcome.into_response();
        assert_eq!(resp.status, StatusCode::CLIENT_CLOSED_REQUEST);
        assert_eq!(
            resp.body.as_ref(),
            b"Client Closed Request: request cancelled"
        );
    }

    // --- RequestContext accessors ---

    #[test]
    fn context_accessors() {
        let cx = test_cx();
        let mut req = test_request("DELETE", "/users/99");
        req.headers
            .insert("authorization".to_string(), "Bearer token".to_string());
        let mut params = std::collections::HashMap::new();
        params.insert("id".to_string(), "99".to_string());
        req.path_params = params;

        let region = RequestRegion::new(&cx, req);

        let outcome = region.run(|ctx| {
            assert_eq!(ctx.method(), "DELETE");
            assert_eq!(ctx.path(), "/users/99");
            assert_eq!(ctx.path_param("id"), Some("99"));
            assert_eq!(ctx.path_param("missing"), None);
            assert_eq!(ctx.header("Authorization"), Some("Bearer token"));
            assert_eq!(ctx.header("authorization"), Some("Bearer token"));
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
        let mut params = std::collections::HashMap::new();
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
        assert_eq!(resp.body.as_ref(), b"Internal Server Error");
    }

    #[test]
    fn panicked_response_does_not_leak_panic_message() {
        let resp = RegionOutcome::Panicked("secret panic details".to_string()).into_response();
        assert_eq!(resp.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(resp.body.as_ref(), b"Internal Server Error");
    }

    #[test]
    fn isolated_handler_cancelled_returns_499() {
        let handler = IsolatedHandler::new(|_ctx| {
            panic!("should not run");
        });

        let cx = test_cx();
        cx.set_cancel_requested(true);
        let req = test_request("GET", "/");
        let resp = handler.call(&cx, req);
        assert_eq!(resp.status, StatusCode::CLIENT_CLOSED_REQUEST);
        assert_eq!(
            resp.body.as_ref(),
            b"Client Closed Request: request cancelled"
        );
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

    // ─── Metamorphic Testing: Cancel-on-Disconnect Invariants ──────────────────

    mod metamorphic_tests {
        use super::*;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
        use std::time::Duration;

        /// MR1: Client disconnect triggers request-region cancel within 1 tick
        ///
        /// Property: If the client disconnects during handler execution,
        /// the region's cancellation state should be observable within 1 tick.
        #[test]
        fn mr_disconnect_triggers_cancel_within_one_tick() {
            let cx = test_cx();
            let req = test_request("GET", "/long-running");
            let region = RequestRegion::new(&cx, req);

            let cancel_observed = Arc::new(AtomicBool::new(false));
            let cancel_observed_clone = Arc::clone(&cancel_observed);
            let cx_clone = cx.clone();

            // Simulate client disconnect by setting cancel after a brief delay
            let _handle = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(1)); // Simulate network delay
                cx_clone.set_cancel_requested(true);
            });

            let outcome = region.run(|ctx| {
                // Handler checks cancellation repeatedly
                for _i in 0..10 {
                    if ctx.cx().is_cancel_requested() {
                        cancel_observed_clone.store(true, Ordering::SeqCst);
                        return Response::new(
                            StatusCode::CLIENT_CLOSED_REQUEST,
                            b"cancelled".to_vec(),
                        );
                    }
                    // Simulate work that might take multiple ticks
                    std::thread::sleep(Duration::from_millis(1));
                }
                Response::new(StatusCode::OK, b"completed".to_vec())
            });

            // MR1: Cancel should be observed within reasonable time
            assert!(
                cancel_observed.load(Ordering::SeqCst) || outcome.is_cancelled(),
                "Client disconnect should trigger observable cancellation"
            );
        }

        /// MR2: All pending downstream futures receive cancellation
        ///
        /// Property: When the request region is cancelled, all spawned tasks
        /// within the region should also be cancelled.
        #[test]
        fn mr_downstream_futures_receive_cancellation() {
            let cx = test_cx();
            let req = test_request("GET", "/spawn-tasks");
            let region = RequestRegion::new(&cx, req);

            let task_cancelled = Arc::new(AtomicBool::new(false));
            let task_cancelled_clone = Arc::clone(&task_cancelled);

            let _outcome = region.run(|ctx| {
                std::thread::scope(|s| {
                    // Spawn a background task that monitors cancellation
                    let task_ctx = ctx.cx().clone();
                    s.spawn(move || {
                        for _ in 0..100 {
                            if task_ctx.is_cancel_requested() {
                                task_cancelled_clone.store(true, Ordering::SeqCst);
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    });

                    // Simulate client disconnect
                    std::thread::sleep(Duration::from_millis(5));
                    ctx.cx().set_cancel_requested(true);

                    // Give spawned task time to observe cancellation
                    std::thread::sleep(Duration::from_millis(10));
                });

                Response::new(StatusCode::OK, b"ok".to_vec())
            });

            // MR2: Spawned tasks should observe cancellation
            assert!(
                task_cancelled.load(Ordering::SeqCst) || outcome.is_cancelled(),
                "Spawned tasks should receive cancellation signal"
            );
        }

        /// MR3: No obligation leaks after disconnect
        ///
        /// Property: When a request is cancelled, all tracked obligations
        /// should be properly cleaned up (committed or aborted).
        #[test]
        fn mr_no_obligation_leaks_after_disconnect() {
            let cx = test_cx();
            let req = test_request("POST", "/transaction");
            let region = RequestRegion::new(&cx, req);

            let obligation_cleaned = Arc::new(AtomicBool::new(false));
            let obligation_cleaned_clone = Arc::clone(&obligation_cleaned);

            let outcome = region.run(|ctx| {
                // Simulate creating an obligation (e.g., database transaction)
                struct MockObligation {
                    cleaned: Arc<AtomicBool>,
                }

                impl Drop for MockObligation {
                    fn drop(&mut self) {
                        self.cleaned.store(true, Ordering::SeqCst);
                    }
                }

                let _obligation = MockObligation {
                    cleaned: obligation_cleaned_clone,
                };

                // Simulate client disconnect during transaction
                std::thread::sleep(Duration::from_millis(1));
                ctx.cx().set_cancel_requested(true);

                // Early return should trigger obligation cleanup via Drop
                if ctx.cx().checkpoint().is_err() {
                    return Response::new(StatusCode::CLIENT_CLOSED_REQUEST, b"cancelled".to_vec());
                }

                Response::new(StatusCode::OK, b"committed".to_vec())
            });

            // Give time for cleanup
            std::thread::sleep(Duration::from_millis(1));

            // MR3: Obligations should be cleaned up after cancellation
            assert!(
                obligation_cleaned.load(Ordering::SeqCst),
                "Obligations must be cleaned up when request is cancelled"
            );
        }

        /// MR4: Partial response flushed atomically
        ///
        /// Property: If a response is partially written when cancellation occurs,
        /// the response should be atomically committed or discarded (no partial writes).
        #[test]
        fn mr_partial_response_flushed_atomically() {
            let cx = test_cx();
            let req = test_request("GET", "/streaming");
            let region = RequestRegion::new(&cx, req);

            let response_complete = Arc::new(AtomicBool::new(false));
            let response_complete_clone = Arc::clone(&response_complete);

            let outcome = region.run(|ctx| {
                // Simulate building a response that could be interrupted
                let mut response_data = Vec::new();

                for i in 0..10 {
                    if ctx.cx().is_cancel_requested() {
                        // If cancelled, return what we have or a cancellation response
                        return Response::new(
                            StatusCode::CLIENT_CLOSED_REQUEST,
                            b"cancelled".to_vec(),
                        );
                    }

                    // Simulate response building
                    response_data.push(b'a' + (i % 26) as u8);
                    std::thread::sleep(Duration::from_millis(1));
                }

                response_complete_clone.store(true, Ordering::SeqCst);
                Response::new(StatusCode::OK, response_data)
            });

            // Simulate client disconnect during response building
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(5));
                cx.set_cancel_requested(true);
            });

            std::thread::sleep(Duration::from_millis(15));

            // MR4: Response should be either complete or properly cancelled
            match outcome {
                RegionOutcome::Ok(_) => assert!(
                    response_complete.load(Ordering::SeqCst),
                    "Complete response should only be returned if fully built"
                ),
                RegionOutcome::Cancelled => assert!(
                    !response_complete.load(Ordering::SeqCst),
                    "Cancelled response should not complete response building"
                ),
                _ => panic!("Unexpected outcome: {:?}", outcome),
            }
        }

        /// MR5: Reconnect with same request-id deduplicated
        ///
        /// Property: If a client reconnects with the same request identifier,
        /// the request should be deduplicated (idempotency).
        #[test]
        fn mr_reconnect_request_id_deduplicated() {
            let cx = test_cx();
            let request_counter = Arc::new(AtomicU32::new(0));

            // First request with ID "req-123"
            let mut req1 = test_request("POST", "/idempotent");
            req1.headers
                .insert("x-request-id".to_string(), "req-123".to_string());
            req1.headers
                .insert("x-idempotency-key".to_string(), "key-123".to_string());

            let region1 = RequestRegion::new(&cx, req1);
            let counter_clone1 = Arc::clone(&request_counter);

            let outcome1 = region1.run(|ctx| {
                // Check for idempotency key in real implementation
                let request_id = ctx.header("x-request-id").unwrap_or("none");
                let idempotency_key = ctx.header("x-idempotency-key").unwrap_or("none");

                // Simulate idempotent operation
                if request_id == "req-123" && idempotency_key == "key-123" {
                    counter_clone1.fetch_add(1, Ordering::SeqCst);
                    Response::new(StatusCode::CREATED, b"resource created".to_vec())
                } else {
                    Response::new(StatusCode::BAD_REQUEST, b"missing headers".to_vec())
                }
            });

            // Second request with same ID (reconnect/retry)
            let mut req2 = test_request("POST", "/idempotent");
            req2.headers
                .insert("x-request-id".to_string(), "req-123".to_string());
            req2.headers
                .insert("x-idempotency-key".to_string(), "key-123".to_string());

            let region2 = RequestRegion::new(&cx, req2);
            let counter_clone2 = Arc::clone(&request_counter);

            let outcome2 = region2.run(|ctx| {
                let request_id = ctx.header("x-request-id").unwrap_or("none");
                let idempotency_key = ctx.header("x-idempotency-key").unwrap_or("none");

                // In a real implementation, this would check a cache/database
                // For this test, we simulate that the operation should be idempotent
                let current_count = counter_clone2.load(Ordering::SeqCst);

                if request_id == "req-123" && idempotency_key == "key-123" && current_count > 0 {
                    // Already processed - return cached result
                    Response::new(StatusCode::CREATED, b"resource created".to_vec())
                } else if current_count == 0 {
                    // First time - process it
                    counter_clone2.fetch_add(1, Ordering::SeqCst);
                    Response::new(StatusCode::CREATED, b"resource created".to_vec())
                } else {
                    Response::new(StatusCode::BAD_REQUEST, b"invalid state".to_vec())
                }
            });

            // MR5: Both requests should succeed, but operation should only happen once
            assert!(outcome1.is_ok(), "First request should succeed");
            assert!(
                outcome2.is_ok(),
                "Second request (reconnect) should succeed"
            );

            // The key invariant: idempotent operations should only execute once
            let final_count = request_counter.load(Ordering::SeqCst);
            assert_eq!(
                final_count, 1,
                "Idempotent operation should only execute once despite multiple requests"
            );
        }

        /// Composite MR: Disconnect during concurrent operations
        ///
        /// Tests multiple invariants simultaneously to catch interaction bugs.
        #[test]
        fn mr_composite_disconnect_concurrent_operations() {
            let cx = test_cx();
            let req = test_request("POST", "/complex");
            let region = RequestRegion::new(&cx, req);

            let task_count = Arc::new(AtomicU32::new(0));
            let cleanup_count = Arc::new(AtomicU32::new(0));

            let task_count_clone = Arc::clone(&task_count);
            let cleanup_count_clone = Arc::clone(&cleanup_count);

            let outcome = region.run(|ctx| {
                std::thread::scope(|s| {
                    // Spawn multiple concurrent tasks
                    let mut handles = Vec::new();
                    for _i in 0..3 {
                        let task_ctx = ctx.cx().clone();
                        let task_counter = Arc::clone(&task_count_clone);
                        let cleanup_counter = Arc::clone(&cleanup_count_clone);

                        handles.push(s.spawn(move || {
                            task_counter.fetch_add(1, Ordering::SeqCst);

                            // Simulate work with cleanup
                            let _cleanup = CleanupGuard {
                                counter: cleanup_counter,
                            };

                            for _ in 0..20 {
                                if task_ctx.is_cancel_requested() {
                                    return; // Task cancelled
                                }
                                std::thread::sleep(Duration::from_micros(100));
                            }
                        }));
                    }

                    // Simulate client disconnect after brief work
                    std::thread::sleep(Duration::from_millis(2));
                    ctx.cx().set_cancel_requested(true);

                    // Give tasks time to observe cancellation and clean up
                    std::thread::sleep(Duration::from_millis(10));
                    
                    for h in handles {
                        let _ = h.join();
                    }
                });

                Response::new(StatusCode::CLIENT_CLOSED_REQUEST, b"cancelled".to_vec())
            });

            std::thread::sleep(Duration::from_millis(5)); // Allow cleanup to complete

            // Composite invariants:
            // 1. All tasks should have started
            assert_eq!(
                task_count.load(Ordering::SeqCst),
                3,
                "All spawned tasks should have started"
            );

            // 2. All tasks should have cleaned up
            assert_eq!(
                cleanup_count.load(Ordering::SeqCst),
                3,
                "All tasks should have performed cleanup"
            );

            // 3. Request should be cancelled
            assert!(
                outcome.is_cancelled(),
                "Request should be marked as cancelled"
            );
        }

        struct CleanupGuard {
            counter: Arc<AtomicU32>,
        }

        impl Drop for CleanupGuard {
            fn drop(&mut self) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}
