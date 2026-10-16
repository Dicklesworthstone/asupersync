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
//!     // Spawn a background task, owned by this request's region. The factory
//!     // receives the task's own Cx.
//!     let summary = audit_summary(ctx.request());
//!     let _audit = ctx.cx().spawn(move |task_cx| audit_log(task_cx, summary));
//!
//!     // If this handler panics or is cancelled, the audit task is
//!     // automatically drained and finalizers run.
//!     process(ctx).await
//! }
//! ```

use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Waker;
use std::time::Duration;

use crate::cx::scope::CatchUnwind;
use crate::cx::{CancelWakerToken, Cx, cap};
use crate::error::Error;
use crate::trace::event::TraceEvent;
use crate::types::{Budget, CancelKind, Time};
use crate::web::extract::Request;
use crate::web::response::{Response, StatusCode};

pub(crate) const HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC: &str =
    "[ASUP-E501] server request budget deadline exceeded";

/// Terminal class for a producer that returned its cancellation error during
/// the request region's bounded drain window.
///
/// `ServerRequestRegion` normally reports deadline and connection loss itself
/// when the child remains pending through the whole drain grace. A
/// cancellation-aware producer can instead wake, observe its cancelled `Cx`,
/// and return `HttpError::BodyCancelled` during that grace. Deadline causes
/// remain exact here, including causes retained through `ParentCancelled`.
/// Structural `ParentCancelled` without a time-exceeded cause remains an
/// ordinary cancellation because it also represents local resets and cleanup;
/// the protocol transport arm that observed a peer reset/EOF/write error owns
/// the corresponding client-abort diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) enum ServerProducerCancellation {
    DeadlineExceeded,
    Cancelled,
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn classify_server_producer_cancellation(cx: &Cx) -> ServerProducerCancellation {
    if cx
        .cancel_reason()
        .is_some_and(|reason| reason.chain().any(|cause| cause.is_time_exceeded()))
    {
        ServerProducerCancellation::DeadlineExceeded
    } else {
        ServerProducerCancellation::Cancelled
    }
}

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
    ///
    /// # Cancel-race semantics (br-asupersync-bmc8m5)
    ///
    /// Cancellation is checked *before* the handler runs (request → drain
    /// boundary): a cancelled region rejects the handler call entirely and
    /// returns [`RegionOutcome::Cancelled`].
    ///
    /// Once the handler has *completed*, the response (or panic) is a
    /// committed obligation and is **always returned to the caller**, even
    /// if a cancel arrived during the handler's execution. Discarding a
    /// completed response on a cancel race would leak the work the
    /// handler already performed (allocations, side effects, downstream
    /// I/O receipts) and present a misleading view of the region's
    /// outcome to the caller. Callers that need to observe the cancel
    /// can read [`Cx::is_cancel_requested`] on the original `Cx`.
    #[inline]
    pub fn run<F>(self, handler: F) -> RegionOutcome
    where
        F: FnOnce(&RequestContext<'_>) -> Response,
    {
        let _cx_guard = Cx::set_current(Some(self.cx.clone()));
        let ctx = RequestContext {
            cx: self.cx,
            request: &self.request,
            _not_send_sync: PhantomData,
        };

        // Pre-handler check: a cancelled region must not start new work.
        if self.cx.checkpoint().is_err() {
            return RegionOutcome::Cancelled;
        }

        // Run with panic isolation.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(&ctx)));

        match result {
            // br-asupersync-bmc8m5: commit the response even if cancel
            // arrived during execution. The handler's completed work is a
            // discharged obligation; dropping the Response here would
            // silently lose state the caller needs.
            Ok(response) => RegionOutcome::Ok(response),
            Err(panic_payload) => {
                let message = extract_panic_message(&panic_payload);
                RegionOutcome::Panicked(message)
            }
        }
    }

    /// Execute an async handler within this request region.
    ///
    /// Phase 1: Async implementation with full asupersync runtime integration.
    /// The handler receives a `Cx` for structured concurrency and executes
    /// within the request region. On any exit path, the region is closed and
    /// cleanup occurs.
    ///
    /// # Cancel-race semantics
    ///
    /// Same as [`run`](Self::run): cancellation is checked before the handler
    /// runs, but a completed async response is always returned even if cancel
    /// arrived during execution.
    #[inline]
    #[allow(clippy::future_not_send)]
    pub async fn run_async<F, Fut>(self, handler: F) -> RegionOutcome
    where
        F: FnOnce(&RequestContext<'_>) -> Fut,
        Fut: std::future::Future<Output = Response>,
    {
        let _cx_guard = Cx::set_current(Some(self.cx.clone()));
        let ctx = RequestContext {
            cx: self.cx,
            request: &self.request,
            _not_send_sync: PhantomData,
        };

        // Pre-handler check: a cancelled region must not start new work.
        if self.cx.checkpoint().is_err() {
            return RegionOutcome::Cancelled;
        }

        // br-asupersync-hwdzlm: Use CatchUnwind for proper async panic isolation
        let handler_future = CatchUnwind {
            inner: handler(&ctx),
        };

        // Execute the handler with async panic isolation
        match handler_future.await {
            // br-asupersync-hwdzlm: commit the response even if cancel
            // arrived during execution. The handler's completed work is a
            // discharged obligation; dropping the Response here would
            // silently lose state the caller needs.
            Ok(response) => RegionOutcome::Ok(response),
            Err(panic_payload) => {
                let message = extract_panic_message(&panic_payload);
                RegionOutcome::Panicked(message)
            }
        }
    }

    /// Execute an async Handler implementation within this request region.
    ///
    /// Phase 1: Integration with the async Handler trait for web framework usage.
    /// This is the primary method used by routers and middleware.
    #[inline]
    #[allow(clippy::future_not_send)]
    pub async fn run_handler<H>(self, handler: &H) -> RegionOutcome
    where
        H: crate::web::handler::Handler,
    {
        let _cx_guard = Cx::set_current(Some(self.cx.clone()));

        // Pre-handler check: a cancelled region must not start new work.
        if self.cx.checkpoint().is_err() {
            return RegionOutcome::Cancelled;
        }

        // br-asupersync-hwdzlm: Use CatchUnwind for proper async panic isolation
        let handler_future = CatchUnwind {
            inner: handler.call(self.cx, self.request),
        };

        // Execute the handler with async panic isolation
        match handler_future.await {
            // br-asupersync-hwdzlm: commit the response even if cancel
            // arrived during execution. The handler's completed work is a
            // discharged obligation; dropping the Response here would
            // silently lose state the caller needs.
            Ok(response) => RegionOutcome::Ok(response),
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
    /// br-asupersync-hwdzlm: The async counterpart is `run_async_result` below.
    #[inline]
    #[allow(clippy::result_large_err)]
    pub fn run_sync<F>(self, handler: F) -> RegionOutcome
    where
        F: FnOnce(&RequestContext<'_>) -> Result<Response, Error>,
    {
        let _cx_guard = Cx::set_current(Some(self.cx.clone()));
        let ctx = RequestContext {
            cx: self.cx,
            request: &self.request,
            _not_send_sync: PhantomData,
        };

        // Pre-handler check: a cancelled region must not start new work.
        if self.cx.checkpoint().is_err() {
            return RegionOutcome::Cancelled;
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(&ctx)));

        match result {
            // br-asupersync-bmc8m5: commit handler output (Ok or Err
            // application-level result) even if cancel arrived during
            // execution. Discarding completed work on the cancel race
            // would silently drop state the caller has already paid
            // for. The cancel signal stays observable on the cx; the
            // caller can read it post-hoc if it needs that signal.
            Ok(Ok(response)) => RegionOutcome::Ok(response),
            Ok(Err(err)) => RegionOutcome::Error(err),
            Err(panic_payload) => {
                let message = extract_panic_message(&panic_payload);
                RegionOutcome::Panicked(message)
            }
        }
    }

    /// Execute an async handler that returns Result<Response, Error> within this request region.
    ///
    /// br-asupersync-hwdzlm: Phase 1 async implementation - the async counterpart
    /// to `run_sync()`. Provides the same panic isolation and error handling
    /// semantics but for async handlers that return `Future<Output = Result<Response, Error>>`.
    ///
    /// This integrates with asupersync's structured concurrency and handles
    /// both application-level errors (Err) and panics with proper isolation.
    #[allow(clippy::future_not_send)]
    pub async fn run_async_result<F, Fut>(self, handler: F) -> RegionOutcome
    where
        F: FnOnce(&RequestContext<'_>) -> Fut,
        Fut: Future<Output = Result<Response, Error>>,
    {
        let _cx_guard = Cx::set_current(Some(self.cx.clone()));
        let ctx = RequestContext {
            cx: self.cx,
            request: &self.request,
            _not_send_sync: PhantomData,
        };

        // Pre-handler check: a cancelled region must not start new work.
        if self.cx.checkpoint().is_err() {
            return RegionOutcome::Cancelled;
        }

        // Create panic-isolated future using CatchUnwind
        let handler_future = CatchUnwind {
            inner: handler(&ctx),
        };

        // Execute the handler with async panic isolation
        match handler_future.await {
            // br-asupersync-hwdzlm: commit handler output (Ok or Err
            // application-level result) even if cancel arrived during
            // execution. Discarding completed work on the cancel race
            // would silently drop state the caller has already paid
            // for. The cancel signal stays observable on the cx; the
            // caller can read it post-hoc if it needs that signal.
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
/// This type is `!Send`/`!Sync` to prevent the context from crossing thread
/// boundaries while still borrowed from a request-scoped region.
///
/// ```compile_fail
/// use asupersync::web::request_region::RequestContext;
///
/// fn assert_send<T: Send>() {}
///
/// assert_send::<RequestContext<'static>>();
/// ```
pub struct RequestContext<'a> {
    cx: &'a Cx,
    request: &'a Request,
    _not_send_sync: PhantomData<Rc<()>>,
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

// ─── Server-Hop Request Regions ─────────────────────────────────────────────
// br-asupersync-server-stack-hardening-eeexl1.1.1: protocol-agnostic
// per-request region executor for server hops (HTTP/1.1, gRPC-over-h2).
// The protocol layer derives a request budget (meet semantics — tightening
// only), mints a request-scoped Cx through the runtime boundary, and runs
// the handler inside the region with panic isolation, deadline enforcement,
// connection-cancel bridging, and a bounded protocol drain.

/// Which budget sources tightened the request budget at the server hop.
///
/// Carried into the `server.budget_installed` trace event so operators can
/// see whether a request deadline came from server config, a client header
/// (always clamped by the configured cap), both, or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBudgetSource {
    /// Neither a server default nor a header timeout applied; the request
    /// inherits the connection budget unchanged.
    Inherited,
    /// Only the server-configured default request timeout applied.
    ServerConfig,
    /// Only a client-supplied timeout header (clamped to the configured
    /// cap) applied.
    HeaderClamped,
    /// Both the server default and a clamped header timeout applied.
    ServerConfigAndHeader,
}

impl RequestBudgetSource {
    /// Stable token used in budget trace events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inherited => "inherited",
            Self::ServerConfig => "config",
            Self::HeaderClamped => "header",
            Self::ServerConfigAndHeader => "config+header",
        }
    }
}

/// Derives the effective per-request budget at a server hop.
///
/// Composition is pure meet (`Budget::meet` via
/// [`Budget::tightened_by_timeout`]), so the result can only tighten
/// `base` — never loosen it:
///
/// 1. `base` — the connection task's budget (deadline/quotas inherited).
/// 2. `server_timeout` — the server-configured default request timeout.
/// 3. `header_timeout` — the client-requested timeout, honored **only**
///    when `header_cap` is configured, and clamped to that cap first.
///
/// # Security
///
/// A client header can never extend the request budget: with no cap
/// configured the header is ignored entirely, and with a cap the header is
/// clamped to `min(header, cap)` before the meet — which itself can only
/// tighten whatever the connection and server config already imposed.
#[must_use]
pub fn derive_request_budget(
    base: Budget,
    now: Time,
    server_timeout: Option<Duration>,
    header_timeout: Option<Duration>,
    header_cap: Option<Duration>,
) -> (Budget, RequestBudgetSource) {
    let mut budget = base;
    let config_applied = if let Some(timeout) = server_timeout {
        budget = budget.tightened_by_timeout(now, timeout);
        true
    } else {
        false
    };
    let header_applied = if let (Some(requested), Some(cap)) = (header_timeout, header_cap) {
        budget = budget.tightened_by_timeout(now, requested.min(cap));
        true
    } else {
        false
    };
    let source = match (config_applied, header_applied) {
        (false, false) => RequestBudgetSource::Inherited,
        (true, false) => RequestBudgetSource::ServerConfig,
        (false, true) => RequestBudgetSource::HeaderClamped,
        (true, true) => RequestBudgetSource::ServerConfigAndHeader,
    };
    (budget, source)
}

/// Terminal outcome of running a handler inside a server-hop request region.
#[derive(Debug)]
pub enum ServerHopOutcome<R> {
    /// Handler completed; its response is committed even if cancellation
    /// raced completion (same commit semantics as [`RequestRegion::run`]).
    Ok(R),
    /// The request was cancelled before the handler produced a response
    /// (pre-cancelled region, or connection cancel observed at entry).
    Cancelled,
    /// Handler panicked; contains a best-effort message.
    Panicked(String),
    /// The request budget deadline elapsed and the handler did not
    /// complete within the drain grace.
    DeadlineExceeded,
    /// The connection was cancelled mid-request and the handler did not
    /// complete within the drain grace.
    ConnectionLost,
}

/// Installs a [`Cx`] as the ambient context for every poll of `inner`.
///
/// Unlike holding a [`Cx::set_current`] guard across `.await` points (which
/// pins the ambient context to the *constructing* thread), this re-installs
/// the context on whichever worker thread polls the future, so it is correct
/// for work-stealing runtimes and keeps the wrapped future `Send`.
#[pin_project::pin_project]
pub struct AmbientCxScope<F> {
    cx: Cx,
    #[pin]
    inner: F,
}

impl<F: Future> Future for AmbientCxScope<F> {
    type Output = F::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        task_cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        let _guard = Cx::set_current(Some(this.cx.clone()));
        this.inner.poll(task_cx)
    }
}

/// A server-hop request region: a request-scoped [`Cx`] minted at the
/// runtime boundary plus the budget/trace bookkeeping for one request.
///
/// Mint one per request with [`Self::mint`], then either drive the full
/// lifecycle with [`Self::run_with_protocol_drain`] (HTTP/1.1 server) or
/// instrument a caller-driven dispatch with [`Self::instrumented`] +
/// [`Self::finish`] (gRPC server hop).
pub struct ServerRequestRegion {
    cx: Cx,
    started_at: Time,
    protocol: &'static str,
    /// Set once `server.budget_consumed` has been emitted, so the event fires
    /// exactly once across the normal finish paths and the [`Drop`] backstop.
    consumed: AtomicBool,
    /// Only scheduler-owned bodies use a cancellation-independent drain
    /// timer. Legacy borrowed/non-Send hop execution keeps its existing path.
    owned_drain_timer: Option<crate::time::TimerDriverHandle>,
}

/// An owned absolute timer whose readiness does not acknowledge or mask task
/// cancellation. Used only after admission of a runtime-owned server body.
pub(crate) struct ServerRequestDeadline {
    timer: crate::time::TimerDriverHandle,
    deadline: Time,
    registration: Option<crate::time::TimerHandle>,
}

impl ServerRequestDeadline {
    pub(crate) fn new(timer: crate::time::TimerDriverHandle, deadline: Time) -> Self {
        Self {
            timer,
            deadline,
            registration: None,
        }
    }

    fn clear(&mut self) {
        if let Some(registration) = self.registration.take() {
            let _ = self.timer.cancel(&registration);
        }
    }
}

impl Future for ServerRequestDeadline {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        self.clear();
        if self.timer.now() >= self.deadline {
            return std::task::Poll::Ready(());
        }
        // Refresh the actual waiter, including after an early wheel-horizon
        // wake. Rearming never advances the admitted absolute deadline.
        self.registration = Some(self.timer.register(self.deadline, cx.waker().clone()));
        std::task::Poll::Pending
    }
}

impl Drop for ServerRequestDeadline {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Debug)]
struct ConnectionCancelWaker {
    cx: Cx,
    registered: Option<RegisteredConnectionCancelWaker>,
}

#[derive(Debug)]
struct RegisteredConnectionCancelWaker {
    waker: Waker,
    token: CancelWakerToken,
}

impl ConnectionCancelWaker {
    fn new(cx: Cx) -> Self {
        Self {
            cx,
            registered: None,
        }
    }

    fn is_cancel_requested(&self) -> bool {
        self.cx.is_cancel_requested()
    }

    fn refresh(&mut self, waker: &Waker) {
        let same_local_waker = self
            .registered
            .as_ref()
            .is_some_and(|registered| registered.waker.will_wake(waker));
        let incoming_waker = (!same_local_waker).then(|| waker.clone());
        let previous_token = self.registered.as_ref().map(|registered| registered.token);
        let token = self.cx.refresh_cancel_waker(previous_token, waker);
        let retired_waker = if let Some(incoming_waker) = incoming_waker {
            self.registered.replace(RegisteredConnectionCancelWaker {
                waker: incoming_waker,
                token,
            })
        } else {
            self.registered
                .as_mut()
                .expect("same local Waker requires an existing registration")
                .token = token;
            None
        };
        drop(retired_waker);
    }

    fn clear(&mut self) {
        let Some(registered) = self.registered.take() else {
            return;
        };
        self.cx.clear_cancel_waker(registered.token);
        drop(registered);
    }
}

impl Drop for ConnectionCancelWaker {
    fn drop(&mut self) {
        self.clear();
    }
}

impl ServerRequestRegion {
    /// Mints a request region through the runtime boundary.
    ///
    /// Uses `Runtime::current_request_cx_with_budget` so the request Cx
    /// inherits the runtime's drivers and capability mask (non-escalating;
    /// see br-asupersync-ovztin). Returns `None` when no runtime is
    /// installed on the current thread — callers must preserve their
    /// legacy non-region path in that case. Test builds fall back to a
    /// detached request context so lab/unit tests can exercise the region
    /// without a full runtime.
    #[must_use]
    pub fn mint(protocol: &'static str, budget: Budget, now: Time) -> Option<Self> {
        let cx = Self::mint_cx(budget)?;
        Some(Self {
            cx,
            started_at: now,
            protocol,
            consumed: AtomicBool::new(false),
            owned_drain_timer: None,
        })
    }

    /// Retain the exact scheduler-admitted body authority: identity, gateway,
    /// cancellation state and budget are never minted or reconstructed here.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn from_body_cx(protocol: &'static str, cx: Cx, now: Time) -> Self {
        Self {
            owned_drain_timer: cx.timer_driver(),
            cx,
            started_at: now,
            protocol,
            consumed: AtomicBool::new(false),
        }
    }

    /// Mints a request region from an explicit connection capability context.
    ///
    /// Protocol drivers that already receive `&Cx` should use this constructor
    /// instead of relying on ambient task-local state. The child inherits the
    /// connection's drivers and runtime capability mask, receives independent
    /// cancellation state, and installs the tightened request budget without
    /// any capability escalation. It also inherits the connection's spawn
    /// route, so tasks it spawns belong to the connection's region.
    #[must_use]
    pub fn mint_from_connection(
        protocol: &'static str,
        budget: Budget,
        now: Time,
        connection_cx: &Cx,
    ) -> Self {
        Self {
            cx: Self::child_cx_from_connection(connection_cx, budget),
            started_at: now,
            protocol,
            consumed: AtomicBool::new(false),
            owned_drain_timer: None,
        }
    }

    fn mint_cx(budget: Budget) -> Option<Cx> {
        if let Some(cx) = crate::runtime::Runtime::current_request_cx_with_budget(budget) {
            return Some(cx);
        }
        // No runtime handle (e.g. serving inside a `LabRuntime` task):
        // derive from the ambient task context instead. The request cx
        // gets a fresh `CxInner` (independent cancel state + the tightened
        // budget) while inheriting the ambient drivers (the lab virtual
        // timer under `LabRuntime`, so deadlines stay deterministic),
        // trace buffer, observability/entropy forks, and — critically —
        // the ambient runtime mask, so this path cannot escalate
        // capabilities (br-asupersync-ovztin).
        if let Some(ambient) = Cx::current() {
            return Some(Self::child_cx_from_connection(&ambient, budget));
        }
        // Last resort, test builds only: a detached request context so
        // plain unit tests can exercise the region without any runtime.
        #[cfg(any(test, feature = "test-internals"))]
        {
            Some(Cx::for_request_with_budget(budget))
        }
        #[cfg(not(any(test, feature = "test-internals")))]
        {
            None
        }
    }

    fn child_cx_from_connection(connection_cx: &Cx, budget: Budget) -> Cx {
        let region = connection_cx.region_id();
        let task = connection_cx.task_id();
        let mut cx = Cx::new_with_drivers(
            region,
            task,
            budget,
            Some(connection_cx.child_observability(region, task)),
            connection_cx.io_driver_handle(),
            connection_cx.io_cap_handle(),
            connection_cx.timer_driver(),
            Some(connection_cx.child_entropy(task)),
        )
        .with_blocking_pool_handle(connection_cx.blocking_pool_handle())
        .with_logical_clock(connection_cx.logical_clock_handle());
        // A runtime-owned connection lends its spawn route: work the handler
        // spawns is admitted into the connection's region, under that
        // region's pending-spawn accounting. Without it `cx.spawn` from a
        // request context failed with RuntimeUnavailable
        // (br-asupersync-vqppo5). A detached connection context, which has
        // no gateway, stays as it was.
        if let Some(gateway) = connection_cx.spawn_gateway_handle() {
            cx = cx
                .with_spawn_gateway(Some(gateway))
                .with_pending_spawn_counter(connection_cx.pending_spawn_counter_handle());
        }
        if let Some(trace) = connection_cx.trace_buffer() {
            cx.set_trace_buffer(trace);
        }
        if let Some(history) = connection_cx.loser_drain_history_handle() {
            cx.set_loser_drain_history_handle(history);
        }
        cx.runtime_mask = connection_cx.runtime_mask;
        cx
    }

    /// The request-scoped capability context.
    #[must_use]
    pub fn cx(&self) -> &Cx {
        &self.cx
    }

    /// Wraps a caller-driven handler future with the per-poll ambient
    /// install and emits the `server.budget_installed` event.
    ///
    /// The caller keeps driving the returned future (e.g. inside its own
    /// deadline race) and must resolve the region with [`Self::finish`].
    #[must_use]
    pub fn instrumented<F: Future>(
        &self,
        source: RequestBudgetSource,
        fut: F,
    ) -> AmbientCxScope<F> {
        self.emit_installed(source);
        AmbientCxScope {
            cx: self.cx.clone(),
            inner: fut,
        }
    }

    /// Requests cancellation of the region with [`CancelKind::Timeout`].
    ///
    /// For caller-driven dispatches that enforce their own deadline race
    /// (gRPC): call this when the deadline fires so request-scoped children
    /// observe the cancel before the handler future is dropped.
    pub fn cancel_timeout(&self, message: &'static str) {
        self.cx.cancel_with(CancelKind::Timeout, Some(message));
    }

    /// Cancels the request for its elapsed budget deadline with the hop's
    /// attribution, `CancelKind::Timeout` and ASUP-E501, stamped at that
    /// deadline rather than when the hop saw it. The context's own
    /// budget-deadline timer may already have cancelled it with
    /// `CancelKind::Deadline`, stamped at the deadline and without a message.
    /// An equal-severity reason replaces another only if it is not newer
    /// (`CancelReason::strengthen`), so a hop that saw the deadline late lost
    /// its attribution to the timer's (br-asupersync-pev2xi).
    fn cancel_deadline_exceeded(&self) {
        let now = self.cx.now_for_observability();
        let at = self
            .cx
            .budget()
            .deadline
            .map_or(now, |deadline| deadline.min(now));
        self.cx.cancel_with_reason(
            crate::types::CancelReason::with_origin(CancelKind::Timeout, self.cx.region_id(), at)
                .with_task(self.cx.task_id())
                .with_message(HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC),
        );
    }

    /// Emits the `server.budget_consumed` event and consumes the region.
    ///
    /// `outcome` must be one of the stable tokens: `ok`, `err`,
    /// `cancelled`, `panicked`, `deadline_exceeded`, `connection_lost`.
    pub fn finish(self, outcome: &'static str) {
        self.emit_consumed(outcome);
    }

    fn emit_installed(&self, source: RequestBudgetSource) {
        let Some(trace) = self.cx.trace_buffer() else {
            return;
        };
        let budget = self.cx.budget();
        let task = self.cx.task_id();
        let region = self.cx.region_id();
        let now = region_now(&self.cx);
        let logical_time = self.cx.logical_tick();
        let protocol = self.protocol;
        let deadline_ns = budget.deadline.map(Time::as_nanos);
        let poll_quota = u64::from(budget.poll_quota);
        let cost_quota = budget.cost_quota;
        let priority = budget.priority;
        let source = source.as_str();
        trace.record_event(move |seq| {
            TraceEvent::budget_installed(
                seq,
                now,
                task,
                region,
                protocol,
                deadline_ns,
                poll_quota,
                cost_quota,
                priority,
                source,
            )
            .with_logical_time(logical_time)
        });
    }

    fn emit_consumed(&self, outcome: &'static str) {
        // Emit exactly once: the explicit finish paths and the Drop backstop
        // (force-close) both route through here, so the first caller wins and
        // later calls are no-ops. This keeps the "server.budget_consumed on
        // every path" contract without double-emitting on the normal paths.
        if self.consumed.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(trace) = self.cx.trace_buffer() else {
            return;
        };
        let now = region_now(&self.cx);
        let elapsed_ns = now.duration_since(self.started_at);
        let budget = self.cx.budget();
        let task = self.cx.task_id();
        let region = self.cx.region_id();
        let logical_time = self.cx.logical_tick();
        let protocol = self.protocol;
        let deadline_ns = budget.deadline.map(Time::as_nanos);
        let poll_quota = u64::from(budget.poll_quota);
        let cost_quota = budget.cost_quota;
        let priority = budget.priority;
        trace.record_event(move |seq| {
            TraceEvent::budget_consumed(
                seq,
                now,
                task,
                region,
                protocol,
                deadline_ns,
                poll_quota,
                cost_quota,
                priority,
                Some(elapsed_ns),
                outcome,
            )
            .with_logical_time(logical_time)
        });
    }

    /// Runs `fut` (the handler) inside this request region with the full
    /// server-hop lifecycle:
    ///
    /// 1. **Install**: the request Cx becomes the ambient context for every
    ///    poll of the handler ([`AmbientCxScope`]).
    /// 2. **Pre-gate**: a region or connection that is already cancelled
    ///    rejects the handler entirely ([`ServerHopOutcome::Cancelled`], or
    ///    [`ServerHopOutcome::DeadlineExceeded`] when the request's own
    ///    deadline has passed).
    /// 3. **Race**: the handler races the budget deadline and the
    ///    connection's cancel signal (`conn_cx`).
    /// 4. **Drain**: when the deadline fires or the connection cancels, the
    ///    region is cancel-requested ([`CancelKind::Timeout`] /
    ///    [`CancelKind::ParentCancelled`]) and the handler gets
    ///    `drain_grace` to observe the cancel and finish. A response
    ///    completed during drain is committed (never discarded — same
    ///    semantics as [`RequestRegion::run`]).
    /// 5. **Backstop**: a handler still pending after the grace is dropped
    ///    (drop-based cancel) and the hop resolves
    ///    [`ServerHopOutcome::DeadlineExceeded`] /
    ///    [`ServerHopOutcome::ConnectionLost`]. A connection cancel that is the
    ///    request's own deadline (the request Cx cancelled with
    ///    [`CancelKind::Deadline`], as when `conn_cx` is the request Cx itself)
    ///    takes the deadline path.
    ///
    /// Budget trace events (`server.budget_installed`,
    /// `server.budget_consumed`) are emitted on every path.
    pub async fn run_with_protocol_drain<R, Fut>(
        self,
        source: RequestBudgetSource,
        conn_cx: Option<Cx>,
        drain_grace: Duration,
        fut: Fut,
    ) -> ServerHopOutcome<R>
    where
        Fut: Future<Output = R>,
    {
        self.emit_installed(source);

        // Pre-handler gate: a cancelled region must not start new work. A
        // checkpoint past the request's deadline cancels it with Deadline;
        // that is the deadline outcome, not a cancellation
        // (br-asupersync-m8xsjx).
        if self.cx.checkpoint().is_err() {
            if self.cx.cancelled_by(CancelKind::Deadline) {
                self.finish("deadline_exceeded");
                return ServerHopOutcome::DeadlineExceeded;
            }
            self.finish("cancelled");
            return ServerHopOutcome::Cancelled;
        }
        if conn_cx.as_ref().is_some_and(Cx::is_cancel_requested) {
            self.cx.cancel_with(
                CancelKind::ParentCancelled,
                Some("connection cancelled before handler start"),
            );
            self.finish("cancelled");
            return ServerHopOutcome::Cancelled;
        }

        enum PhaseA<R> {
            Done(Result<R, Box<dyn std::any::Any + Send>>),
            ConnCancelled,
        }

        let mut fut = std::pin::pin!(AmbientCxScope {
            cx: self.cx.clone(),
            inner: CatchUnwind { inner: fut },
        });
        let mut connection_cancel_waker = conn_cx.map(ConnectionCancelWaker::new);

        // Phase A: drive the handler, watching the connection cancel
        // signal on every poll (cancel wakes us via the registered waker).
        let primary = std::future::poll_fn(|task_cx| {
            if let std::task::Poll::Ready(out) = fut.as_mut().poll(task_cx) {
                return std::task::Poll::Ready(PhaseA::Done(out));
            }
            if let Some(conn) = connection_cancel_waker.as_mut() {
                if conn.is_cancel_requested() {
                    return std::task::Poll::Ready(PhaseA::ConnCancelled);
                }
                conn.refresh(task_cx.waker());
                // Re-check after registration to close the cancel/register
                // race window.
                if conn.is_cancel_requested() {
                    return std::task::Poll::Ready(PhaseA::ConnCancelled);
                }
            }
            std::task::Poll::Pending
        });

        let phase_a = match self.cx.budget().deadline {
            Some(deadline) => crate::time::timeout_at(deadline, primary).await,
            None => Ok(primary.await),
        };
        if let Some(registration) = connection_cancel_waker.as_mut() {
            registration.clear();
        }

        // The request's own deadline can reach this point as a connection
        // cancel: when `conn_cx` is the request Cx (the owned h2 hop), the
        // budget-deadline timer, or a checkpoint past the deadline, cancels it
        // with Deadline before the timeout observes the elapsed deadline
        // (br-asupersync-m8xsjx).
        let own_deadline = matches!(phase_a, Ok(PhaseA::ConnCancelled))
            && self.cx.cancelled_by(CancelKind::Deadline);
        match phase_a {
            Ok(PhaseA::Done(Ok(response))) => {
                self.finish("ok");
                ServerHopOutcome::Ok(response)
            }
            Ok(PhaseA::Done(Err(payload))) => {
                let message = extract_panic_message(&payload);
                self.finish("panicked");
                ServerHopOutcome::Panicked(message)
            }
            Ok(PhaseA::ConnCancelled) if !own_deadline => {
                self.cx.cancel_with(
                    CancelKind::ParentCancelled,
                    Some("connection cancelled while request in flight"),
                );
                match self.drain_handler(drain_grace, fut.as_mut()).await {
                    Some(Ok(response)) => {
                        // Commit a response completed during drain: the
                        // handler's work is a discharged obligation.
                        self.finish("ok");
                        ServerHopOutcome::Ok(response)
                    }
                    Some(Err(payload)) => {
                        let message = extract_panic_message(&payload);
                        self.finish("panicked");
                        ServerHopOutcome::Panicked(message)
                    }
                    None => {
                        self.finish("connection_lost");
                        ServerHopOutcome::ConnectionLost
                    }
                }
            }
            Ok(PhaseA::ConnCancelled) | Err(_) => {
                self.cancel_deadline_exceeded();
                match self.drain_handler(drain_grace, fut.as_mut()).await {
                    Some(Ok(response)) => {
                        self.finish("ok");
                        ServerHopOutcome::Ok(response)
                    }
                    Some(Err(payload)) => {
                        let message = extract_panic_message(&payload);
                        self.finish("panicked");
                        ServerHopOutcome::Panicked(message)
                    }
                    None => {
                        self.finish("deadline_exceeded");
                        ServerHopOutcome::DeadlineExceeded
                    }
                }
            }
        }
    }

    async fn drain_handler<F>(&self, grace: Duration, mut fut: F) -> Option<F::Output>
    where
        F: Future + Unpin,
    {
        let Some(timer) = &self.owned_drain_timer else {
            return drain_until(&self.cx, grace, fut).await;
        };
        if grace.is_zero() {
            return None;
        }
        let deadline = timer.now() + grace;
        let mut wait = ServerRequestDeadline::new(timer.clone(), deadline);
        std::future::poll_fn(|cx| {
            if timer.now() > deadline {
                return std::task::Poll::Ready(None);
            }
            if let std::task::Poll::Ready(output) = Pin::new(&mut fut).poll(cx) {
                return std::task::Poll::Ready(Some(output));
            }
            Pin::new(&mut wait).poll(cx).map(|()| None)
        })
        .await
    }
}

impl Drop for ServerRequestRegion {
    /// Backstop for the budget-trace contract: if the region is dropped without
    /// an explicit `finish` — e.g. the HTTP/1.1 force-close path drops the
    /// `run_with_protocol_drain` future while it is still pending — emit
    /// `server.budget_consumed outcome=force_closed` so the event is never
    /// silently lost. `emit_consumed` is idempotent, so normal paths that
    /// already called `finish` make this a no-op.
    fn drop(&mut self) {
        self.emit_consumed("force_closed");
    }
}

impl fmt::Debug for ServerRequestRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerRequestRegion")
            .field("protocol", &self.protocol)
            .field("started_at", &self.started_at)
            .finish_non_exhaustive()
    }
}

/// Current time from the region's timer driver, falling back to wall time.
fn region_now(cx: &Cx) -> Time {
    cx.timer_driver()
        .map_or_else(crate::time::wall_now, |timer| timer.now())
}

/// Awaits `fut` for at most `grace`, returning `None` on expiry (or when
/// the grace is zero). Used for the bounded protocol drain after a region
/// cancel: the handler gets one last window to observe the cancel and
/// finish cleanly before the drop backstop.
async fn drain_until<F>(cx: &Cx, grace: Duration, fut: F) -> Option<F::Output>
where
    F: Future + Unpin,
{
    if grace.is_zero() {
        return None;
    }
    let now = region_now(cx);
    crate::time::timeout(now, grace, fut).await.ok()
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
#[path = "request_region_inline_tests.rs"]
mod tests;
