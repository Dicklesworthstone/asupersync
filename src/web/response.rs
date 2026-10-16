//! Response types and the [`IntoResponse`] trait.
//!
//! Handlers return types that implement [`IntoResponse`], which converts them
//! into an HTTP response. Common types like `String`, `&str`, `Json<T>`, and
//! tuples are supported out of the box.

use std::collections::HashMap;
use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::future::Future;
#[cfg(not(target_arch = "wasm32"))]
use std::num::NonZeroUsize;
#[cfg(not(target_arch = "wasm32"))]
use std::pin::Pin;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

#[cfg(not(target_arch = "wasm32"))]
use crate::Cx;
use crate::bytes::Bytes;
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
use crate::http::h1::OutgoingBody;
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h1::{BodyKind, Http1ProducedResponse, HttpError, OutgoingBodySender};
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h2::listener::{Http2BodySender, Http2ProducedResponse};

#[cfg(not(target_arch = "wasm32"))]
use super::extract::{ExtractionError, FromRequestParts, Request};

// ─── Status Codes ────────────────────────────────────────────────────────────

/// HTTP status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusCode(u16);

impl StatusCode {
    // 1xx Informational
    /// 100 Continue
    pub const CONTINUE: Self = Self(100);
    /// 101 Switching Protocols
    pub const SWITCHING_PROTOCOLS: Self = Self(101);

    // 2xx Success
    /// 200 OK
    pub const OK: Self = Self(200);
    /// 201 Created
    pub const CREATED: Self = Self(201);
    /// 202 Accepted
    pub const ACCEPTED: Self = Self(202);
    /// 204 No Content
    pub const NO_CONTENT: Self = Self(204);
    /// 206 Partial Content
    pub const PARTIAL_CONTENT: Self = Self(206);

    // 3xx Redirection
    /// 301 Moved Permanently
    pub const MOVED_PERMANENTLY: Self = Self(301);
    /// 302 Found
    pub const FOUND: Self = Self(302);
    /// 303 See Other
    pub const SEE_OTHER: Self = Self(303);
    /// 304 Not Modified
    pub const NOT_MODIFIED: Self = Self(304);
    /// 307 Temporary Redirect
    pub const TEMPORARY_REDIRECT: Self = Self(307);
    /// 308 Permanent Redirect
    pub const PERMANENT_REDIRECT: Self = Self(308);

    // 4xx Client Error
    /// 400 Bad Request
    pub const BAD_REQUEST: Self = Self(400);
    /// 401 Unauthorized
    pub const UNAUTHORIZED: Self = Self(401);
    /// 403 Forbidden
    pub const FORBIDDEN: Self = Self(403);
    /// 404 Not Found
    pub const NOT_FOUND: Self = Self(404);
    /// 405 Method Not Allowed
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    /// 408 Request Timeout
    pub const REQUEST_TIMEOUT: Self = Self(408);
    /// 409 Conflict
    pub const CONFLICT: Self = Self(409);
    /// 413 Payload Too Large
    pub const PAYLOAD_TOO_LARGE: Self = Self(413);
    /// 415 Unsupported Media Type
    pub const UNSUPPORTED_MEDIA_TYPE: Self = Self(415);
    /// 416 Range Not Satisfiable
    pub const RANGE_NOT_SATISFIABLE: Self = Self(416);
    /// 422 Unprocessable Entity
    pub const UNPROCESSABLE_ENTITY: Self = Self(422);
    /// 429 Too Many Requests
    pub const TOO_MANY_REQUESTS: Self = Self(429);
    /// 499 Client Closed Request
    pub const CLIENT_CLOSED_REQUEST: Self = Self(499);

    // 5xx Server Error
    /// 500 Internal Server Error
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    /// 501 Not Implemented
    pub const NOT_IMPLEMENTED: Self = Self(501);
    /// 502 Bad Gateway
    pub const BAD_GATEWAY: Self = Self(502);
    /// 503 Service Unavailable
    pub const SERVICE_UNAVAILABLE: Self = Self(503);
    /// 504 Gateway Timeout
    pub const GATEWAY_TIMEOUT: Self = Self(504);

    /// Create a status code from a raw value.
    #[must_use]
    pub const fn from_u16(code: u16) -> Self {
        Self(code)
    }

    /// Return the numeric status code.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns `true` if the status code indicates success (2xx).
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 >= 200 && self.0 < 300
    }

    /// Returns `true` if the status code indicates a client error (4xx).
    #[must_use]
    pub const fn is_client_error(self) -> bool {
        self.0 >= 400 && self.0 < 500
    }

    /// Returns `true` if the status code indicates a server error (5xx).
    #[must_use]
    pub const fn is_server_error(self) -> bool {
        self.0 >= 500 && self.0 < 600
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─── Response ────────────────────────────────────────────────────────────────

/// An HTTP response.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HashMap<String, String>,
    /// Set-Cookie response header lines, one per cookie.
    ///
    /// br-asupersync-ehtkns: `Set-Cookie` is the canonical multi-valued
    /// response header — each cookie must ship as its own header line.
    /// Storing it in `headers` (a single-value `HashMap`) silently
    /// overwrote earlier cookies whenever a second one was set, e.g.
    /// when `SessionMiddleware` set the session cookie after a handler
    /// had already set a CSRF / remember-me cookie. All Set-Cookie
    /// entries now live here; wire-format writers must emit one
    /// `Set-Cookie:` line per entry. The public API funnels Set-Cookie
    /// values into this vector via [`Response::append_set_cookie`] (and
    /// transparently from [`Response::set_header`] when the name is
    /// `set-cookie`), so existing call sites cannot accidentally lose
    /// cookies.
    pub set_cookies: Vec<String>,
    /// Response body.
    pub body: Bytes,
}

impl Response {
    /// Create a new response with the given status, headers, and body.
    #[must_use]
    pub fn new(status: StatusCode, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: HashMap::with_capacity(4),
            set_cookies: Vec::new(),
            body: body.into(),
        }
    }

    /// Create an empty response with the given status code.
    #[must_use]
    pub fn empty(status: StatusCode) -> Self {
        Self::new(status, Bytes::new())
    }

    /// Returns a header value using HTTP's case-insensitive matching rules.
    ///
    /// For `set-cookie`, returns the FIRST entry of [`Self::set_cookies`]
    /// (callers needing every cookie should iterate `set_cookies` directly,
    /// since `Set-Cookie` is canonically multi-valued).
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        if name.eq_ignore_ascii_case("set-cookie") {
            return self.set_cookies.first().map(String::as_str);
        }
        if let Some(value) = self.headers.get(name) {
            return Some(value.as_str());
        }

        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .min_by(|(a, _), (b, _)| a.cmp(b))
            .map(|(_, value)| value.as_str())
    }

    /// Returns `true` when the response contains the named header.
    #[must_use]
    pub fn has_header(&self, name: &str) -> bool {
        if name.eq_ignore_ascii_case("set-cookie") {
            return !self.set_cookies.is_empty();
        }
        self.header_value(name).is_some()
    }

    /// Append a `Set-Cookie` response header line.
    ///
    /// br-asupersync-ehtkns: the explicit, append-only API for cookies.
    /// Each call adds a separate `Set-Cookie:` line on the wire, so
    /// composed middleware (session, CSRF, remember-me, flash) can each
    /// ship their own cookie without clobbering the others. The value
    /// is sanitized through `sanitize_header_value` for parity with
    /// `set_header`, so CR/LF/NUL/control bytes can never split the
    /// header.
    pub fn append_set_cookie(&mut self, value: impl Into<String>) {
        self.set_cookies.push(sanitize_header_value(value.into()));
    }

    /// Insert or replace a header while canonicalizing the stored name.
    ///
    /// br-asupersync-n5b94b: TOCTOU FIX - perform atomic header key normalization
    /// to prevent race conditions where multiple headers with case-variant names
    /// could exist simultaneously. Both names and values are sanitized using
    /// consistent logic to prevent injection attacks.
    ///
    /// br-asupersync-ehtkns: when `name` is `set-cookie`, the call is
    /// transparently routed to [`Self::append_set_cookie`] so multiple
    /// composed middleware layers each get to emit their own cookie
    /// instead of overwriting one another. To remove all previously
    /// queued cookies, clear [`Self::set_cookies`] explicitly.
    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let normalized = sanitize_header_name(name.into()).to_ascii_lowercase();
        if normalized == "set-cookie" {
            self.append_set_cookie(value.into());
            return;
        }
        let sanitized_value = sanitize_header_value(value.into());

        // Atomic removal of all case-variant keys - collect AND remove in the
        // same iteration to prevent TOCTOU where case variants could be added
        // between collection and removal phases
        self.headers
            .retain(|key, _| !key.eq_ignore_ascii_case(&normalized));

        self.headers.insert(normalized, sanitized_value);
    }

    /// Ensure a header exists while preserving any existing value.
    ///
    /// br-asupersync-n5b94b: TOCTOU FIX - atomic header processing to prevent
    /// race conditions. The name is sanitized using consistent validation that
    /// matches header value sanitization.
    ///
    /// br-asupersync-ehtkns: when `name` is `set-cookie`, appends the
    /// default value only when no cookies are currently queued. Use
    /// [`Self::append_set_cookie`] to add additional cookies regardless
    /// of state.
    pub fn ensure_header(&mut self, name: &str, default_value: impl Into<String>) {
        if name.eq_ignore_ascii_case("set-cookie") {
            if self.set_cookies.is_empty() {
                self.append_set_cookie(default_value.into());
            }
            return;
        }
        let normalized = sanitize_header_name(name.to_owned()).to_ascii_lowercase();

        // Atomic check-and-set: find existing value or use default, then
        // set atomically to prevent TOCTOU where header could change between
        // check and set operations
        let value = self
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(&normalized))
            .map_or_else(|| default_value.into(), |(_, value)| value.clone());

        // Remove all case variants atomically
        self.headers
            .retain(|key, _| !key.eq_ignore_ascii_case(&normalized));
        self.headers
            .insert(normalized, sanitize_header_value(value));
    }

    /// Remove a header using HTTP's case-insensitive matching rules.
    ///
    /// br-asupersync-ehtkns: when `name` is `set-cookie`, drains all
    /// queued cookies from [`Self::set_cookies`] and returns the first
    /// one (preserving the legacy single-value return shape).
    pub fn remove_header(&mut self, name: &str) -> Option<String> {
        if name.eq_ignore_ascii_case("set-cookie") {
            if self.set_cookies.is_empty() {
                return None;
            }
            let first = self.set_cookies.remove(0);
            self.set_cookies.clear();
            return Some(first);
        }
        let normalized = name.to_ascii_lowercase();
        let mut matching_keys: Vec<String> = self
            .headers
            .keys()
            .filter(|key| key.eq_ignore_ascii_case(name))
            .cloned()
            .collect();
        matching_keys.sort_by(|left, right| {
            (left != &normalized, left.as_str()).cmp(&(right != &normalized, right.as_str()))
        });
        let mut removed = None;

        for key in matching_keys {
            if let Some(value) = self.headers.remove(&key) {
                removed.get_or_insert(value);
            }
        }

        removed
    }

    /// Add a header to the response.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.set_header(name, value);
        self
    }
}

#[cfg(not(target_arch = "wasm32"))]
type Http1StreamProducerFuture =
    Pin<Box<dyn Future<Output = Result<OutgoingBodySender, HttpError>> + Send + 'static>>;

#[cfg(not(target_arch = "wasm32"))]
type Http1StreamProducer =
    Box<dyn FnOnce(Cx, OutgoingBodySender) -> Http1StreamProducerFuture + Send + 'static>;

/// Deferred HTTP/1 produced-body plan registered during web handler dispatch.
///
/// The plan contains no channel and starts no work. The production listener
/// creates both channel halves from its authoritative request [`Cx`] only
/// after routing and response-head validation complete.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct Http1StreamPlan {
    body_kind: BodyKind,
    capacity: NonZeroUsize,
    max_frame_bytes: NonZeroUsize,
    producer: Http1StreamProducer,
}

#[cfg(not(target_arch = "wasm32"))]
impl Http1StreamPlan {
    pub(crate) fn buffered(body: Bytes) -> Self {
        let max_frame_bytes = NonZeroUsize::new(body.len()).unwrap_or(NonZeroUsize::MIN);
        Self {
            body_kind: BodyKind::Chunked,
            capacity: NonZeroUsize::MIN,
            // A buffered response is already fully materialized before it
            // enters this compatibility adapter, so limiting its one transfer
            // would not bound application production and would break ordinary
            // large buffered routes in the produced-listener lane.
            max_frame_bytes,
            producer: Box::new(move |cx, mut sender| {
                Box::pin(async move {
                    if !body.is_empty() {
                        sender.send_bytes(&cx, body).await?;
                    }
                    sender.finish(&cx)?;
                    Ok(sender)
                })
            }),
        }
    }

    pub(crate) fn into_produced(self, response: Response) -> Http1ProducedResponse {
        debug_assert!(
            response.body.is_empty(),
            "buffered bytes move into the deferred producer before head binding"
        );
        let Self {
            body_kind,
            capacity,
            max_frame_bytes,
            producer,
        } = self;
        let status = response.status.as_u16();
        let reason = crate::http::h1::types::default_reason(status);
        let mut produced = match body_kind {
            BodyKind::Chunked => Http1ProducedResponse::chunked_with_max_frame_bytes(
                capacity,
                max_frame_bytes,
                status,
                reason,
                producer,
            ),
            BodyKind::ContentLength(length) => {
                Http1ProducedResponse::with_content_length_and_max_frame_bytes(
                    capacity,
                    max_frame_bytes,
                    status,
                    reason,
                    length,
                    producer,
                )
            }
            BodyKind::Empty => {
                unreachable!("HTTP/1 produced-response plans use explicit zero Content-Length")
            }
        };

        let mut headers = response.headers.into_iter().collect::<Vec<_>>();
        headers.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        headers.extend(
            response
                .set_cookies
                .into_iter()
                .map(|value| ("set-cookie".to_string(), value)),
        );
        for (name, value) in headers {
            produced = produced.with_header(name, value);
        }
        produced
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Default)]
pub(crate) struct Http1StreamSlot {
    state: Arc<parking_lot::Mutex<Http1StreamSlotState>>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Default)]
enum Http1StreamSlotState {
    #[default]
    Empty,
    Registered(Http1StreamPlan),
    Rejected(&'static str),
    Consumed,
}

#[cfg(not(target_arch = "wasm32"))]
impl fmt::Debug for Http1StreamSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http1StreamSlot")
            .field(
                "state",
                &match &*self.state.lock() {
                    Http1StreamSlotState::Empty => "empty",
                    Http1StreamSlotState::Registered(_) => "registered",
                    Http1StreamSlotState::Rejected(_) => "rejected",
                    Http1StreamSlotState::Consumed => "consumed",
                },
            )
            .finish()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Http1StreamSlot {
    fn register(&self, plan: Http1StreamPlan) -> Result<(), Http1StreamPlan> {
        let displaced = {
            let mut state = self.state.lock();
            if matches!(&*state, Http1StreamSlotState::Empty) {
                *state = Http1StreamSlotState::Registered(plan);
                return Ok(());
            }
            if matches!(&*state, Http1StreamSlotState::Registered(_)) {
                // Poison the request after any duplicate attempt. A handler
                // must not be able to ignore the second refusal and commit the
                // first producer accidentally. Move the first plan out so its
                // user-defined captures are dropped after releasing the lock.
                Some(std::mem::replace(
                    &mut *state,
                    Http1StreamSlotState::Rejected("streamed response registered more than once"),
                ))
            } else {
                None
            }
        };
        drop(displaced);
        Err(plan)
    }

    pub(crate) fn bind_response(
        &self,
        response: &Response,
    ) -> Result<Option<Http1StreamPlan>, &'static str> {
        let state = std::mem::replace(&mut *self.state.lock(), Http1StreamSlotState::Consumed);
        let plan = match state {
            Http1StreamSlotState::Empty => None,
            Http1StreamSlotState::Registered(plan) => {
                if !response.body.is_empty() {
                    return Err("streamed response cannot also carry a buffered body");
                }
                Some(plan)
            }
            Http1StreamSlotState::Rejected(reason) => return Err(reason),
            Http1StreamSlotState::Consumed => {
                return Err("streamed response binding already consumed");
            }
        };

        if matches!(response.status.as_u16(), 100..=199 | 204 | 205 | 304) {
            return Err(
                "current HTTP/1 produced-response transport requires a body-allowed status",
            );
        }
        if plan
            .as_ref()
            .is_some_and(|plan| matches!(plan.body_kind, BodyKind::ContentLength(_)))
            && response.has_header("trailer")
        {
            return Err("fixed-length HTTP/1 produced responses cannot declare trailers");
        }
        if response.has_header("content-length") || response.has_header("transfer-encoding") {
            return Err("current HTTP/1 produced-response transport owns response framing");
        }
        Ok(plan)
    }
}

/// Request-scoped authoring handle for a supervised HTTP/1 response.
///
/// This extractor is available only through
/// [`crate::web::Router::into_http1_produced_handler`]. Calling a handler that
/// requires it through another router adapter fails closed instead of minting
/// transport authority. Registering a producer does not create a channel,
/// spawn a task, or poll the producer; the HTTP/1 listener performs those
/// actions under its authoritative request [`Cx`] after dispatch completes.
///
/// ```no_run
/// use asupersync::bytes::Bytes;
/// use asupersync::web::{Http1StreamResponder, Response, StatusCode};
/// use std::num::NonZeroUsize;
///
/// async fn streamed(responder: Http1StreamResponder) -> Response {
///     responder.chunked(
///         StatusCode::OK,
///         NonZeroUsize::new(4).unwrap(),
///         |_cx, mut sender| async move {
///             sender.send_bytes(&_cx, Bytes::from_static(b"hello")).await?;
///             sender.finish(&_cx)?;
///             Ok(sender)
///         },
///     )
/// }
/// ```
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub struct Http1StreamResponder {
    slot: Http1StreamSlot,
}

#[cfg(not(target_arch = "wasm32"))]
impl FromRequestParts for Http1StreamResponder {
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        let slot = req
            .extensions
            .get_typed_cloned::<Http1StreamSlot>()
            .ok_or_else(|| {
                ExtractionError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "HTTP/1 streamed-response transport unavailable",
                )
            })?;
        Ok(Self { slot })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Http1StreamResponder {
    /// Register one bounded chunked producer and return its middleware-visible
    /// response head.
    ///
    /// The handler may add application headers to the returned [`Response`].
    /// Its body must remain empty: mixing a buffered body with a registered
    /// stream fails closed in the router adapter. A second registration poisons
    /// the request even if the handler ignores the returned `500` response.
    /// `capacity` bounds queued frames and each DATA frame is limited to
    /// [`Http1ProducedResponse::DEFAULT_MAX_FRAME_BYTES`]. Use
    /// [`Self::chunked_with_max_frame_bytes`] to select a smaller or larger
    /// nonzero ceiling explicitly.
    #[must_use]
    pub fn chunked<P, Fut>(
        self,
        status: StatusCode,
        capacity: NonZeroUsize,
        producer: P,
    ) -> Response
    where
        P: FnOnce(Cx, OutgoingBodySender) -> Fut + Send + 'static,
        Fut: Future<Output = Result<OutgoingBodySender, HttpError>> + Send + 'static,
    {
        self.chunked_with_max_frame_bytes(
            status,
            capacity,
            NonZeroUsize::new(Http1ProducedResponse::DEFAULT_MAX_FRAME_BYTES)
                .expect("the default HTTP/1 produced frame limit is nonzero"),
            producer,
        )
    }

    /// Register one chunked producer with an explicit DATA-frame ceiling.
    ///
    /// The response transport rejects a larger DATA send before it enters the
    /// bounded channel. For frame capacity `N` and byte ceiling `M`, the H1
    /// path documents a conservative `(N + 2) * M` retained-DATA envelope;
    /// application bytes held before calling the sender remain caller-owned.
    #[must_use]
    pub fn chunked_with_max_frame_bytes<P, Fut>(
        self,
        status: StatusCode,
        capacity: NonZeroUsize,
        max_frame_bytes: NonZeroUsize,
        producer: P,
    ) -> Response
    where
        P: FnOnce(Cx, OutgoingBodySender) -> Fut + Send + 'static,
        Fut: Future<Output = Result<OutgoingBodySender, HttpError>> + Send + 'static,
    {
        let plan = Http1StreamPlan {
            body_kind: BodyKind::Chunked,
            capacity,
            max_frame_bytes,
            producer: Box::new(move |cx, sender| Box::pin(producer(cx, sender))),
        };
        if self.slot.register(plan).is_err() {
            return Response::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                Bytes::from_static(b"HTTP/1 streamed response already registered"),
            )
            .header("content-type", "text/plain; charset=utf-8");
        }
        Response::empty(status)
    }

    /// Register one supervised response with an exact `Content-Length`.
    ///
    /// The listener owns the framing header, writes DATA without chunk coding,
    /// and accepts clean completion only after exactly `length` bytes. Each
    /// DATA send also uses the default produced-response frame ceiling.
    /// On `HEAD`, `length` is representation metadata only: the listener never
    /// creates or polls this producer, so exact-length enforcement is not
    /// exercised by the HEAD response.
    #[must_use]
    pub fn with_content_length<P, Fut>(
        self,
        status: StatusCode,
        capacity: NonZeroUsize,
        length: u64,
        producer: P,
    ) -> Response
    where
        P: FnOnce(Cx, OutgoingBodySender) -> Fut + Send + 'static,
        Fut: Future<Output = Result<OutgoingBodySender, HttpError>> + Send + 'static,
    {
        self.with_content_length_and_max_frame_bytes(
            status,
            capacity,
            NonZeroUsize::new(Http1ProducedResponse::DEFAULT_MAX_FRAME_BYTES)
                .expect("the default HTTP/1 produced frame limit is nonzero"),
            length,
            producer,
        )
    }

    /// Register an exact-length producer with an explicit DATA-frame ceiling.
    #[must_use]
    pub fn with_content_length_and_max_frame_bytes<P, Fut>(
        self,
        status: StatusCode,
        capacity: NonZeroUsize,
        max_frame_bytes: NonZeroUsize,
        length: u64,
        producer: P,
    ) -> Response
    where
        P: FnOnce(Cx, OutgoingBodySender) -> Fut + Send + 'static,
        Fut: Future<Output = Result<OutgoingBodySender, HttpError>> + Send + 'static,
    {
        let plan = Http1StreamPlan {
            body_kind: BodyKind::ContentLength(length),
            capacity,
            max_frame_bytes,
            producer: Box::new(move |cx, sender| Box::pin(producer(cx, sender))),
        };
        if self.slot.register(plan).is_err() {
            return Response::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                Bytes::from_static(b"HTTP/1 streamed response already registered"),
            )
            .header("content-type", "text/plain; charset=utf-8");
        }
        Response::empty(status)
    }
}

#[cfg(not(target_arch = "wasm32"))]
type Http2StreamProducerFuture =
    Pin<Box<dyn Future<Output = Result<Http2BodySender, HttpError>> + Send + 'static>>;

#[cfg(not(target_arch = "wasm32"))]
type Http2StreamProducer =
    Box<dyn FnOnce(Cx, Http2BodySender) -> Http2StreamProducerFuture + Send + 'static>;

/// Deferred HTTP/2 body plan registered during web handler dispatch.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct Http2StreamPlan {
    capacity: NonZeroUsize,
    max_frame_bytes: NonZeroUsize,
    producer: Http2StreamProducer,
}

#[cfg(not(target_arch = "wasm32"))]
impl Http2StreamPlan {
    pub(crate) fn into_produced(self, response: Response) -> Http2ProducedResponse {
        debug_assert!(
            response.body.is_empty(),
            "a produced HTTP/2 response head cannot retain buffered bytes"
        );
        let status = response.status.as_u16();
        let mut wire_response = crate::http::h1::types::Response::new(
            status,
            crate::http::h1::types::default_reason(status),
            Vec::new(),
        );
        let mut headers = response.headers.into_iter().collect::<Vec<_>>();
        headers.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        headers.extend(
            response
                .set_cookies
                .into_iter()
                .map(|value| ("set-cookie".to_string(), value)),
        );
        for (name, value) in headers {
            wire_response = wire_response.with_header(name, value);
        }
        Http2ProducedResponse::streaming(
            wire_response,
            self.capacity,
            self.max_frame_bytes,
            move |cx, sender| (self.producer)(cx, sender),
        )
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Default)]
pub(crate) struct Http2StreamSlot {
    state: Arc<parking_lot::Mutex<Http2StreamSlotState>>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Default)]
enum Http2StreamSlotState {
    #[default]
    Empty,
    Registered(Http2StreamPlan),
    Rejected(&'static str),
    Consumed,
}

#[cfg(not(target_arch = "wasm32"))]
impl fmt::Debug for Http2StreamSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http2StreamSlot")
            .field(
                "state",
                &match &*self.state.lock() {
                    Http2StreamSlotState::Empty => "empty",
                    Http2StreamSlotState::Registered(_) => "registered",
                    Http2StreamSlotState::Rejected(_) => "rejected",
                    Http2StreamSlotState::Consumed => "consumed",
                },
            )
            .finish()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Http2StreamSlot {
    fn register(&self, plan: Http2StreamPlan) -> Result<(), Http2StreamPlan> {
        let displaced = {
            let mut state = self.state.lock();
            if matches!(&*state, Http2StreamSlotState::Empty) {
                *state = Http2StreamSlotState::Registered(plan);
                return Ok(());
            }
            if matches!(&*state, Http2StreamSlotState::Registered(_)) {
                Some(std::mem::replace(
                    &mut *state,
                    Http2StreamSlotState::Rejected("HTTP/2 response producer registered twice"),
                ))
            } else {
                None
            }
        };
        drop(displaced);
        Err(plan)
    }

    pub(crate) fn bind_response(
        &self,
        response: &Response,
        suppress_response_body: bool,
    ) -> Result<Option<Http2StreamPlan>, &'static str> {
        let state = std::mem::replace(&mut *self.state.lock(), Http2StreamSlotState::Consumed);
        let plan = match state {
            Http2StreamSlotState::Empty => return Ok(None),
            Http2StreamSlotState::Registered(plan) => plan,
            Http2StreamSlotState::Rejected(reason) => return Err(reason),
            Http2StreamSlotState::Consumed => {
                return Err("HTTP/2 response producer binding already consumed");
            }
        };
        if !response.body.is_empty() {
            return Err("produced HTTP/2 response cannot also carry a buffered body");
        }
        if !suppress_response_body
            && matches!(response.status.as_u16(), 100..=199 | 204 | 205 | 304)
        {
            return Err("produced HTTP/2 response requires a body-allowed status");
        }
        if response.has_header("transfer-encoding")
            || (!suppress_response_body && response.has_header("content-length"))
        {
            return Err("produced HTTP/2 response owns message framing");
        }
        Ok(Some(plan))
    }
}

/// Request-scoped authoring handle for a supervised HTTP/2 response body.
///
/// The handle is available only through
/// [`crate::web::Router::into_http2_produced_handler`]. Registration is
/// deferred: it creates no channel and polls no producer until the HTTP/2
/// listener validates the final response head and supplies its request-derived
/// [`Cx`].
///
/// ```no_run
/// use asupersync::bytes::Bytes;
/// use asupersync::web::{Http2StreamResponder, Response, StatusCode};
/// use std::num::NonZeroUsize;
///
/// async fn streamed(responder: Http2StreamResponder) -> Response {
///     responder.streaming(
///         StatusCode::OK,
///         NonZeroUsize::new(4).unwrap(),
///         NonZeroUsize::new(16 * 1024).unwrap(),
///         |_cx, mut sender| async move {
///             sender.send_bytes(&_cx, Bytes::from_static(b"hello")).await?;
///             sender.finish(&_cx)?;
///             Ok(sender)
///         },
///     )
/// }
/// ```
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub struct Http2StreamResponder {
    slot: Http2StreamSlot,
}

#[cfg(not(target_arch = "wasm32"))]
impl FromRequestParts for Http2StreamResponder {
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        let slot = req
            .extensions
            .get_typed_cloned::<Http2StreamSlot>()
            .ok_or_else(|| {
                ExtractionError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "HTTP/2 produced-response transport unavailable",
                )
            })?;
        Ok(Self { slot })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Http2StreamResponder {
    /// Register one bounded DATA-frame producer and return its
    /// middleware-visible response head.
    ///
    /// `capacity * max_frame_bytes` bounds bytes retained in the producer's
    /// transport queue. The final response must keep its buffered body empty
    /// and must not set `Content-Length` or `Transfer-Encoding`.
    #[must_use]
    pub fn streaming<P, Fut>(
        self,
        status: StatusCode,
        capacity: NonZeroUsize,
        max_frame_bytes: NonZeroUsize,
        producer: P,
    ) -> Response
    where
        P: FnOnce(Cx, Http2BodySender) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Http2BodySender, HttpError>> + Send + 'static,
    {
        let plan = Http2StreamPlan {
            capacity,
            max_frame_bytes,
            producer: Box::new(move |cx, sender| Box::pin(producer(cx, sender))),
        };
        if self.slot.register(plan).is_err() {
            return Response::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                Bytes::from_static(b"HTTP/2 response producer already registered"),
            )
            .header("content-type", "text/plain; charset=utf-8");
        }
        Response::empty(status)
    }
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
type Http3StreamProducerFuture =
    Pin<Box<dyn Future<Output = Result<Http3BodySender, HttpError>> + Send + 'static>>;

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
pub(crate) type Http3StreamProducer =
    Box<dyn FnOnce(Cx, Http3BodySender) -> Http3StreamProducerFuture + Send + 'static>;

/// Sender handed to a supervised HTTP/3 response-body producer.
///
/// The channel has fixed frame capacity and every DATA item is bounded by
/// `max_frame_bytes`. The established-session Router bridge pulls at most one
/// item after the preceding QUIC STREAM frame drains and exact encoded H3 wire
/// credit is available.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[derive(Debug)]
pub struct Http3BodySender {
    inner: OutgoingBodySender,
    max_frame_bytes: NonZeroUsize,
    terminal: Http3ProducerTerminal,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Http3ProducerTerminal {
    Open,
    Finished,
    Trailers,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl Http3BodySender {
    /// Maximum DATA bytes accepted by one send operation.
    #[must_use]
    pub fn max_frame_bytes(&self) -> NonZeroUsize {
        self.max_frame_bytes
    }

    /// Total DATA bytes committed into the bounded body channel.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.inner.total_bytes()
    }

    /// Whether the producer explicitly finished with EOF or trailers.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }

    #[must_use]
    pub(crate) fn terminal(&self) -> Http3ProducerTerminal {
        self.terminal
    }

    /// Commit one bounded DATA frame.
    pub async fn send_bytes(&mut self, cx: &Cx, data: Bytes) -> Result<(), HttpError> {
        if data.len() > self.max_frame_bytes.get() {
            return Err(HttpError::BodyTooLargeDetailed {
                actual: u64::try_from(data.len()).unwrap_or(u64::MAX),
                limit: u64::try_from(self.max_frame_bytes.get()).unwrap_or(u64::MAX),
            });
        }
        self.inner.send_bytes(cx, data).await
    }

    /// Copy and commit one bounded DATA frame.
    pub async fn send_chunk(&mut self, cx: &Cx, data: &[u8]) -> Result<(), HttpError> {
        if data.len() > self.max_frame_bytes.get() {
            return Err(HttpError::BodyTooLargeDetailed {
                actual: u64::try_from(data.len()).unwrap_or(u64::MAX),
                limit: u64::try_from(self.max_frame_bytes.get()).unwrap_or(u64::MAX),
            });
        }
        self.inner.send_chunk(cx, data).await
    }

    /// Finish the response with trailing HEADERS.
    pub async fn send_trailers(
        &mut self,
        cx: &Cx,
        trailers: crate::http::HeaderMap,
    ) -> Result<(), HttpError> {
        self.inner.send_trailers(cx, trailers).await?;
        self.terminal = Http3ProducerTerminal::Trailers;
        Ok(())
    }

    /// Finish the response without trailers.
    pub fn finish(&mut self, cx: &Cx) -> Result<(), HttpError> {
        if self.terminal == Http3ProducerTerminal::Trailers {
            return Ok(());
        }
        self.inner.finish(cx)?;
        self.terminal = Http3ProducerTerminal::Finished;
        Ok(())
    }
}

/// Deferred HTTP/3 body plan registered during Router dispatch.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
pub(crate) struct Http3StreamPlan {
    pub(crate) capacity: NonZeroUsize,
    pub(crate) max_frame_bytes: NonZeroUsize,
    pub(crate) producer: Http3StreamProducer,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl Http3StreamPlan {
    pub(crate) fn into_parts(
        self,
        cx: &Cx,
    ) -> (OutgoingBody, Http3BodySender, Http3StreamProducer) {
        let (inner, body) =
            OutgoingBody::channel_with_capacity(cx, BodyKind::Chunked, self.capacity.get());
        let sender = Http3BodySender {
            inner,
            max_frame_bytes: self.max_frame_bytes,
            terminal: Http3ProducerTerminal::Open,
        };
        (body, sender, self.producer)
    }
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[derive(Clone, Default)]
pub(crate) struct Http3StreamSlot {
    state: Arc<parking_lot::Mutex<Http3StreamSlotState>>,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[derive(Default)]
enum Http3StreamSlotState {
    #[default]
    Empty,
    Registered(Http3StreamPlan),
    Rejected(&'static str),
    Consumed,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl fmt::Debug for Http3StreamSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http3StreamSlot")
            .field(
                "state",
                &match &*self.state.lock() {
                    Http3StreamSlotState::Empty => "empty",
                    Http3StreamSlotState::Registered(_) => "registered",
                    Http3StreamSlotState::Rejected(_) => "rejected",
                    Http3StreamSlotState::Consumed => "consumed",
                },
            )
            .finish()
    }
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl Http3StreamSlot {
    fn register(&self, plan: Http3StreamPlan) -> Result<(), Http3StreamPlan> {
        let displaced = {
            let mut state = self.state.lock();
            if matches!(&*state, Http3StreamSlotState::Empty) {
                *state = Http3StreamSlotState::Registered(plan);
                return Ok(());
            }
            if matches!(&*state, Http3StreamSlotState::Registered(_)) {
                Some(std::mem::replace(
                    &mut *state,
                    Http3StreamSlotState::Rejected("HTTP/3 response producer registered twice"),
                ))
            } else {
                None
            }
        };
        drop(displaced);
        Err(plan)
    }

    pub(crate) fn bind_response(
        &self,
        response: &Response,
        suppress_response_body: bool,
    ) -> Result<Option<Http3StreamPlan>, &'static str> {
        let state = std::mem::replace(&mut *self.state.lock(), Http3StreamSlotState::Consumed);
        let plan = match state {
            Http3StreamSlotState::Empty => return Ok(None),
            Http3StreamSlotState::Registered(plan) => plan,
            Http3StreamSlotState::Rejected(reason) => return Err(reason),
            Http3StreamSlotState::Consumed => {
                return Err("HTTP/3 response producer binding already consumed");
            }
        };
        if !response.body.is_empty() {
            return Err("produced HTTP/3 response cannot also carry a buffered body");
        }
        if !suppress_response_body
            && matches!(response.status.as_u16(), 100..=199 | 204 | 205 | 304)
        {
            return Err("produced HTTP/3 response requires a body-allowed status");
        }
        if response.has_header("transfer-encoding")
            || (!suppress_response_body && response.has_header("content-length"))
        {
            return Err("produced HTTP/3 response owns message framing");
        }
        Ok(Some(plan))
    }
}

/// Request-scoped authoring handle for a supervised HTTP/3 response body.
///
/// This extractor is available only while running
/// [`crate::web::NativeH3RouterDispatch::run_produced`]. Registration merely
/// records a bounded plan; channel creation and producer startup remain under
/// the established-session bridge's request capability.
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
#[derive(Debug)]
pub struct Http3StreamResponder {
    slot: Http3StreamSlot,
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl FromRequestParts for Http3StreamResponder {
    fn from_request_parts(req: &Request) -> Result<Self, ExtractionError> {
        let slot = req
            .extensions
            .get_typed_cloned::<Http3StreamSlot>()
            .ok_or_else(|| {
                ExtractionError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "HTTP/3 produced-response transport unavailable",
                )
            })?;
        Ok(Self { slot })
    }
}

#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
impl Http3StreamResponder {
    /// Register one bounded DATA-frame producer and return its authored head.
    #[must_use]
    pub fn streaming<P, Fut>(
        self,
        status: StatusCode,
        capacity: NonZeroUsize,
        max_frame_bytes: NonZeroUsize,
        producer: P,
    ) -> Response
    where
        P: FnOnce(Cx, Http3BodySender) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Http3BodySender, HttpError>> + Send + 'static,
    {
        let plan = Http3StreamPlan {
            capacity,
            max_frame_bytes,
            producer: Box::new(move |cx, sender| Box::pin(producer(cx, sender))),
        };
        if self.slot.register(plan).is_err() {
            return Response::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                Bytes::from_static(b"HTTP/3 response producer already registered"),
            )
            .header("content-type", "text/plain; charset=utf-8");
        }
        Response::empty(status)
    }
}

// ─── IntoResponse Trait ──────────────────────────────────────────────────────

/// Trait for types that can be converted into an HTTP response.
///
/// This is the primary mechanism for returning data from handlers.
/// Any handler return type must implement this trait.
pub trait IntoResponse {
    /// Convert self into a [`Response`].
    fn into_response(self) -> Response;
}

impl IntoResponse for Response {
    fn into_response(self) -> Response {
        self
    }
}

impl IntoResponse for StatusCode {
    fn into_response(self) -> Response {
        Response::empty(self)
    }
}

impl IntoResponse for String {
    fn into_response(self) -> Response {
        Response::new(StatusCode::OK, Bytes::from(self))
            .header("content-type", "text/plain; charset=utf-8")
    }
}

impl IntoResponse for &'static str {
    fn into_response(self) -> Response {
        Response::new(StatusCode::OK, Bytes::from_static(self.as_bytes()))
            .header("content-type", "text/plain; charset=utf-8")
    }
}

impl IntoResponse for Bytes {
    fn into_response(self) -> Response {
        Response::new(StatusCode::OK, self).header("content-type", "application/octet-stream")
    }
}

impl IntoResponse for Vec<u8> {
    fn into_response(self) -> Response {
        Response::new(StatusCode::OK, Bytes::from(self))
            .header("content-type", "application/octet-stream")
    }
}

impl IntoResponse for () {
    fn into_response(self) -> Response {
        Response::empty(StatusCode::OK)
    }
}

/// Tuple: (StatusCode, body) overrides the status code.
impl<T: IntoResponse> IntoResponse for (StatusCode, T) {
    fn into_response(self) -> Response {
        let mut resp = self.1.into_response();
        resp.status = self.0;
        resp
    }
}

/// Tuple: (StatusCode, headers, body) overrides status and adds headers.
impl<T: IntoResponse> IntoResponse for (StatusCode, Vec<(String, String)>, T) {
    fn into_response(self) -> Response {
        let mut resp = self.2.into_response();
        resp.status = self.0;
        for (k, v) in self.1 {
            resp.set_header(k, v);
        }
        resp
    }
}

/// Result: Ok produces the success response, Err the error response.
impl<T: IntoResponse, E: IntoResponse> IntoResponse for Result<T, E> {
    fn into_response(self) -> Response {
        match self {
            Ok(ok) => ok.into_response(),
            Err(err) => err.into_response(),
        }
    }
}

// ─── Json Response ───────────────────────────────────────────────────────────

/// JSON response wrapper.
///
/// Serializes the inner value as JSON with `application/json` content type.
///
/// ```
/// use asupersync::web::Json;
///
/// #[derive(serde::Serialize)]
/// struct User {
///     name: String,
/// }
///
/// async fn get_user() -> Json<User> {
///     Json(User { name: "alice".into() })
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Json<T>(pub T);

impl<T: serde::Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        serde_json::to_vec(&self.0).map_or_else(
            |_| Response::empty(StatusCode::INTERNAL_SERVER_ERROR),
            |body| {
                Response::new(StatusCode::OK, Bytes::from(body))
                    .header("content-type", "application/json")
            },
        )
    }
}

// ─── Html Response ───────────────────────────────────────────────────────────

/// HTML response wrapper.
///
/// Sets the content type to `text/html; charset=utf-8`.
#[derive(Debug, Clone)]
pub struct Html<T>(pub T);

impl IntoResponse for Html<String> {
    fn into_response(self) -> Response {
        Response::new(StatusCode::OK, Bytes::copy_from_slice(self.0.as_bytes()))
            .header("content-type", "text/html; charset=utf-8")
    }
}

impl IntoResponse for Html<&'static str> {
    fn into_response(self) -> Response {
        Response::new(StatusCode::OK, Bytes::from_static(self.0.as_bytes()))
            .header("content-type", "text/html; charset=utf-8")
    }
}

// ─── Redirect ────────────────────────────────────────────────────────────────

/// Why a redirect URI was rejected by the safe-by-default validators
/// (`Redirect::to`, `Redirect::permanent`, `Redirect::temporary`).
///
/// br-asupersync-0hj233: this enum surfaces the open-redirect defense
/// as an explicit error type so callers either (a) handle the error
/// (return 400 to the user) or (b) opt into the explicit
/// `Redirect::external_unchecked` escape hatch when they truly need
/// to redirect to an external host (OAuth callbacks, payment-gateway
/// hand-offs, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectError {
    /// URI is empty.
    EmptyUri,
    /// URI starts with `//` — protocol-relative, browser switches host
    /// to whatever follows the slashes. Trivial open-redirect vector
    /// that defeats naive `starts_with("/")` defenses.
    ProtocolRelative,
    /// URI contains a backslash (`\`). Some HTTP intermediaries and
    /// browsers normalize `\` → `/`, so `/\\attacker.com/x` becomes
    /// `//attacker.com/x` — the protocol-relative attack via a
    /// different parser quirk.
    BackslashInPath,
    /// URI has a scheme other than `http` or `https` (e.g.,
    /// `javascript:`, `data:`, `file:`, `ftp:`). javascript: redirects
    /// in Location headers were historically followed by some browsers
    /// and remain a source of XSS.
    SchemeNotAllowed {
        /// The rejected scheme (e.g., `"javascript"`).
        scheme: String,
    },
    /// URI has an absolute http(s) URL but its host is not in the
    /// caller-provided `allowed_hosts` allowlist.
    HostNotAllowed {
        /// The host that was rejected.
        host: String,
    },
}

impl fmt::Display for RedirectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyUri => write!(f, "redirect URI is empty"),
            Self::ProtocolRelative => write!(
                f,
                "redirect URI starts with '//' (protocol-relative — defeats naive same-origin checks)"
            ),
            Self::BackslashInPath => write!(
                f,
                "redirect URI contains a backslash (intermediaries may normalize to '/' creating a protocol-relative URL)"
            ),
            Self::SchemeNotAllowed { scheme } => write!(
                f,
                "redirect URI scheme '{scheme}' not allowed (only 'http' and 'https')"
            ),
            Self::HostNotAllowed { host } => write!(
                f,
                "redirect URI host '{host}' not in the allowed-hosts allowlist"
            ),
        }
    }
}

impl std::error::Error for RedirectError {}

/// br-asupersync-0hj233: validate a candidate redirect URI for
/// open-redirect safety. Used by [`Redirect::to`] /
/// [`Redirect::permanent`] / [`Redirect::temporary`] (relative-only
/// strict mode) and [`Redirect::to_with_allowed_hosts`] (allowlist
/// mode).
///
/// **Strict mode (`allowed_hosts` is `None` or empty):**
/// - URI MUST start with `/`
/// - URI MUST NOT start with `//` (protocol-relative)
/// - URI MUST NOT contain backslash (`\`)
///
/// **Allowlist mode (`allowed_hosts` is `Some(&[...])`):**
/// - Same rules as strict mode for relative paths, OR
/// - Absolute http(s) URI whose host appears in `allowed_hosts`
fn validate_redirect_uri(uri: &str, allowed_hosts: Option<&[&str]>) -> Result<(), RedirectError> {
    if uri.is_empty() {
        return Err(RedirectError::EmptyUri);
    }
    // br-asupersync-oms1b7: reject any byte outside the
    // authority/path-allowed printable-ASCII set. RFC 3986 §3 caps
    // URI bytes at the unreserved + reserved + percent-encoded
    // alphabet, all of which fall in 0x21..=0x7E. Leading whitespace,
    // CR/LF, NUL, and control bytes are all rejected here so that
    // the protocol-relative `//` check downstream cannot be
    // sidestepped by `\u{0009}//attacker.com`,
    // `\u{0020}//attacker.com`, `\r\n//attacker.com`, etc.
    if uri.bytes().any(|b| !(0x21..=0x7E).contains(&b)) {
        return Err(RedirectError::ProtocolRelative);
    }
    if uri.contains('\\') {
        return Err(RedirectError::BackslashInPath);
    }
    if uri.starts_with("//") {
        return Err(RedirectError::ProtocolRelative);
    }
    // br-asupersync-oms1b7: also reject single-slash forms that some
    // browsers historically interpreted as protocol-relative when
    // the second character was unusual (`/\\attacker.com` is already
    // rejected by the BackslashInPath check above; this guards
    // against the `/%2f`-style encoded variant). The strictest
    // posture: a relative redirect must be `/` followed by a
    // non-`/`, non-`%2f`, non-`%5C` character.
    if let Some(rest) = uri.strip_prefix('/') {
        let lower_first = rest.bytes().next().map(|b| b.to_ascii_lowercase());
        if rest.starts_with("%2f")
            || rest.starts_with("%2F")
            || rest.starts_with("%5c")
            || rest.starts_with("%5C")
            || lower_first == Some(b'\\')
        {
            return Err(RedirectError::ProtocolRelative);
        }
    }
    if uri.starts_with('/') {
        // Relative path — accepted under both strict and allowlist modes.
        return Ok(());
    }
    // Not a relative path. Must be an absolute URI with a recognised scheme.
    let (scheme, rest) = match uri.split_once(':') {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => {
            // No scheme separator AND not relative — reject as malformed.
            return Err(RedirectError::SchemeNotAllowed {
                scheme: String::new(),
            });
        }
    };
    if scheme != "http" && scheme != "https" {
        return Err(RedirectError::SchemeNotAllowed { scheme });
    }
    // http(s) URI: extract host from `//host[:port]/path` form.
    let after_slashes = rest.strip_prefix("//").ok_or_else(|| {
        // http(s) URI must have `://` — without it, treat as bad.
        RedirectError::SchemeNotAllowed {
            scheme: scheme.clone(),
        }
    })?;
    let authority = after_slashes.split(['/', '?', '#']).next().unwrap_or("");
    // A redirect never needs userinfo, and a browser takes the host after
    // the last '@': "https://example.com:443@attacker.com/" goes to
    // attacker.com. Refuse it rather than parse it.
    if authority.contains('@') {
        return Err(RedirectError::HostNotAllowed {
            host: authority.to_string(),
        });
    }
    let host = match authority.strip_prefix('[') {
        // IPv6 literal: "[addr]" or "[addr]:port".
        Some(bracketed) => bracketed.split_once(']').map_or("", |(addr, _)| addr),
        None => authority
            .split_once(':')
            .map_or(authority, |(host, _)| host),
    };
    if host.is_empty() {
        return Err(RedirectError::HostNotAllowed {
            host: String::new(),
        });
    }
    let allowed_hosts = allowed_hosts.unwrap_or(&[]);
    if allowed_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(host))
    {
        Ok(())
    } else {
        Err(RedirectError::HostNotAllowed {
            host: host.to_string(),
        })
    }
}

/// HTTP redirect response.
#[derive(Debug, Clone)]
pub struct Redirect {
    status: StatusCode,
    location: String,
}

impl Redirect {
    /// 302 Found redirect.
    ///
    /// # Safe-by-default validation (br-asupersync-0hj233)
    ///
    /// Returns `Err(RedirectError)` for any URI that is not a
    /// site-relative path (`/foo`). Specifically rejects:
    /// - empty strings,
    /// - protocol-relative URIs (`//attacker.com/...`),
    /// - URIs containing backslash (`/\\attacker.com/...`),
    /// - any URI with a scheme (`javascript:`, `https://attacker.com/`, ...).
    ///
    /// For redirects that legitimately point at an external host (OAuth
    /// callbacks, payment hand-offs), use [`Self::to_with_allowed_hosts`]
    /// (validated against an allowlist) or [`Self::external_unchecked`]
    /// (caller asserts the URI is trustworthy).
    pub fn to(uri: impl Into<String>) -> Result<Self, RedirectError> {
        let uri = uri.into();
        validate_redirect_uri(&uri, None)?;
        Ok(Self {
            status: StatusCode::FOUND,
            location: uri,
        })
    }

    /// 301 Moved Permanently redirect. Same safe-by-default validation
    /// as [`Self::to`]; see that method for details.
    pub fn permanent(uri: impl Into<String>) -> Result<Self, RedirectError> {
        let uri = uri.into();
        validate_redirect_uri(&uri, None)?;
        Ok(Self {
            status: StatusCode::MOVED_PERMANENTLY,
            location: uri,
        })
    }

    /// 307 Temporary Redirect (preserves method). Same safe-by-default
    /// validation as [`Self::to`]; see that method for details.
    pub fn temporary(uri: impl Into<String>) -> Result<Self, RedirectError> {
        let uri = uri.into();
        validate_redirect_uri(&uri, None)?;
        Ok(Self {
            status: StatusCode::TEMPORARY_REDIRECT,
            location: uri,
        })
    }

    /// 302 Found redirect with an explicit allowed-hosts allowlist
    /// (br-asupersync-0hj233).
    ///
    /// Accepts site-relative paths AND absolute http(s) URIs whose
    /// host appears (case-insensitive) in `allowed_hosts`. Use this
    /// for redirect flows whose target host space is
    /// statically-known (OAuth providers, payment gateways).
    pub fn to_with_allowed_hosts(
        uri: impl Into<String>,
        allowed_hosts: &[&str],
    ) -> Result<Self, RedirectError> {
        let uri = uri.into();
        validate_redirect_uri(&uri, Some(allowed_hosts))?;
        Ok(Self {
            status: StatusCode::FOUND,
            location: uri,
        })
    }

    /// **Unchecked** 302 Found redirect — caller asserts the URI is
    /// trustworthy (br-asupersync-0hj233).
    ///
    /// This bypasses the open-redirect validation in [`Self::to`].
    /// Use ONLY when the URI is genuinely controlled by the
    /// application (a hard-coded constant, a value derived from
    /// trusted server-side state, or an OAuth provider URL whose
    /// host is independently verified). NEVER pass user-supplied
    /// strings (URL parameters, form fields, request body) to this
    /// constructor — that's the canonical phishing vector this bead
    /// is defending against.
    ///
    /// The CRLF stripping in the wire-format step (see
    /// `into_response`) still applies — this only bypasses the
    /// scheme/host validation.
    #[must_use]
    pub fn external_unchecked(uri: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FOUND,
            location: uri.into(),
        }
    }

    /// **Unchecked** 301 Moved Permanently redirect; see
    /// [`Self::external_unchecked`] for the safety contract.
    #[must_use]
    pub fn external_unchecked_permanent(uri: impl Into<String>) -> Self {
        Self {
            status: StatusCode::MOVED_PERMANENTLY,
            location: uri.into(),
        }
    }

    /// **Unchecked** 307 Temporary Redirect; see
    /// [`Self::external_unchecked`] for the safety contract.
    #[must_use]
    pub fn external_unchecked_temporary(uri: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TEMPORARY_REDIRECT,
            location: uri.into(),
        }
    }
}

impl IntoResponse for Redirect {
    fn into_response(self) -> Response {
        // br-asupersync-n5b94b: TOCTOU FIX - ensure final sanitization matches
        // the strict validation contract from validate_redirect_uri(). The
        // validation rejects ALL bytes outside 0x21-0x7E, so final sanitization
        // must enforce the same constraint to prevent control character
        // injection if validation is bypassed or weakened in future changes.
        let location = self
            .location
            .bytes()
            .filter(|&b| (0x21..=0x7E).contains(&b))
            .map(|b| b as char)
            .collect::<String>();
        Response::empty(self.status).header("location", location)
    }
}

// ─── Header Sanitization ─────────────────────────────────────────────────────

/// Strip every byte that RFC 9110 §5.5 forbids inside a `field-value`
/// from a header value (br-asupersync-5jtjo0).
///
/// RFC 9110 §5.5 defines `field-value = *( field-vchar [ 1*( SP / HTAB
/// / field-vchar ) field-vchar ] )` where `field-vchar = VCHAR /
/// obs-text` and `VCHAR = %x21-7E`. The legal byte set is therefore
///
///    HTAB (0x09), SP (0x20), VCHAR (0x21..=0x7E), obs-text (0x80..=0xFF)
///
/// EVERY OTHER byte (NUL 0x00, the C0 controls 0x01..=0x08,
/// 0x0A=LF, 0x0B=VT, 0x0C=FF, 0x0D=CR, 0x0E..=0x1F, DEL 0x7F) is a
/// header-value-syntax violation. The previous implementation only
/// stripped CR and LF — leaving NUL, BS, VT, FF, ESC, etc. to flow
/// through unfiltered. Embedded NUL is the highest-impact case: a
/// downstream proxy / WAF / log collector that scans the wire format
/// with C string semantics treats NUL as end-of-line and may parse a
/// forged additional header from whatever follows. VT/FF likewise smuggle
/// past tools that only look for CRLF.
///
/// Allowlist semantics: the function preserves HTAB / SP / printable
/// ASCII / obs-text and replaces every other byte with nothing
/// (deletion, not substitution — substitution would leak length
/// information that could be used as a covert channel). Empty result
/// is acceptable; it produces an empty header value, which the
/// wire-format codec serialises as `name:` with no value (RFC 9110 §5.5
/// allows empty field-values).
fn sanitize_header_value(value: String) -> String {
    if value.bytes().all(is_valid_header_value_byte) {
        return value;
    }
    // Filter byte-by-byte. We only ever drop bytes <= 0x7F that fail
    // the allowlist (NUL, the C0 controls except HTAB, DEL); UTF-8
    // lead bytes (0xC0..=0xFD) and continuation bytes (0x80..=0xBF)
    // are all >= 0x80 and pass through. Multi-byte UTF-8 sequences
    // therefore stay intact byte-for-byte, so the resulting Vec<u8>
    // is still valid UTF-8 and `from_utf8` succeeds. The infallible
    // `expect` documents the invariant; if it ever fires, the
    // allowlist function above changed in a way that broke UTF-8.
    let bytes: Vec<u8> = value
        .bytes()
        .filter(|&b| is_valid_header_value_byte(b))
        .collect();
    String::from_utf8(bytes)
        .expect("filter only drops ASCII control bytes that are not UTF-8 leads/conts")
}

/// br-asupersync-5jtjo0: byte-level allowlist for header-value syntax.
/// HTAB, SP, printable ASCII, and obs-text are accepted.
#[inline]
const fn is_valid_header_value_byte(b: u8) -> bool {
    b == 0x09 || (b >= 0x20 && b <= 0x7E) || b >= 0x80
}

/// Strip CR and LF from a header name to prevent CRLF injection attacks.
///
/// br-asupersync-n5b94b: TOCTOU FIX - apply same sanitization logic to header
/// names as header values to prevent asymmetric processing vulnerabilities.
/// Header names with raw CR/LF would be rejected by the wire-format codec, but
/// stripping them at the web layer is a defense-in-depth measure that ensures
/// the response state is always serializable and matches the symmetric
/// sanitization applied to header values.
pub(crate) fn sanitize_header_name(name: String) -> String {
    // Apply the same sanitization shape as header values for consistency.
    // RFC 9110 field names are tokens: alphanumeric bytes plus the visible
    // punctuation accepted in the match below.
    name.bytes()
        .filter(|&b| {
            // Valid token bytes: ALPHA, DIGIT, and the allowed punctuation set.
            matches!(b,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' |
                b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' |
                b'*' | b'+' | b'-' | b'.' | b'^' | b'_' |
                b'`' | b'|' | b'~'
            )
        })
        .map(|b| b as char)
        .collect()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "response_inline_tests.rs"]
mod tests;
