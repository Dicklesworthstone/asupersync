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
use crate::http::h1::{BodyKind, OutgoingBody};
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h1::{Http1ProducedResponse, HttpError, OutgoingBodySender};
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

/// Deferred HTTP/1 chunked-body plan registered during web handler dispatch.
///
/// The plan contains no channel and starts no work. The production listener
/// creates both channel halves from its authoritative request [`Cx`] only
/// after routing and response-head validation complete.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct Http1StreamPlan {
    capacity: NonZeroUsize,
    max_frame_bytes: NonZeroUsize,
    producer: Http1StreamProducer,
}

#[cfg(not(target_arch = "wasm32"))]
impl Http1StreamPlan {
    pub(crate) fn buffered(body: Bytes) -> Self {
        let max_frame_bytes = NonZeroUsize::new(body.len()).unwrap_or(NonZeroUsize::MIN);
        Self {
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
        let status = response.status.as_u16();
        let mut produced = Http1ProducedResponse::chunked_with_max_frame_bytes(
            self.capacity,
            self.max_frame_bytes,
            status,
            crate::http::h1::types::default_reason(status),
            move |cx, sender| (self.producer)(cx, sender),
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
        if response.has_header("content-length") || response.has_header("transfer-encoding") {
            return Err("current HTTP/1 produced-response transport owns response framing");
        }
        Ok(plan)
    }
}

/// Request-scoped authoring handle for a supervised HTTP/1 chunked response.
///
/// This extractor is available only through
/// [`crate::web::Router::into_http1_produced_handler`]. Calling a handler that
/// requires it through another router adapter fails closed instead of minting
/// transport authority. Registering a producer does not create a channel,
/// spawn a task, or poll the producer; the HTTP/1 listener performs those
/// actions under its authoritative request [`Cx`] after dispatch completes.
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
/// ```ignore
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
    let host_with_port = after_slashes.split(['/', '?', '#']).next().unwrap_or("");
    let host = host_with_port
        .rsplit_once(':')
        .map_or(host_with_port, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']'); // IPv6 brackets
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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn http1_stream_responder_requires_produced_router_adapter() {
        let request = Request::new("GET", "/stream");
        let error = Http1StreamResponder::from_request_parts(&request)
            .expect_err("ordinary router requests have no produced-response authority");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            error.message,
            "HTTP/1 streamed-response transport unavailable"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn http1_stream_responder_duplicate_registration_poisons_slot() {
        let slot = Http1StreamSlot::default();
        let mut request = Request::new("GET", "/stream");
        request.extensions.insert_typed(slot.clone());
        let first = Http1StreamResponder::from_request_parts(&request).expect("first extractor");
        let second = Http1StreamResponder::from_request_parts(&request).expect("second extractor");

        let first_response = first.chunked(
            StatusCode::OK,
            NonZeroUsize::MIN,
            |_cx, sender| async move { Ok(sender) },
        );
        assert_eq!(first_response.status, StatusCode::OK);
        let second_response = second.chunked(
            StatusCode::OK,
            NonZeroUsize::MIN,
            |_cx, sender| async move { Ok(sender) },
        );
        assert_eq!(second_response.status, StatusCode::INTERNAL_SERVER_ERROR);
        let refusal = match slot.bind_response(&first_response) {
            Err(refusal) => refusal,
            Ok(_) => {
                panic!("the adapter must refuse the whole request after a duplicate registration")
            }
        };
        assert_eq!(refusal, "streamed response registered more than once");

        let late_plan = Http1StreamPlan {
            capacity: NonZeroUsize::MIN,
            max_frame_bytes: NonZeroUsize::MIN,
            producer: Box::new(|_cx, sender| Box::pin(async move { Ok(sender) })),
        };
        assert!(
            slot.register(late_plan).is_err(),
            "a consumed slot must remain terminal"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn produced_h1_envelope_router_preserves_custom_frame_limit() {
        let slot = Http1StreamSlot::default();
        let mut request = Request::new("GET", "/stream");
        request.extensions.insert_typed(slot.clone());
        let responder =
            Http1StreamResponder::from_request_parts(&request).expect("stream responder");
        let limit = NonZeroUsize::new(7).unwrap();

        let response = responder.chunked_with_max_frame_bytes(
            StatusCode::OK,
            NonZeroUsize::new(3).unwrap(),
            limit,
            |_cx, sender| async move { Ok(sender) },
        );
        let plan = slot
            .bind_response(&response)
            .expect("valid produced response")
            .expect("registered stream plan");

        assert_eq!(plan.capacity, NonZeroUsize::new(3).unwrap());
        assert_eq!(plan.max_frame_bytes, limit);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn produced_h1_envelope_buffered_route_preserves_large_body() {
        let body = Bytes::from(vec![
            b'x';
            Http1ProducedResponse::DEFAULT_MAX_FRAME_BYTES + 1
        ]);
        let body_len = body.len();
        let plan = Http1StreamPlan::buffered(body);

        assert_eq!(plan.capacity, NonZeroUsize::MIN);
        assert_eq!(plan.max_frame_bytes, NonZeroUsize::new(body_len).unwrap());

        let produced = plan.into_produced(Response::empty(StatusCode::OK));
        assert_eq!(
            produced.max_frame_bytes(),
            NonZeroUsize::new(body_len).unwrap()
        );
        assert_eq!(
            produced.max_retained_data_bytes(),
            u128::try_from(body_len).unwrap() * 3
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn http2_stream_responder_requires_produced_router_adapter() {
        let request = Request::new("GET", "/stream");
        let error = Http2StreamResponder::from_request_parts(&request)
            .expect_err("ordinary router requests have no HTTP/2 producer authority");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            error.message,
            "HTTP/2 produced-response transport unavailable"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn http2_stream_responder_duplicate_registration_poisons_slot() {
        let slot = Http2StreamSlot::default();
        let mut request = Request::new("GET", "/stream");
        request.extensions.insert_typed(slot.clone());
        let first = Http2StreamResponder::from_request_parts(&request).expect("first extractor");
        let second = Http2StreamResponder::from_request_parts(&request).expect("second extractor");

        let first_response = first.streaming(
            StatusCode::OK,
            NonZeroUsize::MIN,
            NonZeroUsize::new(1024).expect("non-zero frame limit"),
            |_cx, sender| async move { Ok(sender) },
        );
        assert_eq!(first_response.status, StatusCode::OK);
        let second_response = second.streaming(
            StatusCode::OK,
            NonZeroUsize::MIN,
            NonZeroUsize::new(1024).expect("non-zero frame limit"),
            |_cx, sender| async move { Ok(sender) },
        );
        assert_eq!(second_response.status, StatusCode::INTERNAL_SERVER_ERROR);
        let refusal = match slot.bind_response(&first_response, false) {
            Err(refusal) => refusal,
            Ok(_) => panic!("duplicate registration must poison the request"),
        };
        assert_eq!(refusal, "HTTP/2 response producer registered twice");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn http2_stream_binding_rejects_body_and_framing_collisions() {
        fn registered_slot() -> Http2StreamSlot {
            let slot = Http2StreamSlot::default();
            assert!(
                slot.register(Http2StreamPlan {
                    capacity: NonZeroUsize::MIN,
                    max_frame_bytes: NonZeroUsize::MIN,
                    producer: Box::new(|_cx, sender| Box::pin(async move { Ok(sender) })),
                })
                .is_ok(),
                "first registration succeeds"
            );
            slot
        }

        fn refusal(result: Result<Option<Http2StreamPlan>, &'static str>) -> &'static str {
            match result {
                Err(reason) => reason,
                Ok(_) => panic!("binding should fail closed"),
            }
        }

        assert_eq!(
            refusal(
                registered_slot().bind_response(&Response::new(StatusCode::OK, "buffered"), false)
            ),
            "produced HTTP/2 response cannot also carry a buffered body"
        );
        assert_eq!(
            refusal(
                registered_slot().bind_response(&Response::empty(StatusCode::NO_CONTENT), false)
            ),
            "produced HTTP/2 response requires a body-allowed status"
        );
        assert_eq!(
            refusal(registered_slot().bind_response(
                &Response::empty(StatusCode::OK).header("content-length", "0"),
                false,
            )),
            "produced HTTP/2 response owns message framing"
        );
        assert!(
            registered_slot()
                .bind_response(
                    &Response::empty(StatusCode::NO_CONTENT).header("content-length", "0"),
                    true,
                )
                .expect("HEAD may preserve authored response metadata without starting a body")
                .is_some()
        );
    }

    #[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
    #[test]
    fn produced_h3_stream_responder_requires_produced_router_adapter() {
        let request = Request::new("GET", "/stream");
        let error = Http3StreamResponder::from_request_parts(&request)
            .expect_err("ordinary router requests have no HTTP/3 producer authority");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            error.message,
            "HTTP/3 produced-response transport unavailable"
        );
    }

    #[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
    #[test]
    fn produced_h3_stream_responder_duplicate_registration_poisons_slot() {
        let slot = Http3StreamSlot::default();
        let mut request = Request::new("GET", "/stream");
        request.extensions.insert_typed(slot.clone());
        let first = Http3StreamResponder::from_request_parts(&request).expect("first extractor");
        let second = Http3StreamResponder::from_request_parts(&request).expect("second extractor");

        let first_response = first.streaming(
            StatusCode::OK,
            NonZeroUsize::MIN,
            NonZeroUsize::new(1024).expect("non-zero frame limit"),
            |_cx, sender| async move { Ok(sender) },
        );
        assert_eq!(first_response.status, StatusCode::OK);
        let second_response = second.streaming(
            StatusCode::OK,
            NonZeroUsize::MIN,
            NonZeroUsize::new(1024).expect("non-zero frame limit"),
            |_cx, sender| async move { Ok(sender) },
        );
        assert_eq!(second_response.status, StatusCode::INTERNAL_SERVER_ERROR);
        let refusal = match slot.bind_response(&first_response, false) {
            Err(refusal) => refusal,
            Ok(_) => panic!("duplicate registration must poison the request"),
        };
        assert_eq!(refusal, "HTTP/3 response producer registered twice");
    }

    #[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
    #[test]
    fn produced_h3_stream_binding_rejects_body_and_framing_collisions() {
        fn registered_slot() -> Http3StreamSlot {
            let slot = Http3StreamSlot::default();
            assert!(
                slot.register(Http3StreamPlan {
                    capacity: NonZeroUsize::MIN,
                    max_frame_bytes: NonZeroUsize::MIN,
                    producer: Box::new(|_cx, sender| Box::pin(async move { Ok(sender) })),
                })
                .is_ok(),
                "first registration succeeds"
            );
            slot
        }

        fn refusal(result: Result<Option<Http3StreamPlan>, &'static str>) -> &'static str {
            match result {
                Err(reason) => reason,
                Ok(_) => panic!("binding should fail closed"),
            }
        }

        assert_eq!(
            refusal(
                registered_slot().bind_response(&Response::new(StatusCode::OK, "buffered"), false)
            ),
            "produced HTTP/3 response cannot also carry a buffered body"
        );
        assert_eq!(
            refusal(
                registered_slot().bind_response(&Response::empty(StatusCode::NO_CONTENT), false)
            ),
            "produced HTTP/3 response requires a body-allowed status"
        );
        assert_eq!(
            refusal(registered_slot().bind_response(
                &Response::empty(StatusCode::OK).header("content-length", "0"),
                false,
            )),
            "produced HTTP/3 response owns message framing"
        );
        assert!(
            registered_slot()
                .bind_response(
                    &Response::empty(StatusCode::NO_CONTENT).header("content-length", "0"),
                    true,
                )
                .expect("HEAD may preserve authored response metadata without starting a body")
                .is_some()
        );
    }

    #[test]
    fn status_code_into_response() {
        let resp = StatusCode::NOT_FOUND.into_response();
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
        assert!(resp.body.is_empty());
    }

    #[test]
    fn string_into_response() {
        let resp = "hello".into_response();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn json_into_response() {
        let resp = Json(serde_json::json!({"ok": true})).into_response();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert!(!resp.body.is_empty());
    }

    #[test]
    fn html_into_response() {
        let resp = Html("<h1>Hello</h1>").into_response();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn redirect_into_response() {
        let resp = Redirect::to("/login")
            .expect("relative path must validate")
            .into_response();
        assert_eq!(resp.status, StatusCode::FOUND);
        assert_eq!(resp.headers.get("location").unwrap(), "/login");
    }

    /// br-asupersync-0hj233: Redirect::to MUST reject external URIs by
    /// default; only relative paths and URIs in an explicit allow-list
    /// (via to_with_allowed_hosts) are accepted. external_unchecked is
    /// the explicit escape hatch.
    #[test]
    fn redirect_to_rejects_external_uri_by_default() {
        // External http URL with arbitrary attacker host — REJECTED.
        let err = Redirect::to("https://attacker.com/phish").unwrap_err();
        assert!(
            matches!(err, RedirectError::HostNotAllowed { .. }),
            "external https URL must be rejected, got {err:?}"
        );

        // External http URL — REJECTED.
        let err = Redirect::to("http://attacker.com").unwrap_err();
        assert!(matches!(err, RedirectError::HostNotAllowed { .. }));

        // Same for permanent and temporary.
        assert!(Redirect::permanent("https://attacker.com").is_err());
        assert!(Redirect::temporary("https://attacker.com").is_err());
    }

    /// br-asupersync-0hj233: protocol-relative URLs '//attacker.com'
    /// are the canonical bypass for naive starts_with('/') defenses
    /// and MUST be rejected with the dedicated ProtocolRelative error
    /// so the failure mode is debuggable.
    #[test]
    fn redirect_to_rejects_protocol_relative_url() {
        let err = Redirect::to("//attacker.com/phish").unwrap_err();
        assert!(
            matches!(err, RedirectError::ProtocolRelative),
            "//... URL must be rejected as ProtocolRelative, got {err:?}"
        );
    }

    /// br-asupersync-0hj233: backslash variant of the protocol-relative
    /// bypass — some intermediaries normalize '\\' to '/' producing
    /// '//attacker.com'. Reject the backslash form too.
    #[test]
    fn redirect_to_rejects_backslash_path() {
        let err = Redirect::to("/\\attacker.com/phish").unwrap_err();
        assert!(
            matches!(err, RedirectError::BackslashInPath),
            "backslash in path must be rejected, got {err:?}"
        );
    }

    /// br-asupersync-0hj233: javascript: / data: / file: schemes MUST
    /// be rejected. Some browsers historically followed javascript:
    /// URLs in Location headers, enabling stored-XSS-via-redirect.
    #[test]
    fn redirect_to_rejects_non_http_schemes() {
        for uri in &[
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///etc/passwd",
            "ftp://attacker.com/",
        ] {
            let err = Redirect::to(*uri).unwrap_err();
            assert!(
                matches!(err, RedirectError::SchemeNotAllowed { .. }),
                "{uri} must be rejected as SchemeNotAllowed, got {err:?}"
            );
        }
    }

    /// br-asupersync-0hj233: empty URI is invalid.
    #[test]
    fn redirect_to_rejects_empty_uri() {
        let err = Redirect::to("").unwrap_err();
        assert!(matches!(err, RedirectError::EmptyUri));
    }

    /// br-asupersync-0hj233: relative paths with various edge-case
    /// shapes are accepted.
    #[test]
    fn redirect_to_accepts_well_formed_relative_paths() {
        for uri in &[
            "/",
            "/login",
            "/path/with/multiple/segments",
            "/path?with=query",
            "/path#fragment",
            "/path?next=/another",
        ] {
            assert!(
                Redirect::to(*uri).is_ok(),
                "relative path {uri} must validate"
            );
        }
    }

    /// br-asupersync-0hj233: to_with_allowed_hosts accepts absolute
    /// URIs whose host is allow-listed and rejects others.
    #[test]
    fn redirect_to_with_allowed_hosts_accepts_listed_rejects_others() {
        let allowed = &["example.com", "auth.example.com"];

        // Listed host — accepted.
        assert!(Redirect::to_with_allowed_hosts("https://example.com/path", allowed).is_ok());
        assert!(
            Redirect::to_with_allowed_hosts(
                "https://auth.example.com/oauth/callback?code=xyz",
                allowed
            )
            .is_ok()
        );
        // Case-insensitive host matching.
        assert!(Redirect::to_with_allowed_hosts("HTTPS://EXAMPLE.COM/", allowed).is_ok());
        // Relative path always accepted.
        assert!(Redirect::to_with_allowed_hosts("/local-path", allowed).is_ok());

        // Unlisted host — rejected.
        let err =
            Redirect::to_with_allowed_hosts("https://attacker.com/phish", allowed).unwrap_err();
        assert!(matches!(err, RedirectError::HostNotAllowed { .. }));

        // Subdomain not in allowlist — rejected (allowlist is exact match).
        let err =
            Redirect::to_with_allowed_hosts("https://evil.example.com/", allowed).unwrap_err();
        assert!(matches!(err, RedirectError::HostNotAllowed { .. }));

        // Protocol-relative even with allowlist — still rejected.
        let err = Redirect::to_with_allowed_hosts("//example.com/path", allowed).unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative));
    }

    /// br-asupersync-0hj233: external_unchecked is the explicit escape
    /// hatch for callers that genuinely need external redirects without
    /// an allowlist (e.g., dynamic OAuth providers). Verifies the API
    /// is reachable AND honors the URI verbatim.
    #[test]
    fn redirect_external_unchecked_accepts_arbitrary_uri() {
        // The whole point: NO validation — caller asserts trust.
        let r = Redirect::external_unchecked("https://anywhere.example/path?q=1");
        assert_eq!(r.status, StatusCode::FOUND);
        assert_eq!(r.location, "https://anywhere.example/path?q=1");

        let r = Redirect::external_unchecked_permanent("https://moved.example/");
        assert_eq!(r.status, StatusCode::MOVED_PERMANENTLY);

        let r = Redirect::external_unchecked_temporary("https://temp.example/");
        assert_eq!(r.status, StatusCode::TEMPORARY_REDIRECT);
    }

    #[test]
    fn tuple_status_override() {
        let resp = (StatusCode::CREATED, "done").into_response();
        assert_eq!(resp.status, StatusCode::CREATED);
    }

    #[test]
    fn response_header_helpers_are_case_insensitive() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.headers
            .insert("Content-Type".to_string(), "text/plain".to_string());

        assert_eq!(resp.header_value("content-type"), Some("text/plain"));
        assert_eq!(resp.header_value("CONTENT-TYPE"), Some("text/plain"));
        assert!(resp.has_header("content-type"));
    }

    #[test]
    fn response_set_header_canonicalizes_existing_case_variant() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.headers
            .insert("X-Trace-Id".to_string(), "old".to_string());

        resp.set_header("x-trace-id", "new");

        assert_eq!(resp.headers.get("x-trace-id"), Some(&"new".to_string()));
        assert!(!resp.headers.contains_key("X-Trace-Id"));
    }

    #[test]
    fn response_ensure_header_preserves_existing_value_and_canonicalizes_name() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.headers
            .insert("Server".to_string(), "custom".to_string());

        resp.ensure_header("server", "fallback");

        assert_eq!(resp.headers.get("server"), Some(&"custom".to_string()));
        assert!(!resp.headers.contains_key("Server"));
    }

    #[test]
    fn response_remove_header_clears_case_variants() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.headers.insert("Server".to_string(), "one".to_string());
        resp.headers.insert("server".to_string(), "two".to_string());

        let removed = resp.remove_header("SERVER");

        assert_eq!(removed.as_deref(), Some("two"));
        assert!(!resp.has_header("server"));
        assert!(resp.headers.is_empty());
    }

    #[test]
    fn result_ok_response() {
        let resp: Result<&str, StatusCode> = Ok("success");
        let r = resp.into_response();
        assert_eq!(r.status, StatusCode::OK);
    }

    #[test]
    fn result_err_response() {
        let resp: Result<&str, StatusCode> = Err(StatusCode::BAD_REQUEST);
        let r = resp.into_response();
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn status_code_properties() {
        assert!(StatusCode::OK.is_success());
        assert!(!StatusCode::OK.is_client_error());
        assert!(StatusCode::NOT_FOUND.is_client_error());
        assert!(StatusCode::INTERNAL_SERVER_ERROR.is_server_error());
    }

    // =========================================================================
    // Wave 50 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn status_code_debug_clone_copy_hash_display() {
        use std::collections::HashSet;
        let sc = StatusCode::OK;
        let dbg = format!("{sc:?}");
        assert!(dbg.contains("StatusCode"), "{dbg}");
        assert!(dbg.contains("200"), "{dbg}");
        let copied = sc;
        let cloned = sc;
        assert_eq!(copied, cloned);
        let display = format!("{sc}");
        assert_eq!(display, "200");
        let mut set = HashSet::new();
        set.insert(sc);
        assert!(set.contains(&StatusCode::OK));
    }

    #[test]
    fn response_debug_clone() {
        let resp = Response::new(StatusCode::OK, Bytes::from_static(b"hi"));
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("Response"), "{dbg}");
        let cloned = resp;
        assert_eq!(cloned.status, StatusCode::OK);
    }

    #[test]
    fn redirect_debug_clone() {
        let r = Redirect::to("/home").expect("relative path must validate");
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Redirect"), "{dbg}");
        let cloned = r;
        let dbg2 = format!("{cloned:?}");
        assert_eq!(dbg, dbg2);
    }

    // =========================================================================
    // CRLF injection defense
    // =========================================================================

    #[test]
    fn set_header_strips_crlf_from_value() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.set_header("x-test", "value\r\nEvil-Header: injected");
        assert_eq!(
            resp.headers.get("x-test").unwrap(),
            "valueEvil-Header: injected"
        );
    }

    #[test]
    fn set_header_strips_bare_lf_from_value() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.set_header("x-test", "line1\nline2");
        assert_eq!(resp.headers.get("x-test").unwrap(), "line1line2");
    }

    #[test]
    fn set_header_strips_bare_cr_from_value() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.set_header("x-test", "line1\rline2");
        assert_eq!(resp.headers.get("x-test").unwrap(), "line1line2");
    }

    #[test]
    fn builder_header_strips_crlf() {
        let resp = Response::empty(StatusCode::OK).header("x-test", "safe\r\nX-Injected: oops");
        assert_eq!(resp.headers.get("x-test").unwrap(), "safeX-Injected: oops");
    }

    #[test]
    fn ensure_header_strips_crlf_from_default() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.ensure_header("x-test", "default\r\nEvil: yes");
        assert_eq!(resp.headers.get("x-test").unwrap(), "defaultEvil: yes");
    }

    #[test]
    fn tuple_headers_strip_crlf() {
        let resp = (
            StatusCode::OK,
            vec![("x-test".to_string(), "a\r\nb".to_string())],
            "body",
        )
            .into_response();
        assert_eq!(resp.headers.get("x-test").unwrap(), "ab");
    }

    #[test]
    fn set_header_strips_crlf_from_name() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.set_header("x-test\r\nEvil-Header: injected", "value");
        // Invalid field-name bytes are stripped before lowercasing/insertion,
        // so the wire-format encoder never sees an injection vector or an
        // unserializable header name.
        assert!(resp.headers.contains_key("x-testevil-headerinjected"));
        assert!(
            !resp
                .headers
                .keys()
                .any(|k| k.contains(['\r', '\n', ':', ' ']))
        );
    }

    #[test]
    fn ensure_header_strips_crlf_from_name() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.ensure_header("x-test\r\nEvil:", "value");
        assert!(
            !resp
                .headers
                .keys()
                .any(|k| k.contains('\r') || k.contains('\n'))
        );
    }

    #[test]
    fn tuple_headers_strip_crlf_from_name() {
        let resp = (
            StatusCode::OK,
            vec![("x-test\r\nEvil:".to_string(), "value".to_string())],
            "body",
        )
            .into_response();
        assert!(
            !resp
                .headers
                .keys()
                .any(|k| k.contains('\r') || k.contains('\n'))
        );
    }

    #[test]
    fn clean_header_value_passes_through_unchanged() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.set_header("x-test", "normal-value");
        assert_eq!(resp.headers.get("x-test").unwrap(), "normal-value");
    }

    /// br-asupersync-ehtkns: Set-Cookie is multi-valued; calling
    /// `set_header("set-cookie", X)` (or `.header()`) twice must
    /// preserve BOTH cookies. Before the fix, the HashMap-backed
    /// header store silently dropped the first cookie, which let
    /// SessionMiddleware overwrite handler-emitted CSRF / remember-me
    /// cookies.
    #[test]
    fn set_cookie_appends_instead_of_overwriting() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.set_header("set-cookie", "csrf=abc123; HttpOnly");
        resp.set_header("set-cookie", "session=def456; HttpOnly; Secure");
        assert_eq!(resp.set_cookies.len(), 2, "both cookies must survive");
        assert_eq!(resp.set_cookies[0], "csrf=abc123; HttpOnly");
        assert_eq!(resp.set_cookies[1], "session=def456; HttpOnly; Secure");
        // Set-Cookie is NOT routed into the regular headers map.
        assert!(!resp.headers.contains_key("set-cookie"));
        // Case-insensitive header lookup still surfaces the first cookie
        // for backward compatibility with single-cookie callers.
        assert_eq!(
            resp.header_value("Set-Cookie"),
            Some("csrf=abc123; HttpOnly"),
        );
        assert!(resp.has_header("set-cookie"));
    }

    /// br-asupersync-ehtkns: append_set_cookie still strips CR/LF
    /// from the cookie line so a malicious cookie value cannot smuggle
    /// a second header onto the wire.
    #[test]
    fn append_set_cookie_strips_crlf_from_value() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.append_set_cookie("session=abc\r\nX-Injected: yes");
        assert_eq!(resp.set_cookies.len(), 1);
        assert!(!resp.set_cookies[0].contains('\r'));
        assert!(!resp.set_cookies[0].contains('\n'));
    }

    /// br-asupersync-ehtkns: removing the Set-Cookie header drains
    /// every queued cookie and surfaces the first as the legacy
    /// single-value return.
    #[test]
    fn remove_set_cookie_drains_all_queued_cookies() {
        let mut resp = Response::empty(StatusCode::OK);
        resp.append_set_cookie("a=1");
        resp.append_set_cookie("b=2");
        let dropped = resp.remove_header("Set-Cookie");
        assert_eq!(dropped.as_deref(), Some("a=1"));
        assert!(resp.set_cookies.is_empty(), "no cookies should remain");
    }

    #[test]
    fn json_html_debug_clone() {
        let j = Json(42);
        let dbg = format!("{j:?}");
        assert!(dbg.contains("Json"), "{dbg}");
        let jc = j;
        assert_eq!(format!("{jc:?}"), dbg);

        let h = Html("hello");
        let dbg2 = format!("{h:?}");
        assert!(dbg2.contains("Html"), "{dbg2}");
        let hc = h.clone();
        assert_eq!(format!("{hc:?}"), dbg2);
    }

    // ====================================================================
    // br-asupersync-5jtjo0: header-value sanitiser allowlist tests
    // ====================================================================

    #[test]
    fn _5jtjo0_strips_nul_byte_from_header_value() {
        let raw = String::from("alice\u{0000}forged-header: value");
        let cleaned = sanitize_header_value(raw);
        assert!(!cleaned.contains('\u{0000}'));
        assert_eq!(cleaned, "aliceforged-header: value");
    }

    #[test]
    fn _5jtjo0_strips_c0_control_bytes() {
        // 0x01-0x08, 0x0B, 0x0C, 0x0E-0x1F all rejected.
        let raw: String = (0x01u8..=0x1F)
            .filter(|b| *b != 0x09) // HTAB stays
            .map(|b| b as char)
            .collect::<String>()
            + "trailing";
        let cleaned = sanitize_header_value(raw);
        // Only "trailing" survives — every C0 control was stripped.
        assert_eq!(cleaned, "trailing");
    }

    #[test]
    fn _5jtjo0_preserves_htab_space_printable_ascii() {
        let raw = String::from("\tHello, World! 123 -_+=()[];,./?\\:");
        let cleaned = sanitize_header_value(raw.clone());
        assert_eq!(cleaned, raw);
    }

    #[test]
    fn _5jtjo0_preserves_obs_text_utf8_passthrough() {
        // UTF-8 codepoints whose bytes are >= 0x80 survive intact
        // (allowlist accepts 0x80..=0xFF as obs-text).
        let raw = String::from("café résumé日本語");
        let cleaned = sanitize_header_value(raw.clone());
        assert_eq!(cleaned, raw);
    }

    #[test]
    fn _5jtjo0_strips_crlf_legacy_behavior_preserved() {
        let raw = String::from("first\r\nforged-header: bad");
        let cleaned = sanitize_header_value(raw);
        assert_eq!(cleaned, "firstforged-header: bad");
    }

    #[test]
    fn _5jtjo0_strips_del_byte() {
        let raw = String::from("hello\u{007F}world");
        let cleaned = sanitize_header_value(raw);
        assert_eq!(cleaned, "helloworld");
    }

    // ====================================================================
    // br-asupersync-oms1b7: redirect protocol-relative + bypass tests
    // ====================================================================

    // ====================================================================
    // br-asupersync-n5b94b: TOCTOU vulnerability fixes
    // ====================================================================

    #[test]
    fn n5b94b_redirect_sanitization_matches_validation_strictness() {
        // Validation rejects control characters, final sanitization must too
        let redirect = Redirect::external_unchecked("http://example.com/path\x01\x1F");
        let response = redirect.into_response();
        let location = response.headers.get("location").unwrap();

        // Control characters must be stripped to match validation strictness
        assert!(!location.contains('\x01'));
        assert!(!location.contains('\x1F'));
        assert_eq!(location, "http://example.com/path");
    }

    #[test]
    fn n5b94b_header_name_sanitization_consistency() {
        let mut resp = Response::new(StatusCode::OK, "test");

        // Header names should be sanitized consistently with values
        resp.set_header("x-test\r\n-header\x01", "value");

        // Control characters should be stripped from header name
        let headers: Vec<_> = resp.headers.keys().collect();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0], "x-test-header");
    }

    #[test]
    fn n5b94b_header_case_normalization_atomic() {
        let mut resp = Response::new(StatusCode::OK, "test");

        // Add multiple case variants
        resp.headers
            .insert("X-Test".to_string(), "value1".to_string());
        resp.headers
            .insert("x-TEST".to_string(), "value2".to_string());
        resp.headers
            .insert("X-test".to_string(), "value3".to_string());

        // set_header should atomically remove all case variants
        resp.set_header("x-test", "final");

        let test_headers: Vec<_> = resp
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("x-test"))
            .collect();

        assert_eq!(
            test_headers.len(),
            1,
            "All case variants should be removed atomically"
        );
        assert_eq!(test_headers[0].0, "x-test");
        assert_eq!(test_headers[0].1, "final");
    }

    #[test]
    fn n5b94b_ensure_header_atomic_check_and_set() {
        let mut resp = Response::new(StatusCode::OK, "test");

        // Add header with non-normalized case
        resp.headers
            .insert("X-Custom".to_string(), "existing".to_string());

        // ensure_header should preserve existing value atomically
        resp.ensure_header("x-custom", "default");

        let custom_headers: Vec<_> = resp
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("x-custom"))
            .collect();

        assert_eq!(
            custom_headers.len(),
            1,
            "Should be exactly one header after ensure"
        );
        assert_eq!(custom_headers[0].0, "x-custom"); // normalized case
        assert_eq!(custom_headers[0].1, "existing"); // preserved value
    }

    #[test]
    fn oms1b7_rejects_protocol_relative() {
        let err = Redirect::to("//attacker.com/path").unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative));
    }

    #[test]
    fn oms1b7_rejects_leading_whitespace_then_protocol_relative() {
        // Without the byte-level prefilter, ` //attacker.com` could
        // bypass the `starts_with("//")` check on lenient browsers.
        let err = Redirect::to(" //attacker.com").unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative), "{err:?}");
    }

    #[test]
    fn oms1b7_rejects_leading_tab_then_protocol_relative() {
        let err = Redirect::to("\t//attacker.com").unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative), "{err:?}");
    }

    #[test]
    fn oms1b7_rejects_leading_crlf() {
        let err = Redirect::to("\r\n//attacker.com").unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative), "{err:?}");
    }

    #[test]
    fn oms1b7_rejects_percent_encoded_double_slash() {
        // /%2fattacker.com would be normalised by some browsers to
        // //attacker.com after percent-decoding. Reject up front.
        let err = Redirect::to("/%2fattacker.com").unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative), "{err:?}");
        let err = Redirect::to("/%2Fattacker.com").unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative), "{err:?}");
    }

    #[test]
    fn oms1b7_rejects_percent_encoded_backslash_after_slash() {
        let err = Redirect::to("/%5cattacker.com").unwrap_err();
        assert!(matches!(err, RedirectError::ProtocolRelative), "{err:?}");
    }

    #[test]
    fn oms1b7_accepts_legitimate_relative_paths() {
        assert!(Redirect::to("/login").is_ok());
        assert!(Redirect::to("/api/v1/foo?x=1&y=2").is_ok());
        assert!(Redirect::to("/path#anchor").is_ok());
    }

    #[test]
    fn oms1b7_rejects_null_byte_in_uri() {
        let err = Redirect::to("/safe\u{0000}//attacker.com").unwrap_err();
        // NUL is outside 0x21..=0x7E so caught by the byte prefilter.
        assert!(matches!(err, RedirectError::ProtocolRelative), "{err:?}");
    }
}
