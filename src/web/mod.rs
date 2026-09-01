//! Web application framework (axum-like).
//!
//! Built on top of Asupersync's HTTP and Service layers, this module provides
//! a high-level API for building web applications with type-safe routing,
//! request extraction, and response conversion.
//!
//! # Quick Start
//!
//! ```ignore
//! use asupersync::Cx;
//! use asupersync::web::{
//!     AsyncCxFnHandler1, AsyncCxFnHandler2, Json, JsonExtract, Router, State,
//!     StatusCode, get,
//! };
//!
//! async fn list_users(cx: Cx, State(db): State<Db>) -> Json<Vec<User>> {
//!     Json(db.list_users(&cx).await)
//! }
//!
//! async fn create_user(
//!     cx: Cx,
//!     State(db): State<Db>,
//!     JsonExtract(input): JsonExtract<CreateUser>,
//! ) -> StatusCode {
//!     db.insert(&cx, input).await;
//!     StatusCode::CREATED
//! }
//!
//! let list_users = AsyncCxFnHandler1::<_, State<Db>>::new(list_users);
//! let create_user =
//!     AsyncCxFnHandler2::<_, State<Db>, JsonExtract<CreateUser>>::new(create_user);
//! let app = Router::new()
//!     .route("/users", get(list_users).post(create_user))
//!     .with_state(db);
//! ```
//!
//! Async handlers that receive [`crate::Cx`] must be wrapped with the matching
//! `AsyncCxFnHandler*` arity before registration. `JsonExtract<T>` is the
//! request extractor, while [`Json<T>`](Json) is the response type.
//!
//! # Extractors
//!
//! Extractors pull data from incoming requests:
//!
//! - [`Path<T>`]: URL path parameters
//! - [`Query<T>`]: Query string parameters
//! - [`Json<T>`]: JSON request body
//! - [`Header<T>`] / [`TypedHeader<T>`]: Typed request headers
//! - [`Cookie`]: Raw `Cookie` request header
//! - [`CookieJar`]: Parsed request cookies
//! - [`State<T>`]: Shared application state
//! - `HeaderMap`: All request headers
//!
//! # Responses
//!
//! Any type implementing [`IntoResponse`] can be returned from handlers:
//!
//! - [`Json<T>`]: Serialize as JSON
//! - [`Html<T>`]: HTML response
//! - [`StatusCode`]: Status-only response
//! - [`Redirect`]: HTTP redirect
//! - Tuples of `(StatusCode, impl IntoResponse)` for custom status

pub mod compress;
pub mod debug;
pub mod extract;
pub mod handler;
pub mod health;
pub mod middleware;
pub mod multipart;
pub mod negotiate;
pub mod nextjs_bootstrap;
pub mod request_region;
pub mod response;
pub mod router;
pub mod security;
pub mod session;
pub mod sse;
pub mod static_files;
#[cfg(test)]
pub mod static_files_audit_test;
#[cfg(test)]
pub mod static_files_path_traversal_audit;
/// WebSocket support for the web framework.
pub mod websocket;

/// Effective request-body budgets applied at the server, router, and route
/// boundaries.
///
/// Policies compose monotonically: every nested boundary takes the minimum of
/// each byte, count, and timeout ceiling. A route can therefore tighten an
/// outer server policy, but it cannot accidentally loosen one. The resolved
/// policy is inserted into request extensions together with its
/// [`extract::BodyLimits`] and [`multipart::MultipartLimits`] projections.
/// Handlers that need the protected effective value can inspect it with
/// [`extract::Request::body_policy`].
///
/// Existing callers that inject `BodyLimits` or `MultipartLimits` directly
/// remain supported. The first explicit `RequestBodyPolicy` boundary converts
/// those legacy values into the same monotonic policy plane.
///
/// The monotonic guarantee covers server, nested-router, route, and typed
/// projection updates while the router-provided request extensions remain
/// intact. Middleware that deliberately replaces the entire public
/// [`extract::Request::extensions`] map discards all router state, including
/// the protected policy snapshot, and is outside that guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RequestBodyPolicy {
    /// Format-independent ceiling for request DATA bytes.
    pub max_total_body_size: usize,
    /// JSON, form, and raw buffered-extractor ceilings.
    pub body_limits: extract::BodyLimits,
    /// Multipart total, field, header, count, and timeout ceilings.
    pub multipart_limits: multipart::MultipartLimits,
}

/// Private monotonic snapshot retained after the first explicit policy boundary.
///
/// Public projection extensions remain writable for backwards compatibility.
/// While the extensions map remains intact, extractors meet those projections
/// with this snapshot so later projection updates can tighten but never loosen
/// an already-enforced policy.
#[derive(Debug, Clone, Copy)]
pub(super) struct EnforcedRequestBodyPolicy {
    pub(super) policy: RequestBodyPolicy,
}

impl Default for RequestBodyPolicy {
    fn default() -> Self {
        Self {
            max_total_body_size: 16 * 1024 * 1024,
            body_limits: extract::BodyLimits::default(),
            multipart_limits: multipart::MultipartLimits::default(),
        }
    }
}

impl RequestBodyPolicy {
    /// Create the compatibility defaults: 16 MiB total, 10 MiB JSON/raw,
    /// 2 MiB form, and the standard multipart ceilings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the format-independent request DATA ceiling.
    #[must_use]
    pub fn max_total_body_size(mut self, bytes: usize) -> Self {
        self.max_total_body_size = bytes;
        self
    }

    /// Set the JSON, form, and raw extractor ceilings.
    #[must_use]
    pub fn body_limits(mut self, limits: extract::BodyLimits) -> Self {
        self.body_limits = limits;
        self
    }

    /// Set the multipart parser ceilings.
    #[must_use]
    pub fn multipart_limits(mut self, limits: multipart::MultipartLimits) -> Self {
        self.multipart_limits = limits;
        self
    }

    /// Meet this policy with another boundary's policy.
    ///
    /// Every field takes the smaller value, including timeout ceilings. For
    /// resolved policies this operation is commutative, associative, and
    /// idempotent. The returned policy is always resolved.
    #[must_use]
    pub fn tightened_with(self, other: Self) -> Self {
        Self {
            max_total_body_size: self.max_total_body_size.min(other.max_total_body_size),
            body_limits: self.body_limits.tightened_with(other.body_limits),
            multipart_limits: self.multipart_limits.tightened_with(other.multipart_limits),
        }
        .resolved()
    }

    /// Return the extractor projections after applying the format-independent
    /// total ceiling.
    #[must_use]
    pub fn resolved(self) -> Self {
        let total = self.max_total_body_size;
        let body_limits = self.body_limits.max_total_body_size(total);
        let multipart_limits = self.multipart_limits.max_total_body_size(total);
        Self {
            max_total_body_size: total,
            body_limits,
            multipart_limits,
        }
    }
}

pub use extract::{
    Accept, Authorization, ContentType, Cookie, CookieJar, Extension, Form, FromHeaderValue,
    FromRequest, FromRequestParts, Header, HeaderParseError, Json as JsonExtract, Path, Query,
    State, TypedHeader, UserAgent,
};
#[cfg(not(target_arch = "wasm32"))]
pub use extract::{CollectedStreamingRawBody, StreamingRawBody, StreamingRawBodyCollectError};
pub use handler::{
    AsyncCxFnHandler, AsyncCxFnHandler1, AsyncCxFnHandler2, AsyncCxFnHandler3, AsyncCxFnHandler4,
    AsyncCxFnHandler5, AsyncCxFnHandler6, AsyncCxFnHandler7, AsyncCxFnHandler8, FnHandler,
    FnHandler1, FnHandler2, FnHandler3, FnHandler4, FnHandler5, FnHandler6, FnHandler7, FnHandler8,
    FnHandler9, Handler,
};
pub use nextjs_bootstrap::{
    BootstrapCommand, BootstrapLogEvent, BootstrapRecoveryAction, NextjsBootstrapConfig,
    NextjsBootstrapError, NextjsBootstrapSnapshot, NextjsBootstrapState,
};
pub use response::{Html, IntoResponse, Json, Redirect, Response, StatusCode};
#[cfg(not(target_arch = "wasm32"))]
pub use response::{Http1StreamResponder, Http2StreamResponder};
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
pub use response::{Http3BodySender, Http3StreamResponder};
#[cfg(not(target_arch = "wasm32"))]
pub use router::{Http1ProducedHandlerFuture, Http2ProducedHandlerFuture};
pub use router::{
    HttpHandlerFuture, MethodRouter, RouteBodyPolicyInfo, RouteInfo, Router, delete, get, patch,
    post, put,
};
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
pub use router::{
    NativeH3ProducedEvent, NativeH3Router, NativeH3RouterConfig, NativeH3RouterDispatch,
    NativeH3RouterDispatchToken, NativeH3RouterEvent, NativeH3RouterIngress,
    NativeH3RouterPreparedProducedResponse, NativeH3RouterPreparedResponse,
    NativeH3RouterProducedDispatch, NativeH3RouterProducer, NativeH3RouterRefusal,
};
pub use sse::Http1SseResponse;
