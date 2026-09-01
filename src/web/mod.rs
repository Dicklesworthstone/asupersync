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
#[cfg(not(target_arch = "wasm32"))]
pub use router::{Http1ProducedHandlerFuture, Http2ProducedHandlerFuture};
pub use router::{
    HttpHandlerFuture, MethodRouter, RouteInfo, Router, delete, get, patch, post, put,
};
#[cfg(all(feature = "http3", not(target_arch = "wasm32")))]
pub use router::{
    NativeH3Router, NativeH3RouterConfig, NativeH3RouterDispatch, NativeH3RouterDispatchToken,
    NativeH3RouterEvent, NativeH3RouterIngress, NativeH3RouterPreparedResponse,
    NativeH3RouterRefusal,
};
pub use sse::Http1SseResponse;
