//! Web application framework (axum-like).
//!
//! Built on top of Asupersync's HTTP and Service layers, this module provides
//! a high-level API for building web applications with type-safe routing,
//! request extraction, and response conversion.
//!
//! # Quick Start
//!
//! ```ignore
//! use asupersync::web::{Router, Json, State, get, post};
//!
//! async fn list_users(State(db): State<Db>) -> Json<Vec<User>> {
//!     Json(db.list_users().await)
//! }
//!
//! async fn create_user(State(db): State<Db>, Json(input): Json<CreateUser>) -> StatusCode {
//!     db.insert(input).await;
//!     StatusCode::CREATED
//! }
//!
//! let app = Router::new()
//!     .route("/users", get(list_users).post(create_user))
//!     .with_state(db);
//! ```
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
pub use router::{MethodRouter, RouteInfo, Router, delete, get, patch, post, put};
