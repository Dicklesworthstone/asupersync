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
//! - [`State<T>`]: Shared application state
//! - [`HeaderMap`]: All request headers
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

pub mod debug;
pub mod extract;
pub mod handler;
pub mod request_region;
pub mod response;
pub mod router;

pub use extract::{Form, FromRequest, FromRequestParts, Json as JsonExtract, Path, Query, State};
pub use handler::Handler;
pub use response::{Html, IntoResponse, Json, Redirect, Response, StatusCode};
pub use router::{delete, get, patch, post, put, MethodRouter, Router};
