//! Response types and the [`IntoResponse`] trait.
//!
//! Handlers return types that implement [`IntoResponse`], which converts them
//! into an HTTP response. Common types like `String`, `&str`, `Json<T>`, and
//! tuples are supported out of the box.

use std::collections::HashMap;
use std::fmt;

use crate::bytes::Bytes;

// ─── Status Codes ────────────────────────────────────────────────────────────

/// HTTP status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusCode(u16);

impl StatusCode {
    // 1xx Informational
    /// 100 Continue
    pub const CONTINUE: Self = Self(100);

    // 2xx Success
    /// 200 OK
    pub const OK: Self = Self(200);
    /// 201 Created
    pub const CREATED: Self = Self(201);
    /// 202 Accepted
    pub const ACCEPTED: Self = Self(202);
    /// 204 No Content
    pub const NO_CONTENT: Self = Self(204);

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
    /// 409 Conflict
    pub const CONFLICT: Self = Self(409);
    /// 413 Payload Too Large
    pub const PAYLOAD_TOO_LARGE: Self = Self(413);
    /// 415 Unsupported Media Type
    pub const UNSUPPORTED_MEDIA_TYPE: Self = Self(415);
    /// 422 Unprocessable Entity
    pub const UNPROCESSABLE_ENTITY: Self = Self(422);
    /// 429 Too Many Requests
    pub const TOO_MANY_REQUESTS: Self = Self(429);

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
            body: body.into(),
        }
    }

    /// Create an empty response with the given status code.
    #[must_use]
    pub fn empty(status: StatusCode) -> Self {
        Self::new(status, Bytes::new())
    }

    /// Add a header to the response.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
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
            resp.headers.insert(k, v);
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

/// HTTP redirect response.
#[derive(Debug, Clone)]
pub struct Redirect {
    status: StatusCode,
    location: String,
}

impl Redirect {
    /// 302 Found redirect.
    #[must_use]
    pub fn to(uri: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FOUND,
            location: uri.into(),
        }
    }

    /// 301 Moved Permanently redirect.
    #[must_use]
    pub fn permanent(uri: impl Into<String>) -> Self {
        Self {
            status: StatusCode::MOVED_PERMANENTLY,
            location: uri.into(),
        }
    }

    /// 307 Temporary Redirect (preserves method).
    #[must_use]
    pub fn temporary(uri: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TEMPORARY_REDIRECT,
            location: uri.into(),
        }
    }
}

impl IntoResponse for Redirect {
    fn into_response(self) -> Response {
        Response::empty(self.status).header("location", self.location)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        let resp = Redirect::to("/login").into_response();
        assert_eq!(resp.status, StatusCode::FOUND);
        assert_eq!(resp.headers.get("location").unwrap(), "/login");
    }

    #[test]
    fn tuple_status_override() {
        let resp = (StatusCode::CREATED, "done").into_response();
        assert_eq!(resp.status, StatusCode::CREATED);
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
}
