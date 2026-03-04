//! HTTP/1.1 protocol types.
//!
//! Provides [`Method`], [`Version`], [`StatusCode`], and request/response types
//! for HTTP/1.1 protocol handling. Includes ergonomic builder patterns for
//! constructing requests with JSON, form, multipart, query, and auth helpers,
//! plus response body reading utilities.

use std::fmt;
use std::net::SocketAddr;

/// HTTP request method.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    /// GET
    Get,
    /// HEAD
    Head,
    /// POST
    Post,
    /// PUT
    Put,
    /// DELETE
    Delete,
    /// CONNECT
    Connect,
    /// OPTIONS
    Options,
    /// TRACE
    Trace,
    /// PATCH
    Patch,
    /// Extension method not covered by the standard set.
    Extension(String),
}

impl Method {
    /// Parse a method from its ASCII representation.
    #[must_use]
    pub fn from_bytes(src: &[u8]) -> Option<Self> {
        match src {
            b"GET" => Some(Self::Get),
            b"HEAD" => Some(Self::Head),
            b"POST" => Some(Self::Post),
            b"PUT" => Some(Self::Put),
            b"DELETE" => Some(Self::Delete),
            b"CONNECT" => Some(Self::Connect),
            b"OPTIONS" => Some(Self::Options),
            b"TRACE" => Some(Self::Trace),
            b"PATCH" => Some(Self::Patch),
            other => std::str::from_utf8(other)
                .ok()
                .filter(|s| is_valid_token(s))
                .map(|s| Self::Extension(s.to_owned())),
        }
    }

    /// Returns the method as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Connect => "CONNECT",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Patch => "PATCH",
            Self::Extension(s) => s,
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// HTTP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Version {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
}

impl Version {
    /// Parse a version from its ASCII representation (e.g. `HTTP/1.1`).
    #[must_use]
    pub fn from_bytes(src: &[u8]) -> Option<Self> {
        match src {
            b"HTTP/1.0" => Some(Self::Http10),
            b"HTTP/1.1" => Some(Self::Http11),
            _ => None,
        }
    }

    /// Returns the version as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// HTTP status code with named constants and category helpers.
///
/// Wraps a `u16` status code and provides ergonomic methods for checking
/// status categories (informational, success, redirect, client error,
/// server error).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatusCode(pub u16);

#[allow(missing_docs)]
impl StatusCode {
    // 1xx Informational
    pub const CONTINUE: Self = Self(100);
    pub const SWITCHING_PROTOCOLS: Self = Self(101);

    // 2xx Success
    pub const OK: Self = Self(200);
    pub const CREATED: Self = Self(201);
    pub const ACCEPTED: Self = Self(202);
    pub const NO_CONTENT: Self = Self(204);

    // 3xx Redirection
    pub const MOVED_PERMANENTLY: Self = Self(301);
    pub const FOUND: Self = Self(302);
    pub const SEE_OTHER: Self = Self(303);
    pub const NOT_MODIFIED: Self = Self(304);
    pub const TEMPORARY_REDIRECT: Self = Self(307);
    pub const PERMANENT_REDIRECT: Self = Self(308);

    // 4xx Client Error
    pub const BAD_REQUEST: Self = Self(400);
    pub const UNAUTHORIZED: Self = Self(401);
    pub const FORBIDDEN: Self = Self(403);
    pub const NOT_FOUND: Self = Self(404);
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    pub const REQUEST_TIMEOUT: Self = Self(408);
    pub const CONFLICT: Self = Self(409);
    pub const GONE: Self = Self(410);
    pub const LENGTH_REQUIRED: Self = Self(411);
    pub const PAYLOAD_TOO_LARGE: Self = Self(413);
    pub const URI_TOO_LONG: Self = Self(414);
    pub const UNSUPPORTED_MEDIA_TYPE: Self = Self(415);
    pub const UNPROCESSABLE_ENTITY: Self = Self(422);
    pub const TOO_MANY_REQUESTS: Self = Self(429);
    pub const REQUEST_HEADER_FIELDS_TOO_LARGE: Self = Self(431);

    // 5xx Server Error
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    pub const NOT_IMPLEMENTED: Self = Self(501);
    pub const BAD_GATEWAY: Self = Self(502);
    pub const SERVICE_UNAVAILABLE: Self = Self(503);
    pub const GATEWAY_TIMEOUT: Self = Self(504);

    /// The raw status code value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns `true` for 1xx (informational) status codes.
    #[must_use]
    pub const fn is_informational(self) -> bool {
        self.0 >= 100 && self.0 < 200
    }

    /// Returns `true` for 2xx (success) status codes.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 >= 200 && self.0 < 300
    }

    /// Returns `true` for 3xx (redirection) status codes.
    #[must_use]
    pub const fn is_redirection(self) -> bool {
        self.0 >= 300 && self.0 < 400
    }

    /// Returns `true` for 4xx (client error) status codes.
    #[must_use]
    pub const fn is_client_error(self) -> bool {
        self.0 >= 400 && self.0 < 500
    }

    /// Returns `true` for 5xx (server error) status codes.
    #[must_use]
    pub const fn is_server_error(self) -> bool {
        self.0 >= 500 && self.0 < 600
    }

    /// Returns the default reason phrase for this status code.
    #[must_use]
    pub fn reason(self) -> &'static str {
        default_reason(self.0)
    }
}

impl From<u16> for StatusCode {
    fn from(code: u16) -> Self {
        Self(code)
    }
}

impl From<StatusCode> for u16 {
    fn from(code: StatusCode) -> Self {
        code.0
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<u16> for StatusCode {
    fn eq(&self, other: &u16) -> bool {
        self.0 == *other
    }
}

impl PartialEq<StatusCode> for u16 {
    fn eq(&self, other: &StatusCode) -> bool {
        *self == other.0
    }
}

/// Parsed HTTP/1.1 request (request line + headers + body).
#[derive(Debug, Clone)]
pub struct Request {
    /// HTTP method (GET, POST, etc.).
    pub method: Method,
    /// Request URI (e.g. `/path?query`).
    pub uri: String,
    /// HTTP version.
    pub version: Version,
    /// Request headers as name-value pairs.
    pub headers: Vec<(String, String)>,
    /// Request body bytes.
    pub body: Vec<u8>,
    /// Trailing headers (only valid for chunked transfer-encoding).
    pub trailers: Vec<(String, String)>,
    /// Remote peer address for the connection (if known).
    pub peer_addr: Option<SocketAddr>,
}

impl Request {
    /// Create a request builder for the provided method and URI.
    #[must_use]
    pub fn builder(method: Method, uri: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(method, uri)
    }

    /// Create a `GET` request builder.
    #[must_use]
    pub fn get(uri: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(Method::Get, uri)
    }

    /// Create a `POST` request builder.
    #[must_use]
    pub fn post(uri: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(Method::Post, uri)
    }

    /// Create a `PUT` request builder.
    #[must_use]
    pub fn put(uri: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(Method::Put, uri)
    }

    /// Create a `DELETE` request builder.
    #[must_use]
    pub fn delete(uri: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(Method::Delete, uri)
    }

    /// Create a `HEAD` request builder.
    #[must_use]
    pub fn head(uri: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(Method::Head, uri)
    }

    /// Create a `PATCH` request builder.
    #[must_use]
    pub fn patch(uri: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(Method::Patch, uri)
    }

    /// Create an `OPTIONS` request builder.
    #[must_use]
    pub fn options(uri: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(Method::Options, uri)
    }

    /// Look up the first header value matching `name` (case-insensitive).
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Returns the `Content-Type` header value, if present.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.header_value("content-type")
    }

    /// Returns the `Content-Length` header value as `u64`, if present and valid.
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.header_value("content-length")
            .and_then(|v| v.parse().ok())
    }
}

const DEFAULT_MULTIPART_BOUNDARY: &str = "asupersync-boundary";

/// Errors that can occur while constructing multipart form payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartError {
    /// Boundary is empty or contains invalid bytes for multipart/form-data.
    InvalidBoundary,
}

impl fmt::Display for MultipartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBoundary => f.write_str("invalid multipart boundary"),
        }
    }
}

impl std::error::Error for MultipartError {}

#[derive(Debug, Clone)]
enum MultipartPart {
    Text {
        name: String,
        value: String,
    },
    File {
        name: String,
        filename: String,
        content_type: String,
        data: Vec<u8>,
    },
}

/// Multipart form-data payload builder for HTTP requests.
#[derive(Debug, Clone)]
pub struct MultipartForm {
    boundary: String,
    parts: Vec<MultipartPart>,
}

impl Default for MultipartForm {
    fn default() -> Self {
        Self::new()
    }
}

impl MultipartForm {
    /// Create an empty multipart form with a deterministic default boundary.
    #[must_use]
    pub fn new() -> Self {
        Self {
            boundary: DEFAULT_MULTIPART_BOUNDARY.to_owned(),
            parts: Vec::new(),
        }
    }

    /// Create an empty multipart form with a caller-provided boundary.
    ///
    /// Returns an error when the boundary is empty or contains invalid bytes.
    pub fn with_boundary(boundary: impl Into<String>) -> Result<Self, MultipartError> {
        let boundary = boundary.into();
        if !is_valid_multipart_boundary(&boundary) {
            return Err(MultipartError::InvalidBoundary);
        }
        Ok(Self {
            boundary,
            parts: Vec::new(),
        })
    }

    /// Return the active multipart boundary string.
    #[must_use]
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// Add a text field part.
    #[must_use]
    pub fn text(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.parts.push(MultipartPart::Text {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    /// Add a binary file part.
    #[must_use]
    pub fn file(
        mut self,
        name: impl Into<String>,
        filename: impl Into<String>,
        content_type: impl Into<String>,
        data: impl Into<Vec<u8>>,
    ) -> Self {
        self.parts.push(MultipartPart::File {
            name: name.into(),
            filename: filename.into(),
            content_type: content_type.into(),
            data: data.into(),
        });
        self
    }

    /// Return `Content-Type` header value for this multipart body.
    #[must_use]
    pub fn content_type_header(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    /// Encode the multipart form body bytes.
    #[must_use]
    pub fn to_body(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for part in &self.parts {
            body.extend_from_slice(b"--");
            body.extend_from_slice(self.boundary.as_bytes());
            body.extend_from_slice(b"\r\n");

            match part {
                MultipartPart::Text { name, value } => {
                    let escaped_name = escape_content_disposition_value(name);
                    body.extend_from_slice(
                        format!("Content-Disposition: form-data; name=\"{escaped_name}\"\r\n\r\n")
                            .as_bytes(),
                    );
                    body.extend_from_slice(value.as_bytes());
                    body.extend_from_slice(b"\r\n");
                }
                MultipartPart::File {
                    name,
                    filename,
                    content_type,
                    data,
                } => {
                    let escaped_name = escape_content_disposition_value(name);
                    let escaped_filename = escape_content_disposition_value(filename);
                    body.extend_from_slice(
                        format!(
                            "Content-Disposition: form-data; name=\"{escaped_name}\"; filename=\"{escaped_filename}\"\r\n"
                        )
                        .as_bytes(),
                    );
                    let safe_ct = sanitize_content_type(content_type);
                    body.extend_from_slice(format!("Content-Type: {safe_ct}\r\n\r\n").as_bytes());
                    body.extend_from_slice(data);
                    body.extend_from_slice(b"\r\n");
                }
            }
        }
        body.extend_from_slice(b"--");
        body.extend_from_slice(self.boundary.as_bytes());
        body.extend_from_slice(b"--\r\n");
        body
    }
}

fn is_valid_multipart_boundary(boundary: &str) -> bool {
    if boundary.is_empty() || boundary.len() > 70 {
        return false;
    }
    boundary.bytes().all(|b| {
        matches!(
            b,
            b'0'..=b'9'
                | b'A'..=b'Z'
                | b'a'..=b'z'
                | b'\''
                | b'('
                | b')'
                | b'+'
                | b'_'
                | b','
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'='
                | b'?'
        )
    })
}

fn escape_content_disposition_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\r' | '\n' | '\0' => {}
            '"' | '\\' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Returns `true` if the string is a valid HTTP `token` per RFC 9110 Section 5.6.2.
fn is_valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            matches!(
                b,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
                    | b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'a'..=b'z'
            )
        })
}

/// Sanitize a MIME content-type value by stripping CR, LF, and NUL characters
/// that could be used for header injection in multipart bodies.
fn sanitize_content_type(value: &str) -> String {
    value
        .chars()
        .filter(|&ch| ch != '\r' && ch != '\n' && ch != '\0')
        .collect()
}

/// Fluent builder for [`Request`].
#[derive(Debug, Clone)]
pub struct RequestBuilder {
    request: Request,
}

impl RequestBuilder {
    /// Create a builder with HTTP/1.1 defaults.
    #[must_use]
    pub fn new(method: Method, uri: impl Into<String>) -> Self {
        Self {
            request: Request {
                method,
                uri: uri.into(),
                version: Version::Http11,
                headers: Vec::new(),
                body: Vec::new(),
                trailers: Vec::new(),
                peer_addr: None,
            },
        }
    }

    /// Set the request method.
    #[must_use]
    pub fn method(mut self, method: Method) -> Self {
        self.request.method = method;
        self
    }

    /// Set the request URI.
    #[must_use]
    pub fn uri(mut self, uri: impl Into<String>) -> Self {
        self.request.uri = uri.into();
        self
    }

    /// Set the HTTP version.
    #[must_use]
    pub fn version(mut self, version: Version) -> Self {
        self.request.version = version;
        self
    }

    /// Add a header.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.request.headers.push((name.into(), value.into()));
        self
    }

    /// Add multiple headers.
    #[must_use]
    pub fn headers<I, N, V>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = (N, V)>,
        N: Into<String>,
        V: Into<String>,
    {
        self.request.headers.extend(
            headers
                .into_iter()
                .map(|(name, value)| (name.into(), value.into())),
        );
        self
    }

    /// Set request body bytes.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.request.body = body.into();
        self
    }

    /// Add a trailer header.
    #[must_use]
    pub fn trailer(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.request.trailers.push((name.into(), value.into()));
        self
    }

    /// Set remote peer address metadata.
    #[must_use]
    pub fn peer_addr(mut self, peer_addr: SocketAddr) -> Self {
        self.request.peer_addr = Some(peer_addr);
        self
    }

    /// Set the body to a JSON-serialized value and add `Content-Type: application/json`.
    ///
    /// Returns `Err` if serialization fails, preserving the builder for recovery.
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Result<Self, serde_json::Error> {
        let body = serde_json::to_vec(value)?;
        self.request.body = body;
        self.request
            .headers
            .push(("Content-Type".to_owned(), "application/json".to_owned()));
        Ok(self)
    }

    /// Set the body to URL-encoded form data and add
    /// `Content-Type: application/x-www-form-urlencoded`.
    #[must_use]
    pub fn form<I, K, V>(mut self, params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let encoded = url_encode_params(params);
        self.request.body = encoded.into_bytes();
        self.request.headers.push((
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        ));
        self
    }

    /// Set the body to multipart form-data and add the appropriate
    /// `Content-Type: multipart/form-data; boundary=...` header.
    #[must_use]
    pub fn multipart(mut self, form: &MultipartForm) -> Self {
        self.request.body = form.to_body();
        self.request
            .headers
            .push(("Content-Type".to_owned(), form.content_type_header()));
        self
    }

    /// Append query parameters to the URI.
    ///
    /// If the URI already contains a query string, parameters are appended with `&`.
    #[must_use]
    pub fn query<I, K, V>(mut self, params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let encoded = url_encode_params(params);
        if !encoded.is_empty() {
            if self.request.uri.contains('?') {
                self.request.uri.push('&');
            } else {
                self.request.uri.push('?');
            }
            self.request.uri.push_str(&encoded);
        }
        self
    }

    /// Set `Authorization: Bearer <token>` header.
    #[must_use]
    pub fn bearer_auth(self, token: impl AsRef<str>) -> Self {
        self.header("Authorization", format!("Bearer {}", token.as_ref()))
    }

    /// Set `Authorization: Basic <credentials>` header.
    ///
    /// Encodes `username:password` in base64. If `password` is `None`, encodes
    /// `username:`.
    #[must_use]
    pub fn basic_auth(self, username: impl AsRef<str>, password: Option<&str>) -> Self {
        let credentials = password.map_or_else(
            || format!("{}:", username.as_ref()),
            |pw| format!("{}:{}", username.as_ref(), pw),
        );
        let encoded = base64_encode(credentials.as_bytes());
        self.header("Authorization", format!("Basic {encoded}"))
    }

    /// Set the `Content-Type` header.
    #[must_use]
    pub fn content_type(self, content_type: impl Into<String>) -> Self {
        self.header("Content-Type", content_type)
    }

    /// Set the `Accept` header.
    #[must_use]
    pub fn accept(self, accept: impl Into<String>) -> Self {
        self.header("Accept", accept)
    }

    /// Build the request.
    #[must_use]
    pub fn build(self) -> Request {
        self.request
    }
}

/// Parsed HTTP/1.1 response (status line + headers + body).
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP version.
    pub version: Version,
    /// Status code (e.g. 200, 404).
    pub status: u16,
    /// Reason phrase (e.g. "OK", "Not Found").
    pub reason: String,
    /// Response headers as name-value pairs.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
    /// Trailing headers (only valid for chunked transfer-encoding).
    pub trailers: Vec<(String, String)>,
}

impl Response {
    /// Create a simple response with the given status, reason, and body.
    #[must_use]
    pub fn new(status: u16, reason: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            version: Version::Http11,
            status,
            reason: reason.into(),
            headers: Vec::new(),
            body: body.into(),
            trailers: Vec::new(),
        }
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Create a response builder using the standard reason phrase for `status`.
    #[must_use]
    pub fn builder(status: u16) -> ResponseBuilder {
        ResponseBuilder::new(status)
    }

    /// Add a trailer header.
    ///
    /// Trailers are only valid with `Transfer-Encoding: chunked`.
    #[must_use]
    pub fn with_trailer(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.trailers.push((name.into(), value.into()));
        self
    }

    /// Returns the typed [`StatusCode`] for this response.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        StatusCode(self.status)
    }

    /// Returns `true` if this is a 2xx success response.
    #[must_use]
    pub fn is_success(&self) -> bool {
        StatusCode(self.status).is_success()
    }

    /// Returns `true` if this is a 3xx redirection response.
    #[must_use]
    pub fn is_redirection(&self) -> bool {
        StatusCode(self.status).is_redirection()
    }

    /// Returns `true` if this is a 4xx client error response.
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        StatusCode(self.status).is_client_error()
    }

    /// Returns `true` if this is a 5xx server error response.
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        StatusCode(self.status).is_server_error()
    }

    /// Read the body as a UTF-8 string.
    ///
    /// Returns `Err` if the body contains invalid UTF-8.
    pub fn text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    /// Deserialize the body as JSON into type `T`.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    /// Returns a reference to the body bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    /// Look up the first header value matching `name` (case-insensitive).
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Returns the `Content-Type` header value, if present.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.header_value("content-type")
    }

    /// Returns the `Content-Length` header value as `u64`, if present and valid.
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.header_value("content-length")
            .and_then(|v| v.parse().ok())
    }

    /// Returns the `Location` header value, if present.
    #[must_use]
    pub fn location(&self) -> Option<&str> {
        self.header_value("location")
    }

    /// Convenience for `200 OK` with empty body.
    #[must_use]
    pub fn ok() -> Self {
        Self::new(200, "OK", Vec::<u8>::new())
    }

    /// Convenience for `404 Not Found` with empty body.
    #[must_use]
    pub fn not_found() -> Self {
        Self::new(404, "Not Found", Vec::<u8>::new())
    }

    /// Convenience for a JSON response: serializes `value`, sets status and Content-Type.
    pub fn json_response<T: serde::Serialize>(
        status: u16,
        value: &T,
    ) -> Result<Self, serde_json::Error> {
        let body = serde_json::to_vec(value)?;
        Ok(Self {
            version: Version::Http11,
            status,
            reason: default_reason(status).to_owned(),
            headers: vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Content-Length".to_owned(), body.len().to_string()),
            ],
            body,
            trailers: Vec::new(),
        })
    }
}

/// Fluent builder for [`Response`].
#[derive(Debug, Clone)]
pub struct ResponseBuilder {
    response: Response,
}

impl ResponseBuilder {
    /// Create a builder with HTTP/1.1 defaults and the standard reason phrase.
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self {
            response: Response {
                version: Version::Http11,
                status,
                reason: default_reason(status).to_owned(),
                headers: Vec::new(),
                body: Vec::new(),
                trailers: Vec::new(),
            },
        }
    }

    /// Set response status and reset reason phrase to the default for that code.
    #[must_use]
    pub fn status(mut self, status: u16) -> Self {
        self.response.status = status;
        default_reason(status).clone_into(&mut self.response.reason);
        self
    }

    /// Set response reason phrase.
    #[must_use]
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.response.reason = reason.into();
        self
    }

    /// Set HTTP version.
    #[must_use]
    pub fn version(mut self, version: Version) -> Self {
        self.response.version = version;
        self
    }

    /// Add a header.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.response.headers.push((name.into(), value.into()));
        self
    }

    /// Add multiple headers.
    #[must_use]
    pub fn headers<I, N, V>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = (N, V)>,
        N: Into<String>,
        V: Into<String>,
    {
        self.response.headers.extend(
            headers
                .into_iter()
                .map(|(name, value)| (name.into(), value.into())),
        );
        self
    }

    /// Set response body bytes.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.response.body = body.into();
        self
    }

    /// Add a trailer header.
    #[must_use]
    pub fn trailer(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.response.trailers.push((name.into(), value.into()));
        self
    }

    /// Build the response.
    #[must_use]
    pub fn build(self) -> Response {
        self.response
    }
}

/// Percent-encode a byte that is not unreserved per RFC 3986.
fn percent_encode_byte(byte: u8) -> String {
    format!("%{byte:02X}")
}

/// Percent-encode a string for use in URL query parameters.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&percent_encode_byte(byte)),
        }
    }
    out
}

/// URL-encode key-value pairs into a `key=value&key=value` string.
fn url_encode_params<I, K, V>(params: I) -> String
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut parts: Vec<String> = Vec::new();
    for (key, value) in params {
        parts.push(format!(
            "{}={}",
            percent_encode(key.as_ref()),
            percent_encode(value.as_ref())
        ));
    }
    parts.join("&")
}

/// Minimal base64 encoder (standard alphabet, with padding).
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let chunks = input.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);

        if chunk.len() > 1 {
            out.push(ALPHABET[((b1 & 0x0F) << 2 | b2 >> 6) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(ALPHABET[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Returns the standard reason phrase for a status code.
#[must_use]
pub fn default_reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        417 => "Expectation Failed",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_roundtrip() {
        for (bytes, expected) in [
            (&b"GET"[..], Method::Get),
            (b"POST", Method::Post),
            (b"DELETE", Method::Delete),
            (b"PATCH", Method::Patch),
            (b"CUSTOM", Method::Extension("CUSTOM".into())),
        ] {
            let parsed = Method::from_bytes(bytes).unwrap();
            assert_eq!(parsed, expected);
            let reparsed = Method::from_bytes(parsed.as_str().as_bytes()).unwrap();
            assert_eq!(reparsed, expected);
        }
    }

    #[test]
    fn version_roundtrip() {
        assert_eq!(Version::from_bytes(b"HTTP/1.0"), Some(Version::Http10));
        assert_eq!(Version::from_bytes(b"HTTP/1.1"), Some(Version::Http11));
        assert_eq!(Version::from_bytes(b"HTTP/2"), None);
        assert_eq!(Version::Http11.as_str(), "HTTP/1.1");
    }

    #[test]
    fn response_builder() {
        let resp =
            Response::new(200, "OK", b"hello".to_vec()).with_header("Content-Type", "text/plain");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.body, b"hello");
        assert!(resp.trailers.is_empty());
    }

    #[test]
    fn default_reasons() {
        assert_eq!(default_reason(200), "OK");
        assert_eq!(default_reason(404), "Not Found");
        assert_eq!(default_reason(417), "Expectation Failed");
        assert_eq!(default_reason(500), "Internal Server Error");
        assert_eq!(default_reason(999), "Unknown");
    }

    // Pure data-type tests (wave 12 – CyanBarn)

    #[test]
    fn method_display_all_standard() {
        assert_eq!(Method::Get.to_string(), "GET");
        assert_eq!(Method::Head.to_string(), "HEAD");
        assert_eq!(Method::Post.to_string(), "POST");
        assert_eq!(Method::Put.to_string(), "PUT");
        assert_eq!(Method::Delete.to_string(), "DELETE");
        assert_eq!(Method::Connect.to_string(), "CONNECT");
        assert_eq!(Method::Options.to_string(), "OPTIONS");
        assert_eq!(Method::Trace.to_string(), "TRACE");
        assert_eq!(Method::Patch.to_string(), "PATCH");
    }

    #[test]
    fn method_display_extension() {
        let ext = Method::Extension("PURGE".into());
        assert_eq!(ext.to_string(), "PURGE");
    }

    #[test]
    fn method_debug_clone_eq_hash() {
        use std::collections::HashSet;

        let m = Method::Get;
        let dbg = format!("{m:?}");
        assert!(dbg.contains("Get"));
        let cloned = m.clone();
        assert_eq!(m, cloned);

        let mut set = HashSet::new();
        set.insert(Method::Get);
        set.insert(Method::Post);
        set.insert(Method::Get);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn method_from_bytes_all_standard() {
        let methods = [
            (b"GET" as &[u8], Method::Get),
            (b"HEAD", Method::Head),
            (b"POST", Method::Post),
            (b"PUT", Method::Put),
            (b"DELETE", Method::Delete),
            (b"CONNECT", Method::Connect),
            (b"OPTIONS", Method::Options),
            (b"TRACE", Method::Trace),
            (b"PATCH", Method::Patch),
        ];
        for (bytes, expected) in methods {
            assert_eq!(Method::from_bytes(bytes), Some(expected));
        }
    }

    #[test]
    fn method_from_bytes_invalid_utf8() {
        // Invalid UTF-8 should return None (not an extension)
        assert!(Method::from_bytes(&[0xFF, 0xFE]).is_none());
    }

    #[test]
    fn method_inequality() {
        assert_ne!(Method::Get, Method::Post);
        assert_ne!(Method::Get, Method::Extension("GET".into()));
    }

    #[test]
    fn version_display() {
        assert_eq!(Version::Http10.to_string(), "HTTP/1.0");
        assert_eq!(Version::Http11.to_string(), "HTTP/1.1");
    }

    #[test]
    fn version_debug_copy_eq_hash() {
        use std::collections::HashSet;

        let v = Version::Http11;
        let dbg = format!("{v:?}");
        assert!(dbg.contains("Http11"));
        let copied = v;
        assert_eq!(v, copied);

        let mut set = HashSet::new();
        set.insert(Version::Http10);
        set.insert(Version::Http11);
        set.insert(Version::Http10);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn request_debug_clone() {
        let req = Request {
            method: Method::Get,
            uri: "/path".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: b"body".to_vec(),
            trailers: vec![],
            peer_addr: None,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("Get"));
        assert!(dbg.contains("/path"));

        let cloned = req;
        assert_eq!(cloned.method, Method::Get);
        assert_eq!(cloned.uri, "/path");
        assert_eq!(cloned.headers.len(), 1);
    }

    #[test]
    fn request_with_peer_addr() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let req = Request {
            method: Method::Post,
            uri: "/api".to_string(),
            version: Version::Http11,
            headers: vec![],
            body: vec![],
            trailers: vec![],
            peer_addr: Some(addr),
        };
        assert_eq!(req.peer_addr, Some(addr));
    }

    #[test]
    fn request_builder_sets_fields() {
        let peer_addr: SocketAddr = "10.0.0.9:9000".parse().unwrap();
        let req = Request::builder(Method::Patch, "/v1/items/7")
            .version(Version::Http10)
            .header("Host", "example.com")
            .header("X-Trace-Id", "abc123")
            .body(b"payload".to_vec())
            .trailer("Checksum", "sha256:deadbeef")
            .peer_addr(peer_addr)
            .build();

        assert_eq!(req.method, Method::Patch);
        assert_eq!(req.uri, "/v1/items/7");
        assert_eq!(req.version, Version::Http10);
        assert_eq!(
            req.headers,
            vec![
                ("Host".to_string(), "example.com".to_string()),
                ("X-Trace-Id".to_string(), "abc123".to_string()),
            ]
        );
        assert_eq!(req.body, b"payload");
        assert_eq!(
            req.trailers,
            vec![("Checksum".to_string(), "sha256:deadbeef".to_string())]
        );
        assert_eq!(req.peer_addr, Some(peer_addr));
    }

    #[test]
    fn request_convenience_builders_use_expected_method() {
        let get_req = Request::get("/health").build();
        assert_eq!(get_req.method, Method::Get);
        assert_eq!(get_req.uri, "/health");
        assert_eq!(get_req.version, Version::Http11);

        let post_req = Request::post("/submit").build();
        assert_eq!(post_req.method, Method::Post);
        assert_eq!(post_req.uri, "/submit");
        assert_eq!(post_req.version, Version::Http11);

        let put_req = Request::put("/resource/1").build();
        assert_eq!(put_req.method, Method::Put);

        let delete_req = Request::delete("/resource/1").build();
        assert_eq!(delete_req.method, Method::Delete);
    }

    #[test]
    fn response_with_trailer() {
        let resp = Response::new(200, "OK", Vec::<u8>::new())
            .with_header("Transfer-Encoding", "chunked")
            .with_trailer("Checksum", "abc123");
        assert_eq!(resp.trailers.len(), 1);
        assert_eq!(resp.trailers[0].0, "Checksum");
        assert_eq!(resp.trailers[0].1, "abc123");
    }

    #[test]
    fn response_debug_clone() {
        let resp = Response::new(404, "Not Found", b"missing".to_vec());
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("404"));
        let cloned = resp;
        assert_eq!(cloned.status, 404);
        assert_eq!(cloned.reason, "Not Found");
    }

    #[test]
    fn response_defaults_version_http11() {
        let resp = Response::new(200, "OK", Vec::<u8>::new());
        assert_eq!(resp.version, Version::Http11);
    }

    #[test]
    fn response_builder_uses_default_reason_and_chainable_fields() {
        let resp = Response::builder(201)
            .header("Content-Type", "application/json")
            .body(br#"{"ok":true}"#.to_vec())
            .trailer("Checksum", "abc123")
            .build();

        assert_eq!(resp.version, Version::Http11);
        assert_eq!(resp.status, 201);
        assert_eq!(resp.reason, "Created");
        assert_eq!(
            resp.headers,
            vec![("Content-Type".to_string(), "application/json".to_string())]
        );
        assert_eq!(resp.body, br#"{"ok":true}"#);
        assert_eq!(
            resp.trailers,
            vec![("Checksum".to_string(), "abc123".to_string())]
        );
    }

    #[test]
    fn response_builder_status_resets_reason_unless_overridden_afterward() {
        let resp = Response::builder(200)
            .reason("Everything Fine")
            .status(404)
            .build();
        assert_eq!(resp.status, 404);
        assert_eq!(resp.reason, "Not Found");

        let resp_with_custom_reason = Response::builder(200)
            .status(503)
            .reason("Service Busy")
            .build();
        assert_eq!(resp_with_custom_reason.status, 503);
        assert_eq!(resp_with_custom_reason.reason, "Service Busy");
    }

    #[test]
    fn default_reason_all_known() {
        let known = [
            (100, "Continue"),
            (201, "Created"),
            (204, "No Content"),
            (301, "Moved Permanently"),
            (302, "Found"),
            (304, "Not Modified"),
            (400, "Bad Request"),
            (401, "Unauthorized"),
            (403, "Forbidden"),
            (405, "Method Not Allowed"),
            (408, "Request Timeout"),
            (411, "Length Required"),
            (413, "Payload Too Large"),
            (414, "URI Too Long"),
            (431, "Request Header Fields Too Large"),
            (501, "Not Implemented"),
            (502, "Bad Gateway"),
            (503, "Service Unavailable"),
        ];
        for (code, expected) in known {
            assert_eq!(default_reason(code), expected, "code={code}");
        }
    }

    // ---- B.2 ergonomic builder tests ----

    #[test]
    fn status_code_constants_and_categories() {
        assert!(StatusCode::CONTINUE.is_informational());
        assert!(!StatusCode::CONTINUE.is_success());

        assert!(StatusCode::OK.is_success());
        assert!(StatusCode::CREATED.is_success());
        assert!(StatusCode::NO_CONTENT.is_success());

        assert!(StatusCode::MOVED_PERMANENTLY.is_redirection());
        assert!(StatusCode::TEMPORARY_REDIRECT.is_redirection());

        assert!(StatusCode::BAD_REQUEST.is_client_error());
        assert!(StatusCode::NOT_FOUND.is_client_error());
        assert!(StatusCode::TOO_MANY_REQUESTS.is_client_error());

        assert!(StatusCode::INTERNAL_SERVER_ERROR.is_server_error());
        assert!(StatusCode::SERVICE_UNAVAILABLE.is_server_error());
    }

    #[test]
    fn status_code_conversion_and_display() {
        let code = StatusCode::from(404u16);
        assert_eq!(code.as_u16(), 404);
        assert_eq!(u16::from(code), 404);
        assert_eq!(code.to_string(), "404");
        assert_eq!(code.reason(), "Not Found");
    }

    #[test]
    fn status_code_equality_with_u16() {
        assert_eq!(StatusCode::OK, 200u16);
        assert_eq!(200u16, StatusCode::OK);
        assert_ne!(StatusCode::OK, 201u16);
    }

    #[test]
    fn status_code_ordering() {
        assert!(StatusCode::OK < StatusCode::NOT_FOUND);
        assert!(StatusCode::BAD_REQUEST < StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn request_head_patch_options_builders() {
        let head = Request::head("/resource").build();
        assert_eq!(head.method, Method::Head);

        let patch = Request::patch("/resource/1").build();
        assert_eq!(patch.method, Method::Patch);

        let options = Request::options("*").build();
        assert_eq!(options.method, Method::Options);
    }

    #[test]
    fn request_header_lookup_case_insensitive() {
        let req = Request::get("/")
            .header("Content-Type", "text/html")
            .header("X-Request-Id", "abc123")
            .build();

        assert_eq!(req.header_value("content-type"), Some("text/html"));
        assert_eq!(req.header_value("CONTENT-TYPE"), Some("text/html"));
        assert_eq!(req.header_value("Content-Type"), Some("text/html"));
        assert_eq!(req.content_type(), Some("text/html"));
        assert_eq!(req.header_value("x-request-id"), Some("abc123"));
        assert!(req.header_value("missing").is_none());
    }

    #[test]
    fn request_content_length() {
        let req = Request::post("/upload")
            .header("Content-Length", "1024")
            .build();
        assert_eq!(req.content_length(), Some(1024));

        let req_no_cl = Request::get("/").build();
        assert!(req_no_cl.content_length().is_none());
    }

    #[test]
    fn request_json_body() {
        #[derive(serde::Serialize)]
        struct Payload {
            name: String,
            age: u32,
        }
        let payload = Payload {
            name: "Alice".to_owned(),
            age: 30,
        };
        let req = Request::post("/api/users").json(&payload).unwrap().build();

        assert_eq!(req.content_type(), Some("application/json"));
        let body_str = std::str::from_utf8(&req.body).unwrap();
        assert!(body_str.contains("\"name\":\"Alice\""));
        assert!(body_str.contains("\"age\":30"));
    }

    #[test]
    fn request_form_body() {
        let req = Request::post("/login")
            .form([("user", "alice"), ("pass", "s3cret")])
            .build();

        assert_eq!(
            req.content_type(),
            Some("application/x-www-form-urlencoded")
        );
        let body = std::str::from_utf8(&req.body).unwrap();
        assert!(body.contains("user=alice"));
        assert!(body.contains("pass=s3cret"));
    }

    #[test]
    fn request_form_encodes_special_chars() {
        let req = Request::post("/search")
            .form([("q", "hello world"), ("tag", "a&b=c")])
            .build();
        let body = std::str::from_utf8(&req.body).unwrap();
        assert!(body.contains("q=hello%20world"));
        assert!(body.contains("tag=a%26b%3Dc"));
    }

    #[test]
    fn multipart_with_boundary_validates_input() {
        assert!(MultipartForm::with_boundary("safe-boundary_123").is_ok());
        assert!(MultipartForm::with_boundary("").is_err());
        assert!(MultipartForm::with_boundary("bad boundary").is_err());
    }

    #[test]
    fn multipart_form_encodes_text_and_file_parts() {
        let form = MultipartForm::with_boundary("test-boundary")
            .unwrap()
            .text("field", "value")
            .file("upload", "hello.txt", "text/plain", b"hello".to_vec());

        let body = String::from_utf8(form.to_body()).unwrap();
        assert!(body.contains("--test-boundary\r\n"));
        assert!(body.contains("Content-Disposition: form-data; name=\"field\"\r\n\r\nvalue\r\n"));
        assert!(body.contains(
            "Content-Disposition: form-data; name=\"upload\"; filename=\"hello.txt\"\r\n"
        ));
        assert!(body.contains("Content-Type: text/plain\r\n\r\nhello\r\n"));
        assert!(body.ends_with("--test-boundary--\r\n"));
    }

    #[test]
    fn request_multipart_body_sets_content_type_and_body() {
        let form = MultipartForm::with_boundary("upload-boundary")
            .unwrap()
            .text("user", "alice");
        let req = Request::post("/upload").multipart(&form).build();

        assert_eq!(
            req.content_type(),
            Some("multipart/form-data; boundary=upload-boundary")
        );
        let body = String::from_utf8(req.body).unwrap();
        assert!(body.contains("name=\"user\"\r\n\r\nalice\r\n"));
        assert!(body.ends_with("--upload-boundary--\r\n"));
    }

    #[test]
    fn request_query_params() {
        let req = Request::get("/search")
            .query([("q", "rust async"), ("page", "1")])
            .build();
        assert!(req.uri.starts_with("/search?"));
        assert!(req.uri.contains("q=rust%20async"));
        assert!(req.uri.contains("page=1"));
    }

    #[test]
    fn request_query_appends_to_existing() {
        let req = Request::get("/search?limit=10")
            .query([("offset", "20")])
            .build();
        assert!(req.uri.contains("limit=10&offset=20"));
    }

    #[test]
    fn request_bearer_auth() {
        let req = Request::get("/api/me").bearer_auth("my-jwt-token").build();
        assert_eq!(
            req.header_value("authorization"),
            Some("Bearer my-jwt-token")
        );
    }

    #[test]
    fn request_basic_auth_with_password() {
        let req = Request::get("/api")
            .basic_auth("alice", Some("secret"))
            .build();
        let auth = req.header_value("authorization").unwrap();
        assert!(auth.starts_with("Basic "));
        // "alice:secret" => base64 "YWxpY2U6c2VjcmV0"
        assert_eq!(auth, "Basic YWxpY2U6c2VjcmV0");
    }

    #[test]
    fn request_basic_auth_without_password() {
        let req = Request::get("/api").basic_auth("alice", None).build();
        let auth = req.header_value("authorization").unwrap();
        // "alice:" => base64 "YWxpY2U6"
        assert_eq!(auth, "Basic YWxpY2U6");
    }

    #[test]
    fn request_content_type_and_accept() {
        let req = Request::post("/api")
            .content_type("application/xml")
            .accept("text/html")
            .build();
        assert_eq!(req.content_type(), Some("application/xml"));
        assert_eq!(req.header_value("accept"), Some("text/html"));
    }

    #[test]
    fn response_status_category_helpers() {
        let ok = Response::new(200, "OK", Vec::<u8>::new());
        assert!(ok.is_success());
        assert!(!ok.is_client_error());
        assert!(!ok.is_server_error());
        assert!(!ok.is_redirection());

        let redirect = Response::new(301, "Moved", Vec::<u8>::new());
        assert!(redirect.is_redirection());

        let not_found = Response::new(404, "Not Found", Vec::<u8>::new());
        assert!(not_found.is_client_error());

        let error = Response::new(500, "ISE", Vec::<u8>::new());
        assert!(error.is_server_error());
    }

    #[test]
    fn response_text_and_bytes() {
        let resp = Response::new(200, "OK", b"hello world".to_vec());
        assert_eq!(resp.text().unwrap(), "hello world");
        assert_eq!(resp.bytes(), b"hello world");
    }

    #[test]
    fn response_text_invalid_utf8() {
        let resp = Response::new(200, "OK", vec![0xFF, 0xFE]);
        assert!(resp.text().is_err());
    }

    #[test]
    fn response_json_deserialization() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct User {
            name: String,
            age: u32,
        }
        let resp = Response::new(200, "OK", br#"{"name":"Bob","age":25}"#.to_vec());
        let user: User = resp.json().unwrap();
        assert_eq!(
            user,
            User {
                name: "Bob".to_owned(),
                age: 25
            }
        );
    }

    #[test]
    fn response_header_lookup_and_content_type() {
        let resp = Response::new(200, "OK", Vec::<u8>::new())
            .with_header("Content-Type", "application/json")
            .with_header("Content-Length", "42")
            .with_header("Location", "https://example.com/new");

        assert_eq!(resp.content_type(), Some("application/json"));
        assert_eq!(resp.content_length(), Some(42));
        assert_eq!(resp.location(), Some("https://example.com/new"));
        assert!(resp.header_value("missing").is_none());
    }

    #[test]
    fn response_status_code_typed() {
        let resp = Response::new(201, "Created", Vec::<u8>::new());
        let code = resp.status_code();
        assert_eq!(code, StatusCode::CREATED);
        assert!(code.is_success());
    }

    #[test]
    fn response_ok_convenience() {
        let resp = Response::ok();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "OK");
        assert!(resp.body.is_empty());
    }

    #[test]
    fn response_not_found_convenience() {
        let resp = Response::not_found();
        assert_eq!(resp.status, 404);
        assert_eq!(resp.reason, "Not Found");
    }

    #[test]
    fn response_json_response_convenience() {
        #[derive(serde::Serialize)]
        struct ApiResponse {
            ok: bool,
        }
        let resp = Response::json_response(200, &ApiResponse { ok: true }).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type(), Some("application/json"));
        assert!(resp.content_length().is_some());
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(body.contains("\"ok\":true"));
    }

    #[test]
    fn percent_encode_preserves_unreserved() {
        assert_eq!(percent_encode("hello"), "hello");
        assert_eq!(percent_encode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(percent_encode("ABC123"), "ABC123");
    }

    #[test]
    fn percent_encode_encodes_special_chars() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
        assert_eq!(percent_encode("a=b&c"), "a%3Db%26c");
        assert_eq!(percent_encode("100%"), "100%25");
    }

    #[test]
    fn url_encode_params_basic() {
        let encoded = url_encode_params([("key", "value"), ("foo", "bar")]);
        assert_eq!(encoded, "key=value&foo=bar");
    }

    #[test]
    fn base64_encode_known_vectors() {
        // RFC 4648 test vectors
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_encode_credentials() {
        assert_eq!(base64_encode(b"alice:secret"), "YWxpY2U6c2VjcmV0");
        assert_eq!(base64_encode(b"alice:"), "YWxpY2U6");
    }
}
