//! HTTP/1.1 protocol types.
//!
//! Provides [`Method`], [`Version`], [`StatusCode`], and request/response types
//! for HTTP/1.1 protocol handling. Includes ergonomic builder patterns for
//! constructing requests with JSON, form, multipart, query, and auth helpers,
//! plus response body reading utilities.

use crate::bytes::{Buf, Bytes, BytesCursor};
use crate::http::body::{Body, Frame, SizeHint};
use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

/// HTTP request method.
#[derive(Clone, PartialEq, Eq, Hash)]
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

impl fmt::Debug for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Extension(method) => f.debug_tuple("Extension").field(method).finish(),
            method => f.write_str(method.as_str()),
        }
    }
}

/// HTTP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Version {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2 (br-asupersync-eprpk6): requests/responses carried over an
    /// HTTP/2 connection share these `Request`/`Response` types so one
    /// handler can serve both listener stacks.
    Http2,
}

impl Version {
    /// Parse a version from its ASCII representation (e.g. `HTTP/1.1`).
    ///
    /// Intentionally does **not** accept `HTTP/2.0`: HTTP/2 has no textual
    /// request-line version (RFC 9113 §3 — connections start with a binary
    /// preface), so an h1 request line claiming HTTP/2.0 stays rejected.
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
            Self::Http2 => "HTTP/2.0",
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
    pub const CLIENT_CLOSED_REQUEST: Self = Self(499);

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

/// Maximum encoded headers retained for one streaming multipart part.
const MULTIPART_STREAM_HEADER_LIMIT: usize = 64 * 1024;

/// An error constructing or reading a streaming multipart request body.
///
/// A producer error, a length mismatch, or a trailer frame is terminal: no
/// closing multipart delimiter is emitted and all remaining producers are
/// dropped. The legacy [`MultipartError`] remains unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MultipartBodyError {
    /// The boundary is not a valid MIME boundary of 1 through 70 bytes.
    InvalidBoundary,
    /// A metadata value is empty where required or contains a control byte.
    InvalidMetadata {
        /// The rejected metadata field.
        field: &'static str,
    },
    /// One part's encoded header block exceeds its fixed allocation bound.
    HeaderTooLarge {
        /// Maximum encoded header bytes, including its boundary line.
        limit: usize,
    },
    /// A data frame cannot be represented by a 64-bit body length.
    LengthOverflow,
    /// A producer's actual length differs from its declared or exact hint.
    LengthMismatch,
    /// HTTP trailers cannot be embedded inside a multipart part.
    TrailersNotAllowed,
    /// The part producer returned an error.
    Producer(String),
}

impl fmt::Display for MultipartBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBoundary => f.write_str("invalid streaming multipart boundary"),
            Self::InvalidMetadata { field } => {
                write!(f, "invalid streaming multipart {field}")
            }
            Self::HeaderTooLarge { limit } => {
                write!(f, "streaming multipart part headers exceed {limit} bytes")
            }
            Self::LengthOverflow => f.write_str("streaming multipart body length overflows u64"),
            Self::LengthMismatch => f.write_str("streaming multipart part length mismatch"),
            Self::TrailersNotAllowed => {
                f.write_str("streaming multipart parts cannot emit trailers")
            }
            Self::Producer(message) => write!(f, "streaming multipart producer failed: {message}"),
        }
    }
}

impl std::error::Error for MultipartBodyError {}

enum MultipartPartSource<B> {
    Buffered(Bytes),
    Stream(Pin<Box<B>>),
}

/// One text, buffered, or streaming field in a [`MultipartBody`].
///
/// Text fields and streaming files can share a form without sharing their
/// producer type. Different streaming producer types can use
/// [`crate::http::body::BoxBody`] when their data and error types agree.
/// Metadata is checked by [`MultipartBody::with_boundary`] before any output.
pub struct MultipartBodyPart<B = crate::http::body::Empty> {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    source: MultipartPartSource<B>,
    declared_length: Option<u64>,
    remaining: Option<u64>,
    header_length: usize,
}

impl<B> fmt::Debug for MultipartBodyPart<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultipartBodyPart")
            .field("name", &self.name)
            .field("filename", &self.filename)
            .field("content_type", &self.content_type)
            .field("declared_length", &self.declared_length)
            .finish_non_exhaustive()
    }
}

impl<B> MultipartBodyPart<B> {
    /// Add an owned UTF-8 text field without copying it into a whole form.
    #[must_use]
    pub fn text(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::bytes(name, Bytes::from(value.into()))
    }

    /// Add an already-buffered field. The `Bytes` allocation is transferred
    /// directly into an output frame when this part is reached.
    #[must_use]
    pub fn bytes(name: impl Into<String>, value: impl Into<Bytes>) -> Self {
        Self {
            name: name.into(),
            filename: None,
            content_type: None,
            source: MultipartPartSource::Buffered(value.into()),
            declared_length: None,
            remaining: None,
            header_length: 0,
        }
    }

    /// Add a lazy body producer, defaulting its media type to
    /// `application/octet-stream`. No producer frame is polled at construction.
    /// The producer is pinned internally, so it need not implement `Unpin`.
    #[must_use]
    pub fn stream(name: impl Into<String>, body: B) -> Self {
        Self {
            name: name.into(),
            filename: None,
            content_type: Some("application/octet-stream".to_owned()),
            source: MultipartPartSource::Stream(Box::pin(body)),
            declared_length: None,
            remaining: None,
            header_length: 0,
        }
    }

    /// Set the quoted filename parameter. Quotes and backslashes are escaped;
    /// control bytes are refused when the form is constructed.
    #[must_use]
    pub fn filename(mut self, filename: impl Into<String>) -> Self {
        self.filename = Some(filename.into());
        self
    }

    /// Set this part's media type. CR, LF, NUL and other ASCII control bytes
    /// are refused when the form is constructed.
    #[must_use]
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Declare an exact part length, overriding the producer's size hint.
    ///
    /// This is checked against actual DATA and EOF; it does not add a
    /// `Content-Length` header inside the multipart field. An overlong frame
    /// is rejected before any of that frame is returned to the transport.
    #[must_use]
    pub fn with_length(mut self, length: u64) -> Self {
        self.declared_length = Some(length);
        self
    }

    fn effective_content_type(&self) -> Option<&str> {
        self.content_type
            .as_deref()
            .or_else(|| self.filename.as_ref().map(|_| "application/octet-stream"))
    }

    fn checked_header_length(&self, boundary: &str) -> Result<usize, MultipartBodyError> {
        let mut length = b"--\r\nContent-Disposition: form-data; name=\"\"\r\n\r\n"
            .len()
            .saturating_add(boundary.len())
            .saturating_add(self.name.len());
        if let Some(filename) = &self.filename {
            length = length
                .saturating_add(b"; filename=\"\"".len())
                .saturating_add(filename.len());
        }
        if let Some(content_type) = self.effective_content_type() {
            length = length
                .saturating_add(b"\r\nContent-Type: ".len())
                .saturating_add(content_type.len());
        }
        // Bound work and allocation before escaping potentially large input.
        if length > MULTIPART_STREAM_HEADER_LIMIT {
            return Err(MultipartBodyError::HeaderTooLarge {
                limit: MULTIPART_STREAM_HEADER_LIMIT,
            });
        }
        for (field, value) in [
            ("name", Some(self.name.as_str())),
            ("filename", self.filename.as_deref()),
            ("content type", self.effective_content_type()),
        ] {
            if let Some(value) = value {
                if value.bytes().any(|byte| byte < b' ' || byte == 0x7f)
                    || field == "content type" && value.trim().is_empty()
                {
                    return Err(MultipartBodyError::InvalidMetadata { field });
                }
            }
        }
        for value in [Some(self.name.as_str()), self.filename.as_deref()]
            .into_iter()
            .flatten()
        {
            length = length.saturating_add(
                value
                    .bytes()
                    .filter(|&byte| matches!(byte, b'"' | b'\\'))
                    .count(),
            );
        }
        if length > MULTIPART_STREAM_HEADER_LIMIT {
            return Err(MultipartBodyError::HeaderTooLarge {
                limit: MULTIPART_STREAM_HEADER_LIMIT,
            });
        }
        Ok(length)
    }

    fn encode_head(&self, boundary: &str) -> Bytes {
        let mut encoded = Vec::with_capacity(self.header_length);
        encoded.extend_from_slice(b"--");
        encoded.extend_from_slice(boundary.as_bytes());
        encoded.extend_from_slice(b"\r\nContent-Disposition: form-data; name=\"");
        append_multipart_quoted_value(&mut encoded, &self.name);
        encoded.extend_from_slice(b"\"");
        if let Some(filename) = &self.filename {
            encoded.extend_from_slice(b"; filename=\"");
            append_multipart_quoted_value(&mut encoded, filename);
            encoded.extend_from_slice(b"\"");
        }
        if let Some(content_type) = self.effective_content_type() {
            encoded.extend_from_slice(b"\r\nContent-Type: ");
            encoded.extend_from_slice(content_type.as_bytes());
        }
        encoded.extend_from_slice(b"\r\n\r\n");
        debug_assert_eq!(encoded.len(), self.header_length);
        Bytes::from(encoded)
    }
}

/// One multipart output frame, preserving the source buffer's segmentation.
///
/// Generated delimiters, headers and owned text use `Framing`; streaming
/// producer DATA is returned as `Payload` without copying or requiring `Unpin`.
pub enum MultipartChunk<D> {
    /// Multipart syntax or an already-buffered field.
    Framing(BytesCursor),
    /// The original data buffer returned by a part producer.
    Payload(D),
}

impl<D: Buf> fmt::Debug for MultipartChunk<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultipartChunk")
            .field("remaining", &self.remaining())
            .finish_non_exhaustive()
    }
}

impl<D: Buf> Buf for MultipartChunk<D> {
    fn remaining(&self) -> usize {
        match self {
            Self::Framing(bytes) => bytes.remaining(),
            Self::Payload(data) => data.remaining(),
        }
    }

    fn chunk(&self) -> &[u8] {
        match self {
            Self::Framing(bytes) => bytes.chunk(),
            Self::Payload(data) => data.chunk(),
        }
    }

    fn advance(&mut self, count: usize) {
        match self {
            Self::Framing(bytes) => bytes.advance(count),
            Self::Payload(data) => data.advance(count),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultipartBodyPhase {
    Head,
    Data,
    Separator,
    Closing,
    Done,
}

/// A lazy multipart/form-data upload over the shared [`Body`] contract.
///
/// Only the current part is polled. Producer DATA is forwarded without copying;
/// generated headers are limited to 64 KiB per part. Each call returns at most
/// one frame and no background task or whole-upload buffer is created. The
/// caller still owns the cost of its supplied part list, buffered fields and
/// individual producer frames.
///
/// Supply a boundary that cannot occur as a delimiter in any part (typically a
/// fresh high-entropy value chosen by the caller). A streaming encoder cannot
/// pre-scan arbitrary producers to prove that condition. Unlike the legacy
/// [`MultipartForm`], this API does not silently choose a deterministic boundary.
/// Parts with the same name remain separate and retain their supplied order.
///
/// The size hint is exact only when every part supplies a known length and the
/// aggregate fits in `u64`. Each known length is checked against actual DATA and
/// EOF. A part error, unexpected trailers, or length mismatch terminates the
/// body, drops queued producers, and never emits a successful closing delimiter.
///
/// For a text-only form, select the otherwise unused producer type explicitly:
///
/// ```
/// use asupersync::http::body::Empty;
/// use asupersync::http::h1::{MultipartBody, MultipartBodyError, MultipartBodyPart};
///
/// let body = MultipartBody::<Empty>::with_boundary(
///     "chosen-for-these-fields",
///     [MultipartBodyPart::text("message", "hello")],
/// )?;
/// assert_eq!(body.boundary(), "chosen-for-these-fields");
/// # Ok::<(), MultipartBodyError>(())
/// ```
pub struct MultipartBody<B = crate::http::body::Empty> {
    boundary: String,
    parts: VecDeque<MultipartBodyPart<B>>,
    phase: MultipartBodyPhase,
    remaining: Option<u64>,
}

impl<B> fmt::Debug for MultipartBody<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultipartBody")
            .field("boundary", &self.boundary)
            .field("remaining_parts", &self.parts.len())
            .field("phase", &self.phase)
            .field("remaining", &self.remaining)
            .finish()
    }
}

impl<B: Body> MultipartBody<B> {
    /// Validate all metadata and create a one-shot multipart body.
    ///
    /// No DATA is polled here. The boundary must satisfy MIME's 1–70 byte
    /// grammar; internal spaces are allowed, a trailing space is not. Names
    /// and filenames are quoted and escaped rather than interpreted as header
    /// fragments. Metadata containing ASCII controls is rejected.
    pub fn with_boundary(
        boundary: impl Into<String>,
        parts: impl IntoIterator<Item = MultipartBodyPart<B>>,
    ) -> Result<Self, MultipartBodyError> {
        let boundary = boundary.into();
        if !is_valid_streaming_multipart_boundary(&boundary) {
            return Err(MultipartBodyError::InvalidBoundary);
        }
        let mut remaining = u64::try_from(boundary.len()).ok().and_then(|n| n.checked_add(6));
        let mut queued = VecDeque::new();
        for mut part in parts {
            part.header_length = part.checked_header_length(&boundary)?;
            part.remaining = part.declared_length.or_else(|| match &part.source {
                MultipartPartSource::Buffered(bytes) => u64::try_from(bytes.len()).ok(),
                MultipartPartSource::Stream(body) => body.size_hint().exact(),
            });
            remaining = remaining.and_then(|length| {
                length
                    .checked_add(u64::try_from(part.header_length).ok()?)?
                    .checked_add(part.remaining?)?
                    .checked_add(2)
            });
            queued.push_back(part);
        }
        Ok(Self {
            boundary,
            parts: queued,
            phase: MultipartBodyPhase::Head,
            remaining,
        })
    }

    /// The exact boundary used by both the body and its media-type header.
    #[must_use]
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// The media type for the outer HTTP request. Quoting also supports MIME
    /// boundary characters, such as `:` and spaces, that are not HTTP tokens.
    #[must_use]
    pub fn content_type_header(&self) -> String {
        format!("multipart/form-data; boundary=\"{}\"", self.boundary)
    }

    fn fail(&mut self, error: MultipartBodyError) -> MultipartBodyError {
        self.phase = MultipartBodyPhase::Done;
        self.remaining = Some(0);
        // Producer destructors are caller code. Publish terminal ownership
        // before invoking them, even if a caller catches a destructor panic.
        let retired = std::mem::take(&mut self.parts);
        drop(retired);
        error
    }

    fn emit(
        &mut self,
        chunk: MultipartChunk<B::Data>,
    ) -> Result<Frame<MultipartChunk<B::Data>>, MultipartBodyError> {
        let Ok(length) = u64::try_from(chunk.remaining()) else {
            return Err(self.fail(MultipartBodyError::LengthOverflow));
        };
        if let Some(remaining) = self.remaining {
            let Some(remaining) = remaining.checked_sub(length) else {
                return Err(self.fail(MultipartBodyError::LengthMismatch));
            };
            self.remaining = Some(remaining);
        }
        Ok(Frame::Data(chunk))
    }
}

impl<B> Body for MultipartBody<B>
where
    B: Body,
    B::Error: fmt::Display,
{
    type Data = MultipartChunk<B::Data>;
    type Error = MultipartBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        // An always-ready producer may emit arbitrarily many empty frames.
        // Yield after bounded work even when no output bytes are available.
        for _ in 0..32 {
            match this.phase {
                MultipartBodyPhase::Head => {
                    let Some(part) = this.parts.front() else {
                        this.phase = MultipartBodyPhase::Closing;
                        continue;
                    };
                    let head = part.encode_head(&this.boundary);
                    this.phase = MultipartBodyPhase::Data;
                    return Poll::Ready(Some(this.emit(MultipartChunk::Framing(
                        BytesCursor::new(head),
                    ))));
                }
                MultipartBodyPhase::Data => {
                    let part = this.parts.front_mut().expect("multipart DATA owns a part");
                    let frame = match &mut part.source {
                        MultipartPartSource::Buffered(bytes) => {
                            if bytes.is_empty() {
                                None
                            } else {
                                Some(Ok(Frame::Data(MultipartChunk::Framing(BytesCursor::new(
                                    std::mem::take(bytes),
                                )))))
                            }
                        }
                        MultipartPartSource::Stream(body) => {
                            std::task::ready!(body.as_mut().poll_frame(cx))
                                .map(|frame| {
                                    frame.map(|frame| frame.map_data(MultipartChunk::Payload))
                                })
                        }
                    };
                    match frame {
                        Some(Ok(Frame::Data(data))) => {
                            let Ok(length) = u64::try_from(data.remaining()) else {
                                return Poll::Ready(Some(Err(
                                    this.fail(MultipartBodyError::LengthOverflow),
                                )));
                            };
                            if let Some(remaining) = part.remaining {
                                let Some(remaining) = remaining.checked_sub(length) else {
                                    return Poll::Ready(Some(Err(
                                        this.fail(MultipartBodyError::LengthMismatch),
                                    )));
                                };
                                part.remaining = Some(remaining);
                            }
                            if length != 0 {
                                return Poll::Ready(Some(this.emit(data)));
                            }
                        }
                        Some(Ok(Frame::Trailers(_))) => {
                            return Poll::Ready(Some(Err(
                                this.fail(MultipartBodyError::TrailersNotAllowed),
                            )));
                        }
                        Some(Err(error)) => {
                            return Poll::Ready(Some(Err(
                                this.fail(MultipartBodyError::Producer(error.to_string())),
                            )));
                        }
                        None => {
                            if part.remaining.is_some_and(|remaining| remaining != 0) {
                                return Poll::Ready(Some(Err(
                                    this.fail(MultipartBodyError::LengthMismatch),
                                )));
                            }
                            this.phase = MultipartBodyPhase::Separator;
                        }
                    }
                }
                MultipartBodyPhase::Separator => {
                    // Retiring a producer may run an arbitrary destructor.
                    // A caught panic must leave a terminal form rather than
                    // let the next poll silently skip the following part.
                    this.phase = MultipartBodyPhase::Done;
                    let mut parts = std::mem::take(&mut this.parts);
                    let retired = parts.pop_front();
                    drop(retired);
                    this.parts = parts;
                    this.phase = MultipartBodyPhase::Head;
                    return Poll::Ready(Some(this.emit(MultipartChunk::Framing(
                        BytesCursor::new(Bytes::from_static(b"\r\n")),
                    ))));
                }
                MultipartBodyPhase::Closing => {
                    let closing = Bytes::from(format!("--{}--\r\n", this.boundary));
                    this.phase = MultipartBodyPhase::Done;
                    return Poll::Ready(Some(this.emit(MultipartChunk::Framing(
                        BytesCursor::new(closing),
                    ))));
                }
                MultipartBodyPhase::Done => return Poll::Ready(None),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        self.phase == MultipartBodyPhase::Done
    }

    fn size_hint(&self) -> SizeHint {
        if self.is_end_stream() {
            SizeHint::with_exact(0)
        } else {
            self.remaining.map_or_else(SizeHint::default, SizeHint::with_exact)
        }
    }
}

fn append_multipart_quoted_value(encoded: &mut Vec<u8>, value: &str) {
    for byte in value.bytes() {
        if matches!(byte, b'"' | b'\\') {
            encoded.push(b'\\');
        }
        encoded.push(byte);
    }
}

fn is_valid_streaming_multipart_boundary(boundary: &str) -> bool {
    !boundary.is_empty()
        && boundary.len() <= 70
        && !boundary.ends_with(' ')
        && boundary.bytes().all(|byte| {
            matches!(
                byte,
                b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b' '
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

/// Percent-encode a string for use in URL query parameters.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + input.len() / 4);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                use std::fmt::Write;
                write!(out, "%{byte:02X}").expect("write to string shouldn't fail");
            }
        }
    }
    out
}

/// URL-encode key-value pairs into a `key=value&key=value` string.
pub(crate) fn url_encode_params<I, K, V>(params: I) -> String
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
        499 => "Client Closed Request",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

#[cfg(test)]
#[path = "types_inline_tests.rs"]
mod tests;
