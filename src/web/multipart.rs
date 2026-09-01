//! Multipart form data parsing extractor.
//!
//! Parses `multipart/form-data` request bodies per [RFC 7578].
//! Each part exposes its name, optional filename, content type, and body bytes.
//!
//! [RFC 7578]: https://tools.ietf.org/html/rfc7578
//!
//! # Example
//!
//! ```ignore
//! use asupersync::web::multipart::Multipart;
//! use asupersync::web::response::StatusCode;
//!
//! fn upload(form: Multipart) -> StatusCode {
//!     for field in form.fields() {
//!         println!("name={} filename={:?} len={}", field.name(), field.filename(), field.body().len());
//!     }
//!     StatusCode::OK
//! }
//! ```

use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::pin::Pin;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use super::extract::{
    ExtractionError, FromRequest, Request, header_value_ci, parse_content_length,
};
#[cfg(not(target_arch = "wasm32"))]
use super::extract::{
    StreamingRawBody, StreamingRawBodyCollectError, StreamingRawBodySlot,
    reject_buffered_extractor_on_streaming_request, streaming_extraction_error,
};
use super::response::StatusCode;
use crate::Cx;
use crate::bytes::Bytes;
#[cfg(not(target_arch = "wasm32"))]
use crate::bytes::{Buf, BytesCursor};
#[cfg(not(target_arch = "wasm32"))]
use crate::channel::oneshot;
#[cfg(not(target_arch = "wasm32"))]
use crate::http::body::{Body, Frame};
#[cfg(not(target_arch = "wasm32"))]
use crate::http::h1::stream::IncomingBodyError;
use crate::time::wall_now;
#[cfg(not(target_arch = "wasm32"))]
use crate::types::CancelKind;
use crate::types::Time;

/// Default maximum multipart body size (16 MiB).
const DEFAULT_MAX_MULTIPART_SIZE: usize = 16 * 1024 * 1024;

/// Default maximum number of parts to prevent abuse.
const DEFAULT_MAX_PARTS: usize = 1024;

/// Default maximum header section size per part (8 KiB).
const DEFAULT_MAX_PART_HEADERS: usize = 8 * 1024;

/// Default maximum part body size (8 MiB).
const DEFAULT_MAX_PART_BODY_SIZE: usize = 8 * 1024 * 1024;

/// Default request parsing timeout (30 seconds).
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default idle timeout between parsing steps (5 seconds).
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 5;

/// Configurable limits for multipart request parsing.
///
/// Inject via request extensions to override defaults on a per-route or
/// per-server basis. The multipart parser checks for this type in extensions
/// and falls back to defaults if absent.
///
/// # Example
///
/// ```ignore
/// let limits = MultipartLimits::new()
///     .max_total_size(100 * 1024 * 1024)  // 100 MiB
///     .max_parts(50);
/// // Inject via middleware into request.extensions.insert_typed(limits)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultipartLimits {
    /// Maximum total multipart body size in bytes.
    pub max_total_size: usize,
    /// Maximum number of parts.
    pub max_parts: usize,
    /// Maximum header section size per part in bytes.
    pub max_part_headers: usize,
    /// Maximum body size per part in bytes.
    pub max_part_body_size: usize,
    /// Maximum time to spend parsing the entire request in seconds.
    pub request_timeout_secs: u64,
    /// Maximum idle time between parsing operations in seconds.
    pub idle_timeout_secs: u64,
}

impl Default for MultipartLimits {
    fn default() -> Self {
        Self {
            max_total_size: DEFAULT_MAX_MULTIPART_SIZE,
            max_parts: DEFAULT_MAX_PARTS,
            max_part_headers: DEFAULT_MAX_PART_HEADERS,
            max_part_body_size: DEFAULT_MAX_PART_BODY_SIZE,
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
        }
    }
}

impl MultipartLimits {
    /// Create multipart limits with defaults (16 MiB total, 1024 parts, 8 KiB headers, 8 MiB part body).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum total multipart body size.
    #[must_use]
    pub fn max_total_size(mut self, bytes: usize) -> Self {
        self.max_total_size = bytes;
        self
    }

    /// Set the maximum number of parts.
    #[must_use]
    pub fn max_parts(mut self, count: usize) -> Self {
        self.max_parts = count;
        self
    }

    /// Set the maximum header section size per part.
    #[must_use]
    pub fn max_part_headers(mut self, bytes: usize) -> Self {
        self.max_part_headers = bytes;
        self
    }

    /// Set the maximum body size per part.
    #[must_use]
    pub fn max_part_body_size(mut self, bytes: usize) -> Self {
        self.max_part_body_size = bytes;
        self
    }

    /// Set the request parsing timeout in seconds.
    #[must_use]
    pub fn request_timeout_secs(mut self, secs: u64) -> Self {
        self.request_timeout_secs = secs;
        self
    }

    /// Set the idle timeout between parsing operations in seconds.
    #[must_use]
    pub fn idle_timeout_secs(mut self, secs: u64) -> Self {
        self.idle_timeout_secs = secs;
        self
    }

    /// Meet these limits with another boundary's limits.
    #[must_use]
    pub fn tightened_with(self, other: Self) -> Self {
        Self {
            max_total_size: self.max_total_size.min(other.max_total_size),
            max_parts: self.max_parts.min(other.max_parts),
            max_part_headers: self.max_part_headers.min(other.max_part_headers),
            max_part_body_size: self.max_part_body_size.min(other.max_part_body_size),
            request_timeout_secs: self.request_timeout_secs.min(other.request_timeout_secs),
            idle_timeout_secs: self.idle_timeout_secs.min(other.idle_timeout_secs),
        }
    }

    /// Apply a format-independent total request-body ceiling.
    #[must_use]
    pub fn max_total_body_size(mut self, bytes: usize) -> Self {
        self.max_total_size = self.max_total_size.min(bytes);
        self.max_part_body_size = self.max_part_body_size.min(bytes);
        self
    }
}

fn effective_multipart_limits(req: &Request) -> MultipartLimits {
    let projected = req.extensions.get_typed::<MultipartLimits>().copied();
    let enforced =
        super::extract::effective_request_body_policy(req).map(|policy| policy.multipart_limits);
    match (enforced, projected) {
        (Some(enforced), Some(projected)) => enforced.tightened_with(projected),
        (Some(limits), None) | (None, Some(limits)) => limits,
        (None, None) => MultipartLimits::default(),
    }
}

fn coded_multipart_error(
    status: StatusCode,
    diagnostic: super::WebBodyDiagnostic,
    message: impl fmt::Display,
) -> ExtractionError {
    ExtractionError::coded(status, diagnostic, message)
}

fn multipart_total_limit_error(message: impl fmt::Display) -> ExtractionError {
    coded_multipart_error(
        StatusCode::PAYLOAD_TOO_LARGE,
        super::WebBodyDiagnostic::TotalBodyLimit,
        message,
    )
}

fn multipart_field_limit_error(status: StatusCode, message: impl fmt::Display) -> ExtractionError {
    coded_multipart_error(
        status,
        super::WebBodyDiagnostic::MultipartFieldLimit,
        message,
    )
}

fn malformed_multipart_error(status: StatusCode, message: impl fmt::Display) -> ExtractionError {
    coded_multipart_error(
        status,
        super::WebBodyDiagnostic::MalformedMultipart,
        message,
    )
}

fn multipart_timeout_error(message: impl fmt::Display) -> ExtractionError {
    coded_multipart_error(
        StatusCode::REQUEST_TIMEOUT,
        super::WebBodyDiagnostic::Timeout,
        message,
    )
}

// ─── MultipartField ─────────────────────────────────────────────────────────

/// A single field/part from a multipart form.
#[derive(Debug, Clone)]
pub struct MultipartField {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    headers: HashMap<String, String>,
    body: Bytes,
}

impl MultipartField {
    /// The form field name from `Content-Disposition`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The original filename, if this is a file upload.
    #[must_use]
    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// The content type of this part, if specified.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// The part headers.
    #[must_use]
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// The raw body bytes of this part.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Consume and return the body bytes.
    #[must_use]
    pub fn into_body(self) -> Bytes {
        self.body
    }

    /// Try to interpret the body as UTF-8 text.
    pub fn text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }
}

// ─── Multipart ──────────────────────────────────────────────────────────────

/// Parsed multipart form data.
///
/// Implements [`FromRequest`] and parses `multipart/form-data` bodies.
#[derive(Debug, Clone)]
pub struct Multipart {
    fields: Vec<MultipartField>,
}

impl Multipart {
    /// All parsed fields.
    #[must_use]
    pub fn fields(&self) -> &[MultipartField] {
        &self.fields
    }

    /// Consume and return all fields.
    #[must_use]
    pub fn into_fields(self) -> Vec<MultipartField> {
        self.fields
    }

    /// Find the first field with the given name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&MultipartField> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Get all fields with the given name (for repeated fields).
    #[must_use]
    pub fn fields_by_name(&self, name: &str) -> Vec<&MultipartField> {
        self.fields.iter().filter(|f| f.name == name).collect()
    }

    /// Number of fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Returns `true` if there are no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl FromRequest for Multipart {
    fn from_request(req: Request) -> Result<Self, ExtractionError> {
        #[cfg(not(target_arch = "wasm32"))]
        reject_buffered_extractor_on_streaming_request(&req, "Multipart")?;

        let limits = effective_multipart_limits(&req);

        check_request_content_length_limit(&req, limits.max_total_size)?;

        // Size check.
        if req.body.len() > limits.max_total_size {
            return Err(multipart_total_limit_error(format!(
                "multipart body too large: {} bytes (max {})",
                req.body.len(),
                limits.max_total_size
            )));
        }

        validate_request_content_length(&req)?;

        let boundary = validate_multipart_content_type(&req)?;

        let parse_start = wall_now();
        let fields = parse_multipart(&req.body, &boundary, &limits, parse_start)?;

        Ok(Self { fields })
    }

    fn from_request_with_cx<'a>(
        cx: &'a Cx,
        req: Request,
    ) -> impl std::future::Future<Output = Result<Self, ExtractionError>> + Send + 'a
    where
        Self: Send + 'a,
    {
        async move {
            #[cfg(not(target_arch = "wasm32"))]
            if req.extensions.get_typed::<StreamingRawBodySlot>().is_some() {
                return extract_streaming_multipart(cx, req).await;
            }

            Self::from_request(req)
        }
    }
}

// ─── Streaming multipart fields ─────────────────────────────────────────────

/// A live, bounded multipart request stream.
///
/// Unlike [`Multipart`], this extractor does not collect every field before
/// invoking the handler. Call [`Self::next_field`] to borrow one linear field
/// lease, then consume that field with [`StreamingMultipartField::next_chunk`].
/// The borrow prevents advancing the parser while the field is live. Dropping
/// an incomplete field abandons the request body so the HTTP/1 driver applies
/// its bounded drain-or-close policy before any connection reuse.
///
/// This extractor is available only on the native streaming Router path.
///
/// # Linear field consumption
///
/// ```no_run
/// use asupersync::Cx;
/// use asupersync::web::multipart::{StreamingMultipart, StreamingMultipartError};
///
/// async fn consume(
///     cx: &Cx,
///     form: &mut StreamingMultipart,
/// ) -> Result<usize, StreamingMultipartError> {
///     let mut total = 0;
///     while let Some(mut field) = form.next_field(cx).await? {
///         if field.name() == "reject-me" {
///             // Early drop deliberately abandons the whole request body.
///             // Return from the handler; do not call `next_field` again.
///             drop(field);
///             return Ok(total);
///         }
///         while let Some(chunk) = field.next_chunk(cx).await? {
///             total += chunk.len();
///         }
///     }
///     Ok(total)
/// }
/// ```
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub struct StreamingMultipart {
    body: Option<StreamingRawBody>,
    input: Option<BytesCursor>,
    delimiter: Vec<u8>,
    limits: MultipartLimits,
    expected_length: Option<usize>,
    parse_start: Time,
    phase: StreamingMultipartPhase,
    buffer: Vec<u8>,
    input_frame_bytes_peak: usize,
    parser_buffer_bytes_peak: usize,
    yielded_field_chunk_bytes_peak: usize,
    total_received: usize,
    work_units: usize,
    max_work_units: usize,
    header_scan_from: usize,
    buffer_starts_at_line_start: bool,
    part_count: usize,
    current_part_bytes: usize,
    current_part_length: Option<usize>,
    eof: bool,
    eof_validated: bool,
    field_active: bool,
    abandoned: bool,
}

/// Read-only high-water marks for one live multipart parser.
///
/// These measurements describe logical request-body ownership at the parser
/// boundary; they do not measure allocator capacity, heap/RSS, socket buffers,
/// decoder scratch, parsed multipart-header allocations, or bytes retained by
/// application code after a yielded chunk is returned. Queue-byte accounting
/// includes logical trailer field bytes when trailers are present.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamingMultipartRetentionSnapshot {
    /// Peak permit-backed bytes queued or waiting to enter the incoming-body channel.
    ///
    /// `None` means the parser abandoned and dropped its incoming body, so the
    /// live queue observer is no longer available.
    pub incoming_queue_bytes_peak: Option<usize>,
    /// Peak number of producer-admitted frames, including a send waiting on a full queue.
    ///
    /// `None` has the same abandonment meaning as [`Self::incoming_queue_bytes_peak`].
    pub incoming_queue_frames_peak: Option<usize>,
    /// Largest logical decoded DATA-frame length presented to the parser.
    pub input_frame_bytes_peak: usize,
    /// Largest logical `Vec` length used by the multipart parser scratch buffer.
    pub parser_buffer_bytes_peak: usize,
    /// Largest single field-body chunk yielded to the handler.
    pub yielded_field_chunk_bytes_peak: usize,
}

/// A borrow-tied field from [`StreamingMultipart`].
///
/// The lease yields bounded body chunks exactly once. It must reach field EOF
/// before the parent parser can advance. Dropping it early marks the live body
/// abandoned, which prevents unsynchronized HTTP/1 connection reuse.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
#[must_use = "a streaming multipart field must be consumed to EOF or explicitly dropped"]
pub struct StreamingMultipartField<'a> {
    multipart: &'a mut StreamingMultipart,
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    headers: HashMap<String, String>,
    complete: bool,
}

/// Stable failure category for the live multipart field API.
///
/// [`StreamingMultipartError::code`] preserves the `ASUP-E504` compatibility
/// umbrella. [`StreamingMultipartError::diagnostic_code`] distinguishes the
/// more precise E501/E505-E509 cause when assigned. The category and HTTP status
/// remain machine-readable so callers never need to parse human text.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamingMultipartErrorKind {
    /// Malformed multipart framing, headers, or declared lengths (HTTP 400).
    Malformed,
    /// The request or an outstanding body read exceeded its deadline (HTTP 408).
    Timeout,
    /// A declared or observed body limit was exceeded (HTTP 413).
    PayloadTooLarge,
    /// The request media type was not `multipart/form-data` (HTTP 415).
    UnsupportedMediaType,
    /// The request body or handler context was cancelled (HTTP 499 or 503).
    Cancelled,
    /// The client/request-body transport disconnected (HTTP 499 telemetry;
    /// the protocol listener closes or resets without synthesizing a response).
    Transport,
    /// A prior field lease was dropped or forgotten before field EOF (HTTP 400 or 500).
    AbandonedField,
    /// An internal parser invariant or accounting invariant failed (HTTP 500).
    Internal,
}

/// Registry-backed failure from [`StreamingMultipart`] or
/// [`StreamingMultipartField`].
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
pub struct StreamingMultipartError {
    kind: StreamingMultipartErrorKind,
    status: StatusCode,
    message: String,
    cancel_kind: Option<CancelKind>,
    diagnostic: Option<super::WebBodyDiagnostic>,
    registry_code_override: Option<&'static str>,
}

#[cfg(not(target_arch = "wasm32"))]
impl StreamingMultipartError {
    /// Stable diagnostic token for every streaming multipart failure.
    pub const CODE: &'static str = "ASUP-E504";

    fn new(
        kind: StreamingMultipartErrorKind,
        status: StatusCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            status,
            message: message.into(),
            cancel_kind: None,
            diagnostic: None,
            registry_code_override: None,
        }
    }

    fn with_diagnostic(
        kind: StreamingMultipartErrorKind,
        status: StatusCode,
        diagnostic: super::WebBodyDiagnostic,
        message: impl Into<String>,
    ) -> Self {
        let mut error = Self::new(kind, status, message);
        error.diagnostic = Some(diagnostic);
        error
    }

    fn cancelled(kind: CancelKind) -> Self {
        let (status, message) = match kind {
            CancelKind::Timeout
            | CancelKind::Deadline
            | CancelKind::PollQuota
            | CancelKind::CostBudget
            | CancelKind::ResourceUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "multipart request body unavailable",
            ),
            _ => (
                StatusCode::CLIENT_CLOSED_REQUEST,
                "multipart request body cancelled",
            ),
        };
        let mut error = Self::new(StreamingMultipartErrorKind::Cancelled, status, message);
        error.cancel_kind = Some(kind);
        error
    }

    fn from_body_error(error: IncomingBodyError) -> Self {
        match error {
            IncomingBodyError::BodyTooLarge { actual, limit } => Self::with_diagnostic(
                StreamingMultipartErrorKind::PayloadTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
                super::WebBodyDiagnostic::TotalBodyLimit,
                actual.map_or_else(
                    || format!("multipart body too large (limit {limit})"),
                    |actual| format!("multipart body too large: {actual} bytes (limit {limit})"),
                ),
            ),
            IncomingBodyError::QueueFrameTooLarge { actual, limit } => Self::with_diagnostic(
                StreamingMultipartErrorKind::PayloadTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
                super::WebBodyDiagnostic::TotalBodyLimit,
                format!("multipart body too large: {actual} bytes (limit {limit})"),
            ),
            IncomingBodyError::Cancelled { kind } => Self::cancelled(kind),
            IncomingBodyError::BadContentLength
            | IncomingBodyError::BadChunkedEncoding
            | IncomingBodyError::TrailersTooLarge
            | IncomingBodyError::BadHeader
            | IncomingBodyError::InvalidHeaderName
            | IncomingBodyError::InvalidHeaderValue => Self::with_diagnostic(
                StreamingMultipartErrorKind::Malformed,
                StatusCode::BAD_REQUEST,
                super::WebBodyDiagnostic::MalformedMultipart,
                "invalid multipart request body",
            ),
            IncomingBodyError::ClientAborted => Self::with_diagnostic(
                StreamingMultipartErrorKind::Transport,
                StatusCode::CLIENT_CLOSED_REQUEST,
                super::WebBodyDiagnostic::ClientAbort,
                "multipart request body transport aborted",
            ),
            IncomingBodyError::SourceDisconnected => Self::new(
                StreamingMultipartErrorKind::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
                "multipart request body producer disconnected",
            ),
            IncomingBodyError::ConsumerDropped => Self::abandoned(
                StatusCode::INTERNAL_SERVER_ERROR,
                "multipart request body consumer was dropped",
            ),
            IncomingBodyError::AccountingOverflow => Self::new(
                StreamingMultipartErrorKind::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to account for multipart request body",
            ),
            IncomingBodyError::DrainTimeout => Self::with_diagnostic(
                StreamingMultipartErrorKind::Timeout,
                StatusCode::REQUEST_TIMEOUT,
                super::WebBodyDiagnostic::Timeout,
                "multipart request body drain timed out",
            ),
            IncomingBodyError::DrainLimitExceeded { .. } | IncomingBodyError::AlreadyTerminal => {
                Self::new(
                    StreamingMultipartErrorKind::Internal,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "multipart request body drain failed",
                )
            }
        }
    }

    fn abandoned(status: StatusCode, message: impl Into<String>) -> Self {
        Self::new(StreamingMultipartErrorKind::AbandonedField, status, message)
    }

    /// Machine-readable failure category.
    #[must_use]
    pub const fn kind(&self) -> StreamingMultipartErrorKind {
        self.kind
    }

    /// HTTP status retained by the extractor response boundary.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Stable registry code without log-decoration brackets.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        Self::CODE
    }

    /// Exact diagnostic category for this failure, when BODY-8 assigned one.
    #[must_use]
    pub const fn diagnostic(&self) -> Option<super::WebBodyDiagnostic> {
        self.diagnostic
    }

    /// Exact registry code for the typed BODY-8 cause.
    ///
    /// [`Self::code`] remains the `ASUP-E504` streaming-multipart umbrella for
    /// v0.4 compatibility; this accessor distinguishes the BODY-8 causes.
    #[must_use]
    pub const fn diagnostic_code(&self) -> &'static str {
        if let Some(code) = self.registry_code_override {
            return code;
        }
        match self.diagnostic {
            Some(diagnostic) => diagnostic.code(),
            None if matches!(
                self.cancel_kind,
                Some(CancelKind::Timeout | CancelKind::Deadline)
            ) =>
            {
                "ASUP-E501"
            }
            None => Self::CODE,
        }
    }

    /// Human-readable context for this occurrence.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Exact structured cancellation cause, when [`Self::kind`] is
    /// [`StreamingMultipartErrorKind::Cancelled`].
    #[must_use]
    pub const fn cancel_kind(&self) -> Option<CancelKind> {
        self.cancel_kind
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<ExtractionError> for StreamingMultipartError {
    fn from(error: ExtractionError) -> Self {
        let status = error.status;
        let (diagnostic, registry_code_override, message) =
            if let Some(detail) = error.message.strip_prefix("[ASUP-E501] ") {
                (None, Some("ASUP-E501"), detail.to_owned())
            } else {
                let (diagnostic, message) = decode_coded_multipart_message(error.message);
                (diagnostic, None, message)
            };
        let kind = if status == StatusCode::BAD_REQUEST {
            StreamingMultipartErrorKind::Malformed
        } else if status == StatusCode::REQUEST_TIMEOUT {
            StreamingMultipartErrorKind::Timeout
        } else if status == StatusCode::PAYLOAD_TOO_LARGE {
            StreamingMultipartErrorKind::PayloadTooLarge
        } else if status == StatusCode::UNSUPPORTED_MEDIA_TYPE {
            StreamingMultipartErrorKind::UnsupportedMediaType
        } else if status == StatusCode::CLIENT_CLOSED_REQUEST
            || status == StatusCode::SERVICE_UNAVAILABLE
        {
            StreamingMultipartErrorKind::Cancelled
        } else {
            StreamingMultipartErrorKind::Internal
        };
        let mut error = Self::new(kind, status, message);
        error.diagnostic = diagnostic;
        error.registry_code_override = registry_code_override;
        error
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn decode_coded_multipart_message(message: String) -> (Option<super::WebBodyDiagnostic>, String) {
    for diagnostic in [
        super::WebBodyDiagnostic::TotalBodyLimit,
        super::WebBodyDiagnostic::MultipartFieldLimit,
        super::WebBodyDiagnostic::MalformedMultipart,
        super::WebBodyDiagnostic::Timeout,
        super::WebBodyDiagnostic::ClientAbort,
        super::WebBodyDiagnostic::ResponseProducerFailure,
    ] {
        let prefix = format!("[{}] ", diagnostic.code());
        if let Some(detail) = message.strip_prefix(&prefix) {
            return (Some(diagnostic), detail.to_owned());
        }
    }
    (None, message)
}

#[cfg(not(target_arch = "wasm32"))]
impl From<StreamingMultipartError> for ExtractionError {
    fn from(error: StreamingMultipartError) -> Self {
        let status = error.status;
        let message = if error.diagnostic_code() == error.code() {
            error.to_string()
        } else {
            format!("[{}] {}", error.diagnostic_code(), error.message)
        };
        ExtractionError::new(status, message)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl fmt::Display for StreamingMultipartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "[{}] {} {}",
            self.code(),
            self.status,
            self.message
        )
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl std::error::Error for StreamingMultipartError {}

#[cfg(not(target_arch = "wasm32"))]
impl super::response::IntoResponse for StreamingMultipartError {
    fn into_response(self) -> super::response::Response {
        super::response::IntoResponse::into_response(ExtractionError::from(self))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl StreamingMultipart {
    const INPUT_WINDOW: usize = 4096;

    fn from_streaming_request(req: Request) -> Result<Self, ExtractionError> {
        let limits = effective_multipart_limits(&req);
        check_request_content_length_limit(&req, limits.max_total_size)?;
        let expected_length = header_value_ci(&req, "content-length")
            .map(parse_content_length)
            .transpose()?;
        let boundary = validate_multipart_content_type(&req)?;
        let body = StreamingRawBody::from_request(req)?;
        let delimiter = format!("--{boundary}").into_bytes();
        let work_scale = delimiter
            .len()
            .checked_mul(6)
            .and_then(|units| units.checked_add(16))
            .ok_or_else(|| {
                multipart_field_limit_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "multipart parser work budget overflow",
                )
            })?;
        let max_work_units = limits
            .max_total_size
            .checked_mul(work_scale)
            .ok_or_else(|| {
                multipart_field_limit_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "multipart parser work budget overflow",
                )
            })?;
        let now = wall_now();

        Ok(Self {
            body: Some(body),
            input: None,
            delimiter,
            limits,
            expected_length,
            parse_start: now,
            phase: StreamingMultipartPhase::Preamble,
            buffer: Vec::new(),
            input_frame_bytes_peak: 0,
            parser_buffer_bytes_peak: 0,
            yielded_field_chunk_bytes_peak: 0,
            total_received: 0,
            work_units: 0,
            max_work_units,
            header_scan_from: 0,
            buffer_starts_at_line_start: true,
            part_count: 0,
            current_part_bytes: 0,
            current_part_length: None,
            eof: false,
            eof_validated: false,
            field_active: false,
            abandoned: false,
        })
    }

    /// Take ownership of a native streaming request body.
    ///
    /// Header and media-type failures are returned before body ownership is
    /// taken. Subsequent field operations use the same registry-backed error
    /// type.
    pub fn from_request(req: Request) -> Result<Self, StreamingMultipartError> {
        Self::from_streaming_request(req).map_err(Into::into)
    }

    /// Return cumulative logical request-body retention high-water marks.
    ///
    /// Peaks persist across fields and after clean EOF. An abandoned parser
    /// returns `None` for the incoming-queue component because abandonment
    /// deliberately drops that live observer.
    #[must_use]
    pub fn retention_snapshot(&self) -> StreamingMultipartRetentionSnapshot {
        StreamingMultipartRetentionSnapshot {
            incoming_queue_bytes_peak: self.body.as_ref().map(StreamingRawBody::queued_bytes_peak),
            incoming_queue_frames_peak: self
                .body
                .as_ref()
                .map(StreamingRawBody::queued_frames_peak),
            input_frame_bytes_peak: self.input_frame_bytes_peak,
            parser_buffer_bytes_peak: self.parser_buffer_bytes_peak,
            yielded_field_chunk_bytes_peak: self.yielded_field_chunk_bytes_peak,
        }
    }

    /// Advance to the next field.
    ///
    /// The returned lease mutably borrows this parser, so another field cannot
    /// be requested until the lease is consumed or dropped. After the closing
    /// MIME delimiter, this method still drains the bounded epilogue through
    /// transport EOF before returning `None`; MIME completion alone is not an
    /// HTTP message-boundary proof.
    pub async fn next_field<'a>(
        &'a mut self,
        cx: &Cx,
    ) -> Result<Option<StreamingMultipartField<'a>>, StreamingMultipartError> {
        if self.field_active {
            self.abandon();
            return Err(StreamingMultipartError::abandoned(
                StatusCode::INTERNAL_SERVER_ERROR,
                "previous multipart field lease was forgotten",
            ));
        }
        if self.abandoned {
            return Err(StreamingMultipartError::abandoned(
                StatusCode::BAD_REQUEST,
                "multipart field stream was abandoned before field EOF",
            ));
        }

        let result = self.next_field_metadata(cx).await;
        let metadata = match result {
            Ok(metadata) => metadata,
            Err(error) => {
                self.abandon();
                return Err(error);
            }
        };
        let Some((name, filename, content_type, headers)) = metadata else {
            return Ok(None);
        };

        self.field_active = true;
        Ok(Some(StreamingMultipartField {
            multipart: self,
            name,
            filename,
            content_type,
            headers,
            complete: false,
        }))
    }

    async fn next_field_metadata(
        &mut self,
        cx: &Cx,
    ) -> Result<
        Option<(
            String,
            Option<String>,
            Option<String>,
            HashMap<String, String>,
        )>,
        StreamingMultipartError,
    > {
        loop {
            self.check_live(cx)?;
            match self.phase {
                StreamingMultipartPhase::Preamble => {
                    let (found, examined) = find_streaming_boundary(
                        &self.buffer,
                        &self.delimiter,
                        self.eof,
                        self.buffer_starts_at_line_start,
                    );
                    self.charge_boundary_work(examined)?;
                    if let Some(found) = found {
                        self.drain_buffer_prefix(found.consumed);
                        if found.closing {
                            self.phase = StreamingMultipartPhase::Done;
                        } else {
                            self.enter_headers()?;
                        }
                        continue;
                    }
                    if self.eof {
                        return Err(malformed_multipart_error(
                            StatusCode::BAD_REQUEST,
                            "multipart body missing initial boundary",
                        )
                        .into());
                    }
                    let keep = self.delimiter.len().saturating_add(3);
                    if self.buffer.len() > keep {
                        let discard = self.buffer.len() - keep;
                        self.drain_buffer_prefix(discard);
                    }
                    self.read_more(cx).await?;
                }
                StreamingMultipartPhase::Headers => {
                    let scan_from = self.header_scan_from.min(self.buffer.len());
                    let terminator = find_blank_line(&self.buffer, scan_from);
                    let examined = terminator
                        .map_or(self.buffer.len(), |(_, body_start)| body_start)
                        - scan_from;
                    self.charge_work(examined)?;
                    if let Some((headers_end, body_start)) = terminator {
                        if headers_end > self.limits.max_part_headers {
                            return Err(multipart_field_limit_error(
                                StatusCode::BAD_REQUEST,
                                "multipart part headers too large",
                            )
                            .into());
                        }
                        let headers = parse_part_headers(&self.buffer[..headers_end])?;
                        let disposition = headers
                            .get("content-disposition")
                            .cloned()
                            .unwrap_or_default();
                        let name =
                            parse_disposition_param(&disposition, "name").unwrap_or_default();
                        let filename = parse_disposition_param(&disposition, "filename");
                        let content_type = headers.get("content-type").cloned();
                        if content_type.as_deref().is_some_and(is_multipart_media_type) {
                            return Err(malformed_multipart_error(
                                StatusCode::BAD_REQUEST,
                                "nested multipart parts are not supported",
                            )
                            .into());
                        }
                        let part_length = parse_part_content_length(&headers)?;
                        self.drain_buffer_prefix(body_start);
                        self.current_part_bytes = 0;
                        self.current_part_length = part_length;
                        self.header_scan_from = 0;
                        self.phase = StreamingMultipartPhase::Body;
                        return Ok(Some((name, filename, content_type, headers)));
                    }
                    if self.eof {
                        return Err(malformed_multipart_error(
                            StatusCode::BAD_REQUEST,
                            "multipart part missing header terminator",
                        )
                        .into());
                    }
                    if self.buffer.len() > self.limits.max_part_headers.saturating_add(3) {
                        return Err(multipart_field_limit_error(
                            StatusCode::BAD_REQUEST,
                            "multipart part headers too large",
                        )
                        .into());
                    }
                    self.header_scan_from = self.buffer.len().saturating_sub(3);
                    self.read_more(cx).await?;
                }
                StreamingMultipartPhase::Body => {
                    return Err(ExtractionError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "multipart parser cannot advance while a field body is live",
                    )
                    .into());
                }
                StreamingMultipartPhase::Done => {
                    self.buffer.clear();
                    if self.eof {
                        self.validate_eof()?;
                        return Ok(None);
                    }
                    self.read_more(cx).await?;
                }
            }
        }
    }

    async fn next_field_chunk(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<Bytes>, StreamingMultipartError> {
        loop {
            self.check_live(cx)?;
            if self.phase != StreamingMultipartPhase::Body {
                return Ok(None);
            }

            let (found, examined) = find_streaming_boundary(
                &self.buffer,
                &self.delimiter,
                self.eof,
                self.buffer_starts_at_line_start,
            );
            self.charge_boundary_work(examined)?;
            if let Some(found) = found {
                let body_end = strip_trailing_crlf(&self.buffer, found.start);
                if body_end > Self::INPUT_WINDOW {
                    self.account_current_part(Self::INPUT_WINDOW)?;
                    let chunk = Bytes::copy_from_slice(&self.buffer[..Self::INPUT_WINDOW]);
                    self.drain_buffer_prefix(Self::INPUT_WINDOW);
                    return Ok(Some(chunk));
                }
                self.account_current_part(body_end)?;
                self.validate_current_part_length()?;
                let chunk = Bytes::copy_from_slice(&self.buffer[..body_end]);
                self.drain_buffer_prefix(found.consumed);
                self.current_part_bytes = 0;
                self.current_part_length = None;
                if found.closing {
                    self.phase = StreamingMultipartPhase::Done;
                } else {
                    self.enter_headers()?;
                }
                return if chunk.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(chunk))
                };
            }

            if self.eof {
                return Err(malformed_multipart_error(
                    StatusCode::BAD_REQUEST,
                    "multipart part missing closing boundary",
                )
                .into());
            }

            let keep = self.delimiter.len().saturating_add(3);
            if self.buffer.len() > keep {
                let flush = self.buffer.len() - keep;
                self.account_current_part(flush)?;
                let chunk = Bytes::copy_from_slice(&self.buffer[..flush]);
                self.drain_buffer_prefix(flush);
                return Ok(Some(chunk));
            }
            self.read_more(cx).await?;
        }
    }

    async fn read_more(&mut self, cx: &Cx) -> Result<(), StreamingMultipartError> {
        loop {
            self.check_live(cx)?;
            if let Some(input) = self.input.as_mut() {
                if input.has_remaining() {
                    let count = input.remaining().min(Self::INPUT_WINDOW);
                    let bytes = input.copy_to_bytes(count);
                    self.total_received =
                        self.total_received.checked_add(count).ok_or_else(|| {
                            multipart_total_limit_error("multipart body size accounting overflow")
                        })?;
                    if self.total_received > self.limits.max_total_size {
                        return Err(multipart_total_limit_error(format!(
                            "multipart body too large: {} bytes (max {})",
                            self.total_received, self.limits.max_total_size
                        ))
                        .into());
                    }
                    self.buffer.extend_from_slice(bytes.as_ref());
                    self.parser_buffer_bytes_peak =
                        self.parser_buffer_bytes_peak.max(self.buffer.len());
                    if !input.has_remaining() {
                        self.input = None;
                    }
                    return Ok(());
                }
                self.input = None;
            }

            if self.eof {
                return Ok(());
            }
            let deadline = self.read_deadline();
            let body = self.body.as_mut().ok_or_else(|| {
                ExtractionError::bad_request("multipart field stream body is unavailable")
            })?;
            let timed_read = crate::time::timeout_at(
                deadline,
                std::future::poll_fn(|poll_cx| Pin::new(&mut *body).poll_frame(poll_cx)),
            );
            let next = match futures_lite::future::race(
                async { StreamingMultipartRead::Frame(timed_read.await) },
                async {
                    wait_for_streaming_multipart_cancellation(cx).await;
                    StreamingMultipartRead::Cancelled
                },
            )
            .await
            {
                StreamingMultipartRead::Frame(result) => result.map_err(|_| {
                    StreamingMultipartError::with_diagnostic(
                        StreamingMultipartErrorKind::Timeout,
                        StatusCode::REQUEST_TIMEOUT,
                        super::WebBodyDiagnostic::Timeout,
                        "multipart request body timed out",
                    )
                })?,
                StreamingMultipartRead::Cancelled => {
                    let kind = cx
                        .cancel_reason()
                        .map_or(CancelKind::User, |reason| reason.kind());
                    return Err(StreamingMultipartError::cancelled(kind));
                }
            };
            match next {
                Some(Ok(Frame::Data(data))) => {
                    if !data.has_remaining() {
                        return Err(StreamingMultipartError::new(
                            StreamingMultipartErrorKind::Internal,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "multipart request body produced an empty data cursor",
                        ));
                    }
                    self.input_frame_bytes_peak =
                        self.input_frame_bytes_peak.max(data.get_ref().len());
                    self.input = Some(data);
                }
                Some(Ok(Frame::Trailers(_))) => {}
                Some(Err(error)) => {
                    return Err(StreamingMultipartError::from_body_error(error));
                }
                None => {
                    self.eof = true;
                    self.validate_eof()?;
                    return Ok(());
                }
            }
        }
    }

    fn check_live(&self, cx: &Cx) -> Result<(), StreamingMultipartError> {
        const NANOS_PER_SECOND: u64 = 1_000_000_000;

        if cx.checkpoint().is_err() {
            let kind = cx
                .cancel_reason()
                .map_or(CancelKind::User, |reason| reason.kind());
            return Err(StreamingMultipartError::cancelled(kind));
        }
        let elapsed = wall_now().duration_since(self.parse_start);
        let timeout = self
            .limits
            .request_timeout_secs
            .saturating_mul(NANOS_PER_SECOND);
        if timeout == 0 || elapsed > timeout {
            return Err(StreamingMultipartError::with_diagnostic(
                StreamingMultipartErrorKind::Timeout,
                StatusCode::REQUEST_TIMEOUT,
                super::WebBodyDiagnostic::Timeout,
                format!("multipart parsing timed out after {elapsed}ns (max {timeout}ns)"),
            ));
        }
        Ok(())
    }

    fn read_deadline(&self) -> Time {
        let request_deadline =
            self.parse_start + Duration::from_secs(self.limits.request_timeout_secs);
        let idle_deadline = wall_now() + Duration::from_secs(self.limits.idle_timeout_secs);
        request_deadline.min(idle_deadline)
    }

    fn enter_headers(&mut self) -> Result<(), StreamingMultipartError> {
        if self.part_count >= self.limits.max_parts {
            return Err(multipart_field_limit_error(
                StatusCode::BAD_REQUEST,
                format!("too many multipart parts (max {})", self.limits.max_parts),
            )
            .into());
        }
        self.part_count = self.part_count.checked_add(1).ok_or_else(|| {
            multipart_field_limit_error(
                StatusCode::BAD_REQUEST,
                "multipart part count accounting overflow",
            )
        })?;
        self.header_scan_from = 0;
        self.phase = StreamingMultipartPhase::Headers;
        Ok(())
    }

    fn account_current_part(&mut self, bytes: usize) -> Result<(), StreamingMultipartError> {
        self.current_part_bytes = self.current_part_bytes.checked_add(bytes).ok_or_else(|| {
            multipart_field_limit_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "multipart part body size accounting overflow",
            )
        })?;
        if self.current_part_bytes > self.limits.max_part_body_size {
            return Err(multipart_field_limit_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "multipart part body too large",
            )
            .into());
        }
        Ok(())
    }

    fn validate_current_part_length(&self) -> Result<(), StreamingMultipartError> {
        if let Some(declared_len) = self.current_part_length
            && declared_len != self.current_part_bytes
        {
            return Err(malformed_multipart_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "multipart part content-length mismatch: declared {declared_len} bytes but parsed {} bytes",
                    self.current_part_bytes
                ),
            )
            .into());
        }
        Ok(())
    }

    fn validate_eof(&mut self) -> Result<(), StreamingMultipartError> {
        if self.eof_validated {
            return Ok(());
        }
        if let Some(expected) = self.expected_length
            && expected != self.total_received
        {
            return Err(malformed_multipart_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "multipart Content-Length mismatch: declared {expected} bytes, received {} bytes",
                    self.total_received
                ),
            )
            .into());
        }
        self.eof_validated = true;
        Ok(())
    }

    fn charge_work(&mut self, units: usize) -> Result<(), StreamingMultipartError> {
        self.work_units = self.work_units.checked_add(units).ok_or_else(|| {
            multipart_field_limit_error(
                StatusCode::BAD_REQUEST,
                "multipart parser work accounting overflow",
            )
        })?;
        if self.work_units > self.max_work_units {
            return Err(multipart_field_limit_error(
                StatusCode::BAD_REQUEST,
                "multipart parser work limit exceeded",
            )
            .into());
        }
        Ok(())
    }

    fn charge_boundary_work(
        &mut self,
        starts_examined: usize,
    ) -> Result<(), StreamingMultipartError> {
        let units = starts_examined
            .checked_mul(self.delimiter.len())
            .ok_or_else(|| {
                multipart_field_limit_error(
                    StatusCode::BAD_REQUEST,
                    "multipart parser work accounting overflow",
                )
            })?;
        self.charge_work(units)
    }

    fn drain_buffer_prefix(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        self.buffer_starts_at_line_start = self.buffer[count - 1] == b'\n';
        self.buffer.drain(..count);
    }

    fn abandon(&mut self) {
        self.abandoned = true;
        self.field_active = false;
        self.input = None;
        self.buffer.clear();
        drop(self.body.take());
    }
}

#[cfg(not(target_arch = "wasm32"))]
enum StreamingMultipartRead<T> {
    Frame(T),
    Cancelled,
}

#[cfg(not(target_arch = "wasm32"))]
async fn wait_for_streaming_multipart_cancellation(cx: &Cx) {
    if cx.checkpoint().is_err() {
        return;
    }
    let (sender, mut receiver) = oneshot::channel::<()>();
    let _ = receiver.recv(cx).await;
    drop(sender);
}

#[cfg(not(target_arch = "wasm32"))]
impl FromRequest for StreamingMultipart {
    fn from_request(req: Request) -> Result<Self, ExtractionError> {
        Self::from_request(req).map_err(Into::into)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl StreamingMultipartField<'_> {
    /// The form field name from `Content-Disposition`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The sanitized original filename, if this is a file upload.
    #[must_use]
    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// The content type of this part, if specified.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// The parsed, lower-cased part headers.
    #[must_use]
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Yield the next bounded field-body chunk.
    ///
    /// `None` marks this field boundary, not necessarily HTTP request EOF.
    /// Call [`StreamingMultipart::next_field`] again to advance or synchronize
    /// the final MIME epilogue with transport EOF.
    pub async fn next_chunk(&mut self, cx: &Cx) -> Result<Option<Bytes>, StreamingMultipartError> {
        if self.complete {
            return Ok(None);
        }
        match self.multipart.next_field_chunk(cx).await {
            Ok(Some(chunk)) => {
                self.multipart.yielded_field_chunk_bytes_peak = self
                    .multipart
                    .yielded_field_chunk_bytes_peak
                    .max(chunk.len());
                Ok(Some(chunk))
            }
            Ok(None) => {
                self.complete = true;
                self.multipart.field_active = false;
                Ok(None)
            }
            Err(error) => {
                self.complete = true;
                self.multipart.abandon();
                Err(error.into())
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for StreamingMultipartField<'_> {
    fn drop(&mut self) {
        if self.complete {
            self.multipart.field_active = false;
        } else {
            self.multipart.abandon();
        }
    }
}

// ─── Parsing ────────────────────────────────────────────────────────────────

fn check_request_content_length_limit(req: &Request, limit: usize) -> Result<(), ExtractionError> {
    let Some(value) = header_value_ci(req, "content-length") else {
        return Ok(());
    };
    let declared_len = parse_content_length(value)?;
    if declared_len > limit {
        return Err(multipart_total_limit_error(format!(
            "multipart Content-Length {declared_len} bytes exceeds limit {limit} bytes"
        )));
    }
    Ok(())
}

fn validate_request_content_length(req: &Request) -> Result<(), ExtractionError> {
    let Some(value) = header_value_ci(req, "content-length") else {
        return Ok(());
    };
    let declared_len = parse_content_length(value)?;
    let actual_len = req.body.len();
    if declared_len != actual_len {
        return Err(malformed_multipart_error(
            StatusCode::BAD_REQUEST,
            format!(
                "multipart Content-Length mismatch: declared {declared_len} bytes, received {actual_len} bytes"
            ),
        ));
    }
    Ok(())
}

fn validate_multipart_content_type(req: &Request) -> Result<String, ExtractionError> {
    let content_type = header_value_ci(req, "content-type").ok_or_else(|| {
        malformed_multipart_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "missing Content-Type header",
        )
    })?;

    if !is_multipart_form_data(content_type) {
        return Err(malformed_multipart_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected multipart/form-data Content-Type",
        ));
    }

    extract_boundary(content_type).ok_or_else(|| {
        malformed_multipart_error(
            StatusCode::BAD_REQUEST,
            "missing or invalid boundary in Content-Type",
        )
    })
}

/// Maximum multipart boundary length per RFC 2046 §5.1.1.
///
/// RFC 2046 specifies boundaries are 1..=70 characters. Defending against
/// the ReDoS-like O(body * boundary) substring search a malicious peer
/// could trigger by declaring a very long boundary and sending a large
/// body — see br-asupersync-tamnew.
pub const MAX_BOUNDARY_LEN: usize = 70;

fn content_type_media_type(content_type: &str) -> Option<&str> {
    content_type
        .split(';')
        .next()
        .map(str::trim)
        .filter(|media_type| !media_type.is_empty())
}

/// Returns `true` when the media type is exactly `multipart/form-data`.
fn is_multipart_form_data(content_type: &str) -> bool {
    content_type_media_type(content_type)
        .is_some_and(|media_type| media_type.eq_ignore_ascii_case("multipart/form-data"))
}

/// Returns `true` when the media type is any `multipart/*` value.
fn is_multipart_media_type(content_type: &str) -> bool {
    content_type_media_type(content_type)
        .and_then(|media_type| media_type.split_once('/'))
        .is_some_and(|(type_name, _)| type_name.eq_ignore_ascii_case("multipart"))
}

/// Extract the boundary parameter from a Content-Type header value.
///
/// Returns `None` if the boundary is missing, malformed, empty, or longer
/// than [`MAX_BOUNDARY_LEN`] (RFC 2046 §5.1.1 cap; oversize values are
/// rejected to avoid O(body * boundary) substring search amplification).
fn extract_boundary(content_type: &str) -> Option<String> {
    let (_, mut params) = content_type.split_once(';')?;

    while let Some((param, rest)) = next_mime_param(params) {
        params = rest;
        let Some((name, value)) = param.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("boundary") {
            continue;
        }

        let value = value.trim();
        let boundary = if let Some(stripped) = value.strip_prefix('"') {
            parse_quoted_mime_value(stripped)?
        } else if value.is_empty() {
            return None;
        } else {
            value.to_string()
        };

        // RFC 2046 §5.1.1: boundary length must be 1..=70. Reject
        // pathological lengths that would amplify substring search cost.
        if boundary.is_empty() || boundary.len() > MAX_BOUNDARY_LEN {
            return None;
        }
        return Some(boundary);
    }

    None
}

fn next_mime_param(params: &str) -> Option<(&str, &str)> {
    let trimmed = params.trim_start_matches([';', ' ', '\t', '\r', '\n']);
    if trimmed.is_empty() {
        return None;
    }

    let bytes = trimmed.as_bytes();
    let mut in_quotes = false;
    let mut escaped = false;

    for (idx, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if in_quotes => escaped = true,
            b'"' => in_quotes = !in_quotes,
            b';' if !in_quotes => return Some((trimmed[..idx].trim(), &trimmed[idx + 1..])),
            _ => {}
        }
    }

    Some((trimmed.trim(), ""))
}

fn parse_quoted_mime_value(stripped: &str) -> Option<String> {
    let mut value = String::new();
    let mut escaped = false;

    for (idx, ch) in stripped.char_indices() {
        if escaped {
            value.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => {
                if !stripped[idx + ch.len_utf8()..].trim().is_empty() {
                    return None;
                }
                return Some(value);
            }
            _ => value.push(ch),
        }
    }

    None
}

/// Check if parsing should timeout due to elapsed time.
fn check_timeout(
    parse_start: Time,
    last_progress: Time,
    limits: &MultipartLimits,
) -> Result<(), ExtractionError> {
    const NANOS_PER_SECOND: u64 = 1_000_000_000;

    let now = wall_now();
    let total_elapsed = now.duration_since(parse_start);
    let idle_elapsed = now.duration_since(last_progress);
    let request_timeout = limits.request_timeout_secs.saturating_mul(NANOS_PER_SECOND);
    let idle_timeout = limits.idle_timeout_secs.saturating_mul(NANOS_PER_SECOND);

    if request_timeout == 0 || total_elapsed > request_timeout {
        return Err(multipart_timeout_error(format!(
            "multipart parsing timed out after {total_elapsed}ns (max {request_timeout}ns)"
        )));
    }

    if idle_timeout == 0 || idle_elapsed > idle_timeout {
        return Err(multipart_timeout_error(format!(
            "multipart parsing idle for {idle_elapsed}ns (max {idle_timeout}ns)"
        )));
    }

    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamingMultipartPhase {
    Preamble,
    Headers,
    Body,
    Done,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StreamingBoundaryMatch {
    start: usize,
    consumed: usize,
    closing: bool,
}

/// Incremental multipart decoder used only by the live HTTP/1 extractor.
///
/// The rolling buffer retains a bounded delimiter overlap while seeking or
/// reading a part body, and at most one bounded header section while parsing
/// headers. Completed field bodies remain materialized to preserve the public
/// [`Multipart`] contract.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
struct StreamingMultipartDecoder {
    delimiter: Vec<u8>,
    limits: MultipartLimits,
    expected_length: Option<usize>,
    parse_start: Time,
    last_progress: Time,
    phase: StreamingMultipartPhase,
    buffer: Vec<u8>,
    current_headers: Option<HashMap<String, String>>,
    current_body: Vec<u8>,
    fields: Vec<MultipartField>,
    total_received: usize,
    work_units: usize,
    max_work_units: usize,
    header_scan_from: usize,
    buffer_starts_at_line_start: bool,
}

#[cfg(not(target_arch = "wasm32"))]
impl StreamingMultipartDecoder {
    fn new(
        boundary: &str,
        limits: MultipartLimits,
        expected_length: Option<usize>,
    ) -> Result<Self, ExtractionError> {
        let delimiter = format!("--{boundary}").into_bytes();
        let work_scale = delimiter
            .len()
            .checked_mul(6)
            .and_then(|units| units.checked_add(16))
            .ok_or_else(|| {
                multipart_field_limit_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "multipart parser work budget overflow",
                )
            })?;
        let max_work_units = limits
            .max_total_size
            .checked_mul(work_scale)
            .ok_or_else(|| {
                multipart_field_limit_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "multipart parser work budget overflow",
                )
            })?;
        let now = wall_now();
        Ok(Self {
            delimiter,
            limits,
            expected_length,
            parse_start: now,
            last_progress: now,
            phase: StreamingMultipartPhase::Preamble,
            buffer: Vec::new(),
            current_headers: None,
            current_body: Vec::new(),
            fields: Vec::new(),
            total_received: 0,
            work_units: 0,
            max_work_units,
            header_scan_from: 0,
            buffer_starts_at_line_start: true,
        })
    }

    fn feed(&mut self, data: &[u8]) -> Result<(), ExtractionError> {
        check_timeout(self.parse_start, self.last_progress, &self.limits)?;
        self.total_received = self.total_received.checked_add(data.len()).ok_or_else(|| {
            multipart_total_limit_error("multipart body size accounting overflow")
        })?;
        if self.total_received > self.limits.max_total_size {
            return Err(multipart_total_limit_error(format!(
                "multipart body too large: {} bytes (max {})",
                self.total_received, self.limits.max_total_size
            )));
        }

        if self.phase != StreamingMultipartPhase::Done {
            // Bound transient rolling-buffer retention even when the incoming
            // body yields one large frame. Header/body limits remain the
            // authoritative semantic caps; this window only limits scratch.
            for window in data.chunks(4096) {
                self.buffer.extend_from_slice(window);
                self.process(false)?;
                if self.phase == StreamingMultipartPhase::Done {
                    break;
                }
            }
        }
        if !data.is_empty() {
            self.last_progress = wall_now();
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<MultipartField>, ExtractionError> {
        check_timeout(self.parse_start, self.last_progress, &self.limits)?;
        if let Some(expected) = self.expected_length
            && expected != self.total_received
        {
            return Err(malformed_multipart_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "multipart Content-Length mismatch: declared {expected} bytes, received {} bytes",
                    self.total_received
                ),
            ));
        }
        self.process(true)?;
        match self.phase {
            StreamingMultipartPhase::Done => Ok(self.fields),
            StreamingMultipartPhase::Preamble => Err(malformed_multipart_error(
                StatusCode::BAD_REQUEST,
                "multipart body missing initial boundary",
            )),
            StreamingMultipartPhase::Headers => Err(malformed_multipart_error(
                StatusCode::BAD_REQUEST,
                "multipart part missing header terminator",
            )),
            StreamingMultipartPhase::Body => Err(malformed_multipart_error(
                StatusCode::BAD_REQUEST,
                "multipart part missing closing boundary",
            )),
        }
    }

    fn read_deadline(&self) -> Time {
        let request_deadline =
            self.parse_start + Duration::from_secs(self.limits.request_timeout_secs);
        let idle_deadline = self.last_progress + Duration::from_secs(self.limits.idle_timeout_secs);
        request_deadline.min(idle_deadline)
    }

    fn process(&mut self, eof: bool) -> Result<(), ExtractionError> {
        loop {
            match self.phase {
                StreamingMultipartPhase::Preamble => {
                    if !self.process_preamble(eof)? {
                        return Ok(());
                    }
                }
                StreamingMultipartPhase::Headers => {
                    if !self.process_headers()? {
                        return Ok(());
                    }
                }
                StreamingMultipartPhase::Body => {
                    if !self.process_body(eof)? {
                        return Ok(());
                    }
                }
                StreamingMultipartPhase::Done => {
                    self.buffer.clear();
                    return Ok(());
                }
            }
        }
    }

    fn process_preamble(&mut self, eof: bool) -> Result<bool, ExtractionError> {
        let (found, examined) = find_streaming_boundary(
            &self.buffer,
            &self.delimiter,
            eof,
            self.buffer_starts_at_line_start,
        );
        self.charge_boundary_work(examined)?;
        if let Some(found) = found {
            self.drain_buffer_prefix(found.consumed);
            if found.closing {
                self.phase = StreamingMultipartPhase::Done;
            } else {
                self.enter_headers()?;
            }
            return Ok(true);
        }

        let keep = self.delimiter.len().saturating_add(3);
        if self.buffer.len() > keep {
            let discard = self.buffer.len() - keep;
            self.drain_buffer_prefix(discard);
        }
        Ok(false)
    }

    fn process_headers(&mut self) -> Result<bool, ExtractionError> {
        let scan_from = self.header_scan_from.min(self.buffer.len());
        let terminator = find_blank_line(&self.buffer, scan_from);
        let examined =
            terminator.map_or(self.buffer.len(), |(_, body_start)| body_start) - scan_from;
        self.charge_work(examined)?;
        if let Some((headers_end, body_start)) = terminator {
            if headers_end > self.limits.max_part_headers {
                return Err(multipart_field_limit_error(
                    StatusCode::BAD_REQUEST,
                    "multipart part headers too large",
                ));
            }
            let headers = parse_part_headers(&self.buffer[..headers_end])?;
            self.drain_buffer_prefix(body_start);
            self.current_headers = Some(headers);
            self.current_body.clear();
            self.header_scan_from = 0;
            self.phase = StreamingMultipartPhase::Body;
            return Ok(true);
        }

        if self.buffer.len() > self.limits.max_part_headers.saturating_add(3) {
            return Err(multipart_field_limit_error(
                StatusCode::BAD_REQUEST,
                "multipart part headers too large",
            ));
        }
        self.header_scan_from = self.buffer.len().saturating_sub(3);
        Ok(false)
    }

    fn process_body(&mut self, eof: bool) -> Result<bool, ExtractionError> {
        let (found, examined) = find_streaming_boundary(
            &self.buffer,
            &self.delimiter,
            eof,
            self.buffer_starts_at_line_start,
        );
        self.charge_boundary_work(examined)?;
        if let Some(found) = found {
            let body_end = strip_trailing_crlf(&self.buffer, found.start);
            let prefix = self.buffer[..body_end].to_vec();
            self.append_current_body(&prefix)?;
            self.finish_current_field()?;
            self.drain_buffer_prefix(found.consumed);
            if found.closing {
                self.phase = StreamingMultipartPhase::Done;
            } else {
                self.enter_headers()?;
            }
            return Ok(true);
        }

        let keep = self.delimiter.len().saturating_add(3);
        if self.buffer.len() > keep {
            let flush = self.buffer.len() - keep;
            let prefix = self.buffer[..flush].to_vec();
            self.append_current_body(&prefix)?;
            self.drain_buffer_prefix(flush);
        }
        Ok(false)
    }

    fn enter_headers(&mut self) -> Result<(), ExtractionError> {
        if self.fields.len() >= self.limits.max_parts {
            return Err(multipart_field_limit_error(
                StatusCode::BAD_REQUEST,
                format!("too many multipart parts (max {})", self.limits.max_parts),
            ));
        }
        self.header_scan_from = 0;
        self.phase = StreamingMultipartPhase::Headers;
        Ok(())
    }

    fn append_current_body(&mut self, bytes: &[u8]) -> Result<(), ExtractionError> {
        let next_len = self
            .current_body
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| {
                multipart_field_limit_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "multipart part body size accounting overflow",
                )
            })?;
        if next_len > self.limits.max_part_body_size {
            return Err(multipart_field_limit_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "multipart part body too large",
            ));
        }
        self.current_body.extend_from_slice(bytes);
        Ok(())
    }

    fn finish_current_field(&mut self) -> Result<(), ExtractionError> {
        let headers = self.current_headers.take().ok_or_else(|| {
            ExtractionError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "multipart parser lost current part headers",
            )
        })?;
        validate_part_content_length(&headers, self.current_body.len())?;

        let disposition = headers
            .get("content-disposition")
            .cloned()
            .unwrap_or_default();
        let name = parse_disposition_param(&disposition, "name").unwrap_or_default();
        let filename = parse_disposition_param(&disposition, "filename");
        let content_type = headers.get("content-type").cloned();
        if content_type.as_deref().is_some_and(is_multipart_media_type) {
            return Err(malformed_multipart_error(
                StatusCode::BAD_REQUEST,
                "nested multipart parts are not supported",
            ));
        }

        self.fields.push(MultipartField {
            name,
            filename,
            content_type,
            headers,
            body: Bytes::from(std::mem::take(&mut self.current_body)),
        });
        Ok(())
    }

    fn charge_work(&mut self, units: usize) -> Result<(), ExtractionError> {
        self.work_units = self.work_units.checked_add(units).ok_or_else(|| {
            multipart_field_limit_error(
                StatusCode::BAD_REQUEST,
                "multipart parser work accounting overflow",
            )
        })?;
        if self.work_units > self.max_work_units {
            return Err(multipart_field_limit_error(
                StatusCode::BAD_REQUEST,
                "multipart parser work limit exceeded",
            ));
        }
        Ok(())
    }

    fn charge_boundary_work(&mut self, starts_examined: usize) -> Result<(), ExtractionError> {
        let units = starts_examined
            .checked_mul(self.delimiter.len())
            .ok_or_else(|| {
                multipart_field_limit_error(
                    StatusCode::BAD_REQUEST,
                    "multipart parser work accounting overflow",
                )
            })?;
        self.charge_work(units)
    }

    fn drain_buffer_prefix(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        self.buffer_starts_at_line_start = self.buffer[count - 1] == b'\n';
        self.buffer.drain(..count);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn find_streaming_boundary(
    data: &[u8],
    delimiter: &[u8],
    eof: bool,
    buffer_starts_at_line_start: bool,
) -> (Option<StreamingBoundaryMatch>, usize) {
    if delimiter.is_empty() || data.len() < delimiter.len() {
        return (None, 0);
    }

    let mut starts_examined = 0usize;
    for start in 0..=data.len() - delimiter.len() {
        starts_examined += 1;
        if (start == 0 && !buffer_starts_at_line_start)
            || (start != 0 && data[start - 1] != b'\n')
            || &data[start..start + delimiter.len()] != delimiter
        {
            continue;
        }

        let suffix = start + delimiter.len();
        if data.get(suffix..suffix + 2) == Some(b"--") {
            return (
                Some(StreamingBoundaryMatch {
                    start,
                    consumed: suffix + 2,
                    closing: true,
                }),
                starts_examined,
            );
        }
        if data.get(suffix) == Some(&b'\n') {
            return (
                Some(StreamingBoundaryMatch {
                    start,
                    consumed: suffix + 1,
                    closing: false,
                }),
                starts_examined,
            );
        }
        if data.get(suffix..suffix + 2) == Some(b"\r\n") {
            return (
                Some(StreamingBoundaryMatch {
                    start,
                    consumed: suffix + 2,
                    closing: false,
                }),
                starts_examined,
            );
        }
        if data.get(suffix) == Some(&b'\r') && (eof || data.get(suffix + 1).is_some()) {
            // Preserve the buffered parser's unusual bare-CR compatibility:
            // the delimiter is admitted, but the CR is left as the first
            // header byte because `skip_line_ending` consumes only CRLF/LF.
            return (
                Some(StreamingBoundaryMatch {
                    start,
                    consumed: suffix,
                    closing: false,
                }),
                starts_examined,
            );
        }
    }
    (None, starts_examined)
}

#[cfg(not(target_arch = "wasm32"))]
async fn extract_streaming_multipart(cx: &Cx, req: Request) -> Result<Multipart, ExtractionError> {
    let limits = effective_multipart_limits(&req);
    check_request_content_length_limit(&req, limits.max_total_size)?;
    let expected_length = header_value_ci(&req, "content-length")
        .map(parse_content_length)
        .transpose()?;
    let boundary = validate_multipart_content_type(&req)?;
    let mut body = StreamingRawBody::from_request(req)?;
    let mut decoder = StreamingMultipartDecoder::new(&boundary, limits, expected_length)?;

    loop {
        if cx.checkpoint().is_err() {
            let kind = cx
                .cancel_reason()
                .map_or(CancelKind::User, |reason| reason.kind());
            return Err(streaming_extraction_error(
                "multipart",
                StreamingRawBodyCollectError::Body(IncomingBodyError::Cancelled { kind }),
            ));
        }

        let deadline = decoder.read_deadline();
        let next = crate::time::timeout_at(
            deadline,
            std::future::poll_fn(|poll_cx| Pin::new(&mut body).poll_frame(poll_cx)),
        )
        .await
        .map_err(|_| multipart_timeout_error("multipart request body timed out"))?;
        let Some(frame) = next else {
            break;
        };
        match frame.map_err(|error| {
            streaming_extraction_error("multipart", StreamingRawBodyCollectError::Body(error))
        })? {
            Frame::Data(mut data) => {
                while data.has_remaining() {
                    let chunk = data.chunk();
                    if chunk.is_empty() {
                        return Err(ExtractionError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "multipart request body produced an empty data cursor",
                        ));
                    }
                    decoder.feed(chunk)?;
                    let consumed = chunk.len();
                    data.advance(consumed);
                }
            }
            Frame::Trailers(_) => {}
        }
    }

    decoder.finish().map(|fields| Multipart { fields })
}

/// Parse multipart body given a boundary string.
fn parse_multipart(
    body: &Bytes,
    boundary: &str,
    limits: &MultipartLimits,
    parse_start: Time,
) -> Result<Vec<MultipartField>, ExtractionError> {
    let delimiter = format!("--{boundary}");
    let delimiter_bytes = delimiter.as_bytes();
    let close_delimiter = format!("--{boundary}--");
    let close_bytes = close_delimiter.as_bytes();

    let mut fields = Vec::new();
    let mut pos = 0;
    let mut last_progress = parse_start;

    // Skip preamble: advance to first delimiter.
    check_timeout(parse_start, last_progress, limits)?;
    pos = match find_multipart_delimiter(body, delimiter_bytes, pos) {
        Some(idx) => idx + delimiter_bytes.len(),
        None => {
            return Err(malformed_multipart_error(
                StatusCode::BAD_REQUEST,
                "multipart body missing initial boundary",
            ));
        }
    };

    // Check if the first boundary is actually the close boundary (empty multipart).
    if body.get(pos..pos + 2) == Some(b"--") {
        return Ok(fields);
    }

    // Skip the CRLF (or LF) after the delimiter.
    pos = skip_line_ending(body, pos);

    loop {
        // Check timeout at start of each iteration
        check_timeout(parse_start, last_progress, limits)?;

        if fields.len() >= limits.max_parts {
            return Err(multipart_field_limit_error(
                StatusCode::BAD_REQUEST,
                format!("too many multipart parts (max {})", limits.max_parts),
            ));
        }

        // Check for close delimiter at current position (might have been found
        // as next delimiter in the previous iteration).
        // Find the end of this part's headers (blank line).
        let headers_end = find_blank_line(body, pos).ok_or_else(|| {
            malformed_multipart_error(
                StatusCode::BAD_REQUEST,
                "multipart part missing header terminator",
            )
        })?;
        last_progress = wall_now(); // Mark progress after finding headers

        let headers_section = &body[pos..headers_end.0];
        if headers_section.len() > limits.max_part_headers {
            return Err(multipart_field_limit_error(
                StatusCode::BAD_REQUEST,
                "multipart part headers too large",
            ));
        }

        let part_headers = parse_part_headers(headers_section)?;

        // Body starts after the blank line.
        let body_start = headers_end.1;

        // Find next delimiter.
        check_timeout(parse_start, last_progress, limits)?;
        let next_delim =
            find_multipart_delimiter(body, delimiter_bytes, body_start).ok_or_else(|| {
                malformed_multipart_error(
                    StatusCode::BAD_REQUEST,
                    "multipart part missing closing boundary",
                )
            })?;
        last_progress = wall_now(); // Mark progress after finding boundary

        // Part body ends before the CRLF preceding the delimiter.
        // If the client sent a malformed request where the boundary immediately follows
        // the header terminator, strip_trailing_crlf might strip the header's CRLF,
        // causing body_end < body_start. We clamp it to prevent a panic.
        let body_end = strip_trailing_crlf(body, next_delim).max(body_start);

        if body_end - body_start > limits.max_part_body_size {
            return Err(multipart_field_limit_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "multipart part body too large",
            ));
        }

        let part_body = body.slice(body_start..body_end);
        validate_part_content_length(&part_headers, part_body.len())?;

        // Parse Content-Disposition for name and filename.
        let disposition = part_headers
            .get("content-disposition")
            .cloned()
            .unwrap_or_default();

        let name = parse_disposition_param(&disposition, "name").unwrap_or_default();
        let filename = parse_disposition_param(&disposition, "filename");
        let content_type = part_headers.get("content-type").cloned();
        if content_type.as_deref().is_some_and(is_multipart_media_type) {
            return Err(malformed_multipart_error(
                StatusCode::BAD_REQUEST,
                "nested multipart parts are not supported",
            ));
        }

        fields.push(MultipartField {
            name,
            filename,
            content_type,
            headers: part_headers,
            body: part_body,
        });

        // Advance past this delimiter.
        let after_delim = next_delim + delimiter_bytes.len();

        // Check if this is the close delimiter.
        if body.get(after_delim..after_delim + 2) == Some(b"--") {
            break; // End of multipart.
        }

        // Check for close delimiter at the found position.
        if body.len() >= next_delim + close_bytes.len()
            && &body[next_delim..next_delim + close_bytes.len()] == close_bytes
        {
            break;
        }

        pos = skip_line_ending(body, after_delim);

        // Safety: if we haven't advanced, bail.
        if pos >= body.len() {
            break;
        }
    }

    Ok(fields)
}

/// Find a byte sequence starting from `start`.
fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if start >= haystack.len() || needle.is_empty() {
        return None;
    }
    let search = &haystack[start..];
    // Simple search — for bodies up to 16 MiB this is fine.
    search
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + start)
}

/// Find a multipart boundary delimiter that starts on a line boundary.
fn find_multipart_delimiter(body: &[u8], delimiter: &[u8], start: usize) -> Option<usize> {
    let mut search_start = start;

    while let Some(idx) = find_bytes(body, delimiter, search_start) {
        let at_line_start = idx == 0 || body.get(idx - 1) == Some(&b'\n');
        let after = idx + delimiter.len();
        let has_valid_suffix = body.get(after..after + 2) == Some(b"--")
            || matches!(body.get(after), Some(b'\r' | b'\n'));

        if at_line_start && has_valid_suffix {
            return Some(idx);
        }

        search_start = idx + 1;
    }

    None
}

/// Find a blank line (CRLFCRLF or LFLF) starting at `pos`.
/// Returns (end_of_headers, start_of_body).
///
/// Both `\r\n\r\n` and `\n\n` are scanned and the *earlier* match wins. This
/// matters when a part uses `\n\n` for its header terminator but the part
/// body itself contains `\r\n\r\n`: an unconditional CRLFCRLF-first scan
/// would skip past the real blank line and split the body in the wrong
/// place, corrupting one part's payload.
fn find_blank_line(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let search = &data[pos..];
    let crlf_pos = search.windows(4).position(|w| w == b"\r\n\r\n");
    let lf_pos = search.windows(2).position(|w| w == b"\n\n");
    match (crlf_pos, lf_pos) {
        (Some(c), Some(l)) if c <= l => Some((pos + c, pos + c + 4)),
        (Some(c), None) => Some((pos + c, pos + c + 4)),
        (Some(_) | None, Some(l)) => Some((pos + l, pos + l + 2)),
        (None, None) => None,
    }
}

/// Skip a CRLF or LF at the given position.
fn skip_line_ending(data: &[u8], pos: usize) -> usize {
    if data.get(pos..pos + 2) == Some(b"\r\n") {
        pos + 2
    } else if data.get(pos..pos + 1) == Some(b"\n") {
        pos + 1
    } else {
        pos
    }
}

/// Strip a trailing CRLF or LF before position `end`.
fn strip_trailing_crlf(data: &[u8], end: usize) -> usize {
    if end >= 2 && data.get(end - 2..end) == Some(b"\r\n") {
        end - 2
    } else if end >= 1 && data.get(end - 1..end) == Some(b"\n") {
        end - 1
    } else {
        end
    }
}

/// Parse part headers from raw bytes. Keys are lowercased.
///
/// SECURITY: Rejects non-UTF8 header data to prevent bypass of nested
/// multipart detection via malformed Content-Type headers (br-asupersync-vzvpk9).
fn parse_part_headers(data: &[u8]) -> Result<HashMap<String, String>, ExtractionError> {
    let mut headers = HashMap::new();
    let text = std::str::from_utf8(data).map_err(|_| {
        malformed_multipart_error(
            StatusCode::BAD_REQUEST,
            "multipart part headers contain invalid UTF-8",
        )
    })?;
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    Ok(headers)
}

fn validate_part_content_length(
    headers: &HashMap<String, String>,
    actual_len: usize,
) -> Result<(), ExtractionError> {
    if let Some(declared_len) = parse_part_content_length(headers)?
        && declared_len != actual_len
    {
        return Err(malformed_multipart_error(
            StatusCode::BAD_REQUEST,
            format!(
                "multipart part content-length mismatch: declared {declared_len} bytes but parsed {actual_len} bytes"
            ),
        ));
    }

    Ok(())
}

fn parse_part_content_length(
    headers: &HashMap<String, String>,
) -> Result<Option<usize>, ExtractionError> {
    headers
        .get("content-length")
        .map(|value| {
            value.parse::<usize>().map_err(|_| {
                malformed_multipart_error(
                    StatusCode::BAD_REQUEST,
                    "multipart part content-length is invalid",
                )
            })
        })
        .transpose()
}

/// Sanitize a filename to prevent path traversal attacks.
///
/// Removes path separators, control characters, and normalizes the filename
/// to prevent directory traversal via Content-Disposition filename parameters.
///
/// SECURITY: This function prevents attacks like `../../../etc/passwd` by:
/// 1. Splitting on path separators and taking only the base name
/// 2. Filtering out control characters
/// 3. Trimming leading/trailing dots and spaces (Windows/macOS issues)
/// 4. Providing fallback for empty results
fn sanitize_filename(filename: &str) -> String {
    // Split on path separators and take the last path component first.
    let path_tail = filename.rsplit(['/', '\\']).next().unwrap_or("file");

    // Strip a raw Windows drive prefix like `C:report.txt` before processing
    // other colon-bearing forms such as alternate data streams.
    let without_drive = if path_tail.len() >= 2
        && path_tail.as_bytes()[1] == b':'
        && path_tail.as_bytes()[0].is_ascii_alphabetic()
    {
        &path_tail[2..]
    } else {
        path_tail
    };

    // Discard Windows alternate data stream suffixes like
    // `invoice.pdf:payload.exe` without letting the suffix become the
    // sanitized filename.
    let base_name = without_drive.split(':').next().unwrap_or("file");

    // Filter out control characters and normalize
    let sanitized = base_name
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '?' | '*' | '<' | '>' | '|'))
        .collect::<String>();

    // Trim problematic leading/trailing characters
    let trimmed = sanitized.trim_matches(['.', ' ']).to_string();

    // Fallback to "file" if empty after sanitization
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed
    }
}

/// Parse a parameter from a Content-Disposition header value.
///
/// Handles both quoted and unquoted values:
/// - `form-data; name="field1"`
/// - `form-data; name=field1`
///
/// SECURITY: For filename parameters, applies sanitization to prevent path traversal.
fn parse_disposition_param(disposition: &str, param: &str) -> Option<String> {
    if let Some(value) = parse_disposition_ext_param(disposition, param) {
        return Some(value);
    }

    let search = format!("{param}=");
    let lower = disposition.to_ascii_lowercase();
    // Find the param ensuring it's not a suffix of another param (e.g. "name=" inside "filename=").
    // The match must be preceded by start-of-string, ';', space, or tab.
    let idx = {
        let mut start = 0;
        loop {
            let pos = lower[start..].find(&search)?;
            let abs = start + pos;
            if abs == 0 || matches!(lower.as_bytes()[abs - 1], b';' | b' ' | b'\t') {
                break abs;
            }
            start = abs + search.len();
        }
    };
    let after = &disposition[idx + search.len()..];

    let raw_value = after.strip_prefix('"').map_or_else(
        || {
            let end = after.find([';', ' ', '\t']).unwrap_or(after.len());
            let val = after[..end].trim();
            if val.is_empty() {
                None
            } else {
                Some(val.to_string())
            }
        },
        |stripped| {
            // Quoted value — handle escaped quotes.
            let mut result = String::new();
            let mut chars = stripped.chars();
            loop {
                match chars.next() {
                    Some('"') | None => break,
                    Some('\\') => {
                        if let Some(c) = chars.next() {
                            result.push(c);
                        }
                    }
                    Some(c) => result.push(c),
                }
            }
            Some(result)
        },
    )?;

    // SECURITY: Apply filename sanitization to prevent path traversal
    if param == "filename" {
        Some(sanitize_filename(&raw_value))
    } else {
        Some(raw_value)
    }
}

fn parse_disposition_ext_param(disposition: &str, param: &str) -> Option<String> {
    let search = format!("{param}*=");
    let lower = disposition.to_ascii_lowercase();
    let idx = {
        let mut start = 0;
        loop {
            let pos = lower[start..].find(&search)?;
            let abs = start + pos;
            if abs == 0 || matches!(lower.as_bytes()[abs - 1], b';' | b' ' | b'\t') {
                break abs;
            }
            start = abs + search.len();
        }
    };

    let after = &disposition[idx + search.len()..];
    let end = after.find([';', ' ', '\t']).unwrap_or(after.len());
    let decoded = decode_rfc8187_ext_value(after[..end].trim())?;

    // SECURITY: Apply filename sanitization to RFC 8187 extended filenames
    if param == "filename" {
        Some(sanitize_filename(&decoded))
    } else {
        Some(decoded)
    }
}

fn decode_rfc8187_ext_value(value: &str) -> Option<String> {
    let (charset, rest) = value.split_once('\'')?;
    let (_, encoded) = rest.split_once('\'')?;
    if !charset.eq_ignore_ascii_case("utf-8") {
        return None;
    }

    let mut decoded = Vec::with_capacity(encoded.len());
    let bytes = encoded.as_bytes();
    let mut idx = 0;

    while idx < bytes.len() {
        match bytes[idx] {
            b'%' if idx + 2 < bytes.len() => {
                let hi = (bytes[idx + 1] as char).to_digit(16)?;
                let lo = (bytes[idx + 2] as char).to_digit(16)?;
                decoded.push(((hi << 4) | lo) as u8);
                idx += 3;
            }
            byte if byte.is_ascii() => {
                decoded.push(byte);
                idx += 1;
            }
            _ => return None,
        }
    }

    String::from_utf8(decoded).ok()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

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

    #[test]
    fn body_policy_enforced_snapshot_prevents_late_multipart_limit_loosen() {
        let strict_multipart = MultipartLimits::new()
            .max_total_size(1024)
            .max_part_body_size(2);
        let enforced = super::super::RequestBodyPolicy::new()
            .max_total_body_size(1024)
            .multipart_limits(strict_multipart)
            .resolved();
        let loose_multipart = MultipartLimits::new()
            .max_total_size(4096)
            .max_part_body_size(4096);
        let mut request = Request::new("POST", "/upload")
            .with_header("content-type", "multipart/form-data; boundary=X")
            .with_body(Bytes::from_static(
                b"--X\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nabc\r\n--X--\r\n",
            ));
        request
            .extensions
            .insert_typed(super::super::EnforcedRequestBodyPolicy { policy: enforced });
        request.extensions.insert_typed(
            super::super::RequestBodyPolicy::new()
                .max_total_body_size(4096)
                .multipart_limits(loose_multipart),
        );
        request.extensions.insert_typed(loose_multipart);

        let error = Multipart::from_request(request)
            .expect_err("late middleware must not loosen locked multipart field limit");
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ================================================================
    // Boundary extraction
    // ================================================================

    #[test]
    fn extract_boundary_basic() {
        let ct = "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW";
        assert_eq!(
            extract_boundary(ct).unwrap(),
            "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        );
    }

    #[test]
    fn extract_boundary_quoted() {
        let ct = r#"multipart/form-data; boundary="abc123""#;
        assert_eq!(extract_boundary(ct).unwrap(), "abc123");
    }

    #[test]
    fn extract_boundary_missing() {
        assert!(extract_boundary("multipart/form-data").is_none());
    }

    #[test]
    fn extract_boundary_empty() {
        assert!(extract_boundary("multipart/form-data; boundary=").is_none());
    }

    #[test]
    fn extract_boundary_with_extra_params() {
        let ct = "multipart/form-data; boundary=abc; charset=utf-8";
        assert_eq!(extract_boundary(ct).unwrap(), "abc");
    }

    #[test]
    fn extract_boundary_ignores_similar_parameter_names() {
        let ct = "multipart/form-data; xboundary=wrong; boundary=abc";
        assert_eq!(extract_boundary(ct).unwrap(), "abc");
    }

    #[test]
    fn extract_boundary_allows_whitespace_around_equals() {
        let ct = "multipart/form-data; boundary = abc123";
        assert_eq!(extract_boundary(ct).unwrap(), "abc123");
    }

    #[test]
    fn extract_boundary_unterminated_quote_rejected_even_with_later_fragment() {
        let ct = "multipart/form-data; boundary=\"unterminated; boundary=abc";
        assert_eq!(extract_boundary(ct), None);
    }

    #[test]
    fn extract_boundary_trailing_garbage_after_quote_rejected() {
        let ct = "multipart/form-data; boundary=\"abc\"junk";
        assert_eq!(extract_boundary(ct), None);
    }

    #[test]
    fn extract_boundary_at_70_char_rfc_max_accepted() {
        // br-asupersync-tamnew: RFC 2046 §5.1.1 caps boundary at 70 chars.
        // Exactly 70 chars must still be accepted.
        let boundary_70 = "a".repeat(70);
        let ct = format!("multipart/form-data; boundary={boundary_70}");
        assert_eq!(extract_boundary(&ct).unwrap(), boundary_70);
    }

    #[test]
    fn extract_boundary_above_70_char_rfc_max_rejected() {
        // br-asupersync-tamnew: 71-char boundary MUST be rejected to
        // prevent O(body * boundary) substring search amplification.
        let boundary_71 = "a".repeat(71);
        let ct = format!("multipart/form-data; boundary={boundary_71}");
        assert_eq!(extract_boundary(&ct), None);
    }

    #[test]
    fn extract_boundary_pathological_1mb_rejected() {
        // br-asupersync-tamnew: 1 MiB boundary MUST be rejected fast.
        let boundary_huge = "x".repeat(1_048_576);
        let ct = format!("multipart/form-data; boundary={boundary_huge}");
        assert_eq!(extract_boundary(&ct), None);
    }

    // ================================================================
    // Content-Disposition parameter parsing
    // ================================================================

    #[test]
    fn parse_disposition_name() {
        let d = r#"form-data; name="username""#;
        assert_eq!(parse_disposition_param(d, "name").unwrap(), "username");
    }

    #[test]
    fn parse_disposition_filename() {
        let d = r#"form-data; name="file"; filename="photo.jpg""#;
        assert_eq!(parse_disposition_param(d, "name").unwrap(), "file");
        assert_eq!(parse_disposition_param(d, "filename").unwrap(), "photo.jpg");
    }

    #[test]
    fn parse_disposition_escaped_quote() {
        let d = r#"form-data; name="field"; filename="file\"name.txt""#;
        assert_eq!(
            parse_disposition_param(d, "filename").unwrap(),
            r#"file"name.txt"#
        );
    }

    #[test]
    fn parse_disposition_unquoted() {
        let d = "form-data; name=username";
        assert_eq!(parse_disposition_param(d, "name").unwrap(), "username");
    }

    #[test]
    fn parse_disposition_name_not_confused_with_filename() {
        // Regression: "name=" must not match inside "filename="
        let d = r#"form-data; filename="photo.jpg"; name="field""#;
        assert_eq!(parse_disposition_param(d, "name").unwrap(), "field");
        assert_eq!(parse_disposition_param(d, "filename").unwrap(), "photo.jpg");
    }

    #[test]
    fn parse_disposition_missing() {
        let d = "form-data; name=\"field\"";
        assert!(parse_disposition_param(d, "filename").is_none());
    }

    // ================================================================
    // Part header parsing
    // ================================================================

    #[test]
    fn parse_headers_basic() {
        let raw = b"Content-Disposition: form-data; name=\"file\"\r\nContent-Type: image/png";
        let hdrs = parse_part_headers(raw).unwrap();
        assert_eq!(hdrs.len(), 2);
        assert!(hdrs.get("content-disposition").unwrap().contains("name="));
        assert_eq!(hdrs.get("content-type").unwrap(), "image/png");
    }

    #[test]
    fn parse_headers_empty() {
        let hdrs = parse_part_headers(b"").unwrap();
        assert!(hdrs.is_empty());
    }

    #[test]
    fn parse_headers_rejects_non_utf8() {
        // SECURITY TEST: Non-UTF8 headers must be rejected to prevent
        // bypass of nested multipart detection (br-asupersync-vzvpk9).
        let non_utf8 = b"Content-Type: multipart/mixed\xFF\xFE\r\n";
        let result = parse_part_headers(non_utf8);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("invalid UTF-8"));
    }

    #[test]
    fn validate_part_content_length_rejects_mismatch() {
        let mut headers = HashMap::new();
        headers.insert("content-length".to_string(), "5".to_string());
        let err = validate_part_content_length(&headers, 3).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("content-length mismatch"));
    }

    // ================================================================
    // Full multipart parsing
    // ================================================================

    fn make_multipart_body(boundary: &str, parts: &[(&str, &[u8])]) -> Bytes {
        let mut buf = Vec::new();
        for (headers, body) in parts {
            buf.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            buf.extend_from_slice(headers.as_bytes());
            buf.extend_from_slice(b"\r\n\r\n");
            buf.extend_from_slice(body);
            buf.extend_from_slice(b"\r\n");
        }
        buf.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        Bytes::from(buf)
    }

    fn multipart_request(body: Bytes) -> Request {
        Request::new("POST", "/upload")
            .with_header("content-type", "multipart/form-data; boundary=BOUNDARY")
            .with_body(body)
    }

    #[test]
    fn parse_single_text_field() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"",
                b"alice",
            )],
        );
        let fields =
            parse_multipart(&body, "BOUNDARY", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name(), "username");
        assert_eq!(fields[0].text().unwrap(), "alice");
        assert!(fields[0].filename().is_none());
    }

    #[test]
    fn multipart_extractor_rejects_request_content_length_mismatch() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"",
                b"alice",
            )],
        );
        let actual_len = body.len();
        let req =
            multipart_request(body).with_header("content-length", (actual_len + 1).to_string());

        let err = Multipart::from_request(req).unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(
            err.message.contains("Content-Length mismatch"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn multipart_extractor_rejects_conflicting_request_content_lengths() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"",
                b"alice",
            )],
        );
        let actual_len = body.len();
        let req = multipart_request(body).with_header(
            "content-length",
            format!("{actual_len}, {}", actual_len + 1),
        );

        let err = Multipart::from_request(req).unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(
            err.message.contains("conflicting Content-Length"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn multipart_extractor_rejects_declared_length_over_limit_before_parsing() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"",
                b"alice",
            )],
        );
        let mut req = multipart_request(body).with_header("content-length", "64");
        req.extensions
            .insert_typed(MultipartLimits::new().max_total_size(16));

        let err = Multipart::from_request(req).unwrap_err();

        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            err.message.contains("Content-Length"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn parse_single_field_body_is_zero_copy_slice() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"",
                b"alice",
            )],
        );
        let expected_offset = body
            .windows(b"alice".len())
            .position(|w| w == b"alice")
            .unwrap();

        let fields =
            parse_multipart(&body, "BOUNDARY", &MultipartLimits::default(), wall_now()).unwrap();

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].body().as_ref(), b"alice");
        assert_eq!(fields[0].body().as_ptr(), body[expected_offset..].as_ptr());
    }

    #[test]
    fn parse_rejects_spoofed_part_content_length() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"\r\nContent-Length: 999",
                b"alice",
            )],
        );
        let err = parse_multipart(&body, "BOUNDARY", &MultipartLimits::default(), wall_now())
            .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("content-length mismatch"));
    }

    #[test]
    fn parse_accepts_matching_part_content_length() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"\r\nContent-Length: 5",
                b"alice",
            )],
        );
        let fields =
            parse_multipart(&body, "BOUNDARY", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].text().unwrap(), "alice");
        assert_eq!(
            fields[0]
                .headers()
                .get("content-length")
                .map(String::as_str),
            Some("5")
        );
    }

    #[test]
    fn parse_multiple_fields() {
        let body = make_multipart_body(
            "B",
            &[
                ("Content-Disposition: form-data; name=\"a\"", b"1"),
                ("Content-Disposition: form-data; name=\"b\"", b"2"),
                ("Content-Disposition: form-data; name=\"c\"", b"3"),
            ],
        );
        let fields = parse_multipart(&body, "B", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name(), "a");
        assert_eq!(fields[1].name(), "b");
        assert_eq!(fields[2].name(), "c");
    }

    #[test]
    fn find_blank_line_prefers_earlier_lflf_over_later_crlfcrlf() {
        // Headers terminated with bare LFLF, body contains CRLFCRLF.
        // The earlier (LFLF) match must win so the body is not truncated.
        let data = b"Header: value\n\nbefore\r\n\r\nafter";
        let result = find_blank_line(data, 0);
        assert_eq!(result, Some((13, 15)));
    }

    #[test]
    fn find_blank_line_prefers_earlier_crlfcrlf_over_later_lflf() {
        let data = b"Header: value\r\n\r\nbefore\n\nafter";
        let result = find_blank_line(data, 0);
        assert_eq!(result, Some((13, 17)));
    }

    #[test]
    fn parse_body_with_embedded_boundary_token_does_not_split_field() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"payload\"",
                b"value--BOUNDARYstill-body",
            )],
        );

        let fields =
            parse_multipart(&body, "BOUNDARY", &MultipartLimits::default(), wall_now()).unwrap();

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name(), "payload");
        assert_eq!(fields[0].body().as_ref(), b"value--BOUNDARYstill-body");
    }

    #[test]
    fn parse_rejects_nested_multipart_part() {
        let nested = b"--INNER\r\nContent-Disposition: form-data; name=\"inner\"\r\n\r\nvalue\r\n--INNER--\r\n";
        let body = make_multipart_body(
            "OUTER",
            &[(
                "Content-Disposition: form-data; name=\"payload\"\r\nContent-Type: multipart/mixed; boundary=INNER",
                nested,
            )],
        );

        let err =
            parse_multipart(&body, "OUTER", &MultipartLimits::default(), wall_now()).unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            err.message,
            "[ASUP-E507] nested multipart parts are not supported"
        );
    }

    #[test]
    fn parse_rejects_non_utf8_header_bypass_attempt() {
        // SECURITY TEST: Verify that non-UTF8 headers cannot bypass
        // nested multipart detection (br-asupersync-vzvpk9).
        let nested = b"--INNER\r\nContent-Disposition: form-data; name=\"inner\"\r\n\r\nvalue\r\n--INNER--\r\n";

        // Create a multipart body where the headers contain non-UTF8 bytes
        let mut buf = Vec::new();
        buf.extend_from_slice(b"--OUTER\r\n");
        buf.extend_from_slice(b"Content-Disposition: form-data; name=\"payload\"\r\n");
        // Inject non-UTF8 bytes in Content-Type header to try bypassing detection
        buf.extend_from_slice(b"Content-Type: multipart/mixed\xFF\xFE; boundary=INNER\r\n");
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(nested);
        buf.extend_from_slice(b"\r\n--OUTER--\r\n");
        let body = Bytes::from(buf);

        // This should fail due to non-UTF8 headers, not due to nested multipart detection
        let err =
            parse_multipart(&body, "OUTER", &MultipartLimits::default(), wall_now()).unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("invalid UTF-8"));
    }

    #[test]
    fn parse_file_upload() {
        let body = make_multipart_body(
            "X",
            &[(
                "Content-Disposition: form-data; name=\"doc\"; filename=\"readme.txt\"\r\nContent-Type: text/plain",
                b"Hello, world!",
            )],
        );
        let fields = parse_multipart(&body, "X", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name(), "doc");
        assert_eq!(fields[0].filename().unwrap(), "readme.txt");
        assert_eq!(fields[0].content_type().unwrap(), "text/plain");
        assert_eq!(fields[0].text().unwrap(), "Hello, world!");
    }

    #[test]
    fn parse_file_upload_prefers_rfc8187_extended_filename() {
        let body = make_multipart_body(
            "X",
            &[(
                "Content-Disposition: form-data; name=\"doc\"; filename=\"EURO rates\"; filename*=UTF-8''%e2%82%ac%20exchange%20rates\r\nContent-Type: text/plain",
                b"Hello, world!",
            )],
        );
        let fields = parse_multipart(&body, "X", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name(), "doc");
        assert_eq!(fields[0].filename().unwrap(), "€ exchange rates");
        assert_eq!(fields[0].content_type().unwrap(), "text/plain");
        assert_eq!(fields[0].text().unwrap(), "Hello, world!");
    }

    #[test]
    fn sanitize_filename_discards_windows_drive_and_ads_suffixes() {
        assert_eq!(sanitize_filename("C:report.txt"), "report.txt");
        assert_eq!(sanitize_filename("invoice.pdf:payload.exe"), "invoice.pdf");
        assert_eq!(
            sanitize_filename(r"C:\temp\invoice.pdf:payload.exe"),
            "invoice.pdf"
        );
    }

    #[test]
    fn parse_binary_body() {
        let binary = vec![0u8, 1, 2, 255, 254, 253];
        let body = make_multipart_body(
            "BIN",
            &[(
                "Content-Disposition: form-data; name=\"data\"; filename=\"blob.bin\"\r\nContent-Type: application/octet-stream",
                &binary,
            )],
        );
        let fields =
            parse_multipart(&body, "BIN", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields[0].body().as_ref(), &binary[..]);
        assert!(fields[0].text().is_err()); // Not valid UTF-8.
    }

    #[test]
    fn parse_empty_body_field() {
        let body = make_multipart_body(
            "E",
            &[("Content-Disposition: form-data; name=\"empty\"", b"")],
        );
        let fields = parse_multipart(&body, "E", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 1);
        assert!(fields[0].body().is_empty());
    }

    #[test]
    fn parse_missing_boundary_error() {
        let result = parse_multipart(
            &Bytes::from_static(b"no boundary here"),
            "MISSING",
            &MultipartLimits::default(),
            wall_now(),
        );
        assert!(result.is_err());
    }

    // ================================================================
    // FromRequest integration
    // ================================================================

    #[test]
    fn from_request_success() {
        let body = make_multipart_body(
            "TEST",
            &[("Content-Disposition: form-data; name=\"field\"", b"value")],
        );
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-data; boundary=TEST".to_string(),
        );
        req.body = body;

        let mp = Multipart::from_request(req).unwrap();
        assert_eq!(mp.len(), 1);
        assert_eq!(mp.field("field").unwrap().text().unwrap(), "value");
    }

    #[test]
    fn from_request_accepts_rfc2046_quoted_boundary_with_space() {
        let body = make_multipart_body(
            "simple boundary",
            &[("Content-Disposition: form-data; name=\"field\"", b"value")],
        );
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-data; boundary=\"simple boundary\"".to_string(),
        );
        req.body = body;

        let mp = Multipart::from_request(req).unwrap();
        assert_eq!(mp.len(), 1);
        assert_eq!(mp.field("field").unwrap().text().unwrap(), "value");
    }

    #[test]
    fn from_request_wrong_content_type() {
        let mut req = Request::new("POST", "/upload");
        req.headers
            .insert("content-type".to_string(), "application/json".to_string());
        req.body = Bytes::from(vec![]);

        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn from_request_rejects_media_type_substring_match() {
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-datax; boundary=TEST".to_string(),
        );
        req.body = Bytes::from(vec![]);

        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn from_request_uses_actual_boundary_parameter() {
        let body = make_multipart_body(
            "REAL",
            &[("Content-Disposition: form-data; name=\"field\"", b"value")],
        );
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-data; xboundary=wrong; boundary=REAL".to_string(),
        );
        req.body = body;

        let mp = Multipart::from_request(req).unwrap();
        assert_eq!(mp.len(), 1);
        assert_eq!(mp.field("field").unwrap().text().unwrap(), "value");
    }

    #[test]
    fn from_request_rejects_malformed_boundary_before_later_fragment() {
        let body = make_multipart_body(
            "REAL",
            &[("Content-Disposition: form-data; name=\"field\"", b"value")],
        );
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-data; boundary=\"unterminated; boundary=REAL".to_string(),
        );
        req.body = body;

        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn from_request_missing_content_type() {
        let req = Request::new("POST", "/upload");
        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn from_request_missing_boundary() {
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-data".to_string(),
        );
        req.body = Bytes::from(vec![]);

        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn from_request_payload_too_large() {
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-data; boundary=X".to_string(),
        );
        req.body = Bytes::copy_from_slice(&vec![0u8; DEFAULT_MAX_MULTIPART_SIZE + 1]);

        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn from_request_part_body_too_large() {
        let mut req = Request::new("POST", "/upload");
        req.headers.insert(
            "content-type".to_string(),
            "multipart/form-data; boundary=X".to_string(),
        );
        let mut body = Vec::new();
        body.extend_from_slice(b"--X\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n");
        body.extend_from_slice(&vec![0u8; DEFAULT_MAX_PART_BODY_SIZE + 1]);
        body.extend_from_slice(b"\r\n--X--\r\n");
        req.body = Bytes::from(body);

        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(err.message, "[ASUP-E506] multipart part body too large");
    }

    // ================================================================
    // Multipart accessors
    // ================================================================

    #[test]
    fn multipart_field_by_name() {
        let body = make_multipart_body(
            "F",
            &[
                ("Content-Disposition: form-data; name=\"x\"", b"1"),
                ("Content-Disposition: form-data; name=\"y\"", b"2"),
            ],
        );
        let fields = parse_multipart(&body, "F", &MultipartLimits::default(), wall_now()).unwrap();
        let mp = Multipart { fields };

        assert_eq!(mp.field("x").unwrap().text().unwrap(), "1");
        assert_eq!(mp.field("y").unwrap().text().unwrap(), "2");
        assert!(mp.field("z").is_none());
    }

    #[test]
    fn multipart_repeated_fields() {
        let body = make_multipart_body(
            "R",
            &[
                ("Content-Disposition: form-data; name=\"tag\"", b"a"),
                ("Content-Disposition: form-data; name=\"tag\"", b"b"),
            ],
        );
        let fields = parse_multipart(&body, "R", &MultipartLimits::default(), wall_now()).unwrap();
        let mp = Multipart { fields };

        let tags = mp.fields_by_name("tag");
        assert_eq!(tags.len(), 2);
    }

    #[test]
    fn multipart_is_empty() {
        let mp = Multipart { fields: Vec::new() };
        assert!(mp.is_empty());
        assert_eq!(mp.len(), 0);
    }

    #[test]
    fn multipart_into_fields() {
        let body =
            make_multipart_body("I", &[("Content-Disposition: form-data; name=\"k\"", b"v")]);
        let fields = parse_multipart(&body, "I", &MultipartLimits::default(), wall_now()).unwrap();
        let mp = Multipart { fields };
        let mut owned = mp.into_fields();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned.remove(0).into_body().as_ref(), b"v");
    }

    // ================================================================
    // Edge cases
    // ================================================================

    #[test]
    fn parse_lf_line_endings() {
        // Some clients use bare LF instead of CRLF.
        let mut body = Vec::new();
        body.extend_from_slice(b"--B\n");
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"f\"\n\n");
        body.extend_from_slice(b"data");
        body.extend_from_slice(b"\n--B--\n");
        let body = Bytes::from(body);
        let fields = parse_multipart(&body, "B", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].text().unwrap(), "data");
    }

    #[test]
    fn parse_preamble_before_first_boundary() {
        let mut body = Vec::new();
        body.extend_from_slice(b"This is a preamble that should be ignored.\r\n");
        body.extend_from_slice(b"--BOUND\r\n");
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"x\"\r\n\r\n");
        body.extend_from_slice(b"val");
        body.extend_from_slice(b"\r\n--BOUND--\r\n");
        let body = Bytes::from(body);
        let fields =
            parse_multipart(&body, "BOUND", &MultipartLimits::default(), wall_now()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].text().unwrap(), "val");
    }

    #[test]
    fn field_debug_clone() {
        let f = MultipartField {
            name: "n".into(),
            filename: Some("f.txt".into()),
            content_type: Some("text/plain".into()),
            headers: HashMap::new(),
            body: Bytes::from(b"hi".to_vec()),
        };
        let dbg = format!("{f:?}");
        assert!(dbg.contains("MultipartField"));
    }

    #[test]
    fn multipart_debug_clone() {
        let mp = Multipart { fields: vec![] };
        let dbg = format!("{mp:?}");
        assert!(dbg.contains("Multipart"));
    }

    // ================================================================
    // Timeout tests
    // ================================================================

    #[test]
    fn timeout_limits_configuration() {
        let limits = MultipartLimits::new()
            .request_timeout_secs(60)
            .idle_timeout_secs(10);

        assert_eq!(limits.request_timeout_secs, 60);
        assert_eq!(limits.idle_timeout_secs, 10);
    }

    #[test]
    fn timeout_check_succeeds_within_limits() {
        let limits = MultipartLimits::new()
            .request_timeout_secs(60)
            .idle_timeout_secs(10);

        let start = wall_now();
        let result = check_timeout(start, start, &limits);
        assert!(result.is_ok());
    }

    #[test]
    fn timeout_check_fails_when_request_timeout_exceeded() {
        let limits = MultipartLimits::new()
            .request_timeout_secs(0) // Set to 0 to trigger immediately
            .idle_timeout_secs(10);

        let start = Time::ZERO; // Very old timestamp
        let result = check_timeout(start, start, &limits);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, StatusCode::REQUEST_TIMEOUT);
        assert!(err.message.contains("multipart parsing timed out"));
    }

    #[test]
    fn timeout_check_fails_when_idle_timeout_exceeded() {
        let limits = MultipartLimits::new()
            .request_timeout_secs(60)
            .idle_timeout_secs(0); // Set to 0 to trigger immediately

        let start = wall_now();
        let old_progress = Time::ZERO; // Very old timestamp
        let result = check_timeout(start, old_progress, &limits);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, StatusCode::REQUEST_TIMEOUT);
        assert!(err.message.contains("multipart parsing idle"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn assert_streamed_field_parity(actual: &[MultipartField], expected: &[MultipartField]) {
        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(expected) {
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.filename, expected.filename);
            assert_eq!(actual.content_type, expected.content_type);
            assert_eq!(actual.headers, expected.headers);
            assert_eq!(actual.body.as_ref(), expected.body.as_ref());
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn assert_streaming_decoder_retention(decoder: &StreamingMultipartDecoder) {
        match decoder.phase {
            StreamingMultipartPhase::Preamble | StreamingMultipartPhase::Body => assert!(
                decoder.buffer.len() <= decoder.delimiter.len() + 3,
                "rolling delimiter scratch retained {} bytes",
                decoder.buffer.len()
            ),
            StreamingMultipartPhase::Headers => assert!(
                decoder.buffer.len() <= decoder.limits.max_part_headers.saturating_add(3),
                "header scratch retained {} bytes",
                decoder.buffer.len()
            ),
            StreamingMultipartPhase::Done => assert!(decoder.buffer.is_empty()),
        }
        assert!(decoder.current_body.len() <= decoder.limits.max_part_body_size);
        let completed_body_bytes: usize = decoder.fields.iter().map(|field| field.body.len()).sum();
        assert!(completed_body_bytes <= decoder.total_received);
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn decode_streaming_multipart(
        body: &[u8],
        boundary: &str,
        limits: MultipartLimits,
        split: usize,
    ) -> Result<Vec<MultipartField>, ExtractionError> {
        let mut decoder = StreamingMultipartDecoder::new(boundary, limits, Some(body.len()))?;
        decoder.feed(&body[..split])?;
        decoder.feed(&body[split..])?;
        decoder.finish()
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_decoder_matches_buffered_parser_at_every_split() {
        let boundary = "STREAM-BOUNDARY";
        let mut body = b"ignored preamble\r\n".to_vec();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(b"alpha\r\n--STREAM-BOUNDARYX remains payload");
        body.extend_from_slice(
            format!(
                "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename*=UTF-8''%e2%82%ac.txt\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(&[0, 1, 2, 0xff]);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\nepilogue").as_bytes());

        let bytes = Bytes::from(body.clone());
        let expected = parse_multipart(&bytes, boundary, &MultipartLimits::default(), wall_now())
            .expect("buffered multipart corpus");

        for split in 0..=body.len() {
            let actual =
                decode_streaming_multipart(&body, boundary, MultipartLimits::default(), split)
                    .unwrap_or_else(|error| panic!("split {split} failed: {error:?}"));
            assert_streamed_field_parity(&actual, &expected);
        }

        let mut bytewise =
            StreamingMultipartDecoder::new(boundary, MultipartLimits::default(), Some(body.len()))
                .expect("bytewise decoder");
        for byte in &body {
            bytewise.feed(std::slice::from_ref(byte)).unwrap();
        }
        let actual = bytewise.finish().expect("bytewise multipart corpus");
        assert_streamed_field_parity(&actual, &expected);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_decoder_preserves_false_candidates_and_bare_cr_compatibility() {
        let false_candidate_body = b"preamble x--B--not-initial\r\n--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nline x--B--not-closing\r\n--BX\r\n--B-\nend\r\n--B--";
        let false_candidate_bytes = Bytes::copy_from_slice(false_candidate_body);
        let expected = parse_multipart(
            &false_candidate_bytes,
            "B",
            &MultipartLimits::default(),
            wall_now(),
        )
        .expect("buffered false-candidate corpus");
        for split in 0..=false_candidate_body.len() {
            let actual = decode_streaming_multipart(
                false_candidate_body,
                "B",
                MultipartLimits::default(),
                split,
            )
            .unwrap_or_else(|error| panic!("false-candidate split {split}: {error:?}"));
            assert_streamed_field_parity(&actual, &expected);
        }
        let mut decoder = StreamingMultipartDecoder::new(
            "B",
            MultipartLimits::default(),
            Some(false_candidate_body.len()),
        )
        .unwrap();
        for byte in false_candidate_body {
            decoder.feed(std::slice::from_ref(byte)).unwrap();
            assert_streaming_decoder_retention(&decoder);
        }
        let actual = decoder.finish().expect("streamed false candidates");
        assert_streamed_field_parity(&actual, &expected);
        assert_eq!(
            actual[0].body.as_ref(),
            b"line x--B--not-closing\r\n--BX\r\n--B-\nend"
        );

        let bare_cr_body = b"--B\rContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n--B--";
        let bare_cr_bytes = Bytes::copy_from_slice(bare_cr_body);
        let expected =
            parse_multipart(&bare_cr_bytes, "B", &MultipartLimits::default(), wall_now())
                .expect("buffered bare-CR corpus");
        let mut decoder = StreamingMultipartDecoder::new(
            "B",
            MultipartLimits::default(),
            Some(bare_cr_body.len()),
        )
        .unwrap();
        for byte in bare_cr_body {
            decoder.feed(std::slice::from_ref(byte)).unwrap();
        }
        let actual = decoder.finish().expect("streamed bare-CR corpus");
        assert_streamed_field_parity(&actual, &expected);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_decoder_many_parts_is_segmentation_independent_under_tight_total_cap() {
        let mut body = Vec::new();
        for index in 0..64 {
            body.extend_from_slice(
                format!("--B\r\nContent-Disposition: form-data; name=\"f{index}\"\r\n\r\nx\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(b"--B--");
        let limits = MultipartLimits::new()
            .max_total_size(body.len())
            .max_parts(64);

        let mut one_frame = StreamingMultipartDecoder::new("B", limits, Some(body.len())).unwrap();
        one_frame.feed(&body).expect("single-frame many-parts body");
        assert_streaming_decoder_retention(&one_frame);
        let one_frame = one_frame.finish().expect("single-frame many-parts EOF");

        let mut fragmented = StreamingMultipartDecoder::new("B", limits, Some(body.len())).unwrap();
        for byte in &body {
            fragmented.feed(std::slice::from_ref(byte)).unwrap();
            assert_streaming_decoder_retention(&fragmented);
        }
        let fragmented = fragmented.finish().expect("fragmented many-parts EOF");
        assert_streamed_field_parity(&one_frame, &fragmented);
        assert_eq!(one_frame.len(), 64);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_decoder_refuses_truncation_and_each_logical_limit() {
        let cases: &[(&[u8], &str)] = &[
            (b"preamble", "missing initial boundary"),
            (
                b"--B\r\nContent-Disposition: form-data",
                "missing header terminator",
            ),
            (
                b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nbody",
                "missing closing boundary",
            ),
        ];
        for (body, message) in cases {
            let mut decoder =
                StreamingMultipartDecoder::new("B", MultipartLimits::default(), None).unwrap();
            decoder.feed(body).unwrap();
            let error = decoder.finish().expect_err("truncated multipart");
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert!(error.message.contains(message), "{error:?}");
        }

        let body = b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1234\r\n--B\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n2\r\n--B--";

        let mut total = StreamingMultipartDecoder::new(
            "B",
            MultipartLimits::new().max_total_size(body.len() - 1),
            None,
        )
        .unwrap();
        let error = total.feed(body).expect_err("total limit");
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);

        let mut headers =
            StreamingMultipartDecoder::new("B", MultipartLimits::new().max_part_headers(8), None)
                .unwrap();
        let error = headers.feed(body).expect_err("header limit");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.contains("headers too large"));

        let mut part =
            StreamingMultipartDecoder::new("B", MultipartLimits::new().max_part_body_size(3), None)
                .unwrap();
        let error = part.feed(body).expect_err("part limit");
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(error.message.contains("part body too large"));

        let mut count =
            StreamingMultipartDecoder::new("B", MultipartLimits::new().max_parts(1), None).unwrap();
        let error = count.feed(body).expect_err("part count");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.contains("too many multipart parts"));

        let mut length =
            StreamingMultipartDecoder::new("B", MultipartLimits::default(), Some(body.len() + 1))
                .unwrap();
        length.feed(body).unwrap();
        let error = length.finish().expect_err("request length mismatch");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.contains("Content-Length mismatch"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn multipart_block_on<F: std::future::Future>(future: F) -> F::Output {
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = std::task::Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        loop {
            match std::future::Future::poll(future.as_mut(), &mut task_cx) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn streaming_multipart_request(
        cx: &Cx,
        kind: crate::http::h1::stream::BodyKind,
        limits: MultipartLimits,
    ) -> (
        crate::http::h1::stream::IncomingRequestBodyWriter,
        Request,
        crate::web::extract::StreamingRawBodyControl,
    ) {
        let (writer, body) = crate::http::h1::stream::IncomingRequestBody::channel(cx, kind);
        let mut req = Request::new("POST", "/multipart")
            .with_header("content-type", "multipart/form-data; boundary=B");
        if let crate::http::h1::stream::BodyKind::ContentLength(length) = kind {
            req = req.with_header("content-length", length.to_string());
        }
        req.extensions.insert_typed(limits);
        let control = crate::web::extract::insert_streaming_raw_body(&mut req, body)
            .expect("install streamed multipart body");
        (writer, req, control)
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_multipart_refuses_metadata_before_body_ownership_and_observes_cancellation() {
        use crate::http::h1::stream::BodyKind;
        use crate::types::CancelKind;

        let cx = Cx::for_testing();
        let (writer, req, control) = streaming_multipart_request(
            &cx,
            BodyKind::ContentLength(128),
            MultipartLimits::new().max_total_size(64),
        );
        let error = multipart_block_on(Multipart::from_request_with_cx(&cx, req))
            .expect_err("declared multipart length must fail before body take");
        assert_eq!(error.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!writer.consumer_dropped());
        drop(control);
        assert!(writer.consumer_dropped());

        for (content_type, expected_status) in [
            (None, StatusCode::UNSUPPORTED_MEDIA_TYPE),
            (Some("text/plain"), StatusCode::UNSUPPORTED_MEDIA_TYPE),
            (
                Some("multipart/form-data; boundary="),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let metadata_cx = Cx::for_testing();
            let (metadata_writer, mut req, metadata_control) = streaming_multipart_request(
                &metadata_cx,
                BodyKind::ContentLength(1),
                MultipartLimits::default(),
            );
            req.headers.remove("content-type");
            if let Some(content_type) = content_type {
                req.headers
                    .insert("content-type".to_owned(), content_type.to_owned());
            }
            let error = multipart_block_on(Multipart::from_request_with_cx(&metadata_cx, req))
                .expect_err("invalid multipart metadata must fail before body take");
            assert_eq!(error.status, expected_status);
            assert!(!metadata_writer.consumer_dropped());
            drop(metadata_control);
            assert!(metadata_writer.consumer_dropped());
        }

        let eof_cx = Cx::for_testing();
        let (mut eof_writer, eof_req, eof_control) =
            streaming_multipart_request(&eof_cx, BodyKind::Chunked, MultipartLimits::default());
        let mut extraction = std::pin::pin!(Multipart::from_request_with_cx(&eof_cx, eof_req));
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = std::task::Context::from_waker(&waker);
        assert!(matches!(
            std::future::Future::poll(extraction.as_mut(), &mut task_cx),
            std::task::Poll::Pending
        ));
        let multipart_body = b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n--B--";
        let mut transfer_chunk = format!("{:X}\r\n", multipart_body.len()).into_bytes();
        transfer_chunk.extend_from_slice(multipart_body);
        transfer_chunk.extend_from_slice(b"\r\n");
        multipart_block_on(eof_writer.push_bytes(&eof_cx, &transfer_chunk))
            .expect("publish complete multipart before request EOF");
        assert!(matches!(
            std::future::Future::poll(extraction.as_mut(), &mut task_cx),
            std::task::Poll::Pending
        ));
        multipart_block_on(eof_writer.push_bytes(&eof_cx, b"0\r\n\r\n"))
            .expect("publish request EOF");
        let std::task::Poll::Ready(Ok(extracted)) =
            std::future::Future::poll(extraction.as_mut(), &mut task_cx)
        else {
            panic!("multipart extraction must complete after request EOF");
        };
        assert_eq!(extracted.field("f").unwrap().body.as_ref(), b"v");
        drop(extraction);
        drop(eof_control);

        let cancelled_cx = Cx::for_testing();
        let (mut writer, req, control) = streaming_multipart_request(
            &cancelled_cx,
            BodyKind::ContentLength(64),
            MultipartLimits::default(),
        );
        let mut extraction = std::pin::pin!(Multipart::from_request_with_cx(&cancelled_cx, req));
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = std::task::Context::from_waker(&waker);
        assert!(matches!(
            std::future::Future::poll(extraction.as_mut(), &mut task_cx),
            std::task::Poll::Pending
        ));
        cancelled_cx.cancel_fast(CancelKind::Deadline);
        let std::task::Poll::Ready(Err(error)) =
            std::future::Future::poll(extraction.as_mut(), &mut task_cx)
        else {
            panic!("cancelled multipart extraction must terminate");
        };
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            error.message,
            "[ASUP-E501] multipart request body unavailable"
        );
        drop(extraction);
        drop(control);
        assert_eq!(
            multipart_block_on(writer.push_bytes(&cancelled_cx, b"x")),
            Err(IncomingBodyError::Cancelled {
                kind: CancelKind::Deadline,
            })
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn transfer_chunk(data: &[u8]) -> Vec<u8> {
        let mut encoded = format!("{:X}\r\n", data.len()).into_bytes();
        encoded.extend_from_slice(data);
        encoded.extend_from_slice(b"\r\n");
        encoded
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_field_api_yields_metadata_and_bounded_chunks_before_transport_eof() {
        use crate::http::h1::stream::BodyKind;

        let cx = Cx::for_testing();
        let (mut writer, req, control) =
            streaming_multipart_request(&cx, BodyKind::Chunked, MultipartLimits::default());
        let mut multipart = StreamingMultipart::from_request(req).expect("streaming extractor");

        let head = b"--B\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"../safe.bin\"\r\nContent-Type: application/octet-stream\r\nX-Part: yes\r\n\r\n";
        multipart_block_on(writer.push_bytes(&cx, &transfer_chunk(head)))
            .expect("publish field metadata without payload");

        let mut field = multipart_block_on(multipart.next_field(&cx))
            .expect("field metadata")
            .expect("first field");
        assert_eq!(field.name(), "upload");
        assert_eq!(field.filename(), Some("safe.bin"));
        assert_eq!(field.content_type(), Some("application/octet-stream"));
        assert_eq!(
            field.headers().get("x-part").map(String::as_str),
            Some("yes")
        );

        let payload = (0..10_000)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        let mut tail = payload.clone();
        tail.extend_from_slice(b"\r\n--B--\r\nepilogue");
        multipart_block_on(writer.push_bytes(&cx, &transfer_chunk(&tail)))
            .expect("publish field payload and MIME close");

        let mut actual = Vec::new();
        while let Some(chunk) = multipart_block_on(field.next_chunk(&cx)).expect("field chunk") {
            assert!(
                chunk.len() <= StreamingMultipart::INPUT_WINDOW,
                "field chunk retained {} bytes",
                chunk.len()
            );
            actual.extend_from_slice(chunk.as_ref());
        }
        assert_eq!(actual, payload);
        drop(field);

        let mut terminal = std::pin::pin!(multipart.next_field(&cx));
        let waker = std::task::Waker::noop().clone();
        let mut task_cx = std::task::Context::from_waker(&waker);
        assert!(matches!(
            std::future::Future::poll(terminal.as_mut(), &mut task_cx),
            std::task::Poll::Pending
        ));
        multipart_block_on(writer.push_bytes(&cx, b"0\r\n\r\n")).expect("publish HTTP body EOF");
        assert!(matches!(
            std::future::Future::poll(terminal.as_mut(), &mut task_cx),
            std::task::Poll::Ready(Ok(None))
        ));
        drop(terminal);
        drop(control);
        assert!(!writer.consumer_dropped());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_field_api_is_exact_across_every_wire_split() {
        use crate::http::h1::stream::BodyKind;

        let body = b"preamble x--B--not-a-boundary\r\n--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nalpha x--B--payload\r\n--B\r\nContent-Disposition: form-data; name=\"b\"; filename=\"C:\\tmp\\b.txt\"\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nbeta\r\n--B--\r\nepilogue";

        for split in 0..=body.len() {
            let cx = Cx::for_testing();
            let (mut writer, req, control) = streaming_multipart_request(
                &cx,
                BodyKind::ContentLength(u64::try_from(body.len()).unwrap()),
                MultipartLimits::default(),
            );
            let mut multipart = StreamingMultipart::from_request(req).expect("streaming extractor");
            multipart_block_on(writer.push_bytes(&cx, &body[..split]))
                .unwrap_or_else(|error| panic!("split {split} prefix: {error:?}"));
            multipart_block_on(writer.push_bytes(&cx, &body[split..]))
                .unwrap_or_else(|error| panic!("split {split} suffix: {error:?}"));

            let mut fields = Vec::new();
            while let Some(mut field) = multipart_block_on(multipart.next_field(&cx))
                .unwrap_or_else(|error| panic!("split {split} field: {error:?}"))
            {
                let metadata = (
                    field.name().to_owned(),
                    field.filename().map(str::to_owned),
                    field.content_type().map(str::to_owned),
                );
                let mut bytes = Vec::new();
                while let Some(chunk) = multipart_block_on(field.next_chunk(&cx))
                    .unwrap_or_else(|error| panic!("split {split} chunk: {error:?}"))
                {
                    assert!(chunk.len() <= StreamingMultipart::INPUT_WINDOW);
                    bytes.extend_from_slice(chunk.as_ref());
                }
                fields.push((metadata, bytes));
            }

            assert_eq!(fields.len(), 2, "split {split}");
            assert_eq!(fields[0].0, ("a".to_owned(), None, None), "split {split}");
            assert_eq!(fields[0].1, b"alpha x--B--payload", "split {split}");
            assert_eq!(
                fields[1].0,
                (
                    "b".to_owned(),
                    Some("tmpb.txt".to_owned()),
                    Some("text/plain".to_owned())
                ),
                "split {split}"
            );
            assert_eq!(fields[1].1, b"beta", "split {split}");
            drop(control);
            assert!(!writer.consumer_dropped(), "split {split}");
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn streaming_field_drop_and_forgotten_lease_fail_closed() {
        use crate::http::h1::stream::BodyKind;

        let cx = Cx::for_testing();
        let (mut writer, req, control) =
            streaming_multipart_request(&cx, BodyKind::Chunked, MultipartLimits::default());
        let mut multipart = StreamingMultipart::from_request(req).expect("streaming extractor");
        let mut first_chunk = b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n".to_vec();
        first_chunk.extend(std::iter::repeat_n(b'x', 128));
        multipart_block_on(writer.push_bytes(&cx, &transfer_chunk(&first_chunk)))
            .expect("publish partial field");
        let mut field = multipart_block_on(multipart.next_field(&cx))
            .expect("field metadata")
            .expect("first field");
        assert!(
            multipart_block_on(field.next_chunk(&cx))
                .expect("first body chunk")
                .is_some()
        );
        drop(field);
        assert!(writer.consumer_dropped());
        let error = multipart_block_on(multipart.next_field(&cx))
            .expect_err("abandoned field must terminalize parser");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error.kind(), StreamingMultipartErrorKind::AbandonedField);
        assert!(
            multipart
                .retention_snapshot()
                .incoming_queue_bytes_peak
                .is_none(),
            "abandonment drops the live incoming-queue observer"
        );
        assert!(
            multipart
                .retention_snapshot()
                .incoming_queue_frames_peak
                .is_none(),
            "abandonment drops the live incoming-frame observer"
        );
        drop(control);

        let forgotten_cx = Cx::for_testing();
        let (mut forgotten_writer, forgotten_req, forgotten_control) = streaming_multipart_request(
            &forgotten_cx,
            BodyKind::Chunked,
            MultipartLimits::default(),
        );
        let mut forgotten =
            StreamingMultipart::from_request(forgotten_req).expect("streaming extractor");
        let metadata = b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n";
        multipart_block_on(forgotten_writer.push_bytes(&forgotten_cx, &transfer_chunk(metadata)))
            .expect("publish metadata");
        let field = multipart_block_on(forgotten.next_field(&forgotten_cx))
            .expect("field metadata")
            .expect("first field");
        std::mem::forget(field);
        let error = multipart_block_on(forgotten.next_field(&forgotten_cx))
            .expect_err("forgotten lease must fail closed");
        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.kind(), StreamingMultipartErrorKind::AbandonedField);
        assert!(error.message().contains("forgotten"));
        assert!(forgotten_writer.consumer_dropped());
        assert!(
            forgotten
                .retention_snapshot()
                .incoming_queue_bytes_peak
                .is_none(),
            "forgotten field lease drops the live incoming-queue observer"
        );
        assert!(
            forgotten
                .retention_snapshot()
                .incoming_queue_frames_peak
                .is_none(),
            "forgotten field lease drops the live incoming-frame observer"
        );
        drop(forgotten_control);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn body_diagnostic_streaming_field_limits_and_cancellation_keep_typed_statuses() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Wake, Waker};

        use crate::http::h1::stream::BodyKind;
        use crate::types::CancelKind;

        let limit_cx = Cx::for_testing();
        let body = b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n1234\r\n--B--";
        let (mut limit_writer, limit_req, limit_control) = streaming_multipart_request(
            &limit_cx,
            BodyKind::ContentLength(u64::try_from(body.len()).unwrap()),
            MultipartLimits::new().max_part_body_size(3),
        );
        let mut limited = StreamingMultipart::from_request(limit_req).expect("streaming extractor");
        multipart_block_on(limit_writer.push_bytes(&limit_cx, body)).expect("publish body");
        let mut field = multipart_block_on(limited.next_field(&limit_cx))
            .expect("field metadata")
            .expect("first field");
        let error = multipart_block_on(field.next_chunk(&limit_cx))
            .expect_err("part limit must fail during delivery");
        assert_eq!(error.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(error.kind(), StreamingMultipartErrorKind::PayloadTooLarge);
        assert_eq!(error.code(), "ASUP-E504");
        assert_eq!(error.diagnostic_code(), "ASUP-E506");
        assert!(error.to_string().starts_with("[ASUP-E504] 413 "));
        let response = crate::web::response::IntoResponse::into_response(error.clone());
        assert!(response.body.starts_with(b"[ASUP-E506] "));
        drop(field);
        drop(limit_control);

        let metadata_cx = Cx::for_testing();
        let (metadata_writer, mut req, metadata_control) = streaming_multipart_request(
            &metadata_cx,
            BodyKind::Chunked,
            MultipartLimits::default(),
        );
        req.headers
            .insert("content-type".to_owned(), "text/plain".to_owned());
        let error = StreamingMultipart::from_request(req)
            .expect_err("wrong media type must fail before body ownership");
        assert_eq!(error.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            error.kind(),
            StreamingMultipartErrorKind::UnsupportedMediaType
        );
        assert_eq!(error.diagnostic_code(), "ASUP-E507");
        assert!(error.to_string().starts_with("[ASUP-E504] 415 "));
        let response = crate::web::response::IntoResponse::into_response(error.clone());
        assert!(response.body.starts_with(b"[ASUP-E507] "));
        assert!(!metadata_writer.consumer_dropped());
        drop(metadata_control);
        assert!(metadata_writer.consumer_dropped());

        struct CountWake(AtomicUsize);
        impl Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let body_cx = Cx::for_testing();
        let handler_cx = Cx::for_testing();
        let (cancel_writer, cancel_req, cancel_control) =
            streaming_multipart_request(&body_cx, BodyKind::Chunked, MultipartLimits::default());
        let mut cancelled =
            StreamingMultipart::from_request(cancel_req).expect("streaming extractor");
        let wake_count = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wake_count));
        let mut task_cx = std::task::Context::from_waker(&waker);
        let mut next = std::pin::pin!(cancelled.next_field(&handler_cx));
        assert!(matches!(
            std::future::Future::poll(next.as_mut(), &mut task_cx),
            std::task::Poll::Pending
        ));
        handler_cx.cancel_fast(CancelKind::Deadline);
        assert!(wake_count.0.load(Ordering::SeqCst) > 0);
        let std::task::Poll::Ready(Err(error)) =
            std::future::Future::poll(next.as_mut(), &mut task_cx)
        else {
            panic!("external handler cancellation must wake the pending body read");
        };
        assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.kind(), StreamingMultipartErrorKind::Cancelled);
        assert_eq!(error.cancel_kind(), Some(CancelKind::Deadline));
        assert_eq!(error.diagnostic_code(), "ASUP-E501");
        assert!(error.to_string().starts_with("[ASUP-E504] 503 "));
        let response = crate::web::response::IntoResponse::into_response(error.clone());
        assert!(response.body.starts_with(b"[ASUP-E501] "));
        drop(next);
        assert!(cancel_writer.consumer_dropped());
        drop(cancel_control);

        let disconnected =
            StreamingMultipartError::from_body_error(IncomingBodyError::SourceDisconnected);
        assert_eq!(disconnected.kind(), StreamingMultipartErrorKind::Internal);
        assert_eq!(disconnected.cancel_kind(), None);
        assert_eq!(disconnected.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(disconnected.diagnostic_code(), "ASUP-E504");
        assert!(disconnected.to_string().starts_with("[ASUP-E504] 500 "));
        let disconnected_response =
            crate::web::response::IntoResponse::into_response(disconnected.clone());
        assert_eq!(
            disconnected_response.body.as_ref(),
            disconnected.to_string().as_bytes()
        );
        let aborted = StreamingMultipartError::from_body_error(IncomingBodyError::ClientAborted);
        assert_eq!(aborted.diagnostic_code(), "ASUP-E509");
        assert!(aborted.to_string().starts_with("[ASUP-E504] 499 "));
        let aborted_response = crate::web::response::IntoResponse::into_response(aborted.clone());
        assert!(aborted_response.body.starts_with(b"[ASUP-E509] "));
        let consumer_dropped =
            StreamingMultipartError::from_body_error(IncomingBodyError::ConsumerDropped);
        assert_eq!(
            consumer_dropped.kind(),
            StreamingMultipartErrorKind::AbandonedField
        );
        let consumer_dropped_response =
            crate::web::response::IntoResponse::into_response(consumer_dropped.clone());
        assert_eq!(
            consumer_dropped_response.body.as_ref(),
            consumer_dropped.to_string().as_bytes()
        );
        let drain_failed =
            StreamingMultipartError::from_body_error(IncomingBodyError::DrainTimeout);
        assert_eq!(drain_failed.kind(), StreamingMultipartErrorKind::Timeout);
        assert_eq!(drain_failed.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(drain_failed.diagnostic_code(), "ASUP-E508");
    }
}
