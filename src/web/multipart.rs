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

use super::extract::{
    ExtractionError, FromRequest, Request, header_value_ci, parse_content_length,
};
use super::response::StatusCode;
use crate::bytes::Bytes;
use crate::time::wall_now;
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
#[derive(Debug, Clone, Copy)]
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
        let limits = req
            .extensions
            .get_typed::<MultipartLimits>()
            .copied()
            .unwrap_or_default();

        check_request_content_length_limit(&req, limits.max_total_size)?;

        // Size check.
        if req.body.len() > limits.max_total_size {
            return Err(ExtractionError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "multipart body too large: {} bytes (max {})",
                    req.body.len(),
                    limits.max_total_size
                ),
            ));
        }

        validate_request_content_length(&req)?;

        // Content-Type validation and boundary extraction (case-insensitive lookup).
        let content_type = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v)
            .ok_or_else(|| {
                ExtractionError::new(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "missing Content-Type header",
                )
            })?
            .clone();

        if !is_multipart_form_data(&content_type) {
            return Err(ExtractionError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("expected multipart/form-data, got: {content_type}"),
            ));
        }

        let boundary = extract_boundary(&content_type).ok_or_else(|| {
            ExtractionError::bad_request("missing or invalid boundary in Content-Type")
        })?;

        let parse_start = wall_now();
        let fields = parse_multipart(&req.body, &boundary, &limits, parse_start)?;

        Ok(Self { fields })
    }
}

// ─── Parsing ────────────────────────────────────────────────────────────────

fn check_request_content_length_limit(req: &Request, limit: usize) -> Result<(), ExtractionError> {
    let Some(value) = header_value_ci(req, "content-length") else {
        return Ok(());
    };
    let declared_len = parse_content_length(value)?;
    if declared_len > limit {
        return Err(ExtractionError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("multipart Content-Length {declared_len} bytes exceeds limit {limit} bytes"),
        ));
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
        return Err(ExtractionError::new(
            StatusCode::BAD_REQUEST,
            format!(
                "multipart Content-Length mismatch: declared {declared_len} bytes, received {actual_len} bytes"
            ),
        ));
    }
    Ok(())
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
        return Err(ExtractionError::new(
            StatusCode::REQUEST_TIMEOUT,
            format!(
                "multipart parsing timed out after {total_elapsed}ns (max {request_timeout}ns)"
            ),
        ));
    }

    if idle_timeout == 0 || idle_elapsed > idle_timeout {
        return Err(ExtractionError::new(
            StatusCode::REQUEST_TIMEOUT,
            format!("multipart parsing idle for {idle_elapsed}ns (max {idle_timeout}ns)"),
        ));
    }

    Ok(())
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
            return Err(ExtractionError::bad_request(
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
            return Err(ExtractionError::bad_request(format!(
                "too many multipart parts (max {})",
                limits.max_parts
            )));
        }

        // Check for close delimiter at current position (might have been found
        // as next delimiter in the previous iteration).
        // Find the end of this part's headers (blank line).
        let headers_end = find_blank_line(body, pos).ok_or_else(|| {
            ExtractionError::bad_request("multipart part missing header terminator")
        })?;
        last_progress = wall_now(); // Mark progress after finding headers

        let headers_section = &body[pos..headers_end.0];
        if headers_section.len() > limits.max_part_headers {
            return Err(ExtractionError::bad_request(
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
                ExtractionError::bad_request("multipart part missing closing boundary")
            })?;
        last_progress = wall_now(); // Mark progress after finding boundary

        // Part body ends before the CRLF preceding the delimiter.
        // If the client sent a malformed request where the boundary immediately follows
        // the header terminator, strip_trailing_crlf might strip the header's CRLF,
        // causing body_end < body_start. We clamp it to prevent a panic.
        let body_end = strip_trailing_crlf(body, next_delim).max(body_start);

        if body_end - body_start > limits.max_part_body_size {
            return Err(ExtractionError::new(
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
            return Err(ExtractionError::bad_request(
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
        ExtractionError::bad_request("multipart part headers contain invalid UTF-8")
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
    let Some(value) = headers.get("content-length") else {
        return Ok(());
    };

    let declared_len = value
        .parse::<usize>()
        .map_err(|_| ExtractionError::bad_request("multipart part content-length is invalid"))?;

    if declared_len != actual_len {
        return Err(ExtractionError::bad_request(format!(
            "multipart part content-length mismatch: declared {declared_len} bytes but parsed {actual_len} bytes"
        )));
    }

    Ok(())
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
        .filter(|c| !c.is_control() && !matches!(c, '?' | '*' | '"' | '<' | '>' | '|'))
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
        assert_eq!(err.message, "nested multipart parts are not supported");
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
        assert_eq!(err.message, "multipart part body too large");
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
}
