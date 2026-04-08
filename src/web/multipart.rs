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

use super::extract::{ExtractionError, FromRequest, Request};
use super::response::StatusCode;
use crate::bytes::Bytes;

/// Default maximum multipart body size (16 MiB).
const DEFAULT_MAX_MULTIPART_SIZE: usize = 16 * 1024 * 1024;

/// Default maximum number of parts to prevent abuse.
const DEFAULT_MAX_PARTS: usize = 1024;

/// Default maximum header section size per part (8 KiB).
const DEFAULT_MAX_PART_HEADERS: usize = 8 * 1024;

/// Default maximum part body size (8 MiB).
const DEFAULT_MAX_PART_BODY_SIZE: usize = 8 * 1024 * 1024;

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
}

impl Default for MultipartLimits {
    fn default() -> Self {
        Self {
            max_total_size: DEFAULT_MAX_MULTIPART_SIZE,
            max_parts: DEFAULT_MAX_PARTS,
            max_part_headers: DEFAULT_MAX_PART_HEADERS,
            max_part_body_size: DEFAULT_MAX_PART_BODY_SIZE,
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

        if !content_type
            .to_ascii_lowercase()
            .contains("multipart/form-data")
        {
            return Err(ExtractionError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("expected multipart/form-data, got: {content_type}"),
            ));
        }

        let boundary = extract_boundary(&content_type).ok_or_else(|| {
            ExtractionError::bad_request("missing or invalid boundary in Content-Type")
        })?;

        let fields = parse_multipart(&req.body, &boundary, &limits)?;

        Ok(Self { fields })
    }
}

// ─── Parsing ────────────────────────────────────────────────────────────────

/// Extract the boundary parameter from a Content-Type header value.
fn extract_boundary(content_type: &str) -> Option<String> {
    // Look for boundary=... (possibly quoted)
    let lower = content_type.to_ascii_lowercase();
    let idx = lower.find("boundary=")?;
    let after = &content_type[idx + "boundary=".len()..];

    if let Some(stripped) = after.strip_prefix('"') {
        // Quoted boundary
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        // Unquoted — take until whitespace or semicolon
        let end = after
            .find([';', ' ', '\t', '\r', '\n'])
            .unwrap_or(after.len());
        let b = after[..end].trim();
        if b.is_empty() {
            None
        } else {
            Some(b.to_string())
        }
    }
}

/// Parse multipart body given a boundary string.
fn parse_multipart(
    body: &Bytes,
    boundary: &str,
    limits: &MultipartLimits,
) -> Result<Vec<MultipartField>, ExtractionError> {
    let delimiter = format!("--{boundary}");
    let delimiter_bytes = delimiter.as_bytes();
    let close_delimiter = format!("--{boundary}--");
    let close_bytes = close_delimiter.as_bytes();

    let mut fields = Vec::new();
    let mut pos = 0;

    // Skip preamble: advance to first delimiter.
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

        let headers_section = &body[pos..headers_end.0];
        if headers_section.len() > limits.max_part_headers {
            return Err(ExtractionError::bad_request(
                "multipart part headers too large",
            ));
        }

        let part_headers = parse_part_headers(headers_section);

        // Body starts after the blank line.
        let body_start = headers_end.1;

        // Find next delimiter.
        let next_delim =
            find_multipart_delimiter(body, delimiter_bytes, body_start).ok_or_else(|| {
                ExtractionError::bad_request("multipart part missing closing boundary")
            })?;

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

        // Parse Content-Disposition for name and filename.
        let disposition = part_headers
            .get("content-disposition")
            .cloned()
            .unwrap_or_default();

        let name = parse_disposition_param(&disposition, "name").unwrap_or_default();
        let filename = parse_disposition_param(&disposition, "filename");
        let content_type = part_headers.get("content-type").cloned();

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
fn find_blank_line(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let search = &data[pos..];
    // Try CRLFCRLF first.
    if let Some(idx) = search.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((pos + idx, pos + idx + 4));
    }
    // Fall back to LFLF.
    if let Some(idx) = search.windows(2).position(|w| w == b"\n\n") {
        return Some((pos + idx, pos + idx + 2));
    }
    None
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
fn parse_part_headers(data: &[u8]) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    let Ok(text) = std::str::from_utf8(data) else {
        return headers;
    };
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    headers
}

/// Parse a parameter from a Content-Disposition header value.
///
/// Handles both quoted and unquoted values:
/// - `form-data; name="field1"`
/// - `form-data; name=field1`
fn parse_disposition_param(disposition: &str, param: &str) -> Option<String> {
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
            start = abs + 1;
        }
    };
    let after = &disposition[idx + search.len()..];

    after.strip_prefix('"').map_or_else(
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
    )
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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
        let hdrs = parse_part_headers(raw);
        assert_eq!(hdrs.len(), 2);
        assert!(hdrs.get("content-disposition").unwrap().contains("name="));
        assert_eq!(hdrs.get("content-type").unwrap(), "image/png");
    }

    #[test]
    fn parse_headers_empty() {
        let hdrs = parse_part_headers(b"");
        assert!(hdrs.is_empty());
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

    #[test]
    fn parse_single_text_field() {
        let body = make_multipart_body(
            "BOUNDARY",
            &[(
                "Content-Disposition: form-data; name=\"username\"",
                b"alice",
            )],
        );
        let fields = parse_multipart(&body, "BOUNDARY", &MultipartLimits::default()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name(), "username");
        assert_eq!(fields[0].text().unwrap(), "alice");
        assert!(fields[0].filename().is_none());
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

        let fields = parse_multipart(&body, "BOUNDARY", &MultipartLimits::default()).unwrap();

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].body().as_ref(), b"alice");
        assert_eq!(fields[0].body().as_ptr(), body[expected_offset..].as_ptr());
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
        let fields = parse_multipart(&body, "B", &MultipartLimits::default()).unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].name(), "a");
        assert_eq!(fields[1].name(), "b");
        assert_eq!(fields[2].name(), "c");
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

        let fields = parse_multipart(&body, "BOUNDARY", &MultipartLimits::default()).unwrap();

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name(), "payload");
        assert_eq!(fields[0].body().as_ref(), b"value--BOUNDARYstill-body");
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
        let fields = parse_multipart(&body, "X", &MultipartLimits::default()).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name(), "doc");
        assert_eq!(fields[0].filename().unwrap(), "readme.txt");
        assert_eq!(fields[0].content_type().unwrap(), "text/plain");
        assert_eq!(fields[0].text().unwrap(), "Hello, world!");
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
        let fields = parse_multipart(&body, "BIN", &MultipartLimits::default()).unwrap();
        assert_eq!(fields[0].body().as_ref(), &binary[..]);
        assert!(fields[0].text().is_err()); // Not valid UTF-8.
    }

    #[test]
    fn parse_empty_body_field() {
        let body = make_multipart_body(
            "E",
            &[("Content-Disposition: form-data; name=\"empty\"", b"")],
        );
        let fields = parse_multipart(&body, "E", &MultipartLimits::default()).unwrap();
        assert_eq!(fields.len(), 1);
        assert!(fields[0].body().is_empty());
    }

    #[test]
    fn parse_missing_boundary_error() {
        let result = parse_multipart(
            &Bytes::from_static(b"no boundary here"),
            "MISSING",
            &MultipartLimits::default(),
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
    fn from_request_wrong_content_type() {
        let mut req = Request::new("POST", "/upload");
        req.headers
            .insert("content-type".to_string(), "application/json".to_string());
        req.body = Bytes::from(vec![]);

        let err = Multipart::from_request(req).unwrap_err();
        assert_eq!(err.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
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
        let fields = parse_multipart(&body, "F", &MultipartLimits::default()).unwrap();
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
        let fields = parse_multipart(&body, "R", &MultipartLimits::default()).unwrap();
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
        let fields = parse_multipart(&body, "I", &MultipartLimits::default()).unwrap();
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
        let fields = parse_multipart(&body, "B", &MultipartLimits::default()).unwrap();
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
        let fields = parse_multipart(&body, "BOUND", &MultipartLimits::default()).unwrap();
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
}
