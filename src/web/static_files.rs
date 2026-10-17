//! Static file serving with caching, ETag, and conditional request support.
//!
//! Serves files from a directory with automatic MIME detection, strong ETags,
//! `Cache-Control` headers, and `If-None-Match` / `304 Not Modified` support.
//!
//! # Example
//!
//! ```
//! use asupersync::web::static_files::StaticFiles;
//! use asupersync::web::Router;
//!
//! // The handler resolves the request path against the root, so mount it
//! // where the router strips the prefix: `GET /static/app.js` serves
//! // `./public/app.js`.
//! let statics = StaticFiles::new("./public");
//! let app = Router::new().nest("/static", Router::new().fallback(statics.handler()));
//! ```
//!
//! # Security
//!
//! Path traversal attacks (`../`) are blocked. Symlinks are not followed by
//! default.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::bytes::Bytes;
use sha2::{Digest, Sha256};

use super::handler::Handler;
use super::response::{Response, StatusCode};

/// Default max-age for Cache-Control (1 hour).
const DEFAULT_MAX_AGE: u32 = 3600;

/// Default maximum file size to serve (256 MiB).
const DEFAULT_MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

const CONTENT_TYPE_OPTIONS_HEADER: &str = "x-content-type-options";
const CONTENT_TYPE_OPTIONS_NOSNIFF: &str = "nosniff";

/// A byte range for partial content requests.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ByteRange {
    start: usize,
    end: usize, // inclusive
}

/// Error types for Range header parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RangeError {
    InvalidSyntax,
    NotSatisfiable,
}

/// Maximum number of comma-separated range specs accepted in one `Range`
/// header. Without a cap, `Range: bytes=0-,0-,0-,…` (thousands of whole-file
/// prefix ranges packed into a header) forces `num_specs × file_size` bytes to
/// be buffered into one multipart body — the classic multi-range
/// memory-amplification DoS (CVE-2011-3192, "Apache Killer"). Real clients ask
/// for a handful of ranges; a request exceeding this cap is rejected.
const MAX_RANGE_SPECS: usize = 64;

/// Returns true if a path component is a hidden (dot-prefixed) name that must
/// not be served. `.well-known` is exempted (RFC 8615 / ACME discovery). Empty
/// components (from `//` or leading/trailing `/`) are not hidden.
fn is_denied_hidden_component(component: &str) -> bool {
    component.starts_with('.') && component != ".well-known"
}

/// Parse Range header and return satisfiable byte ranges.
/// RFC 9110 §14.1.2 Range specification.
///
/// Overlapping or adjacent satisfiable ranges are coalesced (RFC 9110 §14.1.2
/// permits, and §14.2 recommends, coalescing to bound the response), which
/// guarantees the total emitted bytes never exceed `file_size` regardless of
/// how many duplicate/overlapping specs the client sends.
fn parse_ranges(range_header: &str, file_size: u64) -> Result<Vec<ByteRange>, RangeError> {
    let range_header = range_header.trim();
    // Range units are case-insensitive (RFC 9110 section 14.1).
    let Some(ranges_str) = range_header
        .split_once('=')
        .and_then(|(unit, ranges)| unit.eq_ignore_ascii_case("bytes").then_some(ranges))
    else {
        return Err(RangeError::InvalidSyntax);
    };

    // Bound parse work and the eventual multipart part count before doing any
    // per-spec work. `bytes=` followed by N commas is N+1 specs.
    if ranges_str.bytes().filter(|&b| b == b',').count() >= MAX_RANGE_SPECS {
        return Err(RangeError::NotSatisfiable);
    }

    let mut ranges = Vec::new();

    for range_spec in ranges_str.split(',') {
        let range_spec = range_spec.trim();

        // Skip empty elements (from `,,` or a leading/trailing comma) rather
        // than rejecting the whole header — RFC 7230 §7's legacy list rule says
        // empty list elements do not contribute and must be ignored. A lenient
        // client sending `bytes=0-100,` should still get its range.
        if range_spec.is_empty() {
            continue;
        }

        if let Some((start_str, end_str)) = range_spec.split_once('-') {
            if start_str.is_empty() && end_str.is_empty() {
                return Err(RangeError::InvalidSyntax);
            }

            let range = if start_str.is_empty() {
                // Suffix range: bytes=-500 (last 500 bytes)
                if let Ok(suffix_length) = end_str.parse::<u64>() {
                    if suffix_length == 0 || file_size == 0 {
                        continue; // Skip invalid suffix ranges
                    }
                    let start = file_size.saturating_sub(suffix_length);
                    ByteRange {
                        start: start as usize,
                        end: (file_size - 1) as usize,
                    }
                } else {
                    return Err(RangeError::InvalidSyntax);
                }
            } else if end_str.is_empty() {
                // Prefix range: bytes=500- (from byte 500 to end)
                if let Ok(start) = start_str.parse::<u64>() {
                    if start >= file_size {
                        continue; // Skip ranges beyond file size
                    }
                    ByteRange {
                        start: start as usize,
                        end: (file_size - 1) as usize,
                    }
                } else {
                    return Err(RangeError::InvalidSyntax);
                }
            } else {
                // Full range: bytes=0-499
                let start = start_str
                    .parse::<u64>()
                    .map_err(|_| RangeError::InvalidSyntax)?;
                let end = end_str
                    .parse::<u64>()
                    .map_err(|_| RangeError::InvalidSyntax)?;

                if start > end || start >= file_size {
                    continue; // Skip invalid or unsatisfiable ranges
                }

                let actual_end = std::cmp::min(end, file_size - 1);
                ByteRange {
                    start: start as usize,
                    end: actual_end as usize,
                }
            };

            ranges.push(range);
        } else {
            return Err(RangeError::InvalidSyntax);
        }
    }

    if ranges.is_empty() {
        return Err(RangeError::NotSatisfiable);
    }

    // Coalesce overlapping/adjacent ranges so the emitted body is bounded by
    // `file_size`. Sorting by start makes a single linear merge sufficient.
    // This defeats amplification via duplicated/overlapping specs (e.g. many
    // `0-`) which would otherwise each re-emit the whole file.
    ranges.sort_by_key(|r| (r.start, r.end));
    let mut coalesced: Vec<ByteRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match coalesced.last_mut() {
            // Overlapping or directly adjacent (`prev.end + 1 == range.start`)
            // ranges merge into one contiguous slice.
            Some(prev) if range.start <= prev.end.saturating_add(1) => {
                prev.end = prev.end.max(range.end);
            }
            _ => coalesced.push(range),
        }
    }

    Ok(coalesced)
}

// ─── StaticFiles ────────────────────────────────────────────────────────────

/// Configuration for static file serving.
#[derive(Clone)]
pub struct StaticFiles {
    root: PathBuf,
    max_age: u32,
    max_file_size: u64,
    index_file: Option<String>,
    custom_headers: HashMap<String, String>,
}

impl fmt::Debug for StaticFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticFiles")
            .field("root", &self.root)
            .field("max_age", &self.max_age)
            .field("max_file_size", &self.max_file_size)
            .field("index_file", &self.index_file)
            .field("custom_headers", &self.custom_headers)
            .finish()
    }
}

impl StaticFiles {
    /// Create a new static file server rooted at the given directory.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let mut custom_headers = HashMap::new();
        custom_headers.insert(
            CONTENT_TYPE_OPTIONS_HEADER.to_string(),
            CONTENT_TYPE_OPTIONS_NOSNIFF.to_string(),
        );

        Self {
            root: root.into(),
            max_age: DEFAULT_MAX_AGE,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            index_file: Some("index.html".to_string()),
            custom_headers,
        }
    }

    /// Set the `Cache-Control: max-age` value in seconds.
    #[must_use]
    pub fn max_age(mut self, seconds: u32) -> Self {
        self.max_age = seconds;
        self
    }

    /// Set the maximum file size to serve in bytes.
    ///
    /// Files larger than this limit receive a 413 Payload Too Large response.
    /// Defaults to 256 MiB.
    #[must_use]
    pub fn max_file_size(mut self, bytes: u64) -> Self {
        self.max_file_size = bytes;
        self
    }

    /// Set the index file name (served for directory requests). Pass `None` to disable.
    #[must_use]
    pub fn index_file(mut self, name: Option<impl Into<String>>) -> Self {
        self.index_file = name.map(Into::into);
        self
    }

    /// Add a custom response header to all served files.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom_headers
            .insert(name.into().to_ascii_lowercase(), value.into());
        self
    }

    fn apply_custom_headers(&self, mut response: Response) -> Response {
        for (k, v) in &self.custom_headers {
            response = response.header(k, v);
        }
        response
    }

    /// Resolve a request path to a file, applying security checks.
    fn resolve_path(&self, request_path: &str) -> Option<PathBuf> {
        // Strip leading slash and URL decode each segment on its own, after
        // splitting on the literal `/` (RFC 3986 §2.4). The router keeps a
        // `%2F` inside one segment, so `/files/admin%2Fsecret` never reaches a
        // mount at `/files/admin`; decoding the whole path here would then
        // serve `admin/secret` from an outer mount's root, past whatever
        // guards the inner mount.
        let cleaned = request_path.trim_start_matches('/');
        let mut decoded = String::with_capacity(cleaned.len());
        for (index, segment) in cleaned.split('/').enumerate() {
            let segment = percent_decode(segment);
            if segment.contains('/') {
                return None;
            }
            if index > 0 {
                decoded.push('/');
            }
            decoded.push_str(&segment);
        }

        // Reject traversal, ambiguous Windows separators, and hidden files.
        // Repeat the same policy after bounded additional decoding so a proxy
        // or downstream hop cannot turn a latent escape into a separator or
        // dotfile. URL paths use `/`; accepting `\` would make path meaning
        // platform-dependent. `.well-known` remains exempt only in canonical
        // slash-separated form for ACME / RFC 8615 discovery.
        if has_denied_static_path(&decoded)
            || has_denied_static_path_after_additional_decoding(&decoded)
        {
            return None;
        }

        let root_canonical = self.root.canonicalize().ok()?;
        let mut relative_path = PathBuf::from(&decoded);
        if path_contains_symlink(&root_canonical, &relative_path) {
            return None;
        }

        let mut full_path = root_canonical.join(&relative_path);

        // If it's a directory and we have an index file, try that.
        if full_path.is_dir() {
            let index = self.index_file.as_ref()?;
            relative_path.push(index);
            if path_contains_symlink(&root_canonical, &relative_path) {
                return None;
            }
            full_path = full_path.join(index);
        }

        // Canonicalize and verify it's under root.
        let canonical = full_path.canonicalize().ok()?;
        if !canonical.starts_with(&root_canonical) {
            return None;
        }

        if canonical.is_file() {
            Some(canonical)
        } else {
            None
        }
    }

    fn validated_current_path(&self, path: &Path) -> Option<PathBuf> {
        let root_canonical = self.root.canonicalize().ok()?;
        let relative_path = path.strip_prefix(&root_canonical).ok()?;
        if path_contains_symlink(&root_canonical, relative_path) {
            return None;
        }

        let canonical = path.canonicalize().ok()?;
        if !canonical.starts_with(&root_canonical) || !canonical.is_file() {
            return None;
        }

        Some(canonical)
    }

    /// Serve a file, handling ETag and conditional requests.
    fn serve_file(&self, path: &Path, if_none_match: Option<&str>) -> Response {
        let Some(path) = self.validated_current_path(path) else {
            return Response::empty(StatusCode::NOT_FOUND);
        };

        let Ok(mut file) = open_static_file(&path) else {
            return Response::empty(StatusCode::NOT_FOUND);
        };

        // Read file metadata from the opened handle so the file we size-check is
        // the same one whose body we later hash and serve.
        let Ok(metadata) = file.metadata() else {
            return Response::empty(StatusCode::INTERNAL_SERVER_ERROR);
        };

        if metadata.len() > self.max_file_size {
            return Response::empty(StatusCode::PAYLOAD_TOO_LARGE);
        }

        // Read file contents before generating the ETag. Strong ETags must be
        // content-derived, not just metadata-derived.
        let mut body = Vec::with_capacity(metadata.len().try_into().unwrap_or(0));
        if file.read_to_end(&mut body).is_err() {
            return Response::empty(StatusCode::INTERNAL_SERVER_ERROR);
        }

        let etag = generate_etag(&body);

        // Check If-None-Match.
        if let Some(client_etag) = if_none_match {
            if etag_matches(client_etag, &etag) {
                return self.apply_custom_headers(
                    Response::empty(StatusCode::NOT_MODIFIED)
                        .header("etag", &etag)
                        .header("accept-ranges", "bytes")
                        .header("cache-control", format!("public, max-age={}", self.max_age)),
                );
            }
        }

        let mime = guess_mime(&path);

        let response = Response::new(StatusCode::OK, body)
            .header("content-type", mime)
            .header("etag", &etag)
            .header("accept-ranges", "bytes")
            .header("cache-control", format!("public, max-age={}", self.max_age));

        self.apply_custom_headers(response)
    }

    /// Serve a file with Range request support (RFC 9110 §15.3.7).
    fn serve_range(
        &self,
        path: &Path,
        range_header: &str,
        if_none_match: Option<&str>,
        if_range: Option<&str>,
    ) -> Response {
        let Some(path) = self.validated_current_path(path) else {
            return Response::empty(StatusCode::NOT_FOUND);
        };

        let Ok(mut file) = open_static_file(&path) else {
            return Response::empty(StatusCode::NOT_FOUND);
        };

        let metadata = match file.metadata() {
            Ok(meta) => meta,
            Err(_) => return Response::empty(StatusCode::INTERNAL_SERVER_ERROR),
        };

        let file_size = metadata.len();
        if file_size > self.max_file_size {
            return Response::empty(StatusCode::PAYLOAD_TOO_LARGE);
        }

        // br-asupersync-42wywh: RFC 9110 §13.2.2 — "An origin server
        // that supports Range MUST evaluate the request preconditions
        // before doing so." Read the body and compute the ETag first
        // so a matching If-None-Match returns 304 even when the Range
        // header is malformed or unsatisfiable. Pre-fix the Range
        // parser ran first and short-circuited to 416, forcing
        // already-cached clients into a needless full refetch.
        let mut file_content = Vec::new();
        if file.read_to_end(&mut file_content).is_err() {
            return Response::empty(StatusCode::INTERNAL_SERVER_ERROR);
        }
        // Range math and the reported total MUST use the number of bytes we
        // actually read, not the earlier `metadata.len()`. If the file was
        // truncated between fstat and read (concurrent redeploy/truncate), the
        // stale `file_size` would make `end = file_size - 1` index past
        // `file_content`, panicking the connection task on the range slice.
        let file_size = file_content.len() as u64;
        let etag = generate_etag(&file_content);

        if let Some(client_etag) = if_none_match {
            if etag_matches(client_etag, &etag) {
                return self.apply_custom_headers(
                    Response::empty(StatusCode::NOT_MODIFIED)
                        .header("etag", &etag)
                        .header("cache-control", format!("public, max-age={}", self.max_age))
                        .header("accept-ranges", "bytes"),
                );
            }
        }

        // RFC 9110 §13.1.5: with If-Range, the range applies only while the
        // representation still matches the validator, compared strongly;
        // otherwise the whole current representation is sent with 200, so a
        // resumed download cannot splice bytes of a changed file onto the
        // part it already has. A date validator never matches here (no
        // Last-Modified is sent), so it also gets the full body.
        if if_range.is_some_and(|validator| validator.trim() != etag) {
            return self.serve_file(&path, None);
        }

        // Parse Range header (after preconditions per RFC 9110 §13.2.2).
        let ranges = match parse_ranges(range_header, file_size) {
            Ok(ranges) if !ranges.is_empty() => ranges,
            Ok(_) | Err(RangeError::InvalidSyntax) => {
                // Invalid or empty ranges - return 416 Range Not Satisfiable
                return self.apply_custom_headers(
                    Response::empty(StatusCode::RANGE_NOT_SATISFIABLE)
                        .header("content-range", format!("bytes */{}", file_size))
                        .header("accept-ranges", "bytes"),
                );
            }
            Err(RangeError::NotSatisfiable) => {
                return self.apply_custom_headers(
                    Response::empty(StatusCode::RANGE_NOT_SATISFIABLE)
                        .header("content-range", format!("bytes */{}", file_size))
                        .header("accept-ranges", "bytes"),
                );
            }
        };

        if let [range] = ranges.as_slice() {
            // Single range - return 206 Partial Content
            let range_data = &file_content[range.start..=range.end];
            let content_type = guess_mime(&path);

            let response = Response::new(
                StatusCode::PARTIAL_CONTENT,
                Bytes::from(range_data.to_vec()),
            )
            .header("content-type", content_type)
            .header("content-length", range_data.len().to_string())
            .header(
                "content-range",
                format!("bytes {}-{}/{}", range.start, range.end, file_size),
            )
            .header("accept-ranges", "bytes")
            .header("etag", &etag)
            .header("cache-control", format!("public, max-age={}", self.max_age));

            self.apply_custom_headers(response)
        } else {
            // Multiple ranges - return multipart/byteranges
            let boundary = "asupersync_range_boundary";
            let content_type = guess_mime(&path);
            let mut multipart_body = Vec::new();

            for range in &ranges {
                multipart_body.extend_from_slice(b"--");
                multipart_body.extend_from_slice(boundary.as_bytes());
                multipart_body.extend_from_slice(b"\r\n");
                multipart_body.extend_from_slice(b"Content-Type: ");
                multipart_body.extend_from_slice(content_type.as_bytes());
                multipart_body.extend_from_slice(b"\r\n");
                multipart_body.extend_from_slice(b"Content-Range: bytes ");
                multipart_body.extend_from_slice(
                    format!("{}-{}/{}", range.start, range.end, file_size).as_bytes(),
                );
                multipart_body.extend_from_slice(b"\r\n\r\n");
                multipart_body.extend_from_slice(&file_content[range.start..=range.end]);
                multipart_body.extend_from_slice(b"\r\n");
            }

            multipart_body.extend_from_slice(b"--");
            multipart_body.extend_from_slice(boundary.as_bytes());
            multipart_body.extend_from_slice(b"--\r\n");

            let body_len = multipart_body.len();
            let response = Response::new(StatusCode::PARTIAL_CONTENT, Bytes::from(multipart_body))
                .header(
                    "content-type",
                    format!("multipart/byteranges; boundary={}", boundary),
                )
                .header("content-length", body_len.to_string())
                .header("accept-ranges", "bytes")
                .header("etag", &etag)
                .header("cache-control", format!("public, max-age={}", self.max_age));

            self.apply_custom_headers(response)
        }
    }

    /// Create a handler that serves static files.
    ///
    /// The handler reads the request path and serves the corresponding file.
    /// It handles `If-None-Match` for conditional requests.
    #[must_use]
    pub fn handler(&self) -> StaticFilesHandler {
        StaticFilesHandler {
            config: self.clone(),
        }
    }
}

#[cfg(unix)]
fn open_static_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_static_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().read(true).open(path)
}

/// Handler that serves static files from a configured directory.
///
/// Created by [`StaticFiles::handler()`].
#[derive(Clone)]
pub struct StaticFilesHandler {
    config: StaticFiles,
}

impl Handler for StaticFilesHandler {
    fn call(
        &self,
        _cx: &crate::Cx,
        req: super::extract::Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            let head_only = req.method.eq_ignore_ascii_case("HEAD");
            let if_none_match = req.header("if-none-match").map(str::to_owned);
            let if_range = req.header("if-range");
            // RFC 9110 §14.2: a Range in a unit other than bytes is ignored.
            let range_header = req.header("range").filter(|range| {
                range
                    .trim()
                    .split_once('=')
                    .is_some_and(|(unit, _)| unit.eq_ignore_ascii_case("bytes"))
            });
            let request_path = &req.path;

            let mut response = match self.config.resolve_path(request_path) {
                Some(file_path) => {
                    if let Some(range_str) = range_header {
                        self.config.serve_range(
                            &file_path,
                            range_str,
                            if_none_match.as_deref(),
                            if_range,
                        )
                    } else {
                        let mut resp = self.config.serve_file(&file_path, if_none_match.as_deref());
                        // Add Accept-Ranges header to advertise range support
                        resp.set_header("accept-ranges", "bytes");
                        resp
                    }
                }
                None => Response::empty(StatusCode::NOT_FOUND),
            };

            if head_only {
                if !response.body.is_empty() && !response.has_header("content-length") {
                    response.set_header("content-length", response.body.len().to_string());
                }
                response.body = Bytes::new();
            }
            response
        })
    }
}

// ─── ETag ───────────────────────────────────────────────────────────────────

/// Generate a strong ETag from the exact response body bytes.
fn generate_etag(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let mut etag = String::with_capacity(2 + digest.len() * 2);
    etag.push('"');
    for &byte in &digest {
        let _ = write!(etag, "{byte:02x}");
    }
    etag.push('"');
    etag
}

/// Check if a client ETag matches the server ETag.
///
/// Handles `*` and comma-separated lists of ETags.
fn etag_matches(client: &str, server: &str) -> bool {
    let client = client.trim();
    if client == "*" {
        return true;
    }
    // Support comma-separated list.
    for candidate in client.split(',') {
        let candidate = candidate.trim();
        // Strip weak prefix if present.
        let candidate = candidate.strip_prefix("W/").unwrap_or(candidate);
        if candidate == server {
            return true;
        }
    }
    false
}

// ─── Test Helper Functions ─────────────────────────────────────────────────

/// Test access function to expose generate_etag for audit tests.
#[cfg(test)]
pub fn generate_etag_test_access(body: &[u8]) -> String {
    generate_etag(body)
}

/// Test access function to expose etag_matches for audit tests.
#[cfg(test)]
pub fn etag_matches_test_access(client: &str, server: &str) -> bool {
    etag_matches(client, server)
}

// ─── MIME Detection ─────────────────────────────────────────────────────────

/// Guess the MIME type from a file extension.
fn guess_mime(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        // Text
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("xml") => "application/xml; charset=utf-8",
        Some("txt") => "text/plain; charset=utf-8",
        Some("csv") => "text/csv; charset=utf-8",
        Some("md") => "text/markdown; charset=utf-8",
        Some("yaml" | "yml") => "application/yaml",
        Some("toml") => "application/toml",

        // Images
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("webp") => "image/webp",
        Some("avif") => "image/avif",

        // Fonts
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("eot") => "application/vnd.ms-fontobject",

        // Archives / binary
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        Some("gz" | "gzip") => "application/gzip",
        Some("tar") => "application/x-tar",
        Some("wasm") => "application/wasm",

        // Media
        Some("mp3") => "audio/mpeg",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("ogg") => "audio/ogg",

        // Default
        _ => "application/octet-stream",
    }
}

// ─── Path Security ──────────────────────────────────────────────────────────

/// Check all lexical path policies before constructing a platform-native path.
fn has_denied_static_path(path: &str) -> bool {
    path.contains('\\') || has_traversal(path) || path.split('/').any(is_denied_hidden_component)
}

/// Check for path traversal sequences.
fn has_traversal(path: &str) -> bool {
    // Block ".." components.
    for component in path.split('/') {
        if is_parent_dir_segment(component) {
            return true;
        }
    }
    // Also check backslash separators (Windows paths in URLs).
    for component in path.split('\\') {
        if is_parent_dir_segment(component) {
            return true;
        }
    }
    // Block null bytes.
    path.contains('\0')
}

fn has_denied_static_path_after_additional_decoding(path: &str) -> bool {
    let mut current = path.to_string();
    for _ in 0..4 {
        let decoded = percent_decode(&current);
        if decoded == current {
            return false;
        }
        if has_denied_static_path(&decoded) {
            return true;
        }
        current = decoded;
    }
    false
}

fn is_parent_dir_segment(component: &str) -> bool {
    let mut chars = component.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    let Some(second) = chars.next() else {
        return false;
    };

    is_path_dot(first) && is_path_dot(second) && chars.next().is_none()
}

fn is_path_dot(ch: char) -> bool {
    matches!(ch, '.' | '\u{2024}' | '\u{FE52}' | '\u{FF0E}')
}

fn path_contains_symlink(root: &Path, relative: &Path) -> bool {
    let mut current = root.to_path_buf();

    for component in relative.components() {
        match component {
            std::path::Component::Normal(segment) => current.push(segment),
            std::path::Component::CurDir => continue,
            _ => return true,
        }

        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return true,
            Ok(_) | Err(_) => {}
        }
    }

    false
}

/// Simple percent-decoding for URL paths.
///
/// Decodes `%XX` hex pairs into raw bytes, then converts the result to a
/// UTF-8 string (lossy replacement for invalid sequences).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "static_files_inline_tests.rs"]
mod tests;
