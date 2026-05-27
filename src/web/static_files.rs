//! Static file serving with caching, ETag, and conditional request support.
//!
//! Serves files from a directory with automatic MIME detection, strong ETags,
//! `Cache-Control` headers, and `If-None-Match` / `304 Not Modified` support.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::web::static_files::StaticFiles;
//! use asupersync::web::{Router, get};
//!
//! let statics = StaticFiles::new("./public");
//! let app = Router::new()
//!     .route("/static/*path", get(statics.handler()));
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

/// Parse Range header and return satisfiable byte ranges.
/// RFC 9110 §14.1.2 Range specification.
fn parse_ranges(range_header: &str, file_size: u64) -> Result<Vec<ByteRange>, RangeError> {
    let range_header = range_header.trim();
    let Some(ranges_str) = range_header.strip_prefix("bytes=") else {
        return Err(RangeError::InvalidSyntax);
    };
    let mut ranges = Vec::new();

    for range_spec in ranges_str.split(',') {
        let range_spec = range_spec.trim();

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
        Err(RangeError::NotSatisfiable)
    } else {
        Ok(ranges)
    }
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
        // Strip leading slash and URL decode.
        let cleaned = request_path.trim_start_matches('/');
        let decoded = percent_decode(cleaned);

        // Reject path traversal, including sequences that would become
        // traversal only if an upstream/downstream hop decodes once more.
        if has_traversal(&decoded) || has_traversal_after_additional_decoding(&decoded) {
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
            let range_header = req.header("range");
            let request_path = &req.path;

            let mut response = match self.config.resolve_path(request_path) {
                Some(file_path) => {
                    if let Some(range_str) = range_header {
                        self.config
                            .serve_range(&file_path, range_str, if_none_match.as_deref())
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
    if path.contains('\0') {
        return true;
    }
    false
}

fn has_traversal_after_additional_decoding(path: &str) -> bool {
    let mut current = path.to_string();
    for _ in 0..4 {
        let decoded = percent_decode(&current);
        if decoded == current {
            return false;
        }
        if has_traversal(&decoded) {
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
    use std::fs;
    use tempfile::TempDir;

    trait SyncHandlerExt {
        fn call_sync(&self, req: super::super::extract::Request) -> Response;
    }

    impl<H: super::super::handler::Handler> SyncHandlerExt for H {
        fn call_sync(&self, req: super::super::extract::Request) -> Response {
            futures_lite::future::block_on(super::super::handler::Handler::call(
                self,
                &crate::Cx::for_testing(),
                req,
            ))
        }
    }

    fn setup_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("hello.txt"), "Hello, world!").unwrap();
        fs::write(dir.path().join("style.css"), "body { color: red; }").unwrap();
        fs::write(dir.path().join("app.js"), "console.log('hi');").unwrap();
        fs::write(dir.path().join("data.json"), r#"{"key":"val"}"#).unwrap();
        fs::write(dir.path().join("image.png"), [0x89, 0x50, 0x4E, 0x47]).unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/page.html"), "<h1>Sub</h1>").unwrap();
        fs::write(dir.path().join("sub/index.html"), "<h1>Index</h1>").unwrap();
        dir
    }

    // ================================================================
    // MIME detection
    // ================================================================

    #[test]
    fn mime_html() {
        assert_eq!(
            guess_mime(Path::new("index.html")),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn mime_css() {
        assert_eq!(
            guess_mime(Path::new("style.css")),
            "text/css; charset=utf-8"
        );
    }

    #[test]
    fn mime_js() {
        assert_eq!(
            guess_mime(Path::new("app.js")),
            "application/javascript; charset=utf-8"
        );
    }

    #[test]
    fn mime_json() {
        assert_eq!(
            guess_mime(Path::new("data.json")),
            "application/json; charset=utf-8"
        );
    }

    #[test]
    fn mime_png() {
        assert_eq!(guess_mime(Path::new("image.png")), "image/png");
    }

    #[test]
    fn mime_unknown() {
        assert_eq!(
            guess_mime(Path::new("file.xyz")),
            "application/octet-stream"
        );
    }

    #[test]
    fn mime_case_insensitive() {
        assert_eq!(
            guess_mime(Path::new("FILE.HTML")),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn mime_wasm() {
        assert_eq!(guess_mime(Path::new("module.wasm")), "application/wasm");
    }

    // ================================================================
    // Path security
    // ================================================================

    #[test]
    fn traversal_double_dot() {
        assert!(has_traversal("../etc/passwd"));
        assert!(has_traversal("foo/../bar"));
        assert!(has_traversal("foo/.."));
    }

    #[test]
    fn traversal_backslash() {
        assert!(has_traversal("..\\etc\\passwd"));
    }

    #[test]
    fn traversal_null_byte() {
        assert!(has_traversal("file\0.txt"));
    }

    #[test]
    fn traversal_unicode_dot_variants() {
        assert!(has_traversal("\u{2024}\u{2024}/etc/passwd"));
        assert!(has_traversal(".\u{2024}/etc/passwd"));
        assert!(has_traversal("foo/\u{FE52}\u{FE52}/bar"));
        assert!(has_traversal("foo/\u{FF0E}\u{FF0E}/bar"));
    }

    #[test]
    fn traversal_deferred_percent_decoding() {
        assert!(has_traversal_after_additional_decoding("%2e%2e/etc/passwd"));
        assert!(has_traversal_after_additional_decoding(
            "safe/%2e%2e/secret.txt"
        ));
        assert!(has_traversal_after_additional_decoding(
            "safe%2f..%2fsecret.txt"
        ));
        assert!(has_traversal_after_additional_decoding(
            "safe%5c..%5csecret.txt"
        ));
        assert!(has_traversal_after_additional_decoding(
            "%252e%252e/etc/passwd"
        ));
        assert!(!has_traversal_after_additional_decoding(
            "version%2e1/file.txt"
        ));
    }

    #[test]
    fn no_traversal() {
        assert!(!has_traversal("hello.txt"));
        assert!(!has_traversal("sub/page.html"));
        assert!(!has_traversal("deeply/nested/file.js"));
    }

    // ================================================================
    // Percent decoding
    // ================================================================

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
    }

    #[test]
    fn percent_decode_no_encoding() {
        assert_eq!(percent_decode("hello.txt"), "hello.txt");
    }

    #[test]
    fn percent_decode_path_separator() {
        assert_eq!(percent_decode("foo%2Fbar"), "foo/bar");
    }

    #[test]
    fn percent_decode_utf8_path_dot() {
        assert_eq!(percent_decode("%E2%80%A4%E2%80%A4"), "\u{2024}\u{2024}");
        assert!(has_traversal(&percent_decode(
            "%E2%80%A4%E2%80%A4/etc/passwd"
        )));
    }

    #[test]
    fn percent_decode_incomplete() {
        assert_eq!(percent_decode("hello%2"), "hello%2");
    }

    #[test]
    fn percent_decode_invalid_sequence_preserves_bytes() {
        assert_eq!(percent_decode("hello%GGworld"), "hello%GGworld");
        assert_eq!(percent_decode("sub%2/page.html"), "sub%2/page.html");
        assert_eq!(percent_decode("%"), "%");
    }

    // ================================================================
    // ETag
    // ================================================================

    #[test]
    fn etag_matches_exact() {
        assert!(etag_matches("\"abc\"", "\"abc\""));
    }

    #[test]
    fn etag_matches_star() {
        assert!(etag_matches("*", "\"abc\""));
    }

    #[test]
    fn etag_matches_list() {
        assert!(etag_matches("\"x\", \"y\", \"z\"", "\"y\""));
    }

    #[test]
    fn etag_matches_weak() {
        assert!(etag_matches("W/\"abc\"", "\"abc\""));
    }

    #[test]
    fn etag_no_match() {
        assert!(!etag_matches("\"abc\"", "\"def\""));
    }

    #[test]
    fn strong_etag_changes_for_same_length_content() {
        let first = generate_etag(b"abc");
        let second = generate_etag(b"abd");

        assert_ne!(
            first, second,
            "strong ETags must change when same-length content changes"
        );
    }

    // ================================================================
    // Path resolution
    // ================================================================

    #[test]
    fn resolve_simple_file() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/hello.txt");
        assert!(path.is_some());
    }

    #[test]
    fn resolve_nested_file() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/sub/page.html");
        assert!(path.is_some());
    }

    #[test]
    fn resolve_directory_index() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/sub/");
        assert!(path.is_some());
        assert!(path.unwrap().ends_with("index.html"));
    }

    #[test]
    fn resolve_nonexistent() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        assert!(sf.resolve_path("/missing.txt").is_none());
    }

    #[test]
    fn resolve_traversal_blocked() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        assert!(sf.resolve_path("/../../../etc/passwd").is_none());
    }

    #[test]
    fn resolve_percent_encoded() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        assert!(sf.resolve_path("/hello%2Etxt").is_some());
    }

    #[test]
    fn resolve_double_encoded_traversal_blocked() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        assert!(sf.resolve_path("/%252e%252e/etc/passwd").is_none());
        assert!(sf.resolve_path("/sub%252f..%252fhello.txt").is_none());
        assert!(sf.resolve_path("/sub%255c..%255chello.txt").is_none());
    }

    #[test]
    fn resolve_unicode_dot_traversal_blocked_after_percent_decode() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());

        assert!(sf.resolve_path("/%E2%80%A4%E2%80%A4/etc/passwd").is_none());
        assert!(
            sf.resolve_path("/sub/%EF%B9%92%EF%B9%92/hello.txt")
                .is_none()
        );
        assert!(
            sf.resolve_path("/sub/%EF%BC%8E%EF%BC%8E/hello.txt")
                .is_none()
        );
    }

    #[test]
    fn resolve_invalid_percent_encoding_does_not_alias_other_path() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        assert!(
            sf.resolve_path("/sub%2/page.html").is_none(),
            "malformed escapes must be preserved instead of silently dropping bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_symlinked_file_blocked() {
        let dir = setup_dir();
        std::os::unix::fs::symlink("hello.txt", dir.path().join("hello-link.txt")).unwrap();

        let sf = StaticFiles::new(dir.path());
        assert!(
            sf.resolve_path("/hello-link.txt").is_none(),
            "symlinked files must not be served by default"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_symlinked_directory_blocked() {
        let dir = setup_dir();
        std::os::unix::fs::symlink("sub", dir.path().join("sub-link")).unwrap();

        let sf = StaticFiles::new(dir.path());
        assert!(
            sf.resolve_path("/sub-link/page.html").is_none(),
            "symlinked directories must not be traversed"
        );
        assert!(
            sf.resolve_path("/sub-link/").is_none(),
            "directory indexes behind symlinks must not be served"
        );
    }

    #[cfg(unix)]
    #[test]
    fn serve_file_rejects_post_resolution_symlink_swap() {
        let dir = setup_dir();
        let outside = TempDir::new().unwrap();
        let outside_path = outside.path().join("secret.txt");
        fs::write(&outside_path, "top secret").unwrap();

        let sf = StaticFiles::new(dir.path());
        let resolved = sf.resolve_path("/hello.txt").unwrap();
        let backup = dir.path().join("hello.backup.txt");
        fs::rename(&resolved, &backup).unwrap();
        std::os::unix::fs::symlink(&outside_path, &resolved).unwrap();

        let resp = sf.serve_file(&resolved, None);
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
        assert_ne!(resp.body.as_ref(), b"top secret");
    }

    // ================================================================
    // File serving
    // ================================================================

    #[test]
    fn serve_txt_file() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/hello.txt").unwrap();
        let resp = sf.serve_file(&path, None);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "Hello, world!");
        assert!(resp.headers.contains_key("etag"));
        assert!(resp.headers.contains_key("cache-control"));
        assert_eq!(
            resp.headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    #[test]
    fn serve_css_file() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/style.css").unwrap();
        let resp = sf.serve_file(&path, None);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/css; charset=utf-8"
        );
    }

    #[test]
    fn serve_304_not_modified() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/hello.txt").unwrap();

        // First request to get the ETag.
        let resp1 = sf.serve_file(&path, None);
        let etag = resp1.headers.get("etag").unwrap().clone();

        // Second request with If-None-Match.
        let resp2 = sf.serve_file(&path, Some(&etag));
        assert_eq!(resp2.status, StatusCode::NOT_MODIFIED);
        assert!(resp2.body.is_empty());
        assert_eq!(
            resp2.headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    #[test]
    fn serve_304_not_modified_for_if_none_match_wildcard() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/hello.txt").unwrap();

        let resp = sf.serve_file(&path, Some("*"));
        assert_eq!(resp.status, StatusCode::NOT_MODIFIED);
        assert!(resp.body.is_empty());
        assert!(resp.headers.contains_key("etag"));
        assert_eq!(
            resp.headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    /// br-asupersync-42wywh — RFC 9110 §13.2.2 requires preconditions
    /// (If-None-Match in particular) to be evaluated BEFORE Range
    /// processing. Pre-fix: an unsatisfiable / malformed Range header
    /// short-circuited to 416 even when If-None-Match matched the
    /// current ETag, forcing clients into a needless full refetch on
    /// the next request. Post-fix: If-None-Match wins → 304 Not Modified.
    #[test]
    fn serve_range_with_matching_if_none_match_prefers_304_over_416() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/hello.txt").unwrap();

        // Capture the current ETag from a plain GET so we can replay
        // the matching If-None-Match below.
        let etag = sf
            .serve_file(&path, None)
            .headers
            .get("etag")
            .expect("etag must be present")
            .clone();

        // Range that is provably unsatisfiable: file is 13 bytes, the
        // requested range starts well past EOF. parse_ranges returns
        // NotSatisfiable, which the pre-fix path short-circuited to
        // 416 before checking If-None-Match.
        let resp = sf.serve_range(&path, "bytes=99999-100000", Some(&etag));

        assert_eq!(
            resp.status,
            StatusCode::NOT_MODIFIED,
            "If-None-Match must be evaluated before Range (RFC 9110 §13.2.2); \
             matching ETag must yield 304, not 416. Got status={:?}",
            resp.status,
        );
        assert!(resp.body.is_empty(), "304 responses MUST NOT carry a body",);
        assert_eq!(
            resp.headers.get("etag").map(String::as_str),
            Some(etag.as_str()),
            "304 must echo the ETag",
        );
        assert!(
            !resp.headers.contains_key("content-range"),
            "304 must not carry Content-Range; got {:?}",
            resp.headers.get("content-range"),
        );
    }

    /// br-asupersync-42wywh — same precondition-ordering requirement
    /// for the syntactically-malformed Range case (`bytes=abc-def`).
    /// The matching If-None-Match takes precedence; 304, not 416.
    #[test]
    fn serve_range_invalid_syntax_with_matching_if_none_match_returns_304() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/hello.txt").unwrap();

        let etag = sf
            .serve_file(&path, None)
            .headers
            .get("etag")
            .expect("etag must be present")
            .clone();

        let resp = sf.serve_range(&path, "bytes=abc-def", Some(&etag));

        assert_eq!(
            resp.status,
            StatusCode::NOT_MODIFIED,
            "If-None-Match must trump even a malformed Range header per \
             RFC 9110 §13.2.2; got status={:?}",
            resp.status,
        );
    }

    /// br-asupersync-42wywh — counter test: a non-matching If-None-Match
    /// with an unsatisfiable Range still yields 416. The fix must NOT
    /// regress the existing behavior when the precondition is false.
    #[test]
    fn serve_range_unsatisfiable_with_non_matching_if_none_match_still_416() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let path = sf.resolve_path("/hello.txt").unwrap();

        let resp = sf.serve_range(&path, "bytes=99999-100000", Some("\"not-the-etag\""));

        assert_eq!(
            resp.status,
            StatusCode::RANGE_NOT_SATISFIABLE,
            "Non-matching If-None-Match must NOT prevent the 416 path",
        );
    }

    #[test]
    fn serve_custom_max_age() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path()).max_age(86400);
        let path = sf.resolve_path("/hello.txt").unwrap();
        let resp = sf.serve_file(&path, None);
        assert_eq!(
            resp.headers.get("cache-control").unwrap(),
            "public, max-age=86400"
        );
    }

    #[test]
    fn serve_custom_headers() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path()).header("x-custom", "value");
        let path = sf.resolve_path("/hello.txt").unwrap();
        let resp = sf.serve_file(&path, None);
        assert_eq!(resp.headers.get("x-custom").unwrap(), "value");
    }

    #[test]
    fn serve_custom_headers_can_override_nosniff() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path()).header("X-Content-Type-Options", "custom-policy");
        let path = sf.resolve_path("/hello.txt").unwrap();
        let resp = sf.serve_file(&path, None);
        assert_eq!(
            resp.headers.get("x-content-type-options").unwrap(),
            "custom-policy"
        );
    }

    // ================================================================
    // Handler integration
    // ================================================================

    #[test]
    fn handler_serves_file() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let handler = sf.handler();

        let req = super::super::extract::Request::new("GET", "/hello.txt");
        let resp = handler.call_sync(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "Hello, world!");
    }

    #[test]
    fn handler_head_omits_body_but_preserves_conditional_headers() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let handler = sf.handler();

        let get_resp = handler.call_sync(super::super::extract::Request::new("GET", "/hello.txt"));
        let head_resp =
            handler.call_sync(super::super::extract::Request::new("HEAD", "/hello.txt"));

        assert_eq!(head_resp.status, StatusCode::OK);
        assert!(head_resp.body.is_empty());
        assert_eq!(
            head_resp.headers.get("content-type"),
            get_resp.headers.get("content-type")
        );
        assert_eq!(
            head_resp.headers.get("content-length"),
            Some(&get_resp.body.len().to_string())
        );
        assert_eq!(head_resp.headers.get("etag"), get_resp.headers.get("etag"));
        assert_eq!(
            head_resp.headers.get("cache-control"),
            get_resp.headers.get("cache-control")
        );
        assert_eq!(
            head_resp.headers.get("x-content-type-options"),
            get_resp.headers.get("x-content-type-options")
        );
    }

    #[test]
    fn handler_returns_404() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let handler = sf.handler();

        let req = super::super::extract::Request::new("GET", "/missing.txt");
        let resp = handler.call_sync(req);
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn handler_304_with_etag() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let handler = sf.handler();

        // First request.
        let req1 = super::super::extract::Request::new("GET", "/hello.txt");
        let resp1 = handler.call_sync(req1);
        let etag = resp1.headers.get("etag").unwrap().clone();

        // Second request with If-None-Match.
        let req2 = super::super::extract::Request::new("GET", "/hello.txt")
            .with_header("If-None-Match", etag);
        let resp2 = handler.call_sync(req2);
        assert_eq!(resp2.status, StatusCode::NOT_MODIFIED);
    }

    #[test]
    fn handler_head_304_with_etag_stays_empty() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let handler = sf.handler();

        let get_resp = handler.call_sync(super::super::extract::Request::new("GET", "/hello.txt"));
        let etag = get_resp.headers.get("etag").unwrap().clone();

        let head_req = super::super::extract::Request::new("HEAD", "/hello.txt")
            .with_header("If-None-Match", etag);
        let head_resp = handler.call_sync(head_req);

        assert_eq!(head_resp.status, StatusCode::NOT_MODIFIED);
        assert!(head_resp.body.is_empty());
        assert!(head_resp.headers.contains_key("etag"));
        assert!(head_resp.headers.contains_key("cache-control"));
        assert_eq!(
            head_resp.headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    // ================================================================
    // Builder API
    // ================================================================

    #[test]
    fn builder_no_index() {
        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path()).index_file(None::<String>);
        assert!(sf.resolve_path("/sub/").is_none());
    }

    #[test]
    fn builder_debug() {
        let sf = StaticFiles::new("/tmp/static");
        let dbg = format!("{sf:?}");
        assert!(dbg.contains("StaticFiles"));
        assert!(dbg.contains("/tmp/static"));
    }

    #[test]
    fn builder_clone() {
        let sf = StaticFiles::new("/tmp/static").max_age(300);
        let sf2 = sf.clone();
        assert_eq!(sf2.max_age, sf.max_age);
    }
}
