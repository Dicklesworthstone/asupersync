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
use std::path::{Path, PathBuf};

use super::handler::Handler;
use super::response::{Response, StatusCode};

/// Default max-age for Cache-Control (1 hour).
const DEFAULT_MAX_AGE: u32 = 3600;

/// Maximum file size to serve (256 MiB).
const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

// ─── StaticFiles ────────────────────────────────────────────────────────────

/// Configuration for static file serving.
#[derive(Clone)]
pub struct StaticFiles {
    root: PathBuf,
    max_age: u32,
    index_file: Option<String>,
    custom_headers: HashMap<String, String>,
}

impl fmt::Debug for StaticFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticFiles")
            .field("root", &self.root)
            .field("max_age", &self.max_age)
            .field("index_file", &self.index_file)
            .field("custom_headers", &self.custom_headers)
            .finish()
    }
}

impl StaticFiles {
    /// Create a new static file server rooted at the given directory.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_age: DEFAULT_MAX_AGE,
            index_file: Some("index.html".to_string()),
            custom_headers: HashMap::new(),
        }
    }

    /// Set the `Cache-Control: max-age` value in seconds.
    #[must_use]
    pub fn max_age(mut self, seconds: u32) -> Self {
        self.max_age = seconds;
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
        self.custom_headers.insert(name.into(), value.into());
        self
    }

    /// Resolve a request path to a file, applying security checks.
    fn resolve_path(&self, request_path: &str) -> Option<PathBuf> {
        // Strip leading slash and URL decode.
        let cleaned = request_path.trim_start_matches('/');
        let decoded = percent_decode(cleaned);

        // Reject path traversal.
        if has_traversal(&decoded) {
            return None;
        }

        let mut full_path = self.root.join(&decoded);

        // If it's a directory and we have an index file, try that.
        if full_path.is_dir() {
            if let Some(ref index) = self.index_file {
                full_path = full_path.join(index);
            } else {
                return None;
            }
        }

        // Canonicalize and verify it's under root.
        let canonical = full_path.canonicalize().ok()?;
        let root_canonical = self.root.canonicalize().ok()?;
        if !canonical.starts_with(&root_canonical) {
            return None;
        }

        if canonical.is_file() {
            Some(canonical)
        } else {
            None
        }
    }

    /// Serve a file, handling ETag and conditional requests.
    fn serve_file(&self, path: &Path, if_none_match: Option<&str>) -> Response {
        // Read file metadata.
        let Ok(metadata) = std::fs::metadata(path) else {
            return Response::empty(StatusCode::NOT_FOUND);
        };

        if metadata.len() > MAX_FILE_SIZE {
            return Response::empty(StatusCode::PAYLOAD_TOO_LARGE);
        }

        // Generate ETag from size + modified time.
        let etag = generate_etag(&metadata);

        // Check If-None-Match.
        if let Some(client_etag) = if_none_match {
            if etag_matches(client_etag, &etag) {
                return Response::empty(StatusCode::NOT_MODIFIED)
                    .header("etag", &etag)
                    .header("cache-control", format!("public, max-age={}", self.max_age));
            }
        }

        // Read file contents.
        let Ok(body) = std::fs::read(path) else {
            return Response::empty(StatusCode::INTERNAL_SERVER_ERROR);
        };

        let mime = guess_mime(path);

        let mut response = Response::new(StatusCode::OK, body)
            .header("content-type", mime)
            .header("etag", &etag)
            .header("cache-control", format!("public, max-age={}", self.max_age));

        for (k, v) in &self.custom_headers {
            response = response.header(k, v);
        }

        response
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

/// Handler that serves static files from a configured directory.
///
/// Created by [`StaticFiles::handler()`].
#[derive(Clone)]
pub struct StaticFilesHandler {
    config: StaticFiles,
}

impl Handler for StaticFilesHandler {
    fn call(&self, req: super::extract::Request) -> Response {
        let if_none_match = req.headers.get("if-none-match").cloned();
        let request_path = &req.path;

        self.config.resolve_path(request_path).map_or_else(
            || Response::empty(StatusCode::NOT_FOUND),
            |file_path| self.config.serve_file(&file_path, if_none_match.as_deref()),
        )
    }
}

// ─── ETag ───────────────────────────────────────────────────────────────────

/// Generate an ETag from file metadata (size + mtime).
fn generate_etag(metadata: &std::fs::Metadata) -> String {
    use std::time::UNIX_EPOCH;

    let size = metadata.len();
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());

    // Strong ETag: combine size and mtime.
    format!("\"{size:x}-{mtime:x}\"")
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
        if component == ".." {
            return true;
        }
    }
    // Also check backslash separators (Windows paths in URLs).
    for component in path.split('\\') {
        if component == ".." {
            return true;
        }
    }
    // Block null bytes.
    if path.contains('\0') {
        return true;
    }
    false
}

/// Simple percent-decoding for URL paths.
///
/// Decodes `%XX` hex pairs into raw bytes, then converts the result to a
/// UTF-8 string (lossy replacement for invalid sequences).
fn percent_decode(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().and_then(hex_val);
            let lo = bytes.next().and_then(hex_val);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(h << 4 | l);
            } else {
                out.push(b'%');
            }
        } else {
            out.push(b);
        }
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
    use super::*;
    use std::fs;
    use tempfile::TempDir;

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
    fn percent_decode_incomplete() {
        // Incomplete percent sequence: "%" is preserved, trailing bytes consumed.
        assert_eq!(percent_decode("hello%2"), "hello%");
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

    // ================================================================
    // Handler integration
    // ================================================================

    #[test]
    fn handler_serves_file() {
        use super::super::handler::Handler;

        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let handler = sf.handler();

        let req = super::super::extract::Request::new("GET", "/hello.txt");
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(std::str::from_utf8(&resp.body).unwrap(), "Hello, world!");
    }

    #[test]
    fn handler_returns_404() {
        use super::super::handler::Handler;

        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let handler = sf.handler();

        let req = super::super::extract::Request::new("GET", "/missing.txt");
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn handler_304_with_etag() {
        use super::super::handler::Handler;

        let dir = setup_dir();
        let sf = StaticFiles::new(dir.path());
        let handler = sf.handler();

        // First request.
        let req1 = super::super::extract::Request::new("GET", "/hello.txt");
        let resp1 = handler.call(req1);
        let etag = resp1.headers.get("etag").unwrap().clone();

        // Second request with If-None-Match.
        let mut req2 = super::super::extract::Request::new("GET", "/hello.txt");
        req2.headers.insert("if-none-match".to_string(), etag);
        let resp2 = handler.call(req2);
        assert_eq!(resp2.status, StatusCode::NOT_MODIFIED);
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
