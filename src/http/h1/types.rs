//! HTTP/1.1 protocol types.
//!
//! Provides [`Method`], [`Version`], and request/response types for HTTP/1.1
//! protocol handling.

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

    /// Add a trailer header.
    ///
    /// Trailers are only valid with `Transfer-Encoding: chunked`.
    #[must_use]
    pub fn with_trailer(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.trailers.push((name.into(), value.into()));
        self
    }
}

/// Returns the standard reason phrase for a status code.
#[must_use]
pub fn default_reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
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
        let m = Method::Get;
        let dbg = format!("{m:?}");
        assert!(dbg.contains("Get"));
        let cloned = m.clone();
        assert_eq!(m, cloned);

        use std::collections::HashSet;
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
        let v = Version::Http11;
        let dbg = format!("{v:?}");
        assert!(dbg.contains("Http11"));
        let copied = v;
        assert_eq!(v, copied);

        use std::collections::HashSet;
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
}
