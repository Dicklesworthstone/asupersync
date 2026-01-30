//! HTTP/1.1 protocol types.
//!
//! Provides [`Method`], [`Version`], and request/response types for HTTP/1.1
//! protocol handling.

use std::fmt;

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
        }
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
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
    }

    #[test]
    fn default_reasons() {
        assert_eq!(default_reason(200), "OK");
        assert_eq!(default_reason(404), "Not Found");
        assert_eq!(default_reason(500), "Internal Server Error");
        assert_eq!(default_reason(999), "Unknown");
    }
}
