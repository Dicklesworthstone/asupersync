//! High-level HTTP/1.1 client with connection pooling, DNS resolution,
//! TLS support, and redirect following.
//!
//! [`HttpClient`] integrates [`Http1Client`], [`Pool`], DNS resolution,
//! and optional TLS into a simple API for making HTTP requests.
//!
//! # Example
//!
//! ```ignore
//! let client = HttpClient::new();
//! let resp = client.get("http://example.com/api").await?;
//! assert_eq!(resp.status, 200);
//! ```

use crate::http::h1::client::{ClientStreamingResponse, Http1Client};
use crate::http::h1::types::{Method, Request, Response, Version};
use crate::http::pool::{Pool, PoolConfig, PoolKey};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::net::tcp::stream::TcpStream;
#[cfg(feature = "tls")]
use crate::tls::{TlsConnectorBuilder, TlsStream};
use std::io;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

/// Errors that can occur during HTTP client operations.
#[derive(Debug)]
pub enum ClientError {
    /// Invalid URL.
    InvalidUrl(String),
    /// DNS resolution failed.
    DnsError(io::Error),
    /// TCP connection failed.
    ConnectError(io::Error),
    /// TLS handshake failed.
    TlsError(String),
    /// HTTP protocol error.
    HttpError(crate::http::h1::codec::HttpError),
    /// Too many redirects.
    TooManyRedirects {
        /// Number of redirects followed.
        count: u32,
        /// Maximum allowed.
        max: u32,
    },
    /// I/O error.
    Io(io::Error),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(url) => write!(f, "invalid URL: {url}"),
            Self::DnsError(e) => write!(f, "DNS resolution failed: {e}"),
            Self::ConnectError(e) => write!(f, "connection failed: {e}"),
            Self::TlsError(e) => write!(f, "TLS error: {e}"),
            Self::HttpError(e) => write!(f, "HTTP error: {e}"),
            Self::TooManyRedirects { count, max } => {
                write!(f, "too many redirects ({count} of max {max})")
            }
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DnsError(e) | Self::ConnectError(e) | Self::Io(e) => Some(e),
            Self::HttpError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<crate::http::h1::codec::HttpError> for ClientError {
    fn from(e: crate::http::h1::codec::HttpError) -> Self {
        Self::HttpError(e)
    }
}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Parsed URL components.
#[derive(Debug, Clone)]
pub struct ParsedUrl {
    /// URL scheme (http or https).
    pub scheme: Scheme,
    /// Host name.
    pub host: String,
    /// Port number.
    pub port: u16,
    /// Path and query string.
    pub path: String,
}

/// URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Plain HTTP.
    Http,
    /// HTTPS (TLS).
    Https,
}

/// HTTP client transport stream (plain TCP or TLS).
#[derive(Debug)]
pub enum ClientIo {
    /// Plain TCP stream.
    Plain(TcpStream),
    /// TLS-wrapped TCP stream.
    #[cfg(feature = "tls")]
    Tls(TlsStream<TcpStream>),
}

impl AsyncRead for ClientIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ClientIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_write(cx, data),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s).poll_write(cx, data),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl ParsedUrl {
    /// Parse a URL string into components.
    pub fn parse(url: &str) -> Result<Self, ClientError> {
        let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (Scheme::Https, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (Scheme::Http, rest)
        } else {
            return Err(ClientError::InvalidUrl(format!(
                "unsupported scheme in: {url}"
            )));
        };

        let (authority, path) = rest
            .find('/')
            .map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));

        let (host, port) = if authority.starts_with('[') {
            // IPv6: [::1]:port or [::1]
            let bracket_end = authority.find(']').ok_or_else(|| {
                ClientError::InvalidUrl("unclosed bracket in IPv6 address".into())
            })?;
            let host_str = &authority[..=bracket_end];
            let rest = &authority[bracket_end + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                let port: u16 = port_str
                    .parse()
                    .map_err(|_| ClientError::InvalidUrl(format!("invalid port: {port_str}")))?;
                (host_str.to_owned(), port)
            } else if rest.is_empty() {
                let default_port = match scheme {
                    Scheme::Http => 80,
                    Scheme::Https => 443,
                };
                (host_str.to_owned(), default_port)
            } else {
                return Err(ClientError::InvalidUrl(format!(
                    "unexpected characters after IPv6 address: {rest}"
                )));
            }
        } else if let Some(i) = authority.rfind(':') {
            let port_str = &authority[i + 1..];
            let port: u16 = port_str
                .parse()
                .map_err(|_| ClientError::InvalidUrl(format!("invalid port: {port_str}")))?;
            (authority[..i].to_owned(), port)
        } else {
            let default_port = match scheme {
                Scheme::Http => 80,
                Scheme::Https => 443,
            };
            (authority.to_owned(), default_port)
        };

        if host.is_empty() {
            return Err(ClientError::InvalidUrl("empty host".into()));
        }

        Ok(Self {
            scheme,
            host,
            port,
            path: path.to_owned(),
        })
    }

    /// Returns the pool key for this URL.
    #[must_use]
    pub fn pool_key(&self) -> PoolKey {
        PoolKey::new(&self.host, self.port, self.scheme == Scheme::Https)
    }

    /// Returns the authority (host:port or just host for default ports).
    #[must_use]
    pub fn authority(&self) -> String {
        let default_port = match self.scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        if self.port == default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Redirect policy for the HTTP client.
#[derive(Debug, Clone)]
pub enum RedirectPolicy {
    /// Do not follow redirects.
    None,
    /// Follow up to N redirects.
    Limited(u32),
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self::Limited(10)
    }
}

/// Configuration for the HTTP client.
#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    /// Connection pool configuration.
    pub pool_config: PoolConfig,
    /// Redirect policy.
    pub redirect_policy: RedirectPolicy,
    /// Default User-Agent header value.
    pub user_agent: Option<String>,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            pool_config: PoolConfig::default(),
            redirect_policy: RedirectPolicy::default(),
            user_agent: Some("asupersync/0.1".into()),
        }
    }
}

/// High-level HTTP/1.1 client.
///
/// Provides a simple API for making HTTP requests with automatic connection
/// pooling, DNS resolution, and redirect following.
///
/// # Connection Pooling
///
/// Connections are tracked in a [`Pool`] and reused when possible. The pool
/// enforces per-host and total connection limits.
///
/// # Redirects
///
/// By default, the client follows up to 10 redirects. The redirect policy
/// can be configured via [`HttpClientConfig`].
pub struct HttpClient {
    config: HttpClientConfig,
    pool: Mutex<Pool>,
}

impl HttpClient {
    /// Create a new client with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(HttpClientConfig::default())
    }

    /// Create a new client with custom configuration.
    #[must_use]
    pub fn with_config(config: HttpClientConfig) -> Self {
        let pool = Pool::with_config(config.pool_config.clone());
        Self {
            config,
            pool: Mutex::new(pool),
        }
    }

    /// Send a GET request to the given URL.
    pub async fn get(&self, url: &str) -> Result<Response, ClientError> {
        self.request(Method::Get, url, Vec::new(), Vec::new()).await
    }

    /// Send a POST request to the given URL with a body.
    pub async fn post(&self, url: &str, body: Vec<u8>) -> Result<Response, ClientError> {
        self.request(Method::Post, url, Vec::new(), body).await
    }

    /// Send a POST request and stream the response body.
    pub async fn post_streaming(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> Result<ClientStreamingResponse<ClientIo>, ClientError> {
        self.request_streaming(Method::Post, url, Vec::new(), body)
            .await
    }

    /// Send a PUT request to the given URL with a body.
    pub async fn put(&self, url: &str, body: Vec<u8>) -> Result<Response, ClientError> {
        self.request(Method::Put, url, Vec::new(), body).await
    }

    /// Send a DELETE request to the given URL.
    pub async fn delete(&self, url: &str) -> Result<Response, ClientError> {
        self.request(Method::Delete, url, Vec::new(), Vec::new())
            .await
    }

    /// Send a request with the given method, URL, headers, and body.
    pub async fn request(
        &self,
        method: Method,
        url: &str,
        extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<Response, ClientError> {
        let parsed = ParsedUrl::parse(url)?;
        self.execute_with_redirects(method, parsed, extra_headers, body, 0)
            .await
    }

    /// Send a request and stream the response body.
    pub async fn request_streaming(
        &self,
        method: Method,
        url: &str,
        extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<ClientStreamingResponse<ClientIo>, ClientError> {
        let parsed = ParsedUrl::parse(url)?;
        self.execute_with_redirects_streaming(method, parsed, extra_headers, body, 0)
            .await
    }

    /// Execute a request, following redirects as configured.
    fn execute_with_redirects(
        &self,
        method: Method,
        parsed: ParsedUrl,
        extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
        redirect_count: u32,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Response, ClientError>> + Send + '_>,
    > {
        Box::pin(async move {
            let resp = self
                .execute_single(&method, &parsed, &extra_headers, &body)
                .await?;

            // Check for redirect
            if is_redirect(resp.status) {
                match &self.config.redirect_policy {
                    RedirectPolicy::None => return Ok(resp),
                    RedirectPolicy::Limited(max) => {
                        if redirect_count >= *max {
                            return Err(ClientError::TooManyRedirects {
                                count: redirect_count + 1,
                                max: *max,
                            });
                        }

                        if let Some(location) = get_header(&resp.headers, "Location") {
                            let next_url = resolve_redirect(&parsed, &location);
                            let next_parsed = ParsedUrl::parse(&next_url)?;

                            // 303 See Other always converts to GET
                            // 301/302 traditionally convert to GET for POST
                            let next_method = redirect_method(resp.status, &method);
                            let next_body = if next_method == Method::Get {
                                Vec::new()
                            } else {
                                body
                            };

                            return self
                                .execute_with_redirects(
                                    next_method,
                                    next_parsed,
                                    extra_headers,
                                    next_body,
                                    redirect_count + 1,
                                )
                                .await;
                        }
                    }
                }
            }

            Ok(resp)
        })
    }

    /// Execute a request (streaming), following redirects as configured.
    fn execute_with_redirects_streaming(
        &self,
        method: Method,
        parsed: ParsedUrl,
        extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
        redirect_count: u32,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<ClientStreamingResponse<ClientIo>, ClientError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let resp = self
                .execute_single_streaming(&method, &parsed, &extra_headers, &body)
                .await?;

            // Check for redirect
            if is_redirect(resp.head.status) {
                match &self.config.redirect_policy {
                    RedirectPolicy::None => return Ok(resp),
                    RedirectPolicy::Limited(max) => {
                        if redirect_count >= *max {
                            return Err(ClientError::TooManyRedirects {
                                count: redirect_count + 1,
                                max: *max,
                            });
                        }

                        if let Some(location) = get_header(&resp.head.headers, "Location") {
                            let status = resp.head.status;
                            // Drop streaming response (closes connection) before following.
                            drop(resp);

                            let next_url = resolve_redirect(&parsed, &location);
                            let next_parsed = ParsedUrl::parse(&next_url)?;

                            // 303 See Other always converts to GET
                            // 301/302 traditionally convert to GET for POST
                            let next_method = redirect_method(status, &method);
                            let next_body = if next_method == Method::Get {
                                Vec::new()
                            } else {
                                body
                            };

                            return self
                                .execute_with_redirects_streaming(
                                    next_method,
                                    next_parsed,
                                    extra_headers,
                                    next_body,
                                    redirect_count + 1,
                                )
                                .await;
                        }
                    }
                }
            }

            Ok(resp)
        })
    }

    /// Execute a single request (no redirect handling).
    async fn execute_single(
        &self,
        method: &Method,
        parsed: &ParsedUrl,
        extra_headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Response, ClientError> {
        // Build the request
        let mut headers = Vec::new();
        headers.push(("Host".to_owned(), parsed.authority()));

        if let Some(ref ua) = self.config.user_agent {
            headers.push(("User-Agent".to_owned(), ua.clone()));
        }

        for (name, value) in extra_headers {
            headers.push((name.clone(), value.clone()));
        }

        let req = Request {
            method: method.clone(),
            uri: parsed.path.clone(),
            version: Version::Http11,
            headers,
            body: body.to_vec(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        // Connect and send
        let stream = self.connect_io(parsed).await?;
        let resp = Http1Client::request(stream, req).await?;
        Ok(resp)
    }

    /// Execute a single request (streaming; no redirect handling).
    async fn execute_single_streaming(
        &self,
        method: &Method,
        parsed: &ParsedUrl,
        extra_headers: &[(String, String)],
        body: &[u8],
    ) -> Result<ClientStreamingResponse<ClientIo>, ClientError> {
        // Build the request
        let mut headers = Vec::new();
        headers.push(("Host".to_owned(), parsed.authority()));

        if let Some(ref ua) = self.config.user_agent {
            headers.push(("User-Agent".to_owned(), ua.clone()));
        }

        for (name, value) in extra_headers {
            headers.push((name.clone(), value.clone()));
        }

        let req = Request {
            method: method.clone(),
            uri: parsed.path.clone(),
            version: Version::Http11,
            headers,
            body: body.to_vec(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let stream = self.connect_io(parsed).await?;
        let resp = Http1Client::request_streaming(stream, req).await?;
        Ok(resp)
    }

    async fn connect_io(&self, parsed: &ParsedUrl) -> Result<ClientIo, ClientError> {
        let addr = format!("{}:{}", parsed.host, parsed.port);
        let stream = TcpStream::connect(addr)
            .await
            .map_err(ClientError::ConnectError)?;

        match parsed.scheme {
            Scheme::Http => Ok(ClientIo::Plain(stream)),
            Scheme::Https => {
                #[cfg(feature = "tls")]
                {
                    let domain = parsed.host.trim_start_matches('[').trim_end_matches(']');

                    let builder = TlsConnectorBuilder::new().alpn_http();

                    #[cfg(feature = "tls-native-roots")]
                    let builder = builder
                        .with_native_roots()
                        .map_err(|e| ClientError::TlsError(e.to_string()))?;

                    #[cfg(all(not(feature = "tls-native-roots"), feature = "tls-webpki-roots"))]
                    let builder = builder.with_webpki_roots();

                    let connector = builder
                        .build()
                        .map_err(|e| ClientError::TlsError(e.to_string()))?;

                    let tls = connector
                        .connect(domain, stream)
                        .await
                        .map_err(|e| ClientError::TlsError(e.to_string()))?;

                    Ok(ClientIo::Tls(tls))
                }
                #[cfg(not(feature = "tls"))]
                {
                    let _ = stream;
                    Err(ClientError::TlsError(
                        "TLS support is disabled (enable asupersync feature \"tls\")".into(),
                    ))
                }
            }
        }
    }

    /// Returns current pool statistics.
    pub fn pool_stats(&self) -> crate::http::pool::PoolStats {
        self.pool.lock().expect("pool lock").stats()
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true if the status code is a redirect.
fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Get the first value for a header name (case-insensitive).
fn get_header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// Determine the method for the redirected request.
fn redirect_method(status: u16, original: &Method) -> Method {
    match status {
        // 303 See Other: always GET
        303 => Method::Get,
        // 301/302: convert POST to GET (traditional browser behavior)
        301 | 302 if *original == Method::Post => Method::Get,
        // 307/308 preserve method; all others preserve too
        _ => original.clone(),
    }
}

/// Resolve a redirect Location header relative to the current URL.
fn resolve_redirect(current: &ParsedUrl, location: &str) -> String {
    // Absolute URL
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_owned();
    }

    // Protocol-relative
    if let Some(rest) = location.strip_prefix("//") {
        return match current.scheme {
            Scheme::Http => format!("http://{rest}"),
            Scheme::Https => format!("https://{rest}"),
        };
    }

    // Absolute path
    if location.starts_with('/') {
        let scheme = match current.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        return format!("{scheme}://{}:{}{location}", current.host, current.port);
    }

    // Relative path (append to current path's directory)
    let base_path = current.path.rfind('/').map_or("/", |i| &current.path[..=i]);
    let scheme = match current.scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    };
    format!(
        "{scheme}://{}:{}{base_path}{location}",
        current.host, current.port
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // URL parsing
    // =========================================================================

    #[test]
    fn parse_http_url() {
        let url = ParsedUrl::parse("http://example.com/path").unwrap();
        assert_eq!(url.scheme, Scheme::Http);
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 80);
        assert_eq!(url.path, "/path");
    }

    #[test]
    fn parse_https_url() {
        let url = ParsedUrl::parse("https://example.com/api/v1").unwrap();
        assert_eq!(url.scheme, Scheme::Https);
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 443);
        assert_eq!(url.path, "/api/v1");
    }

    #[test]
    fn parse_url_with_port() {
        let url = ParsedUrl::parse("http://localhost:8080/test").unwrap();
        assert_eq!(url.host, "localhost");
        assert_eq!(url.port, 8080);
        assert_eq!(url.path, "/test");
    }

    #[test]
    fn parse_url_no_path() {
        let url = ParsedUrl::parse("http://example.com").unwrap();
        assert_eq!(url.path, "/");
    }

    #[test]
    fn parse_url_with_query() {
        let url = ParsedUrl::parse("http://example.com/search?q=test&page=1").unwrap();
        assert_eq!(url.path, "/search?q=test&page=1");
    }

    #[test]
    fn parse_url_invalid_scheme() {
        let result = ParsedUrl::parse("ftp://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn parse_url_empty_host() {
        let result = ParsedUrl::parse("http:///path");
        assert!(result.is_err());
    }

    #[test]
    fn parse_url_invalid_port() {
        let result = ParsedUrl::parse("http://example.com:abc/path");
        assert!(result.is_err());
    }

    // =========================================================================
    // Pool key
    // =========================================================================

    #[test]
    fn pool_key_from_http_url() {
        let url = ParsedUrl::parse("http://example.com/path").unwrap();
        let key = url.pool_key();
        assert_eq!(key.host, "example.com");
        assert_eq!(key.port, 80);
        assert!(!key.is_https);
    }

    #[test]
    fn pool_key_from_https_url() {
        let url = ParsedUrl::parse("https://example.com/path").unwrap();
        let key = url.pool_key();
        assert_eq!(key.host, "example.com");
        assert_eq!(key.port, 443);
        assert!(key.is_https);
    }

    // =========================================================================
    // Authority
    // =========================================================================

    #[test]
    fn authority_default_port_omitted() {
        let url = ParsedUrl::parse("http://example.com/path").unwrap();
        assert_eq!(url.authority(), "example.com");

        let url = ParsedUrl::parse("https://example.com/path").unwrap();
        assert_eq!(url.authority(), "example.com");
    }

    #[test]
    fn authority_custom_port_included() {
        let url = ParsedUrl::parse("http://example.com:8080/path").unwrap();
        assert_eq!(url.authority(), "example.com:8080");
    }

    // =========================================================================
    // Redirect detection
    // =========================================================================

    #[test]
    fn is_redirect_detects_all_codes() {
        assert!(is_redirect(301));
        assert!(is_redirect(302));
        assert!(is_redirect(303));
        assert!(is_redirect(307));
        assert!(is_redirect(308));
        assert!(!is_redirect(200));
        assert!(!is_redirect(404));
        assert!(!is_redirect(500));
        assert!(!is_redirect(304)); // Not Modified is NOT a redirect
    }

    // =========================================================================
    // Redirect method transformation
    // =========================================================================

    #[test]
    fn redirect_method_303_always_get() {
        assert_eq!(redirect_method(303, &Method::Post), Method::Get);
        assert_eq!(redirect_method(303, &Method::Put), Method::Get);
        assert_eq!(redirect_method(303, &Method::Get), Method::Get);
    }

    #[test]
    fn redirect_method_307_preserves() {
        assert_eq!(redirect_method(307, &Method::Post), Method::Post);
        assert_eq!(redirect_method(307, &Method::Get), Method::Get);
        assert_eq!(redirect_method(307, &Method::Put), Method::Put);
    }

    #[test]
    fn redirect_method_308_preserves() {
        assert_eq!(redirect_method(308, &Method::Post), Method::Post);
        assert_eq!(redirect_method(308, &Method::Delete), Method::Delete);
    }

    #[test]
    fn redirect_method_301_post_becomes_get() {
        assert_eq!(redirect_method(301, &Method::Post), Method::Get);
        assert_eq!(redirect_method(301, &Method::Get), Method::Get);
    }

    #[test]
    fn redirect_method_302_post_becomes_get() {
        assert_eq!(redirect_method(302, &Method::Post), Method::Get);
        assert_eq!(redirect_method(302, &Method::Get), Method::Get);
    }

    // =========================================================================
    // Redirect URL resolution
    // =========================================================================

    #[test]
    fn resolve_absolute_redirect() {
        let current = ParsedUrl::parse("http://example.com/old").unwrap();
        let result = resolve_redirect(&current, "https://other.com/new");
        assert_eq!(result, "https://other.com/new");
    }

    #[test]
    fn resolve_protocol_relative_redirect() {
        let current = ParsedUrl::parse("https://example.com/old").unwrap();
        let result = resolve_redirect(&current, "//cdn.example.com/asset");
        assert_eq!(result, "https://cdn.example.com/asset");
    }

    #[test]
    fn resolve_absolute_path_redirect() {
        let current = ParsedUrl::parse("http://example.com:8080/old/page").unwrap();
        let result = resolve_redirect(&current, "/new/page");
        assert_eq!(result, "http://example.com:8080/new/page");
    }

    #[test]
    fn resolve_relative_path_redirect() {
        let current = ParsedUrl::parse("http://example.com/dir/old").unwrap();
        let result = resolve_redirect(&current, "new");
        assert_eq!(result, "http://example.com:80/dir/new");
    }

    // =========================================================================
    // Header lookup
    // =========================================================================

    #[test]
    fn get_header_case_insensitive() {
        let headers = vec![
            ("Content-Type".into(), "text/html".into()),
            ("location".into(), "/new".into()),
        ];
        assert_eq!(get_header(&headers, "Location"), Some("/new".into()));
        assert_eq!(get_header(&headers, "LOCATION"), Some("/new".into()));
        assert_eq!(
            get_header(&headers, "content-type"),
            Some("text/html".into())
        );
        assert_eq!(get_header(&headers, "X-Missing"), None);
    }

    // =========================================================================
    // Client error display
    // =========================================================================

    #[test]
    fn client_error_display() {
        let err = ClientError::InvalidUrl("bad".into());
        assert!(format!("{err}").contains("bad"));

        let err = ClientError::TooManyRedirects { count: 5, max: 10 };
        let msg = format!("{err}");
        assert!(msg.contains('5'));
        assert!(msg.contains("10"));
    }

    #[test]
    fn client_error_source() {
        use std::error::Error;

        let err = ClientError::InvalidUrl("x".into());
        assert!(err.source().is_none());

        let io_err = io::Error::other("test");
        let err = ClientError::Io(io_err);
        assert!(err.source().is_some());
    }

    // =========================================================================
    // Client config defaults
    // =========================================================================

    #[test]
    fn default_config() {
        let config = HttpClientConfig::default();
        assert!(matches!(
            config.redirect_policy,
            RedirectPolicy::Limited(10)
        ));
        assert_eq!(config.user_agent, Some("asupersync/0.1".into()));
    }

    #[test]
    fn client_default_creates_pool() {
        let client = HttpClient::new();
        let stats = client.pool_stats();
        assert_eq!(stats.total_connections, 0);
    }

    // =========================================================================
    // Redirect policy
    // =========================================================================

    #[test]
    fn redirect_policy_default_is_limited() {
        let policy = RedirectPolicy::default();
        assert!(matches!(policy, RedirectPolicy::Limited(10)));
    }
}
