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
//! let cx = Cx::for_testing();
//! let resp = client.get(&cx, "http://example.com/api").await?;
//! assert_eq!(resp.status, 200);
//! ```

use crate::cx::Cx;
use crate::http::h1::client::{ClientStreamingResponse, Http1Client};
use crate::http::h1::types::{Method, MultipartForm, Request, Response, Version};
use crate::http::pool::{Pool, PoolConfig, PoolKey};
use crate::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use crate::net::tcp::stream::TcpStream;
#[cfg(feature = "tls")]
use crate::tls::{TlsConnectorBuilder, TlsStream};
use crate::types::Time;
use base64::Engine;
use memchr::memmem;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fmt::Write;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

const CONNECT_MAX_HEADERS_SIZE: usize = 64 * 1024;
/// Maximum number of cookies stored per host (RFC 6265 recommends at least 50).
const MAX_COOKIES_PER_HOST: usize = 64;
/// Maximum number of hosts tracked in the cookie store.
const MAX_COOKIE_HOSTS: usize = 256;
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_AUTH_USER_PASS: u8 = 0x02;
const SOCKS5_AUTH_NO_ACCEPTABLE: u8 = 0xFF;

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
    /// HTTP CONNECT tunnel was rejected by the proxy endpoint.
    ConnectTunnelRefused {
        /// HTTP status code returned by the proxy.
        status: u16,
        /// Reason phrase returned by the proxy.
        reason: String,
    },
    /// Invalid CONNECT target authority or header input.
    InvalidConnectInput(String),
    /// Proxy negotiation failed.
    ProxyError(String),
    /// The operation was cancelled via the Cx cancellation protocol.
    Cancelled,
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
            Self::ConnectTunnelRefused { status, reason } => {
                write!(
                    f,
                    "HTTP CONNECT tunnel rejected with status {status} ({reason})"
                )
            }
            Self::InvalidConnectInput(msg) => write!(f, "invalid CONNECT input: {msg}"),
            Self::ProxyError(msg) => write!(f, "proxy error: {msg}"),
            Self::Cancelled => write!(f, "operation cancelled"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DnsError(e) | Self::ConnectError(e) | Self::Io(e) => Some(e),
            Self::HttpError(e) => Some(e),
            Self::ConnectTunnelRefused { .. }
            | Self::InvalidConnectInput(_)
            | Self::ProxyError(_)
            | Self::TlsError(_)
            | Self::InvalidUrl(_)
            | Self::TooManyRedirects { .. }
            | Self::Cancelled => None,
        }
    }
}

impl ClientError {
    /// Returns `true` if this error represents a cancellation.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

/// Check if the Cx has been cancelled and return `ClientError::Cancelled` if so.
fn check_cx(cx: &Cx) -> Result<(), ClientError> {
    if cx.is_cancel_requested() {
        Err(ClientError::Cancelled)
    } else {
        Ok(())
    }
}

fn wall_clock_now() -> Time {
    crate::time::wall_now()
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
#[allow(clippy::large_enum_variant)]
pub enum ClientIo {
    /// Plain TCP stream.
    Plain(TcpStream),
    /// TLS-wrapped TCP stream.
    #[cfg(feature = "tls")]
    Tls(TlsStream<TcpStream>),
    /// TLS over an HTTP CONNECT tunnel.
    #[cfg(feature = "tls")]
    TlsTunnel(Box<TlsStream<HttpConnectTunnel<ClientIo>>>),
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
            #[cfg(feature = "tls")]
            Self::TlsTunnel(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
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
            #[cfg(feature = "tls")]
            Self::TlsTunnel(s) => Pin::new(s.as_mut()).poll_write(cx, data),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "tls")]
            Self::TlsTunnel(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            Self::TlsTunnel(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Established HTTP CONNECT tunnel.
///
/// The tunnel preserves any bytes that were already read after the `\r\n\r\n`
/// response delimiter and serves them first on reads before delegating to the
/// underlying transport.
#[derive(Debug)]
pub struct HttpConnectTunnel<T> {
    io: T,
    prefetched: Vec<u8>,
    prefetched_pos: usize,
}

impl<T> HttpConnectTunnel<T> {
    fn new(io: T, prefetched: Vec<u8>) -> Self {
        Self {
            io,
            prefetched,
            prefetched_pos: 0,
        }
    }

    /// Number of prefetched bytes that still need to be drained.
    #[must_use]
    pub fn prefetched_len(&self) -> usize {
        self.prefetched.len().saturating_sub(self.prefetched_pos)
    }

    /// Consume the wrapper and return the underlying transport.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.io
    }
}

impl<T> AsyncRead for HttpConnectTunnel<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefetched_pos < self.prefetched.len() && buf.remaining() > 0 {
            let remaining_prefetched = self.prefetched.len() - self.prefetched_pos;
            let to_copy = remaining_prefetched.min(buf.remaining());
            buf.put_slice(&self.prefetched[self.prefetched_pos..self.prefetched_pos + to_copy]);
            self.prefetched_pos += to_copy;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for HttpConnectTunnel<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
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

        // RFC 3986: authority ends at the first '/', '?', or '#'.
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let path_and_rest = &rest[authority_end..];
        let path = if path_and_rest.is_empty() {
            "/"
        } else {
            path_and_rest
        };

        // Reject userinfo (user:pass@host) per RFC 9110 Section 4.2.4.
        // Forwarding credentials in the URL to the Host header can cause
        // header injection or SSRF-like confusion in proxies.
        if authority.contains('@') && !authority.starts_with('[') {
            return Err(ClientError::InvalidUrl(
                "URL must not contain userinfo (user@host)".into(),
            ));
        }

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

/// Builder for [`HttpClient`].
///
/// This provides a reqwest-style fluent API for configuring the high-level
/// HTTP client and its underlying connection pool defaults.
#[derive(Debug, Clone, Default)]
pub struct HttpClientBuilder {
    config: HttpClientConfig,
}

impl HttpClientBuilder {
    /// Creates a builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the full pool configuration.
    #[must_use]
    pub fn pool_config(mut self, pool_config: PoolConfig) -> Self {
        self.config.pool_config = pool_config;
        self
    }

    /// Sets max pooled connections per host.
    #[must_use]
    pub fn max_connections_per_host(mut self, max: usize) -> Self {
        self.config.pool_config.max_connections_per_host = max;
        self
    }

    /// Sets max pooled connections across all hosts.
    #[must_use]
    pub fn max_total_connections(mut self, max: usize) -> Self {
        self.config.pool_config.max_total_connections = max;
        self
    }

    /// Sets idle timeout for pooled connections.
    #[must_use]
    pub fn idle_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.config.pool_config.idle_timeout = timeout;
        self
    }

    /// Sets cleanup interval for idle pooled connections.
    #[must_use]
    pub fn cleanup_interval(mut self, interval: std::time::Duration) -> Self {
        self.config.pool_config.cleanup_interval = interval;
        self
    }

    /// Sets redirect behavior.
    #[must_use]
    pub fn redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.config.redirect_policy = policy;
        self
    }

    /// Follows up to `max` redirects.
    #[must_use]
    pub fn max_redirects(mut self, max: u32) -> Self {
        self.config.redirect_policy = RedirectPolicy::Limited(max);
        self
    }

    /// Disables automatic redirect following.
    #[must_use]
    pub fn no_redirects(mut self) -> Self {
        self.config.redirect_policy = RedirectPolicy::None;
        self
    }

    /// Sets default `User-Agent`.
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.config.user_agent = Some(user_agent.into());
        self
    }

    /// Removes default `User-Agent`.
    #[must_use]
    pub fn no_user_agent(mut self) -> Self {
        self.config.user_agent = None;
        self
    }

    /// Enables/disables automatic cookie persistence and attachment.
    #[must_use]
    pub fn cookie_store(mut self, enabled: bool) -> Self {
        self.config.cookie_store = enabled;
        self
    }

    /// Disables automatic cookie persistence and attachment.
    #[must_use]
    pub fn no_cookie_store(mut self) -> Self {
        self.config.cookie_store = false;
        self
    }

    /// Routes requests through a proxy endpoint.
    ///
    /// Supported URL schemes: `http://`, `https://`, and `socks5://`.
    #[must_use]
    pub fn proxy(mut self, proxy_url: impl Into<String>) -> Self {
        self.config.proxy_url = Some(proxy_url.into());
        self
    }

    /// Disables proxy routing.
    #[must_use]
    pub fn no_proxy(mut self) -> Self {
        self.config.proxy_url = None;
        self
    }

    /// Sets a custom time source for deterministic pool timestamps.
    #[must_use]
    pub fn with_time_getter(mut self, time_getter: fn() -> Time) -> Self {
        self.config.time_getter = time_getter;
        self
    }

    /// Builds the [`HttpClient`].
    #[must_use]
    pub fn build(self) -> HttpClient {
        HttpClient::with_config(self.config)
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
    /// Whether the client should automatically persist and attach cookies.
    pub cookie_store: bool,
    /// Optional proxy URL used for outbound requests.
    pub proxy_url: Option<String>,
    /// Time source used for pool bookkeeping.
    time_getter: fn() -> Time,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            pool_config: PoolConfig::default(),
            redirect_policy: RedirectPolicy::default(),
            user_agent: Some("asupersync/0.1".into()),
            cookie_store: false,
            proxy_url: None,
            time_getter: wall_clock_now,
        }
    }
}

impl HttpClientConfig {
    /// Sets a custom time source for deterministic pool timestamps.
    #[must_use]
    pub const fn with_time_getter(mut self, time_getter: fn() -> Time) -> Self {
        self.time_getter = time_getter;
        self
    }

    /// Returns the time source used for pool bookkeeping.
    #[must_use]
    pub const fn time_getter(&self) -> fn() -> Time {
        self.time_getter
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
    idle_connections: Mutex<HashMap<PoolKey, Vec<(u64, ClientIo)>>>,
    cookies: Mutex<HashMap<String, Vec<StoredCookie>>>,
}

impl HttpClient {
    /// Create a new [`HttpClientBuilder`].
    #[must_use]
    pub fn builder() -> HttpClientBuilder {
        HttpClientBuilder::new()
    }

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
            idle_connections: Mutex::new(HashMap::new()),
            cookies: Mutex::new(HashMap::new()),
        }
    }

    fn pool_now(&self) -> Time {
        (self.config.time_getter)()
    }

    /// Send a GET request to the given URL.
    ///
    /// The `cx` parameter participates in structured cancellation: if the
    /// context is cancelled, the in-flight request is abandoned and
    /// `ClientError::Cancelled` is returned.
    pub async fn get(&self, cx: &Cx, url: &str) -> Result<Response, ClientError> {
        self.request(cx, Method::Get, url, Vec::new(), Vec::new())
            .await
    }

    /// Send a POST request to the given URL with a body.
    pub async fn post(&self, cx: &Cx, url: &str, body: Vec<u8>) -> Result<Response, ClientError> {
        self.request(cx, Method::Post, url, Vec::new(), body).await
    }

    /// Send a POST multipart form-data request.
    pub async fn post_multipart(
        &self,
        cx: &Cx,
        url: &str,
        form: &MultipartForm,
    ) -> Result<Response, ClientError> {
        self.request_multipart(cx, Method::Post, url, Vec::new(), form)
            .await
    }

    /// Send a POST request and stream the response body.
    pub async fn post_streaming(
        &self,
        cx: &Cx,
        url: &str,
        body: Vec<u8>,
    ) -> Result<ClientStreamingResponse<ClientIo>, ClientError> {
        self.request_streaming(cx, Method::Post, url, Vec::new(), body)
            .await
    }

    /// Send a POST multipart form-data request and stream the response body.
    pub async fn post_multipart_streaming(
        &self,
        cx: &Cx,
        url: &str,
        form: &MultipartForm,
    ) -> Result<ClientStreamingResponse<ClientIo>, ClientError> {
        self.request_multipart_streaming(cx, Method::Post, url, Vec::new(), form)
            .await
    }

    /// Send a PUT request to the given URL with a body.
    pub async fn put(&self, cx: &Cx, url: &str, body: Vec<u8>) -> Result<Response, ClientError> {
        self.request(cx, Method::Put, url, Vec::new(), body).await
    }

    /// Send a DELETE request to the given URL.
    pub async fn delete(&self, cx: &Cx, url: &str) -> Result<Response, ClientError> {
        self.request(cx, Method::Delete, url, Vec::new(), Vec::new())
            .await
    }

    /// Send a request with the given method, URL, headers, and body.
    ///
    /// The `cx` parameter participates in structured cancellation: the
    /// cancellation flag is checked before connection establishment, after
    /// TCP connect, after TLS handshake, and before/after the HTTP
    /// request/response exchange.  If cancelled, returns
    /// `ClientError::Cancelled`.
    pub async fn request(
        &self,
        cx: &Cx,
        method: Method,
        url: &str,
        extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<Response, ClientError> {
        check_cx(cx)?;
        let parsed = ParsedUrl::parse(url)?;
        self.execute_with_redirects(cx, method, parsed, extra_headers, body, 0)
            .await
    }

    /// Send a request with multipart form-data body.
    pub async fn request_multipart(
        &self,
        cx: &Cx,
        method: Method,
        url: &str,
        mut extra_headers: Vec<(String, String)>,
        form: &MultipartForm,
    ) -> Result<Response, ClientError> {
        ensure_multipart_content_type(&mut extra_headers, form);
        self.request(cx, method, url, extra_headers, form.to_body())
            .await
    }

    /// Send a request and stream the response body.
    pub async fn request_streaming(
        &self,
        cx: &Cx,
        method: Method,
        url: &str,
        extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<ClientStreamingResponse<ClientIo>, ClientError> {
        check_cx(cx)?;
        let parsed = ParsedUrl::parse(url)?;
        self.execute_with_redirects_streaming(cx, method, parsed, extra_headers, body, 0)
            .await
    }

    /// Send a multipart request and stream the response body.
    pub async fn request_multipart_streaming(
        &self,
        cx: &Cx,
        method: Method,
        url: &str,
        mut extra_headers: Vec<(String, String)>,
        form: &MultipartForm,
    ) -> Result<ClientStreamingResponse<ClientIo>, ClientError> {
        ensure_multipart_content_type(&mut extra_headers, form);
        self.request_streaming(cx, method, url, extra_headers, form.to_body())
            .await
    }

    /// Establish an HTTP/1.1 CONNECT tunnel through a proxy endpoint.
    ///
    /// `proxy_url` is the proxy server URL (e.g. `http://proxy.local:3128`).
    /// `target_authority` is the requested CONNECT authority-form target
    /// (e.g. `example.com:443`).
    pub async fn connect_tunnel(
        &self,
        cx: &Cx,
        proxy_url: &str,
        target_authority: &str,
        extra_headers: Vec<(String, String)>,
    ) -> Result<HttpConnectTunnel<ClientIo>, ClientError> {
        check_cx(cx)?;
        let proxy = ParsedUrl::parse(proxy_url)?;
        let io = self.connect_io(cx, &proxy).await?;
        establish_http_connect_tunnel(
            io,
            target_authority,
            self.config.user_agent.as_deref(),
            &extra_headers,
        )
        .await
    }

    /// Execute a request, following redirects as configured.
    fn execute_with_redirects<'a>(
        &'a self,
        cx: &'a Cx,
        method: Method,
        parsed: ParsedUrl,
        extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
        redirect_count: u32,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Response, ClientError>> + Send + 'a>,
    > {
        Box::pin(async move {
            check_cx(cx)?;
            let resp = self
                .execute_single(cx, &method, &parsed, &extra_headers, &body)
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

                            // Strip sensitive headers on cross-origin redirect
                            let next_headers = strip_sensitive_headers_on_redirect(
                                &parsed,
                                &next_parsed,
                                extra_headers,
                            );

                            return self
                                .execute_with_redirects(
                                    cx,
                                    next_method,
                                    next_parsed,
                                    next_headers,
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
    fn execute_with_redirects_streaming<'a>(
        &'a self,
        cx: &'a Cx,
        method: Method,
        parsed: ParsedUrl,
        extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
        redirect_count: u32,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<ClientStreamingResponse<ClientIo>, ClientError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            check_cx(cx)?;
            let resp = self
                .execute_single_streaming(cx, &method, &parsed, &extra_headers, &body)
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

                            // Strip sensitive headers on cross-origin redirect
                            let next_headers = strip_sensitive_headers_on_redirect(
                                &parsed,
                                &next_parsed,
                                extra_headers,
                            );

                            return self
                                .execute_with_redirects_streaming(
                                    cx,
                                    next_method,
                                    next_parsed,
                                    next_headers,
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
        cx: &Cx,
        method: &Method,
        parsed: &ParsedUrl,
        extra_headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Response, ClientError> {
        check_cx(cx)?;
        if let Some(proxy_url) = self.config.proxy_url.as_deref() {
            return self
                .execute_single_with_proxy(cx, method, parsed, extra_headers, body, proxy_url)
                .await;
        }

        let req = self.build_request(method, parsed, extra_headers, body, None, None);

        let key = parsed.pool_key();
        let acquired = self.acquire_connection(cx, parsed).await?;
        let mut guard = ConnectionGuard::new(self, key.clone(), acquired.pool_id);
        let reused_connection = !acquired.fresh;

        // Check cancellation after connection acquisition.
        check_cx(cx)?;

        match Http1Client::request_with_io(acquired.io, req).await {
            Ok((response, io)) => {
                guard.defused = true;
                self.store_response_cookies(&parsed.host, &response.headers);
                if connection_can_be_reused(&response, method) {
                    self.release_connection(&key, acquired.pool_id, acquired.fresh, io);
                } else {
                    self.drop_connection(&key, acquired.pool_id);
                }
                Ok(response)
            }
            Err(err) => {
                let err = ClientError::from(err);
                if reused_connection && should_retry_reused_connection_failure(method, &err) {
                    drop(guard);
                    return self
                        .retry_single_request_on_fresh_connection(
                            cx,
                            method,
                            parsed,
                            extra_headers,
                            body,
                        )
                        .await;
                }
                // guard drops the connection on return
                Err(err)
            }
        }
    }

    async fn retry_single_request_on_fresh_connection(
        &self,
        cx: &Cx,
        method: &Method,
        parsed: &ParsedUrl,
        extra_headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Response, ClientError> {
        let req = self.build_request(method, parsed, extra_headers, body, None, None);
        let key = parsed.pool_key();
        let acquired = self.acquire_connection(cx, parsed).await?;
        let mut guard = ConnectionGuard::new(self, key.clone(), acquired.pool_id);

        check_cx(cx)?;

        match Http1Client::request_with_io(acquired.io, req).await {
            Ok((response, io)) => {
                guard.defused = true;
                self.store_response_cookies(&parsed.host, &response.headers);
                if connection_can_be_reused(&response, method) {
                    self.release_connection(&key, acquired.pool_id, acquired.fresh, io);
                } else {
                    self.drop_connection(&key, acquired.pool_id);
                }
                Ok(response)
            }
            Err(err) => Err(ClientError::from(err)),
        }
    }

    /// Execute a single request (streaming; no redirect handling).
    async fn execute_single_streaming(
        &self,
        cx: &Cx,
        method: &Method,
        parsed: &ParsedUrl,
        extra_headers: &[(String, String)],
        body: &[u8],
    ) -> Result<ClientStreamingResponse<ClientIo>, ClientError> {
        check_cx(cx)?;
        if let Some(proxy_url) = self.config.proxy_url.as_deref() {
            return self
                .execute_single_streaming_with_proxy(
                    cx,
                    method,
                    parsed,
                    extra_headers,
                    body,
                    proxy_url,
                )
                .await;
        }

        let req = self.build_request(method, parsed, extra_headers, body, None, None);

        let stream = self.connect_io(cx, parsed).await?;
        check_cx(cx)?;
        let resp = Http1Client::request_streaming(stream, req).await?;
        self.store_response_cookies(&parsed.host, &resp.head.headers);
        Ok(resp)
    }

    async fn execute_single_with_proxy(
        &self,
        cx: &Cx,
        method: &Method,
        parsed: &ParsedUrl,
        extra_headers: &[(String, String)],
        body: &[u8],
        proxy_url: &str,
    ) -> Result<Response, ClientError> {
        check_cx(cx)?;
        let proxy = parse_proxy_endpoint(proxy_url)?;
        let proxy_conn = self.connect_via_proxy(cx, parsed, &proxy).await?;
        check_cx(cx)?;
        let request_target = if proxy_conn.use_absolute_form {
            Some(absolute_request_target(parsed))
        } else {
            None
        };
        let req = self.build_request(
            method,
            parsed,
            extra_headers,
            body,
            request_target,
            proxy_conn.proxy_authorization.as_deref(),
        );
        let (response, _io) = Http1Client::request_with_io(proxy_conn.io, req).await?;
        self.store_response_cookies(&parsed.host, &response.headers);
        Ok(response)
    }

    async fn execute_single_streaming_with_proxy(
        &self,
        cx: &Cx,
        method: &Method,
        parsed: &ParsedUrl,
        extra_headers: &[(String, String)],
        body: &[u8],
        proxy_url: &str,
    ) -> Result<ClientStreamingResponse<ClientIo>, ClientError> {
        check_cx(cx)?;
        let proxy = parse_proxy_endpoint(proxy_url)?;
        let proxy_conn = self.connect_via_proxy(cx, parsed, &proxy).await?;
        check_cx(cx)?;
        let request_target = if proxy_conn.use_absolute_form {
            Some(absolute_request_target(parsed))
        } else {
            None
        };
        let req = self.build_request(
            method,
            parsed,
            extra_headers,
            body,
            request_target,
            proxy_conn.proxy_authorization.as_deref(),
        );
        let resp = Http1Client::request_streaming(proxy_conn.io, req).await?;
        self.store_response_cookies(&parsed.host, &resp.head.headers);
        Ok(resp)
    }

    async fn connect_via_proxy(
        &self,
        cx: &Cx,
        parsed: &ParsedUrl,
        proxy: &ProxyEndpoint,
    ) -> Result<ProxyConnection, ClientError> {
        match proxy.scheme {
            ProxyScheme::Http | ProxyScheme::Https => {
                let proxy_parsed = ParsedUrl {
                    scheme: match proxy.scheme {
                        ProxyScheme::Http => Scheme::Http,
                        ProxyScheme::Https => Scheme::Https,
                        ProxyScheme::Socks5 => unreachable!(),
                    },
                    host: proxy.host.clone(),
                    port: proxy.port,
                    path: "/".to_owned(),
                };
                let proxy_io = self.connect_io(cx, &proxy_parsed).await?;

                if parsed.scheme == Scheme::Http {
                    return Ok(ProxyConnection {
                        io: proxy_io,
                        use_absolute_form: true,
                        proxy_authorization: proxy
                            .http_proxy_authorization()
                            .map(std::borrow::ToOwned::to_owned),
                    });
                }

                let mut connect_headers = Vec::new();
                if let Some(auth) = proxy.http_proxy_authorization() {
                    connect_headers.push(("Proxy-Authorization".to_owned(), auth.to_owned()));
                }
                let tunnel = establish_http_connect_tunnel(
                    proxy_io,
                    &parsed.authority(),
                    self.config.user_agent.as_deref(),
                    &connect_headers,
                )
                .await?;

                #[cfg(feature = "tls")]
                {
                    let domain = parsed.host.trim_start_matches('[').trim_end_matches(']');
                    let tls = self.tls_connect_stream(domain, tunnel).await?;
                    return Ok(ProxyConnection {
                        io: ClientIo::TlsTunnel(Box::new(tls)),
                        use_absolute_form: false,
                        proxy_authorization: None,
                    });
                }
                #[cfg(not(feature = "tls"))]
                {
                    let _ = tunnel;
                    Err(ClientError::TlsError(
                        "TLS support is disabled (enable asupersync feature \"tls\")".into(),
                    ))
                }
            }
            ProxyScheme::Socks5 => {
                let tcp = connect_via_socks5(proxy, parsed, cx).await?;
                if parsed.scheme == Scheme::Http {
                    return Ok(ProxyConnection {
                        io: ClientIo::Plain(tcp),
                        use_absolute_form: false,
                        proxy_authorization: None,
                    });
                }
                #[cfg(feature = "tls")]
                {
                    let domain = parsed.host.trim_start_matches('[').trim_end_matches(']');
                    let tls = self.tls_connect_stream(domain, tcp).await?;
                    return Ok(ProxyConnection {
                        io: ClientIo::Tls(tls),
                        use_absolute_form: false,
                        proxy_authorization: None,
                    });
                }
                #[cfg(not(feature = "tls"))]
                {
                    let _ = tcp;
                    Err(ClientError::TlsError(
                        "TLS support is disabled (enable asupersync feature \"tls\")".into(),
                    ))
                }
            }
        }
    }

    fn build_request(
        &self,
        method: &Method,
        parsed: &ParsedUrl,
        extra_headers: &[(String, String)],
        body: &[u8],
        request_target: Option<String>,
        proxy_authorization: Option<&str>,
    ) -> Request {
        let has_cookie_header = extra_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("cookie"));
        let has_proxy_authorization = extra_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"));
        let request_target = request_target.unwrap_or_else(|| parsed.path.clone());
        let mut builder =
            Request::builder(method.clone(), request_target).header("Host", parsed.authority());

        if let Some(user_agent) = self.config.user_agent.as_deref() {
            builder = builder.header("User-Agent", user_agent);
        }

        if self.config.cookie_store
            && !has_cookie_header
            && let Some(cookie_header) = self.cookie_header_for_host(&parsed.host)
        {
            builder = builder.header("Cookie", cookie_header);
        }
        if !has_proxy_authorization && let Some(value) = proxy_authorization {
            builder = builder.header("Proxy-Authorization", value);
        }

        builder
            .headers(extra_headers.iter().cloned())
            .body(body.to_vec())
            .build()
    }

    fn store_response_cookies(&self, host: &str, headers: &[(String, String)]) {
        if !self.config.cookie_store {
            return;
        }

        let host = canonical_cookie_host(host);
        let mut cookies = self.cookies.lock();
        // Cap the number of tracked hosts to prevent unbounded growth.
        if !cookies.contains_key(&host) && cookies.len() >= MAX_COOKIE_HOSTS {
            return;
        }
        let mut touched = false;
        {
            let entry = cookies.entry(host.clone()).or_default();
            for (_, value) in headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
            {
                if let Some((name, value)) = parse_set_cookie_pair(value) {
                    touched = true;
                    if value.is_empty() {
                        entry.retain(|cookie| !cookie.name.eq_ignore_ascii_case(&name));
                        continue;
                    }
                    if let Some(existing) = entry
                        .iter_mut()
                        .find(|cookie| cookie.name.eq_ignore_ascii_case(&name))
                    {
                        existing.value = value;
                    } else if entry.len() < MAX_COOKIES_PER_HOST {
                        entry.push(StoredCookie { name, value });
                    }
                }
            }
        }

        if touched && cookies.get(&host).is_some_and(Vec::is_empty) {
            cookies.remove(&host);
        }
    }

    fn cookie_header_for_host(&self, host: &str) -> Option<String> {
        let host = canonical_cookie_host(host);
        let host_cookies = {
            let cookies = self.cookies.lock();
            cookies.get(&host)?.clone()
        };
        if host_cookies.is_empty() {
            return None;
        }
        Some(
            host_cookies
                .into_iter()
                .map(|cookie| format!("{}={}", cookie.name, cookie.value))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    #[cfg(feature = "tls")]
    async fn tls_connect_stream<T>(
        &self,
        domain: &str,
        stream: T,
    ) -> Result<TlsStream<T>, ClientError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let builder = TlsConnectorBuilder::new().alpn_protocols(vec![b"http/1.1".to_vec()]);

        #[cfg(feature = "tls-native-roots")]
        let builder = builder
            .with_native_roots()
            .map_err(|e| ClientError::TlsError(e.to_string()))?;

        #[cfg(all(not(feature = "tls-native-roots"), feature = "tls-webpki-roots"))]
        let builder = builder.with_webpki_roots();

        let connector = builder
            .build()
            .map_err(|e| ClientError::TlsError(e.to_string()))?;

        connector
            .connect(domain, stream)
            .await
            .map_err(|e| ClientError::TlsError(e.to_string()))
    }

    async fn connect_io(&self, cx: &Cx, parsed: &ParsedUrl) -> Result<ClientIo, ClientError> {
        check_cx(cx)?;
        let stream = if let Some(socket_addr) = parsed_numeric_socket_addr(parsed) {
            TcpStream::connect_socket_addr(socket_addr)
                .await
                .map_err(ClientError::ConnectError)?
        } else {
            let addr = format!("{}:{}", parsed.host, parsed.port);
            TcpStream::connect(addr)
                .await
                .map_err(ClientError::ConnectError)?
        };

        // Check cancellation after TCP connect, before TLS.
        check_cx(cx)?;

        match parsed.scheme {
            Scheme::Http => Ok(ClientIo::Plain(stream)),
            Scheme::Https => {
                #[cfg(feature = "tls")]
                {
                    let domain = parsed.host.trim_start_matches('[').trim_end_matches(']');
                    let tls = self.tls_connect_stream(domain, stream).await?;
                    // Check cancellation after TLS handshake.
                    check_cx(cx)?;
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

    async fn acquire_connection(
        &self,
        cx: &Cx,
        parsed: &ParsedUrl,
    ) -> Result<AcquiredConnection, ClientError> {
        struct ConnectGuard<'a> {
            client: &'a HttpClient,
            key: PoolKey,
            id: Option<u64>,
        }
        impl Drop for ConnectGuard<'_> {
            fn drop(&mut self) {
                if let Some(id) = self.id {
                    self.client.pool.lock().remove(&self.key, id);
                }
            }
        }

        let key = parsed.pool_key();
        let now = self.pool_now();
        self.cleanup_expired_idle_connections(now);

        let pooled_id = {
            let mut pool = self.pool.lock();
            pool.try_acquire(&key, now)
        };
        if let Some(pool_id) = pooled_id {
            if let Some(io) = self.take_idle_connection(&key, pool_id) {
                return Ok(AcquiredConnection {
                    pool_id: Some(pool_id),
                    io,
                    fresh: false,
                });
            }
            // Metadata can be stale if a prior request failed before reinserting.
            self.pool.lock().remove(&key, pool_id);
        }

        let fresh_id = {
            let mut pool = self.pool.lock();
            if pool.can_create_connection(&key, now) {
                Some(pool.register_connecting(key.clone(), now, 1))
            } else {
                None
            }
        };

        let mut guard = ConnectGuard {
            client: self,
            key: key.clone(),
            id: fresh_id,
        };

        let io = self.connect_io(cx, parsed).await?;

        guard.id = None; // defuse the guard upon success

        Ok(AcquiredConnection {
            pool_id: fresh_id,
            io,
            fresh: true,
        })
    }

    fn release_connection(&self, key: &PoolKey, pool_id: Option<u64>, fresh: bool, io: ClientIo) {
        if let Some(id) = pool_id {
            let now = self.pool_now();
            if fresh {
                self.pool.lock().mark_connected(key, id, now);
            } else {
                self.pool.lock().release(key, id, now);
            }
            self.store_idle_connection(key.clone(), id, io);
        }
    }

    fn drop_connection(&self, key: &PoolKey, pool_id: Option<u64>) {
        if let Some(id) = pool_id {
            self.pool.lock().remove(key, id);
            self.remove_idle_connection(key, id);
        }
    }

    fn take_idle_connection(&self, key: &PoolKey, id: u64) -> Option<ClientIo> {
        let mut idle = self.idle_connections.lock();
        let (io, remove_key) = {
            let entries = idle.get_mut(key)?;
            let position = entries.iter().position(|(entry_id, _)| *entry_id == id)?;
            let (_, io) = entries.swap_remove(position);
            (io, entries.is_empty())
        };
        if remove_key {
            idle.remove(key);
        }
        drop(idle);
        Some(io)
    }

    fn store_idle_connection(&self, key: PoolKey, id: u64, io: ClientIo) {
        let mut idle = self.idle_connections.lock();
        idle.entry(key).or_default().push((id, io));
    }

    fn remove_idle_connection(&self, key: &PoolKey, id: u64) {
        let mut idle = self.idle_connections.lock();
        if let Some(entries) = idle.get_mut(key) {
            if let Some(position) = entries.iter().position(|(entry_id, _)| *entry_id == id) {
                entries.swap_remove(position);
            }
            if entries.is_empty() {
                idle.remove(key);
            }
        }
    }

    fn cleanup_expired_idle_connections(&self, now: Time) {
        let expired = self.pool.lock().cleanup_expired_entries(now);
        if expired.is_empty() {
            return;
        }

        let mut idle = self.idle_connections.lock();
        for (key, id) in expired {
            if let Some(entries) = idle.get_mut(&key) {
                if let Some(position) = entries.iter().position(|(entry_id, _)| *entry_id == id) {
                    entries.swap_remove(position);
                }
                if entries.is_empty() {
                    idle.remove(&key);
                }
            }
        }
    }

    /// Returns current pool statistics.
    pub fn pool_stats(&self) -> crate::http::pool::PoolStats {
        self.pool.lock().stats()
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

struct AcquiredConnection {
    pool_id: Option<u64>,
    io: ClientIo,
    fresh: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyScheme {
    Http,
    Https,
    Socks5,
}

#[derive(Debug, Clone)]
enum ProxyCredentials {
    HttpBasic(String),
    Socks5 { username: String, password: String },
}

#[derive(Debug, Clone)]
struct ProxyEndpoint {
    scheme: ProxyScheme,
    host: String,
    port: u16,
    credentials: Option<ProxyCredentials>,
}

impl ProxyEndpoint {
    fn http_proxy_authorization(&self) -> Option<&str> {
        match &self.credentials {
            Some(ProxyCredentials::HttpBasic(value)) => Some(value.as_str()),
            _ => None,
        }
    }

    fn socks5_credentials(&self) -> Option<(&str, &str)> {
        match &self.credentials {
            Some(ProxyCredentials::Socks5 { username, password }) => {
                Some((username.as_str(), password.as_str()))
            }
            _ => None,
        }
    }
}

struct ProxyConnection {
    io: ClientIo,
    use_absolute_form: bool,
    proxy_authorization: Option<String>,
}

#[derive(Debug, Clone)]
struct StoredCookie {
    name: String,
    value: String,
}

struct ConnectionGuard<'a> {
    client: &'a HttpClient,
    key: PoolKey,
    pool_id: Option<u64>,
    defused: bool,
}

impl<'a> ConnectionGuard<'a> {
    fn new(client: &'a HttpClient, key: PoolKey, pool_id: Option<u64>) -> Self {
        Self {
            client,
            key,
            pool_id,
            defused: false,
        }
    }
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        if !self.defused {
            self.client.drop_connection(&self.key, self.pool_id);
        }
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

fn ensure_multipart_content_type(headers: &mut Vec<(String, String)>, form: &MultipartForm) {
    if headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
    {
        return;
    }
    headers.push(("Content-Type".to_owned(), form.content_type_header()));
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

fn canonical_cookie_host(host: &str) -> String {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

fn parsed_numeric_socket_addr(parsed: &ParsedUrl) -> Option<SocketAddr> {
    let host = parsed.host.trim_start_matches('[').trim_end_matches(']');
    host.parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, parsed.port))
}

fn parse_set_cookie_pair(raw: &str) -> Option<(String, String)> {
    let pair = raw.split(';').next()?.trim();
    let (name, value) = pair.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some((name.to_owned(), value.trim().to_owned()))
}

fn parse_proxy_endpoint(proxy_url: &str) -> Result<ProxyEndpoint, ClientError> {
    let (scheme, rest) = if let Some(rest) = proxy_url.strip_prefix("http://") {
        (ProxyScheme::Http, rest)
    } else if let Some(rest) = proxy_url.strip_prefix("https://") {
        (ProxyScheme::Https, rest)
    } else if let Some(rest) = proxy_url.strip_prefix("socks5://") {
        (ProxyScheme::Socks5, rest)
    } else {
        return Err(ClientError::InvalidUrl(format!(
            "unsupported proxy scheme in: {proxy_url}"
        )));
    };

    // RFC 3986: authority ends at the first '/', '?', or '#'.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest[..authority_end].trim();
    if authority.is_empty() {
        return Err(ClientError::InvalidUrl(format!(
            "proxy URL missing authority: {proxy_url}"
        )));
    }

    let (userinfo, host_port) = authority
        .rsplit_once('@')
        .map_or((None, authority), |(userinfo, host_port)| {
            (Some(userinfo), host_port)
        });

    let default_port = match scheme {
        ProxyScheme::Http => 80,
        ProxyScheme::Https => 443,
        ProxyScheme::Socks5 => 1080,
    };
    let (host, port) = parse_host_port(host_port, default_port)?;

    let credentials = match userinfo {
        None => None,
        Some(userinfo) => {
            if userinfo.is_empty() {
                return Err(ClientError::InvalidUrl(format!(
                    "proxy URL has empty credentials: {proxy_url}"
                )));
            }
            match scheme {
                ProxyScheme::Http | ProxyScheme::Https => {
                    let encoded = base64::engine::general_purpose::STANDARD.encode(userinfo);
                    Some(ProxyCredentials::HttpBasic(format!("Basic {encoded}")))
                }
                ProxyScheme::Socks5 => {
                    let (username, password) = userinfo
                        .split_once(':')
                        .map_or((userinfo, ""), |(username, password)| (username, password));
                    if username.is_empty() {
                        return Err(ClientError::InvalidUrl(
                            "SOCKS5 username cannot be empty".into(),
                        ));
                    }
                    if username.len() > 255 || password.len() > 255 {
                        return Err(ClientError::InvalidUrl(
                            "SOCKS5 credentials must be <=255 bytes each".into(),
                        ));
                    }
                    Some(ProxyCredentials::Socks5 {
                        username: username.to_owned(),
                        password: password.to_owned(),
                    })
                }
            }
        }
    };

    Ok(ProxyEndpoint {
        scheme,
        host,
        port,
        credentials,
    })
}

fn parse_host_port(authority: &str, default_port: u16) -> Result<(String, u16), ClientError> {
    if authority.is_empty() {
        return Err(ClientError::InvalidUrl("empty authority".into()));
    }

    if authority.starts_with('[') {
        let bracket_end = authority
            .find(']')
            .ok_or_else(|| ClientError::InvalidUrl("unclosed bracket in IPv6 address".into()))?;
        let host = authority[..=bracket_end].to_owned();
        let rest = &authority[bracket_end + 1..];
        if rest.is_empty() {
            return Ok((host, default_port));
        }
        if let Some(port_str) = rest.strip_prefix(':') {
            let port = port_str
                .parse::<u16>()
                .map_err(|_| ClientError::InvalidUrl(format!("invalid port: {port_str}")))?;
            return Ok((host, port));
        }
        return Err(ClientError::InvalidUrl(format!(
            "unexpected characters after IPv6 host: {rest}"
        )));
    }

    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| ClientError::InvalidUrl(format!("invalid port: {port_str}")))?;
        if host.is_empty() {
            return Err(ClientError::InvalidUrl("empty host".into()));
        }
        return Ok((host.to_owned(), port));
    }

    Ok((authority.to_owned(), default_port))
}

fn absolute_request_target(parsed: &ParsedUrl) -> String {
    let scheme = match parsed.scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    };
    format!("{scheme}://{}{}", parsed.authority(), parsed.path)
}

async fn connect_via_socks5(
    proxy: &ProxyEndpoint,
    target: &ParsedUrl,
    cx: &Cx,
) -> Result<TcpStream, ClientError> {
    check_cx(cx)?;
    let addr = format!("{}:{}", proxy.host, proxy.port);
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(ClientError::ConnectError)?;

    check_cx(cx)?;
    socks5_negotiate_auth(&mut stream, proxy.socks5_credentials()).await?;
    check_cx(cx)?;
    let connect_req = build_socks5_connect_request(target)?;
    stream.write_all(&connect_req).await?;
    stream.flush().await?;
    check_cx(cx)?;
    read_socks5_connect_reply(&mut stream).await?;
    check_cx(cx)?;

    Ok(stream)
}

async fn socks5_negotiate_auth(
    stream: &mut TcpStream,
    socks_creds: Option<(&str, &str)>,
) -> Result<(), ClientError> {
    let mut methods = vec![SOCKS5_AUTH_NONE];
    if socks_creds.is_some() {
        methods.push(SOCKS5_AUTH_USER_PASS);
    }

    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(SOCKS5_VERSION);
    greeting.push(
        u8::try_from(methods.len()).map_err(|_| {
            ClientError::ProxyError("too many SOCKS5 auth methods configured".into())
        })?,
    );
    greeting.extend_from_slice(&methods);
    stream.write_all(&greeting).await?;
    stream.flush().await?;

    let mut method_reply = [0u8; 2];
    stream.read_exact(&mut method_reply).await?;
    if method_reply[0] != SOCKS5_VERSION {
        return Err(ClientError::ProxyError(format!(
            "unexpected SOCKS5 version {}",
            method_reply[0]
        )));
    }

    match method_reply[1] {
        SOCKS5_AUTH_NONE => Ok(()),
        SOCKS5_AUTH_USER_PASS => socks5_authenticate_user_pass(stream, socks_creds).await,
        SOCKS5_AUTH_NO_ACCEPTABLE => Err(ClientError::ProxyError(
            "SOCKS5 proxy rejected all authentication methods".into(),
        )),
        method => Err(ClientError::ProxyError(format!(
            "SOCKS5 proxy selected unsupported auth method: {method:#x}"
        ))),
    }
}

async fn socks5_authenticate_user_pass(
    stream: &mut TcpStream,
    socks_creds: Option<(&str, &str)>,
) -> Result<(), ClientError> {
    let Some((username, password)) = socks_creds else {
        return Err(ClientError::ProxyError(
            "SOCKS5 proxy requested username/password auth but credentials were not set".into(),
        ));
    };
    let user_len = u8::try_from(username.len())
        .map_err(|_| ClientError::ProxyError("SOCKS5 username exceeds 255 bytes".into()))?;
    let pass_len = u8::try_from(password.len())
        .map_err(|_| ClientError::ProxyError("SOCKS5 password exceeds 255 bytes".into()))?;

    let mut auth = Vec::with_capacity(3 + username.len() + password.len());
    auth.push(0x01);
    auth.push(user_len);
    auth.extend_from_slice(username.as_bytes());
    auth.push(pass_len);
    auth.extend_from_slice(password.as_bytes());
    stream.write_all(&auth).await?;
    stream.flush().await?;

    let mut auth_reply = [0u8; 2];
    stream.read_exact(&mut auth_reply).await?;
    if auth_reply[0] != 0x01 || auth_reply[1] != 0x00 {
        return Err(ClientError::ProxyError(
            "SOCKS5 username/password authentication failed".into(),
        ));
    }
    Ok(())
}

fn build_socks5_connect_request(target: &ParsedUrl) -> Result<Vec<u8>, ClientError> {
    let mut connect_req = Vec::with_capacity(300);
    connect_req.extend_from_slice(&[SOCKS5_VERSION, 0x01, 0x00]); // CONNECT
    let host = target.host.trim_start_matches('[').trim_end_matches(']');

    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(addr) => {
                connect_req.push(0x01);
                connect_req.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                connect_req.push(0x04);
                connect_req.extend_from_slice(&addr.octets());
            }
        }
    } else {
        let host_bytes = host.as_bytes();
        let host_len = u8::try_from(host_bytes.len())
            .map_err(|_| ClientError::ProxyError("SOCKS5 domain name exceeds 255 bytes".into()))?;
        connect_req.push(0x03);
        connect_req.push(host_len);
        connect_req.extend_from_slice(host_bytes);
    }
    connect_req.extend_from_slice(&target.port.to_be_bytes());

    Ok(connect_req)
}

async fn read_socks5_connect_reply(stream: &mut TcpStream) -> Result<(), ClientError> {
    let mut reply_head = [0u8; 4];
    stream.read_exact(&mut reply_head).await?;
    if reply_head[0] != SOCKS5_VERSION {
        return Err(ClientError::ProxyError(format!(
            "unexpected SOCKS5 connect reply version {}",
            reply_head[0]
        )));
    }
    if reply_head[1] != 0x00 {
        return Err(ClientError::ProxyError(format!(
            "SOCKS5 CONNECT failed: {}",
            socks5_reply_message(reply_head[1])
        )));
    }

    match reply_head[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut addr = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut addr).await?;
        }
        atyp => {
            return Err(ClientError::ProxyError(format!(
                "SOCKS5 CONNECT reply has unknown ATYP {atyp:#x}"
            )));
        }
    }
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(())
}

fn socks5_reply_message(code: u8) -> &'static str {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused by destination host",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown SOCKS5 error",
    }
}

fn connection_can_be_reused(response: &Response, req_method: &Method) -> bool {
    // RFC 9112 §6.3: when a response has no Content-Length and no
    // Transfer-Encoding, the body is delimited by connection close (EOF).
    // Such connections must not be reused.
    let has_content_length = response
        .headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("content-length"));
    let has_transfer_encoding = response
        .headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"));
    let is_bodyless =
        matches!(response.status, 100..=199 | 204 | 304) || matches!(req_method, Method::Head);

    if !has_content_length && !has_transfer_encoding && !is_bodyless {
        return false;
    }

    match response.version {
        Version::Http11 => !header_has_token(&response.headers, "connection", "close"),
        Version::Http10 => header_has_token(&response.headers, "connection", "keep-alive"),
    }
}

fn should_retry_reused_connection_failure(method: &Method, err: &ClientError) -> bool {
    method_is_safe_to_retry_after_stale_reuse(method) && client_error_looks_like_stale_reuse(err)
}

fn method_is_safe_to_retry_after_stale_reuse(method: &Method) -> bool {
    matches!(
        method,
        Method::Get | Method::Head | Method::Options | Method::Trace
    )
}

fn client_error_looks_like_stale_reuse(err: &ClientError) -> bool {
    match err {
        ClientError::Io(io_err) => io_error_looks_like_stale_reuse(io_err),
        ClientError::HttpError(crate::http::h1::codec::HttpError::Io(io_err)) => {
            io_error_looks_like_stale_reuse(io_err)
        }
        _ => false,
    }
}

fn io_error_looks_like_stale_reuse(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}

fn header_has_token(headers: &[(String, String)], name: &str, token: &str) -> bool {
    headers.iter().any(|(header_name, header_value)| {
        header_name.eq_ignore_ascii_case(name)
            && header_value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
    })
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

    // Relative path (append to current path's directory).
    // Strip query string and fragment first — rfind('/') must only see the path component.
    let path_only = current
        .path
        .split_once(&['?', '#'][..])
        .map_or(current.path.as_str(), |(p, _)| p);
    let base_path = path_only.rfind('/').map_or("/", |i| &path_only[..=i]);
    let scheme = match current.scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    };
    format!(
        "{scheme}://{}:{}{base_path}{location}",
        current.host, current.port
    )
}

/// Returns `true` if two parsed URLs share the same origin (scheme + host + port).
fn same_origin(a: &ParsedUrl, b: &ParsedUrl) -> bool {
    a.scheme == b.scheme && a.port == b.port && a.host.eq_ignore_ascii_case(&b.host)
}

/// Strip security-sensitive headers when redirecting to a different origin.
///
/// Per RFC 9110 and common HTTP client practice (curl, reqwest, browsers),
/// `Authorization`, `Cookie`, and `Proxy-Authorization` headers must not be
/// forwarded to a different origin to prevent credential leakage.
fn strip_sensitive_headers_on_redirect(
    from: &ParsedUrl,
    to: &ParsedUrl,
    headers: Vec<(String, String)>,
) -> Vec<(String, String)> {
    if same_origin(from, to) {
        return headers;
    }
    headers
        .into_iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            lower != "authorization" && lower != "cookie" && lower != "proxy-authorization"
        })
        .collect()
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    memmem::find(buf, b"\r\n\r\n").map(|idx| idx + 4)
}

fn contains_ctl_line_break(s: &str) -> bool {
    s.chars().any(|c| matches!(c, '\r' | '\n'))
}

fn validate_connect_inputs(
    target_authority: &str,
    extra_headers: &[(String, String)],
    user_agent: Option<&str>,
) -> Result<(), ClientError> {
    if target_authority.trim().is_empty() {
        return Err(ClientError::InvalidConnectInput(
            "target authority cannot be empty".into(),
        ));
    }
    if target_authority.chars().any(char::is_whitespace)
        || contains_ctl_line_break(target_authority)
    {
        return Err(ClientError::InvalidConnectInput(
            "target authority must be RFC authority-form without whitespace".into(),
        ));
    }
    if let Some(ua) = user_agent
        && contains_ctl_line_break(ua)
    {
        return Err(ClientError::InvalidConnectInput(
            "User-Agent header contains invalid control characters".into(),
        ));
    }
    for (name, value) in extra_headers {
        if name.trim().is_empty() {
            return Err(ClientError::InvalidConnectInput(
                "header name cannot be empty".into(),
            ));
        }
        if contains_ctl_line_break(name) || contains_ctl_line_break(value) {
            return Err(ClientError::InvalidConnectInput(
                "header name/value cannot contain CR or LF".into(),
            ));
        }
    }
    Ok(())
}

fn parse_connect_status_line(line: &str) -> Result<(u16, String), ClientError> {
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().ok_or(ClientError::HttpError(
        crate::http::h1::codec::HttpError::BadRequestLine,
    ))?;
    let status = parts.next().ok_or(ClientError::HttpError(
        crate::http::h1::codec::HttpError::BadRequestLine,
    ))?;
    let reason = parts.next().unwrap_or("").to_owned();

    if Version::from_bytes(version.as_bytes()).is_none() {
        return Err(ClientError::HttpError(
            crate::http::h1::codec::HttpError::UnsupportedVersion,
        ));
    }
    let code = status
        .parse::<u16>()
        .map_err(|_| ClientError::HttpError(crate::http::h1::codec::HttpError::BadRequestLine))?;
    Ok((code, reason))
}

async fn establish_http_connect_tunnel<T>(
    mut io: T,
    target_authority: &str,
    user_agent: Option<&str>,
    extra_headers: &[(String, String)],
) -> Result<HttpConnectTunnel<T>, ClientError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    validate_connect_inputs(target_authority, extra_headers, user_agent)?;

    let mut request = String::with_capacity(256);
    write!(&mut request, "CONNECT {target_authority} HTTP/1.1\r\n")
        .expect("in-memory string write cannot fail");
    write!(&mut request, "Host: {target_authority}\r\n")
        .expect("in-memory string write cannot fail");
    if let Some(ua) = user_agent {
        write!(&mut request, "User-Agent: {ua}\r\n").expect("in-memory string write cannot fail");
    }
    for (name, value) in extra_headers {
        write!(&mut request, "{name}: {value}\r\n").expect("in-memory string write cannot fail");
    }
    request.push_str("\r\n");

    io.write_all(request.as_bytes()).await?;
    io.flush().await?;

    let mut read_buf = Vec::with_capacity(8192);
    let mut scratch = [0u8; 8192];

    loop {
        if let Some(end) = find_headers_end(&read_buf) {
            if end > CONNECT_MAX_HEADERS_SIZE {
                return Err(ClientError::HttpError(
                    crate::http::h1::codec::HttpError::HeadersTooLarge,
                ));
            }

            let head = std::str::from_utf8(&read_buf[..end]).map_err(|_| {
                ClientError::HttpError(crate::http::h1::codec::HttpError::BadRequestLine)
            })?;
            let mut lines = head.split("\r\n");
            let status_line = lines.next().ok_or(ClientError::HttpError(
                crate::http::h1::codec::HttpError::BadRequestLine,
            ))?;
            let (status, reason) = parse_connect_status_line(status_line)?;

            // Permit informational responses and continue until final status.
            if (100..=199).contains(&status) {
                read_buf.drain(..end);
                continue;
            }

            if !(200..=299).contains(&status) {
                return Err(ClientError::ConnectTunnelRefused { status, reason });
            }

            let prefetched = read_buf[end..].to_vec();
            return Ok(HttpConnectTunnel::new(io, prefetched));
        }

        if read_buf.len() > CONNECT_MAX_HEADERS_SIZE {
            return Err(ClientError::HttpError(
                crate::http::h1::codec::HttpError::HeadersTooLarge,
            ));
        }

        let n = poll_fn(|cx| {
            let mut rb = ReadBuf::new(&mut scratch);
            match Pin::new(&mut io).poll_read(cx, &mut rb) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            }
        })
        .await?;

        if n == 0 {
            return Err(ClientError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed before CONNECT response headers were complete",
            )));
        }
        read_buf.extend_from_slice(&scratch[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::AsyncWriteExt;
    use futures_lite::future::block_on;
    use std::cell::Cell;
    use std::future::poll_fn;
    use std::net::TcpListener;

    thread_local! {
        static HTTP_CLIENT_TEST_TIME_NANOS: Cell<u64> = const { Cell::new(0) };
    }

    fn set_http_client_test_time(nanos: u64) {
        HTTP_CLIENT_TEST_TIME_NANOS.with(|t| t.set(nanos));
    }

    fn http_client_test_time() -> Time {
        Time::from_nanos(HTTP_CLIENT_TEST_TIME_NANOS.with(std::cell::Cell::get))
    }

    fn loopback_client_io() -> ClientIo {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener address");
        let client = std::net::TcpStream::connect(addr).expect("connect client");
        let (_server, _) = listener.accept().expect("accept client");
        let stream = TcpStream::from_std(client).expect("wrap stream");
        ClientIo::Plain(stream)
    }

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
    fn parsed_numeric_socket_addr_handles_ipv4_host() {
        let url = ParsedUrl::parse("http://127.0.0.1:8765/healthz").expect("parse url");
        let socket_addr = parsed_numeric_socket_addr(&url).expect("numeric addr");
        assert_eq!(socket_addr, "127.0.0.1:8765".parse().unwrap());
    }

    #[test]
    fn parsed_numeric_socket_addr_handles_ipv6_host() {
        let url = ParsedUrl::parse("http://[::1]:8765/healthz").expect("parse url");
        let socket_addr = parsed_numeric_socket_addr(&url).expect("numeric addr");
        assert_eq!(socket_addr, "[::1]:8765".parse().unwrap());
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

    #[test]
    fn parse_http_proxy_endpoint_with_basic_auth() {
        let proxy = parse_proxy_endpoint("http://alice:secret@proxy.local:8080")
            .expect("proxy should parse");
        assert_eq!(proxy.scheme, ProxyScheme::Http);
        assert_eq!(proxy.host, "proxy.local");
        assert_eq!(proxy.port, 8080);
        assert_eq!(
            proxy.http_proxy_authorization(),
            Some("Basic YWxpY2U6c2VjcmV0")
        );
    }

    #[test]
    fn parse_socks5_proxy_endpoint_with_credentials() {
        let proxy =
            parse_proxy_endpoint("socks5://agent:pw@127.0.0.1").expect("proxy should parse");
        assert_eq!(proxy.scheme, ProxyScheme::Socks5);
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 1080);
        assert_eq!(proxy.socks5_credentials(), Some(("agent", "pw")));
    }

    #[test]
    fn absolute_request_target_uses_full_uri() {
        let parsed = ParsedUrl::parse("http://example.com:8080/path?q=1").unwrap();
        assert_eq!(
            absolute_request_target(&parsed),
            "http://example.com:8080/path?q=1"
        );
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

    #[test]
    fn resolve_relative_path_redirect_ignores_query_slashes() {
        // Regression: rfind('/') must only search the path, not the query.
        let current = ParsedUrl::parse("http://example.com/dir/old?return=/home").unwrap();
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

        let err = ClientError::Cancelled;
        assert!(format!("{err}").contains("cancelled"));
    }

    #[test]
    fn client_error_source() {
        use std::error::Error;

        let err = ClientError::InvalidUrl("x".into());
        assert!(err.source().is_none());

        let io_err = io::Error::other("test");
        let err = ClientError::Io(io_err);
        assert!(err.source().is_some());

        let err = ClientError::Cancelled;
        assert!(err.source().is_none());
    }

    #[test]
    fn client_error_is_cancelled() {
        assert!(ClientError::Cancelled.is_cancelled());
        assert!(!ClientError::InvalidUrl("x".into()).is_cancelled());
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
        assert!(!config.cookie_store);
        assert!(config.proxy_url.is_none());
    }

    #[test]
    fn config_with_time_getter_exposes_custom_clock() {
        set_http_client_test_time(77);
        let config = HttpClientConfig::default().with_time_getter(http_client_test_time);
        assert_eq!((config.time_getter())().as_nanos(), 77);
    }

    #[test]
    fn builder_default_matches_client_defaults() {
        let client = HttpClient::builder().build();
        assert_eq!(client.config.pool_config.max_connections_per_host, 6);
        assert_eq!(client.config.pool_config.max_total_connections, 100);
        assert_eq!(
            client.config.pool_config.idle_timeout,
            std::time::Duration::from_secs(90)
        );
        assert_eq!(
            client.config.pool_config.cleanup_interval,
            std::time::Duration::from_secs(30)
        );
        assert!(matches!(
            client.config.redirect_policy,
            RedirectPolicy::Limited(10)
        ));
        assert_eq!(client.config.user_agent.as_deref(), Some("asupersync/0.1"));
        assert!(!client.config.cookie_store);
        assert!(client.config.proxy_url.is_none());
    }

    #[test]
    fn builder_overrides_pool_and_redirect_and_user_agent() {
        let client = HttpClient::builder()
            .max_connections_per_host(12)
            .max_total_connections(240)
            .idle_timeout(std::time::Duration::from_secs(15))
            .cleanup_interval(std::time::Duration::from_secs(5))
            .no_redirects()
            .no_user_agent()
            .cookie_store(true)
            .no_cookie_store()
            .proxy("http://proxy.internal:3128")
            .no_proxy()
            .build();

        assert_eq!(client.config.pool_config.max_connections_per_host, 12);
        assert_eq!(client.config.pool_config.max_total_connections, 240);
        assert_eq!(
            client.config.pool_config.idle_timeout,
            std::time::Duration::from_secs(15)
        );
        assert_eq!(
            client.config.pool_config.cleanup_interval,
            std::time::Duration::from_secs(5)
        );
        assert!(matches!(
            client.config.redirect_policy,
            RedirectPolicy::None
        ));
        assert!(client.config.user_agent.is_none());
        assert!(!client.config.cookie_store);
        assert!(client.config.proxy_url.is_none());
    }

    #[test]
    fn builder_pool_config_and_max_redirects() {
        let pool_config = PoolConfig::builder()
            .max_connections_per_host(3)
            .max_total_connections(32)
            .idle_timeout(std::time::Duration::from_secs(7))
            .cleanup_interval(std::time::Duration::from_secs(3))
            .build();

        let client = HttpClient::builder()
            .pool_config(pool_config)
            .max_redirects(2)
            .user_agent("asupersync-test/2.0")
            .cookie_store(true)
            .proxy("socks5://proxy.internal:1080")
            .build();

        assert_eq!(client.config.pool_config.max_connections_per_host, 3);
        assert_eq!(client.config.pool_config.max_total_connections, 32);
        assert_eq!(
            client.config.pool_config.idle_timeout,
            std::time::Duration::from_secs(7)
        );
        assert_eq!(
            client.config.pool_config.cleanup_interval,
            std::time::Duration::from_secs(3)
        );
        assert!(matches!(
            client.config.redirect_policy,
            RedirectPolicy::Limited(2)
        ));
        assert_eq!(
            client.config.user_agent.as_deref(),
            Some("asupersync-test/2.0")
        );
        assert!(client.config.cookie_store);
        assert_eq!(
            client.config.proxy_url.as_deref(),
            Some("socks5://proxy.internal:1080")
        );
    }

    #[test]
    fn builder_with_time_getter_overrides_pool_clock() {
        set_http_client_test_time(777);
        let client = HttpClient::builder()
            .with_time_getter(http_client_test_time)
            .build();
        assert_eq!(client.pool_now().as_nanos(), 777);
        assert_eq!((client.config.time_getter())().as_nanos(), 777);
    }

    #[test]
    fn client_default_creates_pool() {
        let client = HttpClient::new();
        let stats = client.pool_stats();
        assert_eq!(stats.total_connections, 0);
    }

    #[test]
    fn release_connection_marks_fresh_connection_with_custom_time_getter() {
        set_http_client_test_time(123);
        let client = HttpClient::builder()
            .with_time_getter(http_client_test_time)
            .build();
        let key = PoolKey::http("example.com", None);
        let id = client
            .pool
            .lock()
            .register_connecting(key.clone(), Time::ZERO, 1);

        client.release_connection(&key, Some(id), true, loopback_client_io());

        let (created_at, last_used, state, requests_served) = {
            let pool = client.pool.lock();
            let meta = pool
                .get_connection_meta(&key, id)
                .expect("connection metadata");
            let values = (
                meta.created_at,
                meta.last_used,
                meta.state,
                meta.requests_served,
            );
            drop(pool);
            values
        };
        assert_eq!(created_at, Time::ZERO);
        assert_eq!(last_used, Time::from_nanos(123));
        assert_eq!(state, crate::http::pool::PooledConnectionState::Idle);
        assert_eq!(requests_served, 0);
    }

    #[test]
    fn release_connection_marks_reused_connection_with_custom_time_getter() {
        let client = HttpClient::builder()
            .with_time_getter(http_client_test_time)
            .build();
        let key = PoolKey::http("example.com", None);
        let id = {
            let mut pool = client.pool.lock();
            let id = pool.register_connecting(key.clone(), Time::from_nanos(10), 1);
            pool.mark_connected(&key, id, Time::from_nanos(20));
            let acquired = pool
                .try_acquire(&key, Time::from_nanos(30))
                .expect("acquire pooled connection");
            assert_eq!(acquired, id);
            drop(pool);
            id
        };

        set_http_client_test_time(456);
        client.release_connection(&key, Some(id), false, loopback_client_io());

        let (created_at, last_used, state, requests_served) = {
            let pool = client.pool.lock();
            let meta = pool
                .get_connection_meta(&key, id)
                .expect("connection metadata");
            let values = (
                meta.created_at,
                meta.last_used,
                meta.state,
                meta.requests_served,
            );
            drop(pool);
            values
        };
        assert_eq!(created_at, Time::from_nanos(10));
        assert_eq!(last_used, Time::from_nanos(456));
        assert_eq!(state, crate::http::pool::PooledConnectionState::Idle);
        assert_eq!(requests_served, 1);
    }

    #[test]
    fn cleanup_expired_idle_connections_drops_stale_client_io() {
        set_http_client_test_time(0);
        let client = HttpClient::builder()
            .with_time_getter(http_client_test_time)
            .idle_timeout(std::time::Duration::from_nanos(100))
            .build();
        let key = PoolKey::http("example.com", None);
        let id = client
            .pool
            .lock()
            .register_connecting(key.clone(), Time::ZERO, 1);

        client.release_connection(&key, Some(id), true, loopback_client_io());
        assert_eq!(
            client.idle_connections.lock().get(&key).map_or(0, Vec::len),
            1,
            "freshly released client IO should be tracked as idle"
        );

        set_http_client_test_time(150);
        client.cleanup_expired_idle_connections(http_client_test_time());

        assert!(
            client.pool.lock().get_connection_meta(&key, id).is_none(),
            "expired pool metadata must be pruned"
        );
        assert!(
            client.idle_connections.lock().get(&key).is_none(),
            "expired idle IO must be dropped alongside metadata"
        );
    }

    #[test]
    fn parse_set_cookie_pair_extracts_first_pair() {
        let parsed = parse_set_cookie_pair("session=abc123; Path=/; HttpOnly");
        assert_eq!(parsed, Some(("session".to_string(), "abc123".to_string())));

        assert_eq!(parse_set_cookie_pair(""), None);
        assert_eq!(parse_set_cookie_pair("invalid"), None);
        assert_eq!(parse_set_cookie_pair(" =value"), None);
    }

    #[test]
    fn cookie_store_attaches_cookie_header_when_enabled() {
        let client = HttpClient::builder().cookie_store(true).build();
        client.store_response_cookies(
            "Example.COM",
            &[(
                "Set-Cookie".to_string(),
                "session=abc123; Path=/".to_string(),
            )],
        );

        let parsed = ParsedUrl::parse("http://example.com/data").expect("valid URL");
        let req = client.build_request(&Method::Get, &parsed, &[], &[], None, None);
        assert_eq!(
            get_header(&req.headers, "cookie"),
            Some("session=abc123".to_string())
        );
    }

    #[test]
    fn cookie_store_respects_explicit_cookie_header() {
        let client = HttpClient::builder().cookie_store(true).build();
        client.store_response_cookies(
            "example.com",
            &[("Set-Cookie".to_string(), "session=abc123".to_string())],
        );

        let parsed = ParsedUrl::parse("http://example.com/path").expect("valid URL");
        let req = client.build_request(
            &Method::Get,
            &parsed,
            &[("Cookie".to_string(), "manual=1".to_string())],
            &[],
            None,
            None,
        );
        assert_eq!(
            get_header(&req.headers, "cookie"),
            Some("manual=1".to_string())
        );
    }

    #[test]
    fn build_request_adds_proxy_authorization_when_not_explicit() {
        let client = HttpClient::builder().build();
        let parsed = ParsedUrl::parse("http://example.com/path").expect("valid URL");
        let req = client.build_request(
            &Method::Get,
            &parsed,
            &[("Accept".to_string(), "application/json".to_string())],
            &[],
            Some(absolute_request_target(&parsed)),
            Some("Basic Zm9vOmJhcg=="),
        );
        assert_eq!(
            get_header(&req.headers, "proxy-authorization"),
            Some("Basic Zm9vOmJhcg==".to_string())
        );
        assert_eq!(
            req.uri, "http://example.com/path",
            "forward proxy request must use absolute-form URI"
        );
    }

    #[test]
    fn build_request_preserves_explicit_proxy_authorization() {
        let client = HttpClient::builder().build();
        let parsed = ParsedUrl::parse("http://example.com/path").expect("valid URL");
        let req = client.build_request(
            &Method::Get,
            &parsed,
            &[(
                "Proxy-Authorization".to_string(),
                "Basic ZXhwbGljaXQ=".to_string(),
            )],
            &[],
            Some(absolute_request_target(&parsed)),
            Some("Basic aWdub3JlZA=="),
        );
        assert_eq!(
            get_header(&req.headers, "proxy-authorization"),
            Some("Basic ZXhwbGljaXQ=".to_string())
        );
    }

    #[test]
    fn ensure_multipart_content_type_adds_header_when_missing() {
        let form = MultipartForm::with_boundary("upload-boundary")
            .unwrap()
            .text("user", "alice");
        let mut headers = vec![("Accept".to_string(), "application/json".to_string())];
        ensure_multipart_content_type(&mut headers, &form);
        assert_eq!(
            get_header(&headers, "content-type"),
            Some("multipart/form-data; boundary=upload-boundary".to_string())
        );
    }

    #[test]
    fn ensure_multipart_content_type_respects_existing_header() {
        let form = MultipartForm::with_boundary("upload-boundary")
            .unwrap()
            .text("user", "alice");
        let mut headers = vec![(
            "Content-Type".to_string(),
            "multipart/form-data; boundary=manual".to_string(),
        )];
        ensure_multipart_content_type(&mut headers, &form);
        assert_eq!(
            get_header(&headers, "content-type"),
            Some("multipart/form-data; boundary=manual".to_string())
        );
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn cookie_store_updates_and_removes_existing_cookie() {
        let client = HttpClient::builder().cookie_store(true).build();
        client.store_response_cookies(
            "example.com",
            &[("Set-Cookie".to_string(), "session=abc123".to_string())],
        );
        client.store_response_cookies(
            "example.com",
            &[("Set-Cookie".to_string(), "theme=dark".to_string())],
        );
        client.store_response_cookies(
            "example.com",
            &[("Set-Cookie".to_string(), "session=updated".to_string())],
        );

        let cookie_header = client
            .cookie_header_for_host("example.com")
            .expect("cookie header");
        assert!(cookie_header.contains("session=updated"));
        assert!(cookie_header.contains("theme=dark"));

        client.store_response_cookies(
            "example.com",
            &[("Set-Cookie".to_string(), "session=".to_string())],
        );
        let cookie_header = client
            .cookie_header_for_host("example.com")
            .expect("cookie header");
        assert!(!cookie_header.contains("session="));
        assert!(cookie_header.contains("theme=dark"));
    }

    #[derive(Debug)]
    struct ConnectTestIo {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
    }

    impl ConnectTestIo {
        fn new(read_data: impl AsRef<[u8]>) -> Self {
            Self {
                read_data: read_data.as_ref().to_vec(),
                read_pos: 0,
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for ConnectTestIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.read_pos >= self.read_data.len() {
                return Poll::Ready(Ok(()));
            }
            let remaining = self.read_data.len() - self.read_pos;
            let to_copy = remaining.min(buf.remaining());
            buf.put_slice(&self.read_data[self.read_pos..self.read_pos + to_copy]);
            self.read_pos += to_copy;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ConnectTestIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn connect_tunnel_writes_expected_request() {
        let io = ConnectTestIo::new("HTTP/1.1 200 Connection Established\r\n\r\n");
        let tunnel = block_on(establish_http_connect_tunnel(
            io,
            "example.com:443",
            Some("asupersync-test/1.0"),
            &[("Proxy-Authorization".into(), "Basic abc".into())],
        ))
        .expect("tunnel should establish");
        let io = tunnel.into_inner();
        let written = String::from_utf8(io.written).expect("request should be utf8");
        assert!(written.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(written.contains("\r\nHost: example.com:443\r\n"));
        assert!(written.contains("\r\nUser-Agent: asupersync-test/1.0\r\n"));
        assert!(written.contains("\r\nProxy-Authorization: Basic abc\r\n"));
        assert!(written.ends_with("\r\n\r\n"));
    }

    #[test]
    fn connect_tunnel_preserves_prefetched_bytes_and_supports_write() {
        let io = ConnectTestIo::new("HTTP/1.1 200 OK\r\n\r\nHELLO");
        let mut tunnel = block_on(establish_http_connect_tunnel(
            io,
            "example.com:443",
            None,
            &[],
        ))
        .expect("tunnel should establish");

        assert_eq!(tunnel.prefetched_len(), 5);
        let mut first = [0u8; 3];
        block_on(async {
            poll_fn(|cx| -> std::task::Poll<Result<(), std::io::Error>> {
                let mut rb = ReadBuf::new(&mut first);
                Pin::new(&mut tunnel).poll_read(cx, &mut rb)
            })
            .await
            .expect("read prefetched bytes");
        });
        assert_eq!(&first, b"HEL");
        assert_eq!(tunnel.prefetched_len(), 2);

        block_on(async {
            tunnel.write_all(b"PING").await.expect("write to tunnel");
            tunnel.flush().await.expect("flush to tunnel");
        });

        let io = tunnel.into_inner();
        let written = String::from_utf8(io.written).expect("request should be utf8");
        assert!(written.ends_with("\r\n\r\nPING"));
    }

    #[test]
    fn connect_tunnel_rejects_non_success_status() {
        let io = ConnectTestIo::new("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
        let err = block_on(establish_http_connect_tunnel(
            io,
            "example.com:443",
            None,
            &[],
        ))
        .expect_err("non-2xx should fail");
        match err {
            ClientError::ConnectTunnelRefused { status, reason } => {
                assert_eq!(status, 407);
                assert!(reason.contains("Proxy Authentication Required"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn connect_tunnel_rejects_header_injection() {
        let io = ConnectTestIo::new("HTTP/1.1 200 OK\r\n\r\n");
        let err = block_on(establish_http_connect_tunnel(
            io,
            "example.com:443",
            None,
            &[("X-Test".into(), "ok\r\nbad".into())],
        ))
        .expect_err("CRLF in header value must be rejected");
        match err {
            ClientError::InvalidConnectInput(msg) => {
                assert!(msg.contains("header name/value"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // =========================================================================
    // Redirect policy
    // =========================================================================

    #[test]
    fn redirect_policy_default_is_limited() {
        let policy = RedirectPolicy::default();
        assert!(matches!(policy, RedirectPolicy::Limited(10)));
    }

    #[test]
    fn scheme_debug_clone_copy_eq() {
        let a = Scheme::Http;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, Scheme::Https);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Http"));
    }

    #[test]
    fn redirect_policy_debug_clone() {
        let a = RedirectPolicy::Limited(5);
        let b = a.clone();
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Limited"));
        assert!(dbg.contains('5'));
        let dbg2 = format!("{b:?}");
        assert_eq!(dbg, dbg2);
    }

    #[test]
    fn parsed_url_debug_clone() {
        let url = ParsedUrl {
            scheme: Scheme::Https,
            host: "example.com".to_string(),
            port: 443,
            path: "/api/v1".to_string(),
        };
        let cloned = url.clone();
        assert_eq!(cloned.host, "example.com");
        assert_eq!(cloned.port, 443);
        let dbg = format!("{url:?}");
        assert!(dbg.contains("ParsedUrl"));
        assert!(dbg.contains("example.com"));
    }

    #[test]
    fn header_has_token_matches_case_insensitive_csv_values() {
        let headers = vec![
            ("Connection".to_string(), "keep-alive, Upgrade".to_string()),
            ("X-Test".to_string(), "value".to_string()),
        ];
        assert!(header_has_token(&headers, "connection", "keep-alive"));
        assert!(header_has_token(&headers, "connection", "upgrade"));
        assert!(!header_has_token(&headers, "connection", "close"));
    }

    #[test]
    fn connection_can_be_reused_for_http11_without_close() {
        let response = Response {
            version: Version::Http11,
            status: 200,
            reason: "OK".into(),
            headers: vec![
                ("Content-Length".into(), "0".into()),
                ("Connection".into(), "keep-alive".into()),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        assert!(connection_can_be_reused(&response, &Method::Get));

        let close_response = Response {
            headers: vec![
                ("Content-Length".into(), "0".into()),
                ("Connection".into(), "close".into()),
            ],
            ..response
        };
        assert!(!connection_can_be_reused(&close_response, &Method::Get));
    }

    #[test]
    fn connection_can_be_reused_for_http10_only_with_keep_alive() {
        let response = Response {
            version: Version::Http10,
            status: 200,
            reason: "OK".into(),
            headers: vec![
                ("Content-Length".into(), "0".into()),
                ("Connection".into(), "keep-alive".into()),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        assert!(connection_can_be_reused(&response, &Method::Get));

        let no_header = Response {
            headers: Vec::new(),
            ..response
        };
        assert!(!connection_can_be_reused(&no_header, &Method::Get));
    }

    #[test]
    fn connection_not_reused_for_eof_delimited_body() {
        // RFC 9112 §6.3: no Content-Length and no Transfer-Encoding means
        // the body is delimited by connection close (EOF-framed).
        let response = Response {
            version: Version::Http11,
            status: 200,
            reason: "OK".into(),
            headers: vec![],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        assert!(!connection_can_be_reused(&response, &Method::Get));

        // Bodyless status codes (204, 304) are exempt.
        let no_content = Response {
            status: 204,
            reason: "No Content".into(),
            ..response.clone()
        };
        assert!(connection_can_be_reused(&no_content, &Method::Get));

        // Transfer-Encoding present: body is chunk-framed, reuse is ok.
        let chunked = Response {
            headers: vec![("Transfer-Encoding".into(), "chunked".into())],
            ..response
        };
        assert!(connection_can_be_reused(&chunked, &Method::Get));
    }

    // =========================================================================
    // Cancellation via Cx
    // =========================================================================

    #[test]
    fn check_cx_returns_cancelled_when_cancelled() {
        let cx = Cx::for_testing();
        assert!(check_cx(&cx).is_ok());

        cx.set_cancel_requested(true);
        let err = check_cx(&cx).unwrap_err();
        assert!(err.is_cancelled());
    }

    #[test]
    fn request_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.get(&cx, "http://example.com/test"));
        assert!(result.is_err());
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn post_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.post(&cx, "http://example.com/submit", b"data".to_vec()));
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn put_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.put(&cx, "http://example.com/item", b"data".to_vec()));
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn delete_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.delete(&cx, "http://example.com/item"));
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn request_streaming_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.request_streaming(
            &cx,
            Method::Get,
            "http://example.com/stream",
            Vec::new(),
            Vec::new(),
        ));
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn connect_tunnel_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.connect_tunnel(
            &cx,
            "http://proxy.local:3128",
            "example.com:443",
            Vec::new(),
        ));
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn request_succeeds_with_non_cancelled_cx() {
        // Verify that a non-cancelled Cx does not interfere with normal operation.
        // This test only verifies we get past the cancellation check (URL parsing
        // will succeed, but the actual connect will fail since there's no server).
        let cx = Cx::for_testing();
        let client = HttpClient::new();
        let result = block_on(client.get(&cx, "http://127.0.0.1:1/nonexistent"));
        // The request should fail with a connect error (not a cancellation error).
        assert!(result.is_err());
        assert!(!result.unwrap_err().is_cancelled());
    }

    #[test]
    fn safe_method_retries_once_after_stale_pooled_connection_close() {
        use std::io::{Read, Write};
        use std::time::Duration;

        fn read_request_head(stream: &mut std::net::TcpStream) {
            let mut buf = [0_u8; 1024];
            let mut request = Vec::new();
            loop {
                let n = stream.read(&mut buf).expect("read request");
                assert!(n > 0, "request must arrive before peer closes");
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener address");
        let server = std::thread::spawn(move || {
            let (mut first, _) = listener.accept().expect("accept first connection");
            read_request_head(&mut first);
            first
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .expect("write first response");
            first.flush().expect("flush first response");
            std::thread::sleep(Duration::from_millis(50));
            drop(first);

            let (mut second, _) = listener.accept().expect("accept retry connection");
            read_request_head(&mut second);
            second
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfresh",
                )
                .expect("write retry response");
            second.flush().expect("flush retry response");
        });

        let client = HttpClient::builder()
            .max_connections_per_host(1)
            .max_total_connections(1)
            .build();
        let cx = Cx::for_testing();
        let url = format!("http://{addr}/healthz");

        let first = block_on(client.get(&cx, &url)).expect("initial request should succeed");
        assert_eq!(first.status, 200);
        assert_eq!(first.body, b"ok");

        std::thread::sleep(Duration::from_millis(100));

        let second = block_on(client.get(&cx, &url)).expect("retry request should succeed");
        assert_eq!(second.status, 200);
        assert_eq!(second.body, b"fresh");

        server.join().expect("server thread should join");
        let stats = client.pool_stats();
        assert!(
            stats.connections_created >= 2,
            "client should establish a fresh connection after stale pooled reuse fails"
        );
    }
}
