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
use crate::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use crate::net::tcp::stream::TcpStream;
#[cfg(feature = "tls")]
use crate::tls::{TlsConnectorBuilder, TlsStream};
use crate::types::Time;
use memchr::memmem;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fmt::Write;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

const CONNECT_MAX_HEADERS_SIZE: usize = 64 * 1024;

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
            | Self::TlsError(_)
            | Self::InvalidUrl(_)
            | Self::TooManyRedirects { .. } => None,
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
#[allow(clippy::large_enum_variant)]
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
    idle_connections: Mutex<HashMap<PoolKey, Vec<(u64, ClientIo)>>>,
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

    /// Establish an HTTP/1.1 CONNECT tunnel through a proxy endpoint.
    ///
    /// `proxy_url` is the proxy server URL (e.g. `http://proxy.local:3128`).
    /// `target_authority` is the requested CONNECT authority-form target
    /// (e.g. `example.com:443`).
    pub async fn connect_tunnel(
        &self,
        proxy_url: &str,
        target_authority: &str,
        extra_headers: Vec<(String, String)>,
    ) -> Result<HttpConnectTunnel<ClientIo>, ClientError> {
        let proxy = ParsedUrl::parse(proxy_url)?;
        let io = self.connect_io(&proxy).await?;
        establish_http_connect_tunnel(
            io,
            target_authority,
            self.config.user_agent.as_deref(),
            &extra_headers,
        )
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
        let req = self.build_request(method, parsed, extra_headers, body);

        let key = parsed.pool_key();
        let acquired = self.acquire_connection(parsed).await?;

        struct ConnectionGuard<'a> {
            client: &'a HttpClient,
            key: PoolKey,
            pool_id: Option<u64>,
            defused: bool,
        }

        impl Drop for ConnectionGuard<'_> {
            fn drop(&mut self) {
                if !self.defused {
                    self.client.drop_connection(&self.key, self.pool_id);
                }
            }
        }

        let mut guard = ConnectionGuard {
            client: self,
            key: key.clone(),
            pool_id: acquired.pool_id,
            defused: false,
        };

        match Http1Client::request_with_io(acquired.io, req).await {
            Ok((response, io)) => {
                guard.defused = true;
                if connection_can_be_reused(&response) {
                    self.release_connection(&key, acquired.pool_id, acquired.fresh, io);
                } else {
                    self.drop_connection(&key, acquired.pool_id);
                }
                Ok(response)
            }
            Err(err) => {
                // guard drops the connection on return
                Err(ClientError::from(err))
            }
        }
    }

    /// Execute a single request (streaming; no redirect handling).
    async fn execute_single_streaming(
        &self,
        method: &Method,
        parsed: &ParsedUrl,
        extra_headers: &[(String, String)],
        body: &[u8],
    ) -> Result<ClientStreamingResponse<ClientIo>, ClientError> {
        let req = self.build_request(method, parsed, extra_headers, body);

        let stream = self.connect_io(parsed).await?;
        let resp = Http1Client::request_streaming(stream, req).await?;
        Ok(resp)
    }

    fn build_request(
        &self,
        method: &Method,
        parsed: &ParsedUrl,
        extra_headers: &[(String, String)],
        body: &[u8],
    ) -> Request {
        let mut builder = Request::builder(method.clone(), parsed.path.clone())
            .header("Host", parsed.authority());

        if let Some(user_agent) = self.config.user_agent.as_deref() {
            builder = builder.header("User-Agent", user_agent);
        }

        builder
            .headers(extra_headers.iter().cloned())
            .body(body.to_vec())
            .build()
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

                    let builder =
                        TlsConnectorBuilder::new().alpn_protocols(vec![b"http/1.1".to_vec()]);

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

    async fn acquire_connection(
        &self,
        parsed: &ParsedUrl,
    ) -> Result<AcquiredConnection, ClientError> {
        let key = parsed.pool_key();
        let now = pool_now();

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

        let io = match self.connect_io(parsed).await {
            Ok(io) => io,
            Err(err) => {
                if let Some(id) = fresh_id {
                    self.pool.lock().remove(&key, id);
                }
                return Err(err);
            }
        };
        Ok(AcquiredConnection {
            pool_id: fresh_id,
            io,
            fresh: true,
        })
    }

    fn release_connection(&self, key: &PoolKey, pool_id: Option<u64>, fresh: bool, io: ClientIo) {
        if let Some(id) = pool_id {
            let now = pool_now();
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

fn connection_can_be_reused(response: &Response) -> bool {
    match response.version {
        Version::Http11 => !header_has_token(&response.headers, "connection", "close"),
        Version::Http10 => header_has_token(&response.headers, "connection", "keep-alive"),
    }
}

fn header_has_token(headers: &[(String, String)], name: &str, token: &str) -> bool {
    headers.iter().any(|(header_name, header_value)| {
        header_name.eq_ignore_ascii_case(name)
            && header_value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
    })
}

fn pool_now() -> Time {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        });
    Time::from_nanos(nanos)
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
    use std::future::poll_fn;

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
    }

    #[test]
    fn client_default_creates_pool() {
        let client = HttpClient::new();
        let stats = client.pool_stats();
        assert_eq!(stats.total_connections, 0);
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
            poll_fn(|cx| {
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
            headers: vec![("Connection".into(), "keep-alive".into())],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        assert!(connection_can_be_reused(&response));

        let close_response = Response {
            headers: vec![("Connection".into(), "close".into())],
            ..response
        };
        assert!(!connection_can_be_reused(&close_response));
    }

    #[test]
    fn connection_can_be_reused_for_http10_only_with_keep_alive() {
        let response = Response {
            version: Version::Http10,
            status: 200,
            reason: "OK".into(),
            headers: vec![("Connection".into(), "keep-alive".into())],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        assert!(connection_can_be_reused(&response));

        let no_header = Response {
            headers: Vec::new(),
            ..response
        };
        assert!(!connection_can_be_reused(&no_header));
    }
}
