//! High-level HTTP/1.1 client with connection pooling, DNS resolution,
//! TLS support, and redirect following.
//!
//! [`HttpClient`] integrates [`Http1Client`], [`Pool`], DNS resolution,
//! and optional TLS into a simple API for making HTTP requests.
//!
//! # No Ambient Client
//!
//! The pooled client is explicit by design. Construct or receive a
//! [`HttpClient`] handle and pass an explicit [`Cx`] into [`send`](ClientRequestBuilder::send);
//! there is no process-global default client or hidden ambient runtime handle.
//!
//! ```compile_fail
//! # async fn demo(client: asupersync::http::Client) -> Result<(), Box<dyn std::error::Error>> {
//! let _: serde_json::Value = client.get("http://127.0.0.1/user").send().await?.json()?;
//! # Ok(())
//! # }
//! ```
//!
//! # GET to JSON
//!
//! ```no_run
//! # async fn demo(cx: &asupersync::Cx) -> Result<(), Box<dyn std::error::Error>> {
//! let client = asupersync::http::Client::new();
//! let user: serde_json::Value = client.get("http://127.0.0.1:8080/user").send(cx).await?.json()?;
//! assert_eq!(user["ok"], true);
//! # Ok(())
//! # }
//! ```
//!
//! # Example
//!
//! ```ignore
//! let client = HttpClient::new();
//! let cx = Cx::for_testing();
//! let resp = client.get("http://example.com/api").send(&cx).await?;
//! assert_eq!(resp.status, 200);
//! ```

use crate::cx::Cx;
use crate::http::h1::client::{ClientStreamingResponse, Http1Client};
use crate::http::h1::types::{
    Method, MultipartForm, Request, Response, Version, url_encode_params,
};
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
use std::sync::Arc;
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
    /// The request's effective deadline elapsed before completion
    /// (br-asupersync-server-stack-hardening-eeexl1.1.3): the meet of the
    /// remaining ambient budget, the client's configured total request
    /// timeout, and any per-call override.
    DeadlineExceeded,
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
    /// Connection pool limits prevented a new connection from being opened.
    PoolExhausted {
        /// Host name for the attempted request.
        host: String,
        /// Port for the attempted request.
        port: u16,
    },
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
            Self::PoolExhausted { host, port } => {
                write!(f, "connection pool exhausted for {host}:{port}")
            }
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::DeadlineExceeded => write!(f, "request budget deadline exceeded"),
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
            | Self::PoolExhausted { .. }
            | Self::TlsError(_)
            | Self::InvalidUrl(_)
            | Self::TooManyRedirects { .. }
            | Self::Cancelled
            | Self::DeadlineExceeded => None,
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
    if cx.checkpoint().is_err() {
        Err(ClientError::Cancelled)
    } else {
        Ok(())
    }
}

/// Drives an outbound exchange under the effective total deadline
/// (br-asupersync-server-stack-hardening-eeexl1.1.3): the **meet** of the
/// remaining `cx` budget, the client's configured total request timeout,
/// and any per-call override — the tightest bound wins, so neither config
/// nor caller can extend past the caller's budget deadline.
///
/// Emits a `client.budget_forwarded` trace event when a deadline applies.
/// With no bound from any source, the future runs unbounded (legacy
/// behavior). On expiry the future is dropped — `ConnectionGuard` ensures
/// the in-flight pooled connection is discarded, not reused — and
/// [`ClientError::DeadlineExceeded`] is returned.
async fn drive_with_budget_deadline<T>(
    cx: &Cx,
    configured: Option<std::time::Duration>,
    per_call: Option<std::time::Duration>,
    fut: impl std::future::Future<Output = Result<T, ClientError>>,
) -> Result<T, ClientError> {
    // Prefer the caller's timer driver, then the ambient one, so `now`
    // shares a timeline with the `Sleep` inside `timeout` (which binds the
    // ambient driver); wall clock is the last resort.
    let now = cx
        .timer_driver()
        .or_else(|| Cx::with_current(|ambient| ambient.timer_driver()).flatten())
        .map_or_else(crate::time::wall_now, |timer| timer.now());
    let remaining = cx
        .budget()
        .deadline
        .map(|deadline| std::time::Duration::from_nanos(deadline.duration_since(now)));
    let effective = [remaining, configured, per_call]
        .into_iter()
        .flatten()
        .min();
    let Some(effective) = effective else {
        return fut.await;
    };
    if effective.is_zero() {
        return Err(ClientError::DeadlineExceeded);
    }
    cx.trace(&format!(
        "client.budget_forwarded proto=h1 remaining_ns={} total_timeout_ns={}",
        remaining.map_or_else(|| "none".to_string(), |r| r.as_nanos().to_string()),
        effective.as_nanos(),
    ));
    match crate::time::timeout(now, effective, std::pin::pin!(fut)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ClientError::DeadlineExceeded),
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
    TlsTunnel(Box<TlsStream<HttpConnectTunnel<Self>>>),
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
            buf.put_slice(
                &self.prefetched[self.prefetched_pos..self.prefetched_pos.saturating_add(to_copy)],
            );
            self.prefetched_pos = self.prefetched_pos.saturating_add(to_copy);
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
        if contains_ctl_or_whitespace(authority) {
            return Err(ClientError::InvalidUrl(
                "URL authority cannot contain control characters or whitespace".into(),
            ));
        }

        let (host, port) = if authority.starts_with('[') {
            // IPv6: [::1]:port or [::1]
            let bracket_end = authority.find(']').ok_or_else(|| {
                ClientError::InvalidUrl("unclosed bracket in IPv6 address".into())
            })?;
            let host_str = &authority[..=bracket_end];
            let rest = &authority[bracket_end.saturating_add(1)..];
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
        } else if authority.matches(':').count() > 1 {
            let default_port = match scheme {
                Scheme::Http => 80,
                Scheme::Https => 443,
            };
            (authority.to_owned(), default_port)
        } else if let Some(i) = authority.rfind(':') {
            let port_str = &authority[i.saturating_add(1)..];
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

    /// Returns the authority-form target required by HTTP CONNECT.
    ///
    /// Unlike [`Self::authority`], this always includes the port, including
    /// scheme defaults. RFC 9110 section 9.3.6 requires CONNECT targets to use
    /// `host:port`; omitting `:443` makes standard forward proxies reject a
    /// tunnel for an ordinary `https://host/` URL.
    #[must_use]
    pub fn connect_authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Redirect policy for the HTTP client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectPolicy {
    /// Do not follow redirects.
    None,
    /// Follow up to N redirects.
    Limited(u32),
    /// Follow up to N redirects only when the target URL has the same
    /// scheme, host, and port as the original request.
    SameOrigin(u32),
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self::Limited(10)
    }
}

/// Retry policy for the HTTP client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RetryPolicy {
    /// Do not retry failed requests automatically.
    None,
    /// Retry safe methods once when a reused pooled connection appears stale.
    ///
    /// This covers the common keep-alive race where the peer closed an idle
    /// connection after it was returned to the pool. Non-safe methods are not
    /// retried by this policy because the server may have observed the request.
    #[default]
    SafeMethodsOnStaleReuse,
    /// Retry idempotent methods on retryable response status codes.
    ///
    /// A valid `Retry-After` delta-seconds header is honored before the retry.
    /// The same policy also keeps the stale pooled-connection retry enabled.
    IdempotentStatusCodes {
        /// Maximum number of response-status retries after the first attempt.
        max_retries: u32,
    },
}

impl RetryPolicy {
    fn should_retry_reused_connection_failure(&self, method: &Method, err: &ClientError) -> bool {
        matches!(
            self,
            Self::SafeMethodsOnStaleReuse | Self::IdempotentStatusCodes { .. }
        ) && method_is_safe_to_retry_after_stale_reuse(method)
            && client_error_looks_like_stale_reuse(err)
    }

    fn response_retry_delay(
        &self,
        method: &Method,
        response: &Response,
        retries_so_far: u32,
    ) -> Option<std::time::Duration> {
        let max_retries = match self {
            Self::IdempotentStatusCodes { max_retries } => *max_retries,
            Self::None | Self::SafeMethodsOnStaleReuse => return None,
        };
        if retries_so_far >= max_retries
            || !method_is_idempotent_for_response_retry(method)
            || !status_is_retriable_response(response.status)
        {
            return None;
        }

        Some(retry_after_delay(&response.headers).unwrap_or(std::time::Duration::ZERO))
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

    /// Sets the default total request timeout
    /// (br-asupersync-server-stack-hardening-eeexl1.1.3).
    ///
    /// Meet-composed with the remaining ambient budget and any per-call
    /// override; the tightest bound wins (see
    /// [`HttpClientConfig::request_timeout`]).
    #[must_use]
    pub fn request_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.config.request_timeout = Some(timeout);
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

    /// Follows redirects only when the target has the same scheme, host, and
    /// port as the original request.
    #[must_use]
    pub fn same_origin_redirects(mut self, max: u32) -> Self {
        self.config.redirect_policy = RedirectPolicy::SameOrigin(max);
        self
    }

    /// Disables automatic redirect following.
    #[must_use]
    pub fn no_redirects(mut self) -> Self {
        self.config.redirect_policy = RedirectPolicy::None;
        self
    }

    /// Sets automatic retry behavior.
    #[must_use]
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.config.retry_policy = policy;
        self
    }

    /// Retries safe methods once when a reused pooled connection is stale.
    #[must_use]
    pub fn retry_safe_methods_on_stale_reuse(mut self) -> Self {
        self.config.retry_policy = RetryPolicy::SafeMethodsOnStaleReuse;
        self
    }

    /// Retries idempotent methods on retryable response status codes.
    ///
    /// Valid `Retry-After` delta-seconds response headers are honored before
    /// retrying. Use [`Self::no_retries`] when no automatic retry behavior is
    /// desired.
    #[must_use]
    pub fn retry_idempotent_statuses(mut self, max_retries: u32) -> Self {
        self.config.retry_policy = RetryPolicy::IdempotentStatusCodes { max_retries };
        self
    }

    /// Disables all automatic retries.
    #[must_use]
    pub fn no_retries(mut self) -> Self {
        self.config.retry_policy = RetryPolicy::None;
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

    /// Adds a default header to every request unless that request supplies
    /// the same header name.
    #[must_use]
    pub fn default_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.config
            .default_headers
            .push((name.into(), value.into()));
        self
    }

    /// Adds multiple default headers.
    #[must_use]
    pub fn default_headers<I, N, V>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = (N, V)>,
        N: Into<String>,
        V: Into<String>,
    {
        self.config.default_headers.extend(
            headers
                .into_iter()
                .map(|(name, value)| (name.into(), value.into())),
        );
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

    /// Sets the maximum response body size in bytes.
    ///
    /// By default, the HTTP/1.1 codec limits responses to 16 MiB. Use this
    /// to raise the limit when downloading large files.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let client = HttpClient::builder()
    ///     .max_body_size(500 * 1024 * 1024) // 500 MB
    ///     .build();
    /// ```
    #[must_use]
    pub fn max_body_size(mut self, size: usize) -> Self {
        self.config.max_body_size = Some(size);
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
    /// Retry policy.
    pub retry_policy: RetryPolicy,
    /// Default User-Agent header value.
    pub user_agent: Option<String>,
    /// Default headers attached to each request.
    pub default_headers: Vec<(String, String)>,
    /// Whether the client should automatically persist and attach cookies.
    pub cookie_store: bool,
    /// Optional proxy URL used for outbound requests.
    pub proxy_url: Option<String>,
    /// Maximum response body size in bytes.
    ///
    /// Defaults to `None`, which uses the per-codec default (16 MiB).
    /// Set this to a larger value when downloading large files.
    pub max_body_size: Option<usize>,
    /// Default total request timeout
    /// (br-asupersync-server-stack-hardening-eeexl1.1.3).
    ///
    /// Composed by meet with the remaining ambient budget and any
    /// per-call override: the tightest bound wins, so neither config nor
    /// caller can extend past the caller's budget deadline. `None` (the
    /// default) imposes no client-side total timeout.
    pub request_timeout: Option<std::time::Duration>,
    /// Time source used for pool bookkeeping.
    time_getter: fn() -> Time,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            pool_config: PoolConfig::default(),
            redirect_policy: RedirectPolicy::default(),
            retry_policy: RetryPolicy::default(),
            user_agent: Some("asupersync/0.1".into()),
            default_headers: Vec::new(),
            cookie_store: false,
            proxy_url: None,
            max_body_size: None,
            request_timeout: None,
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

/// Fluent, client-bound request builder for [`HttpClient`].
///
/// The builder only accumulates per-request options. [`send`](Self::send)
/// delegates to the same request path as [`HttpClient::request`] and
/// [`HttpClient::request_with_timeout`], so redirects, pooling, cookies,
/// proxy routing, and cancellation semantics stay centralized.
#[must_use = "client request builders do nothing unless sent"]
#[derive(Clone)]
pub struct ClientRequestBuilder<'a> {
    client: &'a HttpClient,
    method: Method,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    timeout: Option<std::time::Duration>,
}

impl std::fmt::Debug for ClientRequestBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientRequestBuilder")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl<'a> ClientRequestBuilder<'a> {
    fn new(client: &'a HttpClient, method: Method, url: impl Into<String>) -> Self {
        Self {
            client,
            method,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: None,
        }
    }

    /// Set the HTTP method.
    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Set the absolute request URL.
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    /// Add a request header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Add multiple request headers.
    pub fn headers<I, N, V>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = (N, V)>,
        N: Into<String>,
        V: Into<String>,
    {
        self.headers.extend(
            headers
                .into_iter()
                .map(|(name, value)| (name.into(), value.into())),
        );
        self
    }

    /// Set request body bytes.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Append URL-encoded query parameters to the request URL.
    ///
    /// Existing query strings are preserved and extended with `&`.
    pub fn query<I, K, V>(mut self, params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let encoded = url_encode_params(params);
        if !encoded.is_empty() {
            if self.url.contains('?') {
                self.url.push('&');
            } else {
                self.url.push('?');
            }
            self.url.push_str(&encoded);
        }
        self
    }

    /// Set a JSON body and add `Content-Type: application/json`.
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Result<Self, serde_json::Error> {
        self.body = serde_json::to_vec(value)?;
        self.headers
            .push(("Content-Type".to_owned(), "application/json".to_owned()));
        Ok(self)
    }

    /// Set a URL-encoded form body and add
    /// `Content-Type: application/x-www-form-urlencoded`.
    pub fn form<I, K, V>(mut self, params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let encoded = url_encode_params(params);
        self.body = encoded.into_bytes();
        self.headers.push((
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned(),
        ));
        self
    }

    /// Set a multipart form-data body and content type.
    pub fn multipart(mut self, form: &MultipartForm) -> Self {
        self.body = form.to_body();
        self.headers
            .push(("Content-Type".to_owned(), form.content_type_header()));
        self
    }

    /// Set `Authorization: Bearer <token>`.
    pub fn bearer_auth(self, token: impl AsRef<str>) -> Self {
        self.header("Authorization", format!("Bearer {}", token.as_ref()))
    }

    /// Set `Authorization: Basic <credentials>`.
    pub fn basic_auth(self, username: impl AsRef<str>, password: Option<&str>) -> Self {
        let credentials = password.map_or_else(
            || format!("{}:", username.as_ref()),
            |pw| format!("{}:{}", username.as_ref(), pw),
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
        self.header("Authorization", format!("Basic {encoded}"))
    }

    /// Set the `Content-Type` header.
    pub fn content_type(self, content_type: impl Into<String>) -> Self {
        self.header("Content-Type", content_type)
    }

    /// Set the `Accept` header.
    pub fn accept(self, accept: impl Into<String>) -> Self {
        self.header("Accept", accept)
    }

    /// Set a per-call total request timeout.
    ///
    /// The timeout is meet-composed with the client's configured timeout and
    /// the remaining ambient [`Cx`] budget by [`HttpClient::request_with_timeout`].
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Send the request using the bound client.
    pub async fn send(self, cx: &Cx) -> Result<Response, ClientError> {
        if let Some(timeout) = self.timeout {
            self.client
                .request_with_timeout(cx, self.method, &self.url, self.headers, self.body, timeout)
                .await
        } else {
            self.client
                .request(cx, self.method, &self.url, self.headers, self.body)
                .await
        }
    }
}

/// High-level HTTP/1.1 client.
///
/// Provides a simple API for making HTTP requests with automatic connection
/// pooling, DNS resolution, and redirect following.
/// Cloning the client is cheap and shares the same pool, cookie store, and
/// immutable configuration; callers still pass an explicit [`Cx`] to every
/// request, so no process-global ambient client is introduced.
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
#[derive(Clone)]
pub struct HttpClient {
    config: Arc<HttpClientConfig>,
    pool: Arc<Mutex<Pool>>,
    idle_connections: Arc<Mutex<HashMap<PoolKey, Vec<(u64, ClientIo)>>>>,
    cookies: Arc<Mutex<HashMap<String, Vec<StoredCookie>>>>,
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
        let pool_config = config.pool_config.clone();
        Self {
            config: Arc::new(config),
            pool: Arc::new(Mutex::new(Pool::with_config(pool_config))),
            idle_connections: Arc::new(Mutex::new(HashMap::new())),
            cookies: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn pool_now(&self) -> Time {
        (self.config.time_getter)()
    }

    /// Create a fluent request builder bound to this client.
    pub fn request_builder(
        &self,
        method: Method,
        url: impl Into<String>,
    ) -> ClientRequestBuilder<'_> {
        ClientRequestBuilder::new(self, method, url)
    }

    /// Create a fluent `GET` request builder.
    pub fn get(&self, url: impl Into<String>) -> ClientRequestBuilder<'_> {
        self.request_builder(Method::Get, url)
    }

    /// Create a fluent `POST` request builder.
    pub fn post(&self, url: impl Into<String>) -> ClientRequestBuilder<'_> {
        self.request_builder(Method::Post, url)
    }

    /// Create a fluent `PUT` request builder.
    pub fn put(&self, url: impl Into<String>) -> ClientRequestBuilder<'_> {
        self.request_builder(Method::Put, url)
    }

    /// Create a fluent `PATCH` request builder.
    pub fn patch(&self, url: impl Into<String>) -> ClientRequestBuilder<'_> {
        self.request_builder(Method::Patch, url)
    }

    /// Create a fluent `DELETE` request builder.
    pub fn delete(&self, url: impl Into<String>) -> ClientRequestBuilder<'_> {
        self.request_builder(Method::Delete, url)
    }

    /// Create a fluent `HEAD` request builder.
    pub fn head(&self, url: impl Into<String>) -> ClientRequestBuilder<'_> {
        self.request_builder(Method::Head, url)
    }

    /// Create a fluent `OPTIONS` request builder.
    pub fn options(&self, url: impl Into<String>) -> ClientRequestBuilder<'_> {
        self.request_builder(Method::Options, url)
    }

    /// Send a one-shot GET request to the given URL.
    ///
    /// The `cx` parameter participates in structured cancellation: if the
    /// context is cancelled, the in-flight request is abandoned and
    /// `ClientError::Cancelled` is returned.
    pub async fn send_get(&self, cx: &Cx, url: &str) -> Result<Response, ClientError> {
        self.request(cx, Method::Get, url, Vec::new(), Vec::new())
            .await
    }

    /// Send a one-shot POST request to the given URL with a body.
    pub async fn send_post(
        &self,
        cx: &Cx,
        url: &str,
        body: Vec<u8>,
    ) -> Result<Response, ClientError> {
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

    /// Send a one-shot PUT request to the given URL with a body.
    pub async fn send_put(
        &self,
        cx: &Cx,
        url: &str,
        body: Vec<u8>,
    ) -> Result<Response, ClientError> {
        self.request(cx, Method::Put, url, Vec::new(), body).await
    }

    /// Send a one-shot DELETE request to the given URL.
    pub async fn send_delete(&self, cx: &Cx, url: &str) -> Result<Response, ClientError> {
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
        let fut = self.execute_with_redirects(cx, method, parsed, extra_headers, body, 0, 0);
        drive_with_budget_deadline(cx, self.config.request_timeout, None, fut).await
    }

    /// Send a request with an explicit per-call total timeout
    /// (br-asupersync-server-stack-hardening-eeexl1.1.3).
    ///
    /// The effective deadline is the **meet** of the remaining ambient
    /// budget, the client's configured [`request_timeout`]
    /// (`HttpClientConfig::request_timeout`), and `timeout` — the
    /// tightest bound wins, so a per-call override can never extend past
    /// the caller's budget deadline. On expiry the in-flight exchange is
    /// dropped (the pooled connection is discarded, not reused) and
    /// [`ClientError::DeadlineExceeded`] is returned.
    ///
    /// [`request_timeout`]: Self::request_timeout
    pub async fn request_with_timeout(
        &self,
        cx: &Cx,
        method: Method,
        url: &str,
        extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
        timeout: std::time::Duration,
    ) -> Result<Response, ClientError> {
        check_cx(cx)?;
        let parsed = ParsedUrl::parse(url)?;
        let fut = self.execute_with_redirects(cx, method, parsed, extra_headers, body, 0, 0);
        drive_with_budget_deadline(cx, self.config.request_timeout, Some(timeout), fut).await
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
        // The budget deadline bounds the exchange through the response
        // head; streaming the body afterwards is governed by the budget
        // through the caller's own checkpoints.
        let fut = self.execute_with_redirects_streaming(cx, method, parsed, extra_headers, body, 0);
        drive_with_budget_deadline(cx, self.config.request_timeout, None, fut).await
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
        retry_count: u32,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Response, ClientError>> + Send + 'a>,
    > {
        Box::pin(async move {
            check_cx(cx)?;
            let resp =
                Box::pin(self.execute_single(cx, &method, &parsed, &extra_headers, &body)).await?;

            // Check for redirect
            if is_redirect(resp.status) {
                match &self.config.redirect_policy {
                    RedirectPolicy::None => return Ok(resp),
                    RedirectPolicy::Limited(max) | RedirectPolicy::SameOrigin(max) => {
                        if redirect_count >= *max {
                            return Err(ClientError::TooManyRedirects {
                                count: redirect_count.saturating_add(1),
                                max: *max,
                            });
                        }

                        if let Some(location) = get_header(&resp.headers, "Location") {
                            let next_url = resolve_redirect(&parsed, &location);
                            let next_parsed = ParsedUrl::parse(&next_url)?;
                            if !redirect_policy_allows_target(
                                &self.config.redirect_policy,
                                &parsed,
                                &next_parsed,
                            ) {
                                return Ok(resp);
                            }

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
                                    redirect_count.saturating_add(1),
                                    retry_count,
                                )
                                .await;
                        }
                    }
                }
            }

            if let Some(delay) =
                self.config
                    .retry_policy
                    .response_retry_delay(&method, &resp, retry_count)
            {
                sleep_before_retry(cx, delay).await?;
                return self
                    .execute_with_redirects(
                        cx,
                        method,
                        parsed,
                        extra_headers,
                        body,
                        redirect_count,
                        retry_count.saturating_add(1),
                    )
                    .await;
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
                    RedirectPolicy::Limited(max) | RedirectPolicy::SameOrigin(max) => {
                        if redirect_count >= *max {
                            return Err(ClientError::TooManyRedirects {
                                count: redirect_count.saturating_add(1),
                                max: *max,
                            });
                        }

                        if let Some(location) = get_header(&resp.head.headers, "Location") {
                            let status = resp.head.status;
                            let next_url = resolve_redirect(&parsed, &location);
                            let next_parsed = ParsedUrl::parse(&next_url)?;
                            if !redirect_policy_allows_target(
                                &self.config.redirect_policy,
                                &parsed,
                                &next_parsed,
                            ) {
                                return Ok(resp);
                            }

                            // Drop streaming response (closes connection) before following.
                            drop(resp);

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
                                    redirect_count.saturating_add(1),
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
        let request_forbids_reuse = request_forbids_connection_reuse(&req.headers);

        let key = parsed.pool_key();
        let acquired = self.acquire_connection(cx, parsed).await?;
        let mut guard = ConnectionGuard::new(self, key.clone(), acquired.pool_id);
        let reused_connection = !acquired.fresh;

        // Check cancellation after connection acquisition.
        check_cx(cx)?;

        let result = if let Some(max_body_size) = self.config.max_body_size {
            Http1Client::request_with_io_and_max_body_size(acquired.io, req, max_body_size).await
        } else {
            Http1Client::request_with_io(acquired.io, req).await
        };
        match result {
            Ok((response, io)) => {
                check_cx(cx)?;
                guard.defused = true;
                self.store_response_cookies(&parsed.host, &response.headers);
                if !request_forbids_reuse && connection_can_be_reused(&response, method) {
                    self.release_connection(&key, acquired.pool_id, acquired.fresh, io);
                } else {
                    self.drop_connection(&key, acquired.pool_id);
                }
                Ok(response)
            }
            Err(err) => {
                let err = ClientError::from(err);
                if reused_connection
                    && self
                        .config
                        .retry_policy
                        .should_retry_reused_connection_failure(method, &err)
                {
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
        let request_forbids_reuse = request_forbids_connection_reuse(&req.headers);
        let key = parsed.pool_key();
        let acquired = self.acquire_connection(cx, parsed).await?;
        let mut guard = ConnectionGuard::new(self, key.clone(), acquired.pool_id);

        check_cx(cx)?;

        let result = if let Some(max_body_size) = self.config.max_body_size {
            Http1Client::request_with_io_and_max_body_size(acquired.io, req, max_body_size).await
        } else {
            Http1Client::request_with_io(acquired.io, req).await
        };
        match result {
            Ok((response, io)) => {
                check_cx(cx)?;
                guard.defused = true;
                self.store_response_cookies(&parsed.host, &response.headers);
                if !request_forbids_reuse && connection_can_be_reused(&response, method) {
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
        let resp = if let Some(max_body_size) = self.config.max_body_size {
            Http1Client::request_streaming_with_max_body_size(stream, req, max_body_size).await?
        } else {
            Http1Client::request_streaming(stream, req).await?
        };
        check_cx(cx)?;
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
        let (response, _io) = if let Some(max_body_size) = self.config.max_body_size {
            Http1Client::request_with_io_and_max_body_size(proxy_conn.io, req, max_body_size)
                .await?
        } else {
            Http1Client::request_with_io(proxy_conn.io, req).await?
        };
        check_cx(cx)?;
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
        let resp = if let Some(max_body_size) = self.config.max_body_size {
            Http1Client::request_streaming_with_max_body_size(proxy_conn.io, req, max_body_size)
                .await?
        } else {
            Http1Client::request_streaming(proxy_conn.io, req).await?
        };
        check_cx(cx)?;
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
                        ProxyScheme::Socks5 => {
                            return Err(ClientError::InvalidUrl(
                                "SOCKS5 proxy configuration routed to HTTP handler".to_string(),
                            ));
                        }
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
                    &parsed.connect_authority(),
                    self.config.user_agent.as_deref(),
                    &connect_headers,
                )
                .await?;

                #[cfg(feature = "tls")]
                {
                    let domain = parsed.host.trim_start_matches('[').trim_end_matches(']');
                    let tls = self.tls_connect_stream(domain, tunnel).await?;
                    Ok(ProxyConnection {
                        io: ClientIo::TlsTunnel(Box::new(tls)),
                        use_absolute_form: false,
                        proxy_authorization: None,
                    })
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
                    Ok(ProxyConnection {
                        io: ClientIo::Tls(tls),
                        use_absolute_form: false,
                        proxy_authorization: None,
                    })
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
        let default_headers = &self.config.default_headers;
        let has_cookie_header =
            has_header(extra_headers, "cookie") || has_header(default_headers, "cookie");
        let has_proxy_authorization = has_header(extra_headers, "proxy-authorization")
            || has_header(default_headers, "proxy-authorization");
        let has_user_agent_header =
            has_header(extra_headers, "user-agent") || has_header(default_headers, "user-agent");
        let request_target = request_target.unwrap_or_else(|| parsed.path.clone());
        let mut builder =
            Request::builder(method.clone(), request_target).header("Host", parsed.authority());

        if !has_user_agent_header && let Some(user_agent) = self.config.user_agent.as_deref() {
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
            .headers(
                default_headers
                    .iter()
                    .filter(|(name, _)| {
                        !name.eq_ignore_ascii_case("host") && !has_header(extra_headers, name)
                    })
                    .cloned(),
            )
            .headers(
                extra_headers
                    .iter()
                    .filter(|(name, _)| !name.eq_ignore_ascii_case("host"))
                    .cloned(),
            )
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

        {
            let mut pool = self.pool.lock();
            let mut idle = self.idle_connections.lock();
            match pool.try_acquire(&key, now) {
                Some(pool_id) => {
                    if let Some(io) = Self::take_idle_connection_locked(&mut idle, &key, pool_id) {
                        return Ok(AcquiredConnection {
                            pool_id: Some(pool_id),
                            io,
                            fresh: false,
                        });
                    }
                    // Metadata can be stale if a prior request failed before reinserting.
                    pool.remove(&key, pool_id);
                }
                None => {}
            }
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

        if fresh_id.is_none() {
            return Err(ClientError::PoolExhausted {
                host: parsed.host.clone(),
                port: parsed.port,
            });
        }

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
            let mut pool = self.pool.lock();
            let returned_to_pool = if fresh {
                pool.mark_connected(key, id, now)
            } else {
                pool.release(key, id, now)
            };

            if returned_to_pool {
                let mut idle = self.idle_connections.lock();
                Self::store_idle_connection_locked(&mut idle, key.clone(), id, io);
            } else {
                pool.remove(key, id);
                let mut idle = self.idle_connections.lock();
                Self::remove_idle_connection_locked(&mut idle, key, id);
            }
        }
    }

    fn drop_connection(&self, key: &PoolKey, pool_id: Option<u64>) {
        if let Some(id) = pool_id {
            self.pool.lock().remove(key, id);
            self.remove_idle_connection(key, id);
        }
    }

    fn remove_idle_connection(&self, key: &PoolKey, id: u64) {
        let mut idle = self.idle_connections.lock();
        Self::remove_idle_connection_locked(&mut idle, key, id);
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

impl HttpClient {
    fn take_idle_connection_locked(
        idle: &mut HashMap<PoolKey, Vec<(u64, ClientIo)>>,
        key: &PoolKey,
        id: u64,
    ) -> Option<ClientIo> {
        let (io, remove_key) = {
            let entries = idle.get_mut(key)?;
            let position = entries.iter().position(|(entry_id, _)| *entry_id == id)?;
            let (_, io) = entries.swap_remove(position);
            (io, entries.is_empty())
        };
        if remove_key {
            idle.remove(key);
        }
        Some(io)
    }

    fn store_idle_connection_locked(
        idle: &mut HashMap<PoolKey, Vec<(u64, ClientIo)>>,
        key: PoolKey,
        id: u64,
        io: ClientIo,
    ) {
        idle.entry(key).or_default().push((id, io));
    }

    fn remove_idle_connection_locked(
        idle: &mut HashMap<PoolKey, Vec<(u64, ClientIo)>>,
        key: &PoolKey,
        id: u64,
    ) {
        if let Some(entries) = idle.get_mut(key) {
            if let Some(position) = entries.iter().position(|(entry_id, _)| *entry_id == id) {
                entries.swap_remove(position);
            }
            if entries.is_empty() {
                idle.remove(key);
            }
        }
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

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
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
    // br-asupersync-7xe690: RFC 6265 §5.2.3 specifies paired-DQUOTE strip:
    // both leading AND trailing '"' must be present to remove BOTH; otherwise
    // both are kept. The previous trim_matches('"') was greedy/asymmetric and
    // mis-handled `name="abc` (kept as `abc`), `name=abc"` (kept as `abc`),
    // and `name=""x""` (collapsed to `x` instead of `"x"`).
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value);
    Some((name.to_owned(), value.to_owned()))
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
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(ClientError::InvalidUrl(format!(
            "proxy URL missing authority: {proxy_url}"
        )));
    }
    if contains_ctl_or_whitespace(authority) {
        return Err(ClientError::InvalidUrl(
            "proxy URL authority cannot contain control characters or whitespace".into(),
        ));
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

    if authority.matches(':').count() > 1 {
        // Unbracketed IPv6 address: ambiguous port parsing, treat entire authority as host
        return Ok((authority.to_owned(), default_port));
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

    let mut greeting = Vec::with_capacity(2_usize.saturating_add(methods.len()));
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

    let mut auth = Vec::with_capacity(
        3_usize
            .saturating_add(username.len())
            .saturating_add(password.len()),
    );
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
    if response.status == 101
        || response
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("upgrade"))
        || header_has_token(&response.headers, "connection", "upgrade")
    {
        return false;
    }

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
        // Unreachable for this h1 client (responses are parsed from h1 wire
        // text), but HTTP/2 connections are persistent by default and carry
        // no Connection header semantics (RFC 9113 §8.2.2).
        Version::Http2 => true,
    }
}

fn request_forbids_connection_reuse(headers: &[(String, String)]) -> bool {
    header_has_token(headers, "connection", "close")
        || header_has_token(headers, "connection", "upgrade")
        || headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("upgrade"))
}

fn method_is_safe_to_retry_after_stale_reuse(method: &Method) -> bool {
    matches!(
        method,
        Method::Get | Method::Head | Method::Options | Method::Trace
    )
}

fn method_is_idempotent_for_response_retry(method: &Method) -> bool {
    matches!(
        method,
        Method::Get | Method::Head | Method::Put | Method::Delete | Method::Options | Method::Trace
    )
}

fn status_is_retriable_response(status: u16) -> bool {
    matches!(status, 408 | 425 | 429 | 500 | 502 | 503 | 504)
}

fn retry_after_delay(headers: &[(String, String)]) -> Option<std::time::Duration> {
    get_header(headers, "Retry-After").and_then(|value| parse_retry_after_delta(&value))
}

fn parse_retry_after_delta(value: &str) -> Option<std::time::Duration> {
    let seconds = value.trim().parse::<u64>().ok()?;
    Some(std::time::Duration::from_secs(seconds))
}

fn cx_timer_now(cx: &Cx) -> Time {
    cx.timer_driver()
        .or_else(|| Cx::with_current(|ambient| ambient.timer_driver()).flatten())
        .map_or_else(crate::time::wall_now, |timer| timer.now())
}

async fn sleep_before_retry(cx: &Cx, delay: std::time::Duration) -> Result<(), ClientError> {
    if delay.is_zero() {
        return Ok(());
    }
    check_cx(cx)?;
    crate::time::sleep(cx_timer_now(cx), delay).await;
    check_cx(cx)
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

fn redirect_policy_allows_target(
    policy: &RedirectPolicy,
    from: &ParsedUrl,
    to: &ParsedUrl,
) -> bool {
    match policy {
        RedirectPolicy::None => false,
        RedirectPolicy::Limited(_) => true,
        RedirectPolicy::SameOrigin(_) => same_origin(from, to),
    }
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
    memmem::find(buf, b"\r\n\r\n").map(|idx| idx.saturating_add(4))
}

fn contains_ctl_line_break(s: &str) -> bool {
    s.chars().any(|c| matches!(c, '\r' | '\n'))
}

fn contains_ctl_or_whitespace(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_control() || c.is_whitespace())
}

fn invalid_connect_authority(reason: &'static str) -> ClientError {
    ClientError::InvalidConnectInput(format!(
        "target authority must be host:port authority-form: {reason}"
    ))
}

fn validate_connect_authority_form(target_authority: &str) -> Result<(), ClientError> {
    if target_authority.trim().is_empty() {
        return Err(ClientError::InvalidConnectInput(
            "target authority cannot be empty".into(),
        ));
    }
    if contains_ctl_or_whitespace(target_authority) {
        return Err(invalid_connect_authority(
            "control characters and whitespace are forbidden",
        ));
    }
    if target_authority
        .bytes()
        .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@'))
    {
        return Err(invalid_connect_authority(
            "scheme, path, query, fragment, and userinfo delimiters are forbidden",
        ));
    }

    let port = if let Some(bracketed) = target_authority.strip_prefix('[') {
        let bracket_end = bracketed
            .find(']')
            .ok_or_else(|| invalid_connect_authority("missing closing IPv6 bracket"))?;
        let host_literal = &bracketed[..bracket_end];
        if host_literal.is_empty() {
            return Err(invalid_connect_authority("empty bracketed host"));
        }
        if host_literal.chars().any(|c| matches!(c, '[' | ']')) {
            return Err(invalid_connect_authority(
                "nested brackets are not valid in a host literal",
            ));
        }
        let after_host = &bracketed[bracket_end.saturating_add(1)..];
        after_host
            .strip_prefix(':')
            .ok_or_else(|| invalid_connect_authority("bracketed hosts require an explicit port"))?
    } else {
        if target_authority.chars().any(|c| matches!(c, '[' | ']')) {
            return Err(invalid_connect_authority(
                "brackets are only valid around IPv6 host literals",
            ));
        }
        let (host, port) = target_authority
            .rsplit_once(':')
            .ok_or_else(|| invalid_connect_authority("missing explicit port"))?;
        if host.is_empty() {
            return Err(invalid_connect_authority("empty host"));
        }
        if host.contains(':') {
            return Err(invalid_connect_authority(
                "IPv6 host literals must be bracketed",
            ));
        }
        port
    };

    if port.is_empty() {
        return Err(invalid_connect_authority("empty port"));
    }
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid_connect_authority("port must contain only digits"));
    }
    port.parse::<u16>()
        .map_err(|_| invalid_connect_authority("port is outside the u16 range"))?;
    Ok(())
}

fn validate_connect_inputs(
    target_authority: &str,
    extra_headers: &[(String, String)],
    user_agent: Option<&str>,
) -> Result<(), ClientError> {
    validate_connect_authority_form(target_authority)?;
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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
    fn parse_url_handles_unbracketed_ipv6_host() {
        let url = ParsedUrl::parse("http://::1/healthz").expect("parse url");
        assert_eq!(url.host, "::1");
        assert_eq!(url.port, 80);
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
    fn parse_url_rejects_control_or_whitespace_in_authority() {
        let result = ParsedUrl::parse("http://example.com\r\nx-injected: y/path");
        assert!(matches!(result, Err(ClientError::InvalidUrl(_))));

        let result = ParsedUrl::parse("http://example.com bad/path");
        assert!(matches!(result, Err(ClientError::InvalidUrl(_))));
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
    fn parse_proxy_endpoint_rejects_control_or_whitespace_in_authority() {
        for proxy_url in [
            "http:// proxy.local:8080",
            "http://proxy.local:8080 /path",
            "http://proxy.\tlocal:8080",
            "socks5://agent:pw@127.0.0.1\n:1080",
        ] {
            let error = parse_proxy_endpoint(proxy_url)
                .expect_err("proxy authority whitespace must fail closed");
            assert!(
                matches!(error, ClientError::InvalidUrl(ref message)
                    if message.contains("authority cannot contain control characters or whitespace")),
                "unexpected error for {proxy_url:?}: {error}"
            );
        }
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

    #[test]
    fn connect_authority_always_includes_port() {
        let https = ParsedUrl::parse("https://example.com/path").unwrap();
        assert_eq!(https.connect_authority(), "example.com:443");

        let http = ParsedUrl::parse("http://example.com/path").unwrap();
        assert_eq!(http.connect_authority(), "example.com:80");

        let custom = ParsedUrl::parse("https://example.com:8443/path").unwrap();
        assert_eq!(custom.connect_authority(), "example.com:8443");

        let ipv6 = ParsedUrl::parse("https://[2001:db8::1]/path").unwrap();
        assert_eq!(ipv6.connect_authority(), "[2001:db8::1]:443");
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

        let err = ClientError::PoolExhausted {
            host: "example.com".into(),
            port: 80,
        };
        let msg = format!("{err}");
        assert!(msg.contains("example.com"));
        assert!(msg.contains("80"));
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
        assert_eq!(config.retry_policy, RetryPolicy::SafeMethodsOnStaleReuse);
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
        assert_eq!(
            client.config.retry_policy,
            RetryPolicy::SafeMethodsOnStaleReuse
        );
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
            .no_retries()
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
        assert_eq!(client.config.retry_policy, RetryPolicy::None);
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
            .retry_policy(RetryPolicy::SafeMethodsOnStaleReuse)
            .user_agent("asupersync-test/2.0")
            .default_header("Accept", "application/json")
            .default_headers([("X-Trace-Id", "client-default")])
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
            client.config.retry_policy,
            RetryPolicy::SafeMethodsOnStaleReuse
        );
        assert_eq!(
            client.config.user_agent.as_deref(),
            Some("asupersync-test/2.0")
        );
        assert_eq!(
            client.config.default_headers,
            vec![
                ("Accept".to_owned(), "application/json".to_owned()),
                ("X-Trace-Id".to_owned(), "client-default".to_owned())
            ]
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
    fn builder_same_origin_redirects_sets_policy() {
        let client = HttpClient::builder().same_origin_redirects(4).build();

        assert!(matches!(
            client.config.redirect_policy,
            RedirectPolicy::SameOrigin(4)
        ));
    }

    #[test]
    fn client_default_creates_pool() {
        let client = HttpClient::new();
        let stats = client.pool_stats();
        assert_eq!(stats.total_connections, 0);
    }

    #[test]
    fn default_for_runtime_reuses_lazy_cx_slot() {
        let cx = crate::cx::Cx::for_testing_with_io();

        let first = crate::http::Client::default_for_runtime(&cx);
        let second = crate::http::Client::default_for_runtime(&cx);

        assert!(
            std::sync::Arc::ptr_eq(&first.pool, &second.pool),
            "runtime default client calls on one Cx must share the pool"
        );
        assert!(
            std::sync::Arc::ptr_eq(&first.idle_connections, &second.idle_connections),
            "runtime default client calls on one Cx must share idle state"
        );
        assert!(
            std::sync::Arc::ptr_eq(&first.cookies, &second.cookies),
            "runtime default client calls on one Cx must share cookie state"
        );
    }

    #[test]
    fn default_for_runtime_is_not_process_global() {
        let first_cx = crate::cx::Cx::for_testing_with_io();
        let second_cx = crate::cx::Cx::for_testing_with_io();

        let first = crate::http::Client::default_for_runtime(&first_cx);
        let second = crate::http::Client::default_for_runtime(&second_cx);

        assert!(
            !std::sync::Arc::ptr_eq(&first.pool, &second.pool),
            "independent Cx roots must not share a process-global default client"
        );
    }

    #[test]
    fn client_request_builder_collects_fluent_options() {
        let client = HttpClient::new();
        let builder = client
            .request_builder(Method::Post, "http://example.com/api")
            .header("X-Trace-Id", "trace-1")
            .headers([("Accept", "application/json")])
            .content_type("application/json")
            .bearer_auth("token-1")
            .body(b"{\"ok\":true}".to_vec())
            .timeout(std::time::Duration::from_millis(250));

        assert_eq!(builder.method, Method::Post);
        assert_eq!(builder.url, "http://example.com/api");
        assert_eq!(builder.body.as_slice(), b"{\"ok\":true}");
        assert_eq!(builder.timeout, Some(std::time::Duration::from_millis(250)));
        assert!(
            builder
                .headers
                .contains(&("X-Trace-Id".to_owned(), "trace-1".to_owned()))
        );
        assert!(
            builder
                .headers
                .contains(&("Accept".to_owned(), "application/json".to_owned()))
        );
        assert!(
            builder
                .headers
                .contains(&("Content-Type".to_owned(), "application/json".to_owned()))
        );
        assert!(
            builder
                .headers
                .contains(&("Authorization".to_owned(), "Bearer token-1".to_owned()))
        );
    }

    #[test]
    fn short_client_methods_create_fluent_builders() {
        let client = HttpClient::new();

        assert_eq!(client.get("http://example.com/get").method, Method::Get);
        assert_eq!(client.post("http://example.com/post").method, Method::Post);
        assert_eq!(client.put("http://example.com/put").method, Method::Put);
        assert_eq!(
            client.patch("http://example.com/patch").method,
            Method::Patch
        );
        assert_eq!(
            client.delete("http://example.com/delete").method,
            Method::Delete
        );
        assert_eq!(client.head("http://example.com/head").method, Method::Head);
        assert_eq!(
            client.options("http://example.com/options").method,
            Method::Options
        );
    }

    #[test]
    fn client_request_builder_json_and_basic_auth_helpers() {
        let client = HttpClient::new();
        let builder = client
            .post("http://example.com/api")
            .json(&serde_json::json!({"ok": true}))
            .expect("json body should serialize")
            .basic_auth("alice", Some("secret"));

        assert_eq!(builder.method, Method::Post);
        assert_eq!(
            builder.body,
            serde_json::to_vec(&serde_json::json!({"ok": true})).expect("json body")
        );
        assert!(
            builder
                .headers
                .contains(&("Content-Type".to_owned(), "application/json".to_owned()))
        );
        assert!(builder.headers.contains(&(
            "Authorization".to_owned(),
            "Basic YWxpY2U6c2VjcmV0".to_owned()
        )));
    }

    #[test]
    fn client_request_builder_query_extends_existing_url() {
        let client = HttpClient::new();
        let builder = client
            .get("http://example.com/search?existing=true")
            .query([("q", "rust async"), ("tag", "a+b")]);

        assert_eq!(
            builder.url,
            "http://example.com/search?existing=true&q=rust%20async&tag=a%2Bb"
        );
        assert!(builder.body.is_empty());
    }

    #[test]
    fn client_request_builder_form_sets_body_and_content_type() {
        let client = HttpClient::new();
        let builder = client
            .post("http://example.com/form")
            .form([("name", "Ada Lovelace"), ("role", "math+runtime")]);

        assert_eq!(builder.method, Method::Post);
        assert_eq!(
            builder.body.as_slice(),
            b"name=Ada%20Lovelace&role=math%2Bruntime"
        );
        assert!(builder.headers.contains(&(
            "Content-Type".to_owned(),
            "application/x-www-form-urlencoded".to_owned()
        )));
    }

    #[test]
    fn client_request_builder_send_respects_cancelled_cx_before_dialing() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let err = block_on(
            client
                .get("http://127.0.0.1:1/cancelled")
                .header("X-Trace-Id", "trace-1")
                .send(&cx),
        )
        .expect_err("cancelled cx should reject before connect");

        assert!(err.is_cancelled());
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
            assert!(pool.mark_connected(&key, id, Time::from_nanos(20)));
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
    fn release_connection_drops_fresh_io_when_mark_connected_is_rejected() {
        let client = HttpClient::builder()
            .with_time_getter(http_client_test_time)
            .build();
        let key = PoolKey::http("example.com", None);
        let id = {
            let mut pool = client.pool.lock();
            let id = pool.register_connecting(key.clone(), Time::from_nanos(10), 1);
            assert!(pool.mark_connected(&key, id, Time::from_nanos(20)));
            drop(pool);
            id
        };

        set_http_client_test_time(30);
        client.release_connection(&key, Some(id), true, loopback_client_io());

        assert!(
            client.pool.lock().get_connection_meta(&key, id).is_none(),
            "invalid fresh release must retire pool metadata instead of storing idle IO"
        );
        assert!(
            client.idle_connections.lock().get(&key).is_none(),
            "invalid fresh release must not leave idle IO behind"
        );
    }

    #[test]
    fn release_connection_drops_reused_io_when_release_is_rejected() {
        let client = HttpClient::builder()
            .with_time_getter(http_client_test_time)
            .build();
        let key = PoolKey::http("example.com", None);
        let id = client
            .pool
            .lock()
            .register_connecting(key.clone(), Time::from_nanos(10), 1);

        set_http_client_test_time(30);
        client.release_connection(&key, Some(id), false, loopback_client_io());

        assert!(
            client.pool.lock().get_connection_meta(&key, id).is_none(),
            "invalid reused release must retire pool metadata instead of storing idle IO"
        );
        assert!(
            client.idle_connections.lock().get(&key).is_none(),
            "invalid reused release must not leave idle IO behind"
        );
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
    fn release_connection_holds_pool_lock_until_idle_io_is_recorded() {
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let client = Arc::new(
            HttpClient::builder()
                .with_time_getter(http_client_test_time)
                .build(),
        );
        let key = PoolKey::http("example.com", None);
        let id = client
            .pool
            .lock()
            .register_connecting(key.clone(), Time::ZERO, 1);

        let idle_guard = client.idle_connections.lock();
        let (tx, rx) = mpsc::channel();
        let release_client = Arc::clone(&client);
        let release_key = key.clone();
        let release_thread = std::thread::spawn(move || {
            tx.send(()).expect("signal release start");
            release_client.release_connection(&release_key, Some(id), true, loopback_client_io());
        });

        rx.recv().expect("release thread should start");
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if client.pool.try_lock().is_none() {
                break;
            }
            assert!(
                Instant::now() <= deadline,
                "release_connection should hold the pool lock until idle IO is inserted"
            );
            std::thread::yield_now();
        }

        drop(idle_guard);
        release_thread
            .join()
            .expect("release thread should complete");

        assert_eq!(
            client.idle_connections.lock().get(&key).map_or(0, Vec::len),
            1,
            "release must leave idle IO recorded once the lock handoff completes"
        );
        let state = client
            .pool
            .lock()
            .get_connection_meta(&key, id)
            .expect("connection metadata should remain")
            .state;
        assert_eq!(state, crate::http::pool::PooledConnectionState::Idle);
    }

    #[test]
    fn parse_set_cookie_pair_extracts_first_pair() {
        let parsed = parse_set_cookie_pair("session=abc123; Path=/; HttpOnly");
        assert_eq!(parsed, Some(("session".to_string(), "abc123".to_string())));

        assert_eq!(parse_set_cookie_pair(""), None);
        assert_eq!(parse_set_cookie_pair("invalid"), None);
        assert_eq!(parse_set_cookie_pair(" =value"), None);
    }

    /// br-asupersync-7xe690: RFC 6265 §5.2.3 paired-DQUOTE strip — only
    /// remove BOTH quotes when both are present; never trim asymmetric or
    /// repeated quotes. Previously parse_set_cookie_pair used trim_matches
    /// which is greedy/asymmetric.
    #[test]
    fn parse_set_cookie_pair_paired_dquote_strip_per_rfc6265() {
        // Symmetric paired quotes: strip both.
        assert_eq!(
            parse_set_cookie_pair("session=\"abc123==\""),
            Some(("session".to_string(), "abc123==".to_string())),
            "paired DQUOTEs must be stripped together"
        );
        // Leading-only quote: keep both bytes literal (one-sided is not paired).
        assert_eq!(
            parse_set_cookie_pair("name=\"abc"),
            Some(("name".to_string(), "\"abc".to_string())),
            "asymmetric leading-only DQUOTE must NOT be stripped"
        );
        // Trailing-only quote: keep both bytes literal.
        assert_eq!(
            parse_set_cookie_pair("name=abc\""),
            Some(("name".to_string(), "abc\"".to_string())),
            "asymmetric trailing-only DQUOTE must NOT be stripped"
        );
        // Doubled quotes on each side: strip exactly one pair, leaving the
        // inner pair literal. Previously trim_matches collapsed all four to
        // the inner contents.
        assert_eq!(
            parse_set_cookie_pair("name=\"\"x\"\""),
            Some(("name".to_string(), "\"x\"".to_string())),
            "double-quoted value must yield single inner pair literal, not collapse"
        );
        // No quotes: passthrough.
        assert_eq!(
            parse_set_cookie_pair("name=abc"),
            Some(("name".to_string(), "abc".to_string()))
        );
        // Empty value with paired quotes: paired strip yields empty string.
        assert_eq!(
            parse_set_cookie_pair("k=\"\""),
            Some(("k".to_string(), String::new()))
        );
        // Single quote (only one byte): not enough to be paired, must be kept.
        assert_eq!(
            parse_set_cookie_pair("k=\""),
            Some(("k".to_string(), "\"".to_string())),
            "a single-byte DQUOTE value must remain literal"
        );
    }

    #[test]
    fn cookie_store_replays_quoted_set_cookie_value_without_quotes() {
        fn rfc6265_reference_pair(raw: &str) -> Option<(String, String)> {
            let pair = raw.split(';').next()?.trim();
            let (name, value) = pair.split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|inner| inner.strip_suffix('"'))
                .unwrap_or(value);
            Some((name.to_string(), value.to_string()))
        }

        let raw = r#"session="abc123=="; Path=/; HttpOnly"#;
        assert_eq!(parse_set_cookie_pair(raw), rfc6265_reference_pair(raw));

        let client = HttpClient::builder().cookie_store(true).build();
        client.store_response_cookies(
            "example.com",
            &[("Set-Cookie".to_string(), raw.to_string())],
        );

        let cookie_header = client
            .cookie_header_for_host("example.com")
            .expect("cookie header");
        assert_eq!(cookie_header, "session=abc123==");
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
    fn build_request_ignores_explicit_host_header() {
        let client = HttpClient::builder().build();
        let parsed = ParsedUrl::parse("http://example.com/path").expect("valid URL");
        let req = client.build_request(
            &Method::Get,
            &parsed,
            &[("Host".to_string(), "attacker.test".to_string())],
            &[],
            None,
            None,
        );

        let host_headers: Vec<_> = req
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .collect();
        assert_eq!(host_headers.len(), 1);
        assert_eq!(host_headers[0].1, "example.com");
    }

    #[test]
    fn build_request_applies_default_headers_as_request_fallbacks() {
        let client = HttpClient::builder()
            .default_header("Accept", "application/json")
            .default_header("Host", "wrong.example")
            .default_header("User-Agent", "asupersync-test/default")
            .default_header("X-Trace-Id", "client-default")
            .build();
        let parsed = ParsedUrl::parse("http://example.com/path").expect("valid URL");
        let req = client.build_request(
            &Method::Get,
            &parsed,
            &[
                ("Host".to_string(), "attacker.test".to_string()),
                ("X-Trace-Id".to_string(), "request-override".to_string()),
            ],
            &[],
            None,
            None,
        );

        assert_eq!(
            get_header(&req.headers, "accept"),
            Some("application/json".to_string())
        );
        assert_eq!(
            get_header(&req.headers, "user-agent"),
            Some("asupersync-test/default".to_string())
        );
        assert_eq!(
            get_header(&req.headers, "x-trace-id"),
            Some("request-override".to_string())
        );

        let host_headers: Vec<_> = req
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .collect();
        assert_eq!(host_headers.len(), 1);
        assert_eq!(host_headers[0].1, "example.com");

        let trace_headers = req
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("x-trace-id"))
            .count();
        assert_eq!(trace_headers, 1);
    }

    #[test]
    fn build_request_treats_default_cookie_and_proxy_authorization_as_explicit() {
        let client = HttpClient::builder()
            .cookie_store(true)
            .default_header("Cookie", "client-default=1")
            .default_header("Proxy-Authorization", "Basic Y2xpZW50")
            .build();
        client.store_response_cookies(
            "example.com",
            &[("Set-Cookie".to_string(), "stored=ignored".to_string())],
        );

        let parsed = ParsedUrl::parse("http://example.com/path").expect("valid URL");
        let req = client.build_request(
            &Method::Get,
            &parsed,
            &[],
            &[],
            Some(absolute_request_target(&parsed)),
            Some("Basic cHJveHk="),
        );

        assert_eq!(
            get_header(&req.headers, "cookie"),
            Some("client-default=1".to_string())
        );
        assert_eq!(
            get_header(&req.headers, "proxy-authorization"),
            Some("Basic Y2xpZW50".to_string())
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
            buf.put_slice(&self.read_data[self.read_pos..self.read_pos.saturating_add(to_copy)]);
            self.read_pos = self.read_pos.saturating_add(to_copy);
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
    fn connect_authority_accepts_bracketed_ipv6_with_port() {
        let io = ConnectTestIo::new("HTTP/1.1 200 Connection Established\r\n\r\n");
        let tunnel = block_on(establish_http_connect_tunnel(
            io,
            "[2001:db8::1]:443",
            None,
            &[],
        ))
        .expect("bracketed IPv6 authority should establish");
        let io = tunnel.into_inner();
        let written = String::from_utf8(io.written).expect("request should be utf8");
        assert!(written.starts_with("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"));
        assert!(written.contains("\r\nHost: [2001:db8::1]:443\r\n"));
    }

    #[test]
    fn connect_authority_rejects_ambiguous_targets() {
        for target_authority in [
            "http://example.com:443",
            "example.com",
            "example.com:",
            "example.com:99999",
            "example.com:443/path",
            "example.com:443?token=1",
            "example.com:443#frag",
            "user@example.com:443",
            "2001:db8::1:443",
            "[::1]",
            "[::1]:",
            "[::1]@example.com:443",
            "[]:443",
            "exa mple.com:443",
        ] {
            let io = ConnectTestIo::new("HTTP/1.1 200 OK\r\n\r\n");
            let err = block_on(establish_http_connect_tunnel(
                io,
                target_authority,
                None,
                &[],
            ))
            .expect_err("malformed CONNECT authority must be rejected");
            match err {
                ClientError::InvalidConnectInput(msg) => {
                    assert!(
                        msg.contains("authority"),
                        "unexpected message for {target_authority}: {msg}"
                    );
                }
                other => panic!("unexpected error for {target_authority}: {other:?}"),
            }
        }
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
        let b = a;
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Limited"));
        assert!(dbg.contains('5'));
        let dbg2 = format!("{b:?}");
        assert_eq!(dbg, dbg2);
    }

    #[test]
    fn same_origin_redirect_policy_only_allows_matching_origin() {
        let policy = RedirectPolicy::SameOrigin(5);
        let current = ParsedUrl::parse("http://Example.com:8080/old").unwrap();
        let same = ParsedUrl::parse("http://example.COM:8080/new").unwrap();
        let different_host = ParsedUrl::parse("http://other.example:8080/new").unwrap();
        let different_port = ParsedUrl::parse("http://example.com:9090/new").unwrap();
        let different_scheme = ParsedUrl::parse("https://example.com:8080/new").unwrap();

        assert!(redirect_policy_allows_target(&policy, &current, &same));
        assert!(!redirect_policy_allows_target(
            &policy,
            &current,
            &different_host
        ));
        assert!(!redirect_policy_allows_target(
            &policy,
            &current,
            &different_port
        ));
        assert!(!redirect_policy_allows_target(
            &policy,
            &current,
            &different_scheme
        ));
        assert!(redirect_policy_allows_target(
            &RedirectPolicy::Limited(5),
            &current,
            &different_host
        ));
        assert!(!redirect_policy_allows_target(
            &RedirectPolicy::None,
            &current,
            &same
        ));
    }

    #[test]
    fn retry_policy_default_is_safe_stale_reuse() {
        assert_eq!(RetryPolicy::default(), RetryPolicy::SafeMethodsOnStaleReuse);
    }

    #[test]
    fn retry_policy_gates_stale_reuse_by_policy_method_and_error() {
        let stale_err = || {
            ClientError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed idle connection",
            ))
        };
        let other_err = || ClientError::InvalidUrl("not a transport error".into());

        let policy = RetryPolicy::SafeMethodsOnStaleReuse;
        assert!(policy.should_retry_reused_connection_failure(&Method::Get, &stale_err()));
        assert!(policy.should_retry_reused_connection_failure(&Method::Head, &stale_err()));
        assert!(!policy.should_retry_reused_connection_failure(&Method::Post, &stale_err()));
        assert!(!policy.should_retry_reused_connection_failure(&Method::Get, &other_err()));

        assert!(
            !RetryPolicy::None.should_retry_reused_connection_failure(&Method::Get, &stale_err())
        );
    }

    #[test]
    fn retry_policy_response_status_matrix_is_idempotent_and_retry_after_aware() {
        let response = Response {
            version: Version::Http11,
            status: 503,
            reason: "Service Unavailable".to_owned(),
            headers: vec![("Retry-After".to_owned(), "7".to_owned())],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        let policy = RetryPolicy::IdempotentStatusCodes { max_retries: 1 };

        assert_eq!(
            policy.response_retry_delay(&Method::Get, &response, 0),
            Some(std::time::Duration::from_secs(7))
        );
        assert_eq!(
            policy.response_retry_delay(&Method::Put, &response, 0),
            Some(std::time::Duration::from_secs(7))
        );
        assert_eq!(
            policy.response_retry_delay(&Method::Post, &response, 0),
            None
        );
        assert_eq!(
            policy.response_retry_delay(&Method::Patch, &response, 0),
            None
        );
        assert_eq!(
            policy.response_retry_delay(&Method::Get, &response, 1),
            None
        );

        let mut non_retriable = response;
        non_retriable.status = 400;
        assert_eq!(
            policy.response_retry_delay(&Method::Get, &non_retriable, 0),
            None
        );
        assert_eq!(
            RetryPolicy::SafeMethodsOnStaleReuse.response_retry_delay(
                &Method::Get,
                &non_retriable,
                0
            ),
            None
        );
    }

    #[test]
    fn retry_after_delta_parser_rejects_invalid_values() {
        assert_eq!(
            parse_retry_after_delta(" 12 "),
            Some(std::time::Duration::from_secs(12))
        );
        assert_eq!(
            parse_retry_after_delta("Wed, 21 Oct 2015 07:28:00 GMT"),
            None
        );
        assert_eq!(parse_retry_after_delta("-1"), None);
        assert_eq!(parse_retry_after_delta("abc"), None);
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

    #[test]
    fn connection_not_reused_for_protocol_upgrade() {
        let response = Response {
            version: Version::Http11,
            status: 101,
            reason: "Switching Protocols".into(),
            headers: vec![
                ("Connection".into(), "Upgrade".into()),
                ("Upgrade".into(), "websocket".into()),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        assert!(!connection_can_be_reused(&response, &Method::Get));
    }

    #[test]
    fn request_connection_close_forbids_reuse() {
        let headers = vec![("Connection".to_string(), "keep-alive, close".to_string())];
        assert!(request_forbids_connection_reuse(&headers));

        let upgrade_headers = vec![("Upgrade".to_string(), "websocket".to_string())];
        assert!(request_forbids_connection_reuse(&upgrade_headers));
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
        let result = block_on(client.send_get(&cx, "http://example.com/test"));
        assert!(result.is_err());
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn post_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.send_post(&cx, "http://example.com/submit", b"data".to_vec()));
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn put_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.send_put(&cx, "http://example.com/item", b"data".to_vec()));
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn delete_returns_cancelled_when_cx_already_cancelled() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let client = HttpClient::new();
        let result = block_on(client.send_delete(&cx, "http://example.com/item"));
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
        let result = block_on(client.send_get(&cx, "http://127.0.0.1:1/nonexistent"));
        // The request should fail with a connect error (not a cancellation error).
        assert!(result.is_err());
        assert!(!result.unwrap_err().is_cancelled());
    }

    #[test]
    fn acquire_connection_respects_pool_limits_before_opening_socket() {
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        listener
            .set_nonblocking(true)
            .expect("set nonblocking listener");
        let addr = listener.local_addr().expect("listener address");
        let url = format!("http://{addr}/pooled");
        let parsed = ParsedUrl::parse(&url).expect("parse pooled url");
        let key = parsed.pool_key();

        let client = HttpClient::builder()
            .max_connections_per_host(1)
            .max_total_connections(1)
            .build();
        client.pool.lock().register_connecting(key, Time::ZERO, 1);

        let cx = Cx::for_testing();
        let err = match block_on(client.acquire_connection(&cx, &parsed)) {
            Ok(_) => panic!("pool exhaustion must reject before dialing"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ClientError::PoolExhausted { ref host, port }
                if host == "127.0.0.1" && port == addr.port()
        ));

        let deadline = Instant::now() + Duration::from_millis(100);
        loop {
            match listener.accept() {
                Ok(_) => panic!("pool-exhausted acquisition must not open a socket"),
                Err(io_err) if io_err.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(io_err) => panic!("accept failed: {io_err}"),
            }
        }
    }

    #[test]
    fn request_returns_cancelled_when_cx_is_cancelled_after_exchange() {
        use std::io::{Read, Write};
        use std::sync::{Arc, mpsc};

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
        let (request_seen_tx, request_seen_rx) = mpsc::channel();
        let (send_response_tx, send_response_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            read_request_head(&mut stream);
            request_seen_tx.send(()).expect("notify request arrival");
            send_response_rx
                .recv()
                .expect("wait for cancellation before responding");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .expect("write response");
            stream.flush().expect("flush response");
        });

        let client = Arc::new(
            HttpClient::builder()
                .max_connections_per_host(1)
                .max_total_connections(1)
                .build(),
        );
        let cx = Cx::for_testing();
        let request_cx = cx.clone();
        let request_client = Arc::clone(&client);
        let url = format!("http://{addr}/late-cancel");
        let request_url = url.clone();
        let request = std::thread::spawn(move || {
            block_on(request_client.send_get(&request_cx, &request_url))
        });

        request_seen_rx
            .recv()
            .expect("server should observe the request before cancellation");
        cx.set_cancel_requested(true);
        send_response_tx
            .send(())
            .expect("allow server to send response");

        let result = request.join().expect("request thread should join");
        assert!(matches!(result, Err(ClientError::Cancelled)));

        server.join().expect("server thread should join");
        let stats = client.pool_stats();
        assert_eq!(
            stats.idle_connections, 0,
            "late-cancelled responses must not be returned to the idle pool"
        );
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

        let first = block_on(client.send_get(&cx, &url)).expect("initial request should succeed");
        assert_eq!(first.status, 200);
        assert_eq!(first.body, b"ok");

        std::thread::sleep(Duration::from_millis(100));

        let second = block_on(client.send_get(&cx, &url)).expect("retry request should succeed");
        assert_eq!(second.status, 200);
        assert_eq!(second.body, b"fresh");

        server.join().expect("server thread should join");
        let stats = client.pool_stats();
        assert!(
            stats.connections_created >= 2,
            "client should establish a fresh connection after stale pooled reuse fails"
        );
    }

    #[test]
    fn request_connection_close_header_prevents_pool_reuse() {
        use std::io::{Read, Write};
        use std::time::{Duration, Instant};

        fn read_request_head(stream: &mut std::net::TcpStream) -> Vec<u8> {
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
            request
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        listener
            .set_nonblocking(true)
            .expect("set nonblocking listener");
        let addr = listener.local_addr().expect("listener address");
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let accept = |listener: &TcpListener| -> std::net::TcpStream {
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => return stream,
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() <= deadline,
                                "timed out waiting for a fresh connection"
                            );
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(err) => panic!("accept failed: {err}"),
                    }
                }
            };

            let mut first = accept(&listener);
            let first_req = read_request_head(&mut first);
            first
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .expect("write first response");
            first.flush().expect("flush first response");

            let mut second = accept(&listener);
            let second_req = read_request_head(&mut second);
            second
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write second response");
            second.flush().expect("flush second response");

            (first_req, second_req)
        });

        let client = HttpClient::builder()
            .max_connections_per_host(1)
            .max_total_connections(1)
            .build();
        let cx = Cx::for_testing();
        let url = format!("http://{addr}/close-after-response");

        let headers = vec![("Connection".to_string(), "close".to_string())];
        let first = block_on(client.request(&cx, Method::Get, &url, headers.clone(), Vec::new()))
            .expect("first request should succeed");
        assert_eq!(first.status, 200);

        let second = block_on(client.request(&cx, Method::Get, &url, headers, Vec::new()))
            .expect("second request should succeed");
        assert_eq!(second.status, 200);

        let (first_req, second_req) = server.join().expect("server thread should join");
        let first_text = String::from_utf8(first_req).expect("first request should be utf8");
        let second_text = String::from_utf8(second_req).expect("second request should be utf8");
        assert!(first_text.contains("Connection: close\r\n"));
        assert!(second_text.contains("Connection: close\r\n"));

        let stats = client.pool_stats();
        assert!(
            stats.connections_created >= 2,
            "Connection: close requests must not be satisfied from a reused idle connection"
        );
        assert_eq!(
            stats.idle_connections, 0,
            "Connection: close requests must not leave pooled idle connections behind"
        );
    }

    #[test]
    fn proxy_non_streaming_path_respects_max_body_size() {
        use crate::http::h1::codec::HttpError;
        use std::io::{Read, Write};

        fn read_request_head(stream: &mut std::net::TcpStream) -> Vec<u8> {
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
            request
        }

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept proxy request");
            let request = read_request_head(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write proxy response");
            stream.flush().expect("flush proxy response");
            request
        });

        let client = HttpClient::builder()
            .proxy(format!("http://{addr}"))
            .max_body_size(1)
            .build();
        let cx = Cx::for_testing();
        let err = block_on(client.send_get(&cx, "http://example.com/oversized"))
            .expect_err("response body should exceed configured limit");

        match err {
            ClientError::HttpError(HttpError::BodyTooLargeDetailed { actual, limit }) => {
                assert_eq!(actual, 2);
                assert_eq!(limit, 1);
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let request = server.join().expect("proxy server thread should join");
        let request_text = String::from_utf8(request).expect("proxy request should be utf8");
        assert!(
            request_text.starts_with("GET http://example.com/oversized HTTP/1.1\r\n"),
            "forward-proxy request must use absolute-form and hit the non-streaming proxy path"
        );
    }

    #[test]
    fn configured_https_proxy_connect_includes_default_port() {
        use std::io::{Read, Write};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy listener");
        listener
            .set_nonblocking(true)
            .expect("make proxy listener nonblocking");
        let addr = listener.local_addr().expect("proxy listener address");
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(accepted) => break accepted,
                    Err(err)
                        if err.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(err) => panic!("accept proxy request: {err}"),
                }
            };
            // Windows inherits the listener's nonblocking mode on the accepted
            // socket. Switch the connected stream back to blocking I/O so the
            // bounded read timeout, rather than an immediate WSAEWOULDBLOCK,
            // governs this small wire-capture server.
            stream
                .set_nonblocking(false)
                .expect("make accepted proxy stream blocking");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("set proxy read timeout");
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                assert!(
                    request.len() < CONNECT_MAX_HEADERS_SIZE,
                    "CONNECT request exceeded the header limit"
                );
                let n = stream.read(&mut buf).expect("read CONNECT request");
                assert!(n > 0, "CONNECT request must arrive before peer closes");
                request.extend_from_slice(&buf[..n]);
            }
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .expect("write proxy refusal");
            stream.flush().expect("flush proxy refusal");
            request
        });

        let client = HttpClient::builder()
            .proxy(format!("http://{addr}"))
            .request_timeout(std::time::Duration::from_secs(5))
            .build();
        let cx = Cx::for_testing();
        let err = block_on(client.send_get(&cx, "https://example.com/path"))
            .expect_err("proxy refusal should stop before TLS");
        assert!(matches!(
            err,
            ClientError::ConnectTunnelRefused { status: 502, .. }
        ));

        let request = server.join().expect("proxy server thread should join");
        let request_text = String::from_utf8(request).expect("CONNECT request should be utf8");
        assert!(
            request_text.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
            "configured HTTPS proxy path must preserve the CONNECT port: {request_text:?}"
        );
        assert!(request_text.contains("\r\nHost: example.com:443\r\n"));
    }

    // --- br-asupersync-server-stack-hardening-eeexl1.1.3: outbound ---
    // --- total deadline from the remaining Cx budget                ---

    mod budget_deadline {
        use super::*;
        use crate::runtime::RuntimeBuilder;
        use crate::trace::TraceBufferHandle;
        use crate::trace::event::{TraceData, TraceEventKind};
        use crate::types::Budget;
        use std::time::Duration;

        fn runtime_block_on<F: std::future::Future>(fut: F) -> F::Output {
            RuntimeBuilder::current_thread()
                .build()
                .expect("build current-thread runtime")
                .block_on(fut)
        }

        fn cx_with_remaining(remaining: Duration) -> Cx {
            let now = crate::time::wall_now();
            let budget = Budget::INFINITE.tightened_by_timeout(now, remaining);
            Cx::for_request_with_budget(budget)
        }

        async fn never_completes() -> Result<u8, ClientError> {
            let now = Cx::with_current(|cx| {
                cx.timer_driver()
                    .map_or_else(crate::time::wall_now, |timer| timer.now())
            })
            .unwrap_or_else(crate::time::wall_now);
            crate::time::sleep(now, Duration::from_secs(600)).await;
            Ok(0)
        }

        #[test]
        fn no_bounds_runs_unbounded() {
            let cx = Cx::for_request_with_budget(Budget::INFINITE);
            let result = runtime_block_on(drive_with_budget_deadline(&cx, None, None, async {
                Ok(7_u8)
            }));
            assert!(matches!(result, Ok(7)));
        }

        #[test]
        fn budget_deadline_bounds_the_exchange() {
            let cx = cx_with_remaining(Duration::from_millis(30));
            let started = std::time::Instant::now();
            let result = runtime_block_on(drive_with_budget_deadline(
                &cx,
                None,
                None,
                never_completes(),
            ));
            assert!(
                matches!(result, Err(ClientError::DeadlineExceeded)),
                "got {result:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "budget must bound the exchange"
            );
        }

        /// Security: a per-call override longer than the remaining budget
        /// cannot extend the deadline (meet semantics).
        #[test]
        fn per_call_override_cannot_extend_budget() {
            let cx = cx_with_remaining(Duration::from_millis(30));
            let started = std::time::Instant::now();
            let result = runtime_block_on(drive_with_budget_deadline(
                &cx,
                Some(Duration::from_secs(120)),
                Some(Duration::from_secs(300)),
                never_completes(),
            ));
            assert!(
                matches!(result, Err(ClientError::DeadlineExceeded)),
                "got {result:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "override must not extend past the budget"
            );
        }

        #[test]
        fn per_call_override_tightens_unbounded_budget() {
            let cx = Cx::for_request_with_budget(Budget::INFINITE);
            let started = std::time::Instant::now();
            let result = runtime_block_on(drive_with_budget_deadline(
                &cx,
                None,
                Some(Duration::from_millis(30)),
                never_completes(),
            ));
            assert!(
                matches!(result, Err(ClientError::DeadlineExceeded)),
                "got {result:?}"
            );
            assert!(started.elapsed() < Duration::from_secs(60));
        }

        #[test]
        fn expired_budget_fails_fast() {
            let cx = cx_with_remaining(Duration::ZERO);
            let result = runtime_block_on(drive_with_budget_deadline(
                &cx,
                None,
                None,
                never_completes(),
            ));
            assert!(
                matches!(result, Err(ClientError::DeadlineExceeded)),
                "got {result:?}"
            );
        }

        #[test]
        fn forwarded_budget_trace_event_emitted() {
            let cx = cx_with_remaining(Duration::from_secs(30));
            let trace = TraceBufferHandle::new(64);
            cx.set_trace_buffer(trace.clone());
            let result = runtime_block_on(drive_with_budget_deadline(
                &cx,
                Some(Duration::from_secs(10)),
                None,
                async { Ok(1_u8) },
            ));
            assert!(matches!(result, Ok(1)));

            let forwarded: Vec<String> = trace
                .snapshot()
                .iter()
                .filter(|e| e.kind == TraceEventKind::UserTrace)
                .filter_map(|e| match &e.data {
                    TraceData::Message(msg)
                        if msg.starts_with("client.budget_forwarded proto=h1 ") =>
                    {
                        Some(msg.clone())
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                forwarded.len(),
                1,
                "expected one forwarded event, got {forwarded:?}"
            );
            assert!(forwarded[0].contains("remaining_ns="));
            assert!(forwarded[0].contains("total_timeout_ns="));
        }
    }
}
