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

use crate::cx::{CancelWakerToken, Cx};
use crate::http::body::{Body, Frame, SizeHint};
use crate::http::h1::client::{ClientIncomingBody, ClientStreamingResponse, Http1Client};
use crate::http::h1::codec::{for_each_header_value_token, validate_header_field};
use crate::http::h1::types::{
    Method, MultipartForm, Request, Response, Version, url_encode_params,
};
use crate::http::pool::{Pool, PoolConfig, PoolKey};
use crate::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use crate::net::tcp::stream::TcpStream;
#[cfg(feature = "tls")]
use crate::tls::{TlsConnector, TlsConnectorBuilder, TlsStream};
use crate::types::Time;
use base64::Engine;
use memchr::memmem;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fmt::Write;
use std::future::{Future, poll_fn};
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
    let now = client_timer_now(cx);
    let remaining = cx
        .budget()
        .deadline
        .map(|deadline| std::time::Duration::from_nanos(deadline.duration_since(now)));
    let effective = [remaining, configured, per_call]
        .into_iter()
        .flatten()
        .min();
    let Some(effective) = effective else {
        return cancellation_reported_as_cancelled(cx, fut.await);
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
        Ok(result) => cancellation_reported_as_cancelled(cx, result),
        Err(_elapsed) => Err(ClientError::DeadlineExceeded),
    }
}

/// The clock client timeouts are measured on: the caller's timer driver, then
/// the ambient one, so `now` shares a timeline with the `Sleep` inside
/// `timeout` (which binds the ambient driver); wall clock is the last resort.
fn client_timer_now(cx: &Cx) -> Time {
    cx.timer_driver()
        .or_else(|| Cx::with_current(|ambient| ambient.timer_driver()).flatten())
        .map_or_else(crate::time::wall_now, |timer| timer.now())
}

/// Cancelling the `Cx` interrupts a socket operation parked on it, which
/// surfaces as an `Interrupted` I/O error. Report it as the cancellation it
/// is, so `ClientError::is_cancelled` holds as documented.
fn cancellation_reported_as_cancelled<T>(
    cx: &Cx,
    result: Result<T, ClientError>,
) -> Result<T, ClientError> {
    let interrupted = match &result {
        Err(
            ClientError::Io(error)
            | ClientError::ConnectError(error)
            | ClientError::HttpError(crate::http::h1::codec::HttpError::Io(error)),
        ) => error.kind() == io::ErrorKind::Interrupted,
        _ => false,
    };
    if interrupted && cx.checkpoint().is_err() {
        return Err(ClientError::Cancelled);
    }
    result
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
        // RFC 3986 §3.1: the scheme is case-insensitive.
        let (scheme, rest) = if let Some(rest) = strip_prefix_ignore_ascii_case(url, "https://") {
            (Scheme::Https, rest)
        } else if let Some(rest) = strip_prefix_ignore_ascii_case(url, "http://") {
            (Scheme::Http, rest)
        } else {
            return Err(ClientError::InvalidUrl(format!(
                "unsupported scheme in: {url}"
            )));
        };

        // RFC 3986: authority ends at the first '/', '?', or '#'.
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        // The fragment is for the client and is never sent (RFC 9110 §7.1).
        let path_and_query = rest[authority_end..].split('#').next().unwrap_or_default();
        // An empty path is sent as "/" (RFC 9112 §3.2.1).
        let path = if path_and_query.is_empty() {
            "/".to_owned()
        } else if path_and_query.starts_with('?') {
            format!("/{path_and_query}")
        } else {
            path_and_query.to_owned()
        };
        if path.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err(ClientError::InvalidUrl(
                "URL path cannot contain control characters".into(),
            ));
        }

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
                let port = parse_explicit_port(port_str)?;
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
            let port = parse_explicit_port(port_str)?;
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
            path,
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
    /// A valid `Retry-After` delta-seconds header is honored before the retry;
    /// a response asking for more than 60 seconds, or giving `Retry-After` in
    /// another form such as an HTTP-date, is returned instead. The same policy
    /// also keeps the stale pooled-connection retry enabled.
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

        // A Retry-After that is not delta-seconds, such as an HTTP-date, asks
        // for a wait this client does not compute, so the response is returned
        // rather than retried at once.
        let delay = match get_header(&response.headers, "Retry-After") {
            None => std::time::Duration::ZERO,
            Some(value) => parse_retry_after_delta(&value)?,
        };
        // A server asking for a longer wait than the client will sleep gets its
        // response returned, not a request parked for that long.
        (delay <= MAX_RETRY_AFTER).then_some(delay)
    }
}

/// The longest `Retry-After` delay an automatic retry waits for.
const MAX_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

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

    /// Lets a request wait up to `timeout` for a pooled connection when the
    /// per-host or total connection limit is reached, instead of failing at
    /// once with [`ClientError::PoolExhausted`] (the default).
    ///
    /// A waiting request takes the first connection another request releases
    /// or closes; waiters are not served in FIFO order. The wait counts
    /// toward the request's total timeout and budget deadline, and a
    /// cancelled caller stops waiting. A request still without a connection
    /// when `timeout` elapses fails with [`ClientError::PoolExhausted`].
    #[must_use]
    pub fn pool_wait_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.config.pool_wait_timeout = Some(timeout);
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
    /// retrying. A response asking for more than 60 seconds, or giving
    /// `Retry-After` in another form such as an HTTP-date, is returned without
    /// a retry. Use [`Self::no_retries`] when no automatic retry behavior is
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
    ///
    /// The bounded in-memory store matches exact hosts and sends `Secure`
    /// cookies only over HTTPS. Cookies live for this client's lifetime;
    /// `Domain`, `Path`, expiry, and other attributes are not interpreted.
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

    /// Asks servers for compressed responses and decodes them, like reqwest's
    /// `gzip`, `deflate` and `brotli` options. Off by default.
    ///
    /// It applies to a buffered request whose headers, and the client's
    /// default headers, name no `Accept-Encoding` and no `Range`. The client
    /// then sends `Accept-Encoding: gzip, deflate, br` (with `, zstd` when the
    /// `zstd` feature is also enabled) and decodes the response
    /// with [`Response::decode_content`], using the
    /// [`max_body_size`](Self::max_body_size) limit (16 MiB by default) for
    /// every decoded layer. Any error `decode_content` reports (an unknown
    /// coding, more than eight codings, a bad stream, output past the limit)
    /// fails the request with [`ClientError::HttpError`]. Streaming requests
    /// are not affected. A gzip body of several concatenated members is not
    /// supported.
    #[cfg(feature = "compression")]
    #[must_use]
    pub fn response_decompression(mut self, enabled: bool) -> Self {
        self.config.response_decompression = enabled;
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

    /// Trusts an additional root certificate for HTTPS connections.
    ///
    /// Roots added here are used together with any roots selected by the
    /// `tls-native-roots` / `tls-webpki-roots` features. Without a roots
    /// feature this is the only way the client can verify a server, so a
    /// plain-`tls` client with no installed root still fails every
    /// `https://` request closed before sending a ClientHello.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn add_root_certificate(mut self, certificate: crate::tls::Certificate) -> Self {
        self.config.tls_root_certificates.push(certificate);
        self
    }

    /// Sets an explicit DNS resolver for the client.
    ///
    /// When configured, hostname resolution uses this [`Resolver`](crate::net::dns::Resolver)
    /// (with its caching, TTL enforcement, nameserver routing, and timeout) rather than
    /// an uncached system lookup. Cloned resolvers share the underlying cache, allowing
    /// callers to observe [`cache_stats`](crate::net::dns::Resolver::cache_stats).
    /// (asupersync-lfhzhl)
    #[must_use]
    pub fn dns_resolver(mut self, resolver: crate::net::dns::Resolver) -> Self {
        self.config.dns_resolver = Some(resolver);
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
    /// Additional root certificates trusted for HTTPS connections, on top of
    /// the roots selected by the `tls-native-roots` / `tls-webpki-roots`
    /// features.
    ///
    /// Empty by default. With plain `tls` and no entry here the client keeps
    /// its fail-closed behaviour: every `https://` request is refused before a
    /// ClientHello with "no root certificates configured". Installing a root
    /// (typically a private CA or a self-signed test certificate) is the only
    /// way to make the pooled client trust a server that public roots did not
    /// issue.
    #[cfg(feature = "tls")]
    pub tls_root_certificates: Vec<crate::tls::Certificate>,
    /// Time source used for pool bookkeeping.
    time_getter: fn() -> Time,
    /// Whether buffered requests ask for, and decode, gzip and br responses
    /// (see [`HttpClientBuilder::response_decompression`]).
    response_decompression: bool,
    /// How long a request waits for a pooled connection at the connection
    /// limit (see [`HttpClientBuilder::pool_wait_timeout`]).
    pool_wait_timeout: Option<std::time::Duration>,
    /// Optional DNS resolver for host lookups and Happy Eyeballs connection racing.
    ///
    /// When `None`, host lookups fall back to the system resolver via
    /// `net::happy_eyeballs::connect_resolved`. (asupersync-lfhzhl)
    dns_resolver: Option<crate::net::dns::Resolver>,
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
            #[cfg(feature = "tls")]
            tls_root_certificates: Vec::new(),
            time_getter: wall_clock_now,
            response_decompression: false,
            pool_wait_timeout: None,
            dns_resolver: None,
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

    /// Sets the DNS resolver.
    #[must_use]
    pub fn with_dns_resolver(mut self, resolver: Option<crate::net::dns::Resolver>) -> Self {
        self.dns_resolver = resolver;
        self
    }

    /// Returns the DNS resolver, if configured.
    #[must_use]
    pub fn dns_resolver(&self) -> Option<&crate::net::dns::Resolver> {
        self.dns_resolver.as_ref()
    }

    /// Sets how long a request waits for a pooled connection at the
    /// connection limit (see [`HttpClientBuilder::pool_wait_timeout`]).
    #[must_use]
    pub const fn with_pool_wait_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.pool_wait_timeout = timeout;
        self
    }

    /// Returns how long a request waits for a pooled connection at the
    /// connection limit; `None` fails at once.
    #[must_use]
    pub const fn pool_wait_timeout(&self) -> Option<std::time::Duration> {
        self.pool_wait_timeout
    }

    /// Sets whether buffered requests ask for, and decode, gzip and br
    /// responses (see [`HttpClientBuilder::response_decompression`]).
    #[cfg(feature = "compression")]
    #[must_use]
    pub const fn with_response_decompression(mut self, enabled: bool) -> Self {
        self.response_decompression = enabled;
        self
    }

    /// Returns whether response decompression is on.
    #[cfg(feature = "compression")]
    #[must_use]
    pub const fn response_decompression(&self) -> bool {
        self.response_decompression
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
/// enforces per-host and total connection limits: a request at a limit fails
/// with [`ClientError::PoolExhausted`] unless
/// [`HttpClientBuilder::pool_wait_timeout`] lets it wait for a connection.
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
    /// Signalled whenever a pooled connection is released or closed, for
    /// requests waiting at the connection limit
    /// ([`HttpClientBuilder::pool_wait_timeout`]).
    pool_released: Arc<crate::sync::Notify>,
    cookies: Arc<Mutex<HashMap<String, Vec<StoredCookie>>>>,
    /// asupersync-bo2caw: the TLS connector, built once per client (shared by
    /// clones) on first HTTPS use. Building it loads and parses the root
    /// store and constructs a rustls `ClientConfig`, which used to happen on
    /// every fresh HTTPS connection; `TlsConnector` clones share the
    /// `Arc<ClientConfig>`, so each connection now takes a cheap clone. A
    /// build failure is cached as its message: it is configuration-level (no
    /// trust anchors installed) and must read the same on every request.
    #[cfg(feature = "tls")]
    tls_connector: Arc<std::sync::OnceLock<Result<TlsConnector, String>>>,
}

/// A response whose streaming body retains its connection-pool admission.
///
/// Produced by [`HttpClient::request_streaming_pooled`]. Consuming the body to
/// its complete HTTP message boundary returns a reusable connection to the
/// shared pool. Dropping an unfinished body closes the connection and releases
/// admission synchronously. No task is spawned to drain abandoned responses.
#[derive(Debug)]
pub struct PooledClientStreamingResponse {
    /// Response status line and headers.
    pub head: crate::http::h1::stream::ResponseHead,
    /// The owned, cancellation-aware response body.
    pub body: PooledClientIncomingBody,
    /// Whether the request upload was withheld or interrupted by the peer.
    /// Such connections are never reused, even after the response is drained.
    pub body_withheld: bool,
}

/// An HTTP/1 body that owns a pool slot until completion or abandonment.
///
/// The original request context and absolute effective deadline remain in
/// force while reading the body. A cancelled or expired parked read wakes and
/// reports [`ClientError::Cancelled`] or [`ClientError::DeadlineExceeded`].
/// Protocol and transport errors retain their [`ClientError::HttpError`]
/// source. Any failure closes the connection before waking pool waiters.
///
/// A terminal body returns `None` on subsequent polls. Completing a final DATA
/// or trailer frame releases the slot immediately; an additional EOF poll is
/// unnecessary. Incomplete, close-delimited, upgraded and tainted connections
/// are discarded instead of reused.
pub struct PooledClientIncomingBody {
    body: Option<ClientIncomingBody<ClientIo>>,
    lease: Option<PooledStreamLease>,
    owner: PooledStreamOwner,
}

impl std::fmt::Debug for PooledClientIncomingBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledClientIncomingBody")
            .field("complete", &self.body.is_none())
            .field("owns_pool_admission", &self.lease.is_some())
            .finish_non_exhaustive()
    }
}

impl PooledClientIncomingBody {
    fn new(
        body: ClientIncomingBody<ClientIo>,
        lease: PooledStreamLease,
        cx: &Cx,
        deadline: &PooledStreamDeadline,
    ) -> Self {
        let mut result = Self {
            body: Some(body),
            lease: Some(lease),
            owner: PooledStreamOwner::new(cx.clone(), deadline),
        };
        if result
            .body
            .as_ref()
            .is_some_and(ClientIncomingBody::is_at_message_end)
        {
            result.retire(true);
        }
        result
    }

    fn retire(&mut self, completed: bool) {
        self.owner.retire();
        let body = self.body.take();
        let lease = self.lease.take();
        match (body, lease) {
            (Some(body), Some(lease))
                if completed && lease.may_reuse && body.is_complete_for_reuse() =>
            {
                let (io, _empty_read_ahead) = body.into_inner_with_buffer();
                lease.release(io);
            }
            (body, lease) => {
                // Close the actual socket before publishing free admission.
                drop(body);
                drop(lease);
            }
        }
    }
}

impl Body for PooledClientIncomingBody {
    type Data = crate::bytes::BytesCursor;
    type Error = ClientError;

    fn poll_frame(
        self: Pin<&mut Self>,
        task: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.body.is_none() {
            return Poll::Ready(None);
        }
        if let Some(error) = this.owner.poll_stop(task) {
            this.retire(false);
            return Poll::Ready(Some(Err(error)));
        }
        let result = Pin::new(this.body.as_mut().expect("body checked above")).poll_frame(task);
        match result {
            Poll::Ready(Some(Err(error))) => {
                let error = cancellation_reported_as_cancelled::<()>(
                    &this.owner.cx,
                    Err(ClientError::from(error)),
                )
                .expect_err("an input error remains an error");
                this.retire(false);
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(frame) => {
                if frame.is_none() || this.body.as_ref().is_some_and(Body::is_end_stream) {
                    this.retire(true);
                }
                Poll::Ready(frame.map(|frame| frame.map_err(ClientError::from)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        self.body
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), Body::size_hint)
    }
}

impl Drop for PooledClientIncomingBody {
    fn drop(&mut self) {
        self.retire(false);
    }
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
            pool_released: Arc::new(crate::sync::Notify::new()),
            cookies: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "tls")]
            tls_connector: Arc::new(std::sync::OnceLock::new()),
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
        mut extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<Response, ClientError> {
        check_cx(cx)?;
        let parsed = ParsedUrl::parse(url)?;
        let decode = self
            .request_encoded_response(&mut extra_headers)
            .then(|| method.clone());
        let fut = self.execute_with_redirects(cx, method, parsed, extra_headers, body, None, 0, 0);
        let response =
            drive_with_budget_deadline(cx, self.config.request_timeout, None, fut).await?;
        self.decode_response(decode.as_ref(), response)
    }

    /// Send a request with an explicit per-call total timeout
    /// (br-asupersync-server-stack-hardening-eeexl1.1.3).
    ///
    /// The effective deadline is the **meet** of the remaining ambient
    /// budget, the client's configured [`HttpClientConfig::request_timeout`],
    /// and `timeout` — the
    /// tightest bound wins, so a per-call override can never extend past
    /// the caller's budget deadline. On expiry the in-flight exchange is
    /// dropped (the pooled connection is discarded, not reused) and
    /// [`ClientError::DeadlineExceeded`] is returned.
    pub async fn request_with_timeout(
        &self,
        cx: &Cx,
        method: Method,
        url: &str,
        mut extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
        timeout: std::time::Duration,
    ) -> Result<Response, ClientError> {
        check_cx(cx)?;
        let parsed = ParsedUrl::parse(url)?;
        let decode = self
            .request_encoded_response(&mut extra_headers)
            .then(|| method.clone());
        let fut = self.execute_with_redirects(cx, method, parsed, extra_headers, body, None, 0, 0);
        let response =
            drive_with_budget_deadline(cx, self.config.request_timeout, Some(timeout), fut).await?;
        self.decode_response(decode.as_ref(), response)
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
        let fut =
            self.execute_with_redirects_streaming(cx, method, parsed, extra_headers, body, None, 0);
        drive_with_budget_deadline(cx, self.config.request_timeout, None, fut).await
    }

    /// Stream a direct HTTP or HTTPS response through this client's pool.
    ///
    /// The request shares per-host/total connection admission and
    /// [`HttpClientBuilder::pool_wait_timeout`] with buffered requests. Its
    /// response body retains that admission until fully consumed or dropped.
    /// Reuse requires complete framing, no unread prefetched bytes, and both
    /// peers' keep-alive permission. An unfinished body is closed on drop.
    ///
    /// The original context's cancellation and the tighter of its deadline and
    /// `request_timeout` bound the entire operation, including pool wait,
    /// redirects, setup and all body reads. This absolute deadline is never
    /// restarted per redirect or frame. Headers, cookies and redirect policy
    /// follow the ordinary client rules; only safe stale-connection retries
    /// before receiving a response head are allowed.
    ///
    /// Proxy configurations return [`ClientError::ProxyError`] before opening
    /// a connection; they cannot silently bypass this API's pool guarantees.
    /// Use [`Self::request_streaming`] for the existing unpooled proxy lane.
    pub async fn request_streaming_pooled(
        &self,
        cx: &Cx,
        method: Method,
        url: &str,
        extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<PooledClientStreamingResponse, ClientError> {
        check_cx(cx)?;
        if self.config.proxy_url.is_some() {
            return Err(ClientError::ProxyError(
                "pooled streaming requires a direct HTTP or HTTPS connection".to_owned(),
            ));
        }
        let deadline = PooledStreamDeadline::capture(cx, self.config.request_timeout);
        let parsed = ParsedUrl::parse(url)?;
        let mut owner = PooledStreamOwner::new(cx.clone(), &deadline);
        let mut request = std::pin::pin!(self.execute_with_redirects_pooled_streaming(
            cx,
            method,
            parsed,
            extra_headers,
            body,
            &deadline,
        ));
        poll_fn(|task| {
            if let Some(error) = owner.poll_stop(task) {
                return Poll::Ready(Err(error));
            }
            request.as_mut().poll(task)
        })
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
    ///
    /// Establishing the tunnel (connecting to the proxy and the CONNECT
    /// exchange) is bounded like a request: by
    /// [`HttpClientConfig::request_timeout`] and the remaining budget
    /// deadline, whichever is tighter. On expiry it returns
    /// [`ClientError::DeadlineExceeded`]. Traffic through the established
    /// tunnel is not bounded by them.
    pub async fn connect_tunnel(
        &self,
        cx: &Cx,
        proxy_url: &str,
        target_authority: &str,
        extra_headers: Vec<(String, String)>,
    ) -> Result<HttpConnectTunnel<ClientIo>, ClientError> {
        check_cx(cx)?;
        let proxy = ParsedUrl::parse(proxy_url)?;
        // br-asupersync-vxmjgn: a proxy that accepts and never answers held
        // this call until the Cx was cancelled.
        let fut = async {
            let io = self.connect_io(cx, &proxy).await?;
            establish_http_connect_tunnel(
                io,
                target_authority,
                self.config.user_agent.as_deref(),
                &extra_headers,
            )
            .await
        };
        drive_with_budget_deadline(cx, self.config.request_timeout, None, fut).await
    }

    /// Execute a request, following redirects as configured.
    fn execute_with_redirects<'a>(
        &'a self,
        cx: &'a Cx,
        method: Method,
        parsed: ParsedUrl,
        extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
        origin: Option<ParsedUrl>,
        redirect_count: u32,
        retry_count: u32,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Response, ClientError>> + Send + 'a>,
    > {
        Box::pin(async move {
            check_cx(cx)?;
            let resp = Box::pin(self.execute_single(
                cx,
                &method,
                &parsed,
                &extra_headers,
                &body,
                origin.as_ref(),
            ))
            .await?;

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

                            // When routing through a forward proxy, the proxy is the same
                            // intermediate hop for the redirected request, so retain the
                            // caller's Proxy-Authorization credentials (RFC 9110 §15.4 / asupersync-4ebib5).
                            let proxy_auth = if self.config.proxy_url.is_some() {
                                get_header(&extra_headers, "proxy-authorization")
                            } else {
                                None
                            };

                            // Strip sensitive headers on cross-origin redirect
                            let mut next_headers = strip_sensitive_headers_on_redirect(
                                &parsed,
                                &next_parsed,
                                extra_headers,
                            );
                            if let Some(auth) = proxy_auth {
                                if !has_header(&next_headers, "proxy-authorization") {
                                    next_headers.push(("Proxy-Authorization".to_owned(), auth));
                                }
                            }
                            // A redirect that changes the method drops the body,
                            // and the headers that described it (RFC 9110 §15.4).
                            let next_headers = if next_method == method {
                                next_headers
                            } else {
                                strip_content_headers(next_headers)
                            };

                            // Pin the credential origin to the first request's
                            // URL for the whole chain, so client-wide default
                            // Authorization/Cookie headers are re-attached only
                            // when a later hop lands back on that exact origin.
                            let next_origin = Some(origin.unwrap_or_else(|| parsed.clone()));

                            return self
                                .execute_with_redirects(
                                    cx,
                                    next_method,
                                    next_parsed,
                                    next_headers,
                                    next_body,
                                    next_origin,
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
                        origin,
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
        origin: Option<ParsedUrl>,
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
                .execute_single_streaming(cx, &method, &parsed, &extra_headers, &body, origin.as_ref())
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

                            // When routing through a forward proxy, the proxy is the same
                            // intermediate hop for the redirected request, so retain the
                            // caller's Proxy-Authorization credentials (RFC 9110 §15.4 / asupersync-4ebib5).
                            let proxy_auth = if self.config.proxy_url.is_some() {
                                get_header(&extra_headers, "proxy-authorization")
                            } else {
                                None
                            };

                            // Strip sensitive headers on cross-origin redirect
                            let mut next_headers = strip_sensitive_headers_on_redirect(
                                &parsed,
                                &next_parsed,
                                extra_headers,
                            );
                            if let Some(auth) = proxy_auth {
                                if !has_header(&next_headers, "proxy-authorization") {
                                    next_headers.push(("Proxy-Authorization".to_owned(), auth));
                                }
                            }
                            // A redirect that changes the method drops the body,
                            // and the headers that described it (RFC 9110 §15.4).
                            let next_headers = if next_method == method {
                                next_headers
                            } else {
                                strip_content_headers(next_headers)
                            };

                            // Pin the credential origin to the first request's
                            // URL for the whole chain (see the buffered path).
                            let next_origin = Some(origin.unwrap_or_else(|| parsed.clone()));

                            return self
                                .execute_with_redirects_streaming(
                                    cx,
                                    next_method,
                                    next_parsed,
                                    next_headers,
                                    next_body,
                                    next_origin,
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

    async fn execute_with_redirects_pooled_streaming(
        &self,
        cx: &Cx,
        mut method: Method,
        mut parsed: ParsedUrl,
        mut extra_headers: Vec<(String, String)>,
        mut body: Vec<u8>,
        deadline: &PooledStreamDeadline,
    ) -> Result<PooledClientStreamingResponse, ClientError> {
        let mut origin = None;
        let mut redirect_count = 0_u32;
        loop {
            let response = self
                .execute_single_pooled_streaming(
                    cx,
                    &method,
                    &parsed,
                    &extra_headers,
                    &body,
                    origin.as_ref(),
                    deadline,
                )
                .await?;
            if !is_redirect(response.head.status) {
                return Ok(response);
            }
            let max = match &self.config.redirect_policy {
                RedirectPolicy::None => return Ok(response),
                RedirectPolicy::Limited(max) | RedirectPolicy::SameOrigin(max) => *max,
            };
            if redirect_count >= max {
                return Err(ClientError::TooManyRedirects {
                    count: redirect_count.saturating_add(1),
                    max,
                });
            }
            let Some(location) = get_header(&response.head.headers, "location") else {
                return Ok(response);
            };
            let next_parsed = ParsedUrl::parse(&resolve_redirect(&parsed, &location))?;
            if !redirect_policy_allows_target(&self.config.redirect_policy, &parsed, &next_parsed) {
                return Ok(response);
            }
            let next_method = redirect_method(response.head.status, &method);
            // Unread redirect bodies release admission before the next hop.
            drop(response);
            extra_headers = strip_sensitive_headers_on_redirect(
                &parsed,
                &next_parsed,
                extra_headers,
            );
            if next_method != method {
                extra_headers = strip_content_headers(extra_headers);
            }
            if next_method == Method::Get {
                body.clear();
            }
            origin = Some(origin.unwrap_or_else(|| parsed.clone()));
            method = next_method;
            parsed = next_parsed;
            redirect_count = redirect_count.saturating_add(1);
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_single_pooled_streaming(
        &self,
        cx: &Cx,
        method: &Method,
        parsed: &ParsedUrl,
        extra_headers: &[(String, String)],
        body: &[u8],
        origin: Option<&ParsedUrl>,
        deadline: &PooledStreamDeadline,
    ) -> Result<PooledClientStreamingResponse, ClientError> {
        let mut retry_fresh = false;
        loop {
            check_cx(cx)?;
            let request = self.build_request_with_origin(
                method,
                parsed,
                extra_headers,
                body,
                None,
                None,
                origin,
            );
            let request_forbids_reuse = request_forbids_connection_reuse(&request.headers);
            let key = parsed.pool_key();
            let acquired = if retry_fresh {
                self.acquire_fresh_connection_with_clock(cx, parsed, Some(deadline))
                    .await?
            } else {
                self.acquire_connection_with_clock(cx, parsed, true, Some(deadline))
                    .await?
            };
            let mut guard = ConnectionGuard::new(self, key.clone(), acquired.pool_id);
            check_cx(cx)?;
            let result = if let Some(max_body_size) = self.config.max_body_size {
                Http1Client::request_streaming_with_max_body_size(
                    acquired.io,
                    request,
                    max_body_size,
                )
                .await
            } else {
                Http1Client::request_streaming(acquired.io, request).await
            };
            match result {
                Ok(response) => {
                    check_cx(cx)?;
                    self.store_response_cookies(
                        &parsed.host,
                        parsed.scheme,
                        &response.head.headers,
                    );
                    let may_reuse = !request_forbids_reuse
                        && !response.body_withheld
                        && !header_has_token(&response.head.headers, "connection", "close")
                        && !(matches!(method, Method::Connect)
                            && (200..300).contains(&response.head.status))
                        && response_head_can_be_reused(
                            response.head.status,
                            response.head.version,
                            &response.head.headers,
                            method,
                        );
                    let lease = PooledStreamLease {
                        client: self.clone(),
                        key,
                        pool_id: acquired.pool_id,
                        fresh: acquired.fresh,
                        may_reuse,
                    };
                    // Transfer the slot before constructing a possibly empty
                    // body, whose constructor may immediately release it.
                    guard.defused = true;
                    return Ok(PooledClientStreamingResponse {
                        head: response.head,
                        body: PooledClientIncomingBody::new(response.body, lease, cx, deadline),
                        body_withheld: response.body_withheld,
                    });
                }
                Err(error) => {
                    let error = ClientError::from(error);
                    if !retry_fresh
                        && !acquired.fresh
                        && self
                            .config
                            .retry_policy
                            .should_retry_reused_connection_failure(method, &error)
                    {
                        drop(guard);
                        retry_fresh = true;
                    } else {
                        return cancellation_reported_as_cancelled(cx, Err(error));
                    }
                }
            }
        }
    }

    /// Execute a single request (no redirect handling).
    async fn execute_single(
        &self,
        cx: &Cx,
        method: &Method,
        parsed: &ParsedUrl,
        extra_headers: &[(String, String)],
        body: &[u8],
        origin: Option<&ParsedUrl>,
    ) -> Result<Response, ClientError> {
        check_cx(cx)?;
        if let Some(proxy_url) = self.config.proxy_url.as_deref() {
            return self
                .execute_single_with_proxy(cx, method, parsed, extra_headers, body, proxy_url, origin)
                .await;
        }

        let req =
            self.build_request_with_origin(method, parsed, extra_headers, body, None, None, origin);
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
            Ok((response, io, body_withheld)) => {
                check_cx(cx)?;
                guard.defused = true;
                self.store_response_cookies(&parsed.host, parsed.scheme, &response.headers);
                // A withheld `Expect: 100-continue` body leaves the connection in
                // an indeterminate framing state (Content-Length advertised, body
                // never written), so it must never re-enter the keep-alive pool
                // (br-asupersync-h1-expect-100-pool-h9le7v).
                if !request_forbids_reuse
                    && !body_withheld
                    && connection_can_be_reused(&response, method)
                {
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
                            origin,
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
        origin: Option<&ParsedUrl>,
    ) -> Result<Response, ClientError> {
        let req =
            self.build_request_with_origin(method, parsed, extra_headers, body, None, None, origin);
        let request_forbids_reuse = request_forbids_connection_reuse(&req.headers);
        let key = parsed.pool_key();
        let acquired = self.acquire_fresh_connection(cx, parsed).await?;
        let mut guard = ConnectionGuard::new(self, key.clone(), acquired.pool_id);

        check_cx(cx)?;

        let result = if let Some(max_body_size) = self.config.max_body_size {
            Http1Client::request_with_io_and_max_body_size(acquired.io, req, max_body_size).await
        } else {
            Http1Client::request_with_io(acquired.io, req).await
        };
        match result {
            Ok((response, io, body_withheld)) => {
                check_cx(cx)?;
                guard.defused = true;
                self.store_response_cookies(&parsed.host, parsed.scheme, &response.headers);
                // A withheld `Expect: 100-continue` body leaves the connection in
                // an indeterminate framing state (Content-Length advertised, body
                // never written), so it must never re-enter the keep-alive pool
                // (br-asupersync-h1-expect-100-pool-h9le7v).
                if !request_forbids_reuse
                    && !body_withheld
                    && connection_can_be_reused(&response, method)
                {
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
        origin: Option<&ParsedUrl>,
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
                    origin,
                )
                .await;
        }

        let req =
            self.build_request_with_origin(method, parsed, extra_headers, body, None, None, origin);

        let stream = self.connect_io(cx, parsed).await?;
        check_cx(cx)?;
        let resp = if let Some(max_body_size) = self.config.max_body_size {
            Http1Client::request_streaming_with_max_body_size(stream, req, max_body_size).await?
        } else {
            Http1Client::request_streaming(stream, req).await?
        };
        check_cx(cx)?;
        self.store_response_cookies(&parsed.host, parsed.scheme, &resp.head.headers);
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
        origin: Option<&ParsedUrl>,
    ) -> Result<Response, ClientError> {
        check_cx(cx)?;
        let proxy = parse_proxy_endpoint(proxy_url)?;
        let caller_proxy_authorization = self.caller_proxy_authorization(extra_headers);
        let proxy_conn = self
            .connect_via_proxy(cx, parsed, &proxy, caller_proxy_authorization.as_deref())
            .await?;
        check_cx(cx)?;
        let request_target = if proxy_conn.use_absolute_form {
            Some(absolute_request_target(parsed))
        } else {
            None
        };
        let mut req = self.build_request_with_origin(
            method,
            parsed,
            extra_headers,
            body,
            request_target,
            proxy_conn.proxy_authorization.as_deref(),
            origin,
        );
        if !proxy_conn.use_absolute_form {
            strip_proxy_authorization(&mut req.headers);
        }
        let (response, _io, _body_withheld) = if let Some(max_body_size) = self.config.max_body_size
        {
            Http1Client::request_with_io_and_max_body_size(proxy_conn.io, req, max_body_size)
                .await?
        } else {
            Http1Client::request_with_io(proxy_conn.io, req).await?
        };
        check_cx(cx)?;
        self.store_response_cookies(&parsed.host, parsed.scheme, &response.headers);
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
        origin: Option<&ParsedUrl>,
    ) -> Result<ClientStreamingResponse<ClientIo>, ClientError> {
        check_cx(cx)?;
        let proxy = parse_proxy_endpoint(proxy_url)?;
        let caller_proxy_authorization = self.caller_proxy_authorization(extra_headers);
        let proxy_conn = self
            .connect_via_proxy(cx, parsed, &proxy, caller_proxy_authorization.as_deref())
            .await?;
        check_cx(cx)?;
        let request_target = if proxy_conn.use_absolute_form {
            Some(absolute_request_target(parsed))
        } else {
            None
        };
        let mut req = self.build_request_with_origin(
            method,
            parsed,
            extra_headers,
            body,
            request_target,
            proxy_conn.proxy_authorization.as_deref(),
            origin,
        );
        if !proxy_conn.use_absolute_form {
            strip_proxy_authorization(&mut req.headers);
        }
        let resp = if let Some(max_body_size) = self.config.max_body_size {
            Http1Client::request_streaming_with_max_body_size(proxy_conn.io, req, max_body_size)
                .await?
        } else {
            Http1Client::request_streaming(proxy_conn.io, req).await?
        };
        check_cx(cx)?;
        self.store_response_cookies(&parsed.host, parsed.scheme, &resp.head.headers);
        Ok(resp)
    }

    /// The `Proxy-Authorization` the caller set, for this request or as a
    /// client-wide default.
    fn caller_proxy_authorization(&self, extra_headers: &[(String, String)]) -> Option<String> {
        get_header(extra_headers, "proxy-authorization")
            .or_else(|| get_header(&self.config.default_headers, "proxy-authorization"))
    }

    /// Connects through `proxy`. `caller_proxy_authorization` authenticates an
    /// HTTP CONNECT tunnel and takes precedence over credentials in the proxy
    /// URL, as it does for a forward-proxied request.
    async fn connect_via_proxy(
        &self,
        cx: &Cx,
        parsed: &ParsedUrl,
        proxy: &ProxyEndpoint,
        caller_proxy_authorization: Option<&str>,
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
                        proxy_authorization: caller_proxy_authorization
                            .or_else(|| proxy.http_proxy_authorization())
                            .map(std::borrow::ToOwned::to_owned),
                    });
                }

                let mut connect_headers = Vec::new();
                if let Some(auth) =
                    caller_proxy_authorization.or_else(|| proxy.http_proxy_authorization())
                {
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
                let tcp =
                    connect_via_socks5(proxy, parsed, cx, self.config.dns_resolver.as_ref()).await?;
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

    /// With response decompression on and no `Accept-Encoding` chosen by the
    /// caller or the default headers, asks for the codings the client decodes
    /// and returns `true`. Only the response to such a request is decoded. A
    /// range request is left alone: a 206 slice of a compressed representation
    /// cannot be decoded on its own.
    fn request_encoded_response(&self, extra_headers: &mut Vec<(String, String)>) -> bool {
        let default_headers = &self.config.default_headers;
        let ask = self.config.response_decompression
            && !has_header(extra_headers, "accept-encoding")
            && !has_header(default_headers, "accept-encoding")
            && !has_header(extra_headers, "range")
            && !has_header(default_headers, "range");
        if ask {
            extra_headers.push((
                "Accept-Encoding".to_owned(),
                DECODED_CONTENT_CODINGS.to_owned(),
            ));
        }
        ask
    }

    /// Decodes the response to a request that asked for compressed content
    /// (`request_method` is `Some`) through [`Response::decode_content`], with
    /// the body limit as the decoded-size limit. Its errors (an unknown coding,
    /// more than eight codings, an encoded partial response, a bad stream or
    /// output past the limit) fail the request as
    /// `ClientError::HttpError(HttpError::Io(_))`.
    fn decode_response(
        &self,
        request_method: Option<&Method>,
        mut response: Response,
    ) -> Result<Response, ClientError> {
        let Some(method) = request_method else {
            return Ok(response);
        };
        let limit = crate::http::compress::DecompressionLimit::new(
            self.config
                .max_body_size
                .unwrap_or(crate::http::compress::DEFAULT_MAX_DECOMPRESSED_SIZE),
        );
        response
            .decode_content(method, limit)
            .map_err(|err| ClientError::HttpError(crate::http::h1::codec::HttpError::Io(err)))?;
        Ok(response)
    }

    /// Convenience wrapper preserving the pre-u957g0 six-argument signature.
    /// Production request paths call [`Self::build_request_with_origin`] directly
    /// so they can pass the redirect origin; only the inline unit tests exercise
    /// this shorthand, hence `#[cfg(test)]` (keeps it out of the non-test
    /// `dead_code` frontier under `-D warnings`; br-asupersync-u957g0).
    #[cfg(test)]
    fn build_request(
        &self,
        method: &Method,
        parsed: &ParsedUrl,
        extra_headers: &[(String, String)],
        body: &[u8],
        request_target: Option<String>,
        proxy_authorization: Option<&str>,
    ) -> Request {
        self.build_request_with_origin(
            method,
            parsed,
            extra_headers,
            body,
            request_target,
            proxy_authorization,
            None,
        )
    }

    /// Like `build_request`, but `origin` (the ORIGINAL request URL) lets the
    /// redirect path strip security-sensitive client-wide default headers when
    /// the current `parsed` target is a different origin (br-asupersync-u957g0).
    /// `origin = None` (the plain `build_request`) never strips.
    fn build_request_with_origin(
        &self,
        method: &Method,
        parsed: &ParsedUrl,
        extra_headers: &[(String, String)],
        body: &[u8],
        request_target: Option<String>,
        proxy_authorization: Option<&str>,
        origin: Option<&ParsedUrl>,
    ) -> Request {
        let default_headers = &self.config.default_headers;
        // br-asupersync-u957g0: on a cross-origin redirect target, do NOT forward
        // security-sensitive client-wide DEFAULT headers (Authorization / Cookie /
        // Proxy-Authorization). `build_request` re-applies `default_headers` on every
        // hop, so without this a client-wide default bearer token / cookie leaks to a
        // redirect target of a different origin (or an https->http downgrade). Mirrors
        // `strip_sensitive_headers_on_redirect` for per-request headers. `origin` is
        // the ORIGINAL request URL (== `parsed` on the initial request), so a
        // same-origin redirect keeps its credentials.
        let cross_origin = origin.is_some_and(|o| !same_origin(o, parsed));
        // A cross-origin target's default Cookie is stripped, but the host-scoped
        // cookie jar must still supply the CORRECT cookie for the new host — so a
        // stripped default Cookie/Proxy-Authorization must not suppress the jar/proxy
        // fallback path below.
        let default_cookie_applies = has_header(default_headers, "cookie") && !cross_origin;
        let default_proxy_auth_applies =
            has_header(default_headers, "proxy-authorization") && !cross_origin;
        let has_cookie_header = has_header(extra_headers, "cookie") || default_cookie_applies;
        let has_proxy_authorization =
            has_header(extra_headers, "proxy-authorization") || default_proxy_auth_applies;
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
            && let Some(cookie_header) = self.cookie_header_for_host(&parsed.host, parsed.scheme)
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
                        !(name.eq_ignore_ascii_case("host")
                            || has_header(extra_headers, name)
                            || cross_origin && is_sensitive_redirect_header(name))
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

    /// Stores the `Set-Cookie` headers of a response received over `scheme`
    /// for `host`.
    ///
    /// asupersync-kwvk89: RFC 6265bis section 5.6 makes the response scheme
    /// part of the storage decision. A response that did not arrive over
    /// HTTPS cannot create a cookie carrying the `Secure` attribute, and it
    /// cannot replace or delete a stored cookie whose `Secure` flag is set
    /// ("leave Secure cookies alone"), so an on-path attacker injecting
    /// plain-HTTP responses can neither fix nor evict an HTTPS session
    /// cookie. Plain cookies remain updatable over either scheme.
    fn store_response_cookies(&self, host: &str, scheme: Scheme, headers: &[(String, String)]) {
        if !self.config.cookie_store {
            return;
        }
        let secure_response = scheme == Scheme::Https;

        let host = canonical_cookie_host(host);
        let mut cookies = self.cookies.lock();
        // Cap the number of tracked hosts to prevent unbounded growth.
        if !cookies.contains_key(&host) && cookies.len() >= MAX_COOKIE_HOSTS {
            return;
        }
        let mut touched = false;
        {
            let entry = cookies.entry(host.clone()).or_default();
            for (_, raw) in headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
            {
                if let Some((name, value)) = parse_set_cookie_pair(raw) {
                    touched = true;
                    // RFC 6265 section 5.2.5 matches the attribute name;
                    // its value, if supplied, does not disable Secure.
                    let secure = raw.split(';').skip(1).any(|attribute| {
                        attribute
                            .split_once('=')
                            .map_or(attribute, |(name, _)| name)
                            .trim()
                            .eq_ignore_ascii_case("secure")
                    });
                    if secure && !secure_response {
                        // A non-secure response cannot set a Secure cookie.
                        continue;
                    }
                    let existing = entry
                        .iter_mut()
                        .find(|cookie| cookie.name.eq_ignore_ascii_case(&name));
                    if !secure_response && existing.as_ref().is_some_and(|cookie| cookie.secure) {
                        // Leave Secure cookies alone: neither the replacement
                        // nor the empty-value deletion form may touch them.
                        continue;
                    }
                    if value.is_empty() {
                        entry.retain(|cookie| !cookie.name.eq_ignore_ascii_case(&name));
                        continue;
                    }
                    if let Some(existing) = existing {
                        existing.value = value;
                        existing.secure = secure;
                    } else if entry.len() < MAX_COOKIES_PER_HOST {
                        entry.push(StoredCookie {
                            name,
                            value,
                            secure,
                        });
                    }
                }
            }
        }

        if touched && cookies.get(&host).is_some_and(Vec::is_empty) {
            cookies.remove(&host);
        }
    }

    fn cookie_header_for_host(&self, host: &str, scheme: Scheme) -> Option<String> {
        let host = canonical_cookie_host(host);
        let host_cookies = {
            let cookies = self.cookies.lock();
            cookies
                .get(&host)?
                .iter()
                .filter(|cookie| !cookie.secure || scheme == Scheme::Https)
                .cloned()
                .collect::<Vec<_>>()
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

    /// Returns the client's TLS connector, building it on first use
    /// (asupersync-bo2caw). Every HTTPS connection of this client and of its
    /// clones shares the one connector; a build failure is reported with the
    /// same message on every call.
    #[cfg(feature = "tls")]
    fn tls_connector(&self) -> Result<TlsConnector, ClientError> {
        self.tls_connector
            .get_or_init(|| Self::build_tls_connector(&self.config))
            .clone()
            .map_err(ClientError::TlsError)
    }

    /// Builds the TLS connector from the client configuration: `http/1.1`
    /// ALPN, the feature-selected public roots, then every explicitly
    /// installed root certificate.
    #[cfg(feature = "tls")]
    fn build_tls_connector(config: &HttpClientConfig) -> Result<TlsConnector, String> {
        let builder = TlsConnectorBuilder::new().alpn_protocols(vec![b"http/1.1".to_vec()]);

        #[cfg(feature = "tls-native-roots")]
        let builder = builder.with_native_roots().map_err(|e| e.to_string())?;

        #[cfg(all(not(feature = "tls-native-roots"), feature = "tls-webpki-roots"))]
        let builder = builder.with_webpki_roots();

        // Explicitly installed roots (private CAs, self-signed test servers)
        // extend whatever the feature roots provided.
        let builder = config
            .tls_root_certificates
            .iter()
            .fold(builder, |builder, certificate| {
                builder.add_root_certificate(certificate)
            });

        builder.build().map_err(|e| e.to_string())
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
        let connector = self.tls_connector()?;
        connector
            .connect(domain, stream)
            .await
            .map_err(|e| ClientError::TlsError(e.to_string()))
    }

    async fn connect_io(&self, cx: &Cx, parsed: &ParsedUrl) -> Result<ClientIo, ClientError> {
        check_cx(cx)?;
        let stream = dial_tcp_with_resolver(
            &parsed.host,
            parsed.port,
            parsed_numeric_socket_addr(parsed),
            self.config.dns_resolver.as_ref(),
        )
        .await?;

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
        self.acquire_connection_with(cx, parsed, true).await
    }

    /// Connects a request retried after its reused connection turned out
    /// stale.
    ///
    /// The host's other idle connections are closed first: the server event
    /// that closed one (a restart, or its keep-alive timeout) closed the others
    /// of the same age too, and the retry must not land on one of them. The
    /// retry then dials a new connection, unless it has to wait at the host's
    /// connection limit and a connection is released meanwhile: one that has
    /// just finished an exchange, which it takes. If that one fails too, the
    /// error is the caller's; there is no second retry.
    async fn acquire_fresh_connection(
        &self,
        cx: &Cx,
        parsed: &ParsedUrl,
    ) -> Result<AcquiredConnection, ClientError> {
        self.acquire_fresh_connection_with_clock(cx, parsed, None)
            .await
    }

    async fn acquire_fresh_connection_with_clock(
        &self,
        cx: &Cx,
        parsed: &ParsedUrl,
        clock: Option<&PooledStreamDeadline>,
    ) -> Result<AcquiredConnection, ClientError> {
        let key = parsed.pool_key();
        {
            let mut pool = self.pool.lock();
            let mut idle = self.idle_connections.lock();
            for id in pool.remove_idle(&key) {
                Self::remove_idle_connection_locked(&mut idle, &key, id);
            }
        }
        self.acquire_connection_with_clock(cx, parsed, false, clock)
            .await
    }

    async fn acquire_connection_with(
        &self,
        cx: &Cx,
        parsed: &ParsedUrl,
        reuse_idle: bool,
    ) -> Result<AcquiredConnection, ClientError> {
        self.acquire_connection_with_clock(cx, parsed, reuse_idle, None)
            .await
    }

    async fn acquire_connection_with_clock(
        &self,
        cx: &Cx,
        parsed: &ParsedUrl,
        mut reuse_idle: bool,
        clock: Option<&PooledStreamDeadline>,
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
                    self.client.pool_released.notify_waiters();
                }
            }
        }

        let key = parsed.pool_key();
        let exhausted = || ClientError::PoolExhausted {
            host: parsed.host.clone(),
            port: parsed.port,
        };
        // Set by the first wait at the connection limit
        // (`HttpClientBuilder::pool_wait_timeout`).
        let mut wait_until: Option<Time> = None;
        let mut observe_cancel = true;
        let fresh_id = loop {
            // Armed before the pool is inspected, so a connection released
            // between the inspection and the wait below still wakes it.
            let mut released = std::pin::pin!(self.pool_released.notified());
            released.as_mut().enable();

            let now = self.pool_now();
            self.cleanup_expired_idle_connections(now);

            if reuse_idle {
                loop {
                    let taken = {
                        let mut pool = self.pool.lock();
                        let mut idle = self.idle_connections.lock();
                        let Some(pool_id) = pool.try_acquire(&key, now) else {
                            break;
                        };
                        let Some(io) = Self::take_idle_connection_locked(&mut idle, &key, pool_id)
                        else {
                            // Metadata can be stale if a prior request failed before reinserting.
                            pool.remove(&key, pool_id);
                            break;
                        };
                        (pool_id, io)
                    };
                    let (pool_id, mut io) = taken;
                    if idle_connection_is_reusable(&mut io) {
                        return Ok(AcquiredConnection {
                            pool_id: Some(pool_id),
                            io,
                            fresh: false,
                        });
                    }
                    // The server closed it, or sent something, while it was idle.
                    self.pool.lock().remove(&key, pool_id);
                    self.pool_released.notify_waiters();
                }
            }

            let fresh_id = {
                let mut pool = self.pool.lock();
                // Idle connections to other hosts must not lock this host out of
                // a full pool: close the least recently used one to make room.
                if let Some((evicted_key, evicted_id)) = pool.evict_idle_for(&key, now) {
                    let mut idle = self.idle_connections.lock();
                    Self::remove_idle_connection_locked(&mut idle, &evicted_key, evicted_id);
                }
                if pool.can_create_connection(&key, now) {
                    Some(pool.register_connecting(key.clone(), now, 1))
                } else {
                    None
                }
            };
            if let Some(id) = fresh_id {
                break id;
            }

            // At the connection limit: fail at once, or wait for another
            // request to release or close a connection.
            let Some(wait) = self.config.pool_wait_timeout else {
                return Err(exhausted());
            };
            let timer_now = clock.map_or_else(|| client_timer_now(cx), PooledStreamDeadline::now);
            let until = *wait_until.get_or_insert(timer_now + wait);
            let remaining = std::time::Duration::from_nanos(until.duration_since(timer_now));
            if remaining.is_zero() {
                return Err(exhausted());
            }
            let observe = observe_cancel;
            let mut cancelled = std::pin::pin!(cx.cancelled());
            let woken = poll_fn(move |task| {
                if released.as_mut().poll(task).is_ready() {
                    return Poll::Ready(true);
                }
                if observe && cancelled.as_mut().poll(task).is_ready() {
                    return Poll::Ready(false);
                }
                Poll::Pending
            });
            let wake = if let Some(clock) = clock {
                // The additive pooled-streaming lane retains its explicit
                // owner's clock even if a different task polls admission.
                let mut timer = clock.timer(until);
                let mut woken = std::pin::pin!(woken);
                poll_fn(|task| {
                    if let Poll::Ready(released) = woken.as_mut().poll(task) {
                        return Poll::Ready(Ok(released));
                    }
                    let _ambient = clock.clock.is_none().then(|| Cx::set_current(None));
                    Pin::new(&mut timer).poll_deadline(task).map(|()| Err(()))
                })
                .await
            } else {
                crate::time::timeout(timer_now, remaining, std::pin::pin!(woken))
                    .await
                    .map_err(|_| ())
            };
            match wake {
                // A connection released while this request waited has just
                // finished an exchange, so even a fresh-connection retry (after
                // a stale reuse) may take it from the idle set. Skipping the
                // idle set left it unusable: releases return connections to
                // idle, so the wait ran out with one sitting there
                // (br-asupersync-mu5yhv).
                Ok(true) => reuse_idle = true,
                Ok(false) => {
                    check_cx(cx)?;
                    // Cancellation is masked: keep waiting for a connection.
                    observe_cancel = false;
                }
                Err(_elapsed) => return Err(exhausted()),
            }
        };

        let mut guard = ConnectGuard {
            client: self,
            key: key.clone(),
            id: Some(fresh_id),
        };

        let io = self.connect_io(cx, parsed).await?;

        guard.id = None; // defuse the guard upon success

        Ok(AcquiredConnection {
            pool_id: Some(fresh_id),
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
            drop(pool);
            self.pool_released.notify_waiters();
        }
    }

    fn drop_connection(&self, key: &PoolKey, pool_id: Option<u64>) {
        if let Some(id) = pool_id {
            self.pool.lock().remove(key, id);
            self.remove_idle_connection(key, id);
            self.pool_released.notify_waiters();
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

    /// Returns the configured DNS resolver, if any.
    #[must_use]
    pub fn dns_resolver(&self) -> Option<&crate::net::dns::Resolver> {
        self.config.dns_resolver.as_ref()
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

/// A single absolute bound is copied into each redirect's response owner.
/// The clock is captured at entry and cannot be replaced by the context that
/// happens to poll the body later.
struct PooledStreamDeadline {
    at: Option<Time>,
    clock: Option<crate::time::TimerDriverHandle>,
}

impl PooledStreamDeadline {
    fn capture(cx: &Cx, configured: Option<std::time::Duration>) -> Self {
        let clock = cx.timer_driver();
        let now = clock
            .as_ref()
            .map_or_else(crate::time::wall_now, |clock| clock.now());
        let at = cx
            .budget()
            .deadline
            .into_iter()
            .chain(configured.map(|timeout| now + timeout))
            .min();
        Self { at, clock }
    }

    fn now(&self) -> Time {
        self.clock
            .as_ref()
            .map_or_else(crate::time::wall_now, |clock| clock.now())
    }

    fn timer(&self, at: Time) -> crate::time::Sleep {
        match &self.clock {
            Some(clock) => crate::time::Sleep::with_timer_driver(at, clock.clone()),
            None => {
                let _ambient = Cx::set_current(None);
                crate::time::Sleep::new(at)
            }
        }
    }
}

struct PooledStreamOwner {
    cx: Cx,
    cancel_waker: Option<CancelWakerToken>,
    deadline: Option<crate::time::Sleep>,
    standalone_clock: bool,
}

impl PooledStreamOwner {
    fn new(cx: Cx, deadline: &PooledStreamDeadline) -> Self {
        let timer = deadline.at.map(|at| deadline.timer(at));
        Self {
            cx,
            cancel_waker: None,
            deadline: timer,
            standalone_clock: deadline.clock.is_none(),
        }
    }

    fn poll_stop(&mut self, task: &mut Context<'_>) -> Option<ClientError> {
        self.cancel_waker = Some(self.cx.refresh_cancel_waker(self.cancel_waker, task.waker()));
        if let Some(timer) = self.deadline.as_mut() {
            // A driverless timer otherwise adopts a foreign ambient clock.
            let _ambient = self.standalone_clock.then(|| Cx::set_current(None));
            if Pin::new(timer).poll_deadline(task).is_ready() {
                // Record an expired owner budget, while retaining the client's
                // typed timeout verdict for the configured absolute deadline.
                let _ = self.cx.checkpoint();
                return Some(ClientError::DeadlineExceeded);
            }
        }
        check_cx(&self.cx).err()
    }

    fn retire(&mut self) {
        if let Some(token) = self.cancel_waker.take() {
            self.cx.clear_cancel_waker(token);
        }
        self.deadline = None;
    }
}

impl Drop for PooledStreamOwner {
    fn drop(&mut self) {
        self.retire();
    }
}

struct PooledStreamLease {
    client: HttpClient,
    key: PoolKey,
    pool_id: Option<u64>,
    fresh: bool,
    may_reuse: bool,
}

impl PooledStreamLease {
    fn release(mut self, io: ClientIo) {
        let pool_id = self.pool_id.take();
        // Releasing wakes arbitrary user wakers after publishing the idle
        // connection. A reentrant wake may already acquire it, so unwinding
        // this old lease must not remove its next owner's admission.
        self.client
            .release_connection(&self.key, pool_id, self.fresh, io);
    }
}

impl Drop for PooledStreamLease {
    fn drop(&mut self) {
        self.client.drop_connection(&self.key, self.pool_id);
    }
}

/// Whether an idle pooled connection can carry another request, judged by
/// one read that must not complete.
///
/// - EOF: the server closed the connection while it was idle. Keep-alive
///   timeouts of a few seconds are common, well under the pool's idle timeout.
/// - Bytes: the server sent something unsolicited, such as a 408 before
///   closing.
///
/// Either way a request written there would fail, or read a response that is
/// not its own. TLS bookkeeping such as a session ticket is consumed by the
/// TLS layer and still reads as pending.
fn idle_connection_is_reusable(io: &mut ClientIo) -> bool {
    let mut task_cx = Context::from_waker(std::task::Waker::noop());
    let mut probe = [0_u8; 1];
    let mut buf = ReadBuf::new(&mut probe);
    matches!(
        Pin::new(io).poll_read(&mut task_cx, &mut buf),
        Poll::Pending
    )
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
    secure: bool,
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
/// Proxy credentials are for the proxy. A request carried through a tunnel
/// (HTTP CONNECT or SOCKS5) reaches the origin itself, which must not see
/// them.
fn strip_proxy_authorization(headers: &mut Vec<(String, String)>) {
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case("proxy-authorization"));
}

fn get_header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
}

/// The `Accept-Encoding` a client with response decompression sends.
#[cfg(not(feature = "zstd"))]
const DECODED_CONTENT_CODINGS: &str = "gzip, deflate, br";

/// The `Accept-Encoding` a client with response decompression sends; with
/// the `zstd` feature it decodes zstd too (br-asupersync-t1fblr.32).
#[cfg(feature = "zstd")]
const DECODED_CONTENT_CODINGS: &str = "gzip, deflate, br, zstd";

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
        // 303 See Other: retrieve with GET, or HEAD for a HEAD request
        // (RFC 9110 §15.4.4)
        303 if *original == Method::Head => Method::Head,
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

fn dns_error_to_connect_error(err: crate::net::dns::DnsError) -> ClientError {
    let kind = match err {
        crate::net::dns::DnsError::Timeout => io::ErrorKind::TimedOut,
        crate::net::dns::DnsError::Cancelled => io::ErrorKind::Interrupted,
        crate::net::dns::DnsError::InvalidHost(_) => io::ErrorKind::InvalidInput,
        crate::net::dns::DnsError::NoRecords(_) => io::ErrorKind::NotFound,
        _ => io::ErrorKind::Other,
    };
    ClientError::ConnectError(io::Error::new(kind, err))
}

async fn dial_tcp_with_resolver(
    host: &str,
    port: u16,
    numeric_addr: Option<SocketAddr>,
    resolver: Option<&crate::net::dns::Resolver>,
) -> Result<TcpStream, ClientError> {
    if let Some(socket_addr) = numeric_addr {
        return TcpStream::connect_socket_addr(socket_addr)
            .await
            .map_err(ClientError::ConnectError);
    }
    let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return TcpStream::connect_socket_addr(SocketAddr::new(ip, port))
            .await
            .map_err(ClientError::ConnectError);
    }
    if let Some(resolver) = resolver {
        let lookup = resolver
            .lookup_ip(unbracketed)
            .await
            .map_err(dns_error_to_connect_error)?;
        let addrs: Vec<SocketAddr> = lookup
            .addresses()
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();
        if addrs.is_empty() {
            return Err(ClientError::ConnectError(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no IP addresses resolved for {host}"),
            )));
        }
        let config = crate::net::happy_eyeballs::HappyEyeballsConfig {
            connect_timeout: std::time::Duration::MAX,
            overall_timeout: std::time::Duration::MAX,
            ..Default::default()
        };
        crate::net::happy_eyeballs::connect(&addrs, &config)
            .await
            .map_err(ClientError::ConnectError)
    } else {
        let addr = format!("{host}:{port}");
        crate::net::happy_eyeballs::connect_resolved(addr, None)
            .await
            .map_err(ClientError::ConnectError)
    }
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
            let port = parse_explicit_port(port_str)?;
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
        let port = parse_explicit_port(port_str)?;
        if host.is_empty() {
            return Err(ClientError::InvalidUrl("empty host".into()));
        }
        return Ok((host.to_owned(), port));
    }

    Ok((authority.to_owned(), default_port))
}

fn parse_explicit_port(port: &str) -> Result<u16, ClientError> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ClientError::InvalidUrl(format!("invalid port: {port}")));
    }
    port.parse::<u16>()
        .map_err(|_| ClientError::InvalidUrl(format!("invalid port: {port}")))
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
    dns_resolver: Option<&crate::net::dns::Resolver>,
) -> Result<TcpStream, ClientError> {
    check_cx(cx)?;
    let mut stream = dial_tcp_with_resolver(
        &proxy.host,
        proxy.port,
        None,
        dns_resolver,
    )
    .await?;

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
    response_head_can_be_reused(response.status, response.version, &response.headers, req_method)
}

fn response_head_can_be_reused(
    status: u16,
    version: Version,
    headers: &[(String, String)],
    req_method: &Method,
) -> bool {
    // Only a 101 switches protocols (RFC 9110 section 7.8). A server may
    // advertise Upgrade on any other response, with Connection: Upgrade
    // marking that header hop-by-hop: Apache's mod_http2 sends
    // "Upgrade: h2,h2c" on ordinary responses. That connection is still
    // HTTP/1.1. A request that asked to upgrade is never pooled
    // (request_forbids_connection_reuse).
    if status == 101 {
        return false;
    }

    // RFC 9112 §6.3: when a response has no Content-Length and no
    // Transfer-Encoding, the body is delimited by connection close (EOF).
    // Such connections must not be reused.
    let has_content_length = headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("content-length"));
    let has_transfer_encoding = headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"));
    let is_bodyless =
        matches!(status, 100..=199 | 204 | 304) || matches!(req_method, Method::Head);

    if !has_content_length && !has_transfer_encoding && !is_bodyless {
        return false;
    }

    match version {
        Version::Http11 => !header_has_token(headers, "connection", "close"),
        // RFC 9112 §6.1: Transfer-Encoding in an HTTP/1.0 message means its
        // framing is faulty; close the connection after this response.
        Version::Http10 => {
            !has_transfer_encoding
                && header_has_token(headers, "connection", "keep-alive")
        }
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

fn parse_retry_after_delta(value: &str) -> Option<std::time::Duration> {
    let value = crate::http::h1::codec::trim_ows(value);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let seconds = value.parse::<u64>().ok()?;
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
        if !header_name.eq_ignore_ascii_case(name) {
            return false;
        }

        let mut found = false;
        for_each_header_value_token(header_value.as_bytes(), |part| {
            found |= part.eq_ignore_ascii_case(token.as_bytes());
        });
        found
    })
}

/// `s` without `prefix`, compared ASCII case-insensitively.
fn strip_prefix_ignore_ascii_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let (head, rest) = (s.get(..prefix.len())?, s.get(prefix.len()..)?);
    head.eq_ignore_ascii_case(prefix).then_some(rest)
}

/// Resolve a redirect Location header relative to the current URL.
fn resolve_redirect(current: &ParsedUrl, location: &str) -> String {
    // Absolute URL (the scheme is case-insensitive, RFC 3986 §3.1)
    if strip_prefix_ignore_ascii_case(location, "http://").is_some()
        || strip_prefix_ignore_ascii_case(location, "https://").is_some()
    {
        return location.to_owned();
    }

    // Protocol-relative
    if let Some(rest) = location.strip_prefix("//") {
        return match current.scheme {
            Scheme::Http => format!("http://{rest}"),
            Scheme::Https => format!("https://{rest}"),
        };
    }

    // A relative reference resolves against the current URL as RFC 3986
    // section 5.2.2 describes. The fragment is never sent (RFC 9110 section
    // 7.1).
    let scheme = match current.scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    };
    let location = location.split('#').next().unwrap_or_default();
    let (base_path, base_query) = match current.path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (current.path.as_str(), None),
    };
    let (ref_path, ref_query) = match location.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (location, None),
    };
    let (path, query) = if ref_path.is_empty() {
        // Same resource; a query in the reference replaces the base query.
        (base_path.to_owned(), ref_query.or(base_query))
    } else if ref_path.starts_with('/') {
        (remove_dot_segments(ref_path), ref_query)
    } else {
        // Merge with the base path's directory.
        let directory = base_path.rfind('/').map_or("/", |i| &base_path[..=i]);
        (
            remove_dot_segments(&format!("{directory}{ref_path}")),
            ref_query,
        )
    };
    let authority = format!("{scheme}://{}:{}", current.host, current.port);
    match query {
        Some(query) => format!("{authority}{path}?{query}"),
        None => format!("{authority}{path}"),
    }
}

/// Removes `.` and `..` segments from an absolute path (RFC 3986 section
/// 5.2.4). A path ending in either keeps its trailing slash, and `..` never
/// climbs above the root.
fn remove_dot_segments(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    let mut trailing_slash = false;
    for segment in path.split('/').skip(1) {
        trailing_slash = false;
        match segment {
            "." => trailing_slash = true,
            ".." => {
                segments.pop();
                trailing_slash = true;
            }
            other => segments.push(other),
        }
    }
    let mut resolved = String::with_capacity(path.len());
    for segment in segments {
        resolved.push('/');
        resolved.push_str(segment);
    }
    if trailing_slash || resolved.is_empty() {
        resolved.push('/');
    }
    resolved
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

/// Security-sensitive headers that must not cross an origin boundary. Per RFC
/// 9110 and common HTTP client practice (curl, reqwest, browsers),
/// `Authorization`, `Cookie`, and `Proxy-Authorization` must not be forwarded to
/// a different origin, to prevent credential leakage. Shared by the per-request
/// strip below and the default-header filter in `build_request`
/// (br-asupersync-u957g0).
fn is_sensitive_redirect_header(name: &str) -> bool {
    // `eq_ignore_ascii_case` avoids the per-header `String` allocation that
    // `to_ascii_lowercase` would incur on every default header (br-asupersync-u957g0).
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("proxy-authorization")
}

/// Strip security-sensitive headers when redirecting to a different origin.
/// Drops the headers that describe a request body, for a redirect that changes
/// the method and so drops the body. A kept Content-Length would contradict
/// the empty body and fail the redirected request.
fn strip_content_headers(headers: Vec<(String, String)>) -> Vec<(String, String)> {
    const CONTENT_HEADERS: [&str; 8] = [
        "content-length",
        "content-type",
        "content-encoding",
        "content-language",
        "content-location",
        "transfer-encoding",
        "digest",
        "last-modified",
    ];
    headers
        .into_iter()
        .filter(|(name, _)| {
            !CONTENT_HEADERS
                .iter()
                .any(|content| name.eq_ignore_ascii_case(content))
        })
        .collect()
}

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
        .filter(|(name, _)| !is_sensitive_redirect_header(name))
        .collect()
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    memmem::find(buf, b"\r\n\r\n").map(|idx| idx.saturating_add(4))
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
        && validate_header_field("User-Agent", ua).is_err()
    {
        return Err(ClientError::InvalidConnectInput(
            "User-Agent header is not a valid HTTP field".into(),
        ));
    }
    for (name, value) in extra_headers {
        if validate_header_field(name, value).is_err() {
            return Err(ClientError::InvalidConnectInput(
                "header name/value is not a valid HTTP field".into(),
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
    if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ClientError::HttpError(
            crate::http::h1::codec::HttpError::BadRequestLine,
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
#[path = "http_client_inline_tests.rs"]
mod tests;
