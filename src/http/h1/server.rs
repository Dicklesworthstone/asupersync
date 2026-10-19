//! HTTP/1.1 server connection handler.
//!
//! [`Http1Server`] wraps a service and drives an HTTP/1.1 connection,
//! reading requests and writing responses using [`Http1Codec`] over a
//! framed transport. Supports keep-alive, request limits, idle timeouts,
//! and graceful shutdown.

use crate::bytes::{Buf, BytesMut};
use crate::codec::{Encoder, Framed};
use crate::cx::Cx;
use crate::http::body::Frame;
use crate::http::h1::codec::{
    Http1Codec, HttpError, decode_streaming_request_head, for_each_header_value_token,
    preview_request_head, require_transfer_encoding_chunked, trim_ows, trim_ows_bytes,
    validate_header_field,
};
use crate::http::h1::stream::{
    BodyKind, ChunkedEncoder, Http1ProducedResponse, Http1ProducedResponseFuture,
    IncomingBodyDrainProgress, IncomingBodyError, IncomingRequestBody, IncomingRequestBodyWriter,
    OutgoingBodySender, RequestHead, ResponseHead, StreamingResponse, StreamingServerRequest,
};
use crate::http::h1::types::{Method, Request, Response, Version, default_reason};
use crate::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::server::shutdown::{ShutdownPhase, ShutdownSignal};
use crate::stream::Stream;
use crate::time::{timeout, wall_now};
use crate::tracing_compat::{error, warn};
use crate::types::{Budget, CancelKind};
use crate::web::WebBodyDiagnostic;
use crate::web::request_region::{
    HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC, RequestBudgetSource, ServerHopOutcome,
    ServerProducerCancellation, ServerRequestRegion, classify_server_producer_cancellation,
    derive_request_budget,
};
use crate::web::sse::{
    Http1SseResponse, StreamingSse, StreamingSseSource, StreamingSseTransportError,
    StreamingSseTransportStep, VecSseSource,
};
use base64::Engine as _;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
mod owned;
#[cfg(not(target_arch = "wasm32"))]
pub(super) use owned::OwnedRequests;

/// Inputs shared by legacy and opt-in scheduler-owned dispatch.
pub(super) struct RequestExecutionConfig {
    budget: Budget,
    started_at: crate::types::Time,
    source: RequestBudgetSource,
    drain_grace: Duration,
    connection: Option<Cx>,
    shutdown: Option<ShutdownSignal>,
}

/// Legacy dispatch retains borrowed handlers and response conversion timing.
async fn execute_legacy<F, Fut, R>(
    handler: Arc<F>,
    request: Request,
    config: RequestExecutionConfig,
) -> Result<Option<ServerHopOutcome<Http1Response>>, HttpError>
where
    F: Fn(Request) -> Fut + Send + Sync,
    Fut: Future<Output = R> + Send,
    R: IntoHttp1Response,
{
    let region = match config.connection.as_ref() {
        Some(connection) => Some(ServerRequestRegion::mint_from_connection(
            "h1",
            config.budget,
            config.started_at,
            connection,
        )),
        None => ServerRequestRegion::mint("h1", config.budget, config.started_at),
    };
    let output = match region {
        Some(region) => {
            race_force_close(
                config.shutdown.as_ref(),
                region.run_with_protocol_drain(
                    config.source,
                    config.connection,
                    config.drain_grace,
                    handler(request),
                ),
            )
            .await
        }
        None => race_force_close(config.shutdown.as_ref(), handler(request))
            .await
            .map(ServerHopOutcome::Ok),
    };
    Ok(output.map(|output| match output {
        ServerHopOutcome::Ok(response) => ServerHopOutcome::Ok(response.into_h1_response()),
        ServerHopOutcome::Cancelled => ServerHopOutcome::Cancelled,
        ServerHopOutcome::ConnectionLost => ServerHopOutcome::ConnectionLost,
        ServerHopOutcome::DeadlineExceeded => ServerHopOutcome::DeadlineExceeded,
        ServerHopOutcome::Panicked(message) => ServerHopOutcome::Panicked(message),
    }))
}

/// Host header validation policy for security against Host header injection attacks.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum HostPolicy {
    /// Allow only hosts in the provided list (secure, recommended).
    AllowList(Vec<String>),
    /// Reject all requests - useful for services that don't need Host headers.
    #[default]
    RejectUnknown,
    /// Accept any Host header (INSECURE - only for legacy compatibility).
    /// Malformed requests such as duplicate Host headers are still rejected.
    /// Use with extreme caution as this enables Host header injection attacks.
    AllowAll,
}

impl HostPolicy {
    /// Create an allow-list policy for the given hosts.
    pub fn allow_list(hosts: Vec<String>) -> Self {
        Self::AllowList(hosts)
    }

    /// Allow all hosts (INSECURE - use only for legacy compatibility).
    /// This disables Host header validation and enables injection attacks.
    pub fn allow_all() -> Self {
        Self::AllowAll
    }

    /// Reject all requests (most secure).
    pub fn reject_unknown() -> Self {
        Self::RejectUnknown
    }
}

/// Configuration for HTTP/1.1 server connections.
#[derive(Debug, Clone)]
pub struct Http1Config {
    /// Maximum header block size in bytes.
    pub max_headers_size: usize,
    /// Maximum body size in bytes.
    pub max_body_size: usize,
    /// Whether to support HTTP/1.1 keep-alive.
    pub keep_alive: bool,
    /// Maximum requests allowed on a single keep-alive connection.
    /// `None` means unlimited.
    pub max_requests_per_connection: Option<u64>,
    /// Idle timeout between requests on a keep-alive connection, and the
    /// bound on how long one request may keep the server waiting on the
    /// socket: the buffered server reads a whole request (head and body)
    /// under it, and the streaming server applies it to the head and then to
    /// the body's accumulated socket waits (asupersync-1to1qw). It also
    /// bounds the TLS handshake on `Http1Listener::run_tls` (feature `tls`)
    /// when the acceptor sets no handshake timeout of its own.
    /// Response writes, flushes, and waits for the next produced body frame
    /// also use this bound. Successful frame transmission starts a new window.
    /// `None` means no timeout; force-close still interrupts a pending response.
    pub idle_timeout: Option<Duration>,
    /// br-asupersync-t9yqht, br-asupersync-scxixg: Host header validation policy.
    /// SECURITY: Defends against Host header injection attacks where attackers
    /// set `Host: attacker.com` to poison absolute URLs in password-reset emails,
    /// OAuth `redirect_uri` validation, cache keys, CSRF tokens, etc.
    ///
    /// - `AllowList(hosts)`: Only accept requests with Host headers in the list
    /// - `RejectUnknown`: Reject all requests (secure default for new deployments)
    /// - `AllowAll`: Accept any Host header (legacy insecure behavior)
    pub allowed_hosts: HostPolicy,
    /// br-asupersync-server-stack-hardening-eeexl1.1.1: server-default
    /// per-request timeout. When set, every request budget is tightened by
    /// this duration at the server hop (meet semantics — it can only
    /// tighten the connection budget, never extend it). `None` means no
    /// server-imposed request deadline.
    pub request_timeout: Option<Duration>,
    /// Opt-in cap for the client-supplied `Request-Timeout` header. When
    /// `None` (the default) the header is ignored entirely. When set, a
    /// parseable header tightens the request budget by
    /// `min(header, cap)` — a client can therefore never extend the budget
    /// beyond the cap (or beyond what config/connection already imposed).
    pub request_timeout_header_cap: Option<Duration>,
    /// Bounded drain grace after a request-budget deadline or a
    /// connection cancel: the handler gets this long to observe the
    /// cancel and finish cleanly before the drop backstop.
    pub request_drain_grace: Duration,
}

impl Default for Http1Config {
    fn default() -> Self {
        Self {
            max_headers_size: 64 * 1024,
            max_body_size: 16 * 1024 * 1024,
            keep_alive: true,
            max_requests_per_connection: Some(1000),
            idle_timeout: Some(Duration::from_mins(1)),
            allowed_hosts: HostPolicy::default(), // Secure by default: RejectUnknown
            request_timeout: None,
            request_timeout_header_cap: None,
            request_drain_grace: Duration::from_millis(500),
        }
    }
}

impl Http1Config {
    /// Set the maximum header block size.
    #[must_use]
    pub fn max_headers_size(mut self, size: usize) -> Self {
        self.max_headers_size = size;
        self
    }

    /// Set the maximum body size.
    #[must_use]
    pub fn max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }

    /// Enable or disable keep-alive.
    #[must_use]
    pub fn keep_alive(mut self, enabled: bool) -> Self {
        self.keep_alive = enabled;
        self
    }

    /// Set the maximum number of requests per connection.
    #[must_use]
    pub fn max_requests(mut self, max: Option<u64>) -> Self {
        self.max_requests_per_connection = max;
        self
    }

    /// Set the idle timeout between requests.
    #[must_use]
    pub fn idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the Host header validation policy (br-asupersync-scxixg).
    ///
    /// Replaces legacy allowed_hosts with secure-by-default HostPolicy.
    /// Use HostPolicy::AllowList(hosts), HostPolicy::RejectUnknown, or
    /// HostPolicy::AllowAll (insecure legacy mode).
    #[must_use]
    pub fn host_policy(mut self, policy: HostPolicy) -> Self {
        self.allowed_hosts = policy;
        self
    }

    /// Legacy method for backwards compatibility (br-asupersync-scxixg).
    /// Converts `Option<Vec<String>>` to `HostPolicy`: `None` becomes `AllowAll`,
    /// Some(hosts) becomes AllowList.
    #[must_use]
    pub fn allowed_hosts(mut self, hosts: Option<Vec<String>>) -> Self {
        self.allowed_hosts = match hosts {
            None => HostPolicy::AllowAll,
            Some(hosts) => HostPolicy::AllowList(hosts),
        };
        self
    }

    /// Set the server-default per-request timeout (see
    /// [`Self::request_timeout`] field docs).
    #[must_use]
    pub fn request_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Opt in to the client `Request-Timeout` header with the given cap
    /// (see [`Self::request_timeout_header_cap`] field docs).
    #[must_use]
    pub fn request_timeout_header_cap(mut self, cap: Option<Duration>) -> Self {
        self.request_timeout_header_cap = cap;
        self
    }

    /// Set the post-cancel drain grace for request handlers (see
    /// [`Self::request_drain_grace`] field docs).
    #[must_use]
    pub fn request_drain_grace(mut self, grace: Duration) -> Self {
        self.request_drain_grace = grace;
        self
    }
}

/// Additive configuration for [`Http1StreamingServer`].
///
/// Connection-wide settings remain in the backwards-compatible
/// [`Http1Config`]. Streaming-only queue and unread-body drain controls live
/// here so adding them does not make 0.4.3 `Http1Config` struct literals fail
/// to compile.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Http1StreamingConfig {
    /// Backwards-compatible connection configuration.
    pub connection: Http1Config,
    /// Maximum number of decoded request-body frames queued for a handler.
    pub incoming_body_frame_capacity: usize,
    /// Maximum request-body bytes queued independently of frame capacity.
    pub incoming_body_queued_bytes: usize,
    /// Maximum unread decoded frames discarded after a handler returns.
    pub unread_body_drain_frames: u64,
    /// Maximum unread body bytes discarded after a handler returns.
    pub unread_body_drain_bytes: u64,
    /// Maximum time spent synchronizing unread request-body EOF.
    pub unread_body_drain_timeout: Duration,
}

impl Default for Http1StreamingConfig {
    fn default() -> Self {
        Self::from(Http1Config::default())
    }
}

impl From<Http1Config> for Http1StreamingConfig {
    fn from(connection: Http1Config) -> Self {
        Self {
            connection,
            incoming_body_frame_capacity: 8,
            incoming_body_queued_bytes: 512 * 1024,
            unread_body_drain_frames: 8,
            unread_body_drain_bytes: 512 * 1024,
            unread_body_drain_timeout: Duration::from_millis(500),
        }
    }
}

impl std::ops::Deref for Http1StreamingConfig {
    type Target = Http1Config;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl Http1StreamingConfig {
    /// Replaces the connection-wide HTTP/1 configuration.
    #[must_use]
    pub fn connection(mut self, connection: Http1Config) -> Self {
        self.connection = connection;
        self
    }

    /// Sets independent request-body frame and queued-byte backpressure caps.
    #[must_use]
    pub fn incoming_body_queue(mut self, frame_capacity: usize, queued_bytes: usize) -> Self {
        self.incoming_body_frame_capacity = frame_capacity.max(1);
        self.incoming_body_queued_bytes = queued_bytes.max(1);
        self
    }

    /// Sets bounded unread-body drain frame, byte, and time limits.
    #[must_use]
    pub fn unread_body_drain(mut self, frames: u64, bytes: u64, timeout: Duration) -> Self {
        self.unread_body_drain_frames = frames;
        self.unread_body_drain_bytes = bytes;
        self.unread_body_drain_timeout = timeout;
        self
    }
}

/// Parses the client `Request-Timeout` header into a duration.
///
/// Accepted forms (after RFC OWS (SP / HTAB) trim): a bare integer meaning
/// **milliseconds** (`"1500"`), or an integer with an `ms`, `s`, or `m`
/// suffix (`"1500ms"`, `"5s"`, `"2m"`). Fail-closed on anything else:
///
/// - missing header, empty value, or non-digit characters → `None`
/// - more than one `Request-Timeout` header (ambiguous) → `None`
/// - zero → `None` (a zero timeout cannot express a useful request)
/// - more than 10 digits (would exceed ~115 days in ms) → `None`
///
/// `None` always means "fall back to the server-configured budget"; a
/// malformed header can never weaken or extend anything.
pub(crate) fn parse_request_timeout_header(headers: &[(String, String)]) -> Option<Duration> {
    let mut found: Option<&str> = None;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("request-timeout") {
            if found.is_some() {
                // Duplicate headers are ambiguous: fail closed.
                return None;
            }
            found = Some(value);
        }
    }
    let value = trim_ows(found?);
    let (digits, unit): (&str, fn(u64) -> Duration) = if let Some(d) = value.strip_suffix("ms") {
        (d, Duration::from_millis)
    } else if let Some(d) = value.strip_suffix('s') {
        (d, Duration::from_secs)
    } else if let Some(d) = value.strip_suffix('m') {
        (d, |minutes| Duration::from_secs(minutes.saturating_mul(60)))
    } else {
        (value, Duration::from_millis)
    };
    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let amount: u64 = digits.parse().ok()?;
    if amount == 0 {
        return None;
    }
    Some(unit(amount))
}

/// br-asupersync-t9yqht: extract the host portion of a `Host` header
/// value (strip port, lowercase, IPv6 brackets handled). Returns
/// `None` if the value is malformed.
fn parse_host_header_host(value: &str) -> Option<String> {
    let value = trim_ows(value);
    if !is_valid_host_component(value) {
        return None;
    }
    // IPv6 literals: `[::1]:8080` or `[::1]`. The last ':' OUTSIDE the
    // brackets is the port separator.
    if let Some(stripped) = value.strip_prefix('[') {
        let close = stripped.find(']')?;
        let host = &stripped[..close];
        let remainder = &stripped[(close + 1)..];
        if !is_valid_host_component(host) {
            return None;
        }
        if !remainder.is_empty() {
            let port = remainder.strip_prefix(':')?;
            if !is_valid_host_port(port) {
                return None;
            }
        }
        return Some(host.to_ascii_lowercase());
    }
    // Plain host or `host:port` — split on the last ':' and reject
    // malformed suffixes rather than silently truncating them.
    if let Some((host, port)) = value.rsplit_once(':') {
        if host.is_empty()
            || host.contains(':')
            || !is_valid_host_component(host)
            || !is_valid_host_port(port)
        {
            return None;
        }
        return Some(host.to_ascii_lowercase());
    }
    Some(value.to_ascii_lowercase())
}

fn is_valid_host_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| !ch.is_control() && !ch.is_whitespace())
}

fn is_valid_host_port(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostRejection {
    Missing,
    Multiple,
    Invalid(String),
    NotAllowed(String),
}

impl HostRejection {
    pub(crate) fn status(&self) -> u16 {
        match self {
            Self::Missing | Self::Multiple | Self::Invalid(_) => 400,
            Self::NotAllowed(_) => 421,
        }
    }

    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::Missing | Self::Multiple | Self::Invalid(_) => "Bad Request",
            Self::NotAllowed(_) => "Misdirected Request",
        }
    }

    pub(crate) fn body(&self) -> String {
        match self {
            Self::Missing => "Missing required Host header".to_string(),
            Self::Multiple => "multiple Host headers".to_string(),
            Self::Invalid(host) => format!("Invalid Host header: '{host}'"),
            Self::NotAllowed(host) => format!("Host '{host}' not in allowed-hosts allow-list"),
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Missing => "",
            Self::Multiple => "multiple Host headers",
            Self::Invalid(host) | Self::NotAllowed(host) => host.as_str(),
        }
    }
}

impl std::fmt::Display for HostRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<str> for HostRejection {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for HostRejection {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

fn single_host_header_value(headers: &[(String, String)]) -> Result<Option<&str>, HostRejection> {
    let mut host_value = None;
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("host") {
            continue;
        }
        if host_value.is_some() {
            return Err(HostRejection::Multiple);
        }
        host_value = Some(value.as_str());
    }
    Ok(host_value)
}

/// br-asupersync-scxixg: validate the request's `Host` header against
/// the host policy. Returns `Ok(())` if validation passes; `Err(HostRejection)`
/// on failure with RFC 9112 §3.2 (400 Bad Request for missing/multiple/invalid)
/// or §7.1 (421 Misdirected Request for unallowed hosts).
///
/// `AllowAll` refuses only what RFC 9112 §3.2 calls malformed: duplicate Host
/// fields, an invalid Host value, and an HTTP/1.1 request without Host. As in
/// v0.4.3 it serves HTTP/1.0 and HTTP/2 requests that carry no Host, an empty
/// Host (a target without an authority) and an empty port, all valid syntax.
pub(crate) fn validate_host_header(
    headers: &[(String, String)],
    version: Version,
    host_policy: &HostPolicy,
) -> Result<(), HostRejection> {
    match host_policy {
        HostPolicy::AllowAll => {
            let host_value = single_host_header_value(headers)?;
            let Some(host_value) = host_value else {
                if version == Version::Http11 {
                    return Err(HostRejection::Missing);
                }
                return Ok(());
            };
            let authority = trim_ows(host_value);
            let authority = authority.strip_suffix(':').unwrap_or(authority);
            if authority.is_empty() || parse_host_header_host(authority).is_some() {
                Ok(())
            } else {
                Err(HostRejection::Invalid(host_value.to_string()))
            }
        }
        HostPolicy::RejectUnknown => {
            let host_value = single_host_header_value(headers)?;
            let Some(host_value) = host_value else {
                return Err(HostRejection::Missing);
            };
            let Some(parsed) = parse_host_header_host(host_value) else {
                return Err(HostRejection::Invalid(host_value.to_string()));
            };
            Err(HostRejection::NotAllowed(parsed))
        }
        HostPolicy::AllowList(allow_list) => {
            let host_value = single_host_header_value(headers)?;
            let Some(host_value) = host_value else {
                // RFC 7230 §5.4: HTTP/1.1 requests MUST include Host. Reject.
                return Err(HostRejection::Missing);
            };
            let Some(parsed) = parse_host_header_host(host_value) else {
                return Err(HostRejection::Invalid(host_value.to_string()));
            };
            if allow_list.is_empty() {
                return Err(HostRejection::NotAllowed(parsed));
            }
            if allow_list
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&parsed))
            {
                Ok(())
            } else {
                Err(HostRejection::NotAllowed(parsed))
            }
        }
    }
}

/// Per-connection state tracking for HTTP/1.1 lifecycle.
#[derive(Debug)]
pub struct ConnectionState {
    /// Number of requests processed on this connection.
    pub requests_served: u64,
    /// When the connection was established.
    pub connected_at: crate::types::Time,
    /// When the last request completed.
    pub last_request_at: crate::types::Time,
    /// Current phase of the connection.
    pub phase: ConnectionPhase,
}

/// Boxed future that owns one committed HTTP/1 upgraded connection.
pub type Http1UpgradeFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// An upgraded HTTP/1 connection on whatever transport carried it: TCP, TLS,
/// a Unix-domain socket, or a connection handed over by `HttpAutoListener`.
/// Received by an [`Http1Upgrade::new_any`] action.
pub struct Http1UpgradedIo(Box<dyn UpgradedTransport>);

trait UpgradedTransport: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> UpgradedTransport for T {}

impl Http1UpgradedIo {
    fn new<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(io: T) -> Self {
        Self(Box::new(io))
    }
}

impl std::fmt::Debug for Http1UpgradedIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http1UpgradedIo").finish_non_exhaustive()
    }
}

impl AsyncRead for Http1UpgradedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut crate::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Http1UpgradedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.get_mut().0).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_shutdown(cx)
    }
}

/// The callback of an [`Http1Upgrade`]: typed to the listener's TCP stream,
/// or to any transport.
enum UpgradeDriver {
    Tcp(
        Box<
            dyn FnOnce(Cx, crate::net::tcp::stream::TcpStream, BytesMut) -> Http1UpgradeFuture
                + Send
                + 'static,
        >,
    ),
    Any(Box<dyn FnOnce(Cx, Http1UpgradedIo, BytesMut) -> Http1UpgradeFuture + Send + 'static>),
}

/// One-shot action executed after an HTTP/1 upgrade response is fully flushed.
///
/// The action is intentionally native-listener scoped: it receives the
/// transport owned by the listener connection task plus every byte the HTTP
/// codec read beyond the request. It must not spawn or detach its own owner.
/// An action made with [`Self::new`] receives the TCP stream and runs only
/// on a listener's own TCP connections; one made with [`Self::new_any`] also
/// runs over TLS, Unix-domain sockets and `HttpAutoListener`.
pub struct Http1Upgrade {
    driver: UpgradeDriver,
    expected_protocol: Option<String>,
    expected_extensions: Vec<String>,
}

impl std::fmt::Debug for Http1Upgrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http1Upgrade").finish_non_exhaustive()
    }
}

impl Http1Upgrade {
    /// Create a one-shot native HTTP/1 upgrade action.
    #[must_use]
    pub fn new<F, Fut>(driver: F) -> Self
    where
        F: FnOnce(Cx, crate::net::tcp::stream::TcpStream, BytesMut) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self {
            driver: UpgradeDriver::Tcp(Box::new(move |cx, io, read_ahead| {
                Box::pin(driver(cx, io, read_ahead))
            })),
            expected_protocol: None,
            expected_extensions: Vec::new(),
        }
    }

    /// Create a one-shot upgrade action that runs on any transport the
    /// listener serves (TCP, TLS through `Http1Listener::run_tls`, a
    /// Unix-domain socket, or `HttpAutoListener`); it receives the transport
    /// as an [`Http1UpgradedIo`].
    #[must_use]
    pub fn new_any<F, Fut>(driver: F) -> Self
    where
        F: FnOnce(Cx, Http1UpgradedIo, BytesMut) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self {
            driver: UpgradeDriver::Any(Box::new(move |cx, io, read_ahead| {
                Box::pin(driver(cx, io, read_ahead))
            })),
            expected_protocol: None,
            expected_extensions: Vec::new(),
        }
    }

    /// Bind the callback's negotiated WebSocket metadata to the `101` that
    /// will be committed on the wire.
    #[must_use]
    pub fn with_websocket_negotiation(
        mut self,
        protocol: Option<String>,
        extensions: Vec<String>,
    ) -> Self {
        self.expected_protocol = protocol;
        self.expected_extensions = extensions;
        self
    }

    pub(crate) fn run(
        self,
        cx: Cx,
        io: crate::net::tcp::stream::TcpStream,
        read_ahead: BytesMut,
    ) -> Http1UpgradeFuture {
        match self.driver {
            UpgradeDriver::Tcp(driver) => driver(cx, io, read_ahead),
            UpgradeDriver::Any(driver) => driver(cx, Http1UpgradedIo::new(io), read_ahead),
        }
    }

    /// Runs a transport-generic action on `io`; `None` for a TCP-typed one,
    /// which the transport-generic serve path refuses before the `101`.
    pub(crate) fn run_on<T>(self, cx: Cx, io: T, read_ahead: BytesMut) -> Option<Http1UpgradeFuture>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        match self.driver {
            UpgradeDriver::Tcp(_) => None,
            UpgradeDriver::Any(driver) => Some(driver(cx, Http1UpgradedIo::new(io), read_ahead)),
        }
    }

    const fn runs_on_any_transport(&self) -> bool {
        matches!(self.driver, UpgradeDriver::Any(_))
    }

    pub(crate) fn websocket_negotiation_matches(&self, response: &Response) -> bool {
        let protocols = response
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-protocol"))
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>();
        // The 101 must advertise exactly the extensions the callback's codec
        // was configured with (permessage-deflate is implemented), in order,
        // and none when it negotiated none.
        let extensions = response
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-extensions"))
            .flat_map(|(_, value)| value.split(','))
            .map(str::trim)
            .collect::<Vec<_>>();

        protocols.len() <= 1
            && protocols.first().copied() == self.expected_protocol.as_deref()
            && extensions.len() == self.expected_extensions.len()
            && extensions
                .iter()
                .zip(&self.expected_extensions)
                .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected.trim()))
    }

    pub(crate) fn expected_protocol(&self) -> Option<&str> {
        self.expected_protocol.as_deref()
    }

    pub(crate) fn expected_extensions(&self) -> &[String] {
        &self.expected_extensions
    }
}

/// HTTP/1 response envelope with an optional explicit ownership handoff.
///
/// Plain [`Response`] handlers remain source-compatible through
/// [`IntoHttp1Response`]. A bare `101 Switching Protocols` response never
/// transfers the transport; ownership requires the one-shot action.
#[derive(Debug)]
pub struct Http1Response {
    /// Wire response to validate and flush before any handoff.
    pub response: Response,
    upgrade: Option<Http1Upgrade>,
}

impl Http1Response {
    /// Wrap an ordinary response with no ownership handoff.
    #[must_use]
    pub fn new(response: Response) -> Self {
        Self {
            response,
            upgrade: None,
        }
    }

    /// The response, for a transport that cannot hand the connection off;
    /// `None` when it carries an upgrade action.
    pub(crate) fn into_plain(self) -> Option<Response> {
        self.upgrade.is_none().then_some(self.response)
    }

    /// Attach an explicit one-shot upgrade action.
    #[must_use]
    pub fn with_upgrade(mut self, upgrade: Http1Upgrade) -> Self {
        self.upgrade = Some(upgrade);
        self
    }
}

/// Conversion accepted by [`Http1Server`] and the production HTTP/1 listener.
pub trait IntoHttp1Response {
    /// Convert into the explicit HTTP/1 response envelope.
    fn into_h1_response(self) -> Http1Response;
}

impl IntoHttp1Response for Response {
    fn into_h1_response(self) -> Http1Response {
        Http1Response::new(self)
    }
}

impl IntoHttp1Response for Http1Response {
    fn into_h1_response(self) -> Http1Response {
        self
    }
}

/// Which upgrade actions a serve path may hand the connection to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UpgradeAdmission {
    /// None: the compatibility `serve` path.
    Refused,
    /// TCP-typed and transport-generic actions: a listener's TCP connection.
    Any,
    /// Transport-generic actions only: TLS, Unix-domain, handed-off.
    TransportGeneric,
}

/// Terminal result from the listener-only upgrade-aware connection driver.
pub(crate) enum Http1ServeOutcome<T> {
    Closed(ConnectionState),
    Upgraded {
        io: T,
        read_ahead: BytesMut,
        upgrade: Http1Upgrade,
    },
}

/// Connection lifecycle phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPhase {
    /// Waiting for the first or next request.
    Idle,
    /// Currently reading a request.
    Reading,
    /// Executing the handler.
    Processing,
    /// Writing the response.
    Writing,
    /// Connection is shutting down gracefully.
    Closing,
}

#[derive(Debug)]
enum ReadOutcome {
    Read {
        item: Option<Result<Request, HttpError>>,
        continue_sent: bool,
    },
    ExpectationRejected,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectationAction {
    None,
    Continue,
    Reject,
}

type ShutdownWaitFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

#[derive(Debug)]
enum ExpectationStep {
    ContinueLoop,
    Return(Poll<ReadOutcome>),
}

impl ConnectionState {
    fn new(now: crate::types::Time) -> Self {
        Self {
            requests_served: 0,
            connected_at: now,
            last_request_at: now,
            phase: ConnectionPhase::Idle,
        }
    }

    /// Returns the duration since the last request completed (or since connect).
    #[must_use]
    pub fn idle_duration(&self, now: crate::types::Time) -> Duration {
        Duration::from_nanos(
            now.as_nanos()
                .saturating_sub(self.last_request_at.as_nanos()),
        )
    }

    /// Returns the total connection lifetime.
    #[must_use]
    pub fn connection_age(&self, now: crate::types::Time) -> Duration {
        Duration::from_nanos(now.as_nanos().saturating_sub(self.connected_at.as_nanos()))
    }

    /// Returns whether the connection has exceeded the request limit.
    fn exceeded_request_limit(&self, max: Option<u64>) -> bool {
        max.is_some_and(|max| self.requests_served >= max)
    }

    /// Returns whether the connection has exceeded the idle timeout.
    fn exceeded_idle_timeout(&self, timeout: Option<Duration>, now: crate::types::Time) -> bool {
        timeout.is_some_and(|timeout| self.idle_duration(now) > timeout)
    }
}

/// HTTP/1.1 server that processes requests using a service function.
///
/// Reads requests from the transport, passes them to the service, and
/// writes responses back. Tracks connection lifecycle with configurable
/// keep-alive, request limits, and idle timeouts.
///
/// # Example
///
/// ```ignore
/// let server = Http1Server::new(|req| async move {
///     Response::new(200, "OK", b"Hello".to_vec())
/// });
/// server.serve(tcp_stream).await?;
/// ```
pub struct Http1Server<F> {
    handler: Arc<F>,
    config: Http1Config,
    shutdown_signal: Option<ShutdownSignal>,
    in_flight_requests: Option<Arc<AtomicUsize>>,
}

impl<F, Fut> Http1Server<F>
where
    F: Fn(Request) -> Fut + Send + Sync,
    Fut: Future<Output = Response> + Send,
{
    /// Create a server whose handler returns the established plain response
    /// type. Keeping this exact output type preserves inference for existing
    /// diverging and otherwise unconstrained handler futures.
    pub fn new(handler: F) -> Self {
        Self::new_upgradeable(handler)
    }

    /// Create a plain-response server with custom configuration.
    pub fn with_config(handler: F, config: Http1Config) -> Self {
        Self::with_config_upgradeable(handler, config)
    }
}

impl<F, Fut, R> Http1Server<F>
where
    F: Fn(Request) -> Fut + Send + Sync,
    Fut: Future<Output = R> + Send,
    R: IntoHttp1Response,
{
    /// Create a server that accepts an explicit [`Http1Response`] envelope.
    pub fn new_upgradeable(handler: F) -> Self {
        Self {
            handler: Arc::new(handler),
            config: Http1Config::default(),
            shutdown_signal: None,
            in_flight_requests: None,
        }
    }

    /// Create an upgrade-aware response server with custom configuration.
    pub fn with_config_upgradeable(handler: F, config: Http1Config) -> Self {
        Self {
            handler: Arc::new(handler),
            config,
            shutdown_signal: None,
            in_flight_requests: None,
        }
    }

    /// Attach a shutdown signal for graceful drain / force-close coordination.
    #[must_use]
    pub fn with_shutdown_signal(mut self, signal: ShutdownSignal) -> Self {
        self.shutdown_signal = Some(signal);
        self
    }

    /// Attach a shared in-flight request counter
    /// (br-asupersync-server-stack-hardening-eeexl1.2, D2.2b).
    ///
    /// The counter is incremented once per request the moment the request
    /// head has been read off the wire and decremented when the request's
    /// response has been flushed (or the connection abandons the request).
    /// A listener shares one counter across every connection it serves so a
    /// request-aware drain supervisor can observe total live requests, which
    /// is strictly finer-grained than connection-level tracking: an idle
    /// keep-alive connection holds no in-flight request.
    #[must_use]
    pub fn with_in_flight_requests(mut self, counter: Arc<AtomicUsize>) -> Self {
        self.in_flight_requests = Some(counter);
        self
    }

    async fn read_next<T>(
        &self,
        framed: &mut Framed<T, Http1Codec>,
        _state: &ConnectionState,
        connection_owner: Option<&Cx>,
    ) -> Option<ReadOutcome>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let read_future = async {
            let mut owner_cancel =
                crate::http::listener_cancel::ListenerCancellation::new(connection_owner.cloned());
            let mut polling_cancel =
                crate::http::listener_cancel::ListenerCancellation::new(
                    connection_owner.and_then(|_| Cx::current()),
                );
            let mut pending_expectation_flush = None;
            let mut handled_expectation = false;
            let mut shutdown_fut: Option<ShutdownWaitFuture<'_>> =
                self.shutdown_signal.as_ref().map(|signal| {
                    Box::pin(
                        signal.wait_for_phase(crate::server::shutdown::ShutdownPhase::Draining),
                    ) as ShutdownWaitFuture<'_>
                });

            poll_fn(|cx| {
                loop {
                    let owner_cancelled = owner_cancel.poll_cancelled(cx);
                    let polling_cancelled = polling_cancel.poll_cancelled(cx);
                    let stopping = self.should_stop_reading(cx, shutdown_fut.as_mut());
                    if owner_cancelled || polling_cancelled || stopping {
                        return Poll::Ready(ReadOutcome::Shutdown);
                    }

                    if let Some(outcome) = poll_pending_expectation_flush(
                        cx,
                        framed,
                        &mut pending_expectation_flush,
                        handled_expectation,
                    ) {
                        return outcome;
                    }

                    match Pin::new(&mut *framed).poll_next(cx) {
                        Poll::Ready(item) => {
                            return Poll::Ready(ReadOutcome::Read {
                                item,
                                continue_sent: handled_expectation,
                            });
                        }
                        Poll::Pending => {}
                    }

                    if let Some(step) = poll_request_expectation(
                        cx,
                        framed,
                        &mut pending_expectation_flush,
                        &mut handled_expectation,
                    ) {
                        match step {
                            ExpectationStep::ContinueLoop => continue,
                            ExpectationStep::Return(outcome) => {
                                return outcome;
                            }
                        }
                    }

                    return Poll::Pending;
                }
            })
            .await
        };

        if let Some(idle_timeout) = self.config.idle_timeout {
            timeout_with_owner(connection_owner, idle_timeout, read_future)
                .await
                .ok()
        } else {
            Some(read_future.await)
        }
    }

    fn should_stop_reading(
        &self,
        cx: &mut Context<'_>,
        mut shutdown_fut: Option<&mut ShutdownWaitFuture<'_>>,
    ) -> bool {
        Cx::with_current(|current| current.checkpoint().is_err()).unwrap_or(false)
            || self
                .shutdown_signal
                .as_ref()
                .is_some_and(ShutdownSignal::is_shutting_down)
            || shutdown_fut
                .as_mut()
                .is_some_and(|future| future.as_mut().poll(cx).is_ready())
    }

    /// Serve a single connection, processing requests until the connection
    /// closes, an error occurs, or a lifecycle limit is reached.
    ///
    /// Returns the final connection state along with the result.
    pub async fn serve<T>(self, io: T) -> Result<ConnectionState, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.serve_with_peer_addr(io, None).await
    }

    /// Serve a single connection with an optional peer address.
    ///
    /// When provided, the peer address is attached to each request.
    #[allow(clippy::too_many_lines)]
    pub async fn serve_with_peer_addr<T>(
        self,
        io: T,
        peer_addr: Option<SocketAddr>,
    ) -> Result<ConnectionState, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        match self
            .serve_connection_with_peer_addr(io, peer_addr, UpgradeAdmission::Refused)
            .await?
        {
            Http1ServeOutcome::Closed(state) => Ok(state),
            Http1ServeOutcome::Upgraded { .. } => {
                unreachable!("the compatibility serve path never admits an ownership handoff")
            }
        }
    }

    pub(crate) async fn serve_upgradeable_with_peer_addr<T>(
        self,
        io: T,
        peer_addr: Option<SocketAddr>,
    ) -> Result<Http1ServeOutcome<T>, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.serve_connection_with_peer_addr(io, peer_addr, UpgradeAdmission::Any)
            .await
    }

    /// Serves a connection whose transport is not the listener's own TCP
    /// stream: upgrade actions made with [`Http1Upgrade::new_any`] are
    /// admitted, TCP-typed ones refused before the `101`.
    pub(crate) async fn serve_transport_upgradeable_with_peer_addr<T>(
        self,
        io: T,
        peer_addr: Option<SocketAddr>,
    ) -> Result<Http1ServeOutcome<T>, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.serve_connection_with_peer_addr(io, peer_addr, UpgradeAdmission::TransportGeneric)
            .await
    }

    async fn serve_connection_with_peer_addr<T>(
        self,
        io: T,
        peer_addr: Option<SocketAddr>,
        admit_upgrade: UpgradeAdmission,
    ) -> Result<Http1ServeOutcome<T>, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.serve_connection_using(
            io,
            peer_addr,
            admit_upgrade,
            None,
            execute_legacy::<F, Fut, R>,
        )
        .await
    }

    #[allow(clippy::too_many_lines)]
    pub(super) async fn serve_connection_using<T, Execute, Execution>(
        self,
        io: T,
        peer_addr: Option<SocketAddr>,
        admit_upgrade: UpgradeAdmission,
        connection_owner: Option<Cx>,
        execute_request: Execute,
    ) -> Result<Http1ServeOutcome<T>, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
        Execute: Fn(Arc<F>, Request, RequestExecutionConfig) -> Execution + Send + Sync,
        Execution: Future<Output = Result<Option<ServerHopOutcome<Http1Response>>, HttpError>>,
    {
        let codec = Http1Codec::new()
            .max_headers_size(self.config.max_headers_size)
            .max_body_size(self.config.max_body_size);
        // The codec assembles a whole Content-Length body (or chunk) in the
        // read buffer, so the buffer must admit max_headers_size +
        // max_body_size; Framed's default 8 MiB cap would otherwise drop the
        // connection with an io error before the 413 the config promises.
        let max_buffer_len = self
            .config
            .max_headers_size
            .saturating_add(self.config.max_body_size)
            .saturating_add(64 * 1024)
            .max(crate::codec::framed_read::DEFAULT_MAX_BUFFER_LEN);
        let mut framed = Framed::new(io, codec).with_max_buffer_len(max_buffer_len);
        let response_write =
            ResponseWritePolicy::new(self.config.idle_timeout, self.shutdown_signal.as_ref())
                .with_owner(connection_owner.as_ref());
        let mut state = ConnectionState::new(buffered_connection_now(connection_owner.as_ref()));

        loop {
            state.phase = ConnectionPhase::Idle;

            if self
                .shutdown_signal
                .as_ref()
                .is_some_and(ShutdownSignal::is_shutting_down)
            {
                state.phase = ConnectionPhase::Closing;
                break;
            }

            let owner_cancelled = connection_owner
                .as_ref()
                .is_some_and(|cx| cx.checkpoint().is_err());
            let polling_cancelled =
                Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false);
            if owner_cancelled || polling_cancelled {
                state.phase = ConnectionPhase::Closing;
                break;
            }

            // Check request limit before reading next request
            if state.exceeded_request_limit(self.config.max_requests_per_connection) {
                state.phase = ConnectionPhase::Closing;
                break;
            }

            let now = buffered_connection_now(connection_owner.as_ref());

            // Check idle timeout
            if state.exceeded_idle_timeout(self.config.idle_timeout, now) {
                state.phase = ConnectionPhase::Closing;
                break;
            }

            state.phase = ConnectionPhase::Reading;

            let Some(read_outcome) = self
                .read_next(&mut framed, &state, connection_owner.as_ref())
                .await
            else {
                state.phase = ConnectionPhase::Closing;
                break;
            };

            let (req, continue_sent) = match read_outcome {
                ReadOutcome::ExpectationRejected => {
                    state.requests_served += 1;
                    state.last_request_at = buffered_connection_now(connection_owner.as_ref());
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
                ReadOutcome::Shutdown => {
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
                ReadOutcome::Read {
                    item,
                    continue_sent,
                } => (item, continue_sent),
            };

            // Read next request
            let mut req = match req {
                Some(Ok(req)) => req,
                Some(Err(error)) => {
                    // br-asupersync-hw83se: a rejected request *head* owes the
                    // client the status the configured limits promise
                    // (400 / 413 / 414 / 431 / 505) with `Connection: close`
                    // before the socket closes. Answering with a bare
                    // `return Err` dropped the connection silently —
                    // indistinguishable from a transport fault — and the
                    // 413/431 that `max_headers_size` / `max_body_size`
                    // advertise never reached the wire. Errors with no
                    // meaningful client-facing status (transport I/O,
                    // body-stream lifecycle) still abandon the connection.
                    let Some(reject) = head_parse_failure_response(&error) else {
                        return Err(error);
                    };
                    state.phase = ConnectionPhase::Writing;
                    framed.send(reject)?;
                    response_write.flush_framed(&mut framed).await?;
                    state.requests_served += 1;
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
                None => {
                    // Clean EOF - connection closed by client
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
            };
            req.peer_addr = peer_addr;

            // br-asupersync-server-stack-hardening-eeexl1.2 (D2.2b): the
            // request is now committed — count it as in flight until its
            // response is flushed or the connection abandons it. The guard
            // is loop-iteration scoped so every exit path (including early
            // breaks and error returns) releases it via Drop.
            let _in_flight = InFlightRequestGuard::acquire(self.in_flight_requests.as_ref());

            // br-asupersync-t9yqht: enforce the allowed-hosts allow-list
            // BEFORE the handler runs. A request whose well-formed Host
            // isn't on the list gets 421 Misdirected Request; a missing
            // (HTTP/1.1), duplicate or unparseable Host gets 400 Bad
            // Request (RFC 9112 §3.2). Either way the connection closes — the
            // handler never sees the request, eliminating the host-
            // injection attack surface for absolute-URL emission /
            // OAuth redirect_uri / cache-key computation.
            if let Err(rejection) =
                validate_host_header(&req.headers, req.version, &self.config.allowed_hosts)
            {
                state.phase = ConnectionPhase::Writing;
                let reject_resp = Response {
                    status: rejection.status(),
                    reason: rejection.reason().to_string(),
                    version: req.version,
                    headers: vec![
                        (
                            "content-type".to_string(),
                            "text/plain; charset=utf-8".to_string(),
                        ),
                        ("connection".to_string(), "close".to_string()),
                    ],
                    body: rejection.body().into_bytes(),
                    trailers: Vec::new(),
                };
                framed.send(reject_resp)?;
                response_write.flush_framed(&mut framed).await?;
                state.requests_served += 1;
                state.phase = ConnectionPhase::Closing;
                break;
            }

            let expectation_action = classify_expectation(&req);
            if expectation_action == ExpectationAction::Reject {
                state.phase = ConnectionPhase::Writing;
                let reject = expectation_response(req.version, ExpectationAction::Reject)
                    .expect("reject expectation should build a response");
                framed.send(reject)?;
                response_write.flush_framed(&mut framed).await?;
                state.requests_served += 1;
                state.last_request_at = Cx::current()
                    .and_then(|cx| cx.timer_driver())
                    .map_or_else(wall_now, |timer| timer.now());
                state.phase = ConnectionPhase::Closing;
                break;
            }
            if expectation_action == ExpectationAction::Continue
                && request_expects_body(&req)
                && !continue_sent
            {
                state.phase = ConnectionPhase::Writing;
                let interim = expectation_response(req.version, ExpectationAction::Continue)
                    .expect("continue expectation should build a response");
                framed.send(interim)?;
                response_write.flush_framed(&mut framed).await?;
            }

            // Determine if we should close after this request
            let close_after = should_close_connection(&req, &self.config, &state);
            let request_version = req.version;
            let request_method = req.method.clone();

            state.phase = ConnectionPhase::Processing;

            // br-asupersync-server-stack-hardening-eeexl1.1.1: run the
            // handler inside a server-hop request region. The request
            // budget is the connection budget tightened by the configured
            // request timeout and the (opt-in, cap-clamped) client
            // `Request-Timeout` header; the region bridges connection
            // cancel -> request cancel and enforces the deadline with a
            // bounded protocol drain. When no runtime is installed on this
            // thread, the legacy direct-call path is preserved unchanged.
            let request_now = buffered_connection_now(connection_owner.as_ref());
            let conn_cx = connection_owner.clone().or_else(Cx::current);
            let base_budget = conn_cx.as_ref().map_or(Budget::INFINITE, Cx::budget);
            let header_timeout = parse_request_timeout_header(&req.headers);
            let (request_budget, budget_source) = derive_request_budget(
                base_budget,
                request_now,
                self.config.request_timeout,
                header_timeout,
                self.config.request_timeout_header_cap,
            );

            // Only an upgrade-aware listener checks a handoff against its
            // request, and a request with a body or trailers can never hand
            // off. Keep a copy just for that case: copying every request
            // cost a copy of its whole body, up to max_body_size.
            let upgrade_request = (admit_upgrade != UpgradeAdmission::Refused
                && req.body.is_empty()
                && req.trailers.is_empty())
            .then(|| req.clone());
            let mut forced_close = false;
            // The legacy executor retains connection-scoped spawn behavior.
            // Explicit owned serving instead admits and drains a real request
            // subtree. Both paths share this codec, response and reuse policy.
            let hop = execute_request(
                Arc::clone(&self.handler),
                req,
                RequestExecutionConfig {
                    budget: request_budget,
                    started_at: request_now,
                    source: budget_source,
                    drain_grace: self.config.request_drain_grace,
                    connection: conn_cx,
                    shutdown: self.shutdown_signal.clone(),
                },
            )
            .await?;
            let output = match hop {
                None => {
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
                Some(ServerHopOutcome::Ok(response)) => response,
                Some(ServerHopOutcome::Cancelled | ServerHopOutcome::ConnectionLost) => {
                    state.requests_served += 1;
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
                Some(ServerHopOutcome::Panicked(_)) => {
                    forced_close = true;
                    Http1Response::new(hop_error_response(
                        request_version,
                        500,
                        "Internal Server Error",
                    ))
                }
                Some(ServerHopOutcome::DeadlineExceeded) => {
                    Http1Response::new(hop_error_response(
                        request_version,
                        503,
                        HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC,
                    ))
                }
            };

            let Http1Response {
                response: mut resp,
                upgrade,
            } = output;

            if request_method == Method::Head {
                suppress_response_body_for_head(&mut resp);
            } else if declared_length_mismatches_body(&resp) {
                resp = hop_error_response(request_version, 500, "Internal Server Error");
                forced_close = true;
            }

            // br-asupersync-server-stack-hardening-eeexl1.2 (D2.2b): once the
            // drain has begun, every in-flight response advertises
            // `Connection: close` and the keep-alive loop ends after this
            // response — idle keep-alive connections already exit at the top
            // of the loop, and this closes the in-flight half of the
            // keep-alive coordination contract.
            let draining = self
                .shutdown_signal
                .as_ref()
                .is_some_and(ShutdownSignal::is_shutting_down);

            let upgrade = match upgrade {
                Some(upgrade) => {
                    if admit_upgrade == UpgradeAdmission::Refused {
                        return Err(invalid_upgrade_error(
                            "HTTP/1 upgrade action requires an upgrade-aware listener",
                        ));
                    }
                    if admit_upgrade == UpgradeAdmission::TransportGeneric
                        && !upgrade.runs_on_any_transport()
                    {
                        warn!(
                            peer = ?peer_addr,
                            "TCP-typed HTTP/1 upgrade refused on transport; use Http1Upgrade::new_any (WebSocketUpgrade::on_upgrade_any)"
                        );
                        resp = hop_error_response(
                            request_version,
                            500,
                            "this transport runs only HTTP/1 upgrade actions made with \
                             Http1Upgrade::new_any (WebSocketUpgrade::on_upgrade_any)",
                        );
                        forced_close = true;
                        None
                    } else if draining {
                        return Err(invalid_upgrade_error(
                            "HTTP/1 upgrade refused after listener drain began",
                        ));
                    } else {
                        let Some(upgrade_request) = upgrade_request.as_ref() else {
                            // Same refusals, in the same order, as the check below.
                            if request_version != Version::Http11 || request_method != Method::Get {
                                return Err(invalid_upgrade_error(
                                    "WebSocket handoff requires an HTTP/1.1 GET request",
                                ));
                            }
                            return Err(invalid_upgrade_error(
                                "WebSocket handoff request must not carry a body or trailers",
                            ));
                        };
                        validate_upgrade_handoff(upgrade_request, &resp, &upgrade)?;
                        Some(upgrade)
                    }
                }
                None => None,
            };

            // A bare 101 remains an ordinary response but closes the HTTP
            // parser after it is flushed. Only an explicit action may acquire
            // the transport and its read-ahead bytes.
            let close_after = if upgrade.is_some() {
                false
            } else {
                let bare_switch = resp.status == 101;
                finalize_response_persistence(
                    request_version,
                    &mut resp,
                    close_after || forced_close || draining || bare_switch,
                )
            };

            state.phase = ConnectionPhase::Writing;

            // Write response
            framed.send(resp)?;
            // `Framed::send` only encodes into the internal write buffer; flush to the socket.
            response_write.flush_framed(&mut framed).await?;

            state.requests_served += 1;
            state.last_request_at = buffered_connection_now(connection_owner.as_ref());

            if let Some(upgrade) = upgrade {
                let parts = framed.into_parts();
                if !parts.write_buf.is_empty() {
                    return Err(invalid_upgrade_error(
                        "HTTP/1 upgrade flush left pending response bytes",
                    ));
                }
                return Ok(Http1ServeOutcome::Upgraded {
                    io: parts.inner,
                    read_ahead: parts.read_buf,
                    upgrade,
                });
            }

            if close_after {
                state.phase = ConnectionPhase::Closing;
                break;
            }
        }

        // Gracefully shutdown the connection
        let mut io = framed.into_inner();
        let _ = response_write.close_transport(&mut io).await;

        Ok(Http1ServeOutcome::Closed(state))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<F, Fut, R> Http1Server<F>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp1Response,
{
    /// Serve buffered HTTP/1.1 requests in actual runtime-owned child regions.
    ///
    /// Each admitted handler runs in its own task and region. Its ambient Cx
    /// carries that admitted identity, so tasks it spawns remain in the request
    /// subtree. Before writing a response or reusing the connection, serving
    /// cancels remaining descendants and awaits their retirement and finalizers.
    ///
    /// The supplied context owns the request regions. Its cancellation, the
    /// polling task's cancellation, and listener force-close request cleanup;
    /// serving continues to drain admitted work. Handler drain retains the
    /// configured request timeout and request_drain_grace. Non-cooperative
    /// descendants can still delay quiescence; they are never called drained
    /// merely because a timer elapsed.
    ///
    /// Dropping the serving future closes its transport and requests child
    /// cleanup through the runtime backstop. Continue polling, or drain the
    /// owning region, to observe actual quiescence.
    ///
    /// Existing serve methods retain their legacy request-context behavior.
    /// This opt-in requires a native runtime gateway and timer and accepts only
    /// owned handler factories/futures. Bodies remain bounded and buffered by
    /// Http1Config; this is not the streaming-body API.
    pub async fn serve_owned<T>(self, cx: &Cx, io: T) -> Result<ConnectionState, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.serve_owned_with_peer_addr(cx, io, None).await
    }

    /// Like serve_owned, attaching an optional peer address to every request.
    pub async fn serve_owned_with_peer_addr<T>(
        self,
        cx: &Cx,
        io: T,
        peer_addr: Option<SocketAddr>,
    ) -> Result<ConnectionState, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let executor = OwnedRequests::new(cx.clone())?;
        match self
            .serve_connection_using(
                io,
                peer_addr,
                UpgradeAdmission::Refused,
                Some(cx.clone()),
                move |handler, request, config| executor.clone().execute(handler, request, config),
            )
            .await?
        {
            Http1ServeOutcome::Closed(state) => Ok(state),
            Http1ServeOutcome::Upgraded { .. } => {
                unreachable!("owned single-connection serving does not admit upgrades")
            }
        }
    }
}

fn buffered_connection_now(owner: Option<&Cx>) -> crate::types::Time {
    owner
        .cloned()
        .or_else(Cx::current)
        .and_then(|cx| cx.timer_driver())
        .map_or_else(wall_now, |timer| timer.now())
}

/// Bound explicit-owner I/O to that owner's clock without replacing the
/// actual polling task's context or treating cancellation as elapsed time.
async fn timeout_with_owner<F: Future>(
    owner: Option<&Cx>,
    duration: Duration,
    future: F,
) -> Result<F::Output, crate::time::Elapsed> {
    let Some(driver) = owner.and_then(Cx::timer_driver) else {
        return timeout(buffered_connection_now(None), duration, future).await;
    };
    let deadline = driver.now() + duration;
    let mut future = std::pin::pin!(future);
    let mut deadline_wait = std::pin::pin!(crate::time::Sleep::with_timer_driver(
        deadline,
        driver.clone(),
    ));
    poll_fn(|task| {
        if driver.now() > deadline {
            return Poll::Ready(Err(crate::time::Elapsed::new(deadline)));
        }
        if let Poll::Ready(value) = future.as_mut().poll(task) {
            return Poll::Ready(Ok(value));
        }
        deadline_wait
            .as_mut()
            .poll_deadline(task)
            .map(|()| Err(crate::time::Elapsed::new(deadline)))
    })
    .await
}

/// HTTP/1.1 server that publishes a validated request head before reading its body.
///
/// The handler and wire-body driver are polled concurrently. Request bytes flow
/// through independently bounded frame and byte queues, so a slow handler
/// applies backpressure to the socket. If the handler returns without consuming
/// the body, the driver performs a bounded framing-aware drain; the connection
/// is reusable only after synchronized body EOF.
pub struct Http1StreamingServer<F> {
    handler: F,
    config: Http1StreamingConfig,
    shutdown_signal: Option<ShutdownSignal>,
    in_flight_requests: Option<Arc<AtomicUsize>>,
}

/// Head-only admission is complete before either executor creates a body.
struct StreamingRequestExecution {
    head: RequestHead,
    body_kind: BodyKind,
    peer_addr: Option<SocketAddr>,
    config: Arc<Http1StreamingConfig>,
    request: RequestExecutionConfig,
}

enum StreamingRequestOutcome {
    Complete {
        hop: ServerHopOutcome<Response>,
        // An interrupted exchange cannot claim synchronized body EOF.
        drain: Option<IncomingBodyDrainProgress>,
    },
    BodyFailed(IncomingBodyError),
    Closed,
}

impl StreamingRequestOutcome {
    fn from_joined(
        joined: Result<
            Option<(ServerHopOutcome<Response>, IncomingRequestBodyWriter)>,
            IncomingBodyError,
        >,
    ) -> Self {
        match joined {
            Ok(Some((hop, writer))) => Self::Complete {
                hop,
                drain: Some(writer.drain_progress()),
            },
            Ok(None) => Self::Closed,
            Err(error) => Self::BodyFailed(error),
        }
    }
}

async fn execute_legacy_streaming<F, Fut, T>(
    handler: Arc<F>,
    mut io: T,
    mut read_buffer: BytesMut,
    execution: StreamingRequestExecution,
) -> Result<(T, BytesMut, StreamingRequestOutcome), HttpError>
where
    F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync,
    Fut: Future<Output = Response> + Send,
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let cx = execution
        .request
        .connection
        .as_ref()
        .expect("streaming HTTP/1 connection context");
    let region = ServerRequestRegion::mint_from_connection(
        "h1",
        execution.request.budget,
        execution.request.started_at,
        cx,
    );
    let request_cx = region.cx().clone();
    let body_cx = request_cx.clone();
    let (writer, body) = IncomingRequestBody::channel_with_limits(
        &request_cx,
        execution.body_kind,
        execution.config.incoming_body_frame_capacity,
        execution.config.incoming_body_queued_bytes,
    );
    let request = StreamingServerRequest {
        head: execution.head,
        peer_addr: execution.peer_addr,
        body,
    };
    let handler = race_force_close(
        execution.request.shutdown.as_ref(),
        region.run_with_protocol_drain(
            execution.request.source,
            Some(cx.clone()),
            execution.request.drain_grace,
            handler(request_cx, request),
        ),
    );
    let body_driver = drive_incoming_body(
        &body_cx,
        &mut io,
        &mut read_buffer,
        writer.max_body_size(u64::try_from(execution.config.max_body_size).unwrap_or(u64::MAX)),
        &execution.config,
    );
    let joined = join_streaming_handler_and_body(
        cx,
        handler,
        body_driver,
        &execution.config,
        execution.request.shutdown.as_ref(),
    )
    .await;
    Ok((io, read_buffer, StreamingRequestOutcome::from_joined(joined)))
}

impl<F> Http1StreamingServer<F> {
    /// Creates an HTTP/1 server whose handler returns a supervised framed response.
    ///
    /// This is additive to [`Self::new`] and [`Self::new_sse`]. The server owns
    /// both the produced body and its producer until terminal framing or an
    /// error closes the connection.
    pub fn new_produced(handler: F) -> Self {
        Self::with_config_produced(handler, Http1StreamingConfig::default())
    }

    /// Creates a produced-body HTTP/1 server with explicit connection limits.
    pub fn with_config_produced(handler: F, config: impl Into<Http1StreamingConfig>) -> Self {
        Self {
            handler,
            config: config.into(),
            shutdown_signal: None,
            in_flight_requests: None,
        }
    }

    /// Creates an HTTP/1 server whose handler returns one live SSE response.
    ///
    /// This is additive to [`Self::new`]: buffered [`Response`] handlers keep
    /// their existing API and behavior.
    pub fn new_sse(handler: F) -> Self {
        Self::with_config_sse(handler, Http1StreamingConfig::default())
    }

    /// Creates a live-SSE HTTP/1 server with explicit connection limits.
    pub fn with_config_sse(handler: F, config: impl Into<Http1StreamingConfig>) -> Self {
        Self {
            handler,
            config: config.into(),
            shutdown_signal: None,
            in_flight_requests: None,
        }
    }

    /// Attaches graceful shutdown coordination.
    #[must_use]
    pub fn with_shutdown_signal(mut self, signal: ShutdownSignal) -> Self {
        self.shutdown_signal = Some(signal);
        self
    }

    /// Attaches the listener-shared in-flight request counter.
    #[must_use]
    pub fn with_in_flight_requests(mut self, counter: Arc<AtomicUsize>) -> Self {
        self.in_flight_requests = Some(counter);
        self
    }
}

impl<F, Fut> Http1StreamingServer<F>
where
    F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync,
    Fut: Future<Output = Response> + Send,
{
    /// Creates a streaming HTTP/1 server with default connection limits.
    pub fn new(handler: F) -> Self {
        Self::with_config(handler, Http1StreamingConfig::default())
    }

    /// Creates a streaming HTTP/1 server with explicit connection limits.
    pub fn with_config(handler: F, config: impl Into<Http1StreamingConfig>) -> Self {
        Self {
            handler,
            config: config.into(),
            shutdown_signal: None,
            in_flight_requests: None,
        }
    }

    /// Serves one streaming HTTP/1 connection under an explicit capability context.
    pub async fn serve<T>(self, cx: &Cx, io: T) -> Result<ConnectionState, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.serve_with_peer_addr(cx, io, None).await
    }

    /// Serves one streaming HTTP/1 connection and records its peer address.
    pub async fn serve_with_peer_addr<T>(
        self,
        cx: &Cx,
        io: T,
        peer_addr: Option<SocketAddr>,
    ) -> Result<ConnectionState, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.serve_connection_using(cx, io, peer_addr, execute_legacy_streaming::<F, Fut, T>)
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn serve_connection_using<T, Execute, Execution>(
        self,
        cx: &Cx,
        mut io: T,
        peer_addr: Option<SocketAddr>,
        execute: Execute,
    ) -> Result<ConnectionState, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
        Execute: Fn(Arc<F>, T, BytesMut, StreamingRequestExecution) -> Execution,
        Execution: Future<Output = Result<(T, BytesMut, StreamingRequestOutcome), HttpError>>,
    {
        let handler = Arc::new(self.handler);
        let execution_config = Arc::new(self.config.clone());
        let mut read_buffer = BytesMut::with_capacity(8192);
        let mut state = ConnectionState::new(connection_now(cx));
        let response_write =
            ResponseWritePolicy::new(self.config.idle_timeout, self.shutdown_signal.as_ref())
                .with_owner(Some(cx));

        loop {
            state.phase = ConnectionPhase::Idle;
            if cx.checkpoint().is_err()
                || self
                    .shutdown_signal
                    .as_ref()
                    .is_some_and(ShutdownSignal::is_shutting_down)
                || state.exceeded_request_limit(self.config.max_requests_per_connection)
                || state.exceeded_idle_timeout(self.config.idle_timeout, connection_now(cx))
            {
                state.phase = ConnectionPhase::Closing;
                break;
            }

            state.phase = ConnectionPhase::Reading;
            let head_and_body = match read_streaming_request_head(
                cx,
                &mut io,
                &mut read_buffer,
                &self.config,
                self.shutdown_signal.as_ref(),
            )
            .await
            {
                Ok(value) => value,
                Err(error) => {
                    // br-asupersync-hw83se: write the rejected head's status
                    // (see `head_parse_failure_response`) before closing,
                    // instead of dropping the streaming connection silently.
                    let Some(response) = head_parse_failure_response(&error) else {
                        return Err(error);
                    };
                    state.phase = ConnectionPhase::Writing;
                    response_write
                        .write_streaming_response(cx, &mut io, response)
                        .await?;
                    state.requests_served += 1;
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
            };
            let Some((head, body_kind)) = head_and_body else {
                state.phase = ConnectionPhase::Closing;
                break;
            };
            let _in_flight = InFlightRequestGuard::acquire(self.in_flight_requests.as_ref());

            if let Err(rejection) =
                validate_host_header(&head.headers, head.version, &self.config.allowed_hosts)
            {
                let response = Response {
                    status: rejection.status(),
                    reason: rejection.reason().to_string(),
                    version: head.version,
                    headers: vec![
                        (
                            "content-type".to_owned(),
                            "text/plain; charset=utf-8".to_owned(),
                        ),
                        ("connection".to_owned(), "close".to_owned()),
                    ],
                    body: rejection.body().into_bytes(),
                    trailers: Vec::new(),
                };
                state.phase = ConnectionPhase::Writing;
                response_write.write_streaming_response(cx, &mut io, response).await?;
                state.requests_served += 1;
                state.phase = ConnectionPhase::Closing;
                break;
            }

            let expectation = classify_expectation_from_parts(head.version, &head.headers);
            if expectation == ExpectationAction::Reject {
                let response = expectation_response(head.version, expectation)
                    .expect("rejected expectation must have a response");
                state.phase = ConnectionPhase::Writing;
                response_write.write_streaming_response(cx, &mut io, response).await?;
                state.requests_served += 1;
                state.phase = ConnectionPhase::Closing;
                break;
            }
            if expectation == ExpectationAction::Continue && !body_kind.is_empty() {
                let response = expectation_response(head.version, expectation)
                    .expect("100-continue expectation must have a response");
                state.phase = ConnectionPhase::Writing;
                response_write.write_streaming_response(cx, &mut io, response).await?;
            }

            let close_after =
                should_close_connection_parts(head.version, &head.headers, &self.config, &state);
            let request_version = head.version;
            let request_method = head.method.clone();
            let request_now = connection_now(cx);
            let (request_budget, budget_source) = derive_request_budget(
                cx.budget(),
                request_now,
                self.config.request_timeout,
                parse_request_timeout_header(&head.headers),
                self.config.request_timeout_header_cap,
            );
            state.phase = ConnectionPhase::Processing;
            let (returned_io, returned_buffer, outcome) = execute(
                Arc::clone(&handler),
                io,
                read_buffer,
                StreamingRequestExecution {
                    head,
                    body_kind,
                    peer_addr,
                    config: Arc::clone(&execution_config),
                    request: RequestExecutionConfig {
                        budget: request_budget,
                        started_at: request_now,
                        source: budget_source,
                        drain_grace: self.config.request_drain_grace,
                        connection: Some(cx.clone()),
                        shutdown: self.shutdown_signal.clone(),
                    },
                },
            )
            .await?;
            io = returned_io;
            read_buffer = returned_buffer;
            let (hop, drain) = match outcome {
                StreamingRequestOutcome::Complete { hop, drain } => (hop, drain),
                StreamingRequestOutcome::Closed => {
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
                StreamingRequestOutcome::BodyFailed(body_error) => {
                    record_incoming_body_failure(&body_error);
                    // br-asupersync-hw83se: incoming_body_failure_response maps
                    // DrainLimitExceeded to None; deliver an explicit 413 +
                    // close for it instead of dropping the client's response.
                    // Genuinely client-gone errors (ClientAborted /
                    // ConsumerDropped) still write nothing.
                    let refusal = incoming_body_failure_response(request_version, &body_error)
                        .or_else(|| {
                            matches!(body_error, IncomingBodyError::DrainLimitExceeded { .. }).then(
                                || {
                                    hop_error_response(
                                        request_version,
                                        413,
                                        "[ASUP-E505] request body exceeds the configured limit",
                                    )
                                },
                            )
                        });
                    if let Some(mut response) = refusal {
                        add_connection_close(&mut response);
                        if request_method == Method::Head {
                            suppress_response_body_for_head(&mut response);
                        }
                        state.phase = ConnectionPhase::Writing;
                        response_write
                            .write_streaming_response(cx, &mut io, response)
                            .await?;
                        state.requests_served += 1;
                    }
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
            };
            let mut forced_close = false;
            let mut response = match hop {
                ServerHopOutcome::Ok(response) => response,
                ServerHopOutcome::Cancelled | ServerHopOutcome::ConnectionLost => {
                    state.requests_served += 1;
                    state.phase = ConnectionPhase::Closing;
                    break;
                }
                ServerHopOutcome::Panicked(_) => {
                    forced_close = true;
                    hop_error_response(request_version, 500, "Internal Server Error")
                }
                ServerHopOutcome::DeadlineExceeded => {
                    hop_error_response(request_version, 503, HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC)
                }
            };
            // br-asupersync-hw83se: an unread-body drain overrun still owes the
            // client its already-computed response. Deliver it with Connection:
            // close (force close) rather than dropping the response and closing
            // silently (RFC 9112 §9.6). The connection cannot be reused — the
            // undrained request body would corrupt the next request — so this is
            // a forced close, not keep-alive.
            if drain.is_none_or(|progress| validate_unread_drain(progress, &self.config).is_err()) {
                forced_close = true;
            }
            if request_method == Method::Head {
                suppress_response_body_for_head(&mut response);
            } else if declared_length_mismatches_body(&response) {
                response = hop_error_response(request_version, 500, "Internal Server Error");
                forced_close = true;
            }
            let draining = self
                .shutdown_signal
                .as_ref()
                .is_some_and(ShutdownSignal::is_shutting_down);
            let close_after = finalize_response_persistence(
                request_version,
                &mut response,
                close_after || forced_close || draining,
            );

            state.phase = ConnectionPhase::Writing;
            response_write
                .write_streaming_response(cx, &mut io, response)
                .await?;
            state.requests_served += 1;
            state.last_request_at = connection_now(cx);
            if close_after {
                state.phase = ConnectionPhase::Closing;
                break;
            }
        }

        let _ = response_write.close_transport(&mut io).await;
        Ok(state)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<F, Fut> Http1StreamingServer<F>
where
    F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    /// Serves streaming requests in real request tasks and child regions.
    ///
    /// The complete request head is admitted before the body channel is
    /// created. Both the handler and the incoming-body driver run under the
    /// admitted task's capability context; request bytes remain streamed
    /// through the configured bounded queues. Responses and connection reuse
    /// wait for actual task retirement, descendant cleanup, and finalizers.
    /// Owner cancellation and force-close request that cleanup and keep
    /// joining it. Dropping the serving future requests the runtime backstop;
    /// the enclosing region's close remains the quiescence barrier.
    ///
    /// The transport moves into the request task while that exchange runs,
    /// so this additive entry point requires owned, `'static` transport and
    /// handler state. [`Self::serve`] retains borrowed-state compatibility.
    /// This API serves buffered responses; produced and SSE responses retain
    /// their separately named entry points.
    pub async fn serve_owned<T>(self, cx: &Cx, io: T) -> Result<ConnectionState, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.serve_owned_with_peer_addr(cx, io, None).await
    }

    /// Serves scheduler-owned streaming requests and records the peer address.
    pub async fn serve_owned_with_peer_addr<T>(
        self,
        cx: &Cx,
        io: T,
        peer_addr: Option<SocketAddr>,
    ) -> Result<ConnectionState, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let owned = OwnedRequests::new(cx.clone())?;
        self.serve_connection_using(cx, io, peer_addr, move |handler, io, buffer, execution| {
            owned.clone().execute_streaming(handler, io, buffer, execution)
        })
        .await
    }
}

impl<F> Http1StreamingServer<F> {
    /// Serves one live SSE response under an explicit capability context.
    ///
    /// The first live-response slice intentionally closes the connection after
    /// the response. That fail-closed policy prevents a producer failure after
    /// the committed head from being confused with a clean reusable HTTP/1
    /// message boundary.
    pub async fn serve_sse<Fut, S, T>(self, cx: &Cx, io: T) -> Result<ConnectionState, HttpError>
    where
        F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync,
        Fut: Future<Output = Http1SseResponse<S>> + Send,
        S: StreamingSseSource + Send + 'static,
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.serve_sse_with_peer_addr(cx, io, None).await
    }

    /// Serves one live SSE response and records its peer address.
    ///
    /// Handler execution, request-body synchronization, SSE production, body
    /// writes, and the clean terminating chunk all remain inside the same
    /// [`ServerRequestRegion`] lifecycle. A source error, panic, cancellation,
    /// or transport failure after the response head closes the connection
    /// without emitting a successful chunk terminator.
    #[allow(clippy::too_many_lines)]
    pub async fn serve_sse_with_peer_addr<Fut, S, T>(
        self,
        cx: &Cx,
        io: T,
        peer_addr: Option<SocketAddr>,
    ) -> Result<ConnectionState, HttpError>
    where
        F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync,
        Fut: Future<Output = Http1SseResponse<S>> + Send,
        S: StreamingSseSource + Send + 'static,
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let handler = self.handler;
        let adapted = move |request_cx: Cx, request: StreamingServerRequest| {
            let response = handler(request_cx.clone(), request);
            async move {
                let (stream, capacity) = response.await.into_parts();
                // One serialized event is one produced frame, so the frame
                // cap must admit the stream's own event bound; the channel's
                // 64 KiB default would end the stream without a terminator
                // on the first larger event.
                let max_frame_bytes = std::num::NonZeroUsize::new(stream.event_bytes_limit())
                    .unwrap_or(std::num::NonZeroUsize::MIN);
                let guard = LiveSseCancelGuard::new(stream, request_cx);
                let mut response = Http1ProducedResponse::chunked_with_max_frame_bytes(
                    capacity,
                    max_frame_bytes,
                    200,
                    default_reason(200),
                    move |_producer_cx, sender| produce_live_sse(guard, sender),
                );
                for (name, value) in StreamingSse::<VecSseSource>::headers() {
                    response = response.with_header(name, value);
                }
                response
            }
        };
        serve_produced_connection(
            cx,
            io,
            peer_addr,
            adapted,
            self.config,
            self.shutdown_signal,
            self.in_flight_requests,
            ProducedResponsePolicy::Sse,
        )
        .await
    }

    /// Serves one supervised, generic HTTP/1.1 response.
    pub async fn serve_produced<Fut, T>(self, cx: &Cx, io: T) -> Result<ConnectionState, HttpError>
    where
        F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync,
        Fut: Future<Output = Http1ProducedResponse> + Send,
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.serve_produced_with_peer_addr(cx, io, None).await
    }

    /// Serves one supervised response and records its peer address.
    ///
    /// The response head, bounded body channel, and producer are driven inside
    /// the request region. A producer error drains frames already committed to
    /// the channel, while a transport error cancels and boundedly drains the
    /// producer. Generic terminal trailers are serialized exactly once.
    pub async fn serve_produced_with_peer_addr<Fut, T>(
        self,
        cx: &Cx,
        io: T,
        peer_addr: Option<SocketAddr>,
    ) -> Result<ConnectionState, HttpError>
    where
        F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync,
        Fut: Future<Output = Http1ProducedResponse> + Send,
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        serve_produced_connection(
            cx,
            io,
            peer_addr,
            self.handler,
            self.config,
            self.shutdown_signal,
            self.in_flight_requests,
            ProducedResponsePolicy::Generic,
        )
        .await
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProducedResponsePolicy {
    Sse,
    Generic,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_produced_connection<F, Fut, T>(
    cx: &Cx,
    mut io: T,
    peer_addr: Option<SocketAddr>,
    handler: F,
    config: Http1StreamingConfig,
    shutdown_signal: Option<ShutdownSignal>,
    in_flight_requests: Option<Arc<AtomicUsize>>,
    policy: ProducedResponsePolicy,
) -> Result<ConnectionState, HttpError>
where
    F: Fn(Cx, StreamingServerRequest) -> Fut + Send + Sync,
    Fut: Future<Output = Http1ProducedResponse> + Send,
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut read_buffer = BytesMut::with_capacity(8192);
    let mut state = ConnectionState::new(connection_now(cx));
    let response_write = ResponseWritePolicy::new(config.idle_timeout, shutdown_signal.as_ref());

    if cx.checkpoint().is_err()
        || shutdown_signal
            .as_ref()
            .is_some_and(ShutdownSignal::is_shutting_down)
        || state.exceeded_request_limit(config.max_requests_per_connection)
        || state.exceeded_idle_timeout(config.idle_timeout, connection_now(cx))
    {
        state.phase = ConnectionPhase::Closing;
        let _ = response_write.close_transport(&mut io).await;
        return Ok(state);
    }

    state.phase = ConnectionPhase::Reading;
    let head_and_body = match read_streaming_request_head(
        cx,
        &mut io,
        &mut read_buffer,
        &config,
        shutdown_signal.as_ref(),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            // br-asupersync-hw83se: write the rejected head's status (see
            // `head_parse_failure_response`) before closing, instead of
            // dropping the produced/streaming connection silently.
            let Some(response) = head_parse_failure_response(&error) else {
                return Err(error);
            };
            state.phase = ConnectionPhase::Writing;
            response_write
                .write_streaming_response(cx, &mut io, response)
                .await?;
            state.requests_served += 1;
            state.phase = ConnectionPhase::Closing;
            let _ = response_write.close_transport(&mut io).await;
            return Ok(state);
        }
    };
    let Some((head, body_kind)) = head_and_body else {
        state.phase = ConnectionPhase::Closing;
        let _ = response_write.close_transport(&mut io).await;
        return Ok(state);
    };
    let early_request_method = head.method.clone();
    let _in_flight = InFlightRequestGuard::acquire(in_flight_requests.as_ref());

    if let Err(rejection) = validate_host_header(&head.headers, head.version, &config.allowed_hosts)
    {
        let mut response = Response {
            status: rejection.status(),
            reason: rejection.reason().to_string(),
            version: head.version,
            headers: vec![
                (
                    "content-type".to_owned(),
                    "text/plain; charset=utf-8".to_owned(),
                ),
                ("connection".to_owned(), "close".to_owned()),
            ],
            body: rejection.body().into_bytes(),
            trailers: Vec::new(),
        };
        if early_request_method == Method::Head {
            suppress_response_body_for_head(&mut response);
        }
        state.phase = ConnectionPhase::Writing;
        response_write.write_streaming_response(cx, &mut io, response).await?;
        state.requests_served = 1;
        state.phase = ConnectionPhase::Closing;
        let _ = response_write.close_transport(&mut io).await;
        return Ok(state);
    }

    let expectation = classify_expectation_from_parts(head.version, &head.headers);
    if expectation == ExpectationAction::Reject {
        let mut response = expectation_response(head.version, expectation)
            .expect("rejected expectation must have a response");
        add_connection_close(&mut response);
        if early_request_method == Method::Head {
            suppress_response_body_for_head(&mut response);
        }
        state.phase = ConnectionPhase::Writing;
        response_write.write_streaming_response(cx, &mut io, response).await?;
        state.requests_served = 1;
        state.phase = ConnectionPhase::Closing;
        let _ = response_write.close_transport(&mut io).await;
        return Ok(state);
    }
    if expectation == ExpectationAction::Continue && !body_kind.is_empty() {
        let response = expectation_response(head.version, expectation)
            .expect("100-continue expectation must have a response");
        state.phase = ConnectionPhase::Writing;
        response_write.write_streaming_response(cx, &mut io, response).await?;
    }

    let request_version = head.version;
    let request_method = head.method.clone();
    let request_now = connection_now(cx);
    let (request_budget, budget_source) = derive_request_budget(
        cx.budget(),
        request_now,
        config.request_timeout,
        parse_request_timeout_header(&head.headers),
        config.request_timeout_header_cap,
    );
    let region_name = match policy {
        ProducedResponsePolicy::Sse => "h1-sse",
        ProducedResponsePolicy::Generic => "h1-produced",
    };
    let region =
        ServerRequestRegion::mint_from_connection(region_name, request_budget, request_now, cx);
    let request_cx = region.cx().clone();
    let body_cx = request_cx.clone();
    let (writer, body) = IncomingRequestBody::channel_with_limits(
        &request_cx,
        body_kind,
        config.incoming_body_frame_capacity,
        config.incoming_body_queued_bytes,
    );
    let request = StreamingServerRequest {
        head,
        peer_addr,
        body,
    };
    let handler = handler(request_cx.clone(), request);
    let handler = async move { Some(handler.await) };
    let head_committed = AtomicBool::new(false);

    state.phase = ConnectionPhase::Processing;
    let request_flow = async {
        let body_driver = drive_incoming_body(
            &body_cx,
            &mut io,
            &mut read_buffer,
            writer.max_body_size(u64::try_from(config.max_body_size).unwrap_or(u64::MAX)),
            &config,
        );
        let (produced, writer) = match join_streaming_handler_and_body(
            &request_cx,
            handler,
            body_driver,
            &config,
            shutdown_signal.as_ref(),
        )
        .await
        {
            Ok(Some(joined)) => joined,
            Ok(None) => {
                return Err(HttpError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "request handler ended before synchronized body EOF",
                )));
            }
            Err(body_error) => {
                record_incoming_body_failure(&body_error);
                // br-asupersync-hw83se: mirror the buffered path — a
                // DrainLimitExceeded body error (mapped to None by
                // incoming_body_failure_response) still owes the client an
                // explicit 413 + close rather than a bare I/O error.
                let refusal =
                    incoming_body_failure_response(request_version, &body_error).or_else(|| {
                        matches!(body_error, IncomingBodyError::DrainLimitExceeded { .. }).then(
                            || {
                                hop_error_response(
                                    request_version,
                                    413,
                                    "[ASUP-E505] request body exceeds the configured limit",
                                )
                            },
                        )
                    });
                if let Some(mut response) = refusal {
                    add_connection_close(&mut response);
                    if request_method == Method::Head {
                        suppress_response_body_for_head(&mut response);
                    }
                    head_committed.store(true, Ordering::Release);
                    return response_write
                        .write_streaming_response(&request_cx, &mut io, response)
                        .await;
                }
                return Err(HttpError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    body_error,
                )));
            }
        };
        // br-asupersync-hw83se: an unread-body drain overrun owes the client a
        // status before the (unreusable) connection closes, instead of dropping
        // it and returning an I/O error. incoming_body_failure_response maps
        // DrainTimeout to 408 but DrainLimitExceeded to None, so fall back to an
        // explicit 413 + Connection: close. The produced streaming body is
        // intentionally not started.
        if let Err(error) = validate_unread_drain(writer.drain_progress(), &config) {
            record_incoming_body_failure(&error);
            let mut response =
                incoming_body_failure_response(request_version, &error).unwrap_or_else(|| {
                    hop_error_response(
                        request_version,
                        413,
                        "[ASUP-E505] request body exceeds the configured limit",
                    )
                });
            add_connection_close(&mut response);
            if request_method == Method::Head {
                suppress_response_body_for_head(&mut response);
            }
            head_committed.store(true, Ordering::Release);
            return response_write.write_streaming_response(&request_cx, &mut io, response).await;
        }

        let rejected_method = match policy {
            ProducedResponsePolicy::Sse => {
                request_method != Method::Get && request_method != Method::Head
            }
            ProducedResponsePolicy::Generic => request_method == Method::Connect,
        };
        if rejected_method {
            let message = match policy {
                ProducedResponsePolicy::Sse => "live SSE requires GET or HEAD",
                ProducedResponsePolicy::Generic => {
                    "generic produced responses do not support CONNECT tunnels"
                }
            };
            let mut response = hop_error_response(request_version, 405, message);
            if policy == ProducedResponsePolicy::Sse {
                response
                    .headers
                    .push(("Allow".to_owned(), "GET, HEAD".to_owned()));
            }
            add_connection_close(&mut response);
            head_committed.store(true, Ordering::Release);
            return response_write.write_streaming_response(&request_cx, &mut io, response).await;
        }

        if request_version != Version::Http11 {
            let message = match policy {
                ProducedResponsePolicy::Sse => "live SSE requires HTTP/1.1 chunked framing",
                ProducedResponsePolicy::Generic => {
                    "generic produced responses require HTTP/1.1 framing"
                }
            };
            let mut response = hop_error_response(request_version, 505, message);
            add_connection_close(&mut response);
            if request_method == Method::Head {
                suppress_response_body_for_head(&mut response);
            }
            head_committed.store(true, Ordering::Release);
            return response_write.write_streaming_response(&request_cx, &mut io, response).await;
        }

        if request_method == Method::Head {
            let response = match policy {
                ProducedResponsePolicy::Sse => live_sse_head_only_response(request_version),
                ProducedResponsePolicy::Generic => produced_head_only_response(produced)?,
            };
            head_committed.store(true, Ordering::Release);
            return response_write.write_streaming_response(&request_cx, &mut io, response).await;
        }

        let mut produced = produced;
        let body_kind = produced.body_kind();
        validate_produced_response_head(produced.head_mut(), body_kind)?;
        let (response, producer) = produced.into_parts(&request_cx);
        drive_produced_response(
            &request_cx,
            &mut io,
            response,
            producer,
            policy == ProducedResponsePolicy::Generic,
            config.request_drain_grace,
            response_write,
            &head_committed,
        )
        .await
    };
    let hop = race_force_close(
        shutdown_signal.as_ref(),
        region.run_with_protocol_drain(
            budget_source,
            Some(cx.clone()),
            config.request_drain_grace,
            request_flow,
        ),
    )
    .await;

    state.requests_served = 1;
    state.last_request_at = connection_now(cx);
    state.phase = ConnectionPhase::Closing;
    let result = match hop {
        None | Some(ServerHopOutcome::Cancelled) => Ok(()),
        Some(ServerHopOutcome::ConnectionLost) => {
            error!(
                diagnostic = WebBodyDiagnostic::ClientAbort.code(),
                "[ASUP-E509] h1 produced response lost its client connection"
            );
            Ok(())
        }
        Some(ServerHopOutcome::Ok(result)) => result,
        Some(ServerHopOutcome::Panicked(_)) => {
            if !head_committed.load(Ordering::Acquire) {
                let mut response =
                    hop_error_response(request_version, 500, "Internal Server Error");
                add_connection_close(&mut response);
                if request_method == Method::Head {
                    suppress_response_body_for_head(&mut response);
                }
                response_write.write_streaming_response(cx, &mut io, response).await
            } else {
                error!(
                    diagnostic = WebBodyDiagnostic::ResponseProducerFailure.code(),
                    "[ASUP-E510] h1 response producer panicked after head commitment"
                );
                Ok(())
            }
        }
        Some(ServerHopOutcome::DeadlineExceeded) => {
            if !head_committed.load(Ordering::Acquire) {
                let mut response =
                    hop_error_response(request_version, 503, HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC);
                add_connection_close(&mut response);
                if request_method == Method::Head {
                    suppress_response_body_for_head(&mut response);
                }
                response_write.write_streaming_response(cx, &mut io, response).await
            } else {
                error!(
                    diagnostic = "ASUP-E501",
                    "[ASUP-E501] h1 response producer exceeded its request-region deadline after head commitment"
                );
                Ok(())
            }
        }
    };
    let _ = response_write.close_transport(&mut io).await;
    result.map(|()| state)
}

fn connection_now(cx: &Cx) -> crate::types::Time {
    cx.timer_driver().map_or_else(wall_now, |timer| timer.now())
}

fn live_sse_head_only_response(version: Version) -> Response {
    let mut response = Response::new(200, default_reason(200), Vec::new());
    response.version = version;
    response.headers = StreamingSse::<VecSseSource>::headers()
        .into_iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("connection"))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    add_connection_close(&mut response);
    response
}

fn validate_produced_response_head(
    head: &mut ResponseHead,
    body_kind: BodyKind,
) -> Result<(), HttpError> {
    if matches!(head.status, 100..=199 | 204 | 205 | 304) {
        return Err(HttpError::BadTransferEncoding);
    }
    if head.reason.contains('\r') || head.reason.contains('\n') {
        return Err(HttpError::BadHeader);
    }
    head.version = Version::Http11;
    head.headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case("connection"));
    head.headers
        .push(("Connection".to_owned(), "close".to_owned()));

    let mut content_length = None;
    let mut transfer_encoding = None;
    let mut declares_trailers = false;
    for (name, value) in &head.headers {
        validate_header_field(name, value)?;
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.replace(value.as_str()).is_some() {
                return Err(HttpError::DuplicateContentLength);
            }
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.replace(value.as_str()).is_some() {
                return Err(HttpError::DuplicateTransferEncoding);
            }
        }
        declares_trailers |= name.eq_ignore_ascii_case("trailer");
    }
    if content_length.is_some() && transfer_encoding.is_some() {
        return Err(HttpError::AmbiguousBodyLength);
    }
    match body_kind {
        BodyKind::Chunked => {
            let transfer_encoding = transfer_encoding.ok_or(HttpError::BadTransferEncoding)?;
            require_transfer_encoding_chunked(trim_ows(transfer_encoding))?;
        }
        BodyKind::ContentLength(expected) => {
            if declares_trailers {
                return Err(HttpError::TrailersNotAllowed);
            }
            let content_length = content_length.ok_or(HttpError::BadContentLength)?;
            let content_length = trim_ows(content_length);
            if content_length.is_empty()
                || !content_length.bytes().all(|byte| byte.is_ascii_digit())
                || content_length
                    .parse::<u64>()
                    .map_err(|_| HttpError::BadContentLength)?
                    != expected
            {
                return Err(HttpError::BadContentLength);
            }
        }
        BodyKind::Empty => return Err(HttpError::BadContentLength),
    }
    Ok(())
}

fn produced_head_only_response(produced: Http1ProducedResponse) -> Result<Response, HttpError> {
    let body_kind = produced.body_kind();
    let mut head = produced.into_head();
    validate_produced_response_head(&mut head, body_kind)?;
    let mut response = Response::new(head.status, head.reason, Vec::new());
    response.version = Version::Http11;
    response.headers = head
        .headers
        .into_iter()
        .filter(|(name, _)| {
            !name.eq_ignore_ascii_case("transfer-encoding")
                && !name.eq_ignore_ascii_case("connection")
                && !name.eq_ignore_ascii_case("trailer")
        })
        .collect();
    add_connection_close(&mut response);
    Ok(response)
}

struct LiveSseCancelGuard<S: StreamingSseSource> {
    stream: StreamingSse<S>,
    cx: Cx,
    armed: bool,
    cancel_request_on_drop: bool,
}

impl<S: StreamingSseSource> LiveSseCancelGuard<S> {
    fn new(stream: StreamingSse<S>, cx: Cx) -> Self {
        Self {
            stream,
            cx,
            armed: true,
            cancel_request_on_drop: false,
        }
    }

    fn arm_transport(&mut self) {
        self.cancel_request_on_drop = true;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<S: StreamingSseSource> Drop for LiveSseCancelGuard<S> {
    fn drop(&mut self) {
        if self.armed {
            if self.cancel_request_on_drop {
                self.stream.cancel_for_disconnect(&self.cx);
            } else {
                self.stream.cancel_for_server_abort();
            }
        }
    }
}

async fn produce_live_sse<S>(
    mut guard: LiveSseCancelGuard<S>,
    mut sender: OutgoingBodySender,
) -> Result<OutgoingBodySender, HttpError>
where
    S: StreamingSseSource,
{
    guard.arm_transport();
    loop {
        // br-asupersync-sse7kp2: the live step is heartbeat-aware when the
        // stream sets a heartbeat_interval (and its source overrides
        // poll_next_event to idle), and is otherwise identical to
        // send_next_h1_chunk.
        match guard
            .stream
            .send_next_h1_chunk_live(&guard.cx, &mut sender)
            .await
        {
            Ok(StreamingSseTransportStep::Sent { .. }) => {}
            Ok(StreamingSseTransportStep::Complete) => {
                if !sender.is_finished() {
                    return Err(HttpError::BodyChannelClosed);
                }
                guard.disarm();
                return Ok(sender);
            }
            Err(error) => {
                // A source-side failure must not cancel the body receiver's
                // context before it drains frames already committed to the
                // bounded channel. Transport-side errors have already
                // cancelled through `handle_h1_transport_error`; source
                // cleanup is idempotent in either case.
                guard.stream.cancel_for_server_abort();
                guard.disarm();
                return Err(live_sse_transport_error(error));
            }
        }
    }
}

fn live_sse_transport_error(error: StreamingSseTransportError) -> HttpError {
    match error {
        StreamingSseTransportError::Transport(error) => error,
        StreamingSseTransportError::Stream(error) => HttpError::Io(std::io::Error::other(error)),
    }
}

#[cfg(test)]
fn encode_live_sse_frame(
    encoder: &mut ChunkedEncoder,
    frame: Frame<crate::bytes::BytesCursor>,
    destination: &mut BytesMut,
) -> Result<(), HttpError> {
    if frame.is_trailers() {
        return Err(HttpError::TrailersNotAllowed);
    }
    encoder.encode_frame(frame, destination);
    Ok(())
}

async fn drain_producer_after_write_error<P>(
    cx: &Cx,
    producer: Pin<&mut P>,
    producer_result: &mut Option<Result<OutgoingBodySender, HttpError>>,
    drain_grace: Duration,
) where
    P: Future<Output = Result<OutgoingBodySender, HttpError>> + ?Sized,
{
    cx.cancel_with(
        CancelKind::ParentCancelled,
        Some("HTTP/1 produced response could not make progress"),
    );
    if producer_result.is_none() {
        let _ = timeout(connection_now(cx), drain_grace, producer).await;
    }
}

fn normalize_producer_result(
    result: Result<OutgoingBodySender, HttpError>,
    body: &crate::http::h1::stream::OutgoingBody,
) -> Result<OutgoingBodySender, HttpError> {
    match result {
        Ok(sender) if sender.is_finished() && sender.is_peer_of(body) => Ok(sender),
        Ok(_unfinished_sender) => Err(HttpError::BodyChannelClosed),
        Err(error) => Err(error),
    }
}

fn record_h1_body_diagnostic(diagnostic: WebBodyDiagnostic, cause: &'static str) {
    let _ = (diagnostic, cause);
    error!(
        diagnostic = diagnostic.code(),
        cause,
        "[{}] h1 body stream terminated without a clean response-body boundary",
        diagnostic.code()
    );
}

fn record_h1_produced_error(cx: &Cx, error_value: &HttpError, cause: &'static str) {
    if matches!(error_value, HttpError::BodyCancelled) {
        match classify_server_producer_cancellation(cx) {
            ServerProducerCancellation::DeadlineExceeded => {
                error!(
                    diagnostic = "ASUP-E501",
                    cause, "[ASUP-E501] h1 response producer acknowledged its request deadline"
                );
            }
            ServerProducerCancellation::Cancelled => {}
        }
        return;
    }
    record_h1_body_diagnostic(WebBodyDiagnostic::ResponseProducerFailure, cause);
}

async fn drive_produced_response<T>(
    cx: &Cx,
    io: &mut T,
    mut response: StreamingResponse,
    mut producer: Http1ProducedResponseFuture,
    allow_trailers: bool,
    drain_grace: Duration,
    response_write: ResponseWritePolicy<'_>,
    head_committed: &AtomicBool,
) -> Result<(), HttpError>
where
    T: AsyncWrite + Unpin,
{
    validate_produced_response_head(&mut response.head, response.body.kind())?;
    let encoded_head = response.head.serialize();
    let mut producer_result = None;

    // Once this write is attempted, a partial head may be visible. Every
    // subsequent failure therefore closes the connection without a fallback
    // status or a clean chunk terminator.
    head_committed.store(true, Ordering::Release);
    if let Err(error) = write_all_within_idle(io, encoded_head.as_ref(), response_write).await {
        record_h1_body_diagnostic(
            WebBodyDiagnostic::ClientAbort,
            "client transport failed while writing the response head",
        );
        drain_producer_after_write_error(cx, producer.as_mut(), &mut producer_result, drain_grace)
            .await;
        return Err(HttpError::Io(error));
    }
    if let Err(error) = flush_within_idle(io, response_write).await {
        record_h1_body_diagnostic(
            WebBodyDiagnostic::ClientAbort,
            "client transport failed while flushing the response head",
        );
        drain_producer_after_write_error(cx, producer.as_mut(), &mut producer_result, drain_grace)
            .await;
        return Err(HttpError::Io(error));
    }

    let body_kind = response.body.kind();
    let mut encoder = ChunkedEncoder::new();
    loop {
        // A body producer can park without ever yielding a frame. Socket
        // write deadlines alone cannot release that request's in-flight slot.
        let frame = response_write
            .run(async {
                Ok(poll_fn(|task_cx| {
                    if producer_result.is_none()
                        && let Poll::Ready(result) = producer.as_mut().poll(task_cx)
                    {
                        producer_result = Some(normalize_producer_result(result, &response.body));
                    }
                    // A producer that returned a finished sender has queued
                    // every frame: its context's cancellation no longer decides
                    // where the body ends (br-asupersync-9c8r2c).
                    if matches!(producer_result, Some(Ok(_))) {
                        return Poll::Ready(response.body.take_frame_after_producer_returned());
                    }
                    // Frames the producer committed, including terminal
                    // trailers, precede a later cancellation of its context
                    // (br-asupersync-fy5kwg).
                    response.body.poll_committed_frame(task_cx)
                })
                .await)
            })
            .await;
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                record_h1_body_diagnostic(
                    WebBodyDiagnostic::ResponseProducerFailure,
                    "response producer made no progress before the response deadline",
                );
                drain_producer_after_write_error(
                    cx,
                    producer.as_mut(),
                    &mut producer_result,
                    drain_grace,
                )
                .await;
                return Err(HttpError::Io(error));
            }
        };
        let Some(frame) = frame else {
            let producer_result = match producer_result.take() {
                Some(result) => result,
                None => finish_producer_within_idle(
                    cx, producer.as_mut(), &response.body, response_write, drain_grace,
                ).await,
            };
            let sender = match producer_result {
                Ok(sender) => sender,
                Err(error) => {
                    record_h1_produced_error(cx, &error, "response producer returned an error");
                    return Err(error);
                }
            };
            if !sender.is_finished() || (body_kind.is_chunked() && encoder.is_finished()) {
                record_h1_body_diagnostic(
                    WebBodyDiagnostic::ResponseProducerFailure,
                    "response producer did not finish exactly once",
                );
                return Err(HttpError::BodyChannelClosed);
            }
            if !body_kind.is_chunked() {
                return Ok(());
            }
            let mut final_chunk = BytesMut::new();
            encoder.finalize(None, &mut final_chunk);
            if let Err(error) = write_all_within_idle(io, final_chunk.as_ref(), response_write).await {
                record_h1_body_diagnostic(
                    WebBodyDiagnostic::ClientAbort,
                    "client transport failed while writing the terminal chunk",
                );
                return Err(HttpError::Io(error));
            }
            if let Err(error) = flush_within_idle(io, response_write).await {
                record_h1_body_diagnostic(
                    WebBodyDiagnostic::ClientAbort,
                    "client transport failed while flushing the terminal chunk",
                );
                return Err(HttpError::Io(error));
            }
            return Ok(());
        };

        let frame = match frame {
            Ok(frame) => frame,
            Err(HttpError::BodyCancelled) if producer_result.is_none() => {
                // The receive saw the producer's cancellation. Its outcome
                // decides the end: a finished sender means the queued frames
                // are the whole body, and an unfinished one keeps the error.
                producer_result = Some(
                    finish_producer_within_idle(
                        cx,
                        producer.as_mut(),
                        &response.body,
                        response_write,
                        drain_grace,
                    )
                    .await,
                );
                if matches!(producer_result, Some(Ok(_))) {
                    continue;
                }
                let error = HttpError::BodyCancelled;
                record_h1_produced_error(cx, &error, "response body yielded an error frame");
                return Err(error);
            }
            Err(error) => {
                record_h1_produced_error(cx, &error, "response body yielded an error frame");
                return Err(error);
            }
        };
        let mut encoded_frame = BytesMut::new();
        match frame {
            Frame::Data(mut data) => {
                if body_kind.is_chunked() {
                    encoder.encode_frame(Frame::Data(data), &mut encoded_frame);
                } else {
                    while data.remaining() > 0 {
                        let chunk = data.chunk();
                        if chunk.is_empty() {
                            break;
                        }
                        encoded_frame.extend_from_slice(chunk);
                        data.advance(chunk.len());
                    }
                }
            }
            Frame::Trailers(trailers) => {
                if !allow_trailers || !body_kind.is_chunked() {
                    record_h1_body_diagnostic(
                        WebBodyDiagnostic::ResponseProducerFailure,
                        "response producer emitted trailers for an incompatible body",
                    );
                    return Err(HttpError::TrailersNotAllowed);
                }
                let producer_result = match producer_result.take() {
                    Some(result) => result,
                    None => finish_producer_within_idle(
                        cx, producer.as_mut(), &response.body, response_write, drain_grace,
                    ).await,
                };
                let sender = match producer_result {
                    Ok(sender) => sender,
                    Err(error) => {
                        record_h1_body_diagnostic(
                            WebBodyDiagnostic::ResponseProducerFailure,
                            "response producer failed before trailers",
                        );
                        return Err(error);
                    }
                };
                if encoder.is_finished() {
                    record_h1_body_diagnostic(
                        WebBodyDiagnostic::ResponseProducerFailure,
                        "response producer emitted a duplicate terminal frame",
                    );
                    return Err(HttpError::BodyChannelClosed);
                }
                debug_assert!(sender.is_finished());
                encoder.finalize(Some(&trailers), &mut encoded_frame);

                if let Err(error) =
                    write_all_within_idle(io, encoded_frame.as_ref(), response_write).await
                {
                    record_h1_body_diagnostic(
                        WebBodyDiagnostic::ClientAbort,
                        "client transport failed while writing response trailers",
                    );
                    cx.cancel_with(
                        CancelKind::ParentCancelled,
                        Some("HTTP/1 produced-body client transport disconnected"),
                    );
                    return Err(HttpError::Io(error));
                }
                if let Err(error) = flush_within_idle(io, response_write).await {
                    record_h1_body_diagnostic(
                        WebBodyDiagnostic::ClientAbort,
                        "client transport failed while flushing response trailers",
                    );
                    cx.cancel_with(
                        CancelKind::ParentCancelled,
                        Some("HTTP/1 produced-body client transport disconnected"),
                    );
                    return Err(HttpError::Io(error));
                }
                return Ok(());
            }
        }
        // Do not poll application production while this frame is waiting for
        // socket writability. The bounded channel may retain its already
        // admitted frames, but producer progress resumes only after the
        // current write and flush complete. Transport-error cleanup below is
        // the sole exception: it polls under cancellation for a bounded drain.
        let write_result = async {
            write_all_within_idle(io, encoded_frame.as_ref(), response_write)
                .await
                .map_err(HttpError::Io)?;
            flush_within_idle(io, response_write)
                .await
                .map_err(HttpError::Io)
        }
        .await;

        match write_result {
            Ok(()) => {
                if body_kind.is_chunked() && encoder.is_finished() {
                    return Ok(());
                }
                // A fast in-memory or kernel-buffered writer can otherwise
                // keep an infinite source inside one poll forever. Yield at
                // each committed frame so connection cancellation, request
                // deadlines, and force-close can regain control.
                crate::runtime::yield_now().await;
            }
            Err(error) => {
                record_h1_body_diagnostic(
                    WebBodyDiagnostic::ClientAbort,
                    "client transport failed while writing a response body frame",
                );
                drain_producer_after_write_error(
                    cx,
                    producer.as_mut(),
                    &mut producer_result,
                    drain_grace,
                )
                .await;
                return Err(error);
            }
        }
    }
}

async fn read_streaming_request_head<T>(
    cx: &Cx,
    io: &mut T,
    buffer: &mut BytesMut,
    config: &Http1Config,
    shutdown_signal: Option<&ShutdownSignal>,
) -> Result<Option<(RequestHead, BodyKind)>, HttpError>
where
    T: AsyncRead + Unpin,
{
    // One deadline for the whole head, not one per read: a peer trickling
    // one byte per idle window would otherwise keep a partial head open for
    // `max_headers_size` windows (slowloris); the buffered server bounds the
    // entire request read the same way.
    let head_deadline = config
        .idle_timeout
        .map(|idle_timeout| connection_now(cx) + idle_timeout);
    // No request region exists until a complete head is admitted. An idle
    // connection (including a partial head) must therefore leave on graceful
    // drain, without waiting for bytes, an idle deadline, or force-close.
    // Keep both registrations alive across reads so a parked transport wakes
    // even when idle_timeout is disabled and the peer never sends again.
    let mut cancelled = std::pin::pin!(cx.cancelled());
    let mut draining = std::pin::pin!(async {
        if let Some(signal) = shutdown_signal {
            signal.wait_for_phase(ShutdownPhase::Draining).await;
        } else {
            std::future::pending::<()>().await;
        }
    });
    loop {
        if cx.checkpoint().is_err() || shutdown_signal.is_some_and(ShutdownSignal::is_shutting_down)
        {
            return Ok(None);
        }
        if let Some(head) =
            decode_streaming_request_head(buffer, config.max_headers_size, config.max_body_size)?
        {
            return Ok(Some(head));
        }
        let mut chunk = [0_u8; 8192];
        let count = {
            let mut read = std::pin::pin!(io.read(&mut chunk));
            let read = poll_fn(|task_cx| {
                if cancelled.as_mut().poll(task_cx).is_ready()
                    || draining.as_mut().poll(task_cx).is_ready()
                {
                    return Poll::Ready(None);
                }
                read.as_mut().poll(task_cx).map(Some)
            });
            if let Some(deadline) = head_deadline {
                match crate::time::timeout_at(deadline, read).await {
                    Ok(Some(result)) => result.map_err(HttpError::Io)?,
                    Ok(None) | Err(_) => return Ok(None),
                }
            } else {
                match read.await {
                    Some(result) => result.map_err(HttpError::Io)?,
                    None => return Ok(None),
                }
            }
        };
        if count == 0 {
            // RFC 9112 section 2.2 tolerates empty lines before a
            // request-line, and a client may send a CRLF after a request
            // body. A peer that closes after only those sent no request, so
            // the connection closes without a 400 (br-asupersync-8udzw7
            // A-L1). A partial head is still refused.
            if buffer.iter().all(|byte| matches!(byte, b'\r' | b'\n')) {
                return Ok(None);
            }
            return Err(HttpError::BadRequestLine);
        }
        buffer.extend_from_slice(&chunk[..count]);
    }
}

async fn drive_incoming_body<T>(
    cx: &Cx,
    io: &mut T,
    read_buffer: &mut BytesMut,
    mut writer: IncomingRequestBodyWriter,
    config: &Http1StreamingConfig,
) -> Result<IncomingRequestBodyWriter, IncomingBodyError>
where
    T: AsyncRead + Unpin,
{
    // asupersync-1to1qw: the socket-wait budget for this whole body. A bound
    // applied per read let a peer trickle one byte per idle window and hold
    // the connection, its in-flight slot, the body queues and a handler parked
    // on the body for `max_body_size` windows. The buffered server bounds the
    // entire request read by `idle_timeout` and the streaming head reader
    // bounds the head the same way; the body now spends at most one
    // `idle_timeout` waiting on the socket in total. Time spent applying
    // backpressure to the handler (`push_bytes`) is not charged, so a slow
    // consumer of a fast client is unaffected. Legacy serving drives this
    // outside the logical request region. Owned serving drives it in the
    // admitted request task alongside the handler; both paths still bound
    // the protocol's socket waits independently of application progress.
    let mut read_budget = config.idle_timeout;
    loop {
        if writer.is_done() {
            let remainder = writer.take_remainder();
            if !remainder.is_empty() {
                *read_buffer = remainder;
            }
            return Ok(writer);
        }

        if !read_buffer.is_empty() {
            let input = std::mem::take(read_buffer);
            if writer.consumer_dropped() {
                let progress = writer.discard_bytes(input.as_ref())?;
                validate_unread_drain_limits(progress, config)?;
            } else if let Err(error) = writer.push_bytes(cx, input.as_ref()).await {
                if error != IncomingBodyError::ConsumerDropped {
                    return Err(error);
                }
                let progress = writer.discard_bytes(&[])?;
                validate_unread_drain_limits(progress, config)?;
            }
            continue;
        }

        let mut chunk = [0_u8; 8192];
        let read = io.read(&mut chunk);
        let read_result = if let Some(remaining) = read_budget {
            let started = connection_now(cx);
            match timeout(started, remaining, read).await {
                Ok(result) => {
                    let waited = Duration::from_nanos(
                        connection_now(cx)
                            .as_nanos()
                            .saturating_sub(started.as_nanos()),
                    );
                    read_budget = Some(remaining.saturating_sub(waited));
                    result
                }
                Err(_) => Err(std::io::Error::from(std::io::ErrorKind::TimedOut)),
            }
        } else {
            read.await
        };
        let count = match read_result {
            Ok(count) => count,
            Err(_) => {
                let error = IncomingBodyError::ClientAborted;
                writer.fail(error.clone());
                return Err(error);
            }
        };
        if count == 0 {
            let error = IncomingBodyError::ClientAborted;
            writer.fail(error.clone());
            return Err(error);
        }
        read_buffer.extend_from_slice(&chunk[..count]);
    }
}

async fn join_streaming_handler_and_body<H, B, R>(
    cx: &Cx,
    handler: H,
    body: B,
    config: &Http1StreamingConfig,
    shutdown_signal: Option<&ShutdownSignal>,
) -> Result<Option<(R, IncomingRequestBodyWriter)>, IncomingBodyError>
where
    H: Future<Output = Option<R>>,
    B: Future<Output = Result<IncomingRequestBodyWriter, IncomingBodyError>>,
{
    let mut handler = Some(Box::pin(handler));
    let mut body = Some(Box::pin(body));
    let first = poll_fn(|task_cx| {
        if let Some(handler) = handler.as_mut() {
            if let Poll::Ready(result) = handler.as_mut().poll(task_cx) {
                return Poll::Ready(StreamingJoinFirst::Handler(result));
            }
        }
        if let Some(body) = body.as_mut() {
            if let Poll::Ready(result) = body.as_mut().poll(task_cx) {
                return Poll::Ready(StreamingJoinFirst::Body(result));
            }
        }
        Poll::Pending
    })
    .await;

    match first {
        StreamingJoinFirst::Body(Ok(writer)) => {
            body.take();
            let Some(handler) = handler.take() else {
                return Ok(None);
            };
            let Some(hop) = handler.await else {
                return Ok(None);
            };
            Ok(Some((hop, writer)))
        }
        StreamingJoinFirst::Body(Err(error)) => {
            body.take();
            if let Some(handler) = handler.take() {
                let _ = timeout(connection_now(cx), config.request_drain_grace, handler).await;
            }
            Err(error)
        }
        StreamingJoinFirst::Handler(Some(hop)) => {
            handler.take();
            let Some(body) = body.take() else {
                return Ok(None);
            };
            // The handler (and its request-region cleanup) has completed.
            // Its force-close observer is gone, but the peer may still owe
            // body bytes. Interrupt only this remaining protocol drain; a
            // live handler stays owned by the branches above.
            let Some(drained) = race_force_close(
                shutdown_signal,
                timeout(connection_now(cx), config.unread_body_drain_timeout, body),
            )
            .await
            else {
                return Ok(None);
            };
            let writer = drained.map_err(|_| IncomingBodyError::DrainTimeout)??;
            Ok(Some((hop, writer)))
        }
        StreamingJoinFirst::Handler(None) => Ok(None),
    }
}

/// Map a rejected request *head* to the HTTP status the server owes the client
/// before it closes the connection (`br-asupersync-hw83se`).
///
/// The serve loops previously answered a head-parse failure with a bare
/// `return Err(..)` / `?`, dropping the connection with no response at all: a
/// client could not tell an oversized-header or malformed-request refusal from
/// a dead socket, and the 413/431 that the configured `max_headers_size` /
/// `max_body_size` advertise never reached the wire. This mirrors
/// [`incoming_body_failure_response`], which already covers the streaming-body
/// path, for the request-head path on both the buffered and streaming servers.
///
/// Returns `None` for errors that carry no meaningful client-facing status —
/// transport I/O, body-stream lifecycle, and response-parsing variants that
/// never originate from decoding a server-side request head — so those keep
/// abandoning the connection rather than fabricating a status. The match is
/// deliberately exhaustive so a newly added [`HttpError`] variant forces a
/// classification decision here instead of silently defaulting.
fn head_parse_failure_response(error: &HttpError) -> Option<Response> {
    let (status, message): (u16, &str) = match error {
        HttpError::HeadersTooLarge | HttpError::TooManyHeaders => {
            (431, "request header fields exceed the configured limit")
        }
        HttpError::RequestLineTooLong => (414, "request line exceeds the configured limit"),
        HttpError::BodyTooLarge | HttpError::BodyTooLargeDetailed { .. } => {
            (413, "request body exceeds the configured limit")
        }
        HttpError::UnsupportedVersion => (505, "unsupported HTTP version"),
        HttpError::BadRequestLine
        | HttpError::BadHeader
        | HttpError::BadMethod
        | HttpError::BadContentLength
        | HttpError::DuplicateContentLength
        | HttpError::DuplicateTransferEncoding
        | HttpError::BadTransferEncoding
        | HttpError::InvalidHeaderName
        | HttpError::InvalidHeaderValue
        | HttpError::BadChunkedEncoding
        | HttpError::AmbiguousBodyLength
        | HttpError::TrailersNotAllowed => (400, "malformed request head"),
        HttpError::Io(_)
        | HttpError::BodyCancelled
        | HttpError::BodyChannelClosed
        | HttpError::PrefetchedDataRemaining(_)
        | HttpError::TooManyInformationalResponses { .. } => return None,
    };
    Some(Response {
        status,
        reason: String::new(),
        version: Version::Http11,
        headers: vec![
            (
                "content-type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            ),
            ("connection".to_string(), "close".to_string()),
        ],
        body: message.as_bytes().to_vec(),
        trailers: Vec::new(),
    })
}

fn incoming_body_failure_response(version: Version, error: &IncomingBodyError) -> Option<Response> {
    let (status, message) = match error {
        IncomingBodyError::BodyTooLarge { .. } | IncomingBodyError::QueueFrameTooLarge { .. } => {
            (413, "[ASUP-E505] request body exceeds the configured limit")
        }
        IncomingBodyError::AccountingOverflow => (500, "request body accounting failed"),
        IncomingBodyError::BadContentLength
        | IncomingBodyError::BadChunkedEncoding
        | IncomingBodyError::TrailersTooLarge
        | IncomingBodyError::BadHeader
        | IncomingBodyError::InvalidHeaderName
        | IncomingBodyError::InvalidHeaderValue => (400, "malformed request body framing"),
        IncomingBodyError::Cancelled {
            kind: CancelKind::Deadline | CancelKind::Timeout,
        } => (503, HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC),
        IncomingBodyError::DrainTimeout => (408, "[ASUP-E508] request body drain timed out"),
        IncomingBodyError::SourceDisconnected => (500, "request body producer disconnected"),
        IncomingBodyError::ClientAborted
        | IncomingBodyError::DrainLimitExceeded { .. }
        | IncomingBodyError::ConsumerDropped
        | IncomingBodyError::Cancelled { .. }
        | IncomingBodyError::AlreadyTerminal => return None,
    };
    Some(hop_error_response(version, status, message))
}

fn record_incoming_body_failure(error_value: &IncomingBodyError) {
    let diagnostic = match error_value {
        IncomingBodyError::BodyTooLarge { .. } | IncomingBodyError::QueueFrameTooLarge { .. } => {
            WebBodyDiagnostic::TotalBodyLimit.code()
        }
        IncomingBodyError::Cancelled {
            kind: CancelKind::Deadline | CancelKind::Timeout,
        } => "ASUP-E501",
        IncomingBodyError::DrainTimeout => WebBodyDiagnostic::Timeout.code(),
        IncomingBodyError::ClientAborted => WebBodyDiagnostic::ClientAbort.code(),
        IncomingBodyError::BadContentLength
        | IncomingBodyError::BadChunkedEncoding
        | IncomingBodyError::TrailersTooLarge
        | IncomingBodyError::BadHeader
        | IncomingBodyError::InvalidHeaderName
        | IncomingBodyError::InvalidHeaderValue
        | IncomingBodyError::AccountingOverflow
        | IncomingBodyError::SourceDisconnected
        | IncomingBodyError::DrainLimitExceeded { .. }
        | IncomingBodyError::ConsumerDropped
        | IncomingBodyError::Cancelled { .. }
        | IncomingBodyError::AlreadyTerminal => "uncoded",
    };
    if diagnostic == "uncoded" {
        error!(
            error = %error_value,
            "h1 request body terminated before synchronized EOF"
        );
    } else {
        error!(
            diagnostic,
            error = %error_value,
            "[{diagnostic}] h1 request body terminated before synchronized EOF"
        );
    }
}

enum StreamingJoinFirst<R> {
    Handler(Option<R>),
    Body(Result<IncomingRequestBodyWriter, IncomingBodyError>),
}

fn validate_unread_drain(
    progress: IncomingBodyDrainProgress,
    config: &Http1StreamingConfig,
) -> Result<(), IncomingBodyError> {
    validate_unread_drain_limits(progress, config)?;
    if !progress.synchronized_eof {
        return Err(IncomingBodyError::DrainTimeout);
    }
    Ok(())
}

fn validate_unread_drain_limits(
    progress: IncomingBodyDrainProgress,
    config: &Http1StreamingConfig,
) -> Result<(), IncomingBodyError> {
    if progress.frames > config.unread_body_drain_frames
        || progress.bytes > config.unread_body_drain_bytes
    {
        return Err(IncomingBodyError::DrainLimitExceeded {
            frames: progress.frames,
            bytes: progress.bytes,
            frame_limit: config.unread_body_drain_frames,
            byte_limit: config.unread_body_drain_bytes,
        });
    }
    Ok(())
}

/// RAII guard for the listener-shared in-flight request counter
/// (br-asupersync-server-stack-hardening-eeexl1.2, D2.2b).
///
/// Acquired once a request head has been read off the wire; released on drop
/// no matter how the request ends (response flushed, handler cancelled,
/// connection error, force-close break), so the counter can never leak a
/// request on an early exit path.
struct InFlightRequestGuard {
    counter: Option<Arc<AtomicUsize>>,
}

impl InFlightRequestGuard {
    fn acquire(counter: Option<&Arc<AtomicUsize>>) -> Self {
        if let Some(counter) = counter {
            counter.fetch_add(1, Ordering::AcqRel);
        }
        Self {
            counter: counter.cloned(),
        }
    }
}

impl Drop for InFlightRequestGuard {
    fn drop(&mut self) {
        if let Some(counter) = &self.counter {
            counter.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// One response-progress policy for buffered, streaming and error responses.
/// A progress step is a complete buffered response, a body frame write/flush,
/// or the wait for the next producer frame/terminal receipt. Force-close is
/// effective even when the configured idle timeout is disabled.
#[derive(Clone, Copy)]
struct ResponseWritePolicy<'a> {
    idle_timeout: Option<Duration>,
    shutdown_signal: Option<&'a ShutdownSignal>,
    connection_owner: Option<&'a Cx>,
}

impl<'a> ResponseWritePolicy<'a> {
    const fn new(
        idle_timeout: Option<Duration>,
        shutdown_signal: Option<&'a ShutdownSignal>,
    ) -> Self {
        Self {
            idle_timeout,
            shutdown_signal,
            connection_owner: None,
        }
    }

    const fn with_owner(mut self, owner: Option<&'a Cx>) -> Self {
        self.connection_owner = owner;
        self
    }

    async fn run<F, T>(self, progress: F) -> std::io::Result<T>
    where
        F: Future<Output = std::io::Result<T>>,
    {
        let bounded = async {
            match self.idle_timeout {
                Some(idle) => {
                    timeout_with_owner(self.connection_owner, idle, progress)
                        .await
                        .unwrap_or_else(|_| {
                            Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "HTTP/1 response progress timed out",
                            ))
                        })
                }
                None => progress.await,
            }
        };
        let mut owner_cancel = crate::http::listener_cancel::ListenerCancellation::new(
            self.connection_owner.cloned(),
        );
        let mut polling_cancel = crate::http::listener_cancel::ListenerCancellation::new(
            self.connection_owner.and_then(|_| Cx::current()),
        );
        let mut bounded = std::pin::pin!(bounded);
        let progress = poll_fn(|cx| {
            let owner_cancelled = owner_cancel.poll_cancelled(cx);
            let polling_cancelled = polling_cancel.poll_cancelled(cx);
            if owner_cancelled || polling_cancelled {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "HTTP/1 response owner cancelled",
                )));
            }
            bounded.as_mut().poll(cx)
        });
        race_force_close(self.shutdown_signal, progress)
            .await
            .unwrap_or_else(|| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "HTTP/1 response force-closed",
                ))
            })
    }

    async fn flush_framed<T>(self, framed: &mut Framed<T, Http1Codec>) -> Result<(), HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        self.run(poll_fn(|task_cx| {
            if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "connection cancelled",
                )));
            }
            framed.poll_flush(task_cx)
        }))
        .await
        .map_err(HttpError::Io)
    }

    async fn close_transport<T: AsyncWrite + Unpin>(self, io: &mut T) -> std::io::Result<()> {
        self.run(io.shutdown()).await
    }

    async fn write_streaming_response<T>(
        self,
        cx: &Cx,
        io: &mut T,
        response: Response,
    ) -> Result<(), HttpError>
    where
        T: AsyncWrite + Unpin,
    {
        if cx.checkpoint().is_err() {
            return Err(HttpError::Io(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "connection cancelled",
            )));
        }
        let mut encoded = BytesMut::new();
        Http1Codec::new().encode(response, &mut encoded)?;
        self.run(async {
            io.write_all(encoded.as_ref()).await?;
            io.flush().await
        })
        .await
        .map_err(HttpError::Io)
    }
}

/// Raw produced-body writes share the response policy used by buffered flushes.
async fn write_all_within_idle<T: AsyncWrite + Unpin>(
    io: &mut T,
    bytes: &[u8],
    response_write: ResponseWritePolicy<'_>,
) -> std::io::Result<()> {
    response_write.run(io.write_all(bytes)).await
}

/// Bound a single `flush` on a raw socket by `idle_timeout`. See
/// [`write_all_within_idle`].
async fn flush_within_idle<T: AsyncWrite + Unpin>(
    io: &mut T,
    response_write: ResponseWritePolicy<'_>,
) -> std::io::Result<()> {
    response_write.run(io.flush()).await
}

async fn finish_producer_within_idle(
    cx: &Cx,
    mut producer: Pin<&mut (dyn Future<Output = Result<OutgoingBodySender, HttpError>> + Send)>,
    body: &crate::http::h1::stream::OutgoingBody,
    response_write: ResponseWritePolicy<'_>,
    drain_grace: Duration,
) -> Result<OutgoingBodySender, HttpError> {
    match response_write
        .run(async { Ok(producer.as_mut().await) })
        .await
    {
        Ok(result) => normalize_producer_result(result, body),
        Err(error) => {
            drain_producer_after_write_error(cx, producer, &mut None, drain_grace).await;
            Err(HttpError::Io(error))
        }
    }
}

/// Races `fut` against the shutdown signal's ForceClosing phase. Dropping the
/// interrupted future is the shutdown backstop; no signal means no race.
async fn race_force_close<F: Future>(signal: Option<&ShutdownSignal>, fut: F) -> Option<F::Output> {
    let Some(signal) = signal else {
        return Some(fut.await);
    };
    let mut fut = std::pin::pin!(fut);
    let mut force_close_fut = std::pin::pin!(signal.wait_for_phase(ShutdownPhase::ForceClosing));
    poll_fn(|cx| {
        // If already force-closing, bail immediately.
        if signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8 {
            return Poll::Ready(None);
        }
        // Check if force-close arrived.
        if force_close_fut.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        // Drive the wrapped future.
        fut.as_mut().poll(cx).map(Some)
    })
    .await
}

/// Minimal `text/plain` response for server-hop terminal outcomes
/// (handler panic → 500, request budget deadline → 503).
fn hop_error_response(version: Version, status: u16, body: &str) -> Response {
    Response {
        status,
        reason: String::new(),
        version,
        headers: vec![(
            "content-type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        )],
        body: body.as_bytes().to_vec(),
        trailers: Vec::new(),
    }
}

fn invalid_upgrade_error(message: &'static str) -> HttpError {
    HttpError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    ))
}

fn headers_have_token(headers: &[(String, String)], name: &str, expected: &[u8]) -> bool {
    let mut found = false;
    for (header_name, value) in headers {
        if !header_name.eq_ignore_ascii_case(name) {
            continue;
        }
        for_each_header_value_token(value.as_bytes(), |token| {
            if token.eq_ignore_ascii_case(expected) {
                found = true;
            }
        });
    }
    found
}

fn headers_have_exact_token(headers: &[(String, String)], name: &str, expected: &str) -> bool {
    headers
        .iter()
        .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .any(|token| token == expected)
}

/// Whether the client offered the extension a handoff negotiated. Offers carry
/// parameters (`permessage-deflate; client_max_window_bits`), so only the
/// extension token is compared; the negotiated parameters were validated against
/// the offer when the response was built.
fn request_offers_websocket_extension(headers: &[(String, String)], negotiated: &str) -> bool {
    let token = negotiated.split(';').next().unwrap_or("").trim();
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-extensions"))
        .flat_map(|(_, value)| value.split(','))
        .filter_map(|offer| offer.split(';').next())
        .any(|offer| offer.trim().eq_ignore_ascii_case(token))
}

fn single_header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let mut values = headers
        .iter()
        .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str());
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn validate_upgrade_handoff(
    request: &Request,
    response: &Response,
    upgrade: &Http1Upgrade,
) -> Result<(), HttpError> {
    if request.version != Version::Http11 || request.method != Method::Get {
        return Err(invalid_upgrade_error(
            "WebSocket handoff requires an HTTP/1.1 GET request",
        ));
    }
    if !request.body.is_empty() || !request.trailers.is_empty() {
        return Err(invalid_upgrade_error(
            "WebSocket handoff request must not carry a body or trailers",
        ));
    }
    if request
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(invalid_upgrade_error(
            "WebSocket handoff request must not use transfer encoding",
        ));
    }
    if !headers_have_token(&request.headers, "connection", b"upgrade")
        || !headers_have_token(&request.headers, "upgrade", b"websocket")
    {
        return Err(invalid_upgrade_error(
            "WebSocket handoff request is missing Upgrade tokens",
        ));
    }
    let Some(websocket_key) = single_header_value(&request.headers, "sec-websocket-key") else {
        return Err(invalid_upgrade_error(
            "WebSocket handoff request has invalid version or key headers",
        ));
    };
    if single_header_value(&request.headers, "sec-websocket-version") != Some("13") {
        return Err(invalid_upgrade_error(
            "WebSocket handoff request has invalid version or key headers",
        ));
    }
    let valid_key = base64::engine::general_purpose::STANDARD
        .decode(websocket_key)
        .is_ok_and(|decoded| decoded.len() == 16);
    if !valid_key {
        return Err(invalid_upgrade_error(
            "WebSocket handoff request key must decode to exactly 16 bytes",
        ));
    }
    let expected_accept = crate::net::websocket::compute_accept_key(websocket_key);
    if !upgrade.websocket_negotiation_matches(response)
        || upgrade.expected_protocol().is_some_and(|protocol| {
            !headers_have_exact_token(&request.headers, "sec-websocket-protocol", protocol)
        })
        || upgrade
            .expected_extensions()
            .iter()
            .any(|extension| !request_offers_websocket_extension(&request.headers, extension))
    {
        return Err(invalid_upgrade_error(
            "WebSocket handoff response protocol or extensions do not match the negotiation",
        ));
    }
    let response_has_framing = response.headers.iter().any(|(name, _)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("content-length")
    });
    if response.status != 101
        || !response.body.is_empty()
        || !response.trailers.is_empty()
        || response_has_framing
        || !headers_have_token(&response.headers, "connection", b"upgrade")
        || headers_have_token(&response.headers, "connection", b"close")
        || !headers_have_token(&response.headers, "upgrade", b"websocket")
        || single_header_value(&response.headers, "sec-websocket-accept")
            != Some(expected_accept.as_str())
    {
        return Err(invalid_upgrade_error(
            "WebSocket handoff requires a complete empty 101 response",
        ));
    }
    Ok(())
}

fn read_error(err: HttpError, continue_sent: bool) -> ReadOutcome {
    ReadOutcome::Read {
        item: Some(Err(err)),
        continue_sent,
    }
}

fn poll_pending_expectation_flush<T>(
    cx: &mut Context<'_>,
    framed: &mut Framed<T, Http1Codec>,
    pending_expectation_flush: &mut Option<ExpectationAction>,
    continue_sent: bool,
) -> Option<Poll<ReadOutcome>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let action = (*pending_expectation_flush)?;
    match framed.poll_flush(cx).map_err(HttpError::Io) {
        Poll::Pending => Some(Poll::Pending),
        Poll::Ready(Err(err)) => Some(Poll::Ready(read_error(err, continue_sent))),
        Poll::Ready(Ok(())) => {
            *pending_expectation_flush = None;
            if action == ExpectationAction::Reject {
                Some(Poll::Ready(ReadOutcome::ExpectationRejected))
            } else {
                None
            }
        }
    }
}

fn poll_request_expectation<T>(
    cx: &mut Context<'_>,
    framed: &mut Framed<T, Http1Codec>,
    pending_expectation_flush: &mut Option<ExpectationAction>,
    handled_expectation: &mut bool,
) -> Option<ExpectationStep>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    if *handled_expectation {
        return None;
    }

    let preview = match preview_request_head(framed.codec(), framed.read_buffer()) {
        Ok(preview) => preview,
        Err(err) => {
            return Some(ExpectationStep::Return(Poll::Ready(read_error(
                err,
                *handled_expectation,
            ))));
        }
    }?;

    let action = classify_expectation_from_pairs(preview.version, preview.headers());
    if action == ExpectationAction::None || !request_expects_body_header_pairs(preview.headers()) {
        return None;
    }

    let response = expectation_response(preview.version, action)
        .expect("expectation action should build a response");
    if let Err(err) = framed.send(response) {
        return Some(ExpectationStep::Return(Poll::Ready(read_error(
            err,
            *handled_expectation,
        ))));
    }
    *handled_expectation = true;

    Some(match framed.poll_flush(cx).map_err(HttpError::Io) {
        Poll::Pending => {
            *pending_expectation_flush = Some(action);
            ExpectationStep::Return(Poll::Pending)
        }
        Poll::Ready(Err(err)) => {
            ExpectationStep::Return(Poll::Ready(read_error(err, *handled_expectation)))
        }
        Poll::Ready(Ok(())) => {
            if action == ExpectationAction::Reject {
                ExpectationStep::Return(Poll::Ready(ReadOutcome::ExpectationRejected))
            } else {
                ExpectationStep::ContinueLoop
            }
        }
    })
}

fn classify_expectation(req: &Request) -> ExpectationAction {
    classify_expectation_from_parts(req.version, &req.headers)
}

fn classify_expectation_from_parts(
    version: Version,
    headers: &[(String, String)],
) -> ExpectationAction {
    classify_expectation_from_pairs(
        version,
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes())),
    )
}

fn classify_expectation_from_pairs<'a>(
    version: Version,
    headers: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> ExpectationAction {
    let mut saw_expect = false;
    let mut saw_continue = false;
    let mut saw_unsupported = false;

    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("expect") {
            continue;
        }
        saw_expect = true;
        for_each_header_value_token(value, |token| {
            if token.eq_ignore_ascii_case(b"100-continue") {
                saw_continue = true;
            } else {
                saw_unsupported = true;
            }
        });
    }

    if !saw_expect {
        return ExpectationAction::None;
    }

    if saw_unsupported || version != Version::Http11 {
        return ExpectationAction::Reject;
    }

    if saw_continue {
        return ExpectationAction::Continue;
    }

    // Expect header present but no token content: treat as unsupported.
    ExpectationAction::Reject
}

fn request_expects_body(req: &Request) -> bool {
    request_expects_body_headers(&req.headers) || !req.body.is_empty()
}

fn request_expects_body_headers(headers: &[(String, String)]) -> bool {
    request_expects_body_header_pairs(
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes())),
    )
}

fn request_expects_body_header_pairs<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> bool {
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            let value = trim_ows_bytes(value);
            if !value.is_empty()
                && value.iter().all(u8::is_ascii_digit)
                && std::str::from_utf8(value)
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok())
                    .is_some_and(|len| len > 0)
            {
                return true;
            }
            continue;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            let mut chunked = false;
            for_each_header_value_token(value, |token| {
                chunked |= token.eq_ignore_ascii_case(b"chunked");
            });
            return chunked;
        }
    }
    false
}

fn expectation_response(version: Version, action: ExpectationAction) -> Option<Response> {
    let mut response = match action {
        ExpectationAction::None => return None,
        ExpectationAction::Continue => Response::new(100, default_reason(100), Vec::new()),
        ExpectationAction::Reject => Response::new(417, default_reason(417), Vec::new()),
    };
    finalize_response_persistence(version, &mut response, action == ExpectationAction::Reject);
    Some(response)
}

/// Determine whether the connection should close after this request.
///
/// Considers: explicit Connection header, HTTP version defaults,
/// server keep-alive config, and request limits.
fn should_close_connection(req: &Request, config: &Http1Config, state: &ConnectionState) -> bool {
    should_close_connection_parts(req.version, &req.headers, config, state)
}

fn should_close_connection_parts(
    version: Version,
    headers: &[(String, String)],
    config: &Http1Config,
    state: &ConnectionState,
) -> bool {
    // If keep-alive is disabled server-wide, always close
    if !config.keep_alive {
        return true;
    }

    // If we'll hit the request limit after this request, close
    if let Some(max) = config.max_requests_per_connection {
        if state.requests_served + 1 >= max {
            return true;
        }
    }

    let mut has_keep_alive = false;
    let mut has_close = false;

    // Check explicit Connection header from client (RFC 9110 §7.6.1: comma-separated tokens)
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("connection") {
            for_each_header_value_token(value.as_bytes(), |token| {
                if token.eq_ignore_ascii_case(b"close") {
                    has_close = true;
                } else if token.eq_ignore_ascii_case(b"keep-alive") {
                    has_keep_alive = true;
                }
            });
        }
    }

    if has_close {
        return true;
    }

    if has_keep_alive {
        return false;
    }

    // HTTP/1.0 defaults to close; HTTP/1.1 defaults to keep-alive
    version == Version::Http10
}

/// Add a `Connection: close` header to the response if not already present.
fn add_connection_close(resp: &mut Response) {
    let mut replaced = false;
    resp.headers.retain_mut(|(name, value)| {
        if name.eq_ignore_ascii_case("connection") {
            if replaced {
                false
            } else {
                "close".clone_into(value);
                replaced = true;
                true
            }
        } else {
            true
        }
    });
    if !replaced {
        resp.headers
            .push(("Connection".to_owned(), "close".to_owned()));
    }
}

/// Add a `Connection: keep-alive` header to the response if not already present.
fn add_connection_keep_alive(resp: &mut Response) {
    let mut replaced = false;
    resp.headers.retain_mut(|(name, value)| {
        if name.eq_ignore_ascii_case("connection") {
            if replaced {
                false
            } else {
                "keep-alive".clone_into(value);
                replaced = true;
                true
            }
        } else {
            true
        }
    });
    if !replaced {
        resp.headers
            .push(("Connection".to_owned(), "keep-alive".to_owned()));
    }
}

/// Check if the response explicitly requests closing the connection.
fn response_requests_close(resp: &Response) -> bool {
    for (name, value) in &resp.headers {
        if name.eq_ignore_ascii_case("connection") {
            let mut requests_close = false;
            for_each_header_value_token(value.as_bytes(), |token| {
                if token.eq_ignore_ascii_case(b"close") {
                    requests_close = true;
                }
            });
            if requests_close {
                return true;
            }
        }
    }
    false
}

fn replace_or_insert_header(resp: &mut Response, header_name: &str, header_value: String) {
    let mut replaced = false;
    resp.headers.retain_mut(|(name, value)| {
        if name.eq_ignore_ascii_case(header_name) {
            if replaced {
                false
            } else {
                header_value.clone_into(value);
                replaced = true;
                true
            }
        } else {
            true
        }
    });
    if !replaced {
        resp.headers.push((header_name.to_owned(), header_value));
    }
}

fn remove_header(resp: &mut Response, header_name: &str) -> bool {
    let before = resp.headers.len();
    resp.headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case(header_name));
    resp.headers.len() != before
}

/// Whether a handler's response to a non-HEAD request declares a
/// Content-Length its body does not carry. Written as is, a keep-alive client
/// would take the difference from the next response (or wait for bytes that
/// never come), so the server answers 500 and closes instead. Bodyless
/// statuses carry no body whatever they declare (RFC 9112 6.3).
fn declared_length_mismatches_body(resp: &Response) -> bool {
    if (100..=199).contains(&resp.status) || resp.status == 204 || resp.status == 304 {
        return false;
    }
    resp.headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .any(|(_, value)| {
            let digits = value.trim();
            !digits.bytes().all(|byte| byte.is_ascii_digit())
                || digits.parse::<usize>().ok() != Some(resp.body.len())
        })
}

fn suppress_response_body_for_head(resp: &mut Response) {
    let body_len = resp.body.len();
    let has_content_length = resp
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
    let had_transfer_encoding = remove_header(resp, "transfer-encoding");
    let _ = remove_header(resp, "trailer");

    // RFC 9110 §9.3.2: a HEAD response MUST contain the same Content-Length
    // that would appear in the equivalent GET response.  Only synthesize the
    // header when the handler did not already declare one; when the handler
    // set Content-Length explicitly, trust it as the authoritative GET length.
    if !has_content_length && (body_len != 0 || had_transfer_encoding) {
        replace_or_insert_header(resp, "Content-Length", body_len.to_string());
    }

    resp.trailers.clear();
    resp.body.clear();
}

/// Align the response version/connection headers with the actual socket policy.
fn finalize_response_persistence(
    request_version: Version,
    resp: &mut Response,
    close_after: bool,
) -> bool {
    if request_version == Version::Http10 {
        resp.version = Version::Http10;
    }

    // No Date header is generated. RFC 9110 §6.6.1 forbids one from a server
    // without a clock that approximates UTC, and this server's clock is the
    // runtime's (wall_now: timer or process-relative time, virtual in the
    // lab), not UTC: formatting it gave dates in January 1970. A handler that
    // has a UTC clock can set Date itself with format_unix_nanos_http_date.

    let close_after = close_after || response_requests_close(resp);
    if close_after {
        add_connection_close(resp);
        return true;
    }

    if request_version == Version::Http10 {
        add_connection_keep_alive(resp);
    }

    false
}

#[cfg(test)]
#[path = "server_inline_tests.rs"]
mod tests;
