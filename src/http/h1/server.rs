//! HTTP/1.1 server connection handler.
//!
//! [`Http1Server`] wraps a service and drives an HTTP/1.1 connection,
//! reading requests and writing responses using [`Http1Codec`] over a
//! framed transport. Supports keep-alive, request limits, idle timeouts,
//! and graceful shutdown.

use crate::bytes::{Buf, BytesMut};
use crate::codec::{Encoder, Framed};
use crate::cx::Cx;
use crate::http::body::{Body, Frame};
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
use crate::tracing_compat::error;
use crate::types::{Budget, CancelKind};
use crate::web::WebBodyDiagnostic;
use crate::web::request_region::{
    HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC, ServerHopOutcome, ServerProducerCancellation,
    ServerRequestRegion, classify_server_producer_cancellation, derive_request_budget,
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
    /// Idle timeout between requests on a keep-alive connection.
    /// `None` means no timeout (wait forever).
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

fn single_host_header_value(headers: &[(String, String)]) -> Result<Option<&str>, String> {
    let mut host_value = None;
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("host") {
            continue;
        }
        if host_value.is_some() {
            return Err("multiple Host headers".to_string());
        }
        host_value = Some(value.as_str());
    }
    Ok(host_value)
}

/// br-asupersync-scxixg: validate the request's `Host` header against
/// the host policy. Returns `Ok(())` if validation passes (or is
/// disabled); `Err(host_value)` carrying the offending host string
/// for logging if the header is missing or not allow-listed.
pub(crate) fn validate_host_header(
    headers: &[(String, String)],
    host_policy: &HostPolicy,
) -> Result<(), String> {
    match host_policy {
        HostPolicy::AllowAll => single_host_header_value(headers).map(|_| ()),
        HostPolicy::RejectUnknown => {
            // Reject all requests - most secure default
            let host_value = single_host_header_value(headers)?;
            Err(host_value.unwrap_or("").to_string())
        }
        HostPolicy::AllowList(allow_list) => {
            if allow_list.is_empty() {
                // br-asupersync-scxixg: Empty allow-list MUST reject all hosts to prevent
                // Host header injection attacks. Previous behavior of accepting all hosts
                // with an empty list was a fail-open security vulnerability.
                let host_value = single_host_header_value(headers)?;
                return Err(host_value.unwrap_or("").to_string());
            }
            let host_value = single_host_header_value(headers)?;
            let Some(host_value) = host_value else {
                // RFC 7230 §5.4: HTTP/1.1 requests MUST include Host. Reject.
                return Err(String::new());
            };
            let Some(parsed) = parse_host_header_host(host_value) else {
                return Err(host_value.to_string());
            };
            if allow_list
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&parsed))
            {
                Ok(())
            } else {
                Err(parsed)
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

/// One-shot action executed after an HTTP/1 upgrade response is fully flushed.
///
/// The action is intentionally native-listener scoped: it receives the same
/// TCP stream owned by the listener connection task plus every byte the HTTP
/// codec read beyond the request. It must not spawn or detach its own owner.
pub struct Http1Upgrade {
    driver: Box<
        dyn FnOnce(Cx, crate::net::tcp::stream::TcpStream, BytesMut) -> Http1UpgradeFuture
            + Send
            + 'static,
    >,
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
            driver: Box::new(move |cx, io, read_ahead| Box::pin(driver(cx, io, read_ahead))),
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
        (self.driver)(cx, io, read_ahead)
    }

    pub(crate) fn websocket_negotiation_matches(&self, response: &Response) -> bool {
        let protocols = response
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-protocol"))
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>();
        let has_extensions = response
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-extensions"));

        protocols.len() <= 1
            && protocols.first().copied() == self.expected_protocol.as_deref()
            && !has_extensions
            && self.expected_extensions.is_empty()
    }

    pub(crate) fn expected_protocol(&self) -> Option<&str> {
        self.expected_protocol.as_deref()
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
    handler: F,
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
            handler,
            config: Http1Config::default(),
            shutdown_signal: None,
            in_flight_requests: None,
        }
    }

    /// Create an upgrade-aware response server with custom configuration.
    pub fn with_config_upgradeable(handler: F, config: Http1Config) -> Self {
        Self {
            handler,
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
    ) -> Option<ReadOutcome>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let read_future = async {
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
                    if self.should_stop_reading(cx, shutdown_fut.as_mut()) {
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
            let now = Cx::current()
                .and_then(|cx| cx.timer_driver())
                .map_or_else(wall_now, |timer| timer.now());
            timeout(now, idle_timeout, read_future).await.ok()
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
            .serve_connection_with_peer_addr(io, peer_addr, false)
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
        self.serve_connection_with_peer_addr(io, peer_addr, true)
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn serve_connection_with_peer_addr<T>(
        self,
        io: T,
        peer_addr: Option<SocketAddr>,
        admit_upgrade: bool,
    ) -> Result<Http1ServeOutcome<T>, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let codec = Http1Codec::new()
            .max_headers_size(self.config.max_headers_size)
            .max_body_size(self.config.max_body_size);
        let mut framed = Framed::new(io, codec);
        let mut state = ConnectionState::new(
            Cx::current()
                .and_then(|cx| cx.timer_driver())
                .map_or_else(wall_now, |timer| timer.now()),
        );

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

            if Cx::with_current(|cx| cx.checkpoint().is_err()).unwrap_or(false) {
                state.phase = ConnectionPhase::Closing;
                break;
            }

            // Check request limit before reading next request
            if state.exceeded_request_limit(self.config.max_requests_per_connection) {
                state.phase = ConnectionPhase::Closing;
                break;
            }

            let now = Cx::current()
                .and_then(|cx| cx.timer_driver())
                .map_or_else(wall_now, |timer| timer.now());

            // Check idle timeout
            if state.exceeded_idle_timeout(self.config.idle_timeout, now) {
                state.phase = ConnectionPhase::Closing;
                break;
            }

            state.phase = ConnectionPhase::Reading;

            let Some(read_outcome) = self.read_next(&mut framed, &state).await else {
                state.phase = ConnectionPhase::Closing;
                break;
            };

            let (req, continue_sent) = match read_outcome {
                ReadOutcome::ExpectationRejected => {
                    state.requests_served += 1;
                    state.last_request_at = Cx::current()
                        .and_then(|cx| cx.timer_driver())
                        .map_or_else(wall_now, |timer| timer.now());
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
                Some(Err(e)) => return Err(e),
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
            // BEFORE the handler runs. A request whose Host header isn't
            // on the list (or is missing entirely on HTTP/1.1) gets a
            // 421 Misdirected Request and the connection closes — the
            // handler never sees the request, eliminating the host-
            // injection attack surface for absolute-URL emission /
            // OAuth redirect_uri / cache-key computation.
            if let Err(rejected_host) =
                validate_host_header(&req.headers, &self.config.allowed_hosts)
            {
                state.phase = ConnectionPhase::Writing;
                let body_msg = if rejected_host.is_empty() {
                    "Missing required Host header".to_string()
                } else {
                    format!("Host '{rejected_host}' not in allowed-hosts allow-list")
                };
                // br-asupersync-t9yqht: 421 Misdirected Request per
                // RFC 7540 §9.1.2 — semantically the right code for
                // "the server is unable to produce a response for the
                // combination of the URI and HOST header (effective
                // request URI) presented".
                let reject_resp = Response {
                    status: 421,
                    reason: String::new(),
                    version: req.version,
                    headers: vec![
                        (
                            "content-type".to_string(),
                            "text/plain; charset=utf-8".to_string(),
                        ),
                        ("connection".to_string(), "close".to_string()),
                    ],
                    body: body_msg.into_bytes(),
                    trailers: Vec::new(),
                };
                framed.send(reject_resp)?;
                poll_fn(|cx| {
                    if Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                        return Poll::Ready(Err(HttpError::Io(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "connection cancelled",
                        ))));
                    }
                    framed.poll_flush(cx).map_err(HttpError::Io)
                })
                .await?;
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
                poll_fn(|cx| {
                    if Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                        return Poll::Ready(Err(HttpError::Io(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "connection cancelled",
                        ))));
                    }
                    framed.poll_flush(cx).map_err(HttpError::Io)
                })
                .await?;
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
                poll_fn(|cx| {
                    if Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                        return Poll::Ready(Err(HttpError::Io(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "connection cancelled",
                        ))));
                    }
                    framed.poll_flush(cx).map_err(HttpError::Io)
                })
                .await?;
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
            let request_now = Cx::current()
                .and_then(|cx| cx.timer_driver())
                .map_or_else(wall_now, |timer| timer.now());
            let conn_cx = Cx::current();
            let base_budget = conn_cx.as_ref().map_or(Budget::INFINITE, Cx::budget);
            let header_timeout = parse_request_timeout_header(&req.headers);
            let (request_budget, budget_source) = derive_request_budget(
                base_budget,
                request_now,
                self.config.request_timeout,
                header_timeout,
                self.config.request_timeout_header_cap,
            );

            let upgrade_request = req.clone();
            let mut forced_close = false;
            let output = match ServerRequestRegion::mint("h1", request_budget, request_now) {
                Some(region) => {
                    // Race the whole hop against ForceClosing so slow
                    // handlers don't block shutdown (drop is the backstop).
                    let hop = race_force_close(
                        self.shutdown_signal.as_ref(),
                        region.run_with_protocol_drain(
                            budget_source,
                            conn_cx,
                            self.config.request_drain_grace,
                            (self.handler)(req),
                        ),
                    )
                    .await;
                    match hop {
                        None => {
                            // Force-close interrupted the handler.
                            state.phase = ConnectionPhase::Closing;
                            break;
                        }
                        Some(ServerHopOutcome::Ok(resp)) => resp.into_h1_response(),
                        Some(ServerHopOutcome::Cancelled | ServerHopOutcome::ConnectionLost) => {
                            // The connection is cancelled or the peer is
                            // gone: nothing useful can be written back.
                            state.requests_served += 1;
                            state.phase = ConnectionPhase::Closing;
                            break;
                        }
                        Some(ServerHopOutcome::Panicked(_)) => {
                            // Panic isolation: the server survives; this
                            // connection closes defensively after the 500.
                            forced_close = true;
                            Http1Response::new(hop_error_response(
                                request_version,
                                500,
                                "Internal Server Error",
                            ))
                        }
                        Some(ServerHopOutcome::DeadlineExceeded) => {
                            // The request was fully read and the response
                            // framing is clean, so keep-alive may continue.
                            Http1Response::new(hop_error_response(
                                request_version,
                                503,
                                HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC,
                            ))
                        }
                    }
                }
                None => {
                    // Legacy path: no runtime context on this thread.
                    let Some(resp) =
                        race_force_close(self.shutdown_signal.as_ref(), (self.handler)(req)).await
                    else {
                        // Force-close interrupted the handler.
                        state.phase = ConnectionPhase::Closing;
                        break;
                    };
                    resp.into_h1_response()
                }
            };

            let Http1Response {
                response: mut resp,
                upgrade,
            } = output;

            if request_method == Method::Head {
                suppress_response_body_for_head(&mut resp);
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
                    if !admit_upgrade {
                        return Err(invalid_upgrade_error(
                            "HTTP/1 upgrade action requires an upgrade-aware listener",
                        ));
                    }
                    if draining {
                        return Err(invalid_upgrade_error(
                            "HTTP/1 upgrade refused after listener drain began",
                        ));
                    }
                    validate_upgrade_handoff(&upgrade_request, &resp, &upgrade)?;
                    Some(upgrade)
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
            let flush = poll_fn(|cx| {
                if Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                    return Poll::Ready(Err(HttpError::Io(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "connection cancelled",
                    ))));
                }
                framed.poll_flush(cx).map_err(HttpError::Io)
            });
            let Some(flush_result) = race_force_close(self.shutdown_signal.as_ref(), flush).await
            else {
                return Err(HttpError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "connection force-closed before response flush",
                )));
            };
            flush_result?;

            state.requests_served += 1;
            state.last_request_at = Cx::current()
                .and_then(|cx| cx.timer_driver())
                .map_or_else(wall_now, |timer| timer.now());

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
        let _ = io.shutdown().await;

        Ok(Http1ServeOutcome::Closed(state))
    }
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
    #[allow(clippy::too_many_lines)]
    pub async fn serve_with_peer_addr<T>(
        self,
        cx: &Cx,
        mut io: T,
        peer_addr: Option<SocketAddr>,
    ) -> Result<ConnectionState, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut read_buffer = BytesMut::with_capacity(8192);
        let mut state = ConnectionState::new(connection_now(cx));

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
            let Some((head, body_kind)) =
                read_streaming_request_head(cx, &mut io, &mut read_buffer, &self.config).await?
            else {
                state.phase = ConnectionPhase::Closing;
                break;
            };
            let _in_flight = InFlightRequestGuard::acquire(self.in_flight_requests.as_ref());

            if let Err(rejected_host) =
                validate_host_header(&head.headers, &self.config.allowed_hosts)
            {
                let body = if rejected_host.is_empty() {
                    "Missing required Host header".to_owned()
                } else {
                    format!("Host '{rejected_host}' not in allowed-hosts allow-list")
                };
                let response = Response {
                    status: 421,
                    reason: String::new(),
                    version: head.version,
                    headers: vec![
                        (
                            "content-type".to_owned(),
                            "text/plain; charset=utf-8".to_owned(),
                        ),
                        ("connection".to_owned(), "close".to_owned()),
                    ],
                    body: body.into_bytes(),
                    trailers: Vec::new(),
                };
                state.phase = ConnectionPhase::Writing;
                write_streaming_response(cx, &mut io, response).await?;
                state.requests_served += 1;
                state.phase = ConnectionPhase::Closing;
                break;
            }

            let expectation = classify_expectation_from_parts(head.version, &head.headers);
            if expectation == ExpectationAction::Reject {
                let response = expectation_response(head.version, expectation)
                    .expect("rejected expectation must have a response");
                state.phase = ConnectionPhase::Writing;
                write_streaming_response(cx, &mut io, response).await?;
                state.requests_served += 1;
                state.phase = ConnectionPhase::Closing;
                break;
            }
            if expectation == ExpectationAction::Continue && !body_kind.is_empty() {
                let response = expectation_response(head.version, expectation)
                    .expect("100-continue expectation must have a response");
                state.phase = ConnectionPhase::Writing;
                write_streaming_response(cx, &mut io, response).await?;
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
            let region =
                ServerRequestRegion::mint_from_connection("h1", request_budget, request_now, cx);
            let request_cx = region.cx().clone();
            let body_cx = request_cx.clone();
            let (writer, body) = IncomingRequestBody::channel_with_limits(
                &request_cx,
                body_kind,
                self.config.incoming_body_frame_capacity,
                self.config.incoming_body_queued_bytes,
            );
            let request = StreamingServerRequest {
                head,
                peer_addr,
                body,
            };

            state.phase = ConnectionPhase::Processing;
            let handler = race_force_close(
                self.shutdown_signal.as_ref(),
                region.run_with_protocol_drain(
                    budget_source,
                    Some(cx.clone()),
                    self.config.request_drain_grace,
                    (self.handler)(request_cx, request),
                ),
            );
            let body_driver = drive_incoming_body(
                &body_cx,
                &mut io,
                &mut read_buffer,
                writer.max_body_size(u64::try_from(self.config.max_body_size).unwrap_or(u64::MAX)),
                &self.config,
            );

            let (hop, writer) =
                match join_streaming_handler_and_body(cx, handler, body_driver, &self.config).await
                {
                    Ok(Some(joined)) => joined,
                    Ok(None) => {
                        state.phase = ConnectionPhase::Closing;
                        break;
                    }
                    Err(body_error) => {
                        record_incoming_body_failure(&body_error);
                        if let Some(mut response) =
                            incoming_body_failure_response(request_version, &body_error)
                        {
                            add_connection_close(&mut response);
                            if request_method == Method::Head {
                                suppress_response_body_for_head(&mut response);
                            }
                            state.phase = ConnectionPhase::Writing;
                            write_streaming_response(cx, &mut io, response).await?;
                            state.requests_served += 1;
                        }
                        state.phase = ConnectionPhase::Closing;
                        break;
                    }
                };
            if validate_unread_drain(writer.drain_progress(), &self.config).is_err() {
                state.phase = ConnectionPhase::Closing;
                break;
            }

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
            if request_method == Method::Head {
                suppress_response_body_for_head(&mut response);
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
            write_streaming_response(cx, &mut io, response).await?;
            state.requests_served += 1;
            state.last_request_at = connection_now(cx);
            if close_after {
                state.phase = ConnectionPhase::Closing;
                break;
            }
        }

        let _ = io.shutdown().await;
        Ok(state)
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
                let guard = LiveSseCancelGuard::new(stream, request_cx);
                let mut response = Http1ProducedResponse::chunked(
                    capacity,
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

    if cx.checkpoint().is_err()
        || shutdown_signal
            .as_ref()
            .is_some_and(ShutdownSignal::is_shutting_down)
        || state.exceeded_request_limit(config.max_requests_per_connection)
        || state.exceeded_idle_timeout(config.idle_timeout, connection_now(cx))
    {
        state.phase = ConnectionPhase::Closing;
        let _ = io.shutdown().await;
        return Ok(state);
    }

    state.phase = ConnectionPhase::Reading;
    let Some((head, body_kind)) =
        read_streaming_request_head(cx, &mut io, &mut read_buffer, &config).await?
    else {
        state.phase = ConnectionPhase::Closing;
        let _ = io.shutdown().await;
        return Ok(state);
    };
    let early_request_method = head.method.clone();
    let _in_flight = InFlightRequestGuard::acquire(in_flight_requests.as_ref());

    if let Err(rejected_host) = validate_host_header(&head.headers, &config.allowed_hosts) {
        let body = if rejected_host.is_empty() {
            "Missing required Host header".to_owned()
        } else {
            format!("Host '{rejected_host}' not in allowed-hosts allow-list")
        };
        let mut response = Response {
            status: 421,
            reason: String::new(),
            version: head.version,
            headers: vec![
                (
                    "content-type".to_owned(),
                    "text/plain; charset=utf-8".to_owned(),
                ),
                ("connection".to_owned(), "close".to_owned()),
            ],
            body: body.into_bytes(),
            trailers: Vec::new(),
        };
        if early_request_method == Method::Head {
            suppress_response_body_for_head(&mut response);
        }
        state.phase = ConnectionPhase::Writing;
        write_streaming_response(cx, &mut io, response).await?;
        state.requests_served = 1;
        state.phase = ConnectionPhase::Closing;
        let _ = io.shutdown().await;
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
        write_streaming_response(cx, &mut io, response).await?;
        state.requests_served = 1;
        state.phase = ConnectionPhase::Closing;
        let _ = io.shutdown().await;
        return Ok(state);
    }
    if expectation == ExpectationAction::Continue && !body_kind.is_empty() {
        let response = expectation_response(head.version, expectation)
            .expect("100-continue expectation must have a response");
        state.phase = ConnectionPhase::Writing;
        write_streaming_response(cx, &mut io, response).await?;
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
        let (produced, writer) =
            match join_streaming_handler_and_body(&request_cx, handler, body_driver, &config).await
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
                    if let Some(mut response) =
                        incoming_body_failure_response(request_version, &body_error)
                    {
                        add_connection_close(&mut response);
                        if request_method == Method::Head {
                            suppress_response_body_for_head(&mut response);
                        }
                        head_committed.store(true, Ordering::Release);
                        return write_streaming_response(&request_cx, &mut io, response).await;
                    }
                    return Err(HttpError::Io(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        body_error,
                    )));
                }
            };
        validate_unread_drain(writer.drain_progress(), &config).map_err(|error| {
            HttpError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })?;

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
            return write_streaming_response(&request_cx, &mut io, response).await;
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
            return write_streaming_response(&request_cx, &mut io, response).await;
        }

        if request_method == Method::Head {
            let response = match policy {
                ProducedResponsePolicy::Sse => live_sse_head_only_response(request_version),
                ProducedResponsePolicy::Generic => produced_head_only_response(produced)?,
            };
            head_committed.store(true, Ordering::Release);
            return write_streaming_response(&request_cx, &mut io, response).await;
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
                write_streaming_response(cx, &mut io, response).await
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
                write_streaming_response(cx, &mut io, response).await
            } else {
                error!(
                    diagnostic = "ASUP-E501",
                    "[ASUP-E501] h1 response producer exceeded its request-region deadline after head commitment"
                );
                Ok(())
            }
        }
    };
    let _ = io.shutdown().await;
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
        match guard
            .stream
            .send_next_h1_chunk(&guard.cx, &mut sender)
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
        Some("HTTP/1 produced-body client transport disconnected"),
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
    if let Err(error) = io.write_all(encoded_head.as_ref()).await {
        record_h1_body_diagnostic(
            WebBodyDiagnostic::ClientAbort,
            "client transport failed while writing the response head",
        );
        drain_producer_after_write_error(cx, producer.as_mut(), &mut producer_result, drain_grace)
            .await;
        return Err(HttpError::Io(error));
    }
    if let Err(error) = io.flush().await {
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
        let frame = poll_fn(|task_cx| {
            if producer_result.is_none()
                && let Poll::Ready(result) = producer.as_mut().poll(task_cx)
            {
                producer_result = Some(normalize_producer_result(result, &response.body));
            }
            Pin::new(&mut response.body).poll_frame(task_cx)
        })
        .await;
        let Some(frame) = frame else {
            let producer_result = match producer_result.take() {
                Some(result) => result,
                None => normalize_producer_result(producer.as_mut().await, &response.body),
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
            if let Err(error) = io.write_all(final_chunk.as_ref()).await {
                record_h1_body_diagnostic(
                    WebBodyDiagnostic::ClientAbort,
                    "client transport failed while writing the terminal chunk",
                );
                return Err(HttpError::Io(error));
            }
            if let Err(error) = io.flush().await {
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
                    None => normalize_producer_result(producer.as_mut().await, &response.body),
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

                if let Err(error) = io.write_all(encoded_frame.as_ref()).await {
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
                if let Err(error) = io.flush().await {
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
            io.write_all(encoded_frame.as_ref())
                .await
                .map_err(HttpError::Io)?;
            io.flush().await.map_err(HttpError::Io)
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
) -> Result<Option<(RequestHead, BodyKind)>, HttpError>
where
    T: AsyncRead + Unpin,
{
    loop {
        if let Some(head) =
            decode_streaming_request_head(buffer, config.max_headers_size, config.max_body_size)?
        {
            return Ok(Some(head));
        }
        if cx.checkpoint().is_err() {
            return Ok(None);
        }
        let mut chunk = [0_u8; 8192];
        let read = io.read(&mut chunk);
        let count = if let Some(idle_timeout) = config.idle_timeout {
            match timeout(connection_now(cx), idle_timeout, read).await {
                Ok(result) => result.map_err(HttpError::Io)?,
                Err(_) => return Ok(None),
            }
        } else {
            read.await.map_err(HttpError::Io)?
        };
        if count == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Err(HttpError::BadRequestLine);
        }
        buffer.extend_from_slice(&chunk[..count]);
    }
}

async fn write_streaming_response<T>(
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
    io.write_all(encoded.as_ref())
        .await
        .map_err(HttpError::Io)?;
    io.flush().await.map_err(HttpError::Io)
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
        let count = match io.read(&mut chunk).await {
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
            let writer = timeout(connection_now(cx), config.unread_body_drain_timeout, body)
                .await
                .map_err(|_| IncomingBodyError::DrainTimeout)??;
            Ok(Some((hop, writer)))
        }
        StreamingJoinFirst::Handler(None) => Ok(None),
    }
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

/// Races `fut` against the shutdown signal's ForceClosing phase.
///
/// Returns `None` when force-close interrupts the future (the future is
/// dropped — drop is the cancellation backstop for shutdown). With no
/// signal attached the future simply runs to completion.
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
    {
        return Err(invalid_upgrade_error(
            "WebSocket handoff response protocol does not match the negotiated protocol",
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
    use crate::http::body::{Body, HeaderMap, HeaderName, HeaderValue};
    use crate::http::h1::types::Method;
    use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
    use crate::runtime::RuntimeBuilder;
    use crate::web::sse::{SseEvent, StreamingSseError};
    use std::collections::VecDeque;
    use std::io;
    use std::num::NonZeroUsize;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    struct TestIo {
        read_data: Vec<u8>,
        written: Arc<Mutex<Vec<u8>>>,
        read_limit: usize,
        read_error: Option<io::ErrorKind>,
    }

    impl TestIo {
        fn new(read_data: Vec<u8>, written: Arc<Mutex<Vec<u8>>>) -> Self {
            Self {
                read_data,
                written,
                read_limit: usize::MAX,
                read_error: None,
            }
        }

        fn with_read_limit(mut self, read_limit: usize) -> Self {
            self.read_limit = read_limit.max(1);
            self
        }

        fn with_read_error(mut self, kind: io::ErrorKind) -> Self {
            self.read_error = Some(kind);
            self
        }
    }

    #[test]
    fn body_diagnostic_incoming_body_failures_preserve_safe_terminal_dispositions() {
        let too_large = incoming_body_failure_response(
            Version::Http11,
            &IncomingBodyError::BodyTooLarge {
                actual: Some(9),
                limit: 8,
            },
        )
        .expect("pre-head aggregate limit has a safe response");
        assert_eq!(too_large.status, 413);
        assert_eq!(
            too_large.body,
            b"[ASUP-E505] request body exceeds the configured limit"
        );

        let timeout =
            incoming_body_failure_response(Version::Http11, &IncomingBodyError::DrainTimeout)
                .expect("pre-head drain timeout has a safe response");
        assert_eq!(timeout.status, 408);
        assert_eq!(timeout.body, b"[ASUP-E508] request body drain timed out");

        let deadline = incoming_body_failure_response(
            Version::Http11,
            &IncomingBodyError::Cancelled {
                kind: CancelKind::Deadline,
            },
        )
        .expect("pre-head request deadline retains E501");
        assert_eq!(deadline.status, 503);
        assert_eq!(deadline.body, HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC.as_bytes());

        assert!(
            incoming_body_failure_response(Version::Http11, &IncomingBodyError::ClientAborted,)
                .is_none(),
            "client abort must remain close-only"
        );
        let disconnected =
            incoming_body_failure_response(Version::Http11, &IncomingBodyError::SourceDisconnected)
                .expect("pre-head internal producer loss has a safe response");
        assert_eq!(disconnected.status, 500);
        assert_eq!(disconnected.body, b"request body producer disconnected");

        let accounting =
            incoming_body_failure_response(Version::Http11, &IncomingBodyError::AccountingOverflow)
                .expect("pre-head accounting overflow is an internal response");
        assert_eq!(accounting.status, 500);
        assert!(!accounting.body.starts_with(b"[ASUP-E505]"));

        assert!(
            incoming_body_failure_response(
                Version::Http11,
                &IncomingBodyError::DrainLimitExceeded {
                    bytes: 9,
                    frames: 2,
                    frame_limit: 1,
                    byte_limit: 8,
                },
            )
            .is_none(),
            "drain-budget exhaustion must remain close-only"
        );
    }

    impl AsyncRead for TestIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(kind) = self.read_error {
                return Poll::Ready(Err(io::Error::from(kind)));
            }
            if self.read_data.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let n = buf
                .remaining()
                .min(self.read_data.len())
                .min(self.read_limit);
            buf.put_slice(&self.read_data[..n]);
            self.read_data.drain(..n);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, Clone)]
    struct WriteGateObservation {
        source_calls: usize,
        eof_calls: usize,
        written: Vec<u8>,
    }

    #[derive(Debug, Clone, Copy)]
    enum BodyWriteDisposition {
        GateOnceBeforeObservation { after_writes: usize },
        GateOnceAfterObservation { after_writes: usize },
        GateFlushOnceAfterObservation { after_writes: usize },
        FailAfter { after_writes: usize },
    }

    struct ScriptedWriteIo {
        read_data: Vec<u8>,
        written: Arc<Mutex<Vec<u8>>>,
        source_calls: Arc<AtomicUsize>,
        eof_calls: Arc<AtomicUsize>,
        observation: Arc<Mutex<Option<WriteGateObservation>>>,
        disposition: BodyWriteDisposition,
        head_complete: bool,
        accepted_body_writes: usize,
        gate_stage: u8,
    }

    impl ScriptedWriteIo {
        fn new(
            written: Arc<Mutex<Vec<u8>>>,
            source_calls: Arc<AtomicUsize>,
            eof_calls: Arc<AtomicUsize>,
            observation: Arc<Mutex<Option<WriteGateObservation>>>,
            disposition: BodyWriteDisposition,
        ) -> Self {
            Self {
                read_data: b"GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    .to_vec(),
                written,
                source_calls,
                eof_calls,
                observation,
                disposition,
                head_complete: false,
                accepted_body_writes: 0,
                gate_stage: 0,
            }
        }

        fn observe_gate(&self) {
            let observation = WriteGateObservation {
                source_calls: self.source_calls.load(Ordering::SeqCst),
                eof_calls: self.eof_calls.load(Ordering::SeqCst),
                written: self.written.lock().unwrap().clone(),
            };
            *self.observation.lock().unwrap() = Some(observation);
        }
    }

    impl AsyncRead for ScriptedWriteIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.read_data.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let count = buf.remaining().min(self.read_data.len());
            buf.put_slice(&self.read_data[..count]);
            self.read_data.drain(..count);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedWriteIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            task_cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if !self.head_complete {
                self.written.lock().unwrap().extend_from_slice(buf);
                let head_complete = self
                    .written
                    .lock()
                    .unwrap()
                    .windows(4)
                    .any(|window| window == b"\r\n\r\n");
                self.head_complete = head_complete;
                return Poll::Ready(Ok(buf.len()));
            }

            let after_writes = match self.disposition {
                BodyWriteDisposition::GateOnceBeforeObservation { after_writes }
                | BodyWriteDisposition::GateOnceAfterObservation { after_writes }
                | BodyWriteDisposition::GateFlushOnceAfterObservation { after_writes }
                | BodyWriteDisposition::FailAfter { after_writes } => after_writes,
            };
            if self.accepted_body_writes >= after_writes {
                match self.disposition {
                    BodyWriteDisposition::GateOnceBeforeObservation { .. }
                        if self.gate_stage == 0 =>
                    {
                        self.observe_gate();
                        self.gate_stage = 1;
                        task_cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    BodyWriteDisposition::GateOnceAfterObservation { .. }
                        if self.gate_stage == 0 =>
                    {
                        self.gate_stage = 1;
                        task_cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    BodyWriteDisposition::GateOnceAfterObservation { .. }
                        if self.gate_stage == 1 =>
                    {
                        self.observe_gate();
                        self.gate_stage = 2;
                        task_cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    BodyWriteDisposition::GateOnceAfterObservation { .. }
                        if self.gate_stage == 2 =>
                    {
                        let observed_calls = self
                            .observation
                            .lock()
                            .unwrap()
                            .as_ref()
                            .expect("capacity gate observation")
                            .source_calls;
                        assert_eq!(
                            self.source_calls.load(Ordering::SeqCst),
                            observed_calls,
                            "bounded producer progress must remain stable while the transport stays pending"
                        );
                        self.gate_stage = 3;
                    }
                    BodyWriteDisposition::GateOnceAfterObservation { .. } => {}
                    BodyWriteDisposition::GateFlushOnceAfterObservation { .. } => {}
                    BodyWriteDisposition::FailAfter { .. } => {
                        if self.gate_stage == 0 {
                            self.observe_gate();
                            self.gate_stage = 1;
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "scripted SSE client disconnect",
                        )));
                    }
                    BodyWriteDisposition::GateOnceBeforeObservation { .. } => {}
                }
            }

            self.written.lock().unwrap().extend_from_slice(buf);
            self.accepted_body_writes += 1;
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, task_cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if let BodyWriteDisposition::GateFlushOnceAfterObservation { after_writes } =
                self.disposition
                && self.accepted_body_writes >= after_writes
            {
                if self.gate_stage == 0 {
                    self.observe_gate();
                    self.gate_stage = 1;
                    task_cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                if self.gate_stage == 1 {
                    let observed_calls = self
                        .observation
                        .lock()
                        .unwrap()
                        .as_ref()
                        .expect("flush gate observation")
                        .source_calls;
                    assert_eq!(
                        self.source_calls.load(Ordering::SeqCst),
                        observed_calls,
                        "bounded producer progress must remain stable while flush stays pending"
                    );
                    self.gate_stage = 2;
                }
            }
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct CountingSseSource {
        events: VecDeque<SseEvent>,
        infinite: bool,
        fail_on_call: Option<usize>,
        source_calls: Arc<AtomicUsize>,
        eof_calls: Arc<AtomicUsize>,
        cancel_calls: Arc<AtomicUsize>,
    }

    impl CountingSseSource {
        fn finite(
            events: impl IntoIterator<Item = &'static str>,
            source_calls: Arc<AtomicUsize>,
            eof_calls: Arc<AtomicUsize>,
            cancel_calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                events: events
                    .into_iter()
                    .map(|data| SseEvent::default().data(data))
                    .collect(),
                infinite: false,
                fail_on_call: None,
                source_calls,
                eof_calls,
                cancel_calls,
            }
        }

        fn infinite(
            source_calls: Arc<AtomicUsize>,
            eof_calls: Arc<AtomicUsize>,
            cancel_calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                events: VecDeque::new(),
                infinite: true,
                fail_on_call: None,
                source_calls,
                eof_calls,
                cancel_calls,
            }
        }

        fn failing_after_two_events(
            source_calls: Arc<AtomicUsize>,
            eof_calls: Arc<AtomicUsize>,
            cancel_calls: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                events: ["first", "second"]
                    .into_iter()
                    .map(|data| SseEvent::default().data(data))
                    .collect(),
                infinite: false,
                fail_on_call: Some(3),
                source_calls,
                eof_calls,
                cancel_calls,
            }
        }
    }

    impl StreamingSseSource for CountingSseSource {
        fn next_event(&mut self, cx: &Cx) -> Result<Option<SseEvent>, StreamingSseError> {
            cx.checkpoint().map_err(|_| StreamingSseError::Cancelled)?;
            let call = self.source_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_on_call == Some(call) {
                return Err(StreamingSseError::Producer(
                    "scripted producer failure".to_owned(),
                ));
            }
            if let Some(event) = self.events.pop_front() {
                return Ok(Some(event));
            }
            if self.infinite {
                return Ok(Some(SseEvent::default().data(format!("event-{call}"))));
            }
            self.eof_calls.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }

        fn cancel(&mut self) {
            self.cancel_calls.fetch_add(1, Ordering::SeqCst);
            self.events.clear();
        }
    }

    fn response_body_bytes(response: &[u8]) -> &[u8] {
        let head_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("response head terminator")
            + 4;
        &response[head_end..]
    }

    fn localhost_server_config() -> Http1Config {
        Http1Config::default().host_policy(HostPolicy::AllowList(vec!["localhost".to_string()]))
    }

    #[test]
    fn streaming_sse_server_writes_first_chunk_before_source_eof() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let observation = Arc::new(Mutex::new(None));
        let source = CountingSseSource::finite(
            ["first", "second", "third"],
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );
        let io = ScriptedWriteIo::new(
            Arc::clone(&written),
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&observation),
            BodyWriteDisposition::GateOnceBeforeObservation { after_writes: 1 },
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect("serve live SSE response");

        assert_eq!(state.requests_served, 1);
        let observed = observation
            .lock()
            .unwrap()
            .clone()
            .expect("second body write reached causal gate");
        assert_eq!(observed.eof_calls, 0);
        assert!(observed.source_calls >= 2);
        assert_eq!(
            response_body_bytes(&observed.written),
            ChunkedEncoder::encode_chunk(b"data:first\n\n").as_ref()
        );

        let written = written.lock().unwrap().clone();
        let body = response_body_bytes(&written);
        let mut expected = Vec::new();
        for event in ["first", "second", "third"] {
            expected.extend_from_slice(
                ChunkedEncoder::encode_chunk(format!("data:{event}\n\n").as_bytes()).as_ref(),
            );
        }
        expected.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(body, expected);
        assert_eq!(eof_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn streaming_sse_server_real_tcp_delivers_multiple_chunks_before_disconnect() {
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let source = CountingSseSource::infinite(
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );

        let raw_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = raw_listener
            .local_addr()
            .expect("loopback listener address");
        let client = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            let mut client =
                std::net::TcpStream::connect(address).expect("connect loopback client");
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set client read timeout");
            client
                .write_all(b"GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .expect("write live SSE request");

            let first = ChunkedEncoder::encode_chunk(b"data:event-1\n\n");
            let second = ChunkedEncoder::encode_chunk(b"data:event-2\n\n");
            let mut received = Vec::new();
            while !received
                .windows(first.len())
                .any(|window| window == first.as_ref())
                || !received
                    .windows(second.len())
                    .any(|window| window == second.as_ref())
            {
                let mut buffer = [0_u8; 4096];
                let count = client.read(&mut buffer).expect("read live SSE bytes");
                assert_ne!(count, 0, "connection closed before two live SSE chunks");
                received.extend_from_slice(&buffer[..count]);
            }
            assert!(
                !response_body_bytes(&received)
                    .windows(5)
                    .any(|window| window == b"0\r\n\r\n"),
                "an infinite live source must not publish a clean terminator"
            );
            received
        });
        let (server_raw, _) = raw_listener.accept().expect("accept loopback client");
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                let stream = crate::net::tcp::stream::TcpStream::from_std(server_raw)
                    .expect("wrap loopback server stream");
                server.serve_sse(&cx, stream).await
            })
            .expect_err("client close must terminate the infinite live source");
        let received = client.join().expect("join loopback client");

        assert!(matches!(error, HttpError::Io(_)));
        assert!(
            response_body_bytes(&received)
                .starts_with(ChunkedEncoder::encode_chunk(b"data:event-1\n\n").as_ref())
        );
        assert_eq!(eof_calls.load(Ordering::SeqCst), 0);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn produced_h1_envelope_capacity_one_does_not_poll_during_pending_write() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let observation = Arc::new(Mutex::new(None));
        let source = CountingSseSource::finite(
            ["one", "two", "three", "four"],
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );
        let io = ScriptedWriteIo::new(
            Arc::clone(&written),
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&observation),
            BodyWriteDisposition::GateOnceAfterObservation { after_writes: 0 },
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect("serve capacity-one SSE response");

        let observed = observation
            .lock()
            .unwrap()
            .clone()
            .expect("blocked first body write was observed after one pending poll");
        assert_eq!(
            observed.source_calls, 2,
            "one queued event plus one pending send is the complete bounded runahead"
        );
        assert_eq!(observed.eof_calls, 0);
        assert!(response_body_bytes(&observed.written).is_empty());
        assert_eq!(eof_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn produced_h1_envelope_capacity_one_does_not_poll_during_pending_flush() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let observation = Arc::new(Mutex::new(None));
        let source = CountingSseSource::finite(
            ["one", "two", "three", "four"],
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );
        let io = ScriptedWriteIo::new(
            Arc::clone(&written),
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&observation),
            BodyWriteDisposition::GateFlushOnceAfterObservation { after_writes: 1 },
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect("serve capacity-one SSE response");

        let observed = observation
            .lock()
            .unwrap()
            .clone()
            .expect("blocked first body flush was observed");
        assert_eq!(
            response_body_bytes(&observed.written),
            ChunkedEncoder::encode_chunk(b"data:one\n\n").as_ref()
        );
        assert_eq!(observed.eof_calls, 0);
        assert_eq!(eof_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn streaming_sse_server_disconnect_cancels_source_without_terminator() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let observation = Arc::new(Mutex::new(None));
        let source = CountingSseSource::infinite(
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );
        let io = ScriptedWriteIo::new(
            Arc::clone(&written),
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            observation,
            BodyWriteDisposition::FailAfter { after_writes: 1 },
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect_err("scripted disconnect must fail the live response");

        assert!(
            matches!(error, HttpError::Io(ref error) if error.kind() == io::ErrorKind::BrokenPipe)
        );
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
        assert_eq!(eof_calls.load(Ordering::SeqCst), 0);
        let calls_after_return = source_calls.load(Ordering::SeqCst);
        std::thread::yield_now();
        assert_eq!(source_calls.load(Ordering::SeqCst), calls_after_return);
        let written = written.lock().unwrap().clone();
        assert_eq!(
            response_body_bytes(&written),
            ChunkedEncoder::encode_chunk(b"data:event-1\n\n").as_ref()
        );
        assert!(
            !response_body_bytes(&written)
                .windows(5)
                .any(|window| window == b"0\r\n\r\n")
        );
    }

    #[test]
    fn streaming_sse_server_producer_error_closes_without_terminator() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let source = CountingSseSource::failing_after_two_events(
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );
        let io = TestIo::new(
            b"GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect_err("producer failure must fail the live response");

        assert!(
            matches!(error, HttpError::Io(ref source) if source.to_string().contains("scripted producer failure"))
        );
        assert_eq!(source_calls.load(Ordering::SeqCst), 3);
        assert_eq!(eof_calls.load(Ordering::SeqCst), 0);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
        let written = written.lock().unwrap().clone();
        let mut expected = ChunkedEncoder::encode_chunk(b"data:first\n\n").into_vec();
        expected.extend_from_slice(ChunkedEncoder::encode_chunk(b"data:second\n\n").as_ref());
        assert_eq!(
            response_body_bytes(&written),
            expected,
            "frames already committed to the body channel must drain before the producer error closes the connection"
        );
        assert!(
            !response_body_bytes(&written)
                .windows(5)
                .any(|window| window == b"0\r\n\r\n")
        );
    }

    #[test]
    fn streaming_sse_server_head_never_polls_source_or_emits_chunked_body() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let source = CountingSseSource::finite(
            ["must-not-run"],
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );
        let io = TestIo::new(
            b"HEAD /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect("serve SSE HEAD response");

        assert_eq!(source_calls.load(Ordering::SeqCst), 0);
        assert_eq!(eof_calls.load(Ordering::SeqCst), 0);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
        let written = written.lock().unwrap().clone();
        let head = String::from_utf8_lossy(&written);
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.contains("content-type: text/event-stream\r\n"));
        assert!(!head.contains("Transfer-Encoding"));
        assert!(response_body_bytes(&written).is_empty());
    }

    #[test]
    fn streaming_sse_server_connect_is_rejected_before_source_poll() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let source = CountingSseSource::finite(
            ["must-not-run"],
            Arc::clone(&source_calls),
            Arc::clone(&eof_calls),
            Arc::clone(&cancel_calls),
        );
        let source = Arc::new(Mutex::new(Some(source)));
        let source_for_handler = Arc::clone(&source);
        let server = Http1StreamingServer::with_config_sse(
            move |_cx, _request| {
                let source = source_for_handler
                    .lock()
                    .unwrap()
                    .take()
                    .expect("one live SSE request");
                async move { StreamingSse::from_source(source).into_http1_response(NonZeroUsize::MIN) }
            },
            localhost_server_config(),
        );
        let io = TestIo::new(
            b"CONNECT example.test:443 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                .to_vec(),
            Arc::clone(&written),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect("reject CONNECT before live SSE framing");

        assert_eq!(source_calls.load(Ordering::SeqCst), 0);
        assert_eq!(eof_calls.load(Ordering::SeqCst), 0);
        assert_eq!(cancel_calls.load(Ordering::SeqCst), 1);
        let written = written.lock().unwrap().clone();
        let head = String::from_utf8_lossy(&written);
        assert!(head.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(head.contains("Allow: GET, HEAD\r\n"));
        assert!(!head.contains("Transfer-Encoding"));
    }

    #[test]
    fn streaming_sse_server_rejects_trailers_without_clean_terminator() {
        let mut encoder = ChunkedEncoder::new();
        let mut destination = BytesMut::new();

        let error = encode_live_sse_frame(
            &mut encoder,
            Frame::trailers(crate::http::body::HeaderMap::new()),
            &mut destination,
        )
        .expect_err("live SSE trailers must fail closed");

        assert!(matches!(error, HttpError::TrailersNotAllowed));
        assert!(destination.is_empty());
        assert!(!encoder.is_finished());
    }

    #[test]
    fn streaming_sse_server_empty_source_writes_one_clean_terminator() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /events HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_sse(
            |_cx, _request| async move { StreamingSse::empty().into_http1_response(NonZeroUsize::MIN) },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_sse(&cx, io).await
            })
            .expect("serve empty SSE response");

        assert_eq!(state.requests_served, 1);
        let written = written.lock().unwrap().clone();
        let head = String::from_utf8_lossy(&written);
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.contains("Transfer-Encoding: chunked\r\n"));
        assert!(head.contains("content-type: text/event-stream\r\n"));
        assert_eq!(response_body_bytes(&written), b"0\r\n\r\n");
    }

    #[test]
    fn produced_chunked_response_writes_multiple_frames_and_one_terminator() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::chunked(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"alpha").await?;
                        sender.send_chunk(&producer_cx, b"beta").await?;
                        sender.finish(&producer_cx)?;
                        Ok(sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("serve generic produced response");

        assert_eq!(state.requests_served, 1);
        let written = written.lock().unwrap().clone();
        let mut expected = ChunkedEncoder::encode_chunk(b"alpha").into_vec();
        expected.extend_from_slice(ChunkedEncoder::encode_chunk(b"beta").as_ref());
        expected.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(response_body_bytes(&written), expected);
    }

    #[test]
    fn produced_content_length_writes_raw_frames_without_chunk_terminator() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /fixed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::with_content_length(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    9,
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"alpha").await?;
                        sender.send_chunk(&producer_cx, b"beta").await?;
                        sender.finish(&producer_cx)?;
                        Ok(sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("serve exact fixed-length response");

        let written = written.lock().unwrap().clone();
        let head = String::from_utf8_lossy(&written);
        assert!(head.contains("Content-Length: 9\r\n"));
        assert!(!head.contains("Transfer-Encoding"));
        assert_eq!(response_body_bytes(&written), b"alphabeta");
    }

    #[test]
    fn produced_content_length_overrun_refuses_excess_data() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /fixed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::with_content_length(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    4,
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"four").await?;
                        sender.send_chunk(&producer_cx, b"x").await?;
                        sender.finish(&producer_cx)?;
                        Ok(sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("fixed-length overrun must fail closed");

        assert!(matches!(error, HttpError::BadContentLength));
        let written = written.lock().unwrap().clone();
        assert_eq!(response_body_bytes(&written), b"four");
    }

    #[test]
    fn produced_content_length_underrun_preserves_partial_data_then_fails() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /fixed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::with_content_length(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    5,
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"four").await?;
                        sender.finish(&producer_cx)?;
                        Ok(sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("fixed-length underrun must fail closed");

        assert!(matches!(error, HttpError::BadContentLength));
        let written = written.lock().unwrap().clone();
        assert_eq!(response_body_bytes(&written), b"four");
    }

    #[test]
    fn produced_content_length_rejects_finished_sender_from_foreign_channel() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /fixed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::with_content_length(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    5,
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"four").await?;
                        drop(sender);
                        let (foreign_sender, _foreign_body) =
                            crate::http::h1::stream::OutgoingBody::channel(
                                &producer_cx,
                                BodyKind::ContentLength(0),
                            );
                        assert!(foreign_sender.is_finished());
                        Ok(foreign_sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("foreign finished sender must not authenticate a truncated response");

        assert!(matches!(error, HttpError::BodyChannelClosed));
        let written = written.lock().unwrap().clone();
        assert_eq!(response_body_bytes(&written), b"four");
    }

    #[test]
    fn produced_content_length_head_preserves_metadata_without_factory() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = Arc::clone(&factory_calls);
        let io = TestIo::new(
            b"HEAD /fixed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let factory_calls = Arc::clone(&calls_for_handler);
                async move {
                    Http1ProducedResponse::with_content_length(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        42,
                        move |_producer_cx, sender| {
                            factory_calls.fetch_add(1, Ordering::SeqCst);
                            async move { Ok(sender) }
                        },
                    )
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("serve fixed-length HEAD response");

        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        let written = written.lock().unwrap().clone();
        let head = String::from_utf8_lossy(&written);
        assert!(head.contains("Content-Length: 42\r\n"));
        assert!(!head.contains("Transfer-Encoding"));
        assert!(response_body_bytes(&written).is_empty());
    }

    #[test]
    fn produced_content_length_mismatch_fails_before_factory_and_head() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = Arc::clone(&factory_calls);
        let io = TestIo::new(
            b"GET /fixed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let factory_calls = Arc::clone(&calls_for_handler);
                async move {
                    let mut response = Http1ProducedResponse::with_content_length(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        7,
                        move |_producer_cx, sender| {
                            factory_calls.fetch_add(1, Ordering::SeqCst);
                            async move { Ok(sender) }
                        },
                    );
                    response
                        .head_mut()
                        .headers
                        .iter_mut()
                        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .expect("constructor Content-Length")
                        .1 = "8".to_owned();
                    response
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("mismatched fixed-length head must fail before commit");

        assert!(matches!(error, HttpError::BadContentLength));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        assert!(written.lock().unwrap().is_empty());
    }

    #[test]
    fn produced_content_length_head_validation_rejects_invalid_framing() {
        let validate = |headers: Vec<(&str, &str)>| {
            let mut head = ResponseHead::new(200, "OK");
            head.headers.extend(
                headers
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), value.to_owned())),
            );
            validate_produced_response_head(&mut head, BodyKind::ContentLength(7))
        };

        assert!(validate(vec![("Content-Length", "7")]).is_ok());
        assert!(matches!(
            validate(Vec::new()),
            Err(HttpError::BadContentLength)
        ));
        assert!(matches!(
            validate(vec![("Content-Length", "+7")]),
            Err(HttpError::BadContentLength)
        ));
        assert!(matches!(
            validate(vec![("Content-Length", "8")]),
            Err(HttpError::BadContentLength)
        ));
        assert!(matches!(
            validate(vec![("Content-Length", "7"), ("content-length", "7")]),
            Err(HttpError::DuplicateContentLength)
        ));
        assert!(matches!(
            validate(vec![
                ("Content-Length", "7"),
                ("Transfer-Encoding", "chunked")
            ]),
            Err(HttpError::AmbiguousBodyLength)
        ));
        assert!(matches!(
            validate(vec![("Content-Length", "7"), ("Trailer", "x-checksum")]),
            Err(HttpError::TrailersNotAllowed)
        ));
    }

    #[test]
    fn produced_content_length_trailer_declaration_fails_before_factory() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = Arc::clone(&factory_calls);
        let io = TestIo::new(
            b"GET /fixed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let factory_calls = Arc::clone(&calls_for_handler);
                async move {
                    Http1ProducedResponse::with_content_length(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        7,
                        move |_producer_cx, sender| {
                            factory_calls.fetch_add(1, Ordering::SeqCst);
                            async move { Ok(sender) }
                        },
                    )
                    .with_header("Trailer", "x-checksum")
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("fixed-length trailer declaration must fail before commit");

        assert!(matches!(error, HttpError::TrailersNotAllowed));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        assert!(written.lock().unwrap().is_empty());
    }

    #[test]
    fn produced_content_length_zero_runs_terminal_producer_without_data() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_handler = Arc::clone(&factory_calls);
        let io = TestIo::new(
            b"GET /empty HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let factory_calls = Arc::clone(&calls_for_handler);
                async move {
                    Http1ProducedResponse::with_content_length(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        0,
                        move |producer_cx, mut sender| {
                            factory_calls.fetch_add(1, Ordering::SeqCst);
                            async move {
                                crate::runtime::yield_now().await;
                                assert!(sender.is_finished());
                                sender.finish(&producer_cx)?;
                                Ok(sender)
                            }
                        },
                    )
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("serve zero-length produced response");

        assert_eq!(factory_calls.load(Ordering::SeqCst), 1);
        let written = written.lock().unwrap().clone();
        let head = String::from_utf8_lossy(&written);
        assert!(head.contains("Content-Length: 0\r\n"));
        assert!(response_body_bytes(&written).is_empty());
    }

    #[test]
    fn produced_h1_envelope_custom_limit_accepts_exact_frame() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::chunked_with_max_frame_bytes(
                    NonZeroUsize::MIN,
                    NonZeroUsize::new(4).unwrap(),
                    200,
                    "OK",
                    |producer_cx, mut sender| async move {
                        assert_eq!(sender.max_frame_bytes(), NonZeroUsize::new(4));
                        sender.send_chunk(&producer_cx, b"four").await?;
                        sender.finish(&producer_cx)?;
                        Ok(sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("serve exact-boundary produced response");

        let written = written.lock().unwrap().clone();
        let mut expected = ChunkedEncoder::encode_chunk(b"four").into_vec();
        expected.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(response_body_bytes(&written), expected);
    }

    #[test]
    fn produced_h1_envelope_default_limit_refuses_oversize_without_data() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::chunked(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    |producer_cx, mut sender| async move {
                        let oversized = crate::bytes::Bytes::from(vec![
                            b'x';
                            Http1ProducedResponse::DEFAULT_MAX_FRAME_BYTES
                                + 1
                        ]);
                        sender.send_bytes(&producer_cx, oversized).await?;
                        sender.finish(&producer_cx)?;
                        Ok(sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("oversized produced DATA must fail closed");

        assert!(matches!(
            error,
            HttpError::BodyTooLargeDetailed {
                actual: 65_537,
                limit: 65_536
            }
        ));
        let written = written.lock().unwrap().clone();
        assert!(String::from_utf8_lossy(&written).starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response_body_bytes(&written).is_empty());
        assert!(!response_body_bytes(&written).ends_with(b"0\r\n\r\n"));
    }

    #[test]
    fn produced_chunked_response_drains_committed_frames_before_producer_error() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::chunked(
                    NonZeroUsize::new(2).unwrap(),
                    200,
                    "OK",
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"first").await?;
                        sender.send_chunk(&producer_cx, b"second").await?;
                        Err(io::Error::other("original produced-body failure").into())
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("producer failure must fail the response");

        assert!(
            matches!(error, HttpError::Io(ref source) if source.to_string() == "original produced-body failure")
        );
        let written = written.lock().unwrap().clone();
        let mut expected = ChunkedEncoder::encode_chunk(b"first").into_vec();
        expected.extend_from_slice(ChunkedEncoder::encode_chunk(b"second").as_ref());
        assert_eq!(response_body_bytes(&written), expected);
        assert!(!response_body_bytes(&written).ends_with(b"0\r\n\r\n"));
    }

    #[test]
    fn produced_chunked_response_unfinished_success_drains_then_fails() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::chunked(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"committed").await?;
                        Ok(sender)
                    },
                )
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("unfinished successful producer must fail closed");

        assert!(matches!(error, HttpError::BodyChannelClosed));
        let written = written.lock().unwrap().clone();
        assert_eq!(
            response_body_bytes(&written),
            ChunkedEncoder::encode_chunk(b"committed").as_ref()
        );
    }

    #[test]
    fn produced_chunked_response_writes_terminal_trailers_without_repoll() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let source_calls = Arc::new(AtomicUsize::new(0));
        let eof_calls = Arc::new(AtomicUsize::new(0));
        let observation = Arc::new(Mutex::new(None));
        let io = ScriptedWriteIo::new(
            Arc::clone(&written),
            source_calls,
            eof_calls,
            observation,
            BodyWriteDisposition::GateOnceBeforeObservation { after_writes: 1 },
        );
        let server = Http1StreamingServer::with_config_produced(
            |_cx, _request| async move {
                Http1ProducedResponse::chunked(
                    NonZeroUsize::MIN,
                    200,
                    "OK",
                    |producer_cx, mut sender| async move {
                        sender.send_chunk(&producer_cx, b"payload").await?;
                        let mut trailers = HeaderMap::new();
                        trailers.append(
                            HeaderName::from_static("x-checksum"),
                            HeaderValue::from_static("verified"),
                        );
                        sender.send_trailers(&producer_cx, trailers).await?;
                        Ok(sender)
                    },
                )
                .with_header("Trailer", "x-checksum")
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("serve produced response with terminal trailers");

        let written = written.lock().unwrap().clone();
        let mut expected = ChunkedEncoder::encode_chunk(b"payload").into_vec();
        expected.extend_from_slice(b"0\r\nx-checksum: verified\r\n\r\n");
        assert_eq!(response_body_bytes(&written), expected);
    }

    #[test]
    fn produced_chunked_response_rejects_ambiguous_head_before_factory() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let factory_calls_for_handler = Arc::clone(&factory_calls);
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let factory_calls = Arc::clone(&factory_calls_for_handler);
                async move {
                    Http1ProducedResponse::chunked(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        move |_producer_cx, sender| {
                            factory_calls.fetch_add(1, Ordering::SeqCst);
                            async move { Ok(sender) }
                        },
                    )
                    .with_header("Content-Length", "7")
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("Content-Length plus chunked must fail before head commit");

        assert!(matches!(error, HttpError::AmbiguousBodyLength));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        assert!(written.lock().unwrap().is_empty());
    }

    #[test]
    fn produced_chunked_response_head_drops_factory_without_polling_or_framing() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let factory_calls_for_handler = Arc::clone(&factory_calls);
        let io = TestIo::new(
            b"HEAD /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let factory_calls = Arc::clone(&factory_calls_for_handler);
                async move {
                    Http1ProducedResponse::chunked(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        move |_producer_cx, sender| {
                            factory_calls.fetch_add(1, Ordering::SeqCst);
                            async move { Ok(sender) }
                        },
                    )
                    .with_header("Trailer", "x-checksum")
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect("serve produced HEAD response");

        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        let written = written.lock().unwrap().clone();
        let head = String::from_utf8_lossy(&written);
        assert!(!head.contains("Transfer-Encoding"));
        assert!(!head.contains("Trailer:"));
        assert!(response_body_bytes(&written).is_empty());
    }

    #[test]
    fn produced_chunked_response_rejects_body_forbidden_status_before_factory() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let factory_calls_for_handler = Arc::clone(&factory_calls);
        let io = TestIo::new(
            b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let factory_calls = Arc::clone(&factory_calls_for_handler);
                async move {
                    Http1ProducedResponse::chunked(
                        NonZeroUsize::MIN,
                        204,
                        "No Content",
                        move |_producer_cx, sender| {
                            factory_calls.fetch_add(1, Ordering::SeqCst);
                            async move { Ok(sender) }
                        },
                    )
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("204 chunked body must fail before head commit");

        assert!(matches!(error, HttpError::BadTransferEncoding));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        assert!(written.lock().unwrap().is_empty());
    }

    #[test]
    fn produced_chunked_response_disconnect_cancels_and_drains_producer() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let producer_calls = Arc::new(AtomicUsize::new(0));
        let cancellation_calls = Arc::new(AtomicUsize::new(0));
        let observation = Arc::new(Mutex::new(None));
        let io = ScriptedWriteIo::new(
            Arc::clone(&written),
            Arc::clone(&producer_calls),
            Arc::new(AtomicUsize::new(0)),
            observation,
            BodyWriteDisposition::FailAfter { after_writes: 1 },
        );
        let producer_calls_for_handler = Arc::clone(&producer_calls);
        let cancellation_calls_for_handler = Arc::clone(&cancellation_calls);
        let server = Http1StreamingServer::with_config_produced(
            move |_cx, _request| {
                let producer_calls = Arc::clone(&producer_calls_for_handler);
                let cancellation_calls = Arc::clone(&cancellation_calls_for_handler);
                async move {
                    Http1ProducedResponse::chunked(
                        NonZeroUsize::MIN,
                        200,
                        "OK",
                        move |producer_cx, mut sender| async move {
                            loop {
                                producer_calls.fetch_add(1, Ordering::SeqCst);
                                if let Err(error) = sender.send_chunk(&producer_cx, b"live").await {
                                    cancellation_calls.fetch_add(1, Ordering::SeqCst);
                                    return Err(error);
                                }
                            }
                        },
                    )
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve_produced(&cx, io).await
            })
            .expect_err("scripted disconnect must fail the produced response");

        assert!(
            matches!(error, HttpError::Io(ref source) if source.kind() == io::ErrorKind::BrokenPipe)
        );
        assert_eq!(cancellation_calls.load(Ordering::SeqCst), 1);
        let written = written.lock().unwrap().clone();
        assert_eq!(
            response_body_bytes(&written),
            ChunkedEncoder::encode_chunk(b"live").as_ref()
        );
        assert!(!response_body_bytes(&written).ends_with(b"0\r\n\r\n"));
    }

    struct GatedBodyIo {
        head: Vec<u8>,
        body: Vec<u8>,
        release_marker: Vec<u8>,
        gated_polls: usize,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl GatedBodyIo {
        fn new(
            head: Vec<u8>,
            body: Vec<u8>,
            release_marker: Vec<u8>,
            written: Arc<Mutex<Vec<u8>>>,
        ) -> Self {
            Self {
                head,
                body,
                release_marker,
                gated_polls: 0,
                written,
            }
        }

        fn body_release_seen(&self) -> bool {
            let written = self.written.lock().unwrap();
            written
                .windows(self.release_marker.len())
                .any(|window| window == self.release_marker.as_slice())
        }
    }

    impl AsyncRead for GatedBodyIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if !self.head.is_empty() {
                let n = std::cmp::min(buf.remaining(), self.head.len());
                buf.put_slice(&self.head[..n]);
                self.head.drain(..n);
                return Poll::Ready(Ok(()));
            }

            if self.body.is_empty() {
                return Poll::Ready(Ok(()));
            }

            if self.body_release_seen() {
                let n = std::cmp::min(buf.remaining(), self.body.len());
                buf.put_slice(&self.body[..n]);
                self.body.drain(..n);
                return Poll::Ready(Ok(()));
            }

            self.gated_polls += 1;
            let written_so_far = self.written.lock().unwrap().clone();
            assert!(
                self.gated_polls < 8,
                "request body stayed gated because the server never emitted the expected interim response; wrote so far: {:?}",
                String::from_utf8_lossy(&written_so_far)
            );
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    impl AsyncWrite for GatedBodyIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct HeadFirstIo {
        head: Vec<u8>,
        body_and_pipeline: Vec<u8>,
        head_published: Arc<AtomicBool>,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncRead for HeadFirstIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let source = if self.head.is_empty() {
                assert!(
                    self.head_published.load(Ordering::SeqCst),
                    "server read request-body bytes before publishing the request head"
                );
                &mut self.body_and_pipeline
            } else {
                &mut self.head
            };
            if source.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let count = buf.remaining().min(source.len());
            buf.put_slice(&source[..count]);
            source.drain(..count);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for HeadFirstIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn make_request(version: Version, headers: Vec<(String, String)>) -> Request {
        Request {
            method: Method::Get,
            uri: "/".into(),
            version,
            headers,
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        }
    }

    #[test]
    fn should_close_connection_header_close() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http11, vec![("Connection".into(), "close".into())]);
        assert!(should_close_connection(&req, &config, &state));
    }

    /// br-asupersync-t9yqht: validate_host_header MUST accept Host
    /// values that match the allow-list (case-insensitive,
    /// port-stripped) and reject all others including the missing-Host
    /// case which is itself an HTTP/1.1 protocol violation.
    #[test]
    fn validate_host_header_accepts_listed_rejects_others() {
        let policy = HostPolicy::allow_list(vec![
            "example.com".to_string(),
            "auth.example.com".to_string(),
        ]);

        // Listed host — accepted.
        let headers = vec![("Host".to_string(), "example.com".to_string())];
        assert!(validate_host_header(&headers, &policy).is_ok());

        // Listed host with port — accepted (port stripped).
        let headers = vec![("Host".to_string(), "example.com:8080".to_string())];
        assert!(validate_host_header(&headers, &policy).is_ok());

        // Case-insensitive match.
        let headers = vec![("Host".to_string(), "EXAMPLE.COM".to_string())];
        assert!(validate_host_header(&headers, &policy).is_ok());

        // Different listed host.
        let headers = vec![("Host".to_string(), "auth.example.com".to_string())];
        assert!(validate_host_header(&headers, &policy).is_ok());

        // Unlisted host — REJECTED. This is the host-injection defense.
        let headers = vec![("Host".to_string(), "attacker.com".to_string())];
        let err = validate_host_header(&headers, &policy).unwrap_err();
        assert_eq!(err, "attacker.com");

        // Subdomain not in allowlist — REJECTED (allowlist is exact match).
        let headers = vec![("Host".to_string(), "evil.example.com".to_string())];
        let err = validate_host_header(&headers, &policy).unwrap_err();
        assert_eq!(err, "evil.example.com");

        // Missing Host header (HTTP/1.1 protocol violation per RFC 7230 §5.4).
        let headers = vec![("X-Other".to_string(), "value".to_string())];
        let err = validate_host_header(&headers, &policy).unwrap_err();
        assert!(err.is_empty(), "missing Host should yield empty err string");
    }

    /// br-asupersync-scxixg: validation policies - AllowAll accepts any
    /// single Host, empty allow-list now rejects all (security fix),
    /// RejectUnknown rejects all.
    #[test]
    fn validate_host_header_policy_behaviors() {
        let headers = vec![("Host".to_string(), "anywhere.com".to_string())];

        // AllowAll accepts any single Host header (insecure legacy mode).
        assert!(validate_host_header(&headers, &HostPolicy::AllowAll).is_ok());

        // Empty allowlist now REJECTS all hosts (security fix for br-asupersync-scxixg).
        let empty_policy = HostPolicy::allow_list(vec![]);
        let err = validate_host_header(&headers, &empty_policy).unwrap_err();
        assert_eq!(err, "anywhere.com");

        // RejectUnknown rejects all requests (secure default).
        let reject_policy = HostPolicy::RejectUnknown;
        let err = validate_host_header(&headers, &reject_policy).unwrap_err();
        assert_eq!(err, "anywhere.com");
    }

    #[test]
    fn validate_host_header_rejects_duplicate_host_headers() {
        let duplicate_hosts = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Host".to_string(), "attacker.com".to_string()),
        ];
        let allow_list = HostPolicy::allow_list(vec!["example.com".to_string()]);

        let err = validate_host_header(&duplicate_hosts, &allow_list).unwrap_err();
        assert_eq!(err, "multiple Host headers");

        let err = validate_host_header(&duplicate_hosts, &HostPolicy::RejectUnknown).unwrap_err();
        assert_eq!(err, "multiple Host headers");

        let err = validate_host_header(&duplicate_hosts, &HostPolicy::AllowAll).unwrap_err();
        assert_eq!(err, "multiple Host headers");
    }

    /// br-asupersync-scxixg: IPv6 literal handling — strip brackets
    /// and port correctly so allowed_hosts can be specified as the
    /// bracket-less host.
    #[test]
    fn validate_host_header_ipv6_literal_handling() {
        let policy = HostPolicy::allow_list(vec!["::1".to_string()]);

        // IPv6 literal with port.
        let headers = vec![("Host".to_string(), "[::1]:8080".to_string())];
        assert!(validate_host_header(&headers, &policy).is_ok());

        // IPv6 literal without port.
        let headers = vec![("Host".to_string(), "[::1]".to_string())];
        assert!(validate_host_header(&headers, &policy).is_ok());

        // Different IPv6 — REJECTED.
        let headers = vec![("Host".to_string(), "[fe80::1]:8080".to_string())];
        assert!(validate_host_header(&headers, &policy).is_err());

        // Malformed IPv6 authority suffix must not bypass the allow-list.
        let headers = vec![("Host".to_string(), "[::1]evil.test".to_string())];
        let err = validate_host_header(&headers, &policy).unwrap_err();
        assert_eq!(err, "[::1]evil.test");

        // Out-of-range ports are malformed authorities and must not be
        // canonicalized to the allow-listed IPv6 literal.
        let headers = vec![("Host".to_string(), "[::1]:65536".to_string())];
        let err = validate_host_header(&headers, &policy).unwrap_err();
        assert_eq!(err, "[::1]:65536");
    }

    /// br-asupersync-t9yqht: parse_host_header_host handles edge
    /// cases (whitespace, empty, malformed).
    #[test]
    fn parse_host_header_host_handles_edges() {
        assert_eq!(
            parse_host_header_host("example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            parse_host_header_host("  example.com  ").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            parse_host_header_host("EXAMPLE.com:8080").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            parse_host_header_host("example.com:65535").as_deref(),
            Some("example.com")
        );
        assert_eq!(parse_host_header_host("example.com:65536").as_deref(), None);
        assert_eq!(
            parse_host_header_host("[2001:db8::1]:443").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(
            parse_host_header_host("[2001:db8::1]:65535").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(
            parse_host_header_host("[2001:db8::1]:65536").as_deref(),
            None
        );
        assert_eq!(parse_host_header_host("[2001:db8::1]evil").as_deref(), None);
        assert_eq!(
            parse_host_header_host("[2001:db8::1]:https").as_deref(),
            None
        );
        assert_eq!(parse_host_header_host("example.com:https").as_deref(), None);
        assert_eq!(parse_host_header_host("example.com:80:90").as_deref(), None);
        assert_eq!(parse_host_header_host("2001:db8::1").as_deref(), None);
        assert_eq!(parse_host_header_host(""), None);
        assert_eq!(parse_host_header_host("   "), None);
        assert_eq!(
            parse_host_header_host("\t example.com \t").as_deref(),
            Some("example.com")
        );
        assert_eq!(parse_host_header_host("\u{a0}example.com\u{a0}"), None);
        assert_eq!(parse_host_header_host("\u{a0}example.com:443"), None);
        assert_eq!(
            parse_host_header_host("münich.example").as_deref(),
            Some("münich.example"),
            "OWS hardening must not narrow the previously accepted non-whitespace Unicode host surface",
        );
    }

    #[test]
    fn should_close_connection_header_keepalive() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(
            Version::Http11,
            vec![("Connection".into(), "keep-alive".into())],
        );
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn connection_tokens_use_only_rfc_ows() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);

        let ascii_ows = make_request(
            Version::Http10,
            vec![("Connection".into(), "\t keep-alive \t".into())],
        );
        assert!(!should_close_connection(&ascii_ows, &config, &state));

        let unicode_whitespace = make_request(
            Version::Http10,
            vec![("Connection".into(), "\u{a0}keep-alive\u{a0}".into())],
        );
        assert!(should_close_connection(
            &unicode_whitespace,
            &config,
            &state
        ));

        let response =
            Response::new(200, "OK", Vec::new()).with_header("Connection", "\u{a0}close\u{a0}");
        assert!(!response_requests_close(&response));
    }

    #[test]
    fn should_close_http10_default() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http10, vec![]);
        assert!(should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_http10_with_keepalive() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(
            Version::Http10,
            vec![("Connection".into(), "keep-alive".into())],
        );
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_http11_default() {
        let config = Http1Config::default();
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http11, vec![]);
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_keepalive_disabled() {
        let config = Http1Config {
            keep_alive: false,
            ..Default::default()
        };
        let state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http11, vec![]);
        assert!(should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_at_request_limit() {
        let config = Http1Config {
            max_requests_per_connection: Some(5),
            ..Default::default()
        };
        let mut state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http11, vec![]);

        // At 4 served (next will be 5th = limit), should close
        state.requests_served = 4;
        assert!(should_close_connection(&req, &config, &state));

        // At 3 served, should not close
        state.requests_served = 3;
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn should_close_unlimited_requests() {
        let config = Http1Config {
            max_requests_per_connection: None,
            ..Default::default()
        };
        let mut state = ConnectionState::new(crate::types::Time::ZERO);
        let req = make_request(Version::Http11, vec![]);

        state.requests_served = 1_000_000;
        assert!(!should_close_connection(&req, &config, &state));
    }

    #[test]
    fn connection_state_tracking() {
        let state = ConnectionState::new(crate::types::Time::ZERO);
        assert_eq!(state.requests_served, 0);
        assert_eq!(state.phase, ConnectionPhase::Idle);
        assert!(!state.exceeded_request_limit(Some(10)));
        assert!(!state.exceeded_request_limit(None));
    }

    #[test]
    fn connection_state_request_limit() {
        let mut state = ConnectionState::new(crate::types::Time::ZERO);
        state.requests_served = 10;
        assert!(state.exceeded_request_limit(Some(10)));
        assert!(state.exceeded_request_limit(Some(5)));
        assert!(!state.exceeded_request_limit(Some(11)));
        assert!(!state.exceeded_request_limit(None));
    }

    #[test]
    fn add_connection_close_header() {
        let mut resp = Response::new(200, "OK", Vec::new());
        assert!(resp.headers.is_empty());
        add_connection_close(&mut resp);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "close");
    }

    #[test]
    fn add_connection_close_header_already_present() {
        let mut resp = Response::new(200, "OK", Vec::new());
        resp.headers
            .push(("Connection".to_owned(), "keep-alive".to_owned()));
        add_connection_close(&mut resp);
        // Should not add duplicate and should overwrite to close
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "close");
    }

    #[test]
    fn add_connection_keep_alive_header() {
        let mut resp = Response::new(200, "OK", Vec::new());
        assert!(resp.headers.is_empty());
        add_connection_keep_alive(&mut resp);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "keep-alive");
    }

    #[test]
    fn add_connection_keep_alive_header_already_present() {
        let mut resp = Response::new(200, "OK", Vec::new());
        resp.headers
            .push(("Connection".to_owned(), "close".to_owned()));
        add_connection_keep_alive(&mut resp);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "keep-alive");
    }

    #[test]
    fn finalize_response_persistence_http10_keepalive_normalizes_version_and_header() {
        let mut resp = Response::new(200, "OK", Vec::new());

        let close_after = finalize_response_persistence(Version::Http10, &mut resp, false);

        assert!(!close_after);
        assert_eq!(resp.version, Version::Http10);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "keep-alive");
    }

    #[test]
    fn finalize_response_persistence_http10_close_normalizes_version_and_header() {
        let mut resp = Response::new(200, "OK", Vec::new());

        let close_after = finalize_response_persistence(Version::Http10, &mut resp, true);

        assert!(close_after);
        assert_eq!(resp.version, Version::Http10);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "close");
    }

    #[test]
    fn finalize_response_persistence_preserves_handler_requested_close() {
        let mut resp = Response::new(200, "OK", Vec::new()).with_header("Connection", "close");

        let close_after = finalize_response_persistence(Version::Http11, &mut resp, false);

        assert!(close_after);
        assert_eq!(resp.version, Version::Http11);
        assert_eq!(resp.headers.len(), 1);
        assert_eq!(resp.headers[0].0, "Connection");
        assert_eq!(resp.headers[0].1, "close");
    }

    #[test]
    fn suppress_response_body_for_head_replaces_chunked_framing() {
        let mut resp = Response::new(200, "OK", b"hello".to_vec())
            .with_header("Trailer", "X-Trace")
            .with_header("Transfer-Encoding", "chunked")
            .with_trailer("X-Trace", "abc123");

        suppress_response_body_for_head(&mut resp);

        assert!(resp.body.is_empty());
        assert!(resp.trailers.is_empty());
        assert_eq!(resp.header_value("trailer"), None);
        assert_eq!(resp.header_value("transfer-encoding"), None);
        assert_eq!(resp.header_value("content-length"), Some("5"));
    }

    #[test]
    fn suppress_response_body_for_head_preserves_handler_content_length() {
        // RFC 9110 §9.3.2: HEAD response MUST carry the same Content-Length
        // as the equivalent GET response.  When the handler explicitly sets
        // Content-Length (even if it differs from the sentinel body), trust
        // it as the authoritative GET length.
        let mut resp =
            Response::new(200, "OK", b"hello".to_vec()).with_header("Content-Length", "999");

        suppress_response_body_for_head(&mut resp);

        assert!(resp.body.is_empty());
        assert_eq!(resp.header_value("content-length"), Some("999"));
    }

    #[test]
    fn config_builder() {
        let config = Http1Config::default()
            .max_headers_size(1024)
            .max_body_size(2048)
            .keep_alive(false)
            .max_requests(Some(50))
            .idle_timeout(Some(Duration::from_secs(30)));

        assert_eq!(config.max_headers_size, 1024);
        assert_eq!(config.max_body_size, 2048);
        assert!(!config.keep_alive);
        assert_eq!(config.max_requests_per_connection, Some(50));
        assert_eq!(config.idle_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn classify_expectation_none_when_absent() {
        let req = make_request(Version::Http11, vec![]);
        assert_eq!(classify_expectation(&req), ExpectationAction::None);
    }

    #[test]
    fn classify_expectation_continue_for_http11() {
        let req = make_request(
            Version::Http11,
            vec![("Expect".into(), "100-continue".into())],
        );
        assert_eq!(classify_expectation(&req), ExpectationAction::Continue);
    }

    #[test]
    fn classify_expectation_rejects_http10_continue() {
        let req = make_request(
            Version::Http10,
            vec![("Expect".into(), "100-continue".into())],
        );
        assert_eq!(classify_expectation(&req), ExpectationAction::Reject);
    }

    #[test]
    fn classify_expectation_rejects_unsupported_expectation() {
        let req = make_request(Version::Http11, vec![("Expect".into(), "foo".into())]);
        assert_eq!(classify_expectation(&req), ExpectationAction::Reject);
    }

    #[test]
    fn expectation_and_body_preview_use_only_rfc_ows() {
        let unicode_expect = make_request(
            Version::Http11,
            vec![("Expect".into(), "\u{a0}100-continue\u{a0}".into())],
        );
        assert_eq!(
            classify_expectation(&unicode_expect),
            ExpectationAction::Reject
        );

        let ascii_ows_expect = make_request(
            Version::Http11,
            vec![("Expect".into(), "\t 100-continue \t".into())],
        );
        assert_eq!(
            classify_expectation(&ascii_ows_expect),
            ExpectationAction::Continue
        );

        assert!(!request_expects_body_headers(&[(
            "Content-Length".into(),
            "\u{a0}5\u{a0}".into(),
        )]));
        assert!(!request_expects_body_headers(&[(
            "Transfer-Encoding".into(),
            "\u{a0}chunked\u{a0}".into(),
        )]));
    }

    #[test]
    fn classify_expectation_rejects_mixed_tokens() {
        let req = make_request(
            Version::Http11,
            vec![("Expect".into(), "100-continue, foo".into())],
        );
        assert_eq!(classify_expectation(&req), ExpectationAction::Reject);
    }

    #[test]
    fn request_expects_body_content_length_positive() {
        let req = make_request(Version::Http11, vec![("Content-Length".into(), "5".into())]);
        assert!(request_expects_body(&req));
    }

    #[test]
    fn request_expects_body_content_length_zero() {
        let req = make_request(Version::Http11, vec![("Content-Length".into(), "0".into())]);
        assert!(!request_expects_body(&req));
    }

    #[test]
    fn request_expects_body_chunked_encoding() {
        let req = make_request(
            Version::Http11,
            vec![("Transfer-Encoding".into(), "chunked".into())],
        );
        assert!(request_expects_body(&req));
    }

    #[test]
    fn streaming_server_publishes_head_before_reading_body() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let head_published = Arc::new(AtomicBool::new(false));
        let io = HeadFirstIo {
            head: b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\n".to_vec(),
            body_and_pipeline: b"hello".to_vec(),
            head_published: Arc::clone(&head_published),
            written: Arc::clone(&written),
        };
        let published_by_handler = Arc::clone(&head_published);
        let server = Http1StreamingServer::with_config(
            move |_cx, mut request| {
                let published_by_handler = Arc::clone(&published_by_handler);
                async move {
                    published_by_handler.store(true, Ordering::SeqCst);
                    let mut body = Vec::new();
                    while let Some(frame) =
                        poll_fn(|task_cx| Pin::new(&mut request.body).poll_frame(task_cx)).await
                    {
                        if let Some(data) = frame.expect("valid body frame").into_data() {
                            body.extend_from_slice(data.into_inner().as_ref());
                        }
                    }
                    assert_eq!(body, b"hello");
                    Response::new(200, "OK", b"done")
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("serve streaming request");

        assert_eq!(state.requests_served, 1);
        assert!(head_published.load(Ordering::SeqCst));
        assert!(String::from_utf8_lossy(&written.lock().unwrap()).contains("200 OK"));
    }

    #[test]
    fn incoming_body_driver_observes_supplied_request_context_cancellation() {
        let request_cx = Cx::for_testing();
        request_cx.cancel_fast(crate::types::CancelKind::PollQuota);
        let (writer, _body) =
            IncomingRequestBody::channel_with_limits(&request_cx, BodyKind::ContentLength(1), 1, 1);
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut io = TestIo::new(Vec::new(), written);
        let mut read_buffer = BytesMut::from(&b"x"[..]);
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = runtime
            .block_on(drive_incoming_body(
                &request_cx,
                &mut io,
                &mut read_buffer,
                writer,
                &Http1StreamingConfig::default(),
            ))
            .expect_err("request cancellation must stop body publication");

        assert_eq!(
            error,
            IncomingBodyError::Cancelled {
                kind: crate::types::CancelKind::PollQuota,
            }
        );
    }

    #[test]
    fn body_diagnostic_incoming_driver_preserves_client_abort_for_consumer() {
        let request_cx = Cx::for_testing();
        let (writer, mut body) =
            IncomingRequestBody::channel_with_limits(&request_cx, BodyKind::ContentLength(1), 1, 1);
        let written = Arc::new(Mutex::new(Vec::new()));
        let mut io = TestIo::new(Vec::new(), written).with_read_error(io::ErrorKind::BrokenPipe);
        let mut read_buffer = BytesMut::new();
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let (driver_error, consumer_error) = runtime.block_on(async {
            let driver_error = drive_incoming_body(
                &request_cx,
                &mut io,
                &mut read_buffer,
                writer,
                &Http1StreamingConfig::default(),
            )
            .await
            .expect_err("transport read failure must abort the request body");
            let consumer_error =
                std::future::poll_fn(|task_cx| Pin::new(&mut body).poll_frame(task_cx))
                    .await
                    .expect("failed body emits one terminal frame")
                    .expect_err("failed body frame retains its typed cause");
            (driver_error, consumer_error)
        });

        assert_eq!(driver_error, IncomingBodyError::ClientAborted);
        assert_eq!(consumer_error, IncomingBodyError::ClientAborted);
        assert!(
            incoming_body_failure_response(Version::Http11, &consumer_error).is_none(),
            "a live client abort must never synthesize a wire response"
        );
    }

    #[test]
    fn body_diagnostic_incoming_driver_classifies_unsynchronized_eof_as_client_abort() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        for (body_kind, partial_wire) in [
            (BodyKind::ContentLength(5), &b"hi"[..]),
            (BodyKind::Chunked, &b"2\r\nhi\r\n"[..]),
        ] {
            let request_cx = Cx::for_testing();
            let (writer, mut body) =
                IncomingRequestBody::channel_with_limits(&request_cx, body_kind, 2, 64);
            let written = Arc::new(Mutex::new(Vec::new()));
            let mut io = TestIo::new(partial_wire.to_vec(), written);
            let mut read_buffer = BytesMut::new();

            let (driver_error, consumer_error) = runtime.block_on(async {
                let driver_error = drive_incoming_body(
                    &request_cx,
                    &mut io,
                    &mut read_buffer,
                    writer,
                    &Http1StreamingConfig::default(),
                )
                .await
                .expect_err("premature peer EOF must abort the request body");
                let consumer_error = loop {
                    let frame =
                        std::future::poll_fn(|task_cx| Pin::new(&mut body).poll_frame(task_cx))
                            .await
                            .expect("aborted body emits a terminal error frame");
                    match frame {
                        Ok(_) => continue,
                        Err(error) => break error,
                    }
                };
                (driver_error, consumer_error)
            });

            assert_eq!(driver_error, IncomingBodyError::ClientAborted);
            assert_eq!(consumer_error, IncomingBodyError::ClientAborted);
            assert!(incoming_body_failure_response(Version::Http11, &consumer_error).is_none());
        }
    }

    #[test]
    fn streaming_server_drains_unread_body_before_pipeline_reuse() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /first HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhelloGET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_handler = Arc::clone(&seen);
        let server = Http1StreamingServer::with_config(
            move |_cx, request| {
                seen_by_handler
                    .lock()
                    .unwrap()
                    .push(request.head.uri.clone());
                async move { Response::new(200, "OK", request.head.uri.into_bytes()) }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("serve pipelined streaming requests");

        assert_eq!(state.requests_served, 2);
        assert_eq!(&*seen.lock().unwrap(), &["/first", "/second"]);
        let written = String::from_utf8_lossy(&written.lock().unwrap()).into_owned();
        assert_eq!(written.matches("HTTP/1.1 200 OK").count(), 2);
    }

    #[test]
    fn streaming_server_drains_segmented_unread_body_before_pipeline_reuse() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /first HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhelloGET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        )
        .with_read_limit(1);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_handler = Arc::clone(&seen);
        let server = Http1StreamingServer::with_config(
            move |_cx, request| {
                seen_by_handler
                    .lock()
                    .unwrap()
                    .push(request.head.uri.clone());
                async move { Response::new(200, "OK", request.head.uri.into_bytes()) }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("serve segmented pipelined streaming requests");

        assert_eq!(state.requests_served, 2);
        assert_eq!(&*seen.lock().unwrap(), &["/first", "/second"]);
        let written = String::from_utf8_lossy(&written.lock().unwrap()).into_owned();
        assert_eq!(written.matches("HTTP/1.1 200 OK").count(), 2);
    }

    #[test]
    fn streaming_server_drains_segmented_chunked_unread_body_before_pipeline_reuse() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /first HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Checksum: yes\r\n\r\nGET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        )
        .with_read_limit(1);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_handler = Arc::clone(&seen);
        let server = Http1StreamingServer::with_config(
            move |_cx, request| {
                seen_by_handler
                    .lock()
                    .unwrap()
                    .push(request.head.uri.clone());
                async move { Response::new(200, "OK", request.head.uri.into_bytes()) }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("serve segmented chunked pipelined streaming requests");

        assert_eq!(state.requests_served, 2);
        assert_eq!(&*seen.lock().unwrap(), &["/first", "/second"]);
        let written = String::from_utf8_lossy(&written.lock().unwrap()).into_owned();
        assert_eq!(written.matches("HTTP/1.1 200 OK").count(), 2);
    }

    #[test]
    fn streaming_server_closes_when_unread_body_exceeds_drain_limit() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /first HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\n0123456789GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let config = Http1StreamingConfig::from(localhost_server_config()).unread_body_drain(
            8,
            4,
            Duration::from_secs(1),
        );
        let server = Http1StreamingServer::with_config(
            |_cx, _request| async move { Response::new(200, "OK", b"must not commit") },
            config,
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("drain-limit close is a clean connection outcome");

        assert_eq!(state.requests_served, 0);
        assert!(written.lock().unwrap().is_empty());
        assert_eq!(state.phase, ConnectionPhase::Closing);
    }

    #[test]
    fn streaming_server_preserves_chunked_frames_and_trailers() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /chunk HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\nX-Checksum: yes\r\n\r\n"
                .to_vec(),
            Arc::clone(&written),
        );
        let observed = Arc::new(Mutex::new((Vec::new(), Vec::new())));
        let observed_by_handler = Arc::clone(&observed);
        let server = Http1StreamingServer::with_config(
            move |_cx, mut request| {
                let observed_by_handler = Arc::clone(&observed_by_handler);
                async move {
                    while let Some(frame) =
                        poll_fn(|task_cx| Pin::new(&mut request.body).poll_frame(task_cx)).await
                    {
                        match frame.expect("valid chunked frame") {
                            crate::http::body::Frame::Data(data) => observed_by_handler
                                .lock()
                                .unwrap()
                                .0
                                .extend_from_slice(data.into_inner().as_ref()),
                            crate::http::body::Frame::Trailers(trailers) => {
                                observed_by_handler.lock().unwrap().1 = trailers
                                    .iter()
                                    .map(|(name, value)| {
                                        (
                                            name.as_str().to_owned(),
                                            String::from_utf8_lossy(value.as_bytes()).into_owned(),
                                        )
                                    })
                                    .collect();
                            }
                        }
                    }
                    Response::new(204, "No Content", Vec::new())
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("serve chunked streaming request");

        assert_eq!(state.requests_served, 1);
        assert_eq!(observed.lock().unwrap().0, b"hello");
        assert_eq!(
            observed.lock().unwrap().1,
            vec![("x-checksum".to_owned(), "yes".to_owned())]
        );
    }

    #[test]
    fn streaming_server_refuses_actual_chunked_bytes_over_limit() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /chunk HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
                .to_vec(),
            Arc::clone(&written),
        );
        let observed_error: Arc<Mutex<Option<IncomingBodyError>>> = Arc::new(Mutex::new(None));
        let observed_by_handler = Arc::clone(&observed_error);
        let server = Http1StreamingServer::with_config(
            move |_cx, mut request| {
                let observed_by_handler = Arc::clone(&observed_by_handler);
                async move {
                    while let Some(frame) =
                        poll_fn(|task_cx| Pin::new(&mut request.body).poll_frame(task_cx)).await
                    {
                        if let Err(error) = frame {
                            *observed_by_handler.lock().unwrap() = Some(error);
                            break;
                        }
                    }
                    Response::new(200, "OK", b"must not commit")
                }
            },
            localhost_server_config().max_body_size(4),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("over-limit body closes the connection cleanly");

        assert_eq!(state.requests_served, 0);
        assert!(written.lock().unwrap().is_empty());
        assert_eq!(state.phase, ConnectionPhase::Closing);
        assert_eq!(
            observed_error.lock().unwrap().as_ref(),
            Some(&IncomingBodyError::BodyTooLarge {
                actual: Some(5),
                limit: 4,
            })
        );
    }

    #[test]
    fn streaming_server_reports_truncated_content_length_and_closes() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /short HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhi".to_vec(),
            Arc::clone(&written),
        );
        let observed_error: Arc<Mutex<Option<IncomingBodyError>>> = Arc::new(Mutex::new(None));
        let observed_by_handler = Arc::clone(&observed_error);
        let server = Http1StreamingServer::with_config(
            move |_cx, mut request| {
                let observed_by_handler = Arc::clone(&observed_by_handler);
                async move {
                    while let Some(frame) =
                        poll_fn(|task_cx| Pin::new(&mut request.body).poll_frame(task_cx)).await
                    {
                        if let Err(error) = frame {
                            *observed_by_handler.lock().unwrap() = Some(error);
                            break;
                        }
                    }
                    Response::new(200, "OK", b"must not commit")
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async {
                let cx = Cx::current().expect("runtime connection context");
                server.serve(&cx, io).await
            })
            .expect("truncated body closes the connection cleanly");

        assert_eq!(state.requests_served, 0);
        assert!(written.lock().unwrap().is_empty());
        assert_eq!(state.phase, ConnectionPhase::Closing);
        assert_eq!(
            observed_error.lock().unwrap().as_ref(),
            Some(&IncomingBodyError::ClientAborted)
        );
    }

    #[test]
    fn serve_head_request_omits_response_body_bytes() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config(
            |_req| async move { Response::new(200, "OK", b"hello") },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve head request");

        assert_eq!(state.requests_served, 1);

        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(written.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(written.contains("Content-Length: 5\r\n"));
        assert!(written.contains("Connection: close\r\n"));
        assert!(written.ends_with("\r\n\r\n"));
        assert!(!written.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn serve_expect_continue_unblocks_body_waiting_client() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let seen_body = Arc::new(Mutex::new(Vec::new()));
        let io = GatedBodyIo::new(
            b"POST /upload HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 5\r\nConnection: close\r\n\r\n".to_vec(),
            b"hello".to_vec(),
            b"HTTP/1.1 100 Continue\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let seen_body_for_handler = Arc::clone(&seen_body);
        let server = Http1Server::with_config(
            move |req| {
                let seen_body_for_handler = Arc::clone(&seen_body_for_handler);
                async move {
                    *seen_body_for_handler.lock().unwrap() = req.body.clone();
                    Response::new(200, "OK", b"done")
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve expect-continue request");

        assert_eq!(state.requests_served, 1);
        assert_eq!(&*seen_body.lock().unwrap(), b"hello");

        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(written.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"));
        assert!(written.contains("Content-Length: 4\r\n"));
    }

    #[test]
    fn serve_expect_continue_when_body_arrives_eagerly() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let seen_body = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"POST /upload HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".to_vec(),
            Arc::clone(&written),
        );
        let seen_body_for_handler = Arc::clone(&seen_body);
        let server = Http1Server::with_config(
            move |req| {
                let seen_body_for_handler = Arc::clone(&seen_body_for_handler);
                async move {
                    *seen_body_for_handler.lock().unwrap() = req.body.clone();
                    Response::new(200, "OK", b"done")
                }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve eager expect-continue request");

        assert_eq!(state.requests_served, 1);
        assert_eq!(&*seen_body.lock().unwrap(), b"hello");

        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(written.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"));
        assert!(written.contains("Content-Length: 4\r\n"));
    }

    #[test]
    fn serve_rejects_unsupported_expectation_before_body_arrives() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let handler_called = Arc::new(AtomicBool::new(false));
        let io = GatedBodyIo::new(
            b"POST /upload HTTP/1.1\r\nHost: localhost\r\nExpect: fancy-feature\r\nContent-Length: 5\r\nConnection: close\r\n\r\n".to_vec(),
            b"hello".to_vec(),
            b"HTTP/1.1 417 Expectation Failed\r\n".to_vec(),
            Arc::clone(&written),
        );
        let handler_called_for_handler = Arc::clone(&handler_called);
        let server = Http1Server::with_config(
            move |_req| {
                handler_called_for_handler.store(true, Ordering::SeqCst);
                async move { Response::new(200, "OK", b"nope") }
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve unsupported expect request");

        assert_eq!(state.requests_served, 1);
        assert!(!handler_called.load(Ordering::SeqCst));

        let written = String::from_utf8(written.lock().unwrap().clone())
            .expect("response should be valid utf8");
        assert!(written.starts_with("HTTP/1.1 417 Expectation Failed\r\n"));
        assert!(written.contains("Connection: close\r\n"));
        assert!(!written.contains("200 OK"));
    }

    #[test]
    fn connection_phase_equality() {
        assert_eq!(ConnectionPhase::Idle, ConnectionPhase::Idle);
        assert_ne!(ConnectionPhase::Idle, ConnectionPhase::Reading);
        assert_ne!(ConnectionPhase::Processing, ConnectionPhase::Writing);
    }

    #[test]
    fn connection_phase_debug_clone_copy() {
        let p = ConnectionPhase::Closing;
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Closing"));

        let p2 = p;
        assert_eq!(p, p2);

        // Copy
        let p3 = p;
        assert_eq!(p, p3);
    }

    #[test]
    fn http1_config_debug_clone() {
        let c = Http1Config::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Http1Config"));

        let c2 = c;
        assert_eq!(c2.max_headers_size, 64 * 1024);
        assert!(c2.keep_alive);
    }

    // --- br-asupersync-server-stack-hardening-eeexl1.1.1: server-hop ---
    // --- request regions, budgets, and Request-Timeout handling      ---

    #[test]
    fn parse_request_timeout_header_accepts_valid_forms() {
        let cases: [(&str, Duration); 5] = [
            ("1500", Duration::from_millis(1500)),
            ("1500ms", Duration::from_millis(1500)),
            ("5s", Duration::from_secs(5)),
            ("2m", Duration::from_secs(120)),
            ("  30  ", Duration::from_millis(30)),
        ];
        for (value, expected) in cases {
            let headers = vec![("Request-Timeout".to_string(), value.to_string())];
            assert_eq!(
                parse_request_timeout_header(&headers),
                Some(expected),
                "value {value:?}"
            );
        }
        // Case-insensitive header name.
        let headers = vec![("REQUEST-TIMEOUT".to_string(), "5s".to_string())];
        assert_eq!(
            parse_request_timeout_header(&headers),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn parse_request_timeout_header_fails_closed() {
        let bad_values = [
            "",
            " ",
            "abc",
            "-5",
            "5.5s",
            "5 s",
            "1h",
            "0",
            "0ms",
            "0s",
            "99999999999",   // 11 digits
            "184467440737s", // overflow-adjacent garbage length
            "5ss",
            "ms",
            "\u{a0}5s\u{a0}",
        ];
        for value in bad_values {
            let headers = vec![("Request-Timeout".to_string(), value.to_string())];
            assert_eq!(
                parse_request_timeout_header(&headers),
                None,
                "value {value:?} must fail closed"
            );
        }
        // Missing header.
        assert_eq!(parse_request_timeout_header(&[]), None);
        // Duplicate headers are ambiguous: fail closed.
        let headers = vec![
            ("Request-Timeout".to_string(), "5s".to_string()),
            ("request-timeout".to_string(), "10s".to_string()),
        ];
        assert_eq!(parse_request_timeout_header(&headers), None);
    }

    #[test]
    fn serve_handler_observes_config_derived_request_budget() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config(
            |_req| async move {
                let deadline_installed =
                    Cx::with_current(|cx| cx.budget().deadline.is_some()).unwrap_or(false);
                if deadline_installed {
                    Response::new(200, "OK", b"deadline-installed")
                } else {
                    Response::new(500, "ERR", b"no-deadline")
                }
            },
            localhost_server_config().request_timeout(Some(Duration::from_secs(30))),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve request");
        assert_eq!(state.requests_served, 1);

        let written = String::from_utf8(written.lock().unwrap().clone()).expect("utf8");
        assert!(
            written.starts_with("HTTP/1.1 200 OK\r\n"),
            "handler must observe the config-derived budget deadline: {written}"
        );
    }

    #[test]
    fn serve_request_timeout_maps_to_503() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config(
            |_req| async move {
                let now = Cx::current()
                    .and_then(|cx| cx.timer_driver())
                    .map_or_else(wall_now, |timer| timer.now());
                crate::time::sleep(now, Duration::from_secs(600)).await;
                Response::new(200, "OK", b"too late")
            },
            localhost_server_config()
                .request_timeout(Some(Duration::from_millis(25)))
                .request_drain_grace(Duration::from_millis(10)),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let started = std::time::Instant::now();
        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve request");
        assert_eq!(state.requests_served, 1);
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "request timeout must bound the handler"
        );

        let written = String::from_utf8(written.lock().unwrap().clone()).expect("utf8");
        assert!(
            written.starts_with("HTTP/1.1 503"),
            "deadline exceeded must map to 503: {written}"
        );
        assert!(written.contains("request budget deadline exceeded"));
    }

    /// Parent AC 3 (security): a hostile `Request-Timeout` header cannot
    /// extend the request budget beyond the configured cap.
    #[test]
    fn serve_header_timeout_clamped_by_cap_security() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nRequest-Timeout: 9999999s\r\nConnection: close\r\n\r\n"
                .to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config(
            |_req| async move {
                let now = Cx::current()
                    .and_then(|cx| cx.timer_driver())
                    .map_or_else(wall_now, |timer| timer.now());
                crate::time::sleep(now, Duration::from_secs(600)).await;
                Response::new(200, "OK", b"too late")
            },
            localhost_server_config()
                .request_timeout_header_cap(Some(Duration::from_millis(25)))
                .request_drain_grace(Duration::from_millis(10)),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let started = std::time::Instant::now();
        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve request");
        assert_eq!(state.requests_served, 1);
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the cap must bound a hostile header timeout"
        );

        let written = String::from_utf8(written.lock().unwrap().clone()).expect("utf8");
        assert!(
            written.starts_with("HTTP/1.1 503"),
            "cap-clamped header deadline must map to 503: {written}"
        );
    }

    #[test]
    fn serve_header_timeout_ignored_without_cap_opt_in() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nRequest-Timeout: 1ms\r\nConnection: close\r\n\r\n"
                .to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config(
            |_req| async move {
                let now = Cx::current()
                    .and_then(|cx| cx.timer_driver())
                    .map_or_else(wall_now, |timer| timer.now());
                crate::time::sleep(now, Duration::from_millis(50)).await;
                Response::new(200, "OK", b"finished")
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve request");
        assert_eq!(state.requests_served, 1);

        let written = String::from_utf8(written.lock().unwrap().clone()).expect("utf8");
        assert!(
            written.starts_with("HTTP/1.1 200 OK\r\n"),
            "without cap opt-in the header must be ignored: {written}"
        );
    }

    #[test]
    fn serve_handler_panic_maps_to_500_and_closes_connection() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config(
            |_req| async move { panic!("handler exploded") },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let state = runtime
            .block_on(async { server.serve(io).await })
            .expect("serve must survive a handler panic");
        assert_eq!(state.requests_served, 1);

        let written = String::from_utf8(written.lock().unwrap().clone()).expect("utf8");
        assert!(
            written.starts_with("HTTP/1.1 500"),
            "handler panic must map to 500: {written}"
        );
        assert!(
            written.contains("Connection: close") || written.contains("connection: close"),
            "connection must close after a handler panic: {written}"
        );
    }

    #[test]
    fn upgradeable_server_preserves_deterministic_codec_read_ahead() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let frame = [
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
        ];
        let mut input = b"GET /ws HTTP/1.1\r\n\
            Host: localhost\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
            Sec-WebSocket-Version: 13\r\n\
            \r\n"
            .to_vec();
        input.extend_from_slice(&frame);
        let io = TestIo::new(input, Arc::clone(&written));
        let server = Http1Server::with_config_upgradeable(
            |_request| async move {
                let response = Response::new(101, "Switching Protocols", Vec::new())
                    .with_header("connection", "Upgrade")
                    .with_header("upgrade", "websocket")
                    .with_header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
                Http1Response::new(response)
                    .with_upgrade(Http1Upgrade::new(|_cx, _io, _read_ahead| async {}))
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let outcome = runtime
            .block_on(async { server.serve_upgradeable_with_peer_addr(io, None).await })
            .expect("upgrade handoff");
        let Http1ServeOutcome::Upgraded { read_ahead, .. } = outcome else {
            panic!("expected upgraded ownership outcome");
        };
        assert_eq!(&read_ahead[..], &frame);
        let response = String::from_utf8(written.lock().unwrap().clone()).expect("response UTF-8");
        assert_eq!(response.matches("HTTP/1.1 101").count(), 1);
        assert!(response.ends_with("\r\n\r\n"));
    }

    #[test]
    fn upgradeable_server_rejects_non_rfc6455_key_before_flush() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET /ws HTTP/1.1\r\n\
              Host: localhost\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: not-base64\r\n\
              Sec-WebSocket-Version: 13\r\n\
              \r\n"
                .to_vec(),
            Arc::clone(&written),
        );
        let server = Http1Server::with_config_upgradeable(
            |_request| async move {
                let response = Response::new(101, "Switching Protocols", Vec::new())
                    .with_header("connection", "Upgrade")
                    .with_header("upgrade", "websocket")
                    .with_header(
                        "sec-websocket-accept",
                        crate::net::websocket::compute_accept_key("not-base64"),
                    );
                Http1Response::new(response)
                    .with_upgrade(Http1Upgrade::new(|_cx, _io, _read_ahead| async {}))
            },
            localhost_server_config(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        let error = match runtime
            .block_on(async { server.serve_upgradeable_with_peer_addr(io, None).await })
        {
            Err(error) => error,
            Ok(_) => panic!("invalid WebSocket key must refuse handoff"),
        };
        assert!(
            matches!(error, HttpError::Io(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert!(written.lock().unwrap().is_empty());
    }

    #[test]
    fn serve_emits_budget_trace_events_at_server_hop() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = TestIo::new(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            Arc::clone(&written),
        );
        let trace_probe: Arc<Mutex<Option<crate::trace::TraceBufferHandle>>> =
            Arc::new(Mutex::new(None));
        let probe = Arc::clone(&trace_probe);
        let server = Http1Server::with_config(
            move |_req| {
                let probe = Arc::clone(&probe);
                async move {
                    *probe.lock().unwrap() = Cx::with_current(|cx| cx.trace_buffer()).flatten();
                    Response::new(200, "OK", b"ok")
                }
            },
            localhost_server_config().request_timeout(Some(Duration::from_secs(30))),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        runtime
            .block_on(async { server.serve(io).await })
            .expect("serve request");

        let trace = trace_probe
            .lock()
            .unwrap()
            .clone()
            .expect("request cx must carry the runtime trace buffer");
        use crate::trace::event::{TraceData, TraceEventKind};
        let events: Vec<(TraceEventKind, TraceData)> = trace
            .snapshot()
            .iter()
            .filter(|e| {
                matches!(
                    e.kind,
                    TraceEventKind::BudgetInstalled | TraceEventKind::BudgetConsumed
                )
            })
            .map(|e| (e.kind, e.data.clone()))
            .collect();
        assert_eq!(
            events.len(),
            2,
            "expected installed + consumed events, got {events:?}"
        );
        assert_eq!(events[0].0, TraceEventKind::BudgetInstalled);
        let TraceData::Budget {
            protocol, source, ..
        } = &events[0].1
        else {
            panic!("expected Budget data, got {:?}", events[0].1);
        };
        assert_eq!(protocol, "h1");
        assert_eq!(source.as_deref(), Some("config"));
        assert_eq!(events[1].0, TraceEventKind::BudgetConsumed);
        let TraceData::Budget {
            protocol, outcome, ..
        } = &events[1].1
        else {
            panic!("expected Budget data, got {:?}", events[1].1);
        };
        assert_eq!(protocol, "h1");
        assert_eq!(outcome.as_deref(), Some("ok"));
    }
}
