//! HTTP/2 server listener surface (br-asupersync-eprpk6).
//!
//! Increment 1: request/response mapping between the h2 frame layer
//! ([`crate::http::h2::connection::ReceivedFrame::Headers`] header blocks)
//! and the shared [`crate::http::h1::types`] `Request`/`Response` handler
//! types, so one `Fn(Request) -> impl Future<Output = Response>` handler
//! serves both the HTTP/1.1 and HTTP/2 listener stacks. H2-aware handlers can
//! instead return [`Http2Response`] to opt into explicit server push.
//!
//! The accept-loop `Http2Listener` and per-connection frame-pump driver land
//! in the next increments (full design recorded on the bead): preface +
//! SETTINGS handshake over `Framed<TcpStream, FrameCodec>`, per-stream
//! handler dispatch through a response funnel, and request-aware graceful
//! drain via the D2.3 two-stage GOAWAY primitives on
//! [`crate::http::h2::connection::Connection`].

use crate::channel::mpsc;
use crate::codec::Framed;
use crate::cx::Cx;
use crate::http::h1::server::{HostPolicy, parse_request_timeout_header, validate_host_header};
use crate::http::h1::types::{Method, Request, Response, Version};
use crate::http::h2::connection::{CLIENT_PREFACE, Connection, FrameCodec, ReceivedFrame};
use crate::http::h2::error::{ErrorCode, H2Error};
use crate::http::h2::frame::Frame;
use crate::http::h2::hpack::Header;
use crate::http::h2::settings::Settings;
use crate::http::h2::stream::StreamState;
use crate::io::AsyncReadExt as _;
use crate::net::tcp::listener::TcpListener;
use crate::net::tcp::stream::TcpStream;
use crate::runtime::{JoinHandle, RuntimeHandle, SpawnError};
use crate::server::connection::ConnectionManager;
use crate::server::shutdown::{
    DrainStep, GracefulDrainReport, GracefulDrainSupervisor, ShutdownPhase, ShutdownSignal,
    ShutdownStats,
};
use crate::stream::Stream;
use crate::tracing_compat::error;
use crate::types::Time;
use crate::web::request_region::{ServerHopOutcome, ServerRequestRegion, derive_request_budget};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

/// Tick interval for the listener's drain supervision loop and for the
/// stage-1 → stage-2 GOAWAY spacing inside the connection driver (one
/// round-trip-ish window for racing in-flight stream creation, RFC 9113
/// §6.8).
const DRAIN_SUPERVISION_TICK: Duration = Duration::from_millis(10);

/// Capacity of the per-connection handler-response funnel.
const RESPONSE_FUNNEL_CAPACITY: usize = 64;

/// Default per-stream request-body buffering cap (mirrors the HTTP/1.1
/// listener's `max_body_size`). HTTP/2 flow control auto-replenishes stream
/// and connection windows, so without an explicit cap a single stream could
/// buffer unbounded bytes and exhaust server memory.
const DEFAULT_H2_MAX_BODY_SIZE: usize = 16 * 1024 * 1024;

/// Base delay for the exponential accept-error backoff (h1 parity).
const TRANSIENT_ACCEPT_BACKOFF_BASE: Duration = Duration::from_millis(2);

/// Cap for the exponential accept-error backoff (h1 parity).
const TRANSIENT_ACCEPT_BACKOFF_CAP: Duration = Duration::from_millis(64);

/// Low-overhead listener counters for diagnosing HTTP/2 accept-path stalls
/// and observing graceful drains (h1 D2.4 AC6 parity).
pub struct Http2ListenerStats {
    accepted_total: AtomicU64,
    transient_accept_errors_total: AtomicU64,
    spawn_failures_total: AtomicU64,
    last_accept_at_ms: AtomicU64,
    drains_started_total: AtomicU64,
    drain_escalations_total: AtomicU64,
    drain_hard_deadline_hits_total: AtomicU64,
    drains_quiescent_total: AtomicU64,
    last_drain_requests_at_start: AtomicU64,
    last_drain_requests_stranded: AtomicU64,
    last_drain_duration_ms: AtomicU64,
    time_getter: fn() -> Time,
}

/// Immutable snapshot of [`Http2ListenerStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2ListenerStatsSnapshot {
    /// Total successful accepts observed by the listener.
    pub accepted_total: u64,
    /// Total transient accept errors that triggered listener backoff.
    pub transient_accept_errors_total: u64,
    /// Total failures to spawn a per-connection task after accept succeeded.
    pub spawn_failures_total: u64,
    /// Logical runtime time in milliseconds when the listener last accepted a connection.
    pub last_accept_at_ms: u64,
    /// Total request-aware drains started by this listener.
    pub drains_started_total: u64,
    /// Total drains whose soft budget elapsed and escalated stragglers.
    pub drain_escalations_total: u64,
    /// Total drains that ended on the hard deadline with requests stranded.
    pub drain_hard_deadline_hits_total: u64,
    /// Total drains that reached quiescence (zero in-flight requests).
    pub drains_quiescent_total: u64,
    /// In-flight request count when the most recent drain started.
    pub last_drain_requests_at_start: u64,
    /// Requests still in flight when the most recent drain ended.
    pub last_drain_requests_stranded: u64,
    /// Duration of the most recent drain in whole milliseconds.
    pub last_drain_duration_ms: u64,
}

impl std::fmt::Debug for Http2ListenerStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2ListenerStats")
            .field(
                "accepted_total",
                &self.accepted_total.load(Ordering::Relaxed),
            )
            .field(
                "transient_accept_errors_total",
                &self.transient_accept_errors_total.load(Ordering::Relaxed),
            )
            .field(
                "spawn_failures_total",
                &self.spawn_failures_total.load(Ordering::Relaxed),
            )
            .field(
                "last_accept_at_ms",
                &self.last_accept_at_ms.load(Ordering::Relaxed),
            )
            .field(
                "drains_started_total",
                &self.drains_started_total.load(Ordering::Relaxed),
            )
            .field(
                "drain_escalations_total",
                &self.drain_escalations_total.load(Ordering::Relaxed),
            )
            .field(
                "drain_hard_deadline_hits_total",
                &self.drain_hard_deadline_hits_total.load(Ordering::Relaxed),
            )
            .field(
                "drains_quiescent_total",
                &self.drains_quiescent_total.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl Default for Http2ListenerStats {
    fn default() -> Self {
        Self::new(default_h2_listener_time_getter)
    }
}

impl Http2ListenerStats {
    fn new(time_getter: fn() -> Time) -> Self {
        Self {
            accepted_total: AtomicU64::new(0),
            transient_accept_errors_total: AtomicU64::new(0),
            spawn_failures_total: AtomicU64::new(0),
            last_accept_at_ms: AtomicU64::new(0),
            drains_started_total: AtomicU64::new(0),
            drain_escalations_total: AtomicU64::new(0),
            drain_hard_deadline_hits_total: AtomicU64::new(0),
            drains_quiescent_total: AtomicU64::new(0),
            last_drain_requests_at_start: AtomicU64::new(0),
            last_drain_requests_stranded: AtomicU64::new(0),
            last_drain_duration_ms: AtomicU64::new(0),
            time_getter,
        }
    }

    fn record_accepted(&self) {
        self.accepted_total.fetch_add(1, Ordering::Relaxed);
        self.last_accept_at_ms
            .store((self.time_getter)().as_millis(), Ordering::Relaxed);
    }

    fn record_transient_accept_error(&self) {
        self.transient_accept_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_spawn_failure(&self) {
        self.spawn_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_drain_started(&self, in_flight: usize) {
        self.drains_started_total.fetch_add(1, Ordering::Relaxed);
        self.last_drain_requests_at_start.store(
            u64::try_from(in_flight).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn record_drain_escalated(&self) {
        self.drain_escalations_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_drain_hard_deadline(&self) {
        self.drain_hard_deadline_hits_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_drain_finished(&self, report: &GracefulDrainReport) {
        if report.reached_quiescence {
            self.drains_quiescent_total.fetch_add(1, Ordering::Relaxed);
        }
        self.last_drain_requests_stranded.store(
            u64::try_from(report.requests_stranded).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.last_drain_duration_ms.store(
            u64::try_from(report.drain_duration.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Returns a point-in-time copy of the listener counters.
    #[must_use]
    pub fn snapshot(&self) -> Http2ListenerStatsSnapshot {
        Http2ListenerStatsSnapshot {
            accepted_total: self.accepted_total.load(Ordering::Relaxed),
            transient_accept_errors_total: self
                .transient_accept_errors_total
                .load(Ordering::Relaxed),
            spawn_failures_total: self.spawn_failures_total.load(Ordering::Relaxed),
            last_accept_at_ms: self.last_accept_at_ms.load(Ordering::Relaxed),
            drains_started_total: self.drains_started_total.load(Ordering::Relaxed),
            drain_escalations_total: self.drain_escalations_total.load(Ordering::Relaxed),
            drain_hard_deadline_hits_total: self
                .drain_hard_deadline_hits_total
                .load(Ordering::Relaxed),
            drains_quiescent_total: self.drains_quiescent_total.load(Ordering::Relaxed),
            last_drain_requests_at_start: self.last_drain_requests_at_start.load(Ordering::Relaxed),
            last_drain_requests_stranded: self.last_drain_requests_stranded.load(Ordering::Relaxed),
            last_drain_duration_ms: self.last_drain_duration_ms.load(Ordering::Relaxed),
        }
    }
}

/// Accept errors that are transient and should be retried (h1 parity).
fn is_transient_accept_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
    )
}

/// Exponential backoff delay for a streak of transient accept errors so a
/// persistent accept failure does not busy-spin the accept loop (h1 parity).
fn transient_accept_backoff_delay(streak: u32) -> Duration {
    let exponent = (streak.saturating_sub(1) / 16).min(5);
    TRANSIENT_ACCEPT_BACKOFF_BASE
        .saturating_mul(1u32 << exponent)
        .min(TRANSIENT_ACCEPT_BACKOFF_CAP)
}

/// A connection-spawn failure that is connection-scoped (the runtime is at
/// task capacity) should drop that one connection and keep accepting, not
/// tear down the whole listener (h1 parity).
fn should_retry_after_spawn_failure(err: &SpawnError) -> bool {
    matches!(err, SpawnError::RegionAtCapacity { .. })
}

/// Connection-specific h1 headers that MUST NOT be carried into HTTP/2
/// messages (RFC 9113 §8.2.2). `te` is handled separately: it is permitted
/// with the single value `trailers`.
const CONNECTION_SPECIFIC_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// Build a handler [`Request`] from a decoded h2 request header block plus
/// its assembled body.
///
/// The caller (the connection driver) is expected to feed header blocks that
/// already passed the connection's RFC 9113 §8.3.1 pseudo-header structural
/// validation; this function extracts `:method` / `:path` / `:authority`,
/// surfaces the authority as a `host` header for h1 handler parity (unless
/// the request carried an explicit `host`), and rejects shapes it cannot
/// represent (`CONNECT` requests have no `:path` and are not supported by
/// this listener surface yet).
///
/// # Errors
///
/// Returns a protocol-level [`H2Error`] when required pseudo-headers are
/// missing, the method token is invalid, or an unknown request pseudo-header
/// appears.
pub(crate) fn request_from_h2_headers(
    headers: Vec<Header>,
    body: Vec<u8>,
    peer_addr: Option<SocketAddr>,
) -> Result<Request, H2Error> {
    let mut method = None;
    let mut path = None;
    let mut authority = None;
    let mut regular = Vec::with_capacity(headers.len());
    for header in headers {
        match header.name.as_str() {
            ":method" => method = Some(header.value),
            ":path" => path = Some(header.value),
            ":authority" => authority = Some(header.value),
            // `:scheme` has no h1 `Request` equivalent; `:protocol` is the
            // RFC 8441 extended-CONNECT marker, validated upstream.
            ":scheme" | ":protocol" => {}
            name if name.starts_with(':') => {
                return Err(H2Error::protocol(format!(
                    "unexpected request pseudo-header {name}"
                )));
            }
            _ => regular.push((header.name, header.value)),
        }
    }

    let method_text = method.ok_or_else(|| H2Error::protocol(":method pseudo-header missing"))?;
    let method = Method::from_bytes(method_text.as_bytes())
        .ok_or_else(|| H2Error::protocol("invalid :method token"))?;
    let uri = path.ok_or_else(|| {
        H2Error::protocol(":path pseudo-header missing (CONNECT is not supported by this listener)")
    })?;

    let mut request_headers = Vec::with_capacity(regular.len() + 1);
    if let Some(authority) = authority
        && !regular
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        // RFC 9113 §8.3.1: the authority carries what h1 put in Host.
        request_headers.push(("host".to_owned(), authority));
    }
    request_headers.extend(regular);

    Ok(Request {
        method,
        uri,
        version: Version::Http2,
        headers: request_headers,
        body,
        trailers: Vec::new(),
        peer_addr,
    })
}

fn should_strip_h2_response_header(lowered: &str, value: &str) -> bool {
    CONNECTION_SPECIFIC_HEADERS.contains(&lowered)
        || (lowered == "te" && !value.eq_ignore_ascii_case("trailers"))
}

fn is_h2_response_header_name_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
    )
}

fn validate_h2_response_header_name(name: &str) -> Result<(), H2Error> {
    if name.is_empty() || name.starts_with(':') {
        return Err(H2Error::connection(
            ErrorCode::InternalError,
            "invalid h2 response header name",
        ));
    }
    if !name.bytes().all(is_h2_response_header_name_byte) {
        return Err(H2Error::connection(
            ErrorCode::InternalError,
            "invalid h2 response header name",
        ));
    }
    Ok(())
}

fn validate_h2_response_header_value(value: &str) -> Result<(), H2Error> {
    if value
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == b'\0' || (b < 0x20 && b != b'\t') || b == 0x7f)
    {
        return Err(H2Error::connection(
            ErrorCode::InternalError,
            "invalid h2 response header value",
        ));
    }
    Ok(())
}

fn parse_h2_content_length(value: &str) -> Result<usize, H2Error> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(H2Error::connection(
            ErrorCode::InternalError,
            "invalid h2 response content-length",
        ));
    }
    value.parse::<usize>().map_err(|_| {
        H2Error::connection(
            ErrorCode::InternalError,
            "invalid h2 response content-length",
        )
    })
}

fn validate_h2_response_for_queue(
    response: &Response,
    enforce_content_length: bool,
) -> Result<(), H2Error> {
    let mut content_length = None;
    for (name, value) in &response.headers {
        let lowered = name.to_ascii_lowercase();
        if should_strip_h2_response_header(lowered.as_str(), value) {
            continue;
        }
        validate_h2_response_header_name(name)?;
        validate_h2_response_header_value(value)?;
        if lowered == "content-length" {
            let declared = parse_h2_content_length(value)?;
            if content_length.replace(declared).is_some() {
                return Err(H2Error::connection(
                    ErrorCode::InternalError,
                    "duplicate h2 response content-length",
                ));
            }
        }
    }
    for (name, value) in &response.trailers {
        let lowered = name.to_ascii_lowercase();
        if should_strip_h2_response_header(lowered.as_str(), value) {
            continue;
        }
        validate_h2_response_header_name(name)?;
        validate_h2_response_header_value(value)?;
    }
    if enforce_content_length
        && let Some(declared) = content_length
        && declared != response.body.len()
    {
        return Err(H2Error::connection(
            ErrorCode::InternalError,
            "h2 response content-length does not match body length",
        ));
    }
    Ok(())
}

fn invalid_h2_response_fallback() -> Http2Response {
    Http2Response::new(Response::new(500, "Internal Server Error", Vec::new()))
}

/// Map a handler [`Response`] to an h2 response header block.
///
/// Emits `:status` first (RFC 9113 §8.3.2), lowercases field names (h2
/// field names are lowercase on the wire), validates handler-supplied fields,
/// and strips connection-specific h1 headers that MUST NOT appear in h2
/// messages (RFC 9113 §8.2.2), including any `te` value other than
/// `trailers`.
pub(crate) fn h2_headers_from_response(response: &Response) -> Result<Vec<Header>, H2Error> {
    validate_h2_response_for_queue(response, false)?;
    let mut out = Vec::with_capacity(response.headers.len() + 1);
    out.push(Header::new(":status", response.status.to_string()));
    for (name, value) in &response.headers {
        let lowered = name.to_ascii_lowercase();
        if should_strip_h2_response_header(lowered.as_str(), value) {
            continue;
        }
        out.push(Header::new(lowered, value.clone()));
    }
    Ok(out)
}

fn h2_trailers_from_response(response: &Response) -> Result<Vec<Header>, H2Error> {
    let mut out = Vec::with_capacity(response.trailers.len());
    for (name, value) in &response.trailers {
        let lowered = name.to_ascii_lowercase();
        if should_strip_h2_response_header(lowered.as_str(), value) {
            continue;
        }
        validate_h2_response_header_name(name)?;
        validate_h2_response_header_value(value)?;
        out.push(Header::new(lowered, value.clone()));
    }
    Ok(out)
}

/// H2-only response wrapper that can carry explicit server-push promises.
///
/// Plain [`Response`] handlers still work through [`IntoHttp2Response`]. A
/// handler that wants HTTP/2 server push returns this wrapper and appends
/// [`Http2ServerPush`] entries in deterministic order.
#[derive(Debug, Clone)]
pub struct Http2Response {
    /// Main response for the associated request stream.
    pub response: Response,
    /// Ordered server-push entries to promise before the main response.
    pub pushes: Vec<Http2ServerPush>,
}

impl Http2Response {
    /// Create a response wrapper with no pushes.
    #[must_use]
    pub fn new(response: Response) -> Self {
        Self {
            response,
            pushes: Vec::new(),
        }
    }

    /// Add one server-push entry.
    #[must_use]
    pub fn with_push(mut self, push: Http2ServerPush) -> Self {
        self.pushes.push(push);
        self
    }

    /// Add multiple server-push entries in caller-provided order.
    #[must_use]
    pub fn with_pushes(mut self, pushes: impl IntoIterator<Item = Http2ServerPush>) -> Self {
        self.pushes.extend(pushes);
        self
    }
}

impl From<Response> for Http2Response {
    fn from(response: Response) -> Self {
        Self::new(response)
    }
}

/// Conversion trait accepted by the HTTP/2 listener handler.
pub trait IntoHttp2Response {
    /// Convert into the H2 response envelope consumed by the listener.
    fn into_h2_response(self) -> Http2Response;
}

impl IntoHttp2Response for Response {
    fn into_h2_response(self) -> Http2Response {
        self.into()
    }
}

impl IntoHttp2Response for Http2Response {
    fn into_h2_response(self) -> Http2Response {
        self
    }
}

/// One server-push promise plus the response to send on the promised stream.
#[derive(Debug, Clone)]
pub struct Http2ServerPush {
    /// Request header block carried by PUSH_PROMISE.
    pub request_headers: Vec<Header>,
    /// Response to send on the promised stream.
    pub response: Response,
}

impl Http2ServerPush {
    /// Create a server-push entry with a caller-supplied promised request block.
    #[must_use]
    pub fn new(request_headers: Vec<Header>, response: Response) -> Self {
        Self {
            request_headers,
            response,
        }
    }

    /// Create a GET push promise for an HTTPS resource.
    #[must_use]
    pub fn get(path: impl Into<String>, authority: impl Into<String>, response: Response) -> Self {
        Self::get_with_scheme("https", path, authority, response)
    }

    /// Create a GET push promise with an explicit scheme.
    #[must_use]
    pub fn get_with_scheme(
        scheme: impl Into<String>,
        path: impl Into<String>,
        authority: impl Into<String>,
        response: Response,
    ) -> Self {
        Self {
            request_headers: vec![
                Header::new(":method", "GET"),
                Header::new(":scheme", scheme),
                Header::new(":path", path),
                Header::new(":authority", authority),
            ],
            response,
        }
    }

    /// Append a regular request header to the promised request block.
    #[must_use]
    pub fn with_request_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.request_headers.push(Header::new(name, value));
        self
    }
}

/// Outcome for each requested server push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http2PushOutcome {
    /// PUSH_PROMISE was queued and a promised stream was reserved.
    Promised {
        /// Associated client-initiated request stream.
        associated_stream_id: u32,
        /// Reserved promised stream id.
        promised_stream_id: u32,
    },
    /// Push was not queued; the main response can still proceed.
    NotPushed {
        /// Associated client-initiated request stream.
        associated_stream_id: u32,
        /// Reason the push was not emitted.
        reason: Http2PushRejection,
    },
}

/// Typed reason a server push could not be queued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http2PushRejection {
    /// Peer advertised `SETTINGS_ENABLE_PUSH = 0`.
    PeerDisabled,
    /// Associated request stream was cancelled or closed before push could start.
    ParentCancelled,
    /// GOAWAY or drain state prevents opening new promised streams.
    ConnectionClosing,
    /// Any other H2 rejection, captured without requiring `H2Error: Clone`.
    Rejected {
        /// H2 error code.
        code: ErrorCode,
        /// Optional stream id attached by the connection layer.
        stream_id: Option<u32>,
        /// Human-readable reason from the connection layer.
        message: String,
    },
}

fn classify_push_rejection(err: &H2Error) -> Http2PushRejection {
    if err.code == ErrorCode::RefusedStream && err.message == "peer disabled server push" {
        Http2PushRejection::PeerDisabled
    } else if err.code == ErrorCode::StreamClosed && err.message.contains("PUSH_PROMISE on") {
        Http2PushRejection::ParentCancelled
    } else if err.message.contains("GOAWAY") {
        Http2PushRejection::ConnectionClosing
    } else {
        Http2PushRejection::Rejected {
            code: err.code,
            stream_id: err.stream_id,
            message: err.message.clone(),
        }
    }
}

/// RAII in-flight request counter guard (mirrors the HTTP/1.1 server's
/// guard): acquired when a complete request is dispatched to its handler,
/// released after the stream's response frames have left the connection queue.
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

/// Race `fut` against the shutdown signal reaching `ForceClosing`
/// (HTTP/1.1 server parity): `None` means force-close fired and the future
/// was dropped without completing.
async fn race_force_close<F: Future>(signal: &ShutdownSignal, fut: F) -> Option<F::Output> {
    let mut fut = std::pin::pin!(fut);
    let mut force_close_fut = std::pin::pin!(signal.wait_for_phase(ShutdownPhase::ForceClosing));
    std::future::poll_fn(|cx| {
        if signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8 {
            return Poll::Ready(None);
        }
        if force_close_fut.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        fut.as_mut().poll(cx).map(Some)
    })
    .await
}

/// A handler response travelling back to the connection driver, carrying
/// the in-flight guard so accounting is released only after the response
/// frames are queued. The trailing flag records whether the originating
/// request was HEAD and therefore must not receive DATA frames.
type FunnelItem = (u32, Http2Response, InFlightRequestGuard, bool);

fn release_flushed_response_guards(
    conn: &Connection,
    response_guards: &mut HashMap<u32, InFlightRequestGuard>,
) {
    response_guards.retain(|stream_id, _| conn.has_pending_frames_for_stream(*stream_id));
}

fn queue_h2_response(
    conn: &mut Connection,
    stream_id: u32,
    response: impl IntoHttp2Response,
    guard: InFlightRequestGuard,
    suppress_response_body: bool,
    response_guards: &mut HashMap<u32, InFlightRequestGuard>,
) -> Vec<Http2PushOutcome> {
    let mut response = response.into_h2_response();
    if suppress_response_body {
        suppress_response_body_for_head(&mut response.response);
    }
    if let Err(err) = validate_h2_response_for_queue(&response.response, !suppress_response_body) {
        let _ = &err;
        error!(error = %err, "invalid h2 response headers; synthesizing fallback response");
        response = invalid_h2_response_fallback();
    }
    let push_outcomes = queue_h2_server_pushes(conn, stream_id, &response.pushes);

    let header_block = h2_headers_from_response(&response.response)
        .expect("fallback h2 response headers must be valid after validation");
    let trailer_block = h2_trailers_from_response(&response.response)
        .expect("fallback h2 response trailers must be valid after validation");
    let body = std::mem::take(&mut response.response.body);
    let has_trailers = !trailer_block.is_empty();
    let end_stream = body.is_empty() && !has_trailers;
    let mut queued_response = false;
    if conn
        .send_headers(stream_id, header_block, end_stream)
        .is_ok()
    {
        queued_response = true;
        if !end_stream {
            if !body.is_empty() {
                let _ = conn.send_data(stream_id, crate::bytes::Bytes::from(body), !has_trailers);
            }
            if has_trailers {
                let _ = conn.send_headers(stream_id, trailer_block, true);
            }
        }
    }

    if queued_response && conn.has_pending_frames_for_stream(stream_id) {
        let previous = response_guards.insert(stream_id, guard);
        debug_assert!(
            previous.is_none(),
            "one response guard should be active per h2 stream"
        );
    } else {
        drop(guard);
    }

    push_outcomes
}

fn queue_h2_server_pushes(
    conn: &mut Connection,
    associated_stream_id: u32,
    pushes: &[Http2ServerPush],
) -> Vec<Http2PushOutcome> {
    if !associated_stream_accepts_push(conn, associated_stream_id) {
        return pushes
            .iter()
            .map(|_| Http2PushOutcome::NotPushed {
                associated_stream_id,
                reason: Http2PushRejection::ParentCancelled,
            })
            .collect();
    }

    let mut outcomes = Vec::with_capacity(pushes.len());
    for push in pushes {
        let mut pushed_response = push.response.clone();
        if let Err(err) = validate_h2_response_for_queue(&pushed_response, true) {
            outcomes.push(Http2PushOutcome::NotPushed {
                associated_stream_id,
                reason: classify_push_rejection(&err),
            });
            continue;
        }

        let promised_stream_id =
            match conn.send_push_promise(associated_stream_id, push.request_headers.clone()) {
                Ok(promised_stream_id) => promised_stream_id,
                Err(err) => {
                    outcomes.push(Http2PushOutcome::NotPushed {
                        associated_stream_id,
                        reason: classify_push_rejection(&err),
                    });
                    continue;
                }
            };

        let header_block = h2_headers_from_response(&pushed_response)
            .expect("validated pushed h2 response headers must encode");
        let trailer_block =
            h2_trailers_from_response(&pushed_response).expect("validated pushed h2 trailers");
        let body = std::mem::take(&mut pushed_response.body);
        let has_trailers = !trailer_block.is_empty();
        let end_stream = body.is_empty() && !has_trailers;
        if let Err(err) = conn.send_headers(promised_stream_id, header_block, end_stream) {
            conn.reset_stream(promised_stream_id, err.code);
            outcomes.push(Http2PushOutcome::NotPushed {
                associated_stream_id,
                reason: classify_push_rejection(&err),
            });
            continue;
        }
        if !body.is_empty()
            && let Err(err) = conn.send_data(
                promised_stream_id,
                crate::bytes::Bytes::from(body),
                !has_trailers,
            )
        {
            conn.reset_stream(promised_stream_id, err.code);
            outcomes.push(Http2PushOutcome::NotPushed {
                associated_stream_id,
                reason: classify_push_rejection(&err),
            });
            continue;
        }
        if has_trailers && let Err(err) = conn.send_headers(promised_stream_id, trailer_block, true)
        {
            conn.reset_stream(promised_stream_id, err.code);
            outcomes.push(Http2PushOutcome::NotPushed {
                associated_stream_id,
                reason: classify_push_rejection(&err),
            });
            continue;
        }

        outcomes.push(Http2PushOutcome::Promised {
            associated_stream_id,
            promised_stream_id,
        });
    }
    outcomes
}

fn associated_stream_accepts_push(conn: &Connection, stream_id: u32) -> bool {
    conn.stream(stream_id).is_some_and(|stream| {
        matches!(
            stream.state(),
            StreamState::Open | StreamState::HalfClosedRemote
        )
    })
}

fn record_promised_pushes(
    associated_pushes: &mut HashMap<u32, Vec<u32>>,
    outcomes: &[Http2PushOutcome],
) {
    for outcome in outcomes {
        if let Http2PushOutcome::Promised {
            associated_stream_id,
            promised_stream_id,
        } = outcome
        {
            associated_pushes
                .entry(*associated_stream_id)
                .or_default()
                .push(*promised_stream_id);
        }
    }
}

fn reset_associated_pushes(
    conn: &mut Connection,
    associated_pushes: &mut HashMap<u32, Vec<u32>>,
    associated_stream_id: u32,
) {
    let Some(promised_streams) = associated_pushes.remove(&associated_stream_id) else {
        return;
    };

    for promised_stream_id in promised_streams {
        let should_reset = conn
            .stream(promised_stream_id)
            .is_some_and(|stream| !stream.state().is_closed())
            || conn.has_pending_frames_for_stream(promised_stream_id);
        if should_reset {
            conn.reset_stream(promised_stream_id, ErrorCode::Cancel);
        }
    }
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

    // RFC 9110 section 9.3.2: HEAD responses carry the same Content-Length
    // as an equivalent GET response but never send a message body.
    if !has_content_length && (body_len != 0 || had_transfer_encoding) {
        replace_or_insert_header(resp, "Content-Length", body_len.to_string());
    }

    resp.trailers.clear();
    resp.body.clear();
}

/// One wake-up of the connection driver's event select.
enum DriverEvent {
    /// An incoming frame (or EOF when `None`).
    Frame(Option<Result<Frame, H2Error>>),
    /// A handler finished and its response is ready to encode.
    Response(FunnelItem),
    /// The shutdown signal entered `Draining`: begin the stage-1 GOAWAY.
    DrainRequested,
    /// One drain tick elapsed with the stage-1 warning outstanding:
    /// advertise the definitive stage-2 GOAWAY.
    FinalizeTick,
    /// The shutdown signal entered `ForceClosing`: drop the transport.
    ForceClose,
    /// The connection was fully quiescent past its idle budget: close it with
    /// a NO_ERROR GOAWAY (br-asupersync-mfqfst L4).
    IdleTimeout,
    /// An incomplete HEADERS/PUSH_PROMISE CONTINUATION sequence stalled past
    /// the configured budget with no further frame: close it with a
    /// PROTOCOL_ERROR GOAWAY (br-asupersync-mfqfst L4).
    ContinuationTimeout,
}

/// Flush every frame the connection has queued onto the transport.
///
/// Flow-control-blocked DATA stays queued inside the connection (its
/// `next_frame` re-queues it) and is retried after the next processed
/// frame (e.g. a WINDOW_UPDATE) pumps again.
async fn pump_writes(
    conn: &mut Connection,
    framed: &mut Framed<TcpStream, FrameCodec>,
) -> io::Result<()> {
    while let Some(frame) = conn.next_frame() {
        framed.send(frame).map_err(io::Error::other)?;
    }
    std::future::poll_fn(|cx| framed.poll_flush(cx)).await
}

/// Wait for the next driver event: incoming frame, completed handler
/// response, or a shutdown-phase transition.
async fn next_driver_event(
    framed: &mut Framed<TcpStream, FrameCodec>,
    resp_rx: &mut mpsc::Receiver<FunnelItem>,
    task_cx: &Cx,
    signal: &ShutdownSignal,
    watch_drain: bool,
    finalize_deadline: Option<Time>,
    idle_deadline: Option<Time>,
    continuation_deadline: Option<Time>,
) -> DriverEvent {
    if watch_drain && signal.is_shutting_down() {
        return DriverEvent::DrainRequested;
    }
    let mut recv_fut = std::pin::pin!(resp_rx.recv(task_cx));
    let mut force_fut = std::pin::pin!(signal.wait_for_phase(ShutdownPhase::ForceClosing));
    let mut drain_fut = std::pin::pin!(signal.wait_for_phase(ShutdownPhase::Draining));
    // Fixed absolute deadline: the stage-1 -> stage-2 GOAWAY window must not
    // restart on every driver wake-up. Re-creating a relative sleep here let
    // any active traffic (uploads, PINGs, WINDOW_UPDATEs) postpone finalize
    // indefinitely, starving graceful drain and keeping the boundary at
    // 2^31-1 so new streams kept being admitted all through the drain window.
    let mut tick_fut = std::pin::pin!(async move {
        match finalize_deadline {
            Some(deadline) => crate::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
    });
    // br-asupersync-mfqfst L4: absolute idle deadline armed by the caller once
    // the connection went quiescent; like the finalize tick it is fixed (not
    // relative) so it cannot be postponed by spurious wake-ups, and it fires
    // even when no frame ever arrives (the frame-arrival-independent backstop).
    let mut idle_fut = std::pin::pin!(async move {
        match idle_deadline {
            Some(deadline) => crate::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
    });
    // br-asupersync-mfqfst L4: deadline for a stalled CONTINUATION sequence,
    // armed by the caller from the connection's remaining continuation budget.
    // Like the idle deadline it fires without any further frame arriving — the
    // existing check only ran on frame arrival, so a silent client could pin a
    // half-read header block open indefinitely (slowloris).
    let mut continuation_fut = std::pin::pin!(async move {
        match continuation_deadline {
            Some(deadline) => crate::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
    });
    std::future::poll_fn(move |cx| {
        if signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8
            || force_fut.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(DriverEvent::ForceClose);
        }
        if watch_drain && drain_fut.as_mut().poll(cx).is_ready() {
            return Poll::Ready(DriverEvent::DrainRequested);
        }
        if finalize_deadline.is_some() && tick_fut.as_mut().poll(cx).is_ready() {
            return Poll::Ready(DriverEvent::FinalizeTick);
        }
        if idle_deadline.is_some() && idle_fut.as_mut().poll(cx).is_ready() {
            return Poll::Ready(DriverEvent::IdleTimeout);
        }
        if continuation_deadline.is_some() && continuation_fut.as_mut().poll(cx).is_ready() {
            return Poll::Ready(DriverEvent::ContinuationTimeout);
        }
        // Cancel-correct channels make dropping a partially-polled recv
        // safe: no item is consumed unless the future completes.
        if let Poll::Ready(Ok(item)) = recv_fut.as_mut().poll(cx) {
            return Poll::Ready(DriverEvent::Response(item));
        }
        match Pin::new(&mut *framed).poll_next(cx) {
            Poll::Ready(item) => Poll::Ready(DriverEvent::Frame(item)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

/// Dispatch one complete request to the handler on its own task.
///
/// The spawned task races the handler against force-close (h1 parity) and
/// funnels the response back to the driver together with the in-flight
/// guard. Mapping failures reset the stream rather than killing the
/// connection.
#[allow(clippy::too_many_arguments)]
fn dispatch_h2_request<F, Fut, R>(
    conn: &mut Connection,
    stream_id: u32,
    headers: Vec<Header>,
    body: Vec<u8>,
    peer_addr: Option<SocketAddr>,
    handler: &Arc<F>,
    resp_tx: &mpsc::Sender<FunnelItem>,
    shutdown_signal: &ShutdownSignal,
    in_flight_requests: &Arc<AtomicUsize>,
    runtime: &RuntimeHandle,
    host_policy: &HostPolicy,
    request_timeout: Option<Duration>,
    request_timeout_header_cap: Option<Duration>,
    request_drain_grace: Duration,
) where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp2Response + Send + 'static,
{
    let request = match request_from_h2_headers(headers, body, peer_addr) {
        Ok(request) => request,
        Err(_) => {
            conn.reset_stream(stream_id, ErrorCode::ProtocolError);
            return;
        }
    };
    let suppress_response_body = request.method == Method::Head;
    let guard = InFlightRequestGuard::acquire(Some(in_flight_requests));
    let handler = Arc::clone(handler);
    let resp_tx = resp_tx.clone();
    let signal = shutdown_signal.clone();
    let host_policy = host_policy.clone();
    let spawned = runtime.try_spawn(async move {
        let Some(cx) = Cx::current() else {
            drop(guard);
            return;
        };

        // br-asupersync-mfqfst M8: enforce the host allow-list BEFORE the
        // handler runs (h1 parity). h2 carries the effective authority in the
        // synthesized `host` header (see `request_from_h2_headers`); a request
        // whose host isn't allow-listed (or is missing) gets a per-stream 421
        // Misdirected Request (RFC 9113 §9.1.2) instead of reaching the
        // handler, eliminating the host-injection attack surface for
        // absolute-URL emission / OAuth redirect_uri / cache-key computation.
        // Unlike h1 (one request per connection -> connection close), h2 is
        // multiplexed, so only the offending stream is answered with 421; the
        // rest of the connection keeps serving.
        if let Err(rejected_host) = validate_host_header(&request.headers, &host_policy) {
            let body_msg = if rejected_host.is_empty() {
                "Missing required Host header".to_string()
            } else {
                format!("Host '{rejected_host}' not in allowed-hosts allow-list")
            };
            let reject = Response::new(421, "Misdirected Request", body_msg.into_bytes())
                .with_header("content-type", "text/plain; charset=utf-8")
                .into_h2_response();
            if let Ok(permit) = resp_tx.reserve(&cx).await {
                permit.send((stream_id, reject, guard, suppress_response_body));
            }
            return;
        }

        // br-asupersync-mfqfst M8: run the handler inside a server-hop request
        // region so the h2 dispatch path actually has the request budget +
        // deadline + cancel backstop the driver comment promised (h1 parity
        // via `ServerRequestRegion`). The request budget is the connection
        // budget tightened by the configured request timeout and the (opt-in,
        // cap-clamped) client `Request-Timeout` header (meet semantics — it
        // can only tighten, never extend). When no runtime is installed (mint
        // returns `None`) the legacy direct-call path is preserved unchanged.
        let request_now = cx
            .timer_driver()
            .map_or_else(crate::time::wall_now, |timer| timer.now());
        let base_budget = cx.budget();
        let header_timeout = parse_request_timeout_header(&request.headers);
        let (request_budget, budget_source) = derive_request_budget(
            base_budget,
            request_now,
            request_timeout,
            header_timeout,
            request_timeout_header_cap,
        );

        let response = match ServerRequestRegion::mint("h2", request_budget, request_now) {
            Some(region) => {
                // Race the whole hop against ForceClosing so a slow handler
                // cannot block shutdown (drop is the backstop, h1 parity).
                let hop = race_force_close(
                    &signal,
                    region.run_with_protocol_drain(
                        budget_source,
                        None,
                        request_drain_grace,
                        handler(request),
                    ),
                )
                .await;
                match hop {
                    None => {
                        // Force-close interrupted the handler.
                        drop(guard);
                        return;
                    }
                    Some(ServerHopOutcome::Ok(response)) => response.into_h2_response(),
                    Some(ServerHopOutcome::Cancelled | ServerHopOutcome::ConnectionLost) => {
                        // The request was cancelled before producing a
                        // response; nothing useful can be written back. The
                        // stream is torn down with the connection.
                        drop(guard);
                        return;
                    }
                    Some(ServerHopOutcome::Panicked(message)) => {
                        // Panic isolation (h1 parity): the connection driver
                        // survives and the stream completes with a 500 instead
                        // of staying active forever.
                        let _ = &message;
                        error!(message = %message, "h2 handler task panicked");
                        Response::new(500, "Internal Server Error", Vec::new()).into_h2_response()
                    }
                    Some(ServerHopOutcome::DeadlineExceeded) => Response::new(
                        503,
                        "Service Unavailable",
                        b"request budget deadline exceeded".to_vec(),
                    )
                    .into_h2_response(),
                }
            }
            None => {
                // No runtime installed on this thread: preserve the legacy
                // direct-call path (force-close race + panic isolation, no
                // request region).
                let Some(handler_result) = race_force_close(
                    &signal,
                    CatchUnwind {
                        inner: handler(request),
                    },
                )
                .await
                else {
                    drop(guard);
                    return;
                };
                match handler_result {
                    Ok(response) => response.into_h2_response(),
                    Err(payload) => {
                        let message = crate::cx::scope::payload_to_string(&payload);
                        let _ = &message;
                        error!(
                            message = %message,
                            "h2 handler task panicked"
                        );
                        Response::new(500, "Internal Server Error", Vec::new()).into_h2_response()
                    }
                }
            }
        };
        if let Ok(permit) = resp_tx.reserve(&cx).await {
            permit.send((stream_id, response, guard, suppress_response_body));
        }
    });
    if spawned.is_err() {
        conn.reset_stream(stream_id, ErrorCode::InternalError);
    }
}

/// Serve one accepted HTTP/2 connection until close, drain completion, or
/// force-close (br-asupersync-eprpk6 increment 2).
///
/// Protocol shape: strip the 24-byte client preface (the sans-I/O
/// [`Connection`] does not consume it), queue the server SETTINGS, then run
/// an event loop multiplexing incoming frames, completed handler responses,
/// and shutdown transitions. Draining uses the D2.3 two-stage GOAWAY: a
/// stage-1 warning immediately, the definitive stage-2 boundary one drain
/// tick later, transport close at
/// [`Connection::graceful_shutdown_complete`].
/// Builds the inbound frame codec for a freshly-accepted connection, setting
/// the decoder's accept limit to this listener's advertised
/// `SETTINGS_MAX_FRAME_SIZE`. A fresh [`FrameCodec`] otherwise keeps the
/// protocol default (16 KiB), which would reject conformant peer frames sized
/// within a larger advertised limit. `max_frame_size` must be the LOCAL
/// advertised value, never the peer's (br-asupersync-i1r9cw).
fn frame_codec_for(max_frame_size: u32) -> FrameCodec {
    let mut codec = FrameCodec::new();
    codec.set_max_frame_size(max_frame_size);
    codec
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
async fn serve_h2_connection<F, Fut, R>(
    mut stream: TcpStream,
    peer_addr: Option<SocketAddr>,
    handler: Arc<F>,
    settings: Settings,
    shutdown_signal: ShutdownSignal,
    in_flight_requests: Arc<AtomicUsize>,
    runtime: RuntimeHandle,
    max_body_size: usize,
    host_policy: HostPolicy,
    request_timeout: Option<Duration>,
    request_timeout_header_cap: Option<Duration>,
    request_drain_grace: Duration,
    max_requests_per_connection: Option<u64>,
    idle_timeout: Option<Duration>,
    time_getter: fn() -> Time,
) -> io::Result<()>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp2Response + Send + 'static,
{
    let task_cx = Cx::current()
        .ok_or_else(|| io::Error::other("h2 connection task requires a runtime Cx"))?;

    let mut preface = [0u8; CLIENT_PREFACE.len()];
    stream.read_exact(&mut preface).await?;
    if preface != *CLIENT_PREFACE {
        return Err(io::Error::other("invalid HTTP/2 client preface"));
    }

    // Drive the connection's timeout/rate-limit bookkeeping from the same clock
    // the listener uses, so a virtual-time driver makes h2 deadlines (idle,
    // CONTINUATION, RST-window) deterministic in the lab runtime instead of the
    // connection silently reading the wall clock (br-asupersync-faekxk).
    // Honor this listener's advertised SETTINGS_MAX_FRAME_SIZE as the inbound
    // accept limit. Without this the codec keeps the protocol default (16 KiB)
    // even when the local settings advertise a larger `max_frame_size`, so a
    // conformant peer frame sized within the advertised limit would be wrongly
    // rejected with FRAME_SIZE_ERROR. The accept limit is always the LOCAL
    // advertised value, never the peer's (br-asupersync-i1r9cw).
    let local_max_frame_size = settings.max_frame_size;
    let mut conn = Connection::server_with_time_getter(settings, time_getter);
    conn.queue_initial_settings();
    let mut framed = Framed::new(stream, frame_codec_for(local_max_frame_size));

    let (resp_tx, mut resp_rx) = mpsc::channel::<FunnelItem>(RESPONSE_FUNNEL_CAPACITY);
    // Per-stream request assembly: headers arrive first, DATA accumulates
    // until END_STREAM completes the request.
    let mut pending_requests: HashMap<u32, (Vec<Header>, Vec<u8>)> = HashMap::new();
    // Fixed stage-2 GOAWAY deadline, armed once when stage-1 is outstanding.
    let mut finalize_at: Option<Time> = None;
    let mut response_guards: HashMap<u32, InFlightRequestGuard> = HashMap::new();
    let mut associated_pushes: HashMap<u32, Vec<u32>> = HashMap::new();
    // br-asupersync-mfqfst L4: count requests dispatched to the handler on
    // this connection so it can be recycled once the configured budget is
    // reached (see the recycle check at the end of the loop body).
    let mut requests_dispatched: u64 = 0;
    // br-asupersync-mfqfst L4: absolute idle deadline, armed once when the
    // connection becomes fully quiescent and cleared as soon as activity
    // resumes (kept fixed in between so it is not pushed forward by wake-ups).
    let mut idle_at: Option<Time> = None;

    loop {
        pump_writes(&mut conn, &mut framed).await?;
        release_flushed_response_guards(&conn, &mut response_guards);

        // Do not close the transport while frames remain queued. Flow-control
        // -blocked DATA stays in the connection's pending_ops after
        // pump_writes (its next_frame re-queues it), and neither
        // graceful_shutdown_complete() nor goaway_received() consult it.
        // Closing here would truncate an in-flight response and mis-report
        // the loss as a clean drain. The connection stays open until a
        // WINDOW_UPDATE unblocks the data or the drain supervisor escalates
        // to force-close.
        if !conn.has_pending_frames()
            && (conn.graceful_shutdown_complete()
                || (conn.goaway_received()
                    && conn.active_stream_count() == 0
                    && pending_requests.is_empty()))
        {
            std::future::poll_fn(|cx| framed.poll_close(cx)).await?;
            return Ok(());
        }

        let watch_drain = !conn.goaway_sent();
        let now = Cx::current()
            .and_then(|cx| cx.timer_driver())
            .map_or_else(crate::time::wall_now, |timer| timer.now());
        // Arm the stage-2 finalize deadline once, when the stage-1 GOAWAY is
        // outstanding; keep it fixed across loop iterations so active traffic
        // cannot reset the window.
        if conn.graceful_shutdown_pending() {
            if finalize_at.is_none() {
                finalize_at = Some(now + DRAIN_SUPERVISION_TICK);
            }
        } else {
            finalize_at = None;
        }
        // br-asupersync-mfqfst L4: arm the idle timeout while the connection is
        // fully quiescent — no active streams, nothing being assembled, no
        // queued frames, not mid-CONTINUATION, and no GOAWAY in flight (the
        // shutdown paths own closing once a GOAWAY is sent). A busy connection
        // never trips it; an idle keep-alive or a client that connects and
        // makes no progress is reclaimed after the configured budget.
        let connection_idle = !conn.goaway_sent()
            && conn.active_stream_count() == 0
            && pending_requests.is_empty()
            && !conn.is_awaiting_continuation()
            && !conn.has_pending_frames();
        if let Some(timeout) = idle_timeout.filter(|_| connection_idle) {
            if idle_at.is_none() {
                idle_at = Some(now + timeout);
            }
        } else {
            idle_at = None;
        }
        // br-asupersync-mfqfst L4: while a header block is mid-CONTINUATION,
        // arm an absolute deadline from the connection's remaining budget so a
        // client that opens the block and goes silent is reclaimed instead of
        // hanging. Recomputed each iteration: as wall time advances the
        // remaining budget shrinks by the same amount, so `now + remaining`
        // stays a stable absolute deadline and collapses to `now` once spent.
        let continuation_at = conn
            .continuation_timeout_remaining()
            .map(|remaining| now + remaining);
        let event = next_driver_event(
            &mut framed,
            &mut resp_rx,
            &task_cx,
            &shutdown_signal,
            watch_drain,
            finalize_at,
            idle_at,
            continuation_at,
        )
        .await;

        match event {
            DriverEvent::ForceClose => {
                // Escalation: drop the transport; spawned handler hops are
                // raced against ForceClosing and request-region teardown is
                // the cancellation backstop (h1 parity).
                return Ok(());
            }
            DriverEvent::DrainRequested => {
                conn.begin_graceful_shutdown(crate::bytes::Bytes::from_static(b"server draining"));
            }
            DriverEvent::FinalizeTick => {
                conn.finalize_graceful_shutdown(crate::bytes::Bytes::new());
            }
            DriverEvent::IdleTimeout => {
                // br-asupersync-mfqfst L4: the connection has been fully
                // quiescent past the idle budget (it is only armed when no
                // stream is active and nothing is queued), so a NO_ERROR
                // GOAWAY + close strands no in-flight work. h1 parity with
                // the keep-alive idle timeout.
                conn.goaway(
                    ErrorCode::NoError,
                    crate::bytes::Bytes::from_static(b"idle timeout"),
                );
                pump_writes(&mut conn, &mut framed).await?;
                let _ = std::future::poll_fn(|cx| framed.poll_close(cx)).await;
                return Ok(());
            }
            DriverEvent::ContinuationTimeout => {
                // br-asupersync-mfqfst L4: a header block was left incomplete
                // past the CONTINUATION budget with no further frame. RFC 9113
                // §6.10 treats a broken CONTINUATION sequence as a connection
                // PROTOCOL_ERROR, so GOAWAY + close (matching the on-arrival
                // check in Connection::check_continuation_timeout).
                conn.goaway(
                    ErrorCode::ProtocolError,
                    crate::bytes::Bytes::from_static(b"CONTINUATION timeout"),
                );
                pump_writes(&mut conn, &mut framed).await?;
                let _ = std::future::poll_fn(|cx| framed.poll_close(cx)).await;
                return Ok(());
            }
            DriverEvent::Frame(None) => {
                // Peer closed the transport.
                return Ok(());
            }
            DriverEvent::Frame(Some(Err(decode_error))) => {
                conn.goaway(decode_error.code, crate::bytes::Bytes::new());
                pump_writes(&mut conn, &mut framed).await?;
                let _ = std::future::poll_fn(|cx| framed.poll_close(cx)).await;
                return Err(io::Error::other(decode_error));
            }
            DriverEvent::Frame(Some(Ok(frame))) => match conn.process_frame(frame) {
                Err(protocol_error) => {
                    // Stream-scoped errors (RFC 9113 §5.4.2) reset only the
                    // offending stream; tearing down the whole multiplexed
                    // connection would kill every other in-flight request
                    // (e.g. a single malformed header block, a stream-level
                    // flow-control error, or the routine race of client DATA
                    // arriving after the server reset a stream).
                    if let Some(stream_id) = protocol_error.stream_id {
                        conn.reset_stream(stream_id, protocol_error.code);
                        pending_requests.remove(&stream_id);
                        reset_associated_pushes(&mut conn, &mut associated_pushes, stream_id);
                    } else {
                        conn.goaway(protocol_error.code, crate::bytes::Bytes::new());
                        pump_writes(&mut conn, &mut framed).await?;
                        let _ = std::future::poll_fn(|cx| framed.poll_close(cx)).await;
                        return Err(io::Error::other(protocol_error));
                    }
                }
                Ok(Some(ReceivedFrame::Headers {
                    stream_id,
                    headers,
                    end_stream,
                })) => {
                    if let Some((req_headers, req_body)) = pending_requests.remove(&stream_id) {
                        // A second HEADERS block on a stream already
                        // assembling a body is request trailers (RFC 9113
                        // §8.1; the connection enforces trailers carry
                        // END_STREAM). The buffered request is now complete;
                        // dispatch it. Trailer fields are not surfaced through
                        // the h1 Request type.
                        dispatch_h2_request(
                            &mut conn,
                            stream_id,
                            req_headers,
                            req_body,
                            peer_addr,
                            &handler,
                            &resp_tx,
                            &shutdown_signal,
                            &in_flight_requests,
                            &runtime,
                            &host_policy,
                            request_timeout,
                            request_timeout_header_cap,
                            request_drain_grace,
                        );
                        requests_dispatched = requests_dispatched.saturating_add(1);
                    } else if end_stream {
                        dispatch_h2_request(
                            &mut conn,
                            stream_id,
                            headers,
                            Vec::new(),
                            peer_addr,
                            &handler,
                            &resp_tx,
                            &shutdown_signal,
                            &in_flight_requests,
                            &runtime,
                            &host_policy,
                            request_timeout,
                            request_timeout_header_cap,
                            request_drain_grace,
                        );
                        requests_dispatched = requests_dispatched.saturating_add(1);
                    } else {
                        pending_requests.insert(stream_id, (headers, Vec::new()));
                    }
                }
                Ok(Some(ReceivedFrame::Data {
                    stream_id,
                    data,
                    end_stream,
                })) => {
                    if let Some((_, body)) = pending_requests.get_mut(&stream_id) {
                        if body.len().saturating_add(data.len()) > max_body_size {
                            // Bound per-stream request buffering: HTTP/2 flow
                            // control auto-replenishes windows, so without
                            // this cap one stream could buffer unbounded bytes
                            // (remote OOM). Refuse the stream and drop its
                            // partial body.
                            conn.reset_stream(stream_id, ErrorCode::EnhanceYourCalm);
                            pending_requests.remove(&stream_id);
                        } else {
                            body.extend_from_slice(&data);
                            if end_stream {
                                let (headers, body) = pending_requests
                                    .remove(&stream_id)
                                    .expect("pending request present");
                                dispatch_h2_request(
                                    &mut conn,
                                    stream_id,
                                    headers,
                                    body,
                                    peer_addr,
                                    &handler,
                                    &resp_tx,
                                    &shutdown_signal,
                                    &in_flight_requests,
                                    &runtime,
                                    &host_policy,
                                    request_timeout,
                                    request_timeout_header_cap,
                                    request_drain_grace,
                                );
                                requests_dispatched = requests_dispatched.saturating_add(1);
                            }
                        }
                    }
                }
                Ok(Some(ReceivedFrame::Reset { stream_id, .. })) => {
                    pending_requests.remove(&stream_id);
                    reset_associated_pushes(&mut conn, &mut associated_pushes, stream_id);
                }
                Ok(_) => {}
            },
            DriverEvent::Response((stream_id, response, guard, suppress_response_body)) => {
                let outcomes = queue_h2_response(
                    &mut conn,
                    stream_id,
                    response,
                    guard,
                    suppress_response_body,
                    &mut response_guards,
                );
                record_promised_pushes(&mut associated_pushes, &outcomes);
            }
        }

        // br-asupersync-mfqfst L4: recycle the connection once it has served
        // its configured request budget (h1 parity with
        // `Http1Config::max_requests_per_connection`). A graceful shutdown
        // stops admitting new streams while letting the in-flight streams —
        // including the one that hit the limit — run to completion; the
        // existing two-stage GOAWAY + drain machinery then closes the
        // transport. No-op once any GOAWAY is already on the wire (e.g. a
        // server-initiated drain), so it never double-arms the shutdown.
        if !conn.goaway_sent()
            && max_requests_per_connection.is_some_and(|max| requests_dispatched >= max)
        {
            conn.begin_graceful_shutdown(crate::bytes::Bytes::from_static(
                b"max requests per connection reached",
            ));
        }
    }
}

/// Configuration for the HTTP/2 listener (br-asupersync-eprpk6).
#[derive(Debug, Clone)]
pub struct Http2ListenerConfig {
    /// HTTP/2 connection settings advertised by the server.
    pub settings: Settings,
    /// Maximum concurrent connections. `None` means unlimited.
    pub max_connections: Option<usize>,
    /// Soft drain budget: when it elapses with requests in flight, the
    /// drain supervisor escalates stragglers through force-close.
    pub drain_timeout: Duration,
    /// Hard drain deadline (clamped up to at least `drain_timeout`).
    pub hard_drain_timeout: Duration,
    /// Keep the listening socket bound (not accepting) until drain
    /// completes (h1 parity, D2.4 AC5 semantics).
    pub lb_compat_keep_socket: bool,
    /// Maximum buffered request body per stream before the stream is refused
    /// (h1 parity with `Http1Config::max_body_size`). Bounds receiver memory
    /// because HTTP/2 flow control auto-replenishes windows.
    pub max_body_size: usize,
    /// br-asupersync-mfqfst M8: host allow-list policy (h1 parity with
    /// `Http1Config::allowed_hosts`). SECURITY: defends against Host header
    /// injection. The effective h2 authority (`:authority`) is checked through
    /// the synthesized `host` header. Secure by default (`RejectUnknown`);
    /// set `AllowList`/`AllowAll` explicitly. Rejected requests get a
    /// per-stream 421 Misdirected Request (the connection keeps serving).
    pub allowed_hosts: HostPolicy,
    /// br-asupersync-mfqfst M8: server-default per-request timeout (h1 parity
    /// with `Http1Config::request_timeout`). When set, every request budget is
    /// tightened by this duration at the dispatch hop (meet semantics — it can
    /// only tighten, never extend). `None` means no server-imposed deadline.
    pub request_timeout: Option<Duration>,
    /// br-asupersync-mfqfst M8: opt-in cap for the client-supplied
    /// `Request-Timeout` header (h1 parity). `None` ignores the header
    /// entirely; when set, a parseable header tightens the budget by
    /// `min(header, cap)` — a client can never extend the budget past the cap.
    pub request_timeout_header_cap: Option<Duration>,
    /// br-asupersync-mfqfst M8: bounded drain grace after a request-budget
    /// deadline or a connection cancel — the handler gets this long to observe
    /// the cancel and finish cleanly before the drop backstop (h1 parity).
    pub request_drain_grace: Duration,
    /// br-asupersync-mfqfst L4: maximum number of requests served on a single
    /// connection before the server recycles it with a graceful GOAWAY (h1
    /// parity with `Http1Config::max_requests_per_connection`). `None` means
    /// unlimited. Bounds per-connection resource accumulation and lets a load
    /// balancer rebalance long-lived multiplexed connections. When the limit
    /// is reached the server begins a graceful shutdown: new streams are
    /// refused (after the two-stage GOAWAY ratchets down) while the in-flight
    /// streams — including the one that hit the limit — run to completion.
    pub max_requests_per_connection: Option<u64>,
    /// br-asupersync-mfqfst L4: idle timeout for a fully-quiescent connection
    /// (h1 parity with `Http1Config::idle_timeout`). When the connection holds
    /// no active streams, no requests being assembled, no queued frames, and
    /// is not mid-CONTINUATION for this long, the server closes it with a
    /// NO_ERROR GOAWAY. This reclaims idle keep-alive connections and is a
    /// frame-arrival-independent backstop against a client that opens a
    /// connection and then makes no progress (slowloris). `None` disables it.
    pub idle_timeout: Option<Duration>,
    /// Time source for shutdown bookkeeping and drain supervision.
    pub time_getter: fn() -> Time,
}

fn default_h2_listener_time_getter() -> Time {
    Cx::current()
        .and_then(|current| current.timer_driver())
        .map_or_else(crate::time::wall_now, |driver| driver.now())
}

impl Default for Http2ListenerConfig {
    fn default() -> Self {
        Self {
            settings: Settings::server(),
            max_connections: Some(10_000),
            drain_timeout: Duration::from_secs(30),
            hard_drain_timeout: Duration::from_secs(60),
            lb_compat_keep_socket: false,
            max_body_size: DEFAULT_H2_MAX_BODY_SIZE,
            allowed_hosts: HostPolicy::default(), // Secure by default: RejectUnknown
            request_timeout: None,
            request_timeout_header_cap: None,
            request_drain_grace: Duration::from_millis(500),
            max_requests_per_connection: Some(1000),
            idle_timeout: Some(Duration::from_secs(60)),
            time_getter: default_h2_listener_time_getter,
        }
    }
}

impl Http2ListenerConfig {
    /// Set the advertised HTTP/2 settings.
    #[must_use]
    pub fn settings(mut self, settings: Settings) -> Self {
        self.settings = settings;
        self
    }

    /// Set the maximum number of concurrent connections.
    #[must_use]
    pub fn max_connections(mut self, max: Option<usize>) -> Self {
        self.max_connections = max;
        self
    }

    /// Set the soft drain budget for graceful shutdown.
    #[must_use]
    pub fn drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    /// Set the hard drain deadline budget for graceful shutdown.
    #[must_use]
    pub fn hard_drain_timeout(mut self, timeout: Duration) -> Self {
        self.hard_drain_timeout = timeout;
        self
    }

    /// Keep the listening socket bound (not accepting) until drain
    /// completes.
    #[must_use]
    pub fn lb_compat_keep_socket(mut self, keep: bool) -> Self {
        self.lb_compat_keep_socket = keep;
        self
    }

    /// Set the maximum buffered request body per stream.
    #[must_use]
    pub fn max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }

    /// Set the host allow-list policy (br-asupersync-mfqfst M8). Use
    /// [`HostPolicy::allow_list`], [`HostPolicy::reject_unknown`], or
    /// [`HostPolicy::allow_all`] (insecure legacy mode).
    #[must_use]
    pub fn host_policy(mut self, policy: HostPolicy) -> Self {
        self.allowed_hosts = policy;
        self
    }

    /// Set the server-default per-request timeout (br-asupersync-mfqfst M8).
    #[must_use]
    pub fn request_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Set the opt-in cap for the client `Request-Timeout` header
    /// (br-asupersync-mfqfst M8).
    #[must_use]
    pub fn request_timeout_header_cap(mut self, cap: Option<Duration>) -> Self {
        self.request_timeout_header_cap = cap;
        self
    }

    /// Set the bounded drain grace after a request-budget deadline or
    /// connection cancel (br-asupersync-mfqfst M8).
    #[must_use]
    pub fn request_drain_grace(mut self, grace: Duration) -> Self {
        self.request_drain_grace = grace;
        self
    }

    /// Set the maximum number of requests served per connection before the
    /// server recycles it with a graceful GOAWAY (br-asupersync-mfqfst L4).
    /// `None` is unlimited (h1 parity with
    /// `Http1Config::max_requests_per_connection`).
    #[must_use]
    pub fn max_requests_per_connection(mut self, max: Option<u64>) -> Self {
        self.max_requests_per_connection = max;
        self
    }

    /// Set the idle timeout for a fully-quiescent connection
    /// (br-asupersync-mfqfst L4). `None` disables it (h1 parity with
    /// `Http1Config::idle_timeout`).
    #[must_use]
    pub fn idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the time source for listener bookkeeping.
    #[must_use]
    pub fn time_getter(mut self, time_getter: fn() -> Time) -> Self {
        self.time_getter = time_getter;
        self
    }
}

fn h2_shutdown_signal_for_time_getter(time_getter: fn() -> Time) -> ShutdownSignal {
    if std::ptr::fn_addr_eq(time_getter, default_h2_listener_time_getter as fn() -> Time) {
        ShutdownSignal::new()
    } else {
        ShutdownSignal::with_time_getter(time_getter)
    }
}

/// HTTP/2 server listener: accepts connections and serves each through the
/// frame-pump driver with request-aware graceful drain
/// (br-asupersync-eprpk6 increment 3; mirrors [`Http1Listener`] semantics).
///
/// [`Http1Listener`]: crate::http::h1::listener::Http1Listener
pub struct Http2Listener<F> {
    tcp_listener: TcpListener,
    handler: Arc<F>,
    config: Http2ListenerConfig,
    shutdown_signal: ShutdownSignal,
    connection_manager: ConnectionManager,
    stats: Arc<Http2ListenerStats>,
    in_flight_requests: Arc<AtomicUsize>,
}

impl<F, Fut, R> Http2Listener<F>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send + 'static,
    R: IntoHttp2Response + Send + 'static,
{
    /// Bind to the given address with default configuration.
    pub async fn bind<A: ToSocketAddrs + Send + 'static>(addr: A, handler: F) -> io::Result<Self> {
        Self::bind_with_config(addr, handler, Http2ListenerConfig::default()).await
    }

    /// Bind with custom configuration.
    pub async fn bind_with_config<A: ToSocketAddrs + Send + 'static>(
        addr: A,
        handler: F,
        config: Http2ListenerConfig,
    ) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        Ok(Self::from_parts(tcp_listener, handler, config))
    }

    /// Create from an existing [`TcpListener`] with custom configuration.
    #[must_use]
    pub fn from_listener(
        tcp_listener: TcpListener,
        handler: F,
        config: Http2ListenerConfig,
    ) -> Self {
        Self::from_parts(tcp_listener, handler, config)
    }

    fn from_parts(tcp_listener: TcpListener, handler: F, config: Http2ListenerConfig) -> Self {
        let shutdown_signal = h2_shutdown_signal_for_time_getter(config.time_getter);
        let connection_manager = ConnectionManager::with_time_getter(
            config.max_connections,
            shutdown_signal.clone(),
            config.time_getter,
        );
        let stats = Arc::new(Http2ListenerStats::new(config.time_getter));
        Self {
            tcp_listener,
            handler: Arc::new(handler),
            config,
            shutdown_signal,
            connection_manager,
            stats,
            in_flight_requests: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Returns a clone of the shutdown signal for external phase observation.
    #[must_use]
    pub fn shutdown_signal(&self) -> ShutdownSignal {
        self.shutdown_signal.clone()
    }

    /// Begins graceful shutdown using the listener's configured drain timeout.
    #[must_use]
    pub fn begin_drain(&self) -> bool {
        self.connection_manager
            .begin_drain(self.config.drain_timeout)
    }

    /// Returns a reference to the connection manager.
    #[must_use]
    pub fn connection_manager(&self) -> &ConnectionManager {
        &self.connection_manager
    }

    /// Returns the accept-path and drain diagnostic counters for this listener.
    #[must_use]
    pub fn stats_handle(&self) -> Arc<Http2ListenerStats> {
        Arc::clone(&self.stats)
    }

    /// Returns the listener-wide in-flight request counter.
    #[must_use]
    pub fn in_flight_requests(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.in_flight_requests)
    }

    /// Returns the local address this listener is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp_listener.local_addr()
    }

    /// Run the accept loop until shutdown, then drain with request-aware
    /// supervision and return the shutdown statistics (including the
    /// graceful-drain report).
    #[allow(clippy::too_many_lines)]
    pub async fn run(self, runtime: &RuntimeHandle) -> io::Result<ShutdownStats> {
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();
        // Independent push counter so finished connection tasks are reaped
        // periodically instead of accumulating for the listener's lifetime
        // (h1 parity — prevents unbounded memory growth under churn).
        let mut accept_count: u64 = 0;
        // Streak of consecutive transient accept errors for backoff.
        let mut transient_accept_streak: u32 = 0;
        let mut shutdown_rx = self.shutdown_signal.subscribe();

        enum AcceptOrShutdown {
            Accept(io::Result<(TcpStream, SocketAddr)>),
            Shutdown,
        }

        loop {
            if self.shutdown_signal.is_shutting_down() {
                break;
            }

            let result = {
                let accept_fut = self.tcp_listener.accept();
                let shutdown_fut = shutdown_rx.wait();
                let mut accept_fut = core::pin::pin!(accept_fut);
                let mut shutdown_fut = core::pin::pin!(shutdown_fut);
                std::future::poll_fn(|cx| {
                    if self.shutdown_signal.is_shutting_down() {
                        return Poll::Ready(AcceptOrShutdown::Shutdown);
                    }
                    if shutdown_fut.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(AcceptOrShutdown::Shutdown);
                    }
                    if let Poll::Ready(r) = accept_fut.as_mut().poll(cx) {
                        return Poll::Ready(AcceptOrShutdown::Accept(r));
                    }
                    Poll::Pending
                })
                .await
            };

            let (stream, addr) = match result {
                AcceptOrShutdown::Shutdown => break,
                AcceptOrShutdown::Accept(Ok(conn)) => {
                    self.stats.record_accepted();
                    transient_accept_streak = 0;
                    conn
                }
                AcceptOrShutdown::Accept(Err(ref e)) if is_transient_accept_error(e) => {
                    // Back off on a streak of transient errors so a persistent
                    // accept failure (e.g. EMFILE) does not busy-spin the
                    // accept loop (h1 parity).
                    self.stats.record_transient_accept_error();
                    transient_accept_streak = transient_accept_streak.saturating_add(1);
                    let now = (self.config.time_getter)();
                    crate::time::sleep(
                        now,
                        transient_accept_backoff_delay(transient_accept_streak),
                    )
                    .await;
                    continue;
                }
                AcceptOrShutdown::Accept(Err(e)) => return Err(e),
            };

            let Some(guard) = self.connection_manager.register(addr) else {
                drop(stream);
                continue;
            };

            let handler = Arc::clone(&self.handler);
            let settings = self.config.settings.clone();
            let shutdown_signal = self.shutdown_signal.clone();
            let in_flight_requests = Arc::clone(&self.in_flight_requests);
            let runtime_for_conn = runtime.clone();
            let max_body_size = self.config.max_body_size;
            let host_policy = self.config.allowed_hosts.clone();
            let request_timeout = self.config.request_timeout;
            let request_timeout_header_cap = self.config.request_timeout_header_cap;
            let request_drain_grace = self.config.request_drain_grace;
            let max_requests_per_connection = self.config.max_requests_per_connection;
            let idle_timeout = self.config.idle_timeout;
            let conn_time_getter = self.config.time_getter;
            let spawn_result = runtime.try_spawn(async move {
                let peer_addr = Some(addr);
                if let Err(err) = serve_h2_connection(
                    stream,
                    peer_addr,
                    handler,
                    settings,
                    shutdown_signal,
                    in_flight_requests,
                    runtime_for_conn,
                    max_body_size,
                    host_policy,
                    request_timeout,
                    request_timeout_header_cap,
                    request_drain_grace,
                    max_requests_per_connection,
                    idle_timeout,
                    conn_time_getter,
                )
                .await
                {
                    // Bind unconditionally: tracing_compat::error! compiles
                    // to nothing without the tracing feature.
                    let _ = &err;
                    error!(error = %err, "h2 connection task failed");
                }
                drop(guard);
            });
            match spawn_result {
                Ok(handle) => {
                    tasks.push(handle);
                    accept_count = accept_count.wrapping_add(1);
                    if accept_count.is_multiple_of(64) {
                        tasks.retain(|h| !h.is_finished());
                    }
                }
                Err(err) => {
                    self.stats.record_spawn_failure();
                    if should_retry_after_spawn_failure(&err) {
                        // Connection-scoped capacity blip: drop this
                        // connection (its guard is released when the dropped
                        // future is collected) and keep accepting (h1 parity).
                        continue;
                    }
                    return Err(io::Error::other(format!(
                        "failed to spawn h2 connection task: {err}"
                    )));
                }
            }
        }

        // Drain phase: socket lifetime is explicit (h1 D2.4 AC5 parity).
        let parked_socket = self
            .config
            .lb_compat_keep_socket
            .then_some(self.tcp_listener);

        if self.shutdown_signal.phase() == ShutdownPhase::Running {
            let _ = self
                .connection_manager
                .begin_drain(self.config.drain_timeout);
        }

        // Request-aware drain supervision, CONCURRENT with the connection
        // manager's own drain so connection-level accounting is untouched
        // (sequential composition breaks force_closed accounting — see the
        // h1 listener, D2.2b).
        let supervise = async {
            let drain_start = (self.config.time_getter)();
            let in_flight_at_start = self.in_flight_requests.load(Ordering::Acquire);
            self.stats.record_drain_started(in_flight_at_start);
            let mut supervisor = GracefulDrainSupervisor::new(
                in_flight_at_start,
                drain_start,
                self.config.drain_timeout,
                self.config.hard_drain_timeout,
            );
            let mut hard_deadline_hit = false;
            loop {
                let now = (self.config.time_getter)();
                if self.shutdown_signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8
                    && now >= supervisor.drain_deadline()
                    && supervisor.record_external_escalation()
                {
                    self.stats.record_drain_escalated();
                }
                match supervisor.observe(self.in_flight_requests.load(Ordering::Acquire), now) {
                    DrainStep::Continue => {
                        let sleep_now = Cx::current()
                            .and_then(|cx| cx.timer_driver())
                            .map_or_else(crate::time::wall_now, |timer| timer.now());
                        crate::time::sleep(sleep_now, DRAIN_SUPERVISION_TICK).await;
                    }
                    DrainStep::Escalate => {
                        self.stats.record_drain_escalated();
                        let _ = self.shutdown_signal.begin_force_close();
                    }
                    DrainStep::Quiescent => break,
                    DrainStep::HardDeadline => {
                        hard_deadline_hit = true;
                        self.stats.record_drain_hard_deadline();
                        let _ = self.shutdown_signal.begin_force_close();
                        break;
                    }
                }
            }
            let report = supervisor.finish((self.config.time_getter)(), hard_deadline_hit);
            self.stats.record_drain_finished(&report);
            report
        };
        let drain = self.connection_manager.drain_with_stats();

        let mut supervise = core::pin::pin!(supervise);
        let mut drain = core::pin::pin!(drain);
        let mut report_slot = None;
        let mut stats_slot = None;
        std::future::poll_fn(|cx| {
            if report_slot.is_none()
                && let Poll::Ready(report) = supervise.as_mut().poll(cx)
            {
                report_slot = Some(report);
            }
            if stats_slot.is_none()
                && let Poll::Ready(stats) = drain.as_mut().poll(cx)
            {
                stats_slot = Some(stats);
            }
            if report_slot.is_some() && stats_slot.is_some() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        let mut stats = stats_slot.take().expect("drain stats present after join");
        stats.drain_report = report_slot.take();

        let is_force_closing = self.shutdown_signal.phase() == ShutdownPhase::ForceClosing;

        for task in tasks {
            if let Err(payload) = (CatchUnwind { inner: task }).await {
                // Bind unconditionally: tracing_compat::error! compiles to
                // nothing without the tracing feature.
                let _ = &payload;
                error!(
                    message = %crate::cx::scope::payload_to_string(&payload),
                    "h2 connection task panicked"
                );
            }
        }

        if self.connection_manager.is_empty() {
            self.shutdown_signal.mark_stopped();
            if is_force_closing {
                let drain_report = stats.drain_report.take();
                stats = self
                    .shutdown_signal
                    .collect_stats(stats.drained, stats.force_closed);
                stats.drain_report = drain_report;
            }
        }

        drop(parked_socket);
        Ok(stats)
    }
}

/// Panic isolation for connection-task joins (HTTP/1.1 listener parity):
/// a panicked or force-cancelled task must not take down the listener's
/// drain/stats path.
#[pin_project::pin_project]
struct CatchUnwind<F> {
    #[pin]
    inner: F,
}

impl<F: Future> Future for CatchUnwind<F> {
    type Output = std::thread::Result<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            this.inner.as_mut().poll(cx)
        }));
        match result {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
            Err(payload) => Poll::Ready(Err(payload)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        static H2_LISTENER_TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn set_h2_listener_test_time(time: Time) {
        H2_LISTENER_TEST_NOW.with(|now| now.set(time.as_nanos()));
    }

    fn h2_listener_test_time() -> Time {
        H2_LISTENER_TEST_NOW.with(|now| Time::from_nanos(now.get()))
    }

    fn request_block(extra: &[(&str, &str)]) -> Vec<Header> {
        let mut headers = vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":path", "/widgets?q=1"),
            Header::new(":authority", "example.com:8443"),
        ];
        for (name, value) in extra {
            headers.push(Header::new(*name, *value));
        }
        headers
    }

    fn encode_hpack_test_headers(headers: &[(&str, &str)]) -> crate::bytes::Bytes {
        let mut encoder = crate::http::h2::hpack::Encoder::new();
        let mut encoded = crate::bytes::BytesMut::new();
        let headers = headers
            .iter()
            .map(|(name, value)| Header::new(*name, *value))
            .collect::<Vec<_>>();
        encoder.encode(&headers, &mut encoded);
        encoded.freeze()
    }

    fn expect_settings_ack(conn: &mut Connection) {
        match conn.next_frame().expect("SETTINGS ACK should be queued") {
            Frame::Settings(settings) => assert!(settings.ack, "expected SETTINGS ACK"),
            other => panic!("expected SETTINGS ACK, got {other:?}"),
        }
    }

    async fn panicking_h2_handler(_request: Request) -> Response {
        panic!("handler exploded")
    }

    #[test]
    fn stats_snapshot_records_accept_spawn_and_drain_counters() {
        let stats = Http2ListenerStats::new(h2_listener_test_time);

        set_h2_listener_test_time(Time::from_millis(321));
        stats.record_accepted();
        stats.record_transient_accept_error();
        stats.record_spawn_failure();
        stats.record_drain_started(3);
        stats.record_drain_escalated();
        stats.record_drain_hard_deadline();
        stats.record_drain_finished(&GracefulDrainReport {
            requests_at_drain_start: 3,
            requests_completed: 1,
            requests_stranded: 2,
            requests_at_escalation: Some(2),
            observations: 4,
            final_phase: crate::cancel::DrainPhase::SlowTail,
            converging: false,
            confidence_bound: 0.25,
            estimated_remaining_steps: Some(2.0),
            stall_detected: true,
            reached_quiescence: false,
            hard_deadline_hit: true,
            drain_duration: Duration::from_millis(77),
        });

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.accepted_total, 1);
        assert_eq!(snapshot.transient_accept_errors_total, 1);
        assert_eq!(snapshot.spawn_failures_total, 1);
        assert_eq!(snapshot.last_accept_at_ms, 321);
        assert_eq!(snapshot.drains_started_total, 1);
        assert_eq!(snapshot.drain_escalations_total, 1);
        assert_eq!(snapshot.drain_hard_deadline_hits_total, 1);
        assert_eq!(snapshot.drains_quiescent_total, 0);
        assert_eq!(snapshot.last_drain_requests_at_start, 3);
        assert_eq!(snapshot.last_drain_requests_stranded, 2);
        assert_eq!(snapshot.last_drain_duration_ms, 77);
    }

    #[test]
    fn stats_handle_uses_configured_time_getter() {
        crate::test_utils::run_test(|| async {
            let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
            let listener = Http2Listener::from_listener(
                tcp,
                |_req| async { Response::new(200, "OK", Vec::new()) },
                Http2ListenerConfig::default().time_getter(h2_listener_test_time),
            );

            set_h2_listener_test_time(Time::from_millis(456));
            listener.stats_handle().record_accepted();

            assert_eq!(listener.stats_handle().snapshot().last_accept_at_ms, 456);
        });
    }

    #[test]
    fn continuation_split_headers_map_to_listener_request() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );

        let encoded = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/split-continuation"),
            (":authority", "split.example"),
            ("x-trace", "split-block"),
        ]);
        assert!(encoded.len() > 1, "test header block must be splittable");
        let split = encoded.len() / 2;

        assert!(
            conn.process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                encoded.slice(..split),
                true,
                false
            )))
            .expect("partial HEADERS accepted")
            .is_none()
        );

        let received = conn
            .process_frame(Frame::Continuation(
                crate::http::h2::frame::ContinuationFrame {
                    stream_id: 1,
                    header_block: encoded.slice(split..),
                    end_headers: true,
                },
            ))
            .expect("CONTINUATION completes header block")
            .expect("decoded header block emitted");

        let ReceivedFrame::Headers {
            stream_id,
            headers,
            end_stream,
        } = received
        else {
            panic!("expected decoded request headers");
        };

        assert_eq!(stream_id, 1);
        assert!(end_stream, "END_STREAM survives split header assembly");

        let peer = "127.0.0.1:8443".parse().expect("test peer parses");
        let request = request_from_h2_headers(headers, Vec::new(), Some(peer))
            .expect("listener accepts decoded split header block");

        assert_eq!(request.method, Method::Get);
        assert_eq!(request.uri, "/split-continuation");
        assert_eq!(request.version, Version::Http2);
        assert_eq!(request.peer_addr, Some(peer));
        assert_eq!(
            request.headers,
            vec![
                ("host".to_owned(), "split.example".to_owned()),
                ("x-trace".to_owned(), "split-block".to_owned()),
            ]
        );
    }

    #[test]
    fn response_guard_lives_until_queued_stream_frames_flush() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/guard"),
            (":authority", "guard.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(
            matches!(received, Some(ReceivedFrame::Headers { stream_id: 1, .. })),
            "request stream must be established before queuing a response"
        );

        let in_flight = Arc::new(AtomicUsize::new(0));
        let guard = InFlightRequestGuard::acquire(Some(&in_flight));
        assert_eq!(in_flight.load(Ordering::Acquire), 1);

        let mut response_guards = HashMap::new();
        queue_h2_response(
            &mut conn,
            1,
            Response::new(200, "OK", b"hello".to_vec()),
            guard,
            false,
            &mut response_guards,
        );

        assert_eq!(
            in_flight.load(Ordering::Acquire),
            1,
            "guard remains active while response frames are queued"
        );
        assert!(response_guards.contains_key(&1));
        assert!(conn.has_pending_frames_for_stream(1));

        release_flushed_response_guards(&conn, &mut response_guards);
        assert_eq!(
            in_flight.load(Ordering::Acquire),
            1,
            "pending stream frames keep the guard alive"
        );

        while conn.has_pending_frames_for_stream(1) {
            assert!(
                conn.next_frame().is_some(),
                "pending stream frames must eventually flush"
            );
        }
        release_flushed_response_guards(&conn, &mut response_guards);

        assert!(response_guards.is_empty());
        assert_eq!(
            in_flight.load(Ordering::Acquire),
            0,
            "guard releases only after the stream has no queued frames"
        );
    }

    #[test]
    fn queue_h2_response_synthesizes_500_for_invalid_response_headers() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/invalid-response"),
            (":authority", "example.com"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(received, Some(ReceivedFrame::Headers { .. })));

        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            Response::new(200, "OK", b"secret".to_vec()).with_header("x-bad", "ok\r\nbad"),
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );
        assert!(outcomes.is_empty());

        // Drain the SETTINGS ACK the connection queues in response to the peer
        // SETTINGS processed above before inspecting the response frames (same
        // ordering the push tests account for).
        match conn.next_frame().expect("settings ack") {
            Frame::Settings(settings) => assert!(settings.ack, "expected SETTINGS ACK first"),
            other => panic!("expected SETTINGS ACK, got {other:?}"),
        }

        let frame = conn.next_frame().expect("fallback response headers");
        let Frame::Headers(headers) = frame else {
            panic!("expected fallback response HEADERS, got {frame:?}");
        };
        assert!(headers.end_stream, "fallback response has no body");
        let mut block = headers.header_block;
        let decoded = crate::http::h2::HpackDecoder::new()
            .decode(&mut block)
            .expect("fallback headers decode");
        assert!(decoded.contains(&Header::new(":status", "500")));
        assert!(
            decoded.iter().all(|header| header.name != "x-bad"),
            "invalid handler header must not reach HPACK output: {decoded:?}"
        );
        assert!(conn.next_frame().is_none());
        // queue_h2_response retains the in-flight guard until the stream's frames
        // flush (retain-until-flush model); release it now that the stream has no
        // pending frames, mirroring the serve loop, then confirm no guard leaked.
        release_flushed_response_guards(&conn, &mut response_guards);
        assert!(response_guards.is_empty());
    }

    #[test]
    fn queue_h2_response_emits_trailing_headers_after_body() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/trailers"),
            (":authority", "example.com"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(received, Some(ReceivedFrame::Headers { .. })));

        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            Response::new(200, "OK", b"hello".to_vec()).with_trailer("X-Trace", "abc123"),
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );
        assert!(outcomes.is_empty());

        // Drain the SETTINGS ACK queued for the peer SETTINGS before inspecting
        // the response frames.
        match conn.next_frame().expect("settings ack") {
            Frame::Settings(settings) => assert!(settings.ack, "expected SETTINGS ACK first"),
            other => panic!("expected SETTINGS ACK, got {other:?}"),
        }

        let mut decoder = crate::http::h2::HpackDecoder::new();
        match conn.next_frame().expect("response headers") {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, 1);
                assert!(!headers.end_stream);
                let mut block = headers.header_block;
                let decoded = decoder.decode(&mut block).expect("response headers decode");
                assert!(decoded.contains(&Header::new(":status", "200")));
            }
            other => panic!("expected response HEADERS, got {other:?}"),
        }
        match conn.next_frame().expect("response body") {
            Frame::Data(data) => {
                assert_eq!(data.stream_id, 1);
                assert_eq!(data.data, crate::bytes::Bytes::from_static(b"hello"));
                assert!(
                    !data.end_stream,
                    "DATA must leave the stream open for trailers"
                );
            }
            other => panic!("expected response DATA, got {other:?}"),
        }
        match conn.next_frame().expect("response trailers") {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, 1);
                assert!(headers.end_stream);
                let mut block = headers.header_block;
                let decoded = decoder
                    .decode(&mut block)
                    .expect("response trailers decode");
                assert_eq!(decoded, vec![Header::new("x-trace", "abc123")]);
            }
            other => panic!("expected response trailer HEADERS, got {other:?}"),
        }
        assert!(conn.next_frame().is_none());
    }

    #[test]
    fn handler_panic_maps_to_500_and_releases_guard_after_flush() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let handle = runtime.handle();

        runtime.block_on(async move {
            let cx = Cx::current().expect("runtime installs Cx for block_on");
            let mut conn = Connection::server(Settings::default());
            assert!(
                conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                    Vec::new()
                )))
                .expect("initial settings accepted")
                .is_none()
            );

            let request_headers = encode_hpack_test_headers(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/panic"),
                (":authority", "panic.example"),
            ]);
            let received = conn
                .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                    1,
                    request_headers,
                    true,
                    true,
                )))
                .expect("request headers accepted")
                .expect("request headers decoded");
            let ReceivedFrame::Headers {
                stream_id,
                headers,
                end_stream,
            } = received
            else {
                panic!("expected decoded request headers");
            };
            assert_eq!(stream_id, 1);
            assert!(end_stream);

            let (resp_tx, mut resp_rx) = mpsc::channel::<FunnelItem>(RESPONSE_FUNNEL_CAPACITY);
            let shutdown_signal = ShutdownSignal::new();
            let in_flight = Arc::new(AtomicUsize::new(0));
            let handler = Arc::new(panicking_h2_handler);

            dispatch_h2_request(
                &mut conn,
                stream_id,
                headers,
                Vec::new(),
                None,
                &handler,
                &resp_tx,
                &shutdown_signal,
                &in_flight,
                &handle,
                &HostPolicy::allow_list(vec!["panic.example".to_owned()]),
                None,
                None,
                Duration::from_millis(500),
            );

            let (response_stream, response, guard, suppress_response_body) = resp_rx
                .recv(&cx)
                .await
                .expect("panic response must be sent through funnel");
            assert_eq!(response_stream, 1);
            assert_eq!(response.response.status, 500);
            assert_eq!(response.response.reason, "Internal Server Error");
            assert!(response.response.body.is_empty());
            assert!(!suppress_response_body);
            assert_eq!(
                in_flight.load(Ordering::Acquire),
                1,
                "guard remains active until the 500 response is queued and flushed"
            );

            let mut response_guards = HashMap::new();
            queue_h2_response(
                &mut conn,
                response_stream,
                response,
                guard,
                suppress_response_body,
                &mut response_guards,
            );
            while conn.has_pending_frames_for_stream(response_stream) {
                assert!(
                    conn.next_frame().is_some(),
                    "500 response frames must be flushable"
                );
            }
            release_flushed_response_guards(&conn, &mut response_guards);

            assert!(response_guards.is_empty());
            assert_eq!(
                in_flight.load(Ordering::Acquire),
                0,
                "handler-panic guard releases after the synthesized response flushes"
            );
        });
    }

    #[test]
    fn disallowed_host_returns_421_without_invoking_handler() {
        // br-asupersync-mfqfst M8: a request whose :authority/host is not on
        // the allow-list gets a per-stream 421 Misdirected Request and the
        // handler never runs.
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let handle = runtime.handle();

        runtime.block_on(async move {
            let cx = Cx::current().expect("runtime installs Cx for block_on");
            let mut conn = Connection::server(Settings::default());

            let (resp_tx, mut resp_rx) = mpsc::channel::<FunnelItem>(RESPONSE_FUNNEL_CAPACITY);
            let shutdown_signal = ShutdownSignal::new();
            let in_flight = Arc::new(AtomicUsize::new(0));
            let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let invoked_for_handler = Arc::clone(&invoked);
            let handler = Arc::new(move |_req: Request| {
                let invoked = Arc::clone(&invoked_for_handler);
                async move {
                    invoked.store(true, Ordering::SeqCst);
                    Response::new(200, "OK", Vec::new())
                }
            });

            // request_block carries `:authority example.com:8443` -> host
            // `example.com`, which is NOT on this allow-list.
            dispatch_h2_request(
                &mut conn,
                1,
                request_block(&[]),
                Vec::new(),
                None,
                &handler,
                &resp_tx,
                &shutdown_signal,
                &in_flight,
                &handle,
                &HostPolicy::allow_list(vec!["allowed.example".to_owned()]),
                None,
                None,
                Duration::from_millis(500),
            );

            let (stream_id, response, guard, _suppress) = resp_rx
                .recv(&cx)
                .await
                .expect("421 response must be sent through funnel");
            assert_eq!(stream_id, 1);
            assert_eq!(response.response.status, 421);
            assert!(
                String::from_utf8_lossy(&response.response.body).contains("example.com"),
                "421 body should name the rejected host: {:?}",
                response.response.body
            );
            assert!(
                !invoked.load(Ordering::SeqCst),
                "handler must not run for a rejected host"
            );
            drop(guard);
        });
    }

    #[test]
    fn allowed_host_runs_handler() {
        // br-asupersync-mfqfst M8: a request whose host is on the allow-list
        // reaches the handler and its response is funneled back.
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let handle = runtime.handle();

        runtime.block_on(async move {
            let cx = Cx::current().expect("runtime installs Cx for block_on");
            let mut conn = Connection::server(Settings::default());

            let (resp_tx, mut resp_rx) = mpsc::channel::<FunnelItem>(RESPONSE_FUNNEL_CAPACITY);
            let shutdown_signal = ShutdownSignal::new();
            let in_flight = Arc::new(AtomicUsize::new(0));
            let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let invoked_for_handler = Arc::clone(&invoked);
            let handler = Arc::new(move |_req: Request| {
                let invoked = Arc::clone(&invoked_for_handler);
                async move {
                    invoked.store(true, Ordering::SeqCst);
                    Response::new(200, "OK", b"hi".to_vec())
                }
            });

            dispatch_h2_request(
                &mut conn,
                1,
                request_block(&[]),
                Vec::new(),
                None,
                &handler,
                &resp_tx,
                &shutdown_signal,
                &in_flight,
                &handle,
                &HostPolicy::allow_list(vec!["example.com".to_owned()]),
                None,
                None,
                Duration::from_millis(500),
            );

            let (stream_id, response, guard, _suppress) = resp_rx
                .recv(&cx)
                .await
                .expect("handler response must be sent through funnel");
            assert_eq!(stream_id, 1);
            assert_eq!(response.response.status, 200);
            assert!(
                invoked.load(Ordering::SeqCst),
                "handler must run for an allow-listed host"
            );
            drop(guard);
        });
    }

    #[test]
    fn frame_codec_for_honors_local_max_frame_size() {
        use crate::bytes::BytesMut;
        use crate::codec::Decoder;
        use crate::http::h2::frame::DEFAULT_MAX_FRAME_SIZE;

        // A conformant DATA frame on stream 1 whose payload (20000 bytes)
        // exceeds the 16384 protocol default but fits inside a larger advertised
        // SETTINGS_MAX_FRAME_SIZE. 9-byte header: length=20000 (0x004E20),
        // type=DATA(0x0), flags=0, stream id=1.
        let mut frame_bytes = vec![0x00, 0x4E, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        frame_bytes.resize(9 + 20_000, 0u8);

        // The protocol-default accept limit (the pre-fix listener behavior)
        // rejects the frame with FRAME_SIZE_ERROR.
        let mut default_codec = frame_codec_for(DEFAULT_MAX_FRAME_SIZE);
        let mut src = BytesMut::new();
        src.extend_from_slice(&frame_bytes);
        let err = default_codec
            .decode(&mut src)
            .expect_err("default 16 KiB accept limit must reject a 20000-byte frame");
        assert_eq!(err.code, ErrorCode::FrameSizeError);

        // A listener advertising max_frame_size=32768 accepts the same frame.
        let mut wide_codec = frame_codec_for(32_768);
        let mut src = BytesMut::new();
        src.extend_from_slice(&frame_bytes);
        let frame = wide_codec
            .decode(&mut src)
            .expect("decode succeeds under the advertised limit")
            .expect("a full frame is available");
        assert!(
            matches!(frame, Frame::Data(_)),
            "expected a DATA frame, got {frame:?}",
        );
    }

    #[test]
    fn request_mapping_extracts_pseudo_headers_and_synthesizes_host() {
        let request =
            request_from_h2_headers(request_block(&[("x-trace", "abc")]), b"body".to_vec(), None)
                .expect("valid request block");
        assert_eq!(request.method, Method::Get);
        assert_eq!(request.uri, "/widgets?q=1");
        assert_eq!(request.version, Version::Http2);
        assert_eq!(request.body, b"body");
        assert_eq!(
            request.headers,
            vec![
                ("host".to_owned(), "example.com:8443".to_owned()),
                ("x-trace".to_owned(), "abc".to_owned()),
            ]
        );
    }

    #[test]
    fn request_mapping_keeps_explicit_host_over_authority() {
        let request = request_from_h2_headers(
            request_block(&[("host", "explicit.example")]),
            Vec::new(),
            None,
        )
        .expect("valid request block");
        let hosts: Vec<_> = request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .collect();
        assert_eq!(hosts.len(), 1, "no duplicate host header");
        assert_eq!(hosts[0].1, "explicit.example");
    }

    #[test]
    fn request_mapping_rejects_missing_method_and_path() {
        let no_method = vec![Header::new(":path", "/"), Header::new(":scheme", "https")];
        assert!(request_from_h2_headers(no_method, Vec::new(), None).is_err());

        let no_path = vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
        ];
        assert!(request_from_h2_headers(no_path, Vec::new(), None).is_err());
    }

    #[test]
    fn request_mapping_rejects_unknown_pseudo_header() {
        let block = request_block(&[(":bogus", "x")]);
        assert!(request_from_h2_headers(block, Vec::new(), None).is_err());
    }

    #[test]
    fn response_mapping_emits_status_first_and_strips_h1_connection_headers() {
        let response = Response {
            version: Version::Http2,
            status: 204,
            reason: "No Content".to_owned(),
            headers: vec![
                ("Connection".to_owned(), "close".to_owned()),
                ("Transfer-Encoding".to_owned(), "chunked".to_owned()),
                ("TE".to_owned(), "gzip".to_owned()),
                ("X-Trace".to_owned(), "abc".to_owned()),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        let block = h2_headers_from_response(&response).expect("valid response headers");
        assert_eq!(block[0], Header::new(":status", "204"));
        assert_eq!(block.len(), 2, "connection-specific headers stripped");
        assert_eq!(block[1], Header::new("x-trace", "abc"));
    }

    #[test]
    fn response_mapping_keeps_te_trailers() {
        let response = Response {
            version: Version::Http2,
            status: 200,
            reason: "OK".to_owned(),
            headers: vec![("te".to_owned(), "trailers".to_owned())],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        let block = h2_headers_from_response(&response).expect("valid TE trailers header");
        assert_eq!(block.len(), 2);
        assert_eq!(block[1], Header::new("te", "trailers"));
    }

    #[test]
    fn response_mapping_rejects_invalid_handler_supplied_headers() {
        let crlf = Response::new(200, "OK", Vec::new()).with_header("x-trace", "ok\r\nbad");
        assert!(h2_headers_from_response(&crlf).is_err());

        let nul = Response::new(200, "OK", Vec::new()).with_header("x-trace", "bad\0value");
        assert!(h2_headers_from_response(&nul).is_err());

        let bad_name = Response::new(200, "OK", Vec::new()).with_header("x bad", "value");
        assert!(h2_headers_from_response(&bad_name).is_err());

        let pseudo = Response::new(200, "OK", Vec::new()).with_header(":path", "/forged");
        assert!(h2_headers_from_response(&pseudo).is_err());

        let bad_trailer =
            Response::new(200, "OK", Vec::new()).with_trailer("x-trace", "bad\nvalue");
        assert!(validate_h2_response_for_queue(&bad_trailer, false).is_err());
    }

    #[test]
    fn response_content_length_validation_respects_head_suppression() {
        let mismatch = Response::new(200, "OK", b"abc".to_vec()).with_header("Content-Length", "4");
        assert!(validate_h2_response_for_queue(&mismatch, true).is_err());
        assert!(validate_h2_response_for_queue(&mismatch, false).is_ok());

        let invalid = Response::new(200, "OK", b"abc".to_vec()).with_header("Content-Length", "+3");
        assert!(validate_h2_response_for_queue(&invalid, false).is_err());

        let duplicate = Response {
            version: Version::Http2,
            status: 200,
            reason: "OK".to_owned(),
            headers: vec![
                ("Content-Length".to_owned(), "3".to_owned()),
                ("content-length".to_owned(), "3".to_owned()),
            ],
            body: b"abc".to_vec(),
            trailers: Vec::new(),
        };
        assert!(validate_h2_response_for_queue(&duplicate, true).is_err());
    }

    #[test]
    fn plain_response_converts_to_h2_response_without_pushes() {
        let response = Response::new(200, "OK", b"plain".to_vec());
        let h2_response = response.into_h2_response();

        assert_eq!(h2_response.response.status, 200);
        assert!(h2_response.pushes.is_empty());
    }

    #[test]
    fn queue_h2_response_promises_pushed_resource_before_parent_response() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );
        expect_settings_ack(&mut conn);

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "push.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(
            received,
            Some(ReceivedFrame::Headers { stream_id: 1, .. })
        ));

        let pushed = Http2ServerPush::get(
            "/style.css",
            "push.example",
            Response::new(200, "OK", b"css".to_vec()).with_header("Content-Type", "text/css"),
        );
        let response =
            Http2Response::new(Response::new(200, "OK", b"html".to_vec())).with_push(pushed);
        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            response,
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );

        assert_eq!(
            outcomes,
            vec![Http2PushOutcome::Promised {
                associated_stream_id: 1,
                promised_stream_id: 2
            }]
        );

        match conn.next_frame().expect("PUSH_PROMISE should lead") {
            Frame::PushPromise(push) => {
                assert_eq!(push.stream_id, 1);
                assert_eq!(push.promised_stream_id, 2);
                assert!(push.end_headers);
            }
            other => panic!("expected PUSH_PROMISE, got {other:?}"),
        }
        match conn.next_frame().expect("promised response headers") {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, 2);
                assert!(!headers.end_stream);
            }
            other => panic!("expected promised response HEADERS, got {other:?}"),
        }
        match conn.next_frame().expect("promised response body") {
            Frame::Data(data) => {
                assert_eq!(data.stream_id, 2);
                assert_eq!(data.data, crate::bytes::Bytes::from_static(b"css"));
                assert!(data.end_stream);
            }
            other => panic!("expected promised response DATA, got {other:?}"),
        }
        match conn.next_frame().expect("parent response headers") {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, 1);
                assert!(!headers.end_stream);
            }
            other => panic!("expected parent response HEADERS, got {other:?}"),
        }
        match conn.next_frame().expect("parent response body") {
            Frame::Data(data) => {
                assert_eq!(data.stream_id, 1);
                assert_eq!(data.data, crate::bytes::Bytes::from_static(b"html"));
                assert!(data.end_stream);
            }
            other => panic!("expected parent response DATA, got {other:?}"),
        }
    }

    #[test]
    fn queue_h2_response_reports_peer_disabled_no_push() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                vec![crate::http::h2::frame::Setting::EnablePush(false)]
            )))
            .expect("initial settings accepted")
            .is_none()
        );
        expect_settings_ack(&mut conn);

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "push.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(
            received,
            Some(ReceivedFrame::Headers { stream_id: 1, .. })
        ));

        let response = Http2Response::new(Response::new(200, "OK", Vec::new())).with_push(
            Http2ServerPush::get(
                "/style.css",
                "push.example",
                Response::new(200, "OK", Vec::new()),
            ),
        );
        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            response,
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );

        assert_eq!(
            outcomes,
            vec![Http2PushOutcome::NotPushed {
                associated_stream_id: 1,
                reason: Http2PushRejection::PeerDisabled
            }]
        );
        assert!(conn.stream(2).is_none());
        match conn.next_frame().expect("parent response still queues") {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, 1);
                assert!(headers.end_stream);
            }
            other => panic!("expected parent response HEADERS, got {other:?}"),
        }
        assert!(conn.next_frame().is_none());
    }

    #[test]
    fn queue_h2_response_reports_goaway_push_rejection() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );
        expect_settings_ack(&mut conn);

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "push.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(
            received,
            Some(ReceivedFrame::Headers { stream_id: 1, .. })
        ));

        conn.goaway(
            ErrorCode::NoError,
            crate::bytes::Bytes::from_static(b"server draining"),
        );
        let response = Http2Response::new(Response::new(200, "OK", Vec::new())).with_push(
            Http2ServerPush::get(
                "/style.css",
                "push.example",
                Response::new(200, "OK", Vec::new()),
            ),
        );
        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            response,
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );

        assert_eq!(
            outcomes,
            vec![Http2PushOutcome::NotPushed {
                associated_stream_id: 1,
                reason: Http2PushRejection::ConnectionClosing
            }]
        );
        assert!(conn.stream(2).is_none());
        assert!(matches!(conn.next_frame(), Some(Frame::GoAway(_))));
        match conn.next_frame().expect("parent response still queues") {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, 1);
                assert!(headers.end_stream);
            }
            other => panic!("expected parent response HEADERS, got {other:?}"),
        }
    }

    #[test]
    fn queue_h2_response_reports_max_concurrent_push_rejection() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                vec![crate::http::h2::frame::Setting::MaxConcurrentStreams(1)]
            )))
            .expect("max concurrent settings accepted")
            .is_none()
        );
        expect_settings_ack(&mut conn);

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "push.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(
            received,
            Some(ReceivedFrame::Headers { stream_id: 1, .. })
        ));

        let response = Http2Response::new(Response::new(200, "OK", Vec::new())).with_push(
            Http2ServerPush::get(
                "/style.css",
                "push.example",
                Response::new(200, "OK", Vec::new()),
            ),
        );
        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            response,
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );

        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            Http2PushOutcome::NotPushed {
                associated_stream_id,
                reason:
                    Http2PushRejection::Rejected {
                        code,
                        stream_id,
                        message,
                    },
            } => {
                assert_eq!(*associated_stream_id, 1);
                assert_eq!(*code, ErrorCode::ProtocolError);
                assert_eq!(*stream_id, None);
                assert!(message.contains("max concurrent streams exceeded"));
            }
            other => panic!("expected typed max-concurrent push rejection, got {other:?}"),
        }
        assert!(conn.stream(2).is_none());
        match conn.next_frame().expect("parent response still queues") {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, 1);
                assert!(headers.end_stream);
            }
            other => panic!("expected parent response HEADERS, got {other:?}"),
        }
    }

    #[test]
    fn queue_h2_response_reports_parent_cancelled_without_promising() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );
        expect_settings_ack(&mut conn);

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "push.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(
            received,
            Some(ReceivedFrame::Headers { stream_id: 1, .. })
        ));
        let reset = conn
            .process_frame(Frame::RstStream(
                crate::http::h2::frame::RstStreamFrame::new(1, ErrorCode::Cancel),
            ))
            .expect("parent reset accepted");
        assert!(matches!(
            reset,
            Some(ReceivedFrame::Reset {
                stream_id: 1,
                error_code: ErrorCode::Cancel
            })
        ));

        let response = Http2Response::new(Response::new(200, "OK", b"html".to_vec())).with_push(
            Http2ServerPush::get(
                "/style.css",
                "push.example",
                Response::new(200, "OK", b"css".to_vec()),
            ),
        );
        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            response,
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );

        assert_eq!(
            outcomes,
            vec![Http2PushOutcome::NotPushed {
                associated_stream_id: 1,
                reason: Http2PushRejection::ParentCancelled
            }]
        );
        assert!(conn.stream(2).is_none());
        assert!(conn.next_frame().is_none());
    }

    #[test]
    fn parent_reset_cancels_queued_promised_stream_frames() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );
        expect_settings_ack(&mut conn);

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "push.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(
            received,
            Some(ReceivedFrame::Headers { stream_id: 1, .. })
        ));

        let response = Http2Response::new(Response::new(200, "OK", b"html".to_vec())).with_push(
            Http2ServerPush::get(
                "/style.css",
                "push.example",
                Response::new(200, "OK", b"css".to_vec()),
            ),
        );
        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            response,
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );
        assert_eq!(
            outcomes,
            vec![Http2PushOutcome::Promised {
                associated_stream_id: 1,
                promised_stream_id: 2
            }]
        );

        let mut associated_pushes = HashMap::new();
        record_promised_pushes(&mut associated_pushes, &outcomes);
        assert!(conn.has_pending_frames_for_stream(2));

        let reset = conn
            .process_frame(Frame::RstStream(
                crate::http::h2::frame::RstStreamFrame::new(1, ErrorCode::Cancel),
            ))
            .expect("parent reset accepted");
        assert!(matches!(
            reset,
            Some(ReceivedFrame::Reset {
                stream_id: 1,
                error_code: ErrorCode::Cancel
            })
        ));
        reset_associated_pushes(&mut conn, &mut associated_pushes, 1);

        match conn
            .next_frame()
            .expect("promised stream reset should flush")
        {
            Frame::RstStream(reset) => {
                assert_eq!(reset.stream_id, 2);
                assert_eq!(reset.error_code, ErrorCode::Cancel);
            }
            other => panic!("expected promised-stream RST_STREAM, got {other:?}"),
        }
        assert!(conn.next_frame().is_none());
    }

    #[test]
    fn head_response_suppression_drops_body_and_synthesizes_length() {
        let mut response = Response::new(200, "OK", b"hello".to_vec())
            .with_header("Trailer", "X-Trace")
            .with_header("Transfer-Encoding", "chunked")
            .with_trailer("X-Trace", "abc123");

        suppress_response_body_for_head(&mut response);

        assert!(response.body.is_empty());
        assert!(response.trailers.is_empty());
        assert_eq!(response.header_value("content-length"), Some("5"));
        assert_eq!(response.header_value("trailer"), None);
        assert_eq!(response.header_value("transfer-encoding"), None);

        let block = h2_headers_from_response(&response).expect("valid HEAD response headers");
        assert!(
            block
                .iter()
                .any(|header| header.name == "content-length" && header.value == "5")
        );
        assert!(
            !block
                .iter()
                .any(|header| header.name == "trailer" || header.name == "transfer-encoding")
        );
    }

    #[test]
    fn head_response_suppression_preserves_explicit_length() {
        let mut response =
            Response::new(200, "OK", b"sentinel".to_vec()).with_header("Content-Length", "999");

        suppress_response_body_for_head(&mut response);

        assert!(response.body.is_empty());
        assert_eq!(response.header_value("content-length"), Some("999"));
    }
}
