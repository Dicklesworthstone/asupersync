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
use crate::cx::child_region::{ChildRegion, ChildRegionSpec};
use crate::http::body::{Body as _, Frame as BodyFrame, HeaderMap};
use crate::http::h1::HttpError;
use crate::http::h1::server::{HostPolicy, parse_request_timeout_header, validate_host_header};
use crate::http::h1::stream::{BodyKind, OutgoingBody, OutgoingBodySender};
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
use crate::runtime::{JoinError, JoinHandle, RuntimeHandle, SpawnError, TaskHandle};
use crate::server::connection::ConnectionManager;
use crate::server::shutdown::{
    DrainStep, GracefulDrainReport, GracefulDrainSupervisor, ShutdownPhase, ShutdownSignal,
    ShutdownStats,
};
use crate::stream::Stream;
use crate::tracing_compat::error;
use crate::types::{Budget, CancelKind, CancelReason, Time};
use crate::web::WebBodyDiagnostic;
use crate::web::request_region::{
    HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC, RequestBudgetSource, ServerHopOutcome,
    ServerProducerCancellation, ServerRequestDeadline, ServerRequestRegion,
    classify_server_producer_cancellation, derive_request_budget,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::num::NonZeroUsize;
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

/// Default maximum DATA bytes retained in one produced-response frame.
/// Default maximum DATA frame accepted from a produced HTTP/2 response.
pub const DEFAULT_H2_PRODUCED_FRAME_BYTES: usize = 16 * 1024;

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
// Currently exercised only by unit tests (production paths go through
// `request_from_h2_parts` with trailers); keep it compiling under the
// crate-level `deny(dead_code)` for non-test builds of downstream consumers.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn request_from_h2_headers(
    headers: Vec<Header>,
    body: Vec<u8>,
    peer_addr: Option<SocketAddr>,
) -> Result<Request, H2Error> {
    request_from_h2_parts(headers, body, Vec::new(), peer_addr)
}

fn request_from_h2_parts(
    headers: Vec<Header>,
    body: Vec<u8>,
    trailers: Vec<Header>,
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

    let mut request_trailers = Vec::with_capacity(trailers.len());
    for trailer in trailers {
        if trailer.name.starts_with(':') {
            return Err(H2Error::protocol(format!(
                "unexpected request trailer pseudo-header {}",
                trailer.name
            )));
        }
        request_trailers.push((trailer.name, trailer.value));
    }

    Ok(Request {
        method,
        uri,
        version: Version::Http2,
        headers: request_headers,
        body,
        trailers: request_trailers,
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

fn validate_h2_produced_head_for_queue(response: &Response) -> Result<(), H2Error> {
    validate_h2_response_for_queue(response, false)?;
    if !response.body.is_empty() || !response.trailers.is_empty() {
        return Err(H2Error::connection(
            ErrorCode::InternalError,
            "produced h2 response head must not carry buffered body or trailers",
        ));
    }
    Ok(())
}

fn validate_h2_produced_response_for_queue(response: &Response) -> Result<(), H2Error> {
    validate_h2_produced_head_for_queue(response)?;
    if matches!(response.status, 100..=199 | 204 | 205 | 304) {
        return Err(H2Error::connection(
            ErrorCode::InternalError,
            "produced h2 response requires a body-allowed status",
        ));
    }
    if response.headers.iter().any(|(name, _)| {
        name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
    }) {
        return Err(H2Error::connection(
            ErrorCode::InternalError,
            "produced h2 response owns message framing",
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

type Http2ProducerFuture =
    Pin<Box<dyn Future<Output = Result<Http2BodySender, HttpError>> + Send + 'static>>;
type Http2ProducerFactory =
    Box<dyn FnOnce(Cx, Http2BodySender) -> Http2ProducerFuture + Send + 'static>;

/// Sender handed to a supervised HTTP/2 response-body producer.
///
/// The underlying channel has a fixed frame capacity. This wrapper additionally
/// rejects any DATA frame larger than `max_frame_bytes`, so transport-owned
/// retained DATA in the producer channel is bounded by
/// `frame_capacity * max_frame_bytes`. One additional frame may be retained by
/// the H2 connection after it leaves the channel, plus codec write buffering.
/// Memory held by the application before it calls [`Self::send_bytes`] is
/// outside that transport envelope.
#[derive(Debug)]
pub struct Http2BodySender {
    inner: OutgoingBodySender,
    max_frame_bytes: NonZeroUsize,
    terminal: Http2ProducerTerminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Http2ProducerTerminal {
    Open,
    Finished,
    Trailers,
}

impl Http2BodySender {
    /// Maximum DATA bytes accepted by one send operation.
    #[must_use]
    pub fn max_frame_bytes(&self) -> NonZeroUsize {
        self.max_frame_bytes
    }

    /// Total DATA bytes committed into the bounded body channel.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.inner.total_bytes()
    }

    /// Whether the producer has explicitly finished with EOF or trailers.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }

    /// Commit one bounded DATA frame.
    pub async fn send_bytes(
        &mut self,
        cx: &Cx,
        data: crate::bytes::Bytes,
    ) -> Result<(), HttpError> {
        if data.len() > self.max_frame_bytes.get() {
            return Err(HttpError::BodyTooLargeDetailed {
                actual: u64::try_from(data.len()).unwrap_or(u64::MAX),
                limit: u64::try_from(self.max_frame_bytes.get()).unwrap_or(u64::MAX),
            });
        }
        self.inner.send_bytes(cx, data).await
    }

    /// Copy and commit one bounded DATA frame.
    pub async fn send_chunk(&mut self, cx: &Cx, data: &[u8]) -> Result<(), HttpError> {
        if data.len() > self.max_frame_bytes.get() {
            return Err(HttpError::BodyTooLargeDetailed {
                actual: u64::try_from(data.len()).unwrap_or(u64::MAX),
                limit: u64::try_from(self.max_frame_bytes.get()).unwrap_or(u64::MAX),
            });
        }
        self.inner.send_chunk(cx, data).await
    }

    /// Finish the response with a trailing HEADERS block.
    pub async fn send_trailers(&mut self, cx: &Cx, trailers: HeaderMap) -> Result<(), HttpError> {
        self.inner.send_trailers(cx, trailers).await?;
        self.terminal = Http2ProducerTerminal::Trailers;
        Ok(())
    }

    /// Finish the response without trailers.
    pub fn finish(&mut self, cx: &Cx) -> Result<(), HttpError> {
        if self.terminal == Http2ProducerTerminal::Trailers {
            return Ok(());
        }
        self.inner.finish(cx)?;
        self.terminal = Http2ProducerTerminal::Finished;
        Ok(())
    }
}

/// Source-compatible response accepted by [`Http2Listener::run_produced`].
///
/// Buffered responses retain the existing [`Http2Response`] path. Streaming
/// responses defer channel creation and producer startup until the listener has
/// validated the response head and minted a request-derived capability context.
pub struct Http2ProducedResponse {
    kind: Http2ProducedResponseKind,
}

enum Http2ProducedResponseKind {
    Buffered(Http2Response),
    Streaming {
        response: Response,
        frame_capacity: NonZeroUsize,
        max_frame_bytes: NonZeroUsize,
        producer: Http2ProducerFactory,
    },
}

impl std::fmt::Debug for Http2ProducedResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            Http2ProducedResponseKind::Buffered(response) => f
                .debug_tuple("Http2ProducedResponse::Buffered")
                .field(response)
                .finish(),
            Http2ProducedResponseKind::Streaming {
                response,
                frame_capacity,
                max_frame_bytes,
                ..
            } => f
                .debug_struct("Http2ProducedResponse::Streaming")
                .field("response", response)
                .field("frame_capacity", frame_capacity)
                .field("max_frame_bytes", max_frame_bytes)
                .finish_non_exhaustive(),
        }
    }
}

impl Http2ProducedResponse {
    /// Preserve an ordinary buffered H2 response in the produced-listener lane.
    #[must_use]
    pub fn buffered(response: impl IntoHttp2Response) -> Self {
        Self {
            kind: Http2ProducedResponseKind::Buffered(response.into_h2_response()),
        }
    }

    /// Create a bounded, deferred HTTP/2 response producer.
    #[must_use]
    pub fn streaming<P, Fut>(
        response: Response,
        frame_capacity: NonZeroUsize,
        max_frame_bytes: NonZeroUsize,
        producer: P,
    ) -> Self
    where
        P: FnOnce(Cx, Http2BodySender) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Http2BodySender, HttpError>> + Send + 'static,
    {
        Self {
            kind: Http2ProducedResponseKind::Streaming {
                response,
                frame_capacity,
                max_frame_bytes,
                producer: Box::new(move |cx, sender| Box::pin(producer(cx, sender))),
            },
        }
    }

    fn into_driver_response(self) -> H2DispatchResponse {
        match self.kind {
            Http2ProducedResponseKind::Buffered(response) => H2DispatchResponse::Buffered(response),
            Http2ProducedResponseKind::Streaming {
                response,
                frame_capacity,
                max_frame_bytes,
                producer,
            } => H2DispatchResponse::Produced(Http2ProducedPlan {
                response,
                frame_capacity,
                max_frame_bytes,
                producer,
            }),
        }
    }
}

struct Http2ProducedPlan {
    response: Response,
    frame_capacity: NonZeroUsize,
    max_frame_bytes: NonZeroUsize,
    producer: Http2ProducerFactory,
}

impl Http2ProducedPlan {
    fn into_parts(
        self,
        cx: &Cx,
    ) -> (
        Response,
        OutgoingBody,
        Http2BodySender,
        Http2ProducerFactory,
    ) {
        let (inner, body) =
            OutgoingBody::channel_with_capacity(cx, BodyKind::Chunked, self.frame_capacity.get());
        let sender = Http2BodySender {
            inner,
            max_frame_bytes: self.max_frame_bytes,
            terminal: Http2ProducerTerminal::Open,
        };
        (self.response, body, sender, self.producer)
    }
}

enum H2DispatchResponse {
    Buffered(Http2Response),
    Produced(Http2ProducedPlan),
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

#[derive(Clone, Copy)]
struct OwnedH2HopConfig {
    budget: Budget,
    started_at: Time,
    source: RequestBudgetSource,
    drain_grace: Duration,
    idle_timeout: Option<Duration>,
}

struct OwnedH2HopCompletion {
    /// The actual protocol return is distinct from task-level cancellation.
    hop: ServerHopOutcome<H2DispatchResponse>,
    task_outcome: Option<Result<(), JoinError>>,
    idle_expired: bool,
}

struct OwnedH2Request {
    region: Option<ChildRegion>,
    body: Option<TaskHandle<()>>,
}

struct H2ParentCancellation<'a> {
    cx: &'a Cx,
    registration: Option<crate::cx::CancelWakerToken>,
}

impl H2ParentCancellation<'_> {
    fn clear(&mut self) {
        if let Some(registration) = self.registration.take() {
            self.cx.clear_cancel_waker(registration);
        }
    }
}

impl Drop for H2ParentCancellation<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl Drop for OwnedH2Request {
    fn drop(&mut self) {
        // Abandonment requests cancellation; it cannot certify quiescence.
        // Normal dispatch always joins and closes before releasing its guard.
        if let Some(body) = &self.body {
            body.abort();
        }
    }
}

fn h2_request_cancel_reason(cx: &Cx, kind: CancelKind) -> CancelReason {
    let mut reason = CancelReason::with_origin(kind, cx.region_id(), cx.now());
    reason.origin_task = Some(cx.task_id());
    reason
}

impl OwnedH2Request {
    async fn join(
        &mut self,
        cx: &Cx,
        signal: &ShutdownSignal,
        mut idle: Option<(Time, ServerRequestDeadline)>,
    ) -> (Result<(), JoinError>, bool) {
        let mut force = std::pin::pin!(signal.wait_for_phase(ShutdownPhase::ForceClosing));
        let mut cancellation_sent = false;
        let mut idle_expired = false;
        let mut parent = H2ParentCancellation {
            cx,
            registration: None,
        };
        let result = std::future::poll_fn(|poll_cx| {
            if !cancellation_sent {
                parent.registration =
                    Some(cx.refresh_cancel_waker(parent.registration, poll_cx.waker()));
                let forced = signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8
                    || force.as_mut().poll(poll_cx).is_ready();
                let cancelled = cx.is_cancel_requested();
                if forced || cancelled {
                    let reason = if forced {
                        h2_request_cancel_reason(cx, CancelKind::Shutdown)
                    } else {
                        cx.cancel_reason().unwrap_or_else(|| {
                            h2_request_cancel_reason(cx, CancelKind::ParentCancelled)
                        })
                    };
                    self.cancel(cx, reason);
                    cancellation_sent = true;
                    idle = None;
                    parent.clear();
                }
            }
            // Match timeout_at's strict-overdue rule before observing ready
            // work. A body can finish while its coordinator is not scheduled;
            // that delayed join does not extend the admitted idle deadline.
            // At exact equality, the completed body still wins below.
            if !cancellation_sent
                && idle
                    .as_ref()
                    .is_some_and(|(deadline, _)| cx.now() > *deadline)
            {
                idle_expired = true;
                cancellation_sent = true;
                idle = None;
                parent.clear();
                self.cancel(cx, h2_request_cancel_reason(cx, CancelKind::Timeout));
            }
            // No join(cx) cancellation shortcut: retain the actual body until
            // it has finished protocol cleanup and terminal publication.
            let joined = self.body.as_mut().expect("owned body").poll_join(poll_cx);
            if joined.is_ready() {
                return joined;
            }
            if !cancellation_sent
                && idle
                    .as_mut()
                    .is_some_and(|(_, wait)| Pin::new(wait).poll(poll_cx).is_ready())
            {
                idle_expired = true;
                cancellation_sent = true;
                idle = None;
                parent.clear();
                self.cancel(cx, h2_request_cancel_reason(cx, CancelKind::Timeout));
            }
            Poll::Pending
        })
        .await;
        self.body = None;
        (result, idle_expired)
    }

    fn cancel(&self, cx: &Cx, reason: CancelReason) {
        if let Err(error) = self.region.as_ref().expect("owned region").cancel(reason) {
            cx.trace(&format!("h2_owned_request_cancel_failed: {error}"));
        }
    }
}

async fn execute_owned_h2_body<F, Fut>(
    body_cx: Cx,
    config: OwnedH2HopConfig,
    signal: ShutdownSignal,
    factory: F,
) -> ServerHopOutcome<H2DispatchResponse>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = H2DispatchResponse>,
{
    let region = ServerRequestRegion::from_body_cx("h2", body_cx.clone(), config.started_at);
    // A shutdown may win after the spawn post but before its first poll. Do
    // not invoke user code in that interval; the owner still joins and closes.
    if signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8 {
        region.finish("cancelled");
        return ServerHopOutcome::Cancelled;
    }
    let mut execution = Box::pin(CatchUnwind {
        inner: region.run_with_protocol_drain(
            config.source,
            Some(body_cx),
            config.drain_grace,
            async move { factory().await },
        ),
    });
    let returned = execution.as_mut().await;
    let retired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(execution)));
    match (returned, retired) {
        (Err(payload), retirement) => {
            if let Err(secondary) = retirement {
                std::mem::forget(secondary);
            }
            ServerHopOutcome::Panicked(crate::cx::scope::payload_to_string(&payload))
        }
        (Ok(_), Err(payload)) => {
            ServerHopOutcome::Panicked(crate::cx::scope::payload_to_string(&payload))
        }
        (Ok(outcome), Ok(())) => outcome,
    }
}

async fn run_owned_h2_hop<F, Fut>(
    cx: &Cx,
    signal: &ShutdownSignal,
    config: OwnedH2HopConfig,
    factory: F,
) -> Result<OwnedH2HopCompletion, String>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = H2DispatchResponse> + Send + 'static,
{
    let timer = cx
        .timer_driver()
        .ok_or("H2 owned request requires a timer driver")?;
    // Opening has no Drop close backstop. Always obtain actual ownership even
    // when shutdown arrives while the admission command is pending.
    let region = cx
        .open_child_region(ChildRegionSpec::inherit().with_budget(config.budget))
        .await
        .map_err(|error| error.to_string())?;
    let mut owner = OwnedH2Request {
        region: Some(region),
        body: None,
    };
    let idle_expired = config
        .idle_timeout
        .is_some_and(|timeout| timer.now() > config.started_at + timeout);
    if signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8
        || cx.is_cancel_requested()
        || idle_expired
    {
        let kind = if idle_expired {
            CancelKind::Timeout
        } else {
            CancelKind::Shutdown
        };
        owner.cancel(cx, h2_request_cancel_reason(cx, kind));
        owner
            .region
            .take()
            .expect("owned region")
            .close()
            .await
            .map_err(|error| error.to_string())?;
        return Ok(OwnedH2HopCompletion {
            hop: ServerHopOutcome::Cancelled,
            task_outcome: None,
            idle_expired,
        });
    }
    let publication = Arc::new(parking_lot::Mutex::new(None));
    let body_publication = Arc::clone(&publication);
    let body_signal = signal.clone();
    let region = owner.region.as_ref().expect("owned region");
    let scope = region.cx().scope();
    let spawned = region
        .cx()
        .spawn_in_cancellation_dominant(&scope, move |body_cx| async move {
            let outcome = execute_owned_h2_body(body_cx, config, body_signal, factory).await;
            *body_publication.lock() = Some(outcome);
        });
    match spawned {
        Ok(body) => owner.body = Some(body),
        Err(error) => {
            owner
                .region
                .take()
                .expect("owned region")
                .close()
                .await
                .map_err(|close_error| close_error.to_string())?;
            return Err(error.to_string());
        }
    }
    let idle = config.idle_timeout.map(|timeout| {
        let deadline = config.started_at + timeout;
        (deadline, ServerRequestDeadline::new(timer, deadline))
    });
    let (task_outcome, idle_expired) = owner.join(cx, signal, idle).await;
    owner
        .region
        .take()
        .expect("owned region")
        .close()
        .await
        .map_err(|error| error.to_string())?;
    let returned = publication.lock().take();
    let hop = match (&task_outcome, returned) {
        (Err(JoinError::Panicked(payload)), _) => ServerHopOutcome::Panicked(payload.to_string()),
        (_, Some(outcome)) => outcome,
        (Err(JoinError::Cancelled(_)), None) => ServerHopOutcome::Cancelled,
        (_, None) => ServerHopOutcome::Panicked("H2 body omitted terminal publication".to_owned()),
    };
    Ok(OwnedH2HopCompletion {
        hop,
        task_outcome: Some(task_outcome),
        idle_expired,
    })
}

/// A handler outcome travelling back to the connection driver.
enum FunnelItem {
    /// A completed response. The guard is retained until its queued frames
    /// have flushed; `suppress_response_body` records HEAD semantics.
    Response {
        stream_id: u32,
        response: Http2Response,
        guard: InFlightRequestGuard,
        suppress_response_body: bool,
    },
    /// The request stream exceeded its inactivity budget while the handler
    /// future was pending. The driver owns the mutable connection and emits
    /// RST_STREAM(CANCEL); dropping the guard releases in-flight accounting.
    StreamIdleTimeout {
        stream_id: u32,
        guard: InFlightRequestGuard,
    },
    /// A validated produced response is ready. The driver owns the body receiver
    /// and polls it only when the stream has usable send credit.
    ProducedStart {
        stream_id: u32,
        response: Response,
        body: OutgoingBody,
        cancellation: ProducedCancellationGuard,
        guard: Arc<InFlightRequestGuard>,
    },
    /// The supervised producer reached a terminal outcome.
    ProducedDone {
        stream_id: u32,
        outcome: Http2ProducerOutcome,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Http2ProducerOutcome {
    Finished {
        total_bytes: u64,
        terminal: Http2ProducerTerminal,
    },
    Failed,
    DeadlineExceeded,
    ConnectionLost,
    Cancelled,
}

fn classify_h2_producer_hop(
    hop: Option<ServerHopOutcome<Result<Http2BodySender, HttpError>>>,
    producer_cx: &Cx,
) -> Http2ProducerOutcome {
    match hop {
        Some(ServerHopOutcome::Ok(Ok(sender))) if sender.is_finished() => {
            Http2ProducerOutcome::Finished {
                total_bytes: sender.total_bytes(),
                terminal: sender.terminal,
            }
        }
        Some(ServerHopOutcome::Ok(Err(HttpError::BodyCancelled))) => {
            match classify_server_producer_cancellation(producer_cx) {
                ServerProducerCancellation::DeadlineExceeded => {
                    Http2ProducerOutcome::DeadlineExceeded
                }
                ServerProducerCancellation::Cancelled => Http2ProducerOutcome::Cancelled,
            }
        }
        Some(ServerHopOutcome::Ok(Ok(_) | Err(_)) | ServerHopOutcome::Panicked(_)) => {
            Http2ProducerOutcome::Failed
        }
        Some(ServerHopOutcome::DeadlineExceeded) => Http2ProducerOutcome::DeadlineExceeded,
        Some(ServerHopOutcome::ConnectionLost) => Http2ProducerOutcome::ConnectionLost,
        Some(ServerHopOutcome::Cancelled) | None => Http2ProducerOutcome::Cancelled,
    }
}

struct ActiveProducedBody {
    body: OutgoingBody,
    cancellation: ProducedCancellationGuard,
    guard: Option<Arc<InFlightRequestGuard>>,
    producer_outcome: Option<Http2ProducerOutcome>,
    emitted_bytes: u64,
    body_eof: bool,
    pending_trailers: Option<HeaderMap>,
    failure_drain_deadline: Option<Time>,
}

struct ProducedCancellationGuard {
    producer_cx: Cx,
    armed: bool,
}

impl ProducedCancellationGuard {
    fn new(producer_cx: Cx) -> Self {
        Self {
            producer_cx,
            armed: true,
        }
    }

    fn cancel(&mut self, message: &'static str) {
        if self.armed {
            self.producer_cx
                .cancel_with(crate::types::CancelKind::ParentCancelled, Some(message));
            self.armed = false;
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProducedCancellationGuard {
    fn drop(&mut self) {
        self.cancel("HTTP/2 connection dropped a produced response");
    }
}

impl ActiveProducedBody {
    fn cancel(&mut self, message: &'static str) {
        self.cancellation.cancel(message);
    }
}

enum ProducedBodyEvent {
    Frame {
        stream_id: u32,
        frame: Result<BodyFrame<crate::bytes::BytesCursor>, HttpError>,
    },
    Eof {
        stream_id: u32,
    },
}

fn h2_trailers_from_body_map(trailers: &HeaderMap) -> Result<Vec<Header>, H2Error> {
    trailers
        .iter()
        .map(|(name, value)| {
            let value = value.to_str().map_err(|_| {
                H2Error::connection(ErrorCode::InternalError, "invalid h2 trailer value")
            })?;
            validate_h2_response_header_name(name.as_str())?;
            validate_h2_response_header_value(value)?;
            Ok(Header::new(name.as_str(), value))
        })
        .collect()
}

fn cancel_produced_body(
    produced_bodies: &mut BTreeMap<u32, ActiveProducedBody>,
    stream_id: u32,
    message: &'static str,
) {
    if let Some(mut state) = produced_bodies.remove(&stream_id) {
        state.cancel(message);
    }
}

fn record_h2_body_diagnostic(stream_id: u32, diagnostic: WebBodyDiagnostic, cause: &'static str) {
    record_h2_body_diagnostic_code(stream_id, diagnostic.code(), cause);
}

fn record_h2_body_diagnostic_code(stream_id: u32, diagnostic: &'static str, cause: &'static str) {
    let _ = (stream_id, diagnostic, cause);
    error!(
        stream_id,
        diagnostic,
        cause,
        "[{}] h2 body stream terminated without a clean response-body boundary",
        diagnostic
    );
}

fn h2_producer_outcome_diagnostic(
    outcome: Http2ProducerOutcome,
) -> Option<(&'static str, &'static str)> {
    match outcome {
        Http2ProducerOutcome::Failed => Some((
            WebBodyDiagnostic::ResponseProducerFailure.code(),
            "response producer returned an error or panicked",
        )),
        Http2ProducerOutcome::DeadlineExceeded => Some((
            "ASUP-E501",
            "response producer exhausted its request-region deadline",
        )),
        Http2ProducerOutcome::ConnectionLost => Some((
            WebBodyDiagnostic::ClientAbort.code(),
            "response producer lost its client connection",
        )),
        Http2ProducerOutcome::Finished { .. } | Http2ProducerOutcome::Cancelled => None,
    }
}

fn cancel_all_produced_bodies(
    produced_bodies: &mut BTreeMap<u32, ActiveProducedBody>,
    message: &'static str,
) {
    for (_, mut state) in std::mem::take(produced_bodies) {
        state.cancel(message);
    }
}

fn mark_h2_peer_reset_before_response(
    dispatched_streams: &mut HashSet<u32>,
    peer_reset_before_response: &mut HashSet<u32>,
    stream_id: u32,
) -> bool {
    let dispatched = dispatched_streams.remove(&stream_id);
    if dispatched {
        peer_reset_before_response.insert(stream_id);
    }
    dispatched
}

fn finalize_produced_body_if_ready(
    conn: &mut Connection,
    stream_id: u32,
    produced_bodies: &mut BTreeMap<u32, ActiveProducedBody>,
    response_guards: &mut HashMap<u32, Arc<InFlightRequestGuard>>,
) {
    enum FinalizeAction {
        Wait,
        Reset {
            diagnostic: Option<(&'static str, &'static str)>,
        },
        EmptyEof,
        Trailers(Vec<Header>),
    }

    let action = {
        let Some(state) = produced_bodies.get(&stream_id) else {
            return;
        };
        match state.producer_outcome {
            None => FinalizeAction::Wait,
            Some(
                Http2ProducerOutcome::Failed
                | Http2ProducerOutcome::DeadlineExceeded
                | Http2ProducerOutcome::ConnectionLost
                | Http2ProducerOutcome::Cancelled,
            ) if state.body_eof || state.pending_trailers.is_some() => {
                FinalizeAction::Reset { diagnostic: None }
            }
            Some(
                Http2ProducerOutcome::Failed
                | Http2ProducerOutcome::DeadlineExceeded
                | Http2ProducerOutcome::ConnectionLost
                | Http2ProducerOutcome::Cancelled,
            ) => FinalizeAction::Wait,
            Some(Http2ProducerOutcome::Finished {
                total_bytes,
                terminal: _,
            }) if state.emitted_bytes > total_bytes
                || (state.body_eof && state.emitted_bytes != total_bytes) =>
            {
                FinalizeAction::Reset {
                    diagnostic: Some((
                        WebBodyDiagnostic::ResponseProducerFailure.code(),
                        "producer byte count did not match the emitted body terminal state",
                    )),
                }
            }
            Some(Http2ProducerOutcome::Finished {
                total_bytes,
                terminal: Http2ProducerTerminal::Finished,
            }) if state.body_eof && state.emitted_bytes == total_bytes => FinalizeAction::EmptyEof,
            Some(Http2ProducerOutcome::Finished {
                total_bytes,
                terminal: Http2ProducerTerminal::Trailers,
            }) if state.emitted_bytes == total_bytes => match state.pending_trailers.as_ref() {
                Some(trailers) => h2_trailers_from_body_map(trailers).map_or(
                    FinalizeAction::Reset {
                        diagnostic: Some((
                            WebBodyDiagnostic::ResponseProducerFailure.code(),
                            "producer trailers could not be encoded",
                        )),
                    },
                    FinalizeAction::Trailers,
                ),
                None => FinalizeAction::Wait,
            },
            Some(Http2ProducerOutcome::Finished {
                terminal: Http2ProducerTerminal::Open,
                ..
            }) => FinalizeAction::Reset {
                diagnostic: Some((
                    WebBodyDiagnostic::ResponseProducerFailure.code(),
                    "producer returned without a terminal body operation",
                )),
            },
            Some(Http2ProducerOutcome::Finished { .. }) => FinalizeAction::Wait,
        }
    };

    match action {
        FinalizeAction::Wait => {}
        FinalizeAction::Reset { diagnostic } => {
            if let Some((code, cause)) = diagnostic {
                record_h2_body_diagnostic_code(stream_id, code, cause);
            }
            conn.reset_stream(stream_id, ErrorCode::InternalError);
            cancel_produced_body(
                produced_bodies,
                stream_id,
                "HTTP/2 produced response failed before clean terminalization",
            );
        }
        terminal_action @ (FinalizeAction::EmptyEof | FinalizeAction::Trailers(_)) => {
            let mut state = produced_bodies
                .remove(&stream_id)
                .expect("produced body exists for terminal action");
            let result = match terminal_action {
                FinalizeAction::EmptyEof => {
                    conn.send_data(stream_id, crate::bytes::Bytes::new(), true)
                }
                FinalizeAction::Trailers(trailers) => conn.send_headers(stream_id, trailers, true),
                FinalizeAction::Wait | FinalizeAction::Reset { .. } => unreachable!(),
            };
            if result.is_ok() {
                state.cancellation.disarm();
                if conn.has_pending_frames_for_stream(stream_id)
                    && let Some(guard) = state.guard.take()
                {
                    let previous = response_guards.insert(stream_id, guard);
                    debug_assert!(previous.is_none());
                }
            } else {
                record_h2_body_diagnostic(
                    stream_id,
                    WebBodyDiagnostic::ResponseProducerFailure,
                    "terminal response frame could not be queued",
                );
                conn.reset_stream(stream_id, ErrorCode::InternalError);
                state.cancel("HTTP/2 terminal produced response frame could not be queued");
            }
        }
    }
}

fn release_flushed_response_guards(
    conn: &Connection,
    response_guards: &mut HashMap<u32, Arc<InFlightRequestGuard>>,
) {
    response_guards.retain(|stream_id, _| conn.has_pending_frames_for_stream(*stream_id));
}

fn queue_h2_response(
    conn: &mut Connection,
    stream_id: u32,
    response: impl IntoHttp2Response,
    guard: InFlightRequestGuard,
    suppress_response_body: bool,
    response_guards: &mut HashMap<u32, Arc<InFlightRequestGuard>>,
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
        let previous = response_guards.insert(stream_id, Arc::new(guard));
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
    /// One credit-admitted frame or EOF from an active produced body.
    ProducedBody(ProducedBodyEvent),
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
    /// A partially received request stream made no progress before its
    /// inactivity deadline. Reset only that stream; keep the connection open.
    StreamIdleTimeout(u32),
    /// A failed producer exceeded its bounded committed-frame drain grace.
    ProducedDrainTimeout(u32),
}

fn poll_produced_body_event(
    conn: &Connection,
    produced_bodies: &mut BTreeMap<u32, ActiveProducedBody>,
    poll_after: &mut Option<u32>,
    task_cx: &mut std::task::Context<'_>,
) -> Poll<ProducedBodyEvent> {
    fn poll_one(
        conn: &Connection,
        stream_id: u32,
        state: &mut ActiveProducedBody,
        task_cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<ProducedBodyEvent>> {
        if state.body_eof || state.pending_trailers.is_some() {
            return Poll::Pending;
        }
        if conn.has_pending_frames_for_stream(stream_id) {
            return Poll::Pending;
        }

        let remaining_is_terminal_only = matches!(
            state.producer_outcome,
            Some(Http2ProducerOutcome::Finished { total_bytes, .. })
                if total_bytes == state.emitted_bytes
        );
        if conn.available_send_capacity(stream_id) == 0 && !remaining_is_terminal_only {
            return Poll::Pending;
        }

        match Pin::new(&mut state.body).poll_frame(task_cx) {
            Poll::Ready(Some(frame)) => {
                Poll::Ready(Some(ProducedBodyEvent::Frame { stream_id, frame }))
            }
            Poll::Ready(None) => Poll::Ready(Some(ProducedBodyEvent::Eof { stream_id })),
            Poll::Pending => Poll::Pending,
        }
    }

    if let Some(after) = *poll_after {
        for (&stream_id, state) in produced_bodies
            .range_mut((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
        {
            if let Poll::Ready(Some(event)) = poll_one(conn, stream_id, state, task_cx) {
                *poll_after = Some(stream_id);
                return Poll::Ready(event);
            }
        }
        for (&stream_id, state) in produced_bodies
            .range_mut((std::ops::Bound::Unbounded, std::ops::Bound::Included(after)))
        {
            if let Poll::Ready(Some(event)) = poll_one(conn, stream_id, state, task_cx) {
                *poll_after = Some(stream_id);
                return Poll::Ready(event);
            }
        }
    } else {
        for (&stream_id, state) in produced_bodies.iter_mut() {
            if let Poll::Ready(Some(event)) = poll_one(conn, stream_id, state, task_cx) {
                *poll_after = Some(stream_id);
                return Poll::Ready(event);
            }
        }
    }
    Poll::Pending
}

/// Flush every frame the connection has queued onto the transport.
///
/// Flow-control-blocked DATA stays queued inside the connection (its
/// `next_frame` re-queues it) and is retried after the next processed
/// frame (e.g. a WINDOW_UPDATE) pumps again.
#[derive(Debug)]
enum H2PumpWriteError {
    Transport(io::Error),
    Encode(H2Error),
}

fn h2_pump_failure_diagnostic(error: &H2PumpWriteError) -> Option<WebBodyDiagnostic> {
    match error {
        H2PumpWriteError::Transport(_) => Some(WebBodyDiagnostic::ClientAbort),
        H2PumpWriteError::Encode(error) if error.stream_id.is_some() => {
            Some(WebBodyDiagnostic::ResponseProducerFailure)
        }
        H2PumpWriteError::Encode(_) => None,
    }
}

async fn pump_writes(
    conn: &mut Connection,
    framed: &mut Framed<TcpStream, FrameCodec>,
) -> Result<(), H2PumpWriteError> {
    loop {
        // Respect the codec's soft buffer boundary before removing another
        // frame from Connection. This keeps a blocked transport from turning
        // the connection's pending frame queue into an unbounded BytesMut.
        std::future::poll_fn(|cx| framed.poll_ready(cx))
            .await
            .map_err(H2PumpWriteError::Transport)?;
        let Some(frame) = conn.next_frame() else {
            break;
        };
        framed.start_send(frame).map_err(H2PumpWriteError::Encode)?;
    }
    std::future::poll_fn(|cx| framed.poll_flush(cx))
        .await
        .map_err(H2PumpWriteError::Transport)
}

async fn pump_writes_with_body_diagnostics(
    conn: &mut Connection,
    framed: &mut Framed<TcpStream, FrameCodec>,
    pending_requests: &HashMap<u32, (Vec<Header>, Vec<u8>)>,
    dispatched_streams: &HashSet<u32>,
    produced_bodies: &mut BTreeMap<u32, ActiveProducedBody>,
    response_guards: &HashMap<u32, Arc<InFlightRequestGuard>>,
) -> io::Result<()> {
    match pump_writes(conn, framed).await {
        Ok(()) => Ok(()),
        Err(error @ H2PumpWriteError::Transport(_)) => {
            let mut affected_streams = HashSet::new();
            affected_streams.extend(pending_requests.keys().copied());
            affected_streams.extend(dispatched_streams.iter().copied());
            affected_streams.extend(produced_bodies.keys().copied());
            affected_streams.extend(response_guards.keys().copied());
            let diagnostic = h2_pump_failure_diagnostic(&error)
                .expect("transport write failure has a body diagnostic");
            for stream_id in affected_streams {
                record_h2_body_diagnostic(
                    stream_id,
                    diagnostic,
                    "peer transport failed while flushing HTTP/2 frames",
                );
            }
            cancel_all_produced_bodies(
                produced_bodies,
                "HTTP/2 peer transport failed while flushing frames",
            );
            let H2PumpWriteError::Transport(error) = error else {
                unreachable!();
            };
            Err(error)
        }
        Err(error @ H2PumpWriteError::Encode(_)) => {
            let diagnostic = h2_pump_failure_diagnostic(&error);
            let H2PumpWriteError::Encode(error) = error else {
                unreachable!();
            };
            if let (Some(diagnostic), Some(stream_id)) = (diagnostic, error.stream_id)
                && (produced_bodies.contains_key(&stream_id)
                    || response_guards.contains_key(&stream_id))
            {
                record_h2_body_diagnostic(
                    stream_id,
                    diagnostic,
                    "locally queued HTTP/2 body frame could not be encoded",
                );
                cancel_produced_body(
                    produced_bodies,
                    stream_id,
                    "HTTP/2 body frame encoding failed",
                );
            }
            Err(io::Error::other(error))
        }
    }
}

/// Wait for the next driver event: incoming frame, completed handler
/// response, or a shutdown-phase transition.
async fn next_driver_event(
    framed: &mut Framed<TcpStream, FrameCodec>,
    resp_rx: &mut mpsc::Receiver<FunnelItem>,
    conn: &Connection,
    produced_bodies: &mut BTreeMap<u32, ActiveProducedBody>,
    produced_poll_after: &mut Option<u32>,
    task_cx: &Cx,
    signal: &ShutdownSignal,
    watch_drain: bool,
    finalize_deadline: Option<Time>,
    idle_deadline: Option<Time>,
    continuation_deadline: Option<Time>,
    stream_idle_deadline: Option<(u32, Time)>,
    produced_failure_deadline: Option<(u32, Time)>,
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
    let stream_idle_at = stream_idle_deadline.map(|(_, deadline)| deadline);
    let mut stream_idle_fut = std::pin::pin!(async move {
        match stream_idle_at {
            Some(deadline) => crate::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
    });
    let produced_failure_at = produced_failure_deadline.map(|(_, deadline)| deadline);
    let mut produced_failure_fut = std::pin::pin!(async move {
        match produced_failure_at {
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
        if let Some((stream_id, _)) = stream_idle_deadline {
            if stream_idle_fut.as_mut().poll(cx).is_ready() {
                return Poll::Ready(DriverEvent::StreamIdleTimeout(stream_id));
            }
        }
        if let Some((stream_id, _)) = produced_failure_deadline {
            if produced_failure_fut.as_mut().poll(cx).is_ready() {
                return Poll::Ready(DriverEvent::ProducedDrainTimeout(stream_id));
            }
        }
        // Cancel-correct channels make dropping a partially-polled recv
        // safe: no item is consumed unless the future completes.
        if let Poll::Ready(Ok(item)) = recv_fut.as_mut().poll(cx) {
            return Poll::Ready(DriverEvent::Response(item));
        }
        if let Poll::Ready(item) =
            poll_produced_body_event(conn, produced_bodies, produced_poll_after, cx)
        {
            return Poll::Ready(DriverEvent::ProducedBody(item));
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
fn dispatch_h2_request<F, Fut>(
    conn: &mut Connection,
    stream_id: u32,
    headers: Vec<Header>,
    body: Vec<u8>,
    trailers: Vec<Header>,
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
    stream_idle_timeout: Option<Duration>,
    owned_request: bool,
) -> bool
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = H2DispatchResponse> + Send + 'static,
{
    let request = match request_from_h2_parts(headers, body, trailers, peer_addr) {
        Ok(request) => request,
        Err(_) => {
            conn.reset_stream(stream_id, ErrorCode::ProtocolError);
            return false;
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
                permit.send(FunnelItem::Response {
                    stream_id,
                    response: reject,
                    guard,
                    suppress_response_body,
                });
            }
            return;
        }

        // br-asupersync-mfqfst M8: run the handler inside a server-hop request
        // region so the h2 dispatch path actually has the request budget +
        // deadline + cancel backstop the driver comment promised (h1 parity
        // via `ServerRequestRegion`). The request budget is the connection
        // budget tightened by the configured request timeout and the (opt-in,
        // cap-clamped) client `Request-Timeout` header (meet semantics — it
        // can only tighten, never extend). Buffered listeners use an actual
        // admitted child task. Produced listeners retain their existing
        // handler lifetime because the returned producer may release work
        // started by that handler.
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

        let producer_signal = signal.clone();
        let response = if owned_request {
            let completed = run_owned_h2_hop(
                &cx,
                &signal,
                OwnedH2HopConfig {
                    budget: request_budget,
                    started_at: request_now,
                    source: budget_source,
                    drain_grace: request_drain_grace,
                    idle_timeout: stream_idle_timeout,
                },
                move || handler(request),
            )
            .await;
            // Closing the child can itself wait for descendants/finalizers.
            // A response completed before ForceClosing still cannot escape
            // after shutdown won during that owned close.
            if signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8 {
                drop(guard);
                return;
            }
            match completed {
                Ok(completed) => {
                    if let Some(Err(error)) = &completed.task_outcome {
                        cx.trace(&format!("h2_owned_handler_task_terminal: {error:?}"));
                    }
                    if completed.idle_expired {
                        if let Ok(permit) = resp_tx.reserve(&cx).await {
                            permit.send(FunnelItem::StreamIdleTimeout { stream_id, guard });
                        }
                        return;
                    }
                    match completed.hop {
                        ServerHopOutcome::Ok(response) => Some(response),
                        ServerHopOutcome::Cancelled | ServerHopOutcome::ConnectionLost => None,
                        ServerHopOutcome::Panicked(message) => {
                            cx.trace(&format!("h2_owned_handler_panicked: {message}"));
                            Some(H2DispatchResponse::Buffered(
                                Response::new(500, "Internal Server Error", Vec::new())
                                    .into_h2_response(),
                            ))
                        }
                        ServerHopOutcome::DeadlineExceeded => Some(H2DispatchResponse::Buffered(
                            Response::new(
                                503,
                                "Service Unavailable",
                                HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC.as_bytes().to_vec(),
                            )
                            .into_h2_response(),
                        )),
                    }
                }
                Err(error) => {
                    cx.trace(&format!(
                        "h2_owned_handler_admission_or_close_failed: {error}"
                    ));
                    Some(H2DispatchResponse::Buffered(
                        Response::new(500, "Internal Server Error", Vec::new()).into_h2_response(),
                    ))
                }
            }
        } else {
            let handler_future = async move {
                match ServerRequestRegion::mint("h2", request_budget, request_now) {
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
                            None => None,
                            Some(ServerHopOutcome::Ok(response)) => Some(response),
                            Some(
                                ServerHopOutcome::Cancelled | ServerHopOutcome::ConnectionLost,
                            ) => None,
                            Some(ServerHopOutcome::Panicked(message)) => {
                                // Panic isolation (h1 parity): the connection driver
                                // survives and the stream completes with a 500 instead
                                // of staying active forever.
                                let _ = &message;
                                error!(message = %message, "h2 handler task panicked");
                                Some(H2DispatchResponse::Buffered(
                                    Response::new(500, "Internal Server Error", Vec::new())
                                        .into_h2_response(),
                                ))
                            }
                            Some(ServerHopOutcome::DeadlineExceeded) => {
                                Some(H2DispatchResponse::Buffered(
                                    Response::new(
                                        503,
                                        "Service Unavailable",
                                        HTTP_DEADLINE_EXHAUSTED_DIAGNOSTIC.as_bytes().to_vec(),
                                    )
                                    .into_h2_response(),
                                ))
                            }
                        }
                    }
                    None => {
                        // No runtime installed on this thread: preserve the legacy
                        // direct-call path (force-close race + panic isolation, no
                        // request region).
                        let handler_result = race_force_close(
                            &signal,
                            CatchUnwind {
                                inner: handler(request),
                            },
                        )
                        .await?;
                        match handler_result {
                            Ok(response) => Some(response),
                            Err(payload) => {
                                let message = crate::cx::scope::payload_to_string(&payload);
                                let _ = &message;
                                error!(
                                    message = %message,
                                    "h2 handler task panicked"
                                );
                                Some(H2DispatchResponse::Buffered(
                                    Response::new(500, "Internal Server Error", Vec::new())
                                        .into_h2_response(),
                                ))
                            }
                        }
                    }
                }
            };

            if let Some(timeout) = stream_idle_timeout {
                match crate::time::timeout_at(request_now + timeout, handler_future).await {
                    Ok(response) => response,
                    Err(_) => {
                        if let Ok(permit) = resp_tx.reserve(&cx).await {
                            permit.send(FunnelItem::StreamIdleTimeout { stream_id, guard });
                        }
                        return;
                    }
                }
            } else {
                handler_future.await
            }
        };
        let Some(response) = response else {
            drop(guard);
            return;
        };
        match response {
            H2DispatchResponse::Buffered(response) => {
                if let Ok(permit) = resp_tx.reserve(&cx).await {
                    if owned_request
                        && producer_signal.phase() as u8 >= ShutdownPhase::ForceClosing as u8
                    {
                        // Capacity becoming available is not permission to
                        // publish a completed response after forced shutdown.
                        drop(permit);
                        drop(guard);
                        return;
                    }
                    permit.send(FunnelItem::Response {
                        stream_id,
                        response,
                        guard,
                        suppress_response_body,
                    });
                }
            }
            H2DispatchResponse::Produced(plan) => {
                let validation = if suppress_response_body {
                    validate_h2_produced_head_for_queue(&plan.response)
                } else {
                    validate_h2_produced_response_for_queue(&plan.response)
                };
                if validation.is_err() {
                    if let Ok(permit) = resp_tx.reserve(&cx).await {
                        permit.send(FunnelItem::Response {
                            stream_id,
                            response: invalid_h2_response_fallback(),
                            guard,
                            suppress_response_body,
                        });
                    }
                    return;
                }
                if suppress_response_body {
                    if let Ok(permit) = resp_tx.reserve(&cx).await {
                        permit.send(FunnelItem::Response {
                            stream_id,
                            response: plan.response.into_h2_response(),
                            guard,
                            suppress_response_body: true,
                        });
                    }
                    return;
                }

                let region = ServerRequestRegion::mint_from_connection(
                    "h2-produced",
                    request_budget,
                    request_now,
                    &cx,
                );
                let producer_cx = region.cx().clone();
                let (response, body, sender, producer_factory) = plan.into_parts(&producer_cx);
                let Ok(permit) = resp_tx.reserve(&cx).await else {
                    producer_cx.cancel_with(
                        crate::types::CancelKind::ParentCancelled,
                        Some("HTTP/2 response funnel closed before producer start"),
                    );
                    drop(guard);
                    return;
                };
                let guard = Arc::new(guard);
                let producer_guard = Arc::clone(&guard);
                permit.send(FunnelItem::ProducedStart {
                    stream_id,
                    response,
                    body,
                    cancellation: ProducedCancellationGuard::new(producer_cx.clone()),
                    guard,
                });

                let producer_cx_for_factory = producer_cx.clone();
                let producer =
                    async move { producer_factory(producer_cx_for_factory, sender).await };
                let run = region.run_with_protocol_drain(
                    budget_source,
                    Some(producer_cx.clone()),
                    request_drain_grace,
                    producer,
                );
                let outcome = classify_h2_producer_hop(
                    race_force_close(&producer_signal, run).await,
                    &producer_cx,
                );
                if let Ok(permit) = resp_tx.reserve(&cx).await {
                    permit.send(FunnelItem::ProducedDone { stream_id, outcome });
                }
                drop(producer_guard);
            }
        }
    });
    if spawned.is_err() {
        conn.reset_stream(stream_id, ErrorCode::InternalError);
        false
    } else {
        true
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
async fn serve_h2_connection<F, Fut>(
    mut stream: TcpStream,
    peer_addr: Option<SocketAddr>,
    handler: Arc<F>,
    settings: Settings,
    initial_connection_window_size: u32,
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
    stream_idle_timeout: Option<Duration>,
    time_getter: fn() -> Time,
    owned_request: bool,
) -> io::Result<()>
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = H2DispatchResponse> + Send + 'static,
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
    conn.set_initial_connection_recv_window(initial_connection_window_size)
        .map_err(io::Error::other)?;
    let mut framed = Framed::new(stream, frame_codec_for(local_max_frame_size));

    let (resp_tx, mut resp_rx) = mpsc::channel::<FunnelItem>(RESPONSE_FUNNEL_CAPACITY);
    // Per-stream request assembly: headers arrive first, DATA accumulates
    // until END_STREAM completes the request.
    let mut pending_requests: HashMap<u32, (Vec<Header>, Vec<u8>)> = HashMap::new();
    // Absolute inactivity deadlines for partially received request streams.
    // A deadline is replaced only by actual HEADERS/DATA progress, never by
    // unrelated connection wake-ups.
    let mut pending_stream_idle_deadlines: HashMap<u32, Time> = HashMap::new();
    // Fixed stage-2 GOAWAY deadline, armed once when stage-1 is outstanding.
    let mut finalize_at: Option<Time> = None;
    let mut response_guards: HashMap<u32, Arc<InFlightRequestGuard>> = HashMap::new();
    let mut produced_bodies: BTreeMap<u32, ActiveProducedBody> = BTreeMap::new();
    // Complete requests remain tracked while their handler is in flight so a
    // peer RST cannot disappear in the dispatch -> response-funnel gap.
    let mut dispatched_streams: HashSet<u32> = HashSet::new();
    let mut peer_reset_before_response: HashSet<u32> = HashSet::new();
    let mut produced_poll_after = None;
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
        pump_writes_with_body_diagnostics(
            &mut conn,
            &mut framed,
            &pending_requests,
            &dispatched_streams,
            &mut produced_bodies,
            &response_guards,
        )
        .await?;
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
            && produced_bodies.is_empty()
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
            && produced_bodies.is_empty()
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
        let stream_idle_at = pending_stream_idle_deadlines
            .iter()
            .min_by_key(|(stream_id, deadline)| (**deadline, **stream_id))
            .map(|(stream_id, deadline)| (*stream_id, *deadline));
        let produced_failure_at = produced_bodies
            .iter()
            .filter_map(|(stream_id, state)| {
                state
                    .failure_drain_deadline
                    .map(|deadline| (*stream_id, deadline))
            })
            .min_by_key(|(stream_id, deadline)| (*deadline, *stream_id));
        let event = next_driver_event(
            &mut framed,
            &mut resp_rx,
            &conn,
            &mut produced_bodies,
            &mut produced_poll_after,
            &task_cx,
            &shutdown_signal,
            watch_drain,
            finalize_at,
            idle_at,
            continuation_at,
            stream_idle_at,
            produced_failure_at,
        )
        .await;

        match event {
            DriverEvent::ForceClose => {
                // Escalation: drop the transport; spawned handler hops are
                // raced against ForceClosing and request-region teardown is
                // the cancellation backstop (h1 parity).
                cancel_all_produced_bodies(&mut produced_bodies, "HTTP/2 connection force-closed");
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
                pump_writes_with_body_diagnostics(
                    &mut conn,
                    &mut framed,
                    &pending_requests,
                    &dispatched_streams,
                    &mut produced_bodies,
                    &response_guards,
                )
                .await?;
                let _ = std::future::poll_fn(|cx| framed.poll_close(cx)).await;
                cancel_all_produced_bodies(&mut produced_bodies, "HTTP/2 connection idle timeout");
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
                pump_writes_with_body_diagnostics(
                    &mut conn,
                    &mut framed,
                    &pending_requests,
                    &dispatched_streams,
                    &mut produced_bodies,
                    &response_guards,
                )
                .await?;
                let _ = std::future::poll_fn(|cx| framed.poll_close(cx)).await;
                cancel_all_produced_bodies(&mut produced_bodies, "HTTP/2 CONTINUATION timeout");
                return Ok(());
            }
            DriverEvent::StreamIdleTimeout(stream_id) => {
                record_h2_body_diagnostic_code(
                    stream_id,
                    WebBodyDiagnostic::Timeout.code(),
                    "pending request body exceeded its stream idle timeout",
                );
                pending_stream_idle_deadlines.remove(&stream_id);
                pending_requests.remove(&stream_id);
                conn.reset_stream(stream_id, ErrorCode::Cancel);
                cancel_produced_body(
                    &mut produced_bodies,
                    stream_id,
                    "HTTP/2 produced response stream idle timeout",
                );
                reset_associated_pushes(&mut conn, &mut associated_pushes, stream_id);
            }
            DriverEvent::ProducedDrainTimeout(stream_id) => {
                match produced_bodies
                    .get(&stream_id)
                    .and_then(|state| state.producer_outcome)
                {
                    Some(Http2ProducerOutcome::Failed) => record_h2_body_diagnostic(
                        stream_id,
                        WebBodyDiagnostic::ResponseProducerFailure,
                        "failed producer exceeded its bounded drain grace",
                    ),
                    Some(Http2ProducerOutcome::DeadlineExceeded) => {
                        record_h2_body_diagnostic_code(
                            stream_id,
                            "ASUP-E501",
                            "deadline-exhausted producer exceeded its bounded drain grace",
                        );
                    }
                    Some(Http2ProducerOutcome::ConnectionLost) => record_h2_body_diagnostic(
                        stream_id,
                        WebBodyDiagnostic::ClientAbort,
                        "connection-lost producer exceeded its bounded drain grace",
                    ),
                    Some(
                        Http2ProducerOutcome::Cancelled | Http2ProducerOutcome::Finished { .. },
                    )
                    | None => {}
                }
                conn.reset_stream(stream_id, ErrorCode::Cancel);
                cancel_produced_body(
                    &mut produced_bodies,
                    stream_id,
                    "HTTP/2 produced response exceeded failure drain grace",
                );
            }
            DriverEvent::Frame(None) => {
                // Peer closed the transport.
                for stream_id in pending_requests.keys().copied() {
                    record_h2_body_diagnostic(
                        stream_id,
                        WebBodyDiagnostic::ClientAbort,
                        "peer closed the HTTP/2 connection with a pending request body",
                    );
                }
                for stream_id in dispatched_streams.iter().copied() {
                    record_h2_body_diagnostic(
                        stream_id,
                        WebBodyDiagnostic::ClientAbort,
                        "peer closed the HTTP/2 connection while the handler was in flight",
                    );
                }
                for stream_id in produced_bodies.keys().copied() {
                    record_h2_body_diagnostic(
                        stream_id,
                        WebBodyDiagnostic::ClientAbort,
                        "peer closed the HTTP/2 connection",
                    );
                }
                cancel_all_produced_bodies(
                    &mut produced_bodies,
                    "HTTP/2 peer closed the connection",
                );
                return Ok(());
            }
            DriverEvent::Frame(Some(Err(decode_error))) => {
                conn.goaway(decode_error.code, crate::bytes::Bytes::new());
                pump_writes_with_body_diagnostics(
                    &mut conn,
                    &mut framed,
                    &pending_requests,
                    &dispatched_streams,
                    &mut produced_bodies,
                    &response_guards,
                )
                .await?;
                let _ = std::future::poll_fn(|cx| framed.poll_close(cx)).await;
                cancel_all_produced_bodies(&mut produced_bodies, "HTTP/2 frame decode failed");
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
                        pending_stream_idle_deadlines.remove(&stream_id);
                        cancel_produced_body(
                            &mut produced_bodies,
                            stream_id,
                            "HTTP/2 stream protocol error",
                        );
                        reset_associated_pushes(&mut conn, &mut associated_pushes, stream_id);
                    } else {
                        conn.goaway(protocol_error.code, crate::bytes::Bytes::new());
                        pump_writes_with_body_diagnostics(
                            &mut conn,
                            &mut framed,
                            &pending_requests,
                            &dispatched_streams,
                            &mut produced_bodies,
                            &response_guards,
                        )
                        .await?;
                        let _ = std::future::poll_fn(|cx| framed.poll_close(cx)).await;
                        cancel_all_produced_bodies(
                            &mut produced_bodies,
                            "HTTP/2 connection protocol error",
                        );
                        return Err(io::Error::other(protocol_error));
                    }
                }
                Ok(Some(ReceivedFrame::Headers {
                    stream_id,
                    headers,
                    end_stream,
                })) => {
                    if let Some((req_headers, req_body)) = pending_requests.remove(&stream_id) {
                        pending_stream_idle_deadlines.remove(&stream_id);
                        // A second HEADERS block on a stream already
                        // assembling a body is request trailers (RFC 9113
                        // §8.1; the connection enforces trailers carry
                        // END_STREAM). The buffered request is now complete;
                        // dispatch it with the trailer block kept separate on
                        // the shared Request type for protocol adapters.
                        if dispatch_h2_request(
                            &mut conn,
                            stream_id,
                            req_headers,
                            req_body,
                            headers,
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
                            stream_idle_timeout,
                            owned_request,
                        ) {
                            dispatched_streams.insert(stream_id);
                            requests_dispatched = requests_dispatched.saturating_add(1);
                        }
                    } else if end_stream {
                        if dispatch_h2_request(
                            &mut conn,
                            stream_id,
                            headers,
                            Vec::new(),
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
                            stream_idle_timeout,
                            owned_request,
                        ) {
                            dispatched_streams.insert(stream_id);
                            requests_dispatched = requests_dispatched.saturating_add(1);
                        }
                    } else {
                        pending_requests.insert(stream_id, (headers, Vec::new()));
                        if let Some(timeout) = stream_idle_timeout {
                            pending_stream_idle_deadlines
                                .insert(stream_id, (time_getter)() + timeout);
                        }
                    }
                }
                Ok(Some(ReceivedFrame::Data {
                    stream_id,
                    data,
                    end_stream,
                })) => {
                    if let Some((_, body)) = pending_requests.get_mut(&stream_id) {
                        if let Some(timeout) = stream_idle_timeout {
                            pending_stream_idle_deadlines
                                .insert(stream_id, (time_getter)() + timeout);
                        }
                        if body.len().saturating_add(data.len()) > max_body_size {
                            // Bound per-stream request buffering: HTTP/2 flow
                            // control auto-replenishes windows, so without
                            // this cap one stream could buffer unbounded bytes
                            // (remote OOM). Refuse the stream and drop its
                            // partial body.
                            conn.reset_stream(stream_id, ErrorCode::EnhanceYourCalm);
                            pending_requests.remove(&stream_id);
                            pending_stream_idle_deadlines.remove(&stream_id);
                        } else {
                            body.extend_from_slice(&data);
                            if end_stream {
                                let (headers, body) = pending_requests
                                    .remove(&stream_id)
                                    .expect("pending request present");
                                pending_stream_idle_deadlines.remove(&stream_id);
                                if dispatch_h2_request(
                                    &mut conn,
                                    stream_id,
                                    headers,
                                    body,
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
                                    stream_idle_timeout,
                                    owned_request,
                                ) {
                                    dispatched_streams.insert(stream_id);
                                    requests_dispatched = requests_dispatched.saturating_add(1);
                                }
                            }
                        }
                    }
                }
                Ok(Some(ReceivedFrame::Reset { stream_id, .. })) => {
                    let dispatched = mark_h2_peer_reset_before_response(
                        &mut dispatched_streams,
                        &mut peer_reset_before_response,
                        stream_id,
                    );
                    if pending_requests.contains_key(&stream_id)
                        || dispatched
                        || produced_bodies.contains_key(&stream_id)
                    {
                        record_h2_body_diagnostic(
                            stream_id,
                            WebBodyDiagnostic::ClientAbort,
                            "peer reset the request/response body stream",
                        );
                    }
                    pending_requests.remove(&stream_id);
                    pending_stream_idle_deadlines.remove(&stream_id);
                    cancel_produced_body(
                        &mut produced_bodies,
                        stream_id,
                        "HTTP/2 peer reset the produced response stream",
                    );
                    reset_associated_pushes(&mut conn, &mut associated_pushes, stream_id);
                }
                Ok(_) => {}
            },
            DriverEvent::ProducedBody(event) => match event {
                ProducedBodyEvent::Frame {
                    stream_id,
                    frame: Ok(BodyFrame::Data(data)),
                } => {
                    let data = data.into_inner();
                    let data_len = u64::try_from(data.len()).unwrap_or(u64::MAX);
                    let Some(state) = produced_bodies.get_mut(&stream_id) else {
                        continue;
                    };
                    let Some(emitted_bytes) = state.emitted_bytes.checked_add(data_len) else {
                        record_h2_body_diagnostic(
                            stream_id,
                            WebBodyDiagnostic::ResponseProducerFailure,
                            "produced response byte accounting overflowed",
                        );
                        conn.reset_stream(stream_id, ErrorCode::InternalError);
                        cancel_produced_body(
                            &mut produced_bodies,
                            stream_id,
                            "HTTP/2 produced response byte count overflowed",
                        );
                        continue;
                    };
                    state.emitted_bytes = emitted_bytes;
                    if conn.send_data(stream_id, data, false).is_err() {
                        record_h2_body_diagnostic(
                            stream_id,
                            WebBodyDiagnostic::ResponseProducerFailure,
                            "produced DATA could not be queued",
                        );
                        conn.reset_stream(stream_id, ErrorCode::InternalError);
                        cancel_produced_body(
                            &mut produced_bodies,
                            stream_id,
                            "HTTP/2 produced DATA could not be queued",
                        );
                    } else {
                        finalize_produced_body_if_ready(
                            &mut conn,
                            stream_id,
                            &mut produced_bodies,
                            &mut response_guards,
                        );
                    }
                }
                ProducedBodyEvent::Frame {
                    stream_id,
                    frame: Ok(BodyFrame::Trailers(trailers)),
                } => {
                    let Some(state) = produced_bodies.get_mut(&stream_id) else {
                        continue;
                    };
                    if state.pending_trailers.replace(trailers).is_some() || state.body_eof {
                        record_h2_body_diagnostic(
                            stream_id,
                            WebBodyDiagnostic::ResponseProducerFailure,
                            "produced response emitted duplicate terminal frames",
                        );
                        conn.reset_stream(stream_id, ErrorCode::InternalError);
                        cancel_produced_body(
                            &mut produced_bodies,
                            stream_id,
                            "HTTP/2 produced response emitted duplicate terminal frames",
                        );
                    } else {
                        finalize_produced_body_if_ready(
                            &mut conn,
                            stream_id,
                            &mut produced_bodies,
                            &mut response_guards,
                        );
                    }
                }
                ProducedBodyEvent::Frame {
                    stream_id,
                    frame: Err(HttpError::BodyCancelled),
                } => {
                    // The authoritative producer task owns cancellation-cause
                    // classification. Keep the stream pending until its
                    // ProducedDone outcome arrives instead of overwriting a
                    // deadline or peer-reset acknowledgement with E510.
                    if let Some(state) = produced_bodies.get_mut(&stream_id) {
                        state.body_eof = true;
                    }
                    finalize_produced_body_if_ready(
                        &mut conn,
                        stream_id,
                        &mut produced_bodies,
                        &mut response_guards,
                    );
                }
                ProducedBodyEvent::Frame {
                    stream_id,
                    frame: Err(_),
                } => {
                    record_h2_body_diagnostic(
                        stream_id,
                        WebBodyDiagnostic::ResponseProducerFailure,
                        "produced response body yielded an error frame",
                    );
                    if let Some(state) = produced_bodies.get_mut(&stream_id) {
                        state.producer_outcome = Some(Http2ProducerOutcome::Failed);
                        state.body_eof = true;
                    }
                    finalize_produced_body_if_ready(
                        &mut conn,
                        stream_id,
                        &mut produced_bodies,
                        &mut response_guards,
                    );
                }
                ProducedBodyEvent::Eof { stream_id } => {
                    if let Some(state) = produced_bodies.get_mut(&stream_id) {
                        state.body_eof = true;
                    }
                    finalize_produced_body_if_ready(
                        &mut conn,
                        stream_id,
                        &mut produced_bodies,
                        &mut response_guards,
                    );
                }
            },
            DriverEvent::Response(item) => match item {
                FunnelItem::Response {
                    stream_id,
                    response,
                    guard,
                    suppress_response_body,
                } => {
                    dispatched_streams.remove(&stream_id);
                    if peer_reset_before_response.remove(&stream_id) {
                        drop(guard);
                        continue;
                    }
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
                FunnelItem::ProducedStart {
                    stream_id,
                    response,
                    body,
                    mut cancellation,
                    guard,
                } => {
                    dispatched_streams.remove(&stream_id);
                    if peer_reset_before_response.remove(&stream_id) {
                        cancellation.cancel("HTTP/2 peer reset before produced response start");
                        drop(guard);
                        continue;
                    }
                    let writable = conn.stream(stream_id).is_some_and(|stream| {
                        stream.error_code().is_none() && stream.state().can_send()
                    });
                    if !writable
                        || produced_bodies.contains_key(&stream_id)
                        || validate_h2_produced_response_for_queue(&response).is_err()
                    {
                        record_h2_body_diagnostic(
                            stream_id,
                            WebBodyDiagnostic::ResponseProducerFailure,
                            "produced response could not start on a writable stream",
                        );
                        cancellation.cancel("HTTP/2 produced response could not start");
                        conn.reset_stream(stream_id, ErrorCode::InternalError);
                        drop(guard);
                        continue;
                    }
                    let headers = h2_headers_from_response(&response)
                        .expect("validated produced response head must encode");
                    if conn.send_headers(stream_id, headers, false).is_err() {
                        record_h2_body_diagnostic(
                            stream_id,
                            WebBodyDiagnostic::ResponseProducerFailure,
                            "produced response headers could not be queued",
                        );
                        cancellation.cancel("HTTP/2 produced response headers could not be queued");
                        conn.reset_stream(stream_id, ErrorCode::InternalError);
                        drop(guard);
                        continue;
                    }
                    let previous = produced_bodies.insert(
                        stream_id,
                        ActiveProducedBody {
                            body,
                            cancellation,
                            guard: Some(guard),
                            producer_outcome: None,
                            emitted_bytes: 0,
                            body_eof: false,
                            pending_trailers: None,
                            failure_drain_deadline: None,
                        },
                    );
                    debug_assert!(previous.is_none());
                }
                FunnelItem::ProducedDone { stream_id, outcome } => {
                    if let Some(state) = produced_bodies.get_mut(&stream_id) {
                        if let Some((code, cause)) = h2_producer_outcome_diagnostic(outcome) {
                            record_h2_body_diagnostic_code(stream_id, code, cause);
                        }
                        if state.producer_outcome.replace(outcome).is_some() {
                            record_h2_body_diagnostic(
                                stream_id,
                                WebBodyDiagnostic::ResponseProducerFailure,
                                "response producer completed more than once",
                            );
                            conn.reset_stream(stream_id, ErrorCode::InternalError);
                            cancel_produced_body(
                                &mut produced_bodies,
                                stream_id,
                                "HTTP/2 produced response completed more than once",
                            );
                            continue;
                        }
                        if !matches!(outcome, Http2ProducerOutcome::Finished { .. }) {
                            state.failure_drain_deadline =
                                Some((time_getter)() + request_drain_grace);
                        }
                    }
                    finalize_produced_body_if_ready(
                        &mut conn,
                        stream_id,
                        &mut produced_bodies,
                        &mut response_guards,
                    );
                }
                FunnelItem::StreamIdleTimeout { stream_id, guard } => {
                    dispatched_streams.remove(&stream_id);
                    peer_reset_before_response.remove(&stream_id);
                    record_h2_body_diagnostic_code(
                        stream_id,
                        "ASUP-E501",
                        "request handler exceeded its configured execution timeout",
                    );
                    pending_stream_idle_deadlines.remove(&stream_id);
                    pending_requests.remove(&stream_id);
                    conn.reset_stream(stream_id, ErrorCode::Cancel);
                    cancel_produced_body(
                        &mut produced_bodies,
                        stream_id,
                        "HTTP/2 produced response stream idle timeout",
                    );
                    reset_associated_pushes(&mut conn, &mut associated_pushes, stream_id);
                    drop(guard);
                }
            },
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
    /// Connection-level receive window advertised with an initial stream-0
    /// WINDOW_UPDATE. HTTP/2 has no SETTINGS field for this window.
    pub initial_connection_window_size: u32,
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
    /// Maximum inactivity interval for an individual request stream.
    ///
    /// The deadline is reset whenever request HEADERS or DATA arrives. It also
    /// bounds handler execution after END_STREAM because this listener buffers
    /// request bodies before dispatch. Expiry resets only the affected stream
    /// with CANCEL and drops the associated handler future; the multiplexed
    /// connection remains available to other streams. `None` disables it.
    pub stream_idle_timeout: Option<Duration>,
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
            initial_connection_window_size: 65_535,
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
            stream_idle_timeout: None,
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

    /// Set the connection-level receive window advertised at handshake.
    ///
    /// Values outside `65_535..=2^31-1` are rejected by the connection driver
    /// when a peer is accepted; the setter preserves the requested value so a
    /// configuration error cannot be silently clamped.
    #[must_use]
    pub fn initial_connection_window_size(mut self, size: u32) -> Self {
        self.initial_connection_window_size = size;
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

    /// Set the per-request-stream inactivity timeout. `None` disables it.
    #[must_use]
    pub fn stream_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.stream_idle_timeout = timeout;
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

    /// Run the accept loop until shutdown, then drain with request-aware
    /// supervision and return the shutdown statistics (including the
    /// graceful-drain report).
    pub async fn run(self, runtime: &RuntimeHandle) -> io::Result<ShutdownStats> {
        self.run_mapped(runtime, true, |handler, request| async move {
            H2DispatchResponse::Buffered(handler(request).await.into_h2_response())
        })
        .await
    }
}

impl<F> Http2Listener<F> {
    /// Bind a listener whose handler may return a deferred produced body.
    pub async fn bind_produced<A, Fut>(addr: A, handler: F) -> io::Result<Self>
    where
        A: ToSocketAddrs + Send + 'static,
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Http2ProducedResponse> + Send + 'static,
    {
        Self::bind_produced_with_config(addr, handler, Http2ListenerConfig::default()).await
    }

    /// Bind a produced-response listener with custom configuration.
    pub async fn bind_produced_with_config<A, Fut>(
        addr: A,
        handler: F,
        config: Http2ListenerConfig,
    ) -> io::Result<Self>
    where
        A: ToSocketAddrs + Send + 'static,
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Http2ProducedResponse> + Send + 'static,
    {
        let tcp_listener = TcpListener::bind(addr).await?;
        Ok(Self::from_parts(tcp_listener, handler, config))
    }

    /// Create a produced-response listener from an existing TCP listener.
    #[must_use]
    pub fn from_listener_produced<Fut>(
        tcp_listener: TcpListener,
        handler: F,
        config: Http2ListenerConfig,
    ) -> Self
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Http2ProducedResponse> + Send + 'static,
    {
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

    /// Run the accept loop with an output type that may defer a bounded body
    /// producer. Ordinary buffered responses remain on the existing path.
    pub async fn run_produced<Fut>(self, runtime: &RuntimeHandle) -> io::Result<ShutdownStats>
    where
        F: Fn(Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Http2ProducedResponse> + Send + 'static,
    {
        self.run_mapped(runtime, false, |handler, request| async move {
            handler(request).await.into_driver_response()
        })
        .await
    }

    #[allow(clippy::too_many_lines)]
    async fn run_mapped<M, MFut>(
        self,
        runtime: &RuntimeHandle,
        owned_request: bool,
        map_response: M,
    ) -> io::Result<ShutdownStats>
    where
        F: Send + Sync + 'static,
        M: Fn(Arc<F>, Request) -> MFut + Clone + Send + Sync + 'static,
        MFut: Future<Output = H2DispatchResponse> + Send + 'static,
    {
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

            let raw_handler = Arc::clone(&self.handler);
            let map_response = map_response.clone();
            let handler = Arc::new(move |request| map_response(Arc::clone(&raw_handler), request));
            let settings = self.config.settings.clone();
            let initial_connection_window_size = self.config.initial_connection_window_size;
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
            let stream_idle_timeout = self.config.stream_idle_timeout;
            let conn_time_getter = self.config.time_getter;
            // Check the connection's Send boundary once before the runtime's
            // nested task wrappers instantiate it for each handler type.
            let connection: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
                let peer_addr = Some(addr);
                if let Err(err) = serve_h2_connection(
                    stream,
                    peer_addr,
                    handler,
                    settings,
                    initial_connection_window_size,
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
                    stream_idle_timeout,
                    conn_time_getter,
                    owned_request,
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
            let spawn_result = runtime.try_spawn(connection);
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

    fn owned_hop_config() -> OwnedH2HopConfig {
        OwnedH2HopConfig {
            budget: Budget::INFINITE,
            started_at: Time::ZERO,
            source: RequestBudgetSource::Inherited,
            drain_grace: Duration::from_nanos(100),
            idle_timeout: None,
        }
    }

    struct OwnedBodyDrop {
        cx: Cx,
        dropped: Arc<AtomicUsize>,
        cancelled: Arc<AtomicUsize>,
    }

    impl Drop for OwnedBodyDrop {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
            if self.cx.is_cancel_requested() {
                self.cancelled.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn finish_owned_h2_lab(lab: &mut crate::lab::LabRuntime, root: crate::types::RegionId) {
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.regions_len(), 1, "only the actual root remains");
        assert!(lab.state.region(root).is_some());
        assert!(
            lab.state
                .timer_driver_handle()
                .unwrap()
                .next_deadline()
                .is_none()
        );
        assert!(lab.run_until_quiescent_with_report().lab_test_passed());
        lab.state
            .close_region_command(root, &CancelReason::user("owned H2 test finished"));
        assert!(lab.run_until_idle() < 1024);
        assert_eq!(lab.state.regions_len(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert!(
            lab.state
                .timer_driver_handle()
                .unwrap()
                .next_deadline()
                .is_none()
        );
        assert!(lab.run_until_quiescent_with_report().lab_test_passed());
    }

    #[test]
    fn owned_h2_request_force_close_drains_actual_body_and_descendant() {
        for seed in [0x36_100, 0x36_101, 0x36_102] {
            for parent_cancel in [false, true] {
                owned_h2_force_close_case(seed, parent_cancel);
            }
        }
    }

    fn owned_h2_force_close_case(seed: u64, parent_cancel: bool) {
        use crate::channel::oneshot;
        use crate::lab::{LabConfig, LabRuntime};
        let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(2048));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let signal = ShutdownSignal::new();
        let task_signal = signal.clone();
        let body_cx = Arc::new(parking_lot::Mutex::new(None::<Cx>));
        let identity = Arc::clone(&body_cx);
        let cleanup = Arc::new(AtomicUsize::new(0));
        let entered = Arc::clone(&cleanup);
        let dropped = Arc::new(AtomicUsize::new(0));
        let retired = Arc::clone(&dropped);
        let cancelled = Arc::new(AtomicUsize::new(0));
        let observed_cancel = Arc::clone(&cancelled);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&in_flight);
        let result = Arc::new(parking_lot::Mutex::new(None));
        let published = Arc::clone(&result);
        let (release_body, mut body_cleanup) = oneshot::channel();
        let (release_child, mut child_cleanup) = oneshot::channel();
        let (owner, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let _guard = InFlightRequestGuard::acquire(Some(&counter));
                let completed =
                    run_owned_h2_hop(&cx, &task_signal, owned_hop_config(), move || async move {
                        let cx = Cx::current().expect("actual body context");
                        *identity.lock() = Some(cx.clone());
                        let _drop = OwnedBodyDrop {
                            cx: cx.clone(),
                            dropped: retired,
                            cancelled: observed_cancel,
                        };
                        let child_entered = Arc::clone(&entered);
                        let _descendant = cx
                            .spawn(move |child| async move {
                                let (_sender, mut receiver) = mpsc::channel::<()>(1);
                                assert_eq!(
                                    receiver.recv(&child).await,
                                    Err(mpsc::RecvError::Cancelled)
                                );
                                child_entered.fetch_add(1, Ordering::SeqCst);
                                child_cleanup.recv_uninterruptible().await.unwrap();
                            })
                            .unwrap();
                        let token = cx
                            .try_register_obligation_checked(
                                crate::record::ObligationKind::Lease,
                                cx.task_id(),
                            )
                            .unwrap()
                            .unwrap();
                        assert!(token.commit(), "actual admitted body retains its gateway");
                        let (_sender, mut receiver) = mpsc::channel::<()>(1);
                        assert_eq!(receiver.recv(&cx).await, Err(mpsc::RecvError::Cancelled));
                        entered.fetch_add(1, Ordering::SeqCst);
                        body_cleanup.recv_uninterruptible().await.unwrap();
                        H2DispatchResponse::Buffered(
                            Response::new(200, "OK", b"drained".to_vec()).into_h2_response(),
                        )
                    })
                    .await
                    .unwrap();
                *published.lock() = Some(completed);
            })
            .unwrap();
        lab.scheduler.lock().schedule(owner, 0);
        assert!(lab.run_until_idle() < 2048);
        let body = body_cx.lock().clone().expect("body actually polled");
        assert_ne!(body.task_id(), owner);
        assert_ne!(body.region_id(), root);
        assert_eq!(
            lab.state.task(body.task_id()).unwrap().owner,
            body.region_id()
        );
        assert_eq!(lab.state.tasks_len(), 3);
        if parent_cancel {
            lab.state
                .task(owner)
                .unwrap()
                .cx
                .as_ref()
                .unwrap()
                .cancel_with(CancelKind::User, Some("explicit parent Cx cancellation"));
        } else {
            assert!(signal.begin_drain(Duration::from_nanos(1)));
            assert!(signal.begin_force_close());
        }
        assert!(lab.run_until_idle() < 2048);
        assert_eq!(cleanup.load(Ordering::SeqCst), 2);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert_eq!(in_flight.load(Ordering::SeqCst), 1);
        assert!(result.lock().is_none());
        assert_eq!(lab.run_until_idle(), 0, "cancelled drain really parks");
        release_body.send(()).unwrap();
        assert!(lab.run_until_idle() < 2048);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(cancelled.load(Ordering::SeqCst), 1);
        assert!(
            result.lock().is_none(),
            "body join cannot substitute for descendant close"
        );
        assert_eq!(in_flight.load(Ordering::SeqCst), 1);
        assert_eq!(lab.run_until_idle(), 0);
        release_child.send(()).unwrap();
        assert!(lab.run_until_idle() < 2048);
        if parent_cancel {
            assert!(
                matches!(join.try_join(), Err(JoinError::Cancelled(reason)) if reason.kind == CancelKind::User)
            );
        } else {
            assert_eq!(join.try_join(), Ok(Some(())));
        }
        let completed = result.lock().take().unwrap();
        assert!(matches!(
            completed.hop,
            ServerHopOutcome::Ok(H2DispatchResponse::Buffered(_))
        ));
        assert!(matches!(
            completed.task_outcome,
            Some(Err(JoinError::Cancelled(_)))
        ));
        assert!(!completed.idle_expired);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_owned_h2_terminal_trace(&lab.state.trace_handle().snapshot(), &body, owner);
        finish_owned_h2_lab(&mut lab, root);
    }

    fn assert_owned_h2_terminal_trace(
        events: &[crate::trace::TraceEvent],
        body: &Cx,
        owner: crate::types::TaskId,
    ) {
        use crate::trace::{TraceData, TraceEventKind};
        let terminal = |task| {
            events.iter().filter(|event| {
            event.kind == TraceEventKind::Complete
                && matches!(event.data, TraceData::Task { task: actual, .. } if actual == task)
        }).collect::<Vec<_>>()
        };
        let body_terminal = terminal(body.task_id());
        let owner_terminal = terminal(owner);
        assert_eq!(body_terminal.len(), 1);
        assert_eq!(owner_terminal.len(), 1);
        assert!(
            matches!(body_terminal[0].data, TraceData::Task { region, .. } if region == body.region_id())
        );
        let closed = events.iter().filter(|event| {
            event.kind == TraceEventKind::RegionCloseComplete
                && matches!(event.data, TraceData::Region { region, .. } if region == body.region_id())
        }).collect::<Vec<_>>();
        assert_eq!(closed.len(), 1);
        assert!(body_terminal[0].seq < closed[0].seq);
        assert!(closed[0].seq < owner_terminal[0].seq);
    }

    #[test]
    fn owned_h2_request_shutdown_during_admission_never_starts_factory() {
        use crate::lab::{LabConfig, LabRuntime};
        let mut lab = LabRuntime::new(LabConfig::new(0x36_200).max_steps(1024));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let signal = ShutdownSignal::new();
        let task_signal = signal.clone();
        let invoked = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&invoked);
        let (owner, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let mut hop = Box::pin(run_owned_h2_hop(
                    &cx,
                    &task_signal,
                    owned_hop_config(),
                    move || async move {
                        called.fetch_add(1, Ordering::SeqCst);
                        H2DispatchResponse::Buffered(
                            Response::new(200, "OK", b"forbidden".to_vec()).into_h2_response(),
                        )
                    },
                ));
                std::future::poll_fn(|poll_cx| {
                    assert!(
                        hop.as_mut().poll(poll_cx).is_pending(),
                        "actual opening must await scheduler admission"
                    );
                    Poll::Ready(())
                })
                .await;
                assert!(task_signal.begin_drain(Duration::from_nanos(1)));
                assert!(task_signal.begin_force_close());
                let completed = hop.await.unwrap();
                assert!(matches!(completed.hop, ServerHopOutcome::Cancelled));
                assert!(completed.task_outcome.is_none());
            })
            .unwrap();
        lab.scheduler.lock().schedule(owner, 0);
        assert!(lab.run_until_idle() < 1024);
        assert_eq!(join.try_join(), Ok(Some(())));
        assert_eq!(invoked.load(Ordering::SeqCst), 0);
        assert_eq!(lab.state.live_task_count(), 0);
        let events = lab.state.trace_handle().snapshot();
        let opened = events
            .iter()
            .filter(|event| event.kind == crate::trace::TraceEventKind::RegionCreated)
            .count();
        let closed = events
            .iter()
            .filter(|event| event.kind == crate::trace::TraceEventKind::RegionCloseComplete)
            .count();
        assert_eq!(
            opened, 2,
            "one actual root and one admitted empty request region"
        );
        assert_eq!(closed, 1, "the admitted request is actually closed");
        finish_owned_h2_lab(&mut lab, root);
    }

    #[test]
    fn owned_h2_request_deadline_and_idle_expiry_retire_only_after_grace() {
        use crate::lab::{LabConfig, LabRuntime};
        for idle in [false, true] {
            let mut lab =
                LabRuntime::new(LabConfig::new(0x36_300 + u64::from(idle)).max_steps(1024));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let signal = ShutdownSignal::new();
            let dropped = Arc::new(AtomicUsize::new(0));
            let retired = Arc::clone(&dropped);
            let cancelled = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&cancelled);
            let output = Arc::new(parking_lot::Mutex::new(None));
            let returned = Arc::clone(&output);
            let mut config = owned_hop_config();
            config.drain_grace = Duration::from_nanos(10);
            if idle {
                config.idle_timeout = Some(Duration::from_nanos(100));
            } else {
                config.budget = config.budget.with_deadline(Time::from_nanos(100));
            }
            let (owner, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    let completed = run_owned_h2_hop(&cx, &signal, config, move || async move {
                        let _drop = OwnedBodyDrop {
                            cx: Cx::current().unwrap(),
                            dropped: retired,
                            cancelled: observed,
                        };
                        std::future::pending::<H2DispatchResponse>().await
                    })
                    .await
                    .unwrap();
                    *returned.lock() = Some(completed);
                })
                .unwrap();
            lab.scheduler.lock().schedule(owner, 0);
            assert!(lab.run_until_idle() < 1024);
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            lab.advance_time_to(Time::from_nanos(100));
            assert!(lab.state.timer_driver_handle().unwrap().process_timers() > 0);
            assert!(lab.run_until_idle() < 1024);
            assert!(output.lock().is_none());
            assert_eq!(
                dropped.load(Ordering::SeqCst),
                0,
                "expiry requests cancellation before retiring the body"
            );
            assert_eq!(lab.run_until_idle(), 0, "grace waits on its owned timer");
            lab.advance_time_to(Time::from_nanos(110));
            assert!(lab.state.timer_driver_handle().unwrap().process_timers() > 0);
            assert!(lab.run_until_idle() < 1024);
            assert_eq!(join.try_join(), Ok(Some(())));
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert_eq!(cancelled.load(Ordering::SeqCst), 1);
            let completed = output.lock().take().unwrap();
            assert_eq!(completed.idle_expired, idle);
            assert!(matches!(
                completed.task_outcome,
                Some(Err(JoinError::Cancelled(_)))
            ));
            if idle {
                assert!(matches!(completed.hop, ServerHopOutcome::ConnectionLost));
            } else {
                assert!(matches!(completed.hop, ServerHopOutcome::DeadlineExceeded));
            }
            assert_eq!(lab.state.live_task_count(), 0);
            assert!(
                lab.state
                    .timer_driver_handle()
                    .unwrap()
                    .next_deadline()
                    .is_none()
            );
            finish_owned_h2_lab(&mut lab, root);
        }
    }

    #[test]
    fn owned_h2_request_delayed_join_preserves_strict_idle_deadline_and_exact_boundary() {
        use crate::channel::oneshot;
        use crate::lab::{LabConfig, LabRuntime};

        for completed_at in [100u64, 101] {
            let mut lab = LabRuntime::new(LabConfig::new(0x36_400 + completed_at).max_steps(2048));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let signal = ShutdownSignal::new();
            let allow_coordinator = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let gate = Arc::clone(&allow_coordinator);
            let blocked_polls = Arc::new(AtomicUsize::new(0));
            let blocked = Arc::clone(&blocked_polls);
            let coordinator_waker = Arc::new(parking_lot::Mutex::new(None::<std::task::Waker>));
            let waiter = Arc::clone(&coordinator_waker);
            let body_cx = Arc::new(parking_lot::Mutex::new(None::<Cx>));
            let identity = Arc::clone(&body_cx);
            let dropped = Arc::new(AtomicUsize::new(0));
            let retired = Arc::clone(&dropped);
            let cancelled = Arc::new(AtomicUsize::new(0));
            let cancelled_body = Arc::clone(&cancelled);
            let in_flight = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&in_flight);
            let published = Arc::new(parking_lot::Mutex::new(None));
            let result = Arc::clone(&published);
            let (release, mut body_wait) = oneshot::channel::<()>();
            let mut config = owned_hop_config();
            config.idle_timeout = Some(Duration::from_nanos(100));
            let (owner, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    let _guard = InFlightRequestGuard::acquire(Some(&counter));
                    let mut hop =
                        Box::pin(run_owned_h2_hop(&cx, &signal, config, move || async move {
                            let body = Cx::current().expect("actual admitted body");
                            *identity.lock() = Some(body.clone());
                            let _drop = OwnedBodyDrop {
                                cx: body.clone(),
                                dropped: retired,
                                cancelled: cancelled_body,
                            };
                            body_wait.recv_uninterruptible().await.unwrap();
                            assert_eq!(body.now(), Time::from_nanos(completed_at));
                            H2DispatchResponse::Buffered(
                                Response::new(200, "OK", b"completed body".to_vec())
                                    .into_h2_response(),
                            )
                        }));
                    let completed = std::future::poll_fn(|poll_cx| {
                        if !gate.load(Ordering::SeqCst) {
                            *waiter.lock() = Some(poll_cx.waker().clone());
                            blocked.fetch_add(1, Ordering::SeqCst);
                            return Poll::Pending;
                        }
                        hop.as_mut().poll(poll_cx)
                    })
                    .await
                    .unwrap();
                    *result.lock() = Some(completed);
                })
                .unwrap();
            lab.scheduler.lock().schedule(owner, 0);
            assert!(lab.run_until_idle() < 2048);
            let body = body_cx
                .lock()
                .clone()
                .expect("actual body reached its wait");
            assert_ne!(body.task_id(), owner);
            assert_ne!(body.region_id(), root);
            assert_eq!(
                lab.state.task(body.task_id()).unwrap().owner,
                body.region_id()
            );
            assert_eq!(lab.state.live_task_count(), 2);
            assert_eq!(in_flight.load(Ordering::SeqCst), 1);
            assert!(published.lock().is_none());

            // The real timer wakes the coordinator, but this owned test gate
            // deliberately withholds its next hop poll. The separately
            // scheduled body still runs and reaches its actual terminal.
            allow_coordinator.store(false, Ordering::SeqCst);
            lab.advance_time_to(Time::from_nanos(completed_at));
            assert!(lab.state.timer_driver_handle().unwrap().process_timers() > 0);
            assert!(lab.run_until_idle() < 2048);
            assert!(blocked_polls.load(Ordering::SeqCst) > 0);
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            release.send(()).unwrap();
            assert!(lab.run_until_idle() < 2048);
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert_eq!(cancelled.load(Ordering::SeqCst), 0);
            assert_eq!(
                lab.state.live_task_count(),
                1,
                "only the held coordinator is live"
            );
            assert_eq!(
                lab.state.regions_len(),
                2,
                "request region remains owned before join"
            );
            assert!(published.lock().is_none());
            assert_eq!(in_flight.load(Ordering::SeqCst), 1);
            assert_eq!(join.try_join(), Ok(None));
            let before = lab.state.trace_handle().snapshot();
            assert_eq!(
                before
                    .iter()
                    .filter(|event| event.kind == crate::trace::TraceEventKind::Complete
                        && matches!(event.data, crate::trace::TraceData::Task { task, region }
                    if task == body.task_id() && region == body.region_id()))
                    .count(),
                1
            );
            assert!(!before.iter().any(|event|
                event.kind == crate::trace::TraceEventKind::Complete &&
                matches!(event.data, crate::trace::TraceData::Task { task, .. } if task == owner)));

            allow_coordinator.store(true, Ordering::SeqCst);
            let wake = coordinator_waker
                .lock()
                .take()
                .expect("actual registered coordinator waiter");
            wake.wake();
            assert!(lab.run_until_idle() < 2048);
            assert_eq!(join.try_join(), Ok(Some(())));
            let completed = published.lock().take().unwrap();
            assert_eq!(
                completed.idle_expired,
                completed_at > 100,
                "strict overdue must reject; exactly at the boundary ready work wins"
            );
            assert!(matches!(completed.hop,
                ServerHopOutcome::Ok(H2DispatchResponse::Buffered(response))
                    if response.response.body.as_slice() == b"completed body"));
            assert!(
                matches!(completed.task_outcome, Some(Ok(()))),
                "late join cannot fabricate cancellation of an already completed body"
            );
            assert_eq!(cancelled.load(Ordering::SeqCst), 0);
            assert_eq!(in_flight.load(Ordering::SeqCst), 0);
            assert_owned_h2_terminal_trace(&lab.state.trace_handle().snapshot(), &body, owner);
            finish_owned_h2_lab(&mut lab, root);
        }
    }

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

    async fn panicking_h2_handler(_request: Request) -> H2DispatchResponse {
        panic!("handler exploded")
    }

    fn establish_h2_response_stream(conn: &mut Connection, stream_id: u32, path: &str) {
        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", path),
            (":authority", "produced.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                stream_id,
                request_headers,
                true,
                true,
            )))
            .expect("request HEADERS accepted");
        assert!(matches!(
            received,
            Some(ReceivedFrame::Headers {
                stream_id: received_stream_id,
                ..
            }) if received_stream_id == stream_id
        ));
    }

    #[test]
    fn body_diagnostic_h2_producer_outcomes_preserve_terminal_causes() {
        assert_eq!(
            h2_producer_outcome_diagnostic(Http2ProducerOutcome::Failed),
            Some((
                "ASUP-E510",
                "response producer returned an error or panicked"
            ))
        );
        assert_eq!(
            h2_producer_outcome_diagnostic(Http2ProducerOutcome::DeadlineExceeded),
            Some((
                "ASUP-E501",
                "response producer exhausted its request-region deadline"
            ))
        );
        assert_eq!(
            h2_producer_outcome_diagnostic(Http2ProducerOutcome::ConnectionLost),
            Some(("ASUP-E509", "response producer lost its client connection"))
        );
        assert_eq!(
            h2_producer_outcome_diagnostic(Http2ProducerOutcome::Cancelled),
            None
        );
    }

    #[test]
    fn body_diagnostic_cancelled_outgoing_body_uses_authoritative_hop_cause() {
        crate::test_utils::run_test(|| async {
            for (kind, expected) in [
                (
                    crate::types::CancelKind::Timeout,
                    Http2ProducerOutcome::DeadlineExceeded,
                ),
                (
                    crate::types::CancelKind::ParentCancelled,
                    Http2ProducerOutcome::Cancelled,
                ),
            ] {
                let producer_cx = Cx::for_testing();
                let (inner, mut body) =
                    OutgoingBody::channel_with_capacity(&producer_cx, BodyKind::Chunked, 1);
                let _sender = Http2BodySender {
                    inner,
                    max_frame_bytes: NonZeroUsize::new(8).expect("non-zero frame limit"),
                    terminal: Http2ProducerTerminal::Open,
                };
                producer_cx.cancel_with(kind, Some("causal producer cancellation test"));

                let error = std::future::poll_fn(|task_cx| Pin::new(&mut body).poll_frame(task_cx))
                    .await
                    .expect("cancelled body yields a terminal error")
                    .expect_err("cancelled body frame is not clean EOF");
                assert!(matches!(error, HttpError::BodyCancelled));
                assert_eq!(
                    classify_h2_producer_hop(Some(ServerHopOutcome::Ok(Err(error))), &producer_cx,),
                    expected
                );
            }
        });
    }

    #[test]
    fn body_diagnostic_peer_reset_survives_dispatch_to_produced_start_race() {
        let mut dispatched = HashSet::from([1]);
        let mut peer_reset_before_response = HashSet::new();

        assert!(mark_h2_peer_reset_before_response(
            &mut dispatched,
            &mut peer_reset_before_response,
            1,
        ));
        assert!(!dispatched.contains(&1));
        assert!(peer_reset_before_response.remove(&1));
        assert!(peer_reset_before_response.is_empty());
        assert!(!mark_h2_peer_reset_before_response(
            &mut dispatched,
            &mut peer_reset_before_response,
            1,
        ));
    }

    #[test]
    fn body_diagnostic_h2_write_failures_preserve_transport_vs_encoder_cause() {
        assert_eq!(
            h2_pump_failure_diagnostic(&H2PumpWriteError::Transport(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "peer closed",
            ))),
            Some(WebBodyDiagnostic::ClientAbort)
        );
        assert_eq!(
            h2_pump_failure_diagnostic(&H2PumpWriteError::Encode(H2Error::stream(
                1,
                ErrorCode::InternalError,
                "invalid local response frame",
            ))),
            Some(WebBodyDiagnostic::ResponseProducerFailure)
        );
        assert_eq!(
            h2_pump_failure_diagnostic(&H2PumpWriteError::Encode(H2Error::connection(
                ErrorCode::InternalError,
                "invalid local connection frame",
            ))),
            None
        );
    }

    #[test]
    fn produced_sender_rejects_oversized_data_before_channel_commit() {
        crate::test_utils::run_test(|| async {
            let cx = Cx::current().expect("test runtime installs Cx");
            let (inner, mut body) = OutgoingBody::channel_with_capacity(&cx, BodyKind::Chunked, 1);
            let mut sender = Http2BodySender {
                inner,
                max_frame_bytes: NonZeroUsize::new(3).expect("non-zero limit"),
                terminal: Http2ProducerTerminal::Open,
            };

            let error = sender
                .send_bytes(&cx, crate::bytes::Bytes::from_static(b"four"))
                .await
                .expect_err("oversized DATA must fail before queueing");
            assert!(matches!(
                error,
                HttpError::BodyTooLargeDetailed {
                    actual: 4,
                    limit: 3
                }
            ));
            assert_eq!(sender.total_bytes(), 0);

            std::future::poll_fn(|task_cx| {
                assert!(matches!(
                    Pin::new(&mut body).poll_frame(task_cx),
                    Poll::Pending
                ));
                Poll::Ready(())
            })
            .await;
        });
    }

    #[test]
    fn produced_sender_finish_preserves_trailers_terminal() {
        crate::test_utils::run_test(|| async {
            let cx = Cx::current().expect("test runtime installs Cx");
            let (inner, mut body) = OutgoingBody::channel_with_capacity(&cx, BodyKind::Chunked, 1);
            let mut sender = Http2BodySender {
                inner,
                max_frame_bytes: NonZeroUsize::new(8).expect("non-zero limit"),
                terminal: Http2ProducerTerminal::Open,
            };
            let mut trailers = HeaderMap::new();
            trailers.insert(
                crate::http::body::HeaderName::from_static("x-end"),
                crate::http::body::HeaderValue::from_static("true"),
            );

            sender
                .send_trailers(&cx, trailers)
                .await
                .expect("trailers finish the channel");
            sender
                .finish(&cx)
                .expect("finish remains idempotent after trailers");
            assert_eq!(sender.terminal, Http2ProducerTerminal::Trailers);

            let frame = std::future::poll_fn(|task_cx| Pin::new(&mut body).poll_frame(task_cx))
                .await
                .expect("trailers frame")
                .expect("valid trailers frame");
            assert!(matches!(frame, BodyFrame::Trailers(_)));
            assert!(
                std::future::poll_fn(|task_cx| Pin::new(&mut body).poll_frame(task_cx))
                    .await
                    .is_none(),
                "trailers must be the sole terminal frame"
            );
        });
    }

    #[test]
    fn produced_cancellation_guard_cancels_when_driver_drops_ownership() {
        let producer_cx: Cx = Cx::for_testing();
        assert!(!producer_cx.is_cancel_requested());
        drop(ProducedCancellationGuard::new(producer_cx.clone()));
        assert!(producer_cx.is_cancel_requested());
    }

    #[test]
    fn produced_cancellation_retains_in_flight_until_producer_owner_exits() {
        let channel_cx: Cx = Cx::for_testing();
        let producer_cx: Cx = Cx::for_testing();
        let (_sender, body) =
            OutgoingBody::channel_with_capacity(&channel_cx, BodyKind::Chunked, 1);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let transport_guard = Arc::new(InFlightRequestGuard::acquire(Some(&in_flight)));
        let producer_guard = Arc::clone(&transport_guard);
        let mut produced_bodies = BTreeMap::from([(
            1,
            ActiveProducedBody {
                body,
                cancellation: ProducedCancellationGuard::new(producer_cx),
                guard: Some(transport_guard),
                producer_outcome: None,
                emitted_bytes: 0,
                body_eof: false,
                pending_trailers: None,
                failure_drain_deadline: None,
            },
        )]);
        assert_eq!(in_flight.load(Ordering::Acquire), 1);

        cancel_produced_body(&mut produced_bodies, 1, "test transport cancellation");
        assert!(produced_bodies.is_empty());
        assert_eq!(
            in_flight.load(Ordering::Acquire),
            1,
            "transport cancellation cannot report quiescence while producer ownership remains"
        );

        drop(producer_guard);
        assert_eq!(
            in_flight.load(Ordering::Acquire),
            0,
            "the final producer-task owner releases in-flight accounting"
        );
    }

    #[test]
    fn produced_factory_panic_is_reported_after_start_instead_of_escaping() {
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
            let handler = Arc::new(|_req: Request| async move {
                H2DispatchResponse::Produced(Http2ProducedPlan {
                    response: Response::new(200, "OK", Vec::new()),
                    frame_capacity: NonZeroUsize::MIN,
                    max_frame_bytes: NonZeroUsize::new(8).expect("non-zero limit"),
                    producer: Box::new(|_, _| panic!("producer factory exploded")),
                })
            });

            dispatch_h2_request(
                &mut conn,
                1,
                request_block(&[]),
                Vec::new(),
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
                None,
                false,
            );

            let start = resp_rx
                .recv(&cx)
                .await
                .expect("validated head must be funneled before producer polling");
            assert!(matches!(
                start,
                FunnelItem::ProducedStart { stream_id: 1, .. }
            ));
            let done = resp_rx
                .recv(&cx)
                .await
                .expect("factory panic must become a terminal producer outcome");
            assert!(matches!(
                done,
                FunnelItem::ProducedDone {
                    stream_id: 1,
                    outcome: Http2ProducerOutcome::Failed,
                }
            ));
            drop(start);
        });
    }

    #[test]
    fn produced_head_preserves_authored_status_without_starting_factory() {
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
            let factory_invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let factory_invoked_for_handler = Arc::clone(&factory_invoked);
            let handler = Arc::new(move |_req: Request| {
                let factory_invoked = Arc::clone(&factory_invoked_for_handler);
                async move {
                    H2DispatchResponse::Produced(Http2ProducedPlan {
                        response: Response::new(201, "Created", Vec::new())
                            .with_header("x-produced", "head"),
                        frame_capacity: NonZeroUsize::MIN,
                        max_frame_bytes: NonZeroUsize::new(8).expect("non-zero limit"),
                        producer: Box::new(move |_producer_cx, sender| {
                            factory_invoked.store(true, Ordering::SeqCst);
                            Box::pin(async move { Ok(sender) })
                        }),
                    })
                }
            });
            let headers = vec![
                Header::new(":method", "HEAD"),
                Header::new(":scheme", "https"),
                Header::new(":path", "/produced-head"),
                Header::new(":authority", "example.com"),
            ];

            dispatch_h2_request(
                &mut conn,
                1,
                headers,
                Vec::new(),
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
                None,
                false,
            );

            let item = resp_rx
                .recv(&cx)
                .await
                .expect("HEAD response must be funneled");
            let FunnelItem::Response {
                response,
                guard,
                suppress_response_body,
                ..
            } = item
            else {
                panic!("HEAD must use the body-suppressed buffered path");
            };
            assert_eq!(response.response.status, 201);
            assert!(suppress_response_body);
            assert!(!factory_invoked.load(Ordering::SeqCst));
            assert!(
                resp_rx.try_recv().is_err(),
                "HEAD must not start a producer"
            );
            drop(guard);
        });
    }

    #[test]
    fn produced_body_is_not_polled_until_stream_credit_arrives() {
        crate::test_utils::run_test(|| async {
            let cx = Cx::current().expect("test runtime installs Cx");
            let mut conn = Connection::server(Settings::default());
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                vec![crate::http::h2::frame::Setting::InitialWindowSize(0)],
            )))
            .expect("zero initial stream window accepted");
            expect_settings_ack(&mut conn);
            establish_h2_response_stream(&mut conn, 1, "/credit");
            assert_eq!(conn.available_send_capacity(1), 0);

            let (inner, body) = OutgoingBody::channel_with_capacity(&cx, BodyKind::Chunked, 1);
            let mut sender = Http2BodySender {
                inner,
                max_frame_bytes: NonZeroUsize::new(8).expect("non-zero limit"),
                terminal: Http2ProducerTerminal::Open,
            };
            sender
                .send_bytes(&cx, crate::bytes::Bytes::from_static(b"abc"))
                .await
                .expect("bounded DATA queues in producer channel");
            sender.finish(&cx).expect("producer finishes");

            let mut produced_bodies = BTreeMap::from([(
                1,
                ActiveProducedBody {
                    body,
                    cancellation: ProducedCancellationGuard::new(Cx::for_testing()),
                    guard: Some(Arc::new(InFlightRequestGuard::acquire(None))),
                    producer_outcome: Some(Http2ProducerOutcome::Finished {
                        total_bytes: sender.total_bytes(),
                        terminal: sender.terminal,
                    }),
                    emitted_bytes: 0,
                    body_eof: false,
                    pending_trailers: None,
                    failure_drain_deadline: None,
                },
            )]);
            let mut poll_after = None;
            std::future::poll_fn(|task_cx| {
                assert!(matches!(
                    poll_produced_body_event(&conn, &mut produced_bodies, &mut poll_after, task_cx),
                    Poll::Pending
                ));
                Poll::Ready(())
            })
            .await;

            conn.process_frame(Frame::WindowUpdate(
                crate::http::h2::frame::WindowUpdateFrame::new(1, 3),
            ))
            .expect("stream WINDOW_UPDATE accepted");
            let event = std::future::poll_fn(|task_cx| {
                poll_produced_body_event(&conn, &mut produced_bodies, &mut poll_after, task_cx)
            })
            .await;
            let ProducedBodyEvent::Frame {
                stream_id: 1,
                frame: Ok(BodyFrame::Data(data)),
            } = event
            else {
                panic!("expected one DATA frame after credit arrived");
            };
            assert_eq!(data.get_ref().as_ref(), b"abc");
        });
    }

    #[test]
    fn produced_body_credit_observes_connection_window_exhaustion() {
        let mut conn = Connection::server(Settings::default());
        conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
            vec![crate::http::h2::frame::Setting::InitialWindowSize(100_000)],
        )))
        .expect("larger peer stream window accepted");
        expect_settings_ack(&mut conn);
        establish_h2_response_stream(&mut conn, 1, "/connection-credit");

        conn.send_data(1, crate::bytes::Bytes::from(vec![0_u8; 70_000]), false)
            .expect("DATA queues beyond the connection window");
        let mut emitted = 0_usize;
        while let Some(frame) = conn.next_frame() {
            let Frame::Data(data) = frame else {
                panic!("expected only DATA while draining connection credit");
            };
            emitted += data.data.len();
        }
        assert_eq!(emitted, 65_535);
        assert_eq!(conn.available_send_capacity(1), 0);

        conn.process_frame(Frame::WindowUpdate(
            crate::http::h2::frame::WindowUpdateFrame::new(1, 32),
        ))
        .expect("stream credit update accepted");
        assert_eq!(
            conn.available_send_capacity(1),
            0,
            "stream credit cannot bypass an exhausted connection window"
        );

        conn.process_frame(Frame::WindowUpdate(
            crate::http::h2::frame::WindowUpdateFrame::new(0, 3),
        ))
        .expect("connection credit update accepted");
        assert_eq!(conn.available_send_capacity(1), 3);
    }

    #[test]
    fn produced_empty_eof_queues_one_terminal_frame_and_retains_guard() {
        crate::test_utils::run_test(|| async {
            let cx = Cx::current().expect("test runtime installs Cx");
            let mut conn = Connection::server(Settings::default());
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new(),
            )))
            .expect("peer settings accepted");
            expect_settings_ack(&mut conn);
            establish_h2_response_stream(&mut conn, 1, "/empty");
            conn.send_headers(1, vec![Header::new(":status", "200")], false)
                .expect("produced response head queues");
            assert!(matches!(conn.next_frame(), Some(Frame::Headers(_))));

            let (mut sender, body) = OutgoingBody::channel_with_capacity(&cx, BodyKind::Chunked, 1);
            sender.finish(&cx).expect("empty producer finishes");
            let in_flight = Arc::new(AtomicUsize::new(0));
            let mut produced_bodies = BTreeMap::from([(
                1,
                ActiveProducedBody {
                    body,
                    cancellation: ProducedCancellationGuard::new(Cx::for_testing()),
                    guard: Some(Arc::new(InFlightRequestGuard::acquire(Some(&in_flight)))),
                    producer_outcome: Some(Http2ProducerOutcome::Finished {
                        total_bytes: 0,
                        terminal: Http2ProducerTerminal::Finished,
                    }),
                    emitted_bytes: 0,
                    body_eof: false,
                    pending_trailers: None,
                    failure_drain_deadline: None,
                },
            )]);
            let mut poll_after = None;
            let event = std::future::poll_fn(|task_cx| {
                poll_produced_body_event(&conn, &mut produced_bodies, &mut poll_after, task_cx)
            })
            .await;
            assert!(matches!(event, ProducedBodyEvent::Eof { stream_id: 1 }));
            produced_bodies
                .get_mut(&1)
                .expect("body remains active")
                .body_eof = true;

            let mut response_guards = HashMap::new();
            finalize_produced_body_if_ready(
                &mut conn,
                1,
                &mut produced_bodies,
                &mut response_guards,
            );
            assert!(produced_bodies.is_empty());
            assert_eq!(in_flight.load(Ordering::Acquire), 1);
            assert!(response_guards.contains_key(&1));
            match conn.next_frame().expect("terminal DATA queues") {
                Frame::Data(frame) => {
                    assert!(frame.data.is_empty());
                    assert!(frame.end_stream);
                }
                other => panic!("expected terminal DATA, got {other:?}"),
            }
            release_flushed_response_guards(&conn, &mut response_guards);
            assert!(response_guards.is_empty());
            assert_eq!(in_flight.load(Ordering::Acquire), 0);
            assert!(
                conn.next_frame().is_none(),
                "terminal framing is exactly once"
            );
        });
    }

    #[test]
    fn produced_trailers_queue_one_terminal_headers_frame_after_body_completion() {
        crate::test_utils::run_test(|| async {
            let cx = Cx::current().expect("test runtime installs Cx");
            let mut conn = Connection::server(Settings::default());
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new(),
            )))
            .expect("peer settings accepted");
            expect_settings_ack(&mut conn);
            establish_h2_response_stream(&mut conn, 1, "/produced-trailers");
            conn.send_headers(1, vec![Header::new(":status", "200")], false)
                .expect("produced response head queues");
            assert!(matches!(conn.next_frame(), Some(Frame::Headers(_))));

            let (inner, body) = OutgoingBody::channel_with_capacity(&cx, BodyKind::Chunked, 1);
            let mut sender = Http2BodySender {
                inner,
                max_frame_bytes: NonZeroUsize::new(64).expect("non-zero limit"),
                terminal: Http2ProducerTerminal::Open,
            };
            let mut trailers = HeaderMap::new();
            trailers.insert(
                crate::http::body::HeaderName::from_static("x-final"),
                crate::http::body::HeaderValue::from_static("done"),
            );
            sender
                .send_trailers(&cx, trailers)
                .await
                .expect("trailers queue");
            sender
                .finish(&cx)
                .expect("finish after trailers is idempotent");

            let in_flight = Arc::new(AtomicUsize::new(0));
            let mut produced_bodies = BTreeMap::from([(
                1,
                ActiveProducedBody {
                    body,
                    cancellation: ProducedCancellationGuard::new(Cx::for_testing()),
                    guard: Some(Arc::new(InFlightRequestGuard::acquire(Some(&in_flight)))),
                    producer_outcome: Some(Http2ProducerOutcome::Finished {
                        total_bytes: 0,
                        terminal: sender.terminal,
                    }),
                    emitted_bytes: 0,
                    body_eof: false,
                    pending_trailers: None,
                    failure_drain_deadline: None,
                },
            )]);
            let mut poll_after = None;
            let event = std::future::poll_fn(|task_cx| {
                poll_produced_body_event(&conn, &mut produced_bodies, &mut poll_after, task_cx)
            })
            .await;
            let ProducedBodyEvent::Frame {
                stream_id: 1,
                frame: Ok(BodyFrame::Trailers(trailers)),
            } = event
            else {
                panic!("expected the produced trailing header map");
            };
            produced_bodies
                .get_mut(&1)
                .expect("body remains active until trailers queue")
                .pending_trailers = Some(trailers);

            let mut response_guards = HashMap::new();
            finalize_produced_body_if_ready(
                &mut conn,
                1,
                &mut produced_bodies,
                &mut response_guards,
            );
            assert!(produced_bodies.is_empty());
            assert_eq!(in_flight.load(Ordering::Acquire), 1);
            match conn.next_frame().expect("terminal trailing HEADERS queue") {
                Frame::Headers(headers) => {
                    assert_eq!(headers.stream_id, 1);
                    assert!(headers.end_stream);
                    let mut block = headers.header_block;
                    let decoded = crate::http::h2::HpackDecoder::new()
                        .decode(&mut block)
                        .expect("produced trailers decode");
                    assert_eq!(decoded, vec![Header::new("x-final", "done")]);
                }
                other => panic!("expected terminal trailing HEADERS, got {other:?}"),
            }
            release_flushed_response_guards(&conn, &mut response_guards);
            assert!(response_guards.is_empty());
            assert_eq!(in_flight.load(Ordering::Acquire), 0);
            assert!(
                conn.next_frame().is_none(),
                "trailers terminalize exactly once"
            );
        });
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
                None,
                true,
            );

            let item = resp_rx
                .recv(&cx)
                .await
                .expect("panic response must be sent through funnel");
            let FunnelItem::Response {
                stream_id: response_stream,
                response,
                guard,
                suppress_response_body,
            } = item
            else {
                panic!("expected handler response, got stream timeout");
            };
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
                    H2DispatchResponse::Buffered(
                        Response::new(200, "OK", Vec::new()).into_h2_response(),
                    )
                }
            });

            // request_block carries `:authority example.com:8443` -> host
            // `example.com`, which is NOT on this allow-list.
            dispatch_h2_request(
                &mut conn,
                1,
                request_block(&[]),
                Vec::new(),
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
                None,
                true,
            );

            let item = resp_rx
                .recv(&cx)
                .await
                .expect("421 response must be sent through funnel");
            let FunnelItem::Response {
                stream_id,
                response,
                guard,
                suppress_response_body: _,
            } = item
            else {
                panic!("expected host-rejection response, got stream timeout");
            };
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
                    H2DispatchResponse::Buffered(
                        Response::new(200, "OK", b"hi".to_vec()).into_h2_response(),
                    )
                }
            });

            dispatch_h2_request(
                &mut conn,
                1,
                request_block(&[]),
                Vec::new(),
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
                None,
                true,
            );

            let item = resp_rx
                .recv(&cx)
                .await
                .expect("handler response must be sent through funnel");
            let FunnelItem::Response {
                stream_id,
                response,
                guard,
                suppress_response_body: _,
            } = item
            else {
                panic!("expected handler response, got stream timeout");
            };
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
    fn stream_idle_timeout_drops_handler_and_returns_reset_outcome() {
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
            let handler = Arc::new(|_req: Request| std::future::pending::<H2DispatchResponse>());

            dispatch_h2_request(
                &mut conn,
                1,
                request_block(&[]),
                Vec::new(),
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
                Some(Duration::ZERO),
                true,
            );

            let item = resp_rx
                .recv(&cx)
                .await
                .expect("idle timeout must be sent through funnel");
            let FunnelItem::StreamIdleTimeout { stream_id, guard } = item else {
                panic!("pending handler must produce stream timeout, not a response");
            };
            assert_eq!(stream_id, 1);
            assert_eq!(in_flight.load(Ordering::Acquire), 1);
            drop(guard);
            assert_eq!(in_flight.load(Ordering::Acquire), 0);
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
    fn request_mapping_preserves_trailer_block_separately() {
        let request = request_from_h2_parts(
            request_block(&[("x-trace", "abc")]),
            b"body".to_vec(),
            vec![
                Header::new("x-client-tail", "tail-value"),
                Header::new("x-client-token-bin", "AQI"),
            ],
            None,
        )
        .expect("valid request and trailer blocks");

        assert_eq!(
            request.trailers,
            vec![
                ("x-client-tail".to_owned(), "tail-value".to_owned()),
                ("x-client-token-bin".to_owned(), "AQI".to_owned()),
            ]
        );
        assert!(
            request
                .headers
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("x-client-tail"))
        );
    }

    #[test]
    fn request_mapping_rejects_trailer_pseudo_header() {
        let result = request_from_h2_parts(
            request_block(&[]),
            Vec::new(),
            vec![Header::new(":status", "200")],
            None,
        );
        assert!(result.is_err());
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
