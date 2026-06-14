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
use crate::http::h1::types::{Method, Request, Response, Version};
use crate::http::h2::connection::{CLIENT_PREFACE, Connection, FrameCodec, ReceivedFrame};
use crate::http::h2::error::{ErrorCode, H2Error};
use crate::http::h2::frame::Frame;
use crate::http::h2::hpack::Header;
use crate::http::h2::settings::Settings;
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

/// Map a handler [`Response`] to an h2 response header block.
///
/// Emits `:status` first (RFC 9113 §8.3.2), lowercases field names (h2
/// field names are lowercase on the wire), and strips connection-specific
/// h1 headers that MUST NOT appear in h2 messages (RFC 9113 §8.2.2),
/// including any `te` value other than `trailers`.
pub(crate) fn h2_headers_from_response(response: &Response) -> Vec<Header> {
    let mut out = Vec::with_capacity(response.headers.len() + 1);
    out.push(Header::new(":status", response.status.to_string()));
    for (name, value) in &response.headers {
        let lowered = name.to_ascii_lowercase();
        if CONNECTION_SPECIFIC_HEADERS.contains(&lowered.as_str()) {
            continue;
        }
        if lowered == "te" && !value.eq_ignore_ascii_case("trailers") {
            continue;
        }
        out.push(Header::new(lowered, value.clone()));
    }
    out
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
    let push_outcomes = queue_h2_server_pushes(conn, stream_id, &response.pushes);

    let header_block = h2_headers_from_response(&response.response);
    let body = std::mem::take(&mut response.response.body);
    let end_stream = body.is_empty();
    let mut queued_response = false;
    if conn
        .send_headers(stream_id, header_block, end_stream)
        .is_ok()
    {
        queued_response = true;
        if !end_stream {
            let _ = conn.send_data(stream_id, crate::bytes::Bytes::from(body), true);
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
    let mut outcomes = Vec::with_capacity(pushes.len());
    for push in pushes {
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

        let mut pushed_response = push.response.clone();
        let header_block = h2_headers_from_response(&pushed_response);
        let body = std::mem::take(&mut pushed_response.body);
        let end_stream = body.is_empty();
        if let Err(err) = conn.send_headers(promised_stream_id, header_block, end_stream) {
            conn.reset_stream(promised_stream_id, err.code);
            outcomes.push(Http2PushOutcome::NotPushed {
                associated_stream_id,
                reason: classify_push_rejection(&err),
            });
            continue;
        }
        if !end_stream
            && let Err(err) =
                conn.send_data(promised_stream_id, crate::bytes::Bytes::from(body), true)
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
    let spawned = runtime.try_spawn(async move {
        let Some(cx) = Cx::current() else {
            drop(guard);
            return;
        };
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
        let response = match handler_result {
            Ok(response) => response.into_h2_response(),
            Err(payload) => {
                // Match h1's panic isolation contract: the connection driver
                // survives the handler panic and completes the stream with a
                // deterministic 500 instead of leaving it active forever.
                let _ = &payload;
                error!(
                    message = %crate::cx::scope::payload_to_string(&payload),
                    "h2 handler task panicked"
                );
                Response::new(500, "Internal Server Error", Vec::new()).into_h2_response()
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
#[allow(clippy::too_many_lines)]
async fn serve_h2_connection<F, Fut, R>(
    mut stream: TcpStream,
    peer_addr: Option<SocketAddr>,
    handler: Arc<F>,
    settings: Settings,
    shutdown_signal: ShutdownSignal,
    in_flight_requests: Arc<AtomicUsize>,
    runtime: RuntimeHandle,
    max_body_size: usize,
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

    let mut conn = Connection::server(settings);
    conn.queue_initial_settings();
    let mut framed = Framed::new(stream, FrameCodec::new());

    let (resp_tx, mut resp_rx) = mpsc::channel::<FunnelItem>(RESPONSE_FUNNEL_CAPACITY);
    // Per-stream request assembly: headers arrive first, DATA accumulates
    // until END_STREAM completes the request.
    let mut pending_requests: HashMap<u32, (Vec<Header>, Vec<u8>)> = HashMap::new();
    // Fixed stage-2 GOAWAY deadline, armed once when stage-1 is outstanding.
    let mut finalize_at: Option<Time> = None;
    let mut response_guards: HashMap<u32, InFlightRequestGuard> = HashMap::new();

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
        // Arm the stage-2 finalize deadline once, when the stage-1 GOAWAY is
        // outstanding; keep it fixed across loop iterations so active traffic
        // cannot reset the window.
        if conn.graceful_shutdown_pending() {
            if finalize_at.is_none() {
                let now = Cx::current()
                    .and_then(|cx| cx.timer_driver())
                    .map_or_else(crate::time::wall_now, |timer| timer.now());
                finalize_at = Some(now + DRAIN_SUPERVISION_TICK);
            }
        } else {
            finalize_at = None;
        }
        let event = next_driver_event(
            &mut framed,
            &mut resp_rx,
            &task_cx,
            &shutdown_signal,
            watch_drain,
            finalize_at,
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
                        );
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
                        );
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
                                );
                            }
                        }
                    }
                }
                Ok(Some(ReceivedFrame::Reset { stream_id, .. })) => {
                    pending_requests.remove(&stream_id);
                }
                Ok(_) => {}
            },
            DriverEvent::Response((stream_id, response, guard, suppress_response_body)) => {
                queue_h2_response(
                    &mut conn,
                    stream_id,
                    response,
                    guard,
                    suppress_response_body,
                    &mut response_guards,
                );
            }
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
        let block = h2_headers_from_response(&response);
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
        let block = h2_headers_from_response(&response);
        assert_eq!(block.len(), 2);
        assert_eq!(block[1], Header::new("te", "trailers"));
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

        let block = h2_headers_from_response(&response);
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
