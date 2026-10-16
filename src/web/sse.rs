//! Server-Sent Events (SSE) support.
//!
//! Implements the [SSE protocol](https://html.spec.whatwg.org/multipage/server-sent-events.html)
//! for pushing events from server to client over a long-lived HTTP connection.
//!
//! # Wire Format
//!
//! Each event is a sequence of `field: value\n` lines terminated by a blank
//! line (`\n\n`). Supported fields:
//!
//! - `data:` — event payload (multi-line supported)
//! - `event:` — event type name
//! - `id:` — last event ID for reconnection
//! - `retry:` — reconnection interval in milliseconds
//! - `:` (comment) — keep-alive or ignored data
//!
//! # Example
//!
//! ```
//! use asupersync::web::sse::{SseEvent, Sse};
//!
//! fn handler() -> Sse {
//!     Sse::new(vec![
//!         SseEvent::default().data("hello"),
//!         SseEvent::default().event("ping").data("alive"),
//!     ])
//! }
//! ```

use std::collections::VecDeque;
use std::fmt::{self, Write};
use std::num::NonZeroUsize;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::bytes::Bytes;
use crate::cx::Cx;
use crate::http::h1::codec::HttpError;
use crate::time::{timeout, wall_now};
use crate::http::h1::stream::{OutgoingBodySender, StreamingResponse};
use crate::http::h1::types as h1_types;

use super::response::{IntoResponse, Response, StatusCode};

// ─── SseEvent ────────────────────────────────────────────────────────────────

/// A single Server-Sent Event.
///
/// Build events using the builder methods. At minimum, an event should
/// have a `data` field, though comment-only events are also valid.
///
/// # Wire Format
///
/// ```text
/// event: message
/// id: 42
/// data: Hello, world!
///
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SseEvent {
    /// Event type name (the `event:` field).
    event: Option<String>,
    /// Event data (the `data:` field). Multi-line data is split on `\n`.
    data: Option<String>,
    /// Last event ID (the `id:` field). Must not contain null bytes.
    id: Option<String>,
    /// Reconnection time in milliseconds (the `retry:` field).
    retry: Option<u64>,
    /// Comment lines (each prefixed with `:`).
    comment: Option<String>,
}

impl SseEvent {
    /// Set the event type.
    #[must_use]
    pub fn event(mut self, event: impl Into<String>) -> Self {
        self.event = Some(event.into());
        self
    }

    /// Set the event data.
    ///
    /// Multi-line data is automatically split into multiple `data:` lines
    /// per the SSE specification.
    #[must_use]
    pub fn data(mut self, data: impl Into<String>) -> Self {
        self.data = Some(data.into());
        self
    }

    /// Set the last event ID.
    ///
    /// The ID must not contain null bytes (U+0000). If it does, the ID
    /// is silently ignored per the specification.
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        let id = id.into();
        if !id.contains('\0') {
            self.id = Some(id);
        }
        self
    }

    /// Set the reconnection time in milliseconds.
    #[must_use]
    pub fn retry(mut self, millis: u64) -> Self {
        self.retry = Some(millis);
        self
    }

    /// Set the retry interval from a [`Duration`].
    #[must_use]
    pub fn retry_duration(mut self, duration: Duration) -> Self {
        self.retry = Some(duration.as_millis().min(u128::from(u64::MAX)) as u64);
        self
    }

    /// Add a comment line.
    ///
    /// Comments are prefixed with `:` and are typically used for keep-alive
    /// messages. They are ignored by EventSource clients.
    #[must_use]
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Write this event to the given buffer in SSE wire format.
    fn write_to(&self, buf: &mut String) {
        // Comment lines first.
        // Normalize bare \r to \n the same way the data field does so a
        // comment containing `foo\rdata: injected` cannot be interpreted as
        // a real `data:` field by the WHATWG EventSource parser. Rust's
        // `str::lines()` splits on `\n` and `\r\n` but NOT bare `\r`, so
        // without this normalization a bare carriage return in a comment
        // becomes a wire-format separator and injects whatever follows.
        if let Some(ref comment) = self.comment {
            let normalized = comment.replace("\r\n", "\n").replace('\r', "\n");
            for line in normalized.lines() {
                let _ = writeln!(buf, ":{line}");
            }
        }

        // Event type (sanitize to prevent SSE field injection).
        //
        // br-asupersync-fek81o applies to every field, not just `data`: the
        // WHATWG EventSource parser strips one leading U+0020 SPACE from the
        // value. Prepend a padding space so an app-set leading space in the
        // event name survives (otherwise `.event(" ping")` arrives as "ping").
        if let Some(ref event) = self.event {
            let event = event.replace(['\r', '\n'], "");
            if event.starts_with(' ') {
                let _ = writeln!(buf, "event: {event}");
            } else {
                let _ = writeln!(buf, "event:{event}");
            }
        }

        // Data — each line gets its own `data:` prefix.
        // Normalize bare \r to \n before splitting so the browser's
        // EventSource parser (WHATWG SSE spec) can't interpret a bare
        // \r as a field separator and inject retry:/event:/id: fields.
        //
        // br-asupersync-fek81o: WHATWG HTML §9.2.6 EventSource parser
        // strips one U+0020 SPACE from the start of the field value
        // ("If value starts with a U+0020 SPACE character, remove it
        // from value."). Without compensation, `data(" hello")` would
        // round-trip as "hello" — the application's leading space is
        // silently lost. When a data line starts with a space, prepend
        // an extra padding space so the parser's strip leaves the
        // original value intact. The non-leading-space wire format
        // (`data:hello`) stays unchanged for backward compat with the
        // existing wire-format pin tests.
        if let Some(ref data) = self.data {
            let normalized = data.replace("\r\n", "\n").replace('\r', "\n");
            for line in normalized.split('\n') {
                if line.starts_with(' ') {
                    let _ = writeln!(buf, "data: {line}");
                } else {
                    let _ = writeln!(buf, "data:{line}");
                }
            }
        }

        // ID (sanitize to prevent SSE field injection).
        //
        // Same WHATWG leading-space compensation as `event`/`data`: a stripped
        // leading space would corrupt Last-Event-ID reconnection matching
        // (`.id(" 7")` must not become "7").
        if let Some(ref id) = self.id {
            let id = id.replace(['\r', '\n'], "");
            if id.starts_with(' ') {
                let _ = writeln!(buf, "id: {id}");
            } else {
                let _ = writeln!(buf, "id:{id}");
            }
        }

        // Retry.
        if let Some(millis) = self.retry {
            let _ = writeln!(buf, "retry:{millis}");
        }

        // Terminate with blank line.
        buf.push('\n');
    }
}

impl fmt::Display for SseEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = String::new();
        self.write_to(&mut buf);
        f.write_str(&buf)
    }
}

// ─── Streaming SSE ──────────────────────────────────────────────────────────

/// Error raised while incrementally emitting a streaming SSE response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamingSseError {
    /// The request capability context observed cancellation.
    Cancelled,
    /// One serialized event or heartbeat exceeded the per-chunk byte cap.
    EventTooLarge {
        /// Serialized chunk size in bytes.
        actual: usize,
        /// Configured per-chunk maximum.
        max: usize,
    },
    /// Emitting this event would exceed the per-response event-byte cap.
    TotalBytesExceeded {
        /// Total event bytes that would have been emitted.
        actual: usize,
        /// Configured per-response maximum.
        max: usize,
    },
    /// The event producer failed before yielding the next event.
    Producer(String),
}

impl fmt::Display for StreamingSseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("streaming SSE cancelled"),
            Self::EventTooLarge { actual, max } => {
                write!(
                    f,
                    "streaming SSE event exceeds max bytes ({actual} > {max})"
                )
            }
            Self::TotalBytesExceeded { actual, max } => write!(
                f,
                "streaming SSE events exceed max total bytes ({actual} > {max})"
            ),
            Self::Producer(message) => write!(f, "streaming SSE producer failed: {message}"),
        }
    }
}

impl std::error::Error for StreamingSseError {}

/// Default bounded HTTP/1 body-channel capacity for streaming SSE responses.
pub const DEFAULT_STREAMING_SSE_H1_CHANNEL_CAPACITY: usize = 8;

/// Backpressure policy name recorded by transport proof artifacts.
pub const STREAMING_SSE_H1_BACKPRESSURE_POLICY: &str = "bounded-h1-body-channel";

/// Error raised while draining [`StreamingSse`] into an HTTP/1 body stream.
#[derive(Debug)]
pub enum StreamingSseTransportError {
    /// The SSE source or byte-limit state rejected the next chunk.
    Stream(StreamingSseError),
    /// The HTTP/1 outgoing body channel rejected the chunk or finish signal.
    Transport(HttpError),
}

impl fmt::Display for StreamingSseTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream(error) => write!(f, "streaming SSE source error: {error}"),
            Self::Transport(error) => write!(f, "streaming SSE HTTP/1 transport error: {error}"),
        }
    }
}

impl std::error::Error for StreamingSseTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Stream(error) => Some(error),
            Self::Transport(error) => Some(error),
        }
    }
}

/// Result of one host-driven HTTP/1 streaming drain step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamingSseTransportStep {
    /// One SSE chunk was committed to the HTTP/1 outgoing body channel.
    Sent {
        /// Bytes committed by this chunk.
        bytes: usize,
        /// Total serialized SSE bytes produced by the stream so far.
        total_bytes: usize,
    },
    /// The SSE source completed and the HTTP/1 body sender was finished.
    Complete,
}

/// Incremental producer for [`StreamingSse`].
///
/// Implementations should yield at most one event per call and should not block
/// indefinitely. A transport loop can apply backpressure by delaying the next
/// call to [`StreamingSse::next_chunk`].
pub trait StreamingSseSource {
    /// Return the next event, or `Ok(None)` when the stream is complete.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingSseError::Cancelled`] when `cx` has been cancelled,
    /// or [`StreamingSseError::Producer`] for source-specific failures.
    fn next_event(&mut self, cx: &Cx) -> Result<Option<SseEvent>, StreamingSseError>;

    /// Poll for the next event without blocking (br-asupersync-sse7kp2).
    ///
    /// Returns [`Poll::Ready`] with an event, `Ok(None)` at stream completion,
    /// or an error — same outcomes as [`next_event`](Self::next_event). Returns
    /// [`Poll::Pending`] to indicate "no event yet, keep the stream open"; the
    /// implementation must then register `task_cx`'s waker so the transport is
    /// re-polled when an event becomes available. This is the only signal a
    /// live source has to stay idle-but-open (the synchronous `next_event`'s
    /// `Ok(None)` means *complete*), and it lets the server emit keep-alive
    /// heartbeats during idle and detect a dead peer.
    ///
    /// The default delegates to the blocking [`next_event`](Self::next_event)
    /// and is always `Ready`, so existing sources are unchanged and never idle;
    /// a live source overrides this to return `Pending` while it has no event.
    ///
    /// # Errors
    ///
    /// Same as [`next_event`](Self::next_event).
    fn poll_next_event(
        &mut self,
        cx: &Cx,
        task_cx: &mut Context<'_>,
    ) -> Poll<Result<Option<SseEvent>, StreamingSseError>> {
        let _ = task_cx;
        Poll::Ready(self.next_event(cx))
    }

    /// Cancel producer-side state after request cancellation or disconnect.
    fn cancel(&mut self) {}
}

/// Finite event source for deterministic tests and bounded streaming adapters.
#[derive(Debug, Clone, Default)]
pub struct VecSseSource {
    events: VecDeque<SseEvent>,
}

impl VecSseSource {
    /// Create a source from a finite list of events.
    #[must_use]
    pub fn new(events: Vec<SseEvent>) -> Self {
        Self {
            events: events.into(),
        }
    }

    /// Return the number of events not yet emitted.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.events.len()
    }
}

impl StreamingSseSource for VecSseSource {
    fn next_event(&mut self, cx: &Cx) -> Result<Option<SseEvent>, StreamingSseError> {
        cx.checkpoint().map_err(|_| StreamingSseError::Cancelled)?;
        Ok(self.events.pop_front())
    }

    fn cancel(&mut self) {
        self.events.clear();
    }
}

#[derive(Debug, Clone)]
struct PreparedEventChunk {
    bytes: Vec<u8>,
}

/// Incremental Server-Sent Events response state.
///
/// This is separate from [`Sse`], which remains a finite batch response that
/// materializes one complete HTTP body. `StreamingSse` emits one serialized
/// event or heartbeat chunk per call to [`next_chunk`](Self::next_chunk), checks
/// the request [`Cx`] between chunks, and closes producer state on cancellation.
#[derive(Debug, Clone)]
pub struct StreamingSse<S = VecSseSource> {
    source: S,
    max_event_bytes: usize,
    max_total_bytes: usize,
    /// Event bytes serialized and charged against `max_total_bytes`.
    event_bytes_emitted: usize,
    /// All serialized bytes produced (events plus heartbeats).
    bytes_emitted: usize,
    /// Serialized event retained until a chunk API returns it or H1 commits it.
    pending_event_chunk: Option<PreparedEventChunk>,
    heartbeat_comment: String,
    /// Emit a keep-alive heartbeat when the source produces no event within
    /// this interval; `None` disables idle heartbeats (br-asupersync-sse7kp2).
    heartbeat_interval: Option<Duration>,
    closed: bool,
}

/// A server-owned HTTP/1 response plan for one incremental SSE stream.
///
/// This descriptor deliberately does not expose an [`OutgoingBodySender`].
/// [`crate::http::h1::Http1StreamingServer::serve_sse`] creates the body
/// channel inside the server-owned request lifecycle and supervises both halves
/// until normal EOF, producer failure, cancellation, or client disconnect.
/// That ownership prevents a dropped producer from being mistaken for a clean
/// chunked response terminator.
#[derive(Debug, Clone)]
pub struct Http1SseResponse<S = VecSseSource> {
    // Preserve stream ownership and Drop on browser targets, where the
    // native HTTP/1 server consuming this descriptor is unavailable.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    stream: StreamingSse<S>,
    frame_capacity: NonZeroUsize,
}

impl<S> Http1SseResponse<S> {
    /// Return the bounded number of SSE frames allowed in the body channel.
    #[must_use]
    pub const fn frame_capacity(&self) -> NonZeroUsize {
        self.frame_capacity
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn into_parts(self) -> (StreamingSse<S>, NonZeroUsize) {
        (self.stream, self.frame_capacity)
    }
}

impl StreamingSse<VecSseSource> {
    /// Create a streaming SSE response from a finite event list.
    #[must_use]
    pub fn new(events: Vec<SseEvent>) -> Self {
        Self::from_source(VecSseSource::new(events))
    }

    /// Create an empty streaming SSE response.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }
}

impl<S: StreamingSseSource> StreamingSse<S> {
    /// Create a streaming SSE response from an event source.
    #[must_use]
    pub fn from_source(source: S) -> Self {
        Self {
            source,
            max_event_bytes: DEFAULT_SSE_MAX_TOTAL_BYTES,
            max_total_bytes: DEFAULT_SSE_MAX_TOTAL_BYTES,
            event_bytes_emitted: 0,
            bytes_emitted: 0,
            pending_event_chunk: None,
            heartbeat_comment: "keep-alive".to_string(),
            heartbeat_interval: None,
            closed: false,
        }
    }

    /// Header set required for a streaming SSE HTTP response.
    #[must_use]
    pub const fn headers() -> [(&'static str, &'static str); 3] {
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-cache"),
            ("connection", "keep-alive"),
        ]
    }

    /// Override the maximum serialized bytes for one event or heartbeat chunk.
    #[must_use]
    pub fn max_event_bytes(mut self, max: usize) -> Self {
        self.max_event_bytes = max;
        self
    }

    /// The largest serialized event this stream will emit; the HTTP/1 bridge
    /// sizes its produced-body frame cap from it so a large event is framed
    /// rather than failing the stream.
    #[must_use]
    pub fn event_bytes_limit(&self) -> usize {
        self.max_event_bytes
    }

    /// Override the maximum total event bytes emitted by this response.
    ///
    /// Server-authored heartbeat comments remain subject to
    /// [`Self::max_event_bytes`] but do not consume this event-volume budget.
    #[must_use]
    pub fn max_total_bytes(mut self, max: usize) -> Self {
        self.max_total_bytes = max;
        self
    }

    /// Override the heartbeat comment payload.
    #[must_use]
    pub fn heartbeat_comment(mut self, comment: impl Into<String>) -> Self {
        self.heartbeat_comment = comment.into();
        self
    }

    /// Emit a keep-alive heartbeat comment when the source yields no event
    /// within `interval` (br-asupersync-sse7kp2).
    ///
    /// This only takes effect for a source that overrides
    /// [`StreamingSseSource::poll_next_event`] to return [`Poll::Pending`] while
    /// idle; a source using the default (blocking) `next_event` never reports an
    /// idle moment, so no heartbeat is emitted regardless of this setting.
    /// `None` (the default) disables idle heartbeats: the live step then waits
    /// for the source's next event however long it idles.
    #[must_use]
    pub fn heartbeat_interval(mut self, interval: Option<Duration>) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// Convert this source into a server-supervised live HTTP/1 SSE response.
    ///
    /// The capacity bounds queued frames. Each SSE event is independently
    /// bounded by [`Self::max_event_bytes`], so this is not a claim that an
    /// arbitrary HTTP body channel has a byte-count limit. The server owns
    /// response framing, cancellation, and the normal-EOF terminator.
    #[must_use]
    pub fn into_http1_response(self, frame_capacity: NonZeroUsize) -> Http1SseResponse<S> {
        Http1SseResponse {
            stream: self,
            frame_capacity,
        }
    }

    /// Return total serialized bytes produced by the chunk APIs so far.
    ///
    /// This includes both client-visible events and server-authored heartbeat
    /// comments.
    #[must_use]
    pub const fn bytes_emitted(&self) -> usize {
        self.bytes_emitted
    }

    /// Return `true` once the source is complete or cancellation closed it.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Mark the stream closed and cancel the request context for disconnect.
    pub fn cancel_for_disconnect(&mut self, cx: &Cx) {
        self.cancel_source();
        cx.set_cancel_requested(true);
    }

    /// Release producer-side state when the server suppresses or abandons a
    /// response before transport ownership begins.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn cancel_for_server_abort(&mut self) {
        self.cancel_source();
    }

    /// Build the HTTP/1 chunked response head and body sender for this stream.
    ///
    /// The caller owns the host loop: repeatedly call
    /// [`send_next_h1_chunk`](Self::send_next_h1_chunk), flush the transport
    /// after each committed chunk, and call
    /// [`cancel_for_disconnect`](Self::cancel_for_disconnect) when the client
    /// disconnects. This keeps `StreamingSse` out of the synchronous
    /// [`IntoResponse`] path while still using the real HTTP/1 streaming body
    /// primitives that a host/server transport consumes.
    #[must_use]
    pub fn h1_chunked_response(
        &self,
        cx: &Cx,
        capacity: usize,
    ) -> (StreamingResponse, OutgoingBodySender) {
        let (mut response, sender) = StreamingResponse::chunked(
            cx,
            capacity,
            StatusCode::OK.as_u16(),
            h1_types::default_reason(StatusCode::OK.as_u16()),
        );
        response.head.headers.reserve(Self::headers().len());
        for (name, value) in Self::headers() {
            response
                .head
                .headers
                .push((name.to_string(), value.to_string()));
        }
        (response, sender)
    }

    /// Commit one SSE event chunk to an HTTP/1 outgoing body channel.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingSseTransportError::Stream`] for SSE source,
    /// cancellation, or byte-limit errors. Returns
    /// [`StreamingSseTransportError::Transport`] when the HTTP/1 outgoing body
    /// rejects the write; body cancellation or closure is reflected back into
    /// the request [`Cx`] through [`cancel_for_disconnect`](Self::cancel_for_disconnect).
    pub async fn send_next_h1_chunk(
        &mut self,
        cx: &Cx,
        sender: &mut OutgoingBodySender,
    ) -> Result<StreamingSseTransportStep, StreamingSseTransportError> {
        if !self
            .prepare_next_event_chunk(cx)
            .map_err(StreamingSseTransportError::Stream)?
        {
            sender
                .finish(cx)
                .map_err(StreamingSseTransportError::Transport)?;
            return Ok(StreamingSseTransportStep::Complete);
        }

        // The send future owns its copy while the authoritative prepared
        // event stays in `self` for cancellation-safe retry.
        let body_bytes = Bytes::copy_from_slice(
            &self
                .pending_event_chunk
                .as_ref()
                .expect("prepared event remains pending until H1 commit")
                .bytes,
        );
        let bytes = body_bytes.len();
        match sender.send_bytes(cx, body_bytes).await {
            Ok(()) => {
                let committed = self.commit_pending_event();
                debug_assert_eq!(committed.len(), bytes);
                Ok(StreamingSseTransportStep::Sent {
                    bytes,
                    total_bytes: self.bytes_emitted,
                })
            }
            Err(error) => Err(self.handle_h1_transport_error(cx, error)),
        }
    }

    /// Send the next SSE event, or a keep-alive heartbeat if the source yields
    /// no event within `heartbeat_interval` (br-asupersync-sse7kp2).
    ///
    /// Races the source's non-blocking
    /// [`poll_next_event`](StreamingSseSource::poll_next_event) against a
    /// heartbeat deadline: an event commits as usual; stream completion
    /// finishes the body; a source with no event within the interval emits one
    /// heartbeat comment and returns so the caller can loop. A source using the
    /// default (blocking) `poll_next_event` is always `Ready`, so it behaves
    /// like [`send_next_h1_chunk`](Self::send_next_h1_chunk) and never triggers
    /// the heartbeat branch.
    ///
    /// # Errors
    ///
    /// As [`send_next_h1_chunk`](Self::send_next_h1_chunk) /
    /// [`send_h1_heartbeat`](Self::send_h1_heartbeat).
    pub async fn send_next_h1_chunk_with_heartbeat(
        &mut self,
        cx: &Cx,
        sender: &mut OutgoingBodySender,
        heartbeat_interval: Duration,
    ) -> Result<StreamingSseTransportStep, StreamingSseTransportError> {
        let now = cx
            .timer_driver()
            .map_or_else(wall_now, |timer| timer.now());
        let prepared = timeout(
            now,
            heartbeat_interval,
            std::future::poll_fn(|task_cx| self.poll_prepare_next_event_chunk(cx, task_cx)),
        )
        .await;

        match prepared {
            // No event within the interval → keep-alive heartbeat.
            Err(_elapsed) => self.send_h1_heartbeat(cx, sender).await,
            Ok(prepared) => self.send_prepared_h1_chunk(cx, sender, prepared).await,
        }
    }

    /// Finish the body at stream completion, or commit the prepared event
    /// (as [`send_next_h1_chunk`](Self::send_next_h1_chunk) commits it).
    async fn send_prepared_h1_chunk(
        &mut self,
        cx: &Cx,
        sender: &mut OutgoingBodySender,
        prepared: Result<bool, StreamingSseError>,
    ) -> Result<StreamingSseTransportStep, StreamingSseTransportError> {
        match prepared {
            // Stream complete.
            Ok(false) => {
                sender
                    .finish(cx)
                    .map_err(StreamingSseTransportError::Transport)?;
                Ok(StreamingSseTransportStep::Complete)
            }
            // Source error.
            Err(error) => Err(StreamingSseTransportError::Stream(error)),
            // Event prepared → commit it.
            Ok(true) => {
                let body_bytes = Bytes::copy_from_slice(
                    &self
                        .pending_event_chunk
                        .as_ref()
                        .expect("prepared event remains pending until H1 commit")
                        .bytes,
                );
                let bytes = body_bytes.len();
                match sender.send_bytes(cx, body_bytes).await {
                    Ok(()) => {
                        let committed = self.commit_pending_event();
                        debug_assert_eq!(committed.len(), bytes);
                        Ok(StreamingSseTransportStep::Sent {
                            bytes,
                            total_bytes: self.bytes_emitted,
                        })
                    }
                    Err(error) => Err(self.handle_h1_transport_error(cx, error)),
                }
            }
        }
    }

    /// One live host-loop step, the one the HTTP/1 server's SSE loop runs.
    ///
    /// It pulls the source through its non-blocking
    /// [`poll_next_event`](StreamingSseSource::poll_next_event), so a live
    /// source that returns `Pending` while idle stays open without holding a
    /// worker thread. With `heartbeat_interval` set, an idle interval emits a
    /// keep-alive heartbeat (see
    /// [`send_next_h1_chunk_with_heartbeat`](Self::send_next_h1_chunk_with_heartbeat));
    /// without it, the step waits for the next event. A source that does not
    /// override `poll_next_event` is pulled through `next_event`, exactly as
    /// [`send_next_h1_chunk`](Self::send_next_h1_chunk) pulls it
    /// (br-asupersync-sse7kp2, br-asupersync-a1q12q).
    ///
    /// # Errors
    ///
    /// As [`send_next_h1_chunk`](Self::send_next_h1_chunk).
    pub async fn send_next_h1_chunk_live(
        &mut self,
        cx: &Cx,
        sender: &mut OutgoingBodySender,
    ) -> Result<StreamingSseTransportStep, StreamingSseTransportError> {
        match self.heartbeat_interval {
            Some(interval) => {
                self.send_next_h1_chunk_with_heartbeat(cx, sender, interval)
                    .await
            }
            None => {
                let prepared =
                    std::future::poll_fn(|task_cx| self.poll_prepare_next_event_chunk(cx, task_cx))
                        .await;
                self.send_prepared_h1_chunk(cx, sender, prepared).await
            }
        }
    }

    /// Commit one heartbeat/comment chunk to an HTTP/1 outgoing body channel.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingSseTransportError::Stream`] for cancellation or an
    /// oversized heartbeat, and [`StreamingSseTransportError::Transport`] when
    /// the HTTP/1 outgoing body rejects the write.
    pub async fn send_h1_heartbeat(
        &mut self,
        cx: &Cx,
        sender: &mut OutgoingBodySender,
    ) -> Result<StreamingSseTransportStep, StreamingSseTransportError> {
        // Do not write a heartbeat after the stream has completed. Writing
        // into the finished channel would turn a clean completion into a
        // disconnect cancellation.
        let Some(chunk) = self
            .prepare_heartbeat_chunk(cx)
            .map_err(StreamingSseTransportError::Stream)?
        else {
            return Ok(StreamingSseTransportStep::Complete);
        };
        let bytes = chunk.len();
        match sender.send_bytes(cx, Bytes::from(chunk)).await {
            Ok(()) => {
                self.commit_heartbeat(bytes);
                Ok(StreamingSseTransportStep::Sent {
                    bytes,
                    total_bytes: self.bytes_emitted,
                })
            }
            Err(error) => Err(self.handle_h1_transport_error(cx, error)),
        }
    }

    /// Emit one serialized event chunk.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingSseError::Cancelled`] when `cx` has been cancelled,
    /// [`StreamingSseError::EventTooLarge`] when the next event exceeds
    /// `max_event_bytes`, [`StreamingSseError::TotalBytesExceeded`] when event
    /// volume would exceed `max_total_bytes`, or producer-specific errors from
    /// the configured [`StreamingSseSource`].
    pub fn next_chunk(&mut self, cx: &Cx) -> Result<Option<Vec<u8>>, StreamingSseError> {
        if !self.prepare_next_event_chunk(cx)? {
            return Ok(None);
        }
        Ok(Some(self.commit_pending_event()))
    }

    /// Emit one heartbeat/comment chunk without advancing the event source.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingSseError::Cancelled`] on cancellation and
    /// [`StreamingSseError::EventTooLarge`] when the heartbeat exceeds the
    /// per-chunk cap. Heartbeats do not consume `max_total_bytes` and therefore
    /// do not return [`StreamingSseError::TotalBytesExceeded`].
    pub fn heartbeat_chunk(&mut self, cx: &Cx) -> Result<Vec<u8>, StreamingSseError> {
        let Some(chunk) = self.prepare_heartbeat_chunk(cx)? else {
            return Ok(Vec::new());
        };
        self.commit_heartbeat(chunk.len());
        Ok(chunk)
    }

    fn prepare_next_event_chunk(&mut self, cx: &Cx) -> Result<bool, StreamingSseError> {
        if self.closed {
            return Ok(false);
        }
        self.checkpoint(cx)?;
        if let Some(pending) = self.pending_event_chunk.as_ref() {
            // Consuming builder methods can lower caps after a Pending send
            // future is dropped, so retry must honor the current policy.
            self.validate_event_chunk_len(pending.bytes.len())?;
            return Ok(true);
        }

        match self.source.next_event(cx) {
            Ok(Some(event)) => {
                self.pending_event_chunk = Some(self.serialize_event(&event)?);
                Ok(true)
            }
            Ok(None) => {
                self.closed = true;
                Ok(false)
            }
            Err(StreamingSseError::Cancelled) => {
                self.cancel_source();
                Err(StreamingSseError::Cancelled)
            }
            Err(error) => Err(error),
        }
    }

    /// Poll variant of [`prepare_next_event_chunk`](Self::prepare_next_event_chunk)
    /// using the source's non-blocking [`StreamingSseSource::poll_next_event`]
    /// (br-asupersync-sse7kp2). `Ready(Ok(true))` prepared an event,
    /// `Ready(Ok(false))` is stream completion, `Pending` means the source has
    /// no event yet (and registered `task_cx`'s waker).
    fn poll_prepare_next_event_chunk(
        &mut self,
        cx: &Cx,
        task_cx: &mut Context<'_>,
    ) -> Poll<Result<bool, StreamingSseError>> {
        if self.closed {
            return Poll::Ready(Ok(false));
        }
        if let Err(error) = self.checkpoint(cx) {
            return Poll::Ready(Err(error));
        }
        if let Some(pending) = self.pending_event_chunk.as_ref() {
            // Honor a cap lowered while a prior send future was pending, exactly
            // as the blocking prepare does.
            return Poll::Ready(self.validate_event_chunk_len(pending.bytes.len()).map(|()| true));
        }

        match self.source.poll_next_event(cx, task_cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Some(event))) => match self.serialize_event(&event) {
                Ok(chunk) => {
                    self.pending_event_chunk = Some(chunk);
                    Poll::Ready(Ok(true))
                }
                Err(error) => Poll::Ready(Err(error)),
            },
            Poll::Ready(Ok(None)) => {
                self.closed = true;
                Poll::Ready(Ok(false))
            }
            Poll::Ready(Err(StreamingSseError::Cancelled)) => {
                self.cancel_source();
                Poll::Ready(Err(StreamingSseError::Cancelled))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }

    fn prepare_heartbeat_chunk(&mut self, cx: &Cx) -> Result<Option<Vec<u8>>, StreamingSseError> {
        if self.closed {
            return Ok(None);
        }
        self.checkpoint(cx)?;
        let heartbeat = SseEvent::default().comment(self.heartbeat_comment.clone());
        self.serialize_event_uncharged(&heartbeat).map(Some)
    }

    fn checkpoint(&mut self, cx: &Cx) -> Result<(), StreamingSseError> {
        if cx.checkpoint().is_err() {
            self.cancel_source();
            return Err(StreamingSseError::Cancelled);
        }
        Ok(())
    }

    fn cancel_source(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.pending_event_chunk = None;
        self.source.cancel();
    }

    /// Serializes an event and enforces the per-event size cap, without
    /// touching the cumulative `max_total_bytes` budget. Used for
    /// server-authored keep-alive heartbeats, which are transport framing, not
    /// client-visible stream content, and so must not count toward (or be torn
    /// down by) the total-bytes cap.
    fn serialize_event_uncharged(&self, event: &SseEvent) -> Result<Vec<u8>, StreamingSseError> {
        let mut chunk = String::new();
        event.write_to(&mut chunk);
        let chunk_len = chunk.len();
        if chunk_len > self.max_event_bytes {
            return Err(StreamingSseError::EventTooLarge {
                actual: chunk_len,
                max: self.max_event_bytes,
            });
        }
        Ok(chunk.into_bytes())
    }

    fn serialize_event(&self, event: &SseEvent) -> Result<PreparedEventChunk, StreamingSseError> {
        let chunk = self.serialize_event_uncharged(event)?;
        self.validate_event_chunk_len(chunk.len())?;
        Ok(PreparedEventChunk { bytes: chunk })
    }

    fn validate_event_chunk_len(&self, chunk_len: usize) -> Result<(), StreamingSseError> {
        if chunk_len > self.max_event_bytes {
            return Err(StreamingSseError::EventTooLarge {
                actual: chunk_len,
                max: self.max_event_bytes,
            });
        }
        let next_event_total = self.event_bytes_emitted.saturating_add(chunk_len);
        if next_event_total > self.max_total_bytes {
            return Err(StreamingSseError::TotalBytesExceeded {
                actual: next_event_total,
                max: self.max_total_bytes,
            });
        }

        Ok(())
    }

    fn commit_pending_event(&mut self) -> Vec<u8> {
        let pending = self
            .pending_event_chunk
            .take()
            .expect("prepared event must exist before commit");
        self.event_bytes_emitted = self.event_bytes_emitted.saturating_add(pending.bytes.len());
        self.bytes_emitted = self.bytes_emitted.saturating_add(pending.bytes.len());
        pending.bytes
    }

    fn commit_heartbeat(&mut self, bytes: usize) {
        self.bytes_emitted = self.bytes_emitted.saturating_add(bytes);
    }

    fn handle_h1_transport_error(
        &mut self,
        cx: &Cx,
        error: HttpError,
    ) -> StreamingSseTransportError {
        if matches!(
            error,
            HttpError::BodyCancelled | HttpError::BodyChannelClosed
        ) {
            self.cancel_for_disconnect(cx);
        }
        StreamingSseTransportError::Transport(error)
    }
}

// ─── Sse Response ────────────────────────────────────────────────────────────

/// An SSE response containing a sequence of events.
///
/// Wraps a collection of [`SseEvent`]s and serializes them as a
/// `text/event-stream` response body. Implements [`IntoResponse`] for
/// direct use as a handler return type.
///
/// # Keep-Alive
///
/// Use [`Sse::keep_alive`] to prepend a comment-based keep-alive event
/// that prevents proxies from closing idle connections.
///
/// # Example
///
/// ```
/// use asupersync::web::sse::{SseEvent, Sse};
///
/// fn handler() -> Sse {
///     Sse::new(vec![
///         SseEvent::default().event("update").data("{\"count\": 1}"),
///         SseEvent::default().event("update").data("{\"count\": 2}"),
///     ])
///     .keep_alive()
/// }
/// ```
/// Default cap on serialized SSE response size — 16 MiB.
///
/// Defends against a misbehaving handler that derives event count or
/// per-event payload from attacker-controlled input. Override with
/// [`Sse::max_total_bytes`] for legitimate use cases that need larger
/// responses; the cap is per-response, not per-connection. The single-shot
/// non-streaming serialization in [`IntoResponse`] is kept for bounded batch
/// responses; use [`StreamingSse`] when a handler needs incremental chunks that
/// checkpoint request cancellation between emits (br-asupersync-o74l7u.1).
pub const DEFAULT_SSE_MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;

/// Default cap on event count per response — 100 000. Same defensive
/// rationale as [`DEFAULT_SSE_MAX_TOTAL_BYTES`].
pub const DEFAULT_SSE_MAX_EVENTS: usize = 100_000;

/// SSE response: a list of events serialized to the SSE wire format and
/// emitted as a single HTTP response body (see module-header for limits).
#[derive(Debug, Clone)]
pub struct Sse {
    events: Vec<SseEvent>,
    keep_alive: bool,
    max_events: usize,
    max_total_bytes: usize,
}

impl Sse {
    /// Create an SSE response from a list of events.
    #[must_use]
    pub fn new(events: Vec<SseEvent>) -> Self {
        Self {
            events,
            keep_alive: false,
            max_events: DEFAULT_SSE_MAX_EVENTS,
            max_total_bytes: DEFAULT_SSE_MAX_TOTAL_BYTES,
        }
    }

    /// Create an empty SSE response.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Create an SSE response from a single event.
    #[must_use]
    pub fn event(event: SseEvent) -> Self {
        Self::new(vec![event])
    }

    /// Enable keep-alive by prepending a comment event.
    #[must_use]
    pub fn keep_alive(mut self) -> Self {
        self.keep_alive = true;
        self
    }

    /// Override the per-response cap on event count (default
    /// [`DEFAULT_SSE_MAX_EVENTS`]). Exceeding the cap on response yields
    /// `413 Payload Too Large` instead of a serialized stream
    /// (br-asupersync-tamnew).
    #[must_use]
    pub fn max_events(mut self, max: usize) -> Self {
        self.max_events = max;
        self
    }

    /// Override the per-response cap on serialized byte size (default
    /// [`DEFAULT_SSE_MAX_TOTAL_BYTES`]). Exceeding the cap yields
    /// `413 Payload Too Large` (br-asupersync-tamnew).
    #[must_use]
    pub fn max_total_bytes(mut self, max: usize) -> Self {
        self.max_total_bytes = max;
        self
    }

    /// Serialize all events to the SSE wire format.
    #[must_use]
    pub fn to_body(&self) -> String {
        let mut body = String::new();

        // Keep-alive comment.
        if self.keep_alive {
            body.push_str(":keep-alive\n\n");
        }

        // Serialize each event.
        for event in &self.events {
            event.write_to(&mut body);
        }

        body
    }

    /// Return the number of events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Return `true` if there are no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl IntoResponse for Sse {
    fn into_response(self) -> Response {
        // Defensive caps — see DEFAULT_SSE_MAX_EVENTS / DEFAULT_SSE_MAX_TOTAL_BYTES
        // (br-asupersync-tamnew). Exceeding either cap yields 413 Payload
        // Too Large with a brief error body.
        if self.events.len() > self.max_events {
            return Response::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "SSE response exceeds max_events ({} > {})",
                    self.events.len(),
                    self.max_events
                )
                .into_bytes(),
            )
            .header("content-type", "text/plain");
        }
        let body = self.to_body();
        if body.len() > self.max_total_bytes {
            return Response::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "SSE response body exceeds max_total_bytes ({} > {})",
                    body.len(),
                    self.max_total_bytes
                )
                .into_bytes(),
            )
            .header("content-type", "text/plain");
        }
        Response::new(StatusCode::OK, body.into_bytes())
            .header("content-type", "text/event-stream")
            .header("cache-control", "no-cache")
            .header("connection", "keep-alive")
    }
}

impl IntoResponse for SseEvent {
    fn into_response(self) -> Response {
        Sse::event(self).into_response()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "sse_inline_tests.rs"]
mod tests;
