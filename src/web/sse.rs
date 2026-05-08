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
//! ```ignore
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
use std::time::Duration;

use crate::cx::Cx;
use crate::http::h1::codec::HttpError;
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
        if let Some(ref event) = self.event {
            let event = event.replace(['\r', '\n'], "");
            let _ = writeln!(buf, "event:{event}");
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
        if let Some(ref id) = self.id {
            let id = id.replace(['\r', '\n'], "");
            let _ = writeln!(buf, "id:{id}");
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
    /// Emitting this chunk would exceed the per-response byte cap.
    TotalBytesExceeded {
        /// Total bytes that would have been emitted.
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
                "streaming SSE response exceeds max total bytes ({actual} > {max})"
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
        /// Total SSE bytes committed by the stream so far.
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
    bytes_emitted: usize,
    heartbeat_comment: String,
    closed: bool,
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
            bytes_emitted: 0,
            heartbeat_comment: "keep-alive".to_string(),
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

    /// Override the maximum total bytes emitted by this streaming response.
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

    /// Return the number of serialized bytes emitted so far.
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
        self.closed = true;
        self.source.cancel();
        cx.set_cancel_requested(true);
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
        let Some(chunk) = self
            .next_chunk(cx)
            .map_err(StreamingSseTransportError::Stream)?
        else {
            sender
                .finish(cx)
                .map_err(StreamingSseTransportError::Transport)?;
            return Ok(StreamingSseTransportStep::Complete);
        };

        self.send_h1_bytes(cx, sender, &chunk).await
    }

    /// Commit one heartbeat/comment chunk to an HTTP/1 outgoing body channel.
    ///
    /// # Errors
    ///
    /// Returns the same errors as
    /// [`send_next_h1_chunk`](Self::send_next_h1_chunk).
    pub async fn send_h1_heartbeat(
        &mut self,
        cx: &Cx,
        sender: &mut OutgoingBodySender,
    ) -> Result<StreamingSseTransportStep, StreamingSseTransportError> {
        let chunk = self
            .heartbeat_chunk(cx)
            .map_err(StreamingSseTransportError::Stream)?;
        self.send_h1_bytes(cx, sender, &chunk).await
    }

    /// Emit one serialized event chunk.
    ///
    /// # Errors
    ///
    /// Returns [`StreamingSseError::Cancelled`] when `cx` has been cancelled,
    /// [`StreamingSseError::EventTooLarge`] when the next event exceeds
    /// `max_event_bytes`, [`StreamingSseError::TotalBytesExceeded`] when the
    /// stream would exceed `max_total_bytes`, or producer-specific errors from
    /// the configured [`StreamingSseSource`].
    pub fn next_chunk(&mut self, cx: &Cx) -> Result<Option<Vec<u8>>, StreamingSseError> {
        if self.closed {
            return Ok(None);
        }

        self.checkpoint(cx)?;
        match self.source.next_event(cx) {
            Ok(Some(event)) => self.serialize_event(&event).map(Some),
            Ok(None) => {
                self.closed = true;
                Ok(None)
            }
            Err(StreamingSseError::Cancelled) => {
                self.closed = true;
                self.source.cancel();
                Err(StreamingSseError::Cancelled)
            }
            Err(error) => Err(error),
        }
    }

    /// Emit one heartbeat/comment chunk without advancing the event source.
    ///
    /// # Errors
    ///
    /// Returns the same cancellation and byte-limit errors as
    /// [`next_chunk`](Self::next_chunk).
    pub fn heartbeat_chunk(&mut self, cx: &Cx) -> Result<Vec<u8>, StreamingSseError> {
        self.checkpoint(cx)?;
        let heartbeat = SseEvent::default().comment(self.heartbeat_comment.clone());
        self.serialize_event(&heartbeat)
    }

    fn checkpoint(&mut self, cx: &Cx) -> Result<(), StreamingSseError> {
        if cx.checkpoint().is_err() {
            self.closed = true;
            self.source.cancel();
            return Err(StreamingSseError::Cancelled);
        }
        Ok(())
    }

    fn serialize_event(&mut self, event: &SseEvent) -> Result<Vec<u8>, StreamingSseError> {
        let mut chunk = String::new();
        event.write_to(&mut chunk);
        let chunk_len = chunk.len();
        if chunk_len > self.max_event_bytes {
            return Err(StreamingSseError::EventTooLarge {
                actual: chunk_len,
                max: self.max_event_bytes,
            });
        }

        let next_total = self.bytes_emitted.saturating_add(chunk_len);
        if next_total > self.max_total_bytes {
            return Err(StreamingSseError::TotalBytesExceeded {
                actual: next_total,
                max: self.max_total_bytes,
            });
        }

        self.bytes_emitted = next_total;
        Ok(chunk.into_bytes())
    }

    async fn send_h1_bytes(
        &mut self,
        cx: &Cx,
        sender: &mut OutgoingBodySender,
        chunk: &[u8],
    ) -> Result<StreamingSseTransportStep, StreamingSseTransportError> {
        let bytes = chunk.len();
        match sender.send_chunk(cx, chunk).await {
            Ok(()) => Ok(StreamingSseTransportStep::Sent {
                bytes,
                total_bytes: self.bytes_emitted,
            }),
            Err(error) => {
                if matches!(
                    error,
                    HttpError::BodyCancelled | HttpError::BodyChannelClosed
                ) {
                    self.cancel_for_disconnect(cx);
                }
                Err(StreamingSseTransportError::Transport(error))
            }
        }
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
/// ```ignore
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
    use crate::bytes::Buf;
    use crate::http::body::{Body, Frame};
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = std::pin::pin!(future);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn poll_body<B: Body + Unpin>(body: &mut B) -> Option<Result<Frame<B::Data>, B::Error>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        loop {
            match Pin::new(&mut *body).poll_frame(&mut cx) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn body_has_no_more_data_after_cancel<B>(frame: Option<Result<Frame<B>, HttpError>>) -> bool {
        matches!(frame, None | Some(Err(HttpError::BodyCancelled)))
    }

    // ================================================================
    // SseEvent serialization
    // ================================================================

    #[test]
    fn event_data_only() {
        let event = SseEvent::default().data("hello");
        assert_eq!(event.to_string(), "data:hello\n\n");
    }

    #[test]
    fn event_with_type() {
        let event = SseEvent::default().event("message").data("hello");
        assert_eq!(event.to_string(), "event:message\ndata:hello\n\n");
    }

    #[test]
    fn event_with_id() {
        let event = SseEvent::default().data("hello").id("42");
        assert_eq!(event.to_string(), "data:hello\nid:42\n\n");
    }

    #[test]
    fn event_with_retry() {
        let event = SseEvent::default().data("hello").retry(3000);
        assert_eq!(event.to_string(), "data:hello\nretry:3000\n\n");
    }

    #[test]
    fn event_with_retry_duration() {
        let event = SseEvent::default()
            .data("hello")
            .retry_duration(Duration::from_secs(5));
        assert_eq!(event.to_string(), "data:hello\nretry:5000\n\n");
    }

    #[test]
    fn event_with_comment() {
        let event = SseEvent::default().comment("keep-alive");
        assert_eq!(event.to_string(), ":keep-alive\n\n");
    }

    #[test]
    fn event_multiline_data() {
        let event = SseEvent::default().data("line1\nline2\nline3");
        assert_eq!(event.to_string(), "data:line1\ndata:line2\ndata:line3\n\n");
    }

    /// br-asupersync-fek81o — WHATWG HTML §9.2.6 EventSource parser
    /// strips one U+0020 SPACE from the start of every field value.
    /// Without compensation, `data(" hello")` would emit `data: hello`
    /// which the parser strips to `"hello"` — the application's
    /// leading space is silently lost. Pre-fix this test failed with
    /// `data: hello\n\n`. Post-fix the writer emits an extra padding
    /// space (`data:  hello`) so the parser's strip leaves the
    /// original ` hello` intact.
    #[test]
    fn event_data_preserves_leading_space_for_whatwg_round_trip() {
        let event = SseEvent::default().data(" hello");
        assert_eq!(
            event.to_string(),
            "data:  hello\n\n",
            "leading space in data must be padded so the WHATWG parser's \
             leading-space strip preserves the application value",
        );
    }

    /// Counter test: a line with NO leading space stays at the
    /// pre-fix wire format `data:value` (no extra space). Locks the
    /// fix to leading-space lines only so the existing wire-format
    /// test pins below stay green.
    #[test]
    fn event_data_without_leading_space_unchanged() {
        let event = SseEvent::default().data("hello");
        assert_eq!(event.to_string(), "data:hello\n\n");
    }

    /// br-asupersync-fek81o — multi-line data where ONLY some lines
    /// start with a space: each line is independently padded.
    #[test]
    fn event_data_multiline_pads_only_leading_space_lines() {
        let event = SseEvent::default().data("first\n  second\nthird");
        assert_eq!(
            event.to_string(),
            "data:first\ndata:   second\ndata:third\n\n",
            "only the leading-space line gets an extra padding space; \
             the parser will strip one and preserve the rest. Got: {:?}",
            event.to_string(),
        );
    }

    /// br-asupersync-fek81o — a tab-prefixed line is NOT padded
    /// (parser only strips U+0020 SPACE, not U+0009 HTAB).
    #[test]
    fn event_data_tab_prefix_not_padded() {
        let event = SseEvent::default().data("\tindented");
        assert_eq!(
            event.to_string(),
            "data:\tindented\n\n",
            "U+0009 HTAB is not stripped by the WHATWG parser; \
             only U+0020 SPACE needs the padding workaround",
        );
    }

    #[test]
    fn event_all_fields() {
        let event = SseEvent::default()
            .comment("ping")
            .event("update")
            .data("payload")
            .id("7")
            .retry(1000);
        assert_eq!(
            event.to_string(),
            ":ping\nevent:update\ndata:payload\nid:7\nretry:1000\n\n"
        );
    }

    #[test]
    fn event_id_rejects_null_bytes() {
        let event = SseEvent::default().data("hello").id("bad\0id");
        assert!(event.id.is_none(), "null bytes in ID should be rejected");
        assert_eq!(event.to_string(), "data:hello\n\n");
    }

    #[test]
    fn event_empty() {
        let event = SseEvent::default();
        assert_eq!(event.to_string(), "\n");
    }

    #[test]
    fn event_multiline_comment() {
        let event = SseEvent::default().comment("line1\nline2");
        assert_eq!(event.to_string(), ":line1\n:line2\n\n");
    }

    #[test]
    fn event_comment_normalizes_bare_cr_to_block_field_injection() {
        // A bare \r in a comment must be treated as a line break so the
        // browser's EventSource parser cannot interpret the second half as
        // a real `data:` / `event:` / `id:` field. Without normalization,
        // Rust's .lines() leaves the \r in place and the injected payload
        // appears verbatim in the wire format.
        let event = SseEvent::default().comment("safe\rdata: injected");
        let body = event.to_string();
        assert!(
            !body.contains('\r'),
            "comment normalization should remove bare CR; got: {body:?}"
        );
        // The injected payload, if present at all, must appear inside a
        // comment line (prefixed with `:`), never as a top-level data field.
        assert_eq!(body, ":safe\n:data: injected\n\n");
    }

    #[test]
    fn event_comment_normalizes_crlf() {
        // CRLF in a comment should produce two clean comment lines, not
        // a stray \r followed by a separate \n.
        let event = SseEvent::default().comment("first\r\nsecond");
        assert_eq!(event.to_string(), ":first\n:second\n\n");
    }

    // ================================================================
    // Sse response
    // ================================================================

    #[test]
    fn sse_empty() {
        let sse = Sse::empty();
        assert!(sse.is_empty());
        assert_eq!(sse.len(), 0);
        assert_eq!(sse.to_body(), "");
    }

    #[test]
    fn sse_single_event() {
        let sse = Sse::event(SseEvent::default().data("hello"));
        assert_eq!(sse.len(), 1);
        assert_eq!(sse.to_body(), "data:hello\n\n");
    }

    #[test]
    fn sse_multiple_events() {
        let sse = Sse::new(vec![
            SseEvent::default().data("first"),
            SseEvent::default().data("second"),
        ]);
        assert_eq!(sse.to_body(), "data:first\n\ndata:second\n\n");
    }

    #[test]
    fn sse_keep_alive() {
        let sse = Sse::new(vec![SseEvent::default().data("hello")]).keep_alive();
        assert_eq!(sse.to_body(), ":keep-alive\n\ndata:hello\n\n");
    }

    #[test]
    fn sse_explicit_event_ids_drive_reconnection() {
        let sse = Sse::new(vec![
            SseEvent::default().data("first"),
            SseEvent::default().data("last").id("99"),
        ]);
        let body = sse.to_body();
        // First event should not have an ID.
        assert!(body.starts_with("data:first\n\n"));
        // The server-authored last event ID should be present.
        assert!(body.contains("id:99"));
    }

    #[test]
    fn sse_explicit_event_id_is_preserved() {
        let sse = Sse::new(vec![SseEvent::default().data("event").id("existing")]);
        let body = sse.to_body();
        assert!(body.contains("id:existing"));
    }

    // ================================================================
    // IntoResponse
    // ================================================================

    #[test]
    fn sse_into_response_headers() {
        let sse = Sse::event(SseEvent::default().data("hello"));
        let resp = sse.into_response();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/event-stream"
        );
        assert_eq!(resp.headers.get("cache-control").unwrap(), "no-cache");
        assert_eq!(resp.headers.get("connection").unwrap(), "keep-alive");
    }

    #[test]
    fn sse_into_response_body() {
        let sse = Sse::new(vec![
            SseEvent::default().event("msg").data("hello"),
            SseEvent::default().event("msg").data("world"),
        ]);
        let resp = sse.into_response();
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert_eq!(body, "event:msg\ndata:hello\n\nevent:msg\ndata:world\n\n");
    }

    #[test]
    fn sse_event_into_response() {
        let event = SseEvent::default().data("direct");
        let resp = event.into_response();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/event-stream"
        );
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert_eq!(body, "data:direct\n\n");
    }

    #[test]
    fn sse_keep_alive_with_multiple_events() {
        let sse = Sse::new(vec![
            SseEvent::default().data("a"),
            SseEvent::default().data("b"),
            SseEvent::default().data("c"),
        ])
        .keep_alive();
        let body = sse.to_body();
        assert!(body.starts_with(":keep-alive\n\n"));
        assert_eq!(body, ":keep-alive\n\ndata:a\n\ndata:b\n\ndata:c\n\n");
    }

    // ================================================================
    // StreamingSse response state
    // ================================================================

    #[test]
    fn streaming_sse_emits_one_chunk_per_event_in_order() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::new(vec![
            SseEvent::default().event("update").data("one").id("1"),
            SseEvent::default().event("update").data("two").id("2"),
        ]);

        let first = stream
            .next_chunk(&cx)
            .expect("first chunk")
            .expect("first event");
        let second = stream
            .next_chunk(&cx)
            .expect("second chunk")
            .expect("second event");
        let done = stream.next_chunk(&cx).expect("stream end");

        assert_eq!(
            std::str::from_utf8(&first).expect("utf8"),
            "event:update\ndata:one\nid:1\n\n"
        );
        assert_eq!(
            std::str::from_utf8(&second).expect("utf8"),
            "event:update\ndata:two\nid:2\n\n"
        );
        assert!(done.is_none());
        assert!(stream.is_closed());
        assert_eq!(stream.bytes_emitted(), first.len() + second.len());
    }

    #[test]
    fn streaming_sse_heartbeat_chunk_is_comment_without_advancing_events() {
        let cx = Cx::for_testing();
        let mut stream =
            StreamingSse::new(vec![SseEvent::default().data("payload")]).heartbeat_comment("tick");

        let heartbeat = stream.heartbeat_chunk(&cx).expect("heartbeat");
        let event = stream
            .next_chunk(&cx)
            .expect("event chunk")
            .expect("event present");

        assert_eq!(std::str::from_utf8(&heartbeat).expect("utf8"), ":tick\n\n");
        assert_eq!(
            std::str::from_utf8(&event).expect("utf8"),
            "data:payload\n\n"
        );
    }

    #[test]
    fn streaming_sse_rejects_oversized_event_chunk() {
        let cx = Cx::for_testing();
        let mut stream =
            StreamingSse::new(vec![SseEvent::default().data("abcdef")]).max_event_bytes(8);

        let err = stream.next_chunk(&cx).expect_err("event should exceed cap");
        assert!(matches!(
            err,
            StreamingSseError::EventTooLarge { actual, max: 8 } if actual > 8
        ));
        assert_eq!(stream.bytes_emitted(), 0);
    }

    #[test]
    fn streaming_sse_rejects_total_bytes_limit_without_partial_accounting() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::new(vec![
            SseEvent::default().data("one"),
            SseEvent::default().data("two"),
        ])
        .max_total_bytes("data:one\n\n".len());

        let first = stream
            .next_chunk(&cx)
            .expect("first chunk")
            .expect("first event");
        let err = stream
            .next_chunk(&cx)
            .expect_err("second chunk should exceed total cap");

        assert_eq!(std::str::from_utf8(&first).expect("utf8"), "data:one\n\n");
        assert!(matches!(
            err,
            StreamingSseError::TotalBytesExceeded { actual, max }
                if actual > max && max == first.len()
        ));
        assert_eq!(stream.bytes_emitted(), first.len());
    }

    #[test]
    fn streaming_sse_cancellation_closes_source_before_next_emit() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::new(vec![
            SseEvent::default().data("first"),
            SseEvent::default().data("second"),
        ]);
        let _first = stream
            .next_chunk(&cx)
            .expect("first chunk")
            .expect("first event");

        cx.set_cancel_requested(true);
        let err = stream
            .next_chunk(&cx)
            .expect_err("cancelled stream should fail");

        assert_eq!(err, StreamingSseError::Cancelled);
        assert!(stream.is_closed());
        assert!(stream.next_chunk(&Cx::for_testing()).unwrap().is_none());
    }

    #[test]
    fn streaming_sse_disconnect_sets_request_cancellation() {
        let cx = Cx::for_testing();
        let region = crate::web::request_region::RequestRegion::new(
            &cx,
            crate::web::extract::Request::new("GET", "/events"),
        );

        let outcome = region.run(|ctx| {
            let mut stream = StreamingSse::new(vec![SseEvent::default().data("pending")]);
            stream.cancel_for_disconnect(ctx.cx());
            assert!(stream.is_closed());
            Response::empty(StatusCode::CLIENT_CLOSED_REQUEST)
        });

        assert!(
            cx.is_cancel_requested(),
            "client disconnect should mark the request Cx cancelled"
        );
        assert_eq!(
            outcome.into_response().status,
            StatusCode::CLIENT_CLOSED_REQUEST
        );
    }

    #[test]
    fn streaming_sse_propagates_source_error() {
        struct FailingSource;

        impl StreamingSseSource for FailingSource {
            fn next_event(&mut self, _cx: &Cx) -> Result<Option<SseEvent>, StreamingSseError> {
                Err(StreamingSseError::Producer("synthetic failure".to_string()))
            }
        }

        let cx = Cx::for_testing();
        let mut stream = StreamingSse::from_source(FailingSource);
        let err = stream.next_chunk(&cx).expect_err("producer error");

        assert_eq!(
            err,
            StreamingSseError::Producer("synthetic failure".to_string())
        );
        assert!(!stream.is_closed());
    }

    #[test]
    fn streaming_sse_headers_match_event_stream_response_requirements() {
        assert_eq!(
            StreamingSse::<VecSseSource>::headers(),
            [
                ("content-type", "text/event-stream"),
                ("cache-control", "no-cache"),
                ("connection", "keep-alive"),
            ]
        );
    }

    #[test]
    fn streaming_sse_h1_response_head_is_chunked_event_stream() {
        let cx = Cx::for_testing();
        let stream = StreamingSse::new(vec![SseEvent::default().data("hello")]);
        let (response, sender) =
            stream.h1_chunked_response(&cx, DEFAULT_STREAMING_SSE_H1_CHANNEL_CAPACITY);

        let header = |name: &str| {
            response
                .head
                .headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(response.head.status, StatusCode::OK.as_u16());
        assert_eq!(header("transfer-encoding"), Some("chunked"));
        assert_eq!(header("content-type"), Some("text/event-stream"));
        assert_eq!(header("cache-control"), Some("no-cache"));
        assert_eq!(header("connection"), Some("keep-alive"));
        assert!(sender.kind().is_chunked());
    }

    #[test]
    fn streaming_sse_h1_transport_sends_events_in_order_and_finishes() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::new(vec![
            SseEvent::default().data("first"),
            SseEvent::default().data("second"),
        ]);
        let (response, mut sender) = stream.h1_chunked_response(&cx, 2);
        let mut body = response.body;

        let first = block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("first send");
        assert_eq!(
            first,
            StreamingSseTransportStep::Sent {
                bytes: "data:first\n\n".len(),
                total_bytes: "data:first\n\n".len(),
            }
        );
        let first_frame = poll_body(&mut body)
            .expect("first frame")
            .expect("first frame ok");
        assert_eq!(
            first_frame.into_data().expect("data frame").chunk(),
            b"data:first\n\n"
        );

        let second = block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("second send");
        assert_eq!(
            second,
            StreamingSseTransportStep::Sent {
                bytes: "data:second\n\n".len(),
                total_bytes: "data:first\n\n".len() + "data:second\n\n".len(),
            }
        );
        let second_frame = poll_body(&mut body)
            .expect("second frame")
            .expect("second frame ok");
        assert_eq!(
            second_frame.into_data().expect("data frame").chunk(),
            b"data:second\n\n"
        );

        let complete =
            block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("complete send");
        assert_eq!(complete, StreamingSseTransportStep::Complete);
        assert!(sender.is_finished());
        assert!(poll_body(&mut body).is_none());
    }

    #[test]
    fn streaming_sse_h1_transport_sends_heartbeat_comment() {
        let cx = Cx::for_testing();
        let mut stream =
            StreamingSse::new(vec![SseEvent::default().data("payload")]).heartbeat_comment("tick");
        let (response, mut sender) = stream.h1_chunked_response(&cx, 2);
        let mut body = response.body;

        let heartbeat =
            block_on(stream.send_h1_heartbeat(&cx, &mut sender)).expect("heartbeat send");
        assert_eq!(
            heartbeat,
            StreamingSseTransportStep::Sent {
                bytes: ":tick\n\n".len(),
                total_bytes: ":tick\n\n".len(),
            }
        );
        let heartbeat_frame = poll_body(&mut body)
            .expect("heartbeat frame")
            .expect("heartbeat frame ok");
        assert_eq!(
            heartbeat_frame.into_data().expect("data frame").chunk(),
            b":tick\n\n"
        );

        block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("event send");
        let event_frame = poll_body(&mut body)
            .expect("event frame")
            .expect("event frame ok");
        assert_eq!(
            event_frame.into_data().expect("data frame").chunk(),
            b"data:payload\n\n"
        );
    }

    #[test]
    fn streaming_sse_h1_transport_empty_stream_finishes_body() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::empty();
        let (response, mut sender) = stream.h1_chunked_response(&cx, 1);
        let mut body = response.body;

        let step = block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("finish");

        assert_eq!(step, StreamingSseTransportStep::Complete);
        assert!(sender.is_finished());
        assert!(stream.is_closed());
        assert!(poll_body(&mut body).is_none());
    }

    #[test]
    fn streaming_sse_h1_transport_propagates_producer_error_without_commit() {
        struct FailingSource;

        impl StreamingSseSource for FailingSource {
            fn next_event(&mut self, _cx: &Cx) -> Result<Option<SseEvent>, StreamingSseError> {
                Err(StreamingSseError::Producer("synthetic failure".to_string()))
            }
        }

        let cx = Cx::for_testing();
        let mut stream = StreamingSse::from_source(FailingSource);
        let (_response, mut sender) = stream.h1_chunked_response(&cx, 1);

        let err = block_on(stream.send_next_h1_chunk(&cx, &mut sender))
            .expect_err("producer error should surface");

        assert!(matches!(
            err,
            StreamingSseTransportError::Stream(StreamingSseError::Producer(message))
                if message == "synthetic failure"
        ));
        assert_eq!(stream.bytes_emitted(), 0);
        assert_eq!(sender.total_bytes(), 0);
    }

    #[test]
    fn streaming_sse_h1_transport_rejects_event_and_total_overflow() {
        let cx = Cx::for_testing();

        let mut oversized =
            StreamingSse::new(vec![SseEvent::default().data("abcdef")]).max_event_bytes(8);
        let (_response, mut sender) = oversized.h1_chunked_response(&cx, 1);
        let err = block_on(oversized.send_next_h1_chunk(&cx, &mut sender))
            .expect_err("oversized event should fail");
        assert!(matches!(
            err,
            StreamingSseTransportError::Stream(StreamingSseError::EventTooLarge {
                actual,
                max: 8,
            }) if actual > 8
        ));
        assert_eq!(oversized.bytes_emitted(), 0);
        assert_eq!(sender.total_bytes(), 0);

        let first_len = "data:one\n\n".len();
        let mut over_total = StreamingSse::new(vec![
            SseEvent::default().data("one"),
            SseEvent::default().data("two"),
        ])
        .max_total_bytes(first_len);
        let (response, mut sender) = over_total.h1_chunked_response(&cx, 1);
        let mut body = response.body;
        block_on(over_total.send_next_h1_chunk(&cx, &mut sender)).expect("first send");
        let _ = poll_body(&mut body)
            .expect("first frame")
            .expect("ok frame");
        let err = block_on(over_total.send_next_h1_chunk(&cx, &mut sender))
            .expect_err("total overflow should fail");
        assert!(matches!(
            err,
            StreamingSseTransportError::Stream(StreamingSseError::TotalBytesExceeded {
                actual,
                max,
            }) if actual > max && max == first_len
        ));
        assert_eq!(over_total.bytes_emitted(), first_len);
        assert_eq!(sender.total_bytes(), first_len as u64);
    }

    #[test]
    fn streaming_sse_h1_transport_disconnect_before_first_chunk_finishes_empty() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::new(vec![SseEvent::default().data("pending")]);
        let (response, mut sender) = stream.h1_chunked_response(&cx, 1);
        let mut body = response.body;

        stream.cancel_for_disconnect(&cx);
        let step =
            block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("closed stream finish");

        assert_eq!(step, StreamingSseTransportStep::Complete);
        assert!(cx.is_cancel_requested());
        assert_eq!(stream.bytes_emitted(), 0);
        assert!(body_has_no_more_data_after_cancel(poll_body(&mut body)));
    }

    #[test]
    fn streaming_sse_h1_transport_disconnect_after_committed_chunk_stops_later_events() {
        let cx = Cx::for_testing();
        let mut stream = StreamingSse::new(vec![
            SseEvent::default().data("first"),
            SseEvent::default().data("second"),
        ]);
        let (response, mut sender) = stream.h1_chunked_response(&cx, 1);
        let mut body = response.body;

        block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("first send");
        let frame = poll_body(&mut body)
            .expect("first frame")
            .expect("first frame ok");
        assert_eq!(
            frame.into_data().expect("data frame").chunk(),
            b"data:first\n\n"
        );

        stream.cancel_for_disconnect(&cx);
        let step =
            block_on(stream.send_next_h1_chunk(&cx, &mut sender)).expect("closed stream finish");

        assert_eq!(step, StreamingSseTransportStep::Complete);
        assert!(cx.is_cancel_requested());
        assert_eq!(stream.bytes_emitted(), "data:first\n\n".len());
        assert!(body_has_no_more_data_after_cancel(poll_body(&mut body)));
    }

    #[test]
    fn streaming_sse_h1_transport_cancellation_while_producing_closes_source() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let mut stream = StreamingSse::new(vec![SseEvent::default().data("pending")]);
        let (_response, mut sender) = stream.h1_chunked_response(&cx, 1);

        let err = block_on(stream.send_next_h1_chunk(&cx, &mut sender))
            .expect_err("cancelled stream should fail");

        assert!(matches!(
            err,
            StreamingSseTransportError::Stream(StreamingSseError::Cancelled)
        ));
        assert!(stream.is_closed());
        assert_eq!(stream.bytes_emitted(), 0);
    }

    // ================================================================
    // Data type coverage
    // ================================================================

    #[test]
    fn sse_event_debug_clone_default_eq() {
        let event = SseEvent::default();
        let dbg = format!("{event:?}");
        assert!(dbg.contains("SseEvent"));

        let cloned = event.clone();
        assert_eq!(event, cloned);

        let event2 = SseEvent::default().data("different");
        assert_ne!(event, event2);
    }

    #[test]
    fn sse_debug_clone() {
        let sse = Sse::event(SseEvent::default().data("test"));
        let dbg = format!("{sse:?}");
        assert!(dbg.contains("Sse"));
    }

    // ================================================================
    // Realistic usage patterns
    // ================================================================

    #[test]
    fn sse_json_events() {
        let sse = Sse::new(vec![
            SseEvent::default()
                .event("update")
                .data(r#"{"count": 1}"#)
                .id("1"),
            SseEvent::default()
                .event("update")
                .data(r#"{"count": 2}"#)
                .id("2"),
        ]);
        let body = sse.to_body();
        assert!(body.contains("event:update"));
        assert!(body.contains(r#"data:{"count": 1}"#));
        assert!(body.contains("id:1"));
        assert!(body.contains(r#"data:{"count": 2}"#));
        assert!(body.contains("id:2"));
    }

    #[test]
    fn sse_with_retry_and_reconnection() {
        let sse = Sse::new(vec![
            SseEvent::default().retry(5000).comment("reconnect hint"),
            SseEvent::default().event("heartbeat").data(""),
        ]);
        let body = sse.to_body();
        assert!(body.contains("retry:5000"));
        assert!(body.contains(":reconnect hint"));
        assert!(body.contains("event:heartbeat"));
    }

    // ─── br-asupersync-tamnew bounds ─────────────────────────────────

    #[test]
    fn sse_max_events_cap_returns_413() {
        // br-asupersync-tamnew: per-response event count cap rejects with
        // 413 Payload Too Large when exceeded.
        let events: Vec<SseEvent> = (0..6)
            .map(|i| SseEvent::default().data(format!("e{i}")))
            .collect();
        let sse = Sse::new(events).max_events(5);
        let resp = sse.into_response();
        assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(
            body.contains("max_events"),
            "body should mention the cap, got {body:?}"
        );
    }

    #[test]
    fn sse_max_events_cap_at_limit_serves_normally() {
        // Exactly at the cap = OK (off-by-one regression guard).
        let events: Vec<SseEvent> = (0..5)
            .map(|i| SseEvent::default().data(format!("e{i}")))
            .collect();
        let sse = Sse::new(events).max_events(5);
        let resp = sse.into_response();
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn sse_max_total_bytes_cap_returns_413() {
        // br-asupersync-tamnew: per-response body byte cap rejects with 413.
        // Each event body includes "data:e<i>\n\n" overhead too.
        let events = vec![SseEvent::default().data("a".repeat(1024))];
        let sse = Sse::new(events).max_total_bytes(100);
        let resp = sse.into_response();
        assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE);
        let body = std::str::from_utf8(&resp.body).unwrap();
        assert!(
            body.contains("max_total_bytes"),
            "body should mention the cap, got {body:?}"
        );
    }

    #[test]
    fn sse_default_caps_allow_typical_response() {
        // Smoke: default caps (100k events / 16 MiB) easily allow normal use.
        let events: Vec<SseEvent> = (0..10)
            .map(|i| SseEvent::default().data(format!("event-{i}")))
            .collect();
        let resp = Sse::new(events).into_response();
        assert_eq!(resp.status, StatusCode::OK);
    }
}
