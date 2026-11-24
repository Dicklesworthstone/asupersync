//! Incremental, bounded Server-Sent Events clients.
//!
//! SseDecoder implements the WHATWG event stream format, including replacement
//! decoding for malformed UTF-8, CR/LF framing, and committed reconnect cursors.
//! SseStream owns any HTTP Body and emits one event at a time without collecting
//! the response. It retains partial input when a next_event wait is dropped.
//!
//! The generic stream performs no HTTP requests or reconnects. Its body can come
//! from HTTP/1, HTTP/2, or another transport implementing the same Body contract.
//! See https://html.spec.whatwg.org/multipage/server-sent-events.html.

use super::body::{Body, Frame};
use crate::bytes::Buf;
use crate::cx::{CancelWakerToken, Cx};
use crate::stream::Stream;
use crate::time::Sleep;
use crate::types::{CancelReason, Time};
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(not(target_arch = "wasm32"))]
mod client;
#[cfg(not(target_arch = "wasm32"))]
pub use client::{EventSource, EventSourceError, EventSourceOptions, ReconnectPolicy};

const POLL_BYTES: usize = 64 * 1024;
const POLL_FRAMES: usize = 32;

/// Per-line, per-event, and retained-frame bounds for an event stream.
///
/// These are memory bounds, not a limit on the stream's lifetime or event count.
/// The line bound applies to both wire bytes and the replacement-decoded text.
/// The event bound includes data, event type, and the current ID together.
/// A committed cursor is retained separately within the same event-size bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SseLimits {
    max_line_bytes: usize,
    max_event_bytes: usize,
    max_frame_bytes: usize,
}

impl SseLimits {
    /// Uses 64 KiB lines, 1 MiB event state, and 1 MiB DATA frames.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_line_bytes: 64 * 1024,
            max_event_bytes: 1024 * 1024,
            max_frame_bytes: 1024 * 1024,
        }
    }

    /// Sets the maximum raw or decoded line size, excluding its terminator.
    #[must_use]
    pub const fn with_max_line_bytes(mut self, limit: usize) -> Self {
        self.max_line_bytes = limit;
        self
    }

    /// Sets the maximum aggregate data, event-type, and ID buffer size.
    #[must_use]
    pub const fn with_max_event_bytes(mut self, limit: usize) -> Self {
        self.max_event_bytes = limit;
        self
    }

    /// Sets the maximum size of any single retained HTTP DATA frame.
    #[must_use]
    pub const fn with_max_frame_bytes(mut self, limit: usize) -> Self {
        self.max_frame_bytes = limit;
        self
    }

    /// Returns the raw and decoded line bound.
    #[must_use]
    pub const fn max_line_bytes(self) -> usize {
        self.max_line_bytes
    }

    /// Returns the aggregate event-state bound.
    #[must_use]
    pub const fn max_event_bytes(self) -> usize {
        self.max_event_bytes
    }

    /// Returns the retained HTTP DATA-frame bound.
    #[must_use]
    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }
}

impl Default for SseLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// One dispatched event, with its committed reconnect cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SseEvent {
    /// The event field, or "message" when no nonempty event field was supplied.
    pub event_type: String,
    /// Data fields joined by LF, without the final appended LF.
    pub data: String,
    /// The current committed ID, including inherited IDs and explicit resets.
    pub last_event_id: String,
}

/// The bounded resource that refused an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SseLimit {
    /// A wire or replacement-decoded line.
    Line,
    /// Aggregate event data, type, and ID.
    Event,
    /// A retained HTTP DATA frame.
    Frame,
}

/// A terminal event-stream decoding or configuration failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SseDecodeError {
    /// Input exceeded a configured memory bound.
    LimitExceeded {
        /// The resource whose bound was exceeded.
        kind: SseLimit,
        /// The configured byte limit.
        limit: usize,
    },
    /// A seeded reconnect cursor contains NUL, CR, or LF.
    InvalidLastEventId,
    /// A cursor cannot be seeded after decoding has begun.
    AlreadyStarted,
    /// Decoding was attempted after EOF or a terminal error.
    Terminated,
}

impl fmt::Display for SseDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded { kind, limit } => {
                write!(f, "SSE {kind:?} exceeds its {limit}-byte limit")
            }
            Self::InvalidLastEventId => f.write_str("invalid seeded SSE last-event ID"),
            Self::AlreadyStarted => f.write_str("SSE decoding has already started"),
            Self::Terminated => f.write_str("SSE decoder has terminated"),
        }
    }
}

impl std::error::Error for SseDecodeError {}

/// An incremental WHATWG event-stream decoder with no event queue.
///
/// decode consumes through at most one dispatched event, leaving the unconsumed
/// suffix in the caller's slice. A completed blank line commits the ID even if
/// the block has no data. An incomplete block at EOF never advances that cursor.
#[derive(Debug)]
pub struct SseDecoder {
    limits: SseLimits,
    line: Vec<u8>,
    data: String,
    event_type: String,
    id_buffer: String,
    last_event_id: String,
    retry_millis: Option<u64>,
    first_line: bool,
    skip_lf: bool,
    started: bool,
    terminated: bool,
}

impl SseDecoder {
    /// Creates a decoder with explicit memory limits.
    #[must_use]
    pub fn new(limits: SseLimits) -> Self {
        Self {
            limits,
            line: Vec::new(),
            data: String::new(),
            event_type: String::new(),
            id_buffer: String::new(),
            last_event_id: String::new(),
            retry_millis: None,
            first_line: true,
            skip_lf: false,
            started: false,
            terminated: false,
        }
    }

    /// Seeds the committed cursor before any input is consumed.
    ///
    /// Native HTTP clients must additionally validate this string as a header
    /// value before sending it. A stream ID can contain characters unsuitable
    /// for HTTP headers even though they are valid in the event-stream format.
    pub fn with_last_event_id(
        mut self,
        id: impl Into<String>,
    ) -> Result<Self, SseDecodeError> {
        if self.started || self.terminated {
            return Err(SseDecodeError::AlreadyStarted);
        }
        let id = id.into();
        if id.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) {
            return Err(SseDecodeError::InvalidLastEventId);
        }
        if id.len() > self.limits.max_line_bytes {
            return Err(SseDecodeError::LimitExceeded {
                kind: SseLimit::Line,
                limit: self.limits.max_line_bytes,
            });
        }
        self.check_event_size(0, 0, id.len())?;
        self.id_buffer.clone_from(&id);
        self.last_event_id = id;
        Ok(self)
    }

    /// Consumes input through at most one event and returns that event.
    ///
    /// The slice is advanced by the bytes consumed. Keep any remaining bytes
    /// for the next call. Invalid UTF-8 is replaced, as required by the format;
    /// input or replacement expansion exceeding a configured bound is refused.
    pub fn decode(&mut self, input: &mut &[u8]) -> Result<Option<SseEvent>, SseDecodeError> {
        if self.terminated {
            return Err(SseDecodeError::Terminated);
        }
        if !input.is_empty() {
            self.started = true;
        }
        let result = self.decode_inner(input);
        if result.is_err() {
            self.finish();
        }
        result
    }

    fn decode_inner(&mut self, input: &mut &[u8]) -> Result<Option<SseEvent>, SseDecodeError> {
        while let Some((&byte, tail)) = input.split_first() {
            *input = tail;
            if self.skip_lf {
                self.skip_lf = false;
                if byte == b'\n' {
                    continue;
                }
            }
            match byte {
                b'\r' | b'\n' => {
                    self.skip_lf = byte == b'\r';
                    if let Some(event) = self.complete_line()? {
                        return Ok(Some(event));
                    }
                }
                _ => {
                    if self.line.len() >= self.limits.max_line_bytes {
                        return Err(SseDecodeError::LimitExceeded {
                            kind: SseLimit::Line,
                            limit: self.limits.max_line_bytes,
                        });
                    }
                    self.line.push(byte);
                }
            }
        }
        Ok(None)
    }

    fn check_event_size(
        &self,
        data: usize,
        event_type: usize,
        id: usize,
    ) -> Result<(), SseDecodeError> {
        if data
            .checked_add(event_type)
            .and_then(|size| size.checked_add(id))
            .is_none_or(|size| size > self.limits.max_event_bytes)
        {
            return Err(SseDecodeError::LimitExceeded {
                kind: SseLimit::Event,
                limit: self.limits.max_event_bytes,
            });
        }
        Ok(())
    }

    fn complete_line(&mut self) -> Result<Option<SseEvent>, SseDecodeError> {
        let mut bytes = std::mem::take(&mut self.line);
        let result = self.process_line(&bytes);
        bytes.clear();
        self.line = bytes;
        result
    }

    fn process_line(&mut self, bytes: &[u8]) -> Result<Option<SseEvent>, SseDecodeError> {
        let decoded = String::from_utf8_lossy(bytes);
        let line = if self.first_line {
            self.first_line = false;
            decoded.strip_prefix('\u{feff}').unwrap_or(&decoded)
        } else {
            &decoded
        };
        if line.len() > self.limits.max_line_bytes {
            return Err(SseDecodeError::LimitExceeded {
                kind: SseLimit::Line,
                limit: self.limits.max_line_bytes,
            });
        }
        if line.is_empty() {
            self.last_event_id.clone_from(&self.id_buffer);
            if self.data.is_empty() {
                self.event_type.clear();
                return Ok(None);
            }
            self.data.pop();
            let event_type = if self.event_type.is_empty() {
                "message".to_owned()
            } else {
                std::mem::take(&mut self.event_type)
            };
            return Ok(Some(SseEvent {
                event_type,
                data: std::mem::take(&mut self.data),
                last_event_id: self.last_event_id.clone(),
            }));
        }
        if line.starts_with(':') {
            return Ok(None);
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "data" => {
                let size = self
                    .data
                    .len()
                    .checked_add(value.len())
                    .and_then(|size| size.checked_add(1))
                    .ok_or(SseDecodeError::LimitExceeded {
                        kind: SseLimit::Event,
                        limit: self.limits.max_event_bytes,
                    })?;
                self.check_event_size(size, self.event_type.len(), self.id_buffer.len())?;
                self.data.push_str(value);
                self.data.push('\n');
            }
            "event" => {
                self.check_event_size(self.data.len(), value.len(), self.id_buffer.len())?;
                self.event_type.clear();
                self.event_type.push_str(value);
            }
            "id" if !value.contains('\0') => {
                self.check_event_size(self.data.len(), self.event_type.len(), value.len())?;
                self.id_buffer.clear();
                self.id_buffer.push_str(value);
            }
            "retry" if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
                self.retry_millis = Some(value.bytes().fold(0_u64, |number, byte| {
                    number
                        .saturating_mul(10)
                        .saturating_add(u64::from(byte - b'0'))
                }));
            }
            _ => {}
        }
        Ok(None)
    }

    /// Marks EOF and discards any incomplete line or event.
    ///
    /// This never dispatches pending data or commits an unfinished ID block.
    /// The last committed ID and most recent complete retry hint remain usable.
    pub fn finish(&mut self) {
        self.terminated = true;
        self.line.clear();
        self.data.clear();
        self.event_type.clear();
        self.id_buffer.clear();
    }

    /// Returns the cursor committed by the most recent complete blank line.
    #[must_use]
    pub fn last_event_id(&self) -> &str {
        &self.last_event_id
    }

    /// Returns the most recent valid retry field, in milliseconds.
    ///
    /// Values larger than u64::MAX saturate. A reconnecting client should clamp
    /// this hint to its own retry policy.
    #[must_use]
    pub const fn retry_millis(&self) -> Option<u64> {
        self.retry_millis
    }

    /// Returns whether EOF or a decoding failure has terminated this decoder.
    #[must_use]
    pub const fn is_terminated(&self) -> bool {
        self.terminated
    }
}

/// A terminal stream failure preserving the body's exact error type.
#[derive(Debug)]
#[non_exhaustive]
pub enum SseStreamError<E> {
    /// The HTTP body failed.
    Source(E),
    /// The event format exceeded a configured bound or could not be initialized.
    Decode(SseDecodeError),
    /// The owning context acknowledged cancellation, including budget expiry.
    Cancelled(CancelReason),
    /// A body buffer violated the Buf remaining/chunk contract.
    InvalidBodyData,
    /// DATA or a second trailers frame followed trailers.
    InvalidFrameOrder,
    /// A prior poll unwound through user body or buffer code.
    Poisoned,
}

impl<E: fmt::Display> fmt::Display for SseStreamError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => write!(f, "SSE body failed: {error}"),
            Self::Decode(error) => error.fmt(f),
            Self::Cancelled(reason) => write!(f, "SSE stream cancelled: {:?}", reason.kind),
            Self::InvalidBodyData => f.write_str("SSE body violated its buffer contract"),
            Self::InvalidFrameOrder => f.write_str("SSE body yielded a frame after trailers"),
            Self::Poisoned => f.write_str("SSE stream cannot resume after a poll panic"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SseStreamError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(error) => Some(error),
            Self::Decode(error) => Some(error),
            _ => None,
        }
    }
}

struct StreamOwner {
    cx: Cx,
    cancel_waker: Option<CancelWakerToken>,
    observed_deadline: Option<Time>,
    deadline: Option<Sleep>,
}

impl StreamOwner {
    fn new(cx: &Cx) -> Self {
        let observed_deadline = cx.budget().deadline;
        Self {
            cx: cx.clone(),
            cancel_waker: None,
            observed_deadline,
            deadline: observed_deadline.map(|at| cx.sleep_until_on_clock(at)),
        }
    }

    fn check<E>(&mut self, task: &mut Context<'_>) -> Result<(), SseStreamError<E>> {
        self.cancel_waker = Some(
            self.cx
                .refresh_cancel_waker(self.cancel_waker, task.waker()),
        );
        // This frame applies only to owner accounting. Body I/O must retain the
        // actual poller's reactor, including when the response changes owners.
        let _owner = self.cx.clone().set_current_restricted();
        if self.cx.checkpoint().is_err() {
            return Err(self.cancelled());
        }
        if let Some(at) = self.cx.budget().deadline
            && self.observed_deadline.is_none_or(|previous| at < previous)
        {
            self.observed_deadline = Some(at);
            self.deadline = Some(self.cx.sleep_until_on_clock(at));
        }
        if self
            .deadline
            .as_mut()
            .is_some_and(|sleep| Pin::new(sleep).poll_deadline(task).is_ready())
        {
            // Keep the observed deadline after removing an expired timer.
            // Masked cleanup may keep polling; it must not rearm and self-wake.
            self.deadline = None;
        }
        if self.cx.checkpoint().is_err() {
            return Err(self.cancelled());
        }
        Ok(())
    }

    fn cancelled<E>(&self) -> SseStreamError<E> {
        SseStreamError::Cancelled(
            self.cx
                .cancel_reason()
                .unwrap_or_else(|| CancelReason::user("SSE owner cancelled")),
        )
    }

    fn retire(&mut self) {
        self.deadline = None;
        if let Some(token) = self.cancel_waker.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

impl Drop for StreamOwner {
    fn drop(&mut self) {
        self.retire();
    }
}

/// An owned, cancellation-aware event stream over any HTTP Body.
///
/// Body and frame storage are independently owned; neither needs Send, Unpin,
/// or a static lifetime. Each poll decodes at most 64 KiB and requests at most
/// 32 frames, yielding even for endless comments or immediately ready empty
/// frames. Only one event is returned; no background task or event queue exists.
///
/// Dropping a next_event future leaves both partial event state and unconsumed
/// DATA in this stream. Dropping or closing the stream releases the transport.
/// EOF and errors release the body immediately and fuse further polls.
pub struct SseStream<B: Body> {
    body: Option<Pin<Box<B>>>,
    pending: Option<Box<B::Data>>,
    owner: StreamOwner,
    decoder: SseDecoder,
    seen_trailers: bool,
    done: bool,
    poisoned: bool,
}

impl<B: Body> SseStream<B> {
    /// Takes ownership of a body and uses this context's cancellation and clock.
    #[must_use]
    pub fn new(cx: &Cx, body: B, limits: SseLimits) -> Self {
        Self {
            body: Some(Box::pin(body)),
            pending: None,
            owner: StreamOwner::new(cx),
            decoder: SseDecoder::new(limits),
            seen_trailers: false,
            done: false,
            poisoned: false,
        }
    }

    /// Seeds a reconnect cursor before the first input byte is consumed.
    pub fn with_last_event_id(
        mut self,
        id: impl Into<String>,
    ) -> Result<Self, SseDecodeError> {
        let limits = self.decoder.limits;
        let decoder = std::mem::replace(&mut self.decoder, SseDecoder::new(limits));
        self.decoder = decoder.with_last_event_id(id)?;
        Ok(self)
    }

    /// Waits for one event without moving partial decoding state into the wait.
    pub async fn next_event(&mut self) -> Option<Result<SseEvent, SseStreamError<B::Error>>> {
        std::future::poll_fn(|task| Pin::new(&mut *self).poll_next(task)).await
    }

    /// Returns the last ID committed by a complete blank-line boundary.
    #[must_use]
    pub fn last_event_id(&self) -> &str {
        self.decoder.last_event_id()
    }

    /// Returns the latest complete valid retry hint in milliseconds.
    #[must_use]
    pub const fn retry_millis(&self) -> Option<u64> {
        self.decoder.retry_millis()
    }

    /// Returns whether EOF, an error, or close has terminated this stream.
    #[must_use]
    pub const fn is_terminated(&self) -> bool {
        self.done
    }

    /// Releases the body and subscriptions without draining or cancelling Cx.
    pub fn close(&mut self) {
        self.done = true;
        self.decoder.finish();
        // Retire the transport before running a user DATA destructor.
        self.body = None;
        self.pending = None;
        self.owner.retire();
    }

    fn poll_event(
        &mut self,
        task: &mut Context<'_>,
    ) -> Poll<Option<Result<SseEvent, SseStreamError<B::Error>>>> {
        if let Err(error) = self.owner.check(task) {
            return Poll::Ready(Some(Err(error)));
        }
        let mut bytes_left = POLL_BYTES;
        let mut frames_left = POLL_FRAMES;
        loop {
            if let Some(data) = self.pending.as_mut() {
                let remaining = data.remaining();
                if remaining == 0 {
                    self.pending = None;
                    continue;
                }
                if bytes_left == 0 {
                    task.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let chunk = data.chunk();
                if chunk.is_empty() || chunk.len() > remaining {
                    return Poll::Ready(Some(Err(SseStreamError::InvalidBodyData)));
                }
                let supplied = chunk.len().min(bytes_left);
                let mut input = &chunk[..supplied];
                let decoded = self.decoder.decode(&mut input);
                let consumed = supplied - input.len();
                data.advance(consumed);
                bytes_left -= consumed;
                match decoded {
                    Ok(Some(event)) => return Poll::Ready(Some(Ok(event))),
                    Ok(None) => continue,
                    Err(error) => return Poll::Ready(Some(Err(SseStreamError::Decode(error)))),
                }
            }
            if frames_left == 0 || bytes_left == 0 {
                task.waker().wake_by_ref();
                return Poll::Pending;
            }
            frames_left -= 1;
            let Some(body) = self.body.as_mut() else {
                return Poll::Ready(None);
            };
            match body.as_mut().poll_frame(task) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    if let Err(error) = self.owner.check(task) {
                        return Poll::Ready(Some(Err(error)));
                    }
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Some(Err(SseStreamError::Source(error))));
                }
                Poll::Ready(Some(Ok(Frame::Trailers(_)))) => {
                    if self.seen_trailers {
                        return Poll::Ready(Some(Err(SseStreamError::InvalidFrameOrder)));
                    }
                    self.seen_trailers = true;
                }
                Poll::Ready(Some(Ok(Frame::Data(data)))) => {
                    self.pending = Some(Box::new(data));
                    if self.seen_trailers {
                        return Poll::Ready(Some(Err(SseStreamError::InvalidFrameOrder)));
                    }
                    if self
                        .pending
                        .as_ref()
                        .is_some_and(|data| data.remaining() > self.decoder.limits.max_frame_bytes)
                    {
                        return Poll::Ready(Some(Err(SseStreamError::Decode(
                            SseDecodeError::LimitExceeded {
                                kind: SseLimit::Frame,
                                limit: self.decoder.limits.max_frame_bytes,
                            },
                        ))));
                    }
                }
            }
        }
    }
}

impl<B: Body> fmt::Debug for SseStream<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SseStream")
            .field("terminated", &self.done)
            .field("has_pending_frame", &self.pending.is_some())
            .field("limits", &self.decoder.limits)
            .finish_non_exhaustive()
    }
}

impl<B: Body> Stream for SseStream<B> {
    type Item = Result<SseEvent, SseStreamError<B::Error>>;

    fn poll_next(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        if this.poisoned {
            this.close();
            return Poll::Ready(Some(Err(SseStreamError::Poisoned)));
        }
        this.poisoned = true;
        let result = this.poll_event(task);
        if matches!(result, Poll::Ready(None | Some(Err(_)))) {
            this.close();
        }
        this.poisoned = false;
        result
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, self.done.then_some(0))
    }
}

#[cfg(test)]
#[path = "sse/tests.rs"]
mod tests;
