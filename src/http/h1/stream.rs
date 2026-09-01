//! HTTP/1 body streaming support.
//!
//! This module provides streaming body types for HTTP/1.1 that integrate with
//! asupersync's cancel-safety guarantees and backpressure mechanisms.
//!
//! # Overview
//!
//! - [`IncomingRequestBody`]: Streaming reader for request bodies
//! - [`IncomingBody`]: Legacy-compatible streaming request body
//! - [`IncomingRequestBody`]: Typed streaming request body with terminal diagnostics
//! - [`IncomingRequestBodyWriter`]: Feeds bytes into a typed request body with backpressure
//! - [`OutgoingBody`]: Streaming writer-facing body (consumer reads frames)
//! - [`OutgoingBodySender`]: Sends body frames with backpressure + cancellation
//! - [`ChunkedEncoder`]: Encoder for HTTP/1.1 chunked transfer encoding
//! - [`BodyKind`]: Body length determination (fixed vs chunked)

use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use parking_lot::Mutex;

use crate::bytes::{Buf, Bytes, BytesCursor, BytesMut};
use crate::channel::mpsc;
use crate::channel::mpsc::{RecvError, SendError};
use crate::cx::{CancelWakerToken, Cx};
use crate::http::body::{Body, Frame, HeaderMap, HeaderName, HeaderValue, SizeHint};
use crate::http::h1::codec::{
    HttpError, is_forbidden_trailer, parse_chunk_size_line, parse_header_line,
    require_transfer_encoding_chunked, trim_ows, validate_header_field,
};
use crate::types::CancelKind;

const DEFAULT_MAX_BODY_SIZE: u64 = 16 * 1024 * 1024;
const DEFAULT_MAX_TRAILERS_SIZE: usize = 16 * 1024;
const DEFAULT_MAX_BUFFERED_BYTES: usize = 256 * 1024;
const DEFAULT_BODY_CHANNEL_CAPACITY: usize = 8;
const DEFAULT_MAX_QUEUED_BODY_BYTES: usize = 512 * 1024;

/// Typed terminal error for an HTTP request body.
///
/// The protocol driver owns conversion from wire and request-region failures
/// into this closed set. In particular, cancellation preserves the exact
/// [`CancelKind`] instead of collapsing every request-budget outcome into a
/// generic channel error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IncomingBodyError {
    /// The declared Content-Length was invalid or did not match the wire body.
    BadContentLength,
    /// Chunked transfer framing was malformed or truncated.
    BadChunkedEncoding,
    /// The body exceeded the configured aggregate byte limit.
    BodyTooLarge {
        /// Bytes observed when the limit was crossed, when known.
        actual: Option<u64>,
        /// Configured aggregate body limit.
        limit: u64,
    },
    /// Trailer fields exceeded the configured trailer limit.
    TrailersTooLarge,
    /// A trailer line was malformed before field-name/value validation.
    BadHeader,
    /// A trailer field name was invalid.
    InvalidHeaderName,
    /// A trailer field value was invalid.
    InvalidHeaderValue,
    /// The request region was cancelled with this exact cause.
    Cancelled {
        /// Exact cancellation classification from the request context.
        kind: CancelKind,
    },
    /// The transport or producer disappeared before synchronized body EOF.
    SourceDisconnected,
    /// The sole body consumer was dropped before synchronized body EOF.
    ConsumerDropped,
    /// Checked byte accounting overflowed before state mutation.
    AccountingOverflow,
    /// One frame cannot fit inside the configured queued-byte budget.
    QueueFrameTooLarge {
        /// Frame storage bytes.
        actual: usize,
        /// Configured queued-byte limit.
        limit: usize,
    },
    /// Bounded unread-body drain exceeded its frame or byte allowance.
    DrainLimitExceeded {
        /// Frames discarded, including frames abandoned in the queue.
        frames: u64,
        /// Bytes discarded, including bytes abandoned in the queue.
        bytes: u64,
        /// Configured frame allowance.
        frame_limit: u64,
        /// Configured byte allowance.
        byte_limit: u64,
    },
    /// Synchronized body EOF was not reached within the drain deadline.
    DrainTimeout,
    /// The body was polled again after its terminal EOF or error observation.
    AlreadyTerminal,
}

impl std::fmt::Display for IncomingBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadContentLength => write!(f, "request body Content-Length mismatch"),
            Self::BadChunkedEncoding => write!(f, "malformed request body chunk framing"),
            Self::BodyTooLarge { actual, limit } => match actual {
                Some(actual) => write!(f, "request body exceeds limit ({actual} > {limit})"),
                None => write!(f, "request body exceeds limit ({limit})"),
            },
            Self::TrailersTooLarge => write!(f, "request body trailers exceed limit"),
            Self::BadHeader => write!(f, "malformed request trailer"),
            Self::InvalidHeaderName => write!(f, "invalid request trailer name"),
            Self::InvalidHeaderValue => write!(f, "invalid request trailer value"),
            Self::Cancelled { kind } => write!(f, "request body cancelled ({kind:?})"),
            Self::SourceDisconnected => write!(f, "request body source disconnected"),
            Self::ConsumerDropped => write!(f, "request body consumer dropped"),
            Self::AccountingOverflow => write!(f, "request body byte accounting overflow"),
            Self::QueueFrameTooLarge { actual, limit } => {
                write!(
                    f,
                    "request body frame exceeds queue budget ({actual} > {limit})"
                )
            }
            Self::DrainLimitExceeded {
                frames,
                bytes,
                frame_limit,
                byte_limit,
            } => write!(
                f,
                "unread request body exceeds drain bounds ({frames}/{frame_limit} frames, {bytes}/{byte_limit} bytes)"
            ),
            Self::DrainTimeout => write!(f, "unread request body drain timed out"),
            Self::AlreadyTerminal => write!(f, "request body already terminal"),
        }
    }
}

impl std::error::Error for IncomingBodyError {}

impl IncomingBodyError {
    fn from_http_error(error: &HttpError, max_body_size: u64) -> Self {
        match error {
            HttpError::BadContentLength => Self::BadContentLength,
            HttpError::BadChunkedEncoding => Self::BadChunkedEncoding,
            HttpError::BodyTooLarge => Self::BodyTooLarge {
                actual: None,
                limit: max_body_size,
            },
            HttpError::BodyTooLargeDetailed { actual, limit } => Self::BodyTooLarge {
                actual: Some(*actual),
                limit: *limit,
            },
            HttpError::HeadersTooLarge | HttpError::TooManyHeaders => Self::TrailersTooLarge,
            HttpError::InvalidHeaderName => Self::InvalidHeaderName,
            HttpError::BadHeader => Self::BadHeader,
            HttpError::InvalidHeaderValue => Self::InvalidHeaderValue,
            HttpError::BodyCancelled => Self::Cancelled {
                kind: CancelKind::User,
            },
            _ => Self::SourceDisconnected,
        }
    }

    fn cancelled(cx: &Cx) -> Self {
        Self::Cancelled {
            kind: cx
                .cancel_reason()
                .map_or(CancelKind::User, |reason| reason.kind()),
        }
    }

    fn into_http_error(self) -> HttpError {
        match self {
            Self::BadContentLength => HttpError::BadContentLength,
            Self::BadChunkedEncoding => HttpError::BadChunkedEncoding,
            Self::BodyTooLarge { .. } => HttpError::BodyTooLarge,
            Self::TrailersTooLarge => HttpError::HeadersTooLarge,
            Self::BadHeader => HttpError::BadHeader,
            Self::InvalidHeaderName => HttpError::InvalidHeaderName,
            Self::InvalidHeaderValue => HttpError::InvalidHeaderValue,
            Self::Cancelled { .. } => HttpError::BodyCancelled,
            Self::SourceDisconnected
            | Self::ConsumerDropped
            | Self::AlreadyTerminal
            | Self::DrainLimitExceeded { .. }
            | Self::DrainTimeout => HttpError::BodyChannelClosed,
            Self::AccountingOverflow | Self::QueueFrameTooLarge { .. } => HttpError::BodyTooLarge,
        }
    }
}

/// Producer-side terminal state shared with the sole body consumer.
///
/// The channel disconnect signal alone cannot distinguish an explicitly
/// completed body from a producer that disappeared while framing was still
/// open. Store the terminal reason before dropping the final sender so the
/// receiver never turns an unfinished body into a clean EOF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum IncomingProducerTerminal {
    Open = 0,
    Finished = 1,
    Failed = 2,
}

impl IncomingProducerTerminal {
    #[inline]
    fn load(state: &AtomicU8) -> Self {
        match state.load(Ordering::Acquire) {
            0 => Self::Open,
            1 => Self::Finished,
            _ => Self::Failed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum IncomingConsumerTerminal {
    Active = 0,
    Completed = 1,
    Failed = 2,
    Dropped = 3,
}

#[derive(Debug)]
struct QueuedByteState {
    queued: usize,
    next_waiter_id: u64,
    waiter: Option<QueuedByteWaiter>,
}

#[derive(Debug)]
struct QueuedByteWaiter {
    id: u64,
    waker: Waker,
}

#[derive(Debug)]
struct QueuedByteBudget {
    limit: usize,
    state: Mutex<QueuedByteState>,
}

impl QueuedByteBudget {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            state: Mutex::new(QueuedByteState {
                queued: 0,
                next_waiter_id: 0,
                waiter: None,
            }),
        })
    }

    async fn reserve(
        self: &Arc<Self>,
        cx: &Cx,
        amount: usize,
    ) -> Result<QueuedBytePermit, IncomingBodyError> {
        if amount > self.limit {
            return Err(IncomingBodyError::QueueFrameTooLarge {
                actual: amount,
                limit: self.limit,
            });
        }

        QueuedByteReserve {
            budget: Arc::clone(self),
            cx,
            amount,
            waiter_id: None,
            cancel_waker: None,
            completed: false,
        }
        .await
    }

    fn release(&self, amount: usize) {
        let mut state = self.state.lock();
        state.queued = state
            .queued
            .checked_sub(amount)
            .expect("queued request-body byte accounting underflow");
        let waiter = state.waiter.take().map(|waiter| waiter.waker);
        drop(state);
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
}

#[derive(Debug)]
struct QueuedByteCancelWaker {
    waker: Waker,
    token: CancelWakerToken,
}

struct QueuedByteReserve<'a> {
    budget: Arc<QueuedByteBudget>,
    cx: &'a Cx,
    amount: usize,
    waiter_id: Option<u64>,
    cancel_waker: Option<QueuedByteCancelWaker>,
    completed: bool,
}

impl QueuedByteReserve<'_> {
    fn refresh_cancel_waker(&mut self, waker: &Waker) {
        let same_local_waker = self
            .cancel_waker
            .as_ref()
            .is_some_and(|registered| registered.waker.will_wake(waker));
        let incoming_waker = (!same_local_waker).then(|| waker.clone());
        let previous_token = self
            .cancel_waker
            .as_ref()
            .map(|registered| registered.token);
        let token = self.cx.refresh_cancel_waker(previous_token, waker);
        let retired_waker = if let Some(incoming_waker) = incoming_waker {
            self.cancel_waker.replace(QueuedByteCancelWaker {
                waker: incoming_waker,
                token,
            })
        } else {
            self.cancel_waker
                .as_mut()
                .expect("same local Waker requires an existing registration")
                .token = token;
            None
        };
        drop(retired_waker);
    }

    fn clear_cancel_waker(&mut self) {
        let Some(registered) = self.cancel_waker.take() else {
            return;
        };
        self.cx.clear_cancel_waker(registered.token);
        drop(registered);
    }

    fn clear_queue_waiter(&mut self) {
        let Some(waiter_id) = self.waiter_id.take() else {
            return;
        };
        let retired_waker = {
            let mut state = self.budget.state.lock();
            if state
                .waiter
                .as_ref()
                .is_some_and(|waiter| waiter.id == waiter_id)
            {
                state.waiter.take().map(|waiter| waiter.waker)
            } else {
                None
            }
        };
        drop(retired_waker);
    }

    fn finish_error(
        &mut self,
        error: IncomingBodyError,
    ) -> Poll<Result<QueuedBytePermit, IncomingBodyError>> {
        self.completed = true;
        self.clear_queue_waiter();
        self.clear_cancel_waker();
        Poll::Ready(Err(error))
    }
}

impl Future for QueuedByteReserve<'_> {
    type Output = Result<QueuedBytePermit, IncomingBodyError>;

    fn poll(mut self: Pin<&mut Self>, task_cx: &mut Context<'_>) -> Poll<Self::Output> {
        assert!(
            !self.completed,
            "queued-byte reserve polled after completion"
        );

        if self.cx.checkpoint().is_err() {
            let error = IncomingBodyError::cancelled(self.cx);
            return self.finish_error(error);
        }

        self.refresh_cancel_waker(task_cx.waker());
        if self.cx.checkpoint().is_err() {
            let error = IncomingBodyError::cancelled(self.cx);
            return self.finish_error(error);
        }

        // Prepare the replacement outside the budget mutex. Custom RawWaker
        // clone/drop callbacks may re-enter this queue.
        let mut incoming_waker = Some(task_cx.waker().clone());
        let budget = Arc::clone(&self.budget);
        let result = {
            let mut state = budget.state.lock();
            let Some(next) = state.queued.checked_add(self.amount) else {
                drop(state);
                drop(incoming_waker);
                return self.finish_error(IncomingBodyError::AccountingOverflow);
            };

            if next <= budget.limit {
                state.queued = next;
                let retired_waker = if self.waiter_id.is_some_and(|waiter_id| {
                    state
                        .waiter
                        .as_ref()
                        .is_some_and(|waiter| waiter.id == waiter_id)
                }) {
                    state.waiter.take().map(|waiter| waiter.waker)
                } else {
                    None
                };
                self.waiter_id = None;
                Ok((
                    QueuedBytePermit {
                        budget: Arc::clone(&budget),
                        amount: self.amount,
                    },
                    retired_waker,
                ))
            } else {
                let current_waiter = self.waiter_id.and_then(|waiter_id| {
                    state
                        .waiter
                        .as_ref()
                        .filter(|waiter| waiter.id == waiter_id)
                });
                let retired_waker = if current_waiter
                    .is_some_and(|waiter| waiter.waker.will_wake(task_cx.waker()))
                {
                    None
                } else if let Some(waiter_id) = self.waiter_id
                    && state
                        .waiter
                        .as_ref()
                        .is_some_and(|waiter| waiter.id == waiter_id)
                {
                    let replacement = incoming_waker
                        .take()
                        .expect("prepared queued-byte Waker must be available");
                    state
                        .waiter
                        .as_mut()
                        .map(|waiter| std::mem::replace(&mut waiter.waker, replacement))
                } else {
                    let Some(waiter_id) = state.next_waiter_id.checked_add(1) else {
                        drop(state);
                        drop(incoming_waker);
                        return self.finish_error(IncomingBodyError::AccountingOverflow);
                    };
                    state.next_waiter_id = waiter_id;
                    self.waiter_id = Some(waiter_id);
                    let replacement = QueuedByteWaiter {
                        id: waiter_id,
                        waker: incoming_waker
                            .take()
                            .expect("prepared queued-byte Waker must be available"),
                    };
                    state.waiter.replace(replacement).map(|waiter| waiter.waker)
                };
                Err(retired_waker)
            }
        };

        match result {
            Ok((permit, retired_waker)) => {
                self.completed = true;
                drop(retired_waker);
                drop(incoming_waker);
                self.clear_cancel_waker();
                Poll::Ready(Ok(permit))
            }
            Err(retired_waker) => {
                drop(retired_waker);
                drop(incoming_waker);
                Poll::Pending
            }
        }
    }
}

impl Drop for QueuedByteReserve<'_> {
    fn drop(&mut self) {
        self.clear_queue_waiter();
        self.clear_cancel_waker();
    }
}

#[derive(Debug)]
struct QueuedBytePermit {
    budget: Arc<QueuedByteBudget>,
    amount: usize,
}

impl Drop for QueuedBytePermit {
    fn drop(&mut self) {
        self.budget.release(self.amount);
    }
}

#[derive(Debug)]
struct QueuedIncomingFrame {
    frame: Frame<BytesCursor>,
    _byte_permit: QueuedBytePermit,
}

#[derive(Debug)]
struct IncomingBodyShared {
    producer_terminal: AtomicU8,
    consumer_terminal: AtomicU8,
    terminal_error: Mutex<Option<IncomingBodyError>>,
    queued_bytes: Arc<QueuedByteBudget>,
    abandoned_frames: AtomicU64,
    abandoned_bytes: AtomicU64,
}

fn queued_frame_bytes(frame: &Frame<BytesCursor>) -> Result<usize, IncomingBodyError> {
    match frame {
        Frame::Data(data) => Ok(data.remaining()),
        Frame::Trailers(trailers) => trailers.iter().try_fold(0usize, |total, (name, value)| {
            let field_bytes = name
                .as_str()
                .len()
                .checked_add(value.as_bytes().len())
                .and_then(|bytes| bytes.checked_add(4))
                .ok_or(IncomingBodyError::AccountingOverflow)?;
            total
                .checked_add(field_bytes)
                .ok_or(IncomingBodyError::AccountingOverflow)
        }),
    }
}

impl IncomingBodyShared {
    fn consumer_dropped(&self) -> bool {
        self.consumer_terminal.load(Ordering::Acquire) == IncomingConsumerTerminal::Dropped as u8
    }
}

/// The kind of body based on headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// Body with known Content-Length.
    ContentLength(u64),
    /// Chunked transfer encoding.
    Chunked,
    /// No body (zero length).
    Empty,
}

impl BodyKind {
    /// Returns true if this is an empty body.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty | Self::ContentLength(0))
    }

    /// Returns true if this is a chunked body.
    #[must_use]
    pub fn is_chunked(&self) -> bool {
        matches!(self, Self::Chunked)
    }

    /// Returns the exact size if known.
    #[must_use]
    pub fn exact_size(&self) -> Option<u64> {
        match self {
            Self::ContentLength(n) => Some(*n),
            Self::Empty => Some(0),
            Self::Chunked => None,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Empty => SizeHint::with_exact(0),
            Self::ContentLength(n) => SizeHint::with_exact(*n),
            Self::Chunked => SizeHint::default(),
        }
    }
}

/// State machine for reading chunked bodies.
#[derive(Debug, Clone, Copy)]
enum ChunkedReadState {
    /// Waiting for chunk size line.
    SizeLine,
    /// Reading chunk data.
    Data { remaining: usize },
    /// Expecting CRLF after chunk data.
    DataCrlf,
    /// Reading trailer headers.
    Trailers,
    /// Body complete.
    Done,
}

/// Streaming, single-consumer HTTP request body.
///
/// Dropping this value before synchronized EOF publishes a consumer-drop
/// signal to the protocol driver. The driver must then perform its bounded
/// drain-or-close policy before reusing an HTTP/1 connection.
#[derive(Debug)]
pub struct IncomingRequestBody {
    receiver: mpsc::Receiver<QueuedIncomingFrame>,
    shared: Arc<IncomingBodyShared>,
    cx: Cx,
    done: bool,
    terminal_observed: bool,
    received: u64,
    size_hint: SizeHint,
    kind: BodyKind,
}

impl IncomingRequestBody {
    /// Creates a bounded incoming body channel.
    #[must_use]
    pub fn channel(cx: &Cx, kind: BodyKind) -> (IncomingRequestBodyWriter, Self) {
        Self::channel_with_limits(
            cx,
            kind,
            DEFAULT_BODY_CHANNEL_CAPACITY,
            DEFAULT_MAX_QUEUED_BODY_BYTES,
        )
    }

    /// Creates a bounded incoming body channel with custom capacity.
    #[must_use]
    pub fn channel_with_capacity(
        cx: &Cx,
        kind: BodyKind,
        capacity: usize,
    ) -> (IncomingRequestBodyWriter, Self) {
        Self::channel_with_limits(cx, kind, capacity, DEFAULT_MAX_QUEUED_BODY_BYTES)
    }

    /// Creates an incoming body channel with independent frame and byte caps.
    #[must_use]
    pub fn channel_with_limits(
        cx: &Cx,
        kind: BodyKind,
        frame_capacity: usize,
        queued_byte_limit: usize,
    ) -> (IncomingRequestBodyWriter, Self) {
        let (tx, rx) = mpsc::channel(frame_capacity);
        let done = kind.is_empty();
        let shared = Arc::new(IncomingBodyShared {
            producer_terminal: AtomicU8::new(if done {
                IncomingProducerTerminal::Finished as u8
            } else {
                IncomingProducerTerminal::Open as u8
            }),
            consumer_terminal: AtomicU8::new(IncomingConsumerTerminal::Active as u8),
            terminal_error: Mutex::new(None),
            queued_bytes: QueuedByteBudget::new(queued_byte_limit),
            abandoned_frames: AtomicU64::new(0),
            abandoned_bytes: AtomicU64::new(0),
        });
        let body = Self {
            receiver: rx,
            shared: Arc::clone(&shared),
            cx: cx.clone(),
            done,
            terminal_observed: false,
            received: 0,
            size_hint: kind.size_hint(),
            kind,
        };
        let writer = IncomingRequestBodyWriter::new(tx, kind, shared);
        (writer, body)
    }

    /// Returns the body kind.
    #[must_use]
    pub fn kind(&self) -> BodyKind {
        self.kind
    }

    /// Returns bytes currently retained by queued body frames.
    #[must_use]
    pub fn queued_bytes(&self) -> usize {
        self.shared.queued_bytes.state.lock().queued
    }
}

impl Body for IncomingRequestBody {
    type Data = BytesCursor;
    type Error = IncomingBodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        poll_cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            if self.terminal_observed {
                return Poll::Ready(Some(Err(IncomingBodyError::AlreadyTerminal)));
            }
            self.terminal_observed = true;
            self.shared
                .consumer_terminal
                .store(IncomingConsumerTerminal::Completed as u8, Ordering::Release);
            return Poll::Ready(None);
        }

        let cx = self.cx.clone();
        match self.receiver.poll_recv(&cx, poll_cx) {
            Poll::Ready(Ok(queued)) => {
                let QueuedIncomingFrame {
                    frame,
                    _byte_permit,
                } = queued;
                drop(_byte_permit);
                if frame.is_trailers() {
                    // Trailers mark the end of a chunked body.
                    self.done = true;
                    self.size_hint = SizeHint::with_exact(0);
                } else if let Some(data) = frame.data_ref() {
                    let Ok(data_len) = u64::try_from(data.remaining()) else {
                        self.done = true;
                        self.size_hint = SizeHint::with_exact(0);
                        self.terminal_observed = true;
                        self.shared
                            .consumer_terminal
                            .store(IncomingConsumerTerminal::Failed as u8, Ordering::Release);
                        return Poll::Ready(Some(Err(IncomingBodyError::AccountingOverflow)));
                    };
                    let Some(received) = self.received.checked_add(data_len) else {
                        self.done = true;
                        self.size_hint = SizeHint::with_exact(0);
                        self.terminal_observed = true;
                        self.shared
                            .consumer_terminal
                            .store(IncomingConsumerTerminal::Failed as u8, Ordering::Release);
                        return Poll::Ready(Some(Err(IncomingBodyError::AccountingOverflow)));
                    };
                    if let BodyKind::ContentLength(expected) = self.kind {
                        if received > expected {
                            self.done = true;
                            self.size_hint = SizeHint::with_exact(0);
                            self.terminal_observed = true;
                            self.shared
                                .consumer_terminal
                                .store(IncomingConsumerTerminal::Failed as u8, Ordering::Release);
                            return Poll::Ready(Some(Err(IncomingBodyError::BadContentLength)));
                        }
                        if received == expected {
                            self.done = true;
                        }
                        self.size_hint = SizeHint::with_exact(expected - received);
                    }
                    self.received = received;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Err(RecvError::Cancelled)) => {
                self.done = true;
                self.terminal_observed = true;
                self.size_hint = SizeHint::with_exact(0);
                self.shared
                    .consumer_terminal
                    .store(IncomingConsumerTerminal::Failed as u8, Ordering::Release);
                Poll::Ready(Some(Err(IncomingBodyError::cancelled(&self.cx))))
            }
            Poll::Ready(Err(RecvError::Disconnected)) => {
                self.done = true;
                self.size_hint = SizeHint::with_exact(0);
                match IncomingProducerTerminal::load(&self.shared.producer_terminal) {
                    IncomingProducerTerminal::Finished => {
                        self.terminal_observed = true;
                        self.shared
                            .consumer_terminal
                            .store(IncomingConsumerTerminal::Completed as u8, Ordering::Release);
                        Poll::Ready(None)
                    }
                    IncomingProducerTerminal::Open | IncomingProducerTerminal::Failed => {
                        self.terminal_observed = true;
                        self.shared
                            .consumer_terminal
                            .store(IncomingConsumerTerminal::Failed as u8, Ordering::Release);
                        let error = self
                            .shared
                            .terminal_error
                            .lock()
                            .clone()
                            .unwrap_or(IncomingBodyError::SourceDisconnected);
                        Poll::Ready(Some(Err(error)))
                    }
                }
            }
            Poll::Ready(Err(RecvError::Empty)) | Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        self.size_hint
    }
}

impl Drop for IncomingRequestBody {
    fn drop(&mut self) {
        if !self.done {
            // Close before draining so no producer can commit another frame
            // between the queue snapshot and the consumer-drop signal. A
            // sender that already owns a channel permit gets its frame back as
            // Disconnected and accounts it on the producer side instead.
            self.receiver.close();
            let mut abandoned_frames = 0_u64;
            let mut abandoned_bytes = 0_u64;
            while let Ok(queued) = self.receiver.try_recv() {
                abandoned_frames = abandoned_frames.saturating_add(1);
                let data_bytes = queued.frame.data_ref().map_or(0, Buf::remaining);
                abandoned_bytes =
                    abandoned_bytes.saturating_add(u64::try_from(data_bytes).unwrap_or(u64::MAX));
            }
            self.shared
                .abandoned_frames
                .store(abandoned_frames, Ordering::Release);
            self.shared
                .abandoned_bytes
                .store(abandoned_bytes, Ordering::Release);
            self.shared
                .consumer_terminal
                .store(IncomingConsumerTerminal::Dropped as u8, Ordering::Release);
        }
    }
}

/// Writer for feeding bytes into a typed incoming request body.
#[derive(Debug)]
pub struct IncomingRequestBodyWriter {
    sender: Option<mpsc::Sender<QueuedIncomingFrame>>,
    shared: Arc<IncomingBodyShared>,
    buffer: BytesMut,
    kind: BodyKind,
    remaining: u64,
    chunked_state: ChunkedReadState,
    trailers: HeaderMap,
    trailers_bytes: usize,
    done: bool,
    max_chunk_size: usize,
    max_body_size: u64,
    max_trailers_size: usize,
    max_buffered_bytes: usize,
    total_bytes: u64,
    discarded_frames: u64,
    discarded_bytes: u64,
}

/// Cumulative protocol-driver progress while discarding an unread H1 body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncomingBodyDrainProgress {
    /// Fully decoded frames discarded after consumer abandonment.
    pub frames: u64,
    /// Data bytes discarded after consumer abandonment (trailers excluded).
    pub bytes: u64,
    /// True only after synchronized Content-Length or chunked EOF.
    pub synchronized_eof: bool,
}

impl IncomingRequestBodyWriter {
    fn new(
        sender: mpsc::Sender<QueuedIncomingFrame>,
        kind: BodyKind,
        shared: Arc<IncomingBodyShared>,
    ) -> Self {
        let done = kind.is_empty();
        let remaining = match kind {
            BodyKind::ContentLength(n) => n,
            _ => 0,
        };
        let chunked_state = match kind {
            BodyKind::Chunked => ChunkedReadState::SizeLine,
            _ => ChunkedReadState::Done,
        };
        let mut writer = Self {
            sender: Some(sender),
            shared,
            buffer: BytesMut::with_capacity(8192),
            kind,
            remaining,
            chunked_state,
            trailers: HeaderMap::new(),
            trailers_bytes: 0,
            done,
            max_chunk_size: Self::DEFAULT_MAX_CHUNK_SIZE,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            max_trailers_size: DEFAULT_MAX_TRAILERS_SIZE,
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
            total_bytes: 0,
            discarded_frames: 0,
            discarded_bytes: 0,
        };
        if done {
            writer.sender = None;
        }
        writer
    }

    /// Maximum default chunk size for yielding data.
    pub const DEFAULT_MAX_CHUNK_SIZE: usize = 64 * 1024;

    /// Sets the maximum chunk size for yielded frames.
    #[must_use]
    pub fn max_chunk_size(mut self, size: usize) -> Self {
        self.max_chunk_size = size.max(1);
        self
    }

    /// Sets the maximum total body size.
    #[must_use]
    pub fn max_body_size(mut self, size: u64) -> Self {
        self.max_body_size = size;
        self
    }

    /// Sets the maximum buffered bytes for partial parsing.
    #[must_use]
    pub fn max_buffered_bytes(mut self, size: usize) -> Self {
        self.max_buffered_bytes = size.max(1);
        self
    }

    /// Sets the maximum total trailer size.
    #[must_use]
    pub fn max_trailers_size(mut self, size: usize) -> Self {
        self.max_trailers_size = size.max(1);
        self
    }

    /// Returns true if the body has completed.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Returns true when the sole handler-side consumer was dropped early.
    #[must_use]
    pub fn consumer_dropped(&self) -> bool {
        self.shared.consumer_dropped()
    }

    /// Takes bytes parsed past synchronized body EOF.
    ///
    /// These bytes belong to the next pipelined request and must be restored
    /// to the connection decoder before HTTP/1 reuse.
    pub fn take_remainder(&mut self) -> BytesMut {
        if self.done {
            std::mem::take(&mut self.buffer)
        } else {
            BytesMut::new()
        }
    }

    /// Returns cumulative unread-body discard progress.
    #[must_use]
    pub fn drain_progress(&self) -> IncomingBodyDrainProgress {
        IncomingBodyDrainProgress {
            frames: self
                .discarded_frames
                .saturating_add(self.shared.abandoned_frames.load(Ordering::Acquire)),
            bytes: self
                .discarded_bytes
                .saturating_add(self.shared.abandoned_bytes.load(Ordering::Acquire)),
            synchronized_eof: self.done,
        }
    }

    /// Parses and discards unread wire bytes after the consumer was dropped.
    ///
    /// The same fixed-length/chunked framing machine and aggregate byte limit
    /// remain active. No connection may be reused until `synchronized_eof` is
    /// true and the protocol driver's independent frame/byte/time drain bounds
    /// have all remained within policy.
    pub fn discard_bytes(
        &mut self,
        data: &[u8],
    ) -> Result<IncomingBodyDrainProgress, IncomingBodyError> {
        if !self.shared.consumer_dropped() {
            return Err(IncomingBodyError::ConsumerDropped);
        }
        self.sender.take();

        if !data.is_empty() {
            let buffered_bytes = self
                .buffer
                .len()
                .checked_add(data.len())
                .ok_or(IncomingBodyError::AccountingOverflow)?;
            if buffered_bytes > self.max_buffered_bytes {
                let error = IncomingBodyError::BodyTooLarge {
                    actual: u64::try_from(buffered_bytes).ok(),
                    limit: u64::try_from(self.max_buffered_bytes).unwrap_or(u64::MAX),
                };
                self.fail_sender(error.clone());
                return Err(error);
            }
            self.buffer.extend_from_slice(data);
        }

        loop {
            let frame = match self.try_decode_frame() {
                Ok(frame) => frame,
                Err(error) => {
                    let error = IncomingBodyError::from_http_error(&error, self.max_body_size);
                    self.fail_sender(error.clone());
                    return Err(error);
                }
            };
            let Some(frame) = frame else {
                break;
            };
            self.record_discard(&frame)?;
        }
        if self.done {
            self.finish_sender();
        }
        Ok(self.drain_progress())
    }

    /// Pushes raw bytes into the body stream.
    pub async fn push_bytes(&mut self, cx: &Cx, data: &[u8]) -> Result<(), IncomingBodyError> {
        let terminal = IncomingProducerTerminal::load(&self.shared.producer_terminal);
        if terminal != IncomingProducerTerminal::Open {
            return match terminal {
                IncomingProducerTerminal::Finished => Ok(()),
                IncomingProducerTerminal::Open => unreachable!(),
                IncomingProducerTerminal::Failed => Err(self
                    .shared
                    .terminal_error
                    .lock()
                    .clone()
                    .unwrap_or(IncomingBodyError::SourceDisconnected)),
            };
        }
        if self.shared.consumer_dropped() {
            self.sender.take();
            return Err(IncomingBodyError::ConsumerDropped);
        }
        if self.done {
            return Ok(());
        }

        if !data.is_empty() {
            let Some(buffered_bytes) = self.buffer.len().checked_add(data.len()) else {
                let error = IncomingBodyError::AccountingOverflow;
                self.fail_sender(error.clone());
                return Err(error);
            };
            if buffered_bytes > self.max_buffered_bytes {
                let error = IncomingBodyError::BodyTooLarge {
                    actual: u64::try_from(buffered_bytes).ok(),
                    limit: u64::try_from(self.max_buffered_bytes).unwrap_or(u64::MAX),
                };
                self.fail_sender(error.clone());
                return Err(error);
            }
            self.buffer.extend_from_slice(data);
        }

        match self.drain_frames(cx).await {
            Ok(()) => Ok(()),
            Err(IncomingBodyError::ConsumerDropped) => {
                self.sender.take();
                Err(IncomingBodyError::ConsumerDropped)
            }
            Err(error) => {
                self.fail_sender(error.clone());
                Err(error)
            }
        }
    }

    /// Signals EOF with no additional bytes.
    pub fn finish(&mut self, _cx: &Cx) -> Result<(), IncomingBodyError> {
        let terminal = IncomingProducerTerminal::load(&self.shared.producer_terminal);
        if terminal != IncomingProducerTerminal::Open {
            return match terminal {
                IncomingProducerTerminal::Finished => Ok(()),
                IncomingProducerTerminal::Open => unreachable!(),
                IncomingProducerTerminal::Failed => Err(self
                    .shared
                    .terminal_error
                    .lock()
                    .clone()
                    .unwrap_or(IncomingBodyError::SourceDisconnected)),
            };
        }
        if self.done {
            return Ok(());
        }

        if matches!(self.kind, BodyKind::ContentLength(_)) && self.remaining != 0 {
            let error = IncomingBodyError::BadContentLength;
            self.fail_sender(error.clone());
            return Err(error);
        }
        if matches!(self.kind, BodyKind::Chunked) {
            let error = IncomingBodyError::BadChunkedEncoding;
            self.fail_sender(error.clone());
            return Err(error);
        }

        self.done = true;
        self.finish_sender();
        Ok(())
    }

    async fn drain_frames(&mut self, cx: &Cx) -> Result<(), IncomingBodyError> {
        loop {
            let frame = self
                .try_decode_frame()
                .map_err(|error| IncomingBodyError::from_http_error(&error, self.max_body_size))?;
            let Some(frame) = frame else {
                break;
            };
            self.send_frame(cx, frame).await?;
            if self.done {
                self.finish_sender();
                break;
            }
        }

        if self.done {
            self.finish_sender();
        }

        Ok(())
    }

    fn finish_sender(&mut self) {
        let _ = self.shared.producer_terminal.compare_exchange(
            IncomingProducerTerminal::Open as u8,
            IncomingProducerTerminal::Finished as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.sender.take();
    }

    fn fail_sender(&mut self, error: IncomingBodyError) {
        *self.shared.terminal_error.lock() = Some(error);
        let _ = self.shared.producer_terminal.compare_exchange(
            IncomingProducerTerminal::Open as u8,
            IncomingProducerTerminal::Failed as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.done = true;
        self.sender.take();
    }

    fn checked_total_bytes(&self, additional: usize) -> Result<u64, HttpError> {
        let additional = u64::try_from(additional).map_err(|_| HttpError::BodyTooLarge)?;
        let total = self
            .total_bytes
            .checked_add(additional)
            .ok_or(HttpError::BodyTooLarge)?;
        if total > self.max_body_size {
            return Err(HttpError::BodyTooLargeDetailed {
                actual: total,
                limit: self.max_body_size,
            });
        }
        Ok(total)
    }

    async fn send_frame(
        &mut self,
        cx: &Cx,
        frame: Frame<BytesCursor>,
    ) -> Result<(), IncomingBodyError> {
        let Some(sender) = self.sender.clone() else {
            return Err(IncomingBodyError::SourceDisconnected);
        };
        if self.shared.consumer_dropped() {
            self.record_discard(&frame)?;
            return Err(IncomingBodyError::ConsumerDropped);
        }
        let frame_bytes = queued_frame_bytes(&frame)?;
        let data_bytes = frame.data_ref().map_or(0, Buf::remaining);
        let byte_permit = self.shared.queued_bytes.reserve(cx, frame_bytes).await?;
        let queued = QueuedIncomingFrame {
            frame,
            _byte_permit: byte_permit,
        };
        match sender.send(cx, queued).await {
            Ok(()) => Ok(()),
            Err(SendError::Disconnected(_) | SendError::Full(_)) => {
                self.record_discard_counts(data_bytes)?;
                Err(IncomingBodyError::ConsumerDropped)
            }
            Err(SendError::Cancelled(_)) => Err(IncomingBodyError::cancelled(cx)),
        }
    }

    fn record_discard(&mut self, frame: &Frame<BytesCursor>) -> Result<(), IncomingBodyError> {
        let bytes = frame.data_ref().map_or(0, Buf::remaining);
        self.record_discard_counts(bytes)
    }

    fn record_discard_counts(&mut self, bytes: usize) -> Result<(), IncomingBodyError> {
        let bytes = u64::try_from(bytes).map_err(|_| IncomingBodyError::AccountingOverflow)?;
        self.discarded_frames = self
            .discarded_frames
            .checked_add(1)
            .ok_or(IncomingBodyError::AccountingOverflow)?;
        self.discarded_bytes = self
            .discarded_bytes
            .checked_add(bytes)
            .ok_or(IncomingBodyError::AccountingOverflow)?;
        Ok(())
    }

    fn try_decode_frame(&mut self) -> Result<Option<Frame<BytesCursor>>, HttpError> {
        if self.done {
            return Ok(None);
        }

        match self.kind {
            BodyKind::Empty => {
                self.done = true;
                Ok(None)
            }
            BodyKind::ContentLength(_) => self.try_decode_content_length_frame(),
            BodyKind::Chunked => self.try_decode_chunked_frame(),
        }
    }

    fn try_decode_content_length_frame(&mut self) -> Result<Option<Frame<BytesCursor>>, HttpError> {
        if self.remaining == 0 {
            self.done = true;
            return Ok(None);
        }

        if self.buffer.is_empty() {
            return Ok(None);
        }

        let remaining = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        let to_yield = self.buffer.len().min(remaining).min(self.max_chunk_size);
        let next_total = self.checked_total_bytes(to_yield)?;
        let yielded = u64::try_from(to_yield).map_err(|_| HttpError::BodyTooLarge)?;
        let next_remaining = self
            .remaining
            .checked_sub(yielded)
            .ok_or(HttpError::BadContentLength)?;

        let chunk = self.buffer.split_to(to_yield);
        self.remaining = next_remaining;
        self.total_bytes = next_total;

        if self.remaining == 0 {
            self.done = true;
        }

        Ok(Some(Frame::Data(BytesCursor::new(chunk.freeze()))))
    }

    fn try_decode_chunked_frame(&mut self) -> Result<Option<Frame<BytesCursor>>, HttpError> {
        loop {
            match self.chunked_state {
                ChunkedReadState::SizeLine => {
                    let line_end = self.buffer.as_ref().windows(2).position(|w| w == b"\r\n");
                    let Some(line_end) = line_end else {
                        return Ok(None);
                    };

                    let line = &self.buffer.as_ref()[..line_end];
                    // Use the hardened shared parser: it rejects leading/trailing
                    // whitespace and any non-hexdigit prefix (e.g. "+5", " 5"),
                    // which a bare trim()+from_str_radix here would accept. That
                    // divergence is a request-smuggling primitive when a stricter
                    // intermediary (nginx/envoy) frames the same body differently
                    // (br-asupersync-usvn1p / -8dl9j7).
                    let chunk_size = parse_chunk_size_line(line)?;

                    let _ = self.buffer.split_to(line_end + 2);

                    if chunk_size == 0 {
                        self.chunked_state = ChunkedReadState::Trailers;
                        self.trailers = HeaderMap::new();
                        self.trailers_bytes = 0;
                    } else {
                        self.chunked_state = ChunkedReadState::Data {
                            remaining: chunk_size,
                        };
                    }
                }

                ChunkedReadState::Data { remaining } => {
                    if self.buffer.is_empty() {
                        return Ok(None);
                    }

                    let to_yield = self.buffer.len().min(remaining).min(self.max_chunk_size);
                    let next_total = self.checked_total_bytes(to_yield)?;
                    let next_remaining = remaining
                        .checked_sub(to_yield)
                        .ok_or(HttpError::BadChunkedEncoding)?;

                    let chunk = self.buffer.split_to(to_yield);
                    self.chunked_state = if next_remaining == 0 {
                        ChunkedReadState::DataCrlf
                    } else {
                        ChunkedReadState::Data {
                            remaining: next_remaining,
                        }
                    };

                    self.total_bytes = next_total;

                    return Ok(Some(Frame::Data(BytesCursor::new(chunk.freeze()))));
                }

                ChunkedReadState::DataCrlf => {
                    if self.buffer.len() < 2 {
                        return Ok(None);
                    }
                    if self.buffer.as_ref()[0] != b'\r' || self.buffer.as_ref()[1] != b'\n' {
                        return Err(HttpError::BadChunkedEncoding);
                    }
                    let _ = self.buffer.split_to(2);
                    self.chunked_state = ChunkedReadState::SizeLine;
                }

                ChunkedReadState::Trailers => {
                    let line_end = self.buffer.as_ref().windows(2).position(|w| w == b"\r\n");
                    let Some(line_end) = line_end else {
                        // No complete trailer line yet: bound buffered trailer data.
                        let buffered_trailer_bytes = self
                            .trailers_bytes
                            .checked_add(self.buffer.len())
                            .ok_or(HttpError::HeadersTooLarge)?;
                        if buffered_trailer_bytes > self.max_trailers_size {
                            return Err(HttpError::HeadersTooLarge);
                        }
                        return Ok(None);
                    };

                    if line_end == 0 {
                        let _ = self.buffer.split_to(2);
                        self.done = true;
                        self.chunked_state = ChunkedReadState::Done;
                        if !self.trailers.is_empty() {
                            return Ok(Some(Frame::Trailers(std::mem::take(&mut self.trailers))));
                        }
                        return Ok(None);
                    }

                    let line_bytes = line_end.checked_add(2).ok_or(HttpError::HeadersTooLarge)?;
                    let next_trailers_bytes = self
                        .trailers_bytes
                        .checked_add(line_bytes)
                        .ok_or(HttpError::HeadersTooLarge)?;
                    if next_trailers_bytes > self.max_trailers_size {
                        return Err(HttpError::HeadersTooLarge);
                    }

                    let line = self.buffer.split_to(line_end);
                    let _ = self.buffer.split_to(2);
                    self.trailers_bytes = next_trailers_bytes;

                    let line_str =
                        std::str::from_utf8(line.as_ref()).map_err(|_| HttpError::BadHeader)?;
                    let (name, value) = parse_header_line(line_str)?;
                    // br-asupersync-135g0e: RFC 9110 §6.5.1 forbids trailers that
                    // affect framing, routing, request modifiers, auth, payload
                    // processing, or cache control. The codec request path rejects
                    // these; mirror it here so the streaming body path can't be used
                    // to smuggle a Content-Length / Transfer-Encoding override past
                    // an intermediary that merges trailers into the header set.
                    if is_forbidden_trailer(&name) {
                        return Err(HttpError::BadHeader);
                    }
                    self.trailers.append(
                        HeaderName::from_string(&name),
                        HeaderValue::from_bytes(value.as_bytes()),
                    );
                }

                ChunkedReadState::Done => return Ok(None),
            }
        }
    }
}

impl Drop for IncomingRequestBodyWriter {
    fn drop(&mut self) {
        if self.sender.is_some() {
            *self.shared.terminal_error.lock() = Some(IncomingBodyError::SourceDisconnected);
            let _ = self.shared.producer_terminal.compare_exchange(
                IncomingProducerTerminal::Open as u8,
                IncomingProducerTerminal::Failed as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
}

/// Backwards-compatible HTTP/1 request body from the 0.4.3 API.
///
/// New server code should prefer [`IncomingRequestBody`] when it needs typed
/// cancellation causes and strict terminal-repoll diagnostics. This adapter
/// deliberately preserves the legacy [`HttpError`] surface and the standard
/// `Body` rule that every poll after terminal completion returns `None`.
#[derive(Debug)]
pub struct IncomingBody {
    inner: IncomingRequestBody,
    done: bool,
}

impl IncomingBody {
    /// Creates a bounded incoming body channel.
    #[must_use]
    pub fn channel(cx: &Cx, kind: BodyKind) -> (IncomingBodyWriter, Self) {
        Self::channel_with_capacity(cx, kind, DEFAULT_BODY_CHANNEL_CAPACITY)
    }

    /// Creates a bounded incoming body channel with custom frame capacity.
    #[must_use]
    pub fn channel_with_capacity(
        cx: &Cx,
        kind: BodyKind,
        capacity: usize,
    ) -> (IncomingBodyWriter, Self) {
        // The 0.4.3 contract bounded queued *frames* only. Keep the typed
        // implementation's byte accounting, but set its independent byte cap
        // to the representable maximum so this adapter does not introduce the
        // newer 512 KiB backpressure threshold into legacy callers.
        let (writer, inner) =
            IncomingRequestBody::channel_with_limits(cx, kind, capacity, usize::MAX);
        let done = inner.is_end_stream();
        (IncomingBodyWriter { inner: writer }, Self { inner, done })
    }

    /// Returns the body kind.
    #[must_use]
    pub fn kind(&self) -> BodyKind {
        self.inner.kind()
    }
}

impl Body for IncomingBody {
    type Data = BytesCursor;
    type Error = HttpError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        poll_cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.inner).poll_frame(poll_cx) {
            Poll::Ready(Some(Ok(frame))) => {
                self.done = self.inner.is_end_stream();
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.done = true;
                Poll::Ready(Some(Err(error.into_http_error())))
            }
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Backwards-compatible producer for [`IncomingBody`].
///
/// The adapter retains the 0.4.3 method signatures while delegating framing,
/// bounded buffering, and producer/consumer synchronization to the hardened
/// typed implementation.
#[derive(Debug)]
pub struct IncomingBodyWriter {
    inner: IncomingRequestBodyWriter,
}

impl IncomingBodyWriter {
    /// Maximum default chunk size for yielded data.
    pub const DEFAULT_MAX_CHUNK_SIZE: usize = IncomingRequestBodyWriter::DEFAULT_MAX_CHUNK_SIZE;

    /// Sets the maximum chunk size for yielded frames.
    #[must_use]
    pub fn max_chunk_size(mut self, size: usize) -> Self {
        self.inner = self.inner.max_chunk_size(size);
        self
    }

    /// Sets the maximum total body size.
    #[must_use]
    pub fn max_body_size(mut self, size: u64) -> Self {
        self.inner = self.inner.max_body_size(size);
        self
    }

    /// Sets the maximum buffered bytes for partial parsing.
    #[must_use]
    pub fn max_buffered_bytes(mut self, size: usize) -> Self {
        self.inner = self.inner.max_buffered_bytes(size);
        self
    }

    /// Sets the maximum total trailer size.
    #[must_use]
    pub fn max_trailers_size(mut self, size: usize) -> Self {
        self.inner = self.inner.max_trailers_size(size);
        self
    }

    /// Returns true if the body has completed.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.inner.is_done()
    }

    /// Pushes raw bytes into the body stream.
    pub async fn push_bytes(&mut self, cx: &Cx, data: &[u8]) -> Result<(), HttpError> {
        self.inner
            .push_bytes(cx, data)
            .await
            .map_err(IncomingBodyError::into_http_error)
    }

    /// Signals EOF with no additional bytes.
    pub fn finish(&mut self, cx: &Cx) -> Result<(), HttpError> {
        self.inner
            .finish(cx)
            .map_err(IncomingBodyError::into_http_error)
    }
}

/// Encoder for chunked transfer encoding.
#[derive(Debug, Default)]
pub struct ChunkedEncoder {
    finished: bool,
}

impl ChunkedEncoder {
    /// Creates a new chunked encoder.
    #[must_use]
    pub fn new() -> Self {
        Self { finished: false }
    }

    /// Encodes a data chunk into the chunked format.
    ///
    /// Empty data is a no-op — the zero-length chunk is reserved as the
    /// stream terminator and must only be emitted by [`Self::encode_final`].
    #[must_use]
    pub fn encode_chunk(data: &[u8]) -> BytesMut {
        let mut buf = BytesMut::with_capacity(data.len() + 32);
        Self::encode_chunk_into(data, &mut buf);
        buf
    }

    fn encode_chunk_into(data: &[u8], dst: &mut BytesMut) {
        if data.is_empty() {
            return;
        }
        // Write hex size directly into a stack buffer to avoid a heap allocation per chunk.
        let mut buf = [0u8; 18]; // max u64 hex = 16 digits + "\r\n"
        let n = {
            let mut v = data.len();
            let mut pos = 0;
            while v > 0 {
                let digit = (v & 0xF) as u8;
                buf[pos] = if digit < 10 {
                    b'0' + digit
                } else {
                    b'A' + digit - 10
                };
                pos += 1;
                v >>= 4;
            }
            buf[..pos].reverse();
            buf[pos] = b'\r';
            buf[pos + 1] = b'\n';
            pos + 2
        };
        dst.extend_from_slice(&buf[..n]);
        dst.extend_from_slice(data);
        dst.extend_from_slice(b"\r\n");
    }

    /// Encodes the final chunk (zero-length) with optional trailers.
    #[must_use]
    pub fn encode_final(&mut self, trailers: Option<&HeaderMap>) -> BytesMut {
        let mut buf = BytesMut::with_capacity(256);
        self.encode_final_into(trailers, &mut buf);
        buf
    }

    fn encode_final_into(&mut self, trailers: Option<&HeaderMap>, dst: &mut BytesMut) {
        if self.finished {
            return;
        }
        self.finished = true;
        dst.extend_from_slice(b"0\r\n");
        if let Some(trailers) = trailers {
            for (name, value) in trailers.iter() {
                let Ok(value_str) = value.to_str() else {
                    continue;
                };
                // Match the non-streaming HTTP/1 encoder: malformed trailer
                // fields must not reach the wire.
                if validate_header_field(name.as_str(), value_str).is_err() {
                    continue;
                }
                dst.extend_from_slice(name.as_str().as_bytes());
                dst.extend_from_slice(b": ");
                dst.extend_from_slice(value.as_bytes());
                dst.extend_from_slice(b"\r\n");
            }
        }
        dst.extend_from_slice(b"\r\n");
    }

    /// Encodes a body frame into chunked format.
    pub fn encode_frame<B: Buf>(&mut self, frame: Frame<B>, dst: &mut BytesMut) {
        match frame {
            Frame::Data(mut data) => {
                while data.remaining() > 0 {
                    let chunk = data.chunk();
                    if chunk.is_empty() {
                        break;
                    }
                    Self::encode_chunk_into(chunk, dst);
                    data.advance(chunk.len());
                }
            }
            Frame::Trailers(trailers) => self.encode_final_into(Some(&trailers), dst),
        }
    }

    /// Writes the final chunk if not already finished.
    pub fn finalize(&mut self, trailers: Option<&HeaderMap>, dst: &mut BytesMut) {
        self.encode_final_into(trailers, dst);
    }

    /// Returns true if the final chunk has been encoded.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

/// Body receiver for outgoing streams.
#[derive(Debug)]
pub struct OutgoingBody {
    receiver: mpsc::Receiver<Result<Frame<BytesCursor>, HttpError>>,
    cx: Cx,
    done: bool,
    size_hint: SizeHint,
    kind: BodyKind,
}

impl OutgoingBody {
    /// Creates a bounded outgoing body channel.
    #[must_use]
    pub fn channel(cx: &Cx, kind: BodyKind) -> (OutgoingBodySender, Self) {
        Self::channel_with_capacity(cx, kind, DEFAULT_BODY_CHANNEL_CAPACITY)
    }

    /// Creates a bounded outgoing body channel with custom capacity.
    #[must_use]
    pub fn channel_with_capacity(
        cx: &Cx,
        kind: BodyKind,
        capacity: usize,
    ) -> (OutgoingBodySender, Self) {
        let (tx, rx) = mpsc::channel(capacity);
        let body = Self {
            receiver: rx,
            cx: cx.clone(),
            done: kind.is_empty(),
            size_hint: kind.size_hint(),
            kind,
        };
        let sender = OutgoingBodySender::new(tx, kind);
        (sender, body)
    }

    /// Creates an empty outgoing body.
    #[must_use]
    pub fn empty(cx: &Cx) -> Self {
        let (_sender, body) = Self::channel_with_capacity(cx, BodyKind::Empty, 1);
        body
    }

    /// Returns the body kind.
    #[must_use]
    pub fn kind(&self) -> BodyKind {
        self.kind
    }
}

impl Body for OutgoingBody {
    type Data = BytesCursor;
    type Error = HttpError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        poll_cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }

        let cx = self.cx.clone();
        match self.receiver.poll_recv(&cx, poll_cx) {
            Poll::Ready(Ok(frame)) => {
                if let Ok(ref f) = frame {
                    if f.is_trailers() {
                        // Trailers are terminal for chunked bodies.
                        self.done = true;
                    }
                }
                Poll::Ready(Some(frame))
            }
            Poll::Ready(Err(RecvError::Cancelled)) => {
                self.done = true;
                Poll::Ready(Some(Err(HttpError::BodyCancelled)))
            }
            Poll::Ready(Err(RecvError::Disconnected)) => {
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Ready(Err(RecvError::Empty)) | Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        self.size_hint
    }
}

/// Sender for outgoing bodies.
#[derive(Debug)]
pub struct OutgoingBodySender {
    sender: Option<mpsc::Sender<Result<Frame<BytesCursor>, HttpError>>>,
    kind: BodyKind,
    remaining: u64,
    total_bytes: u64,
    finished: bool,
}

impl OutgoingBodySender {
    fn new(sender: mpsc::Sender<Result<Frame<BytesCursor>, HttpError>>, kind: BodyKind) -> Self {
        let remaining = match kind {
            BodyKind::ContentLength(n) => n,
            _ => 0,
        };
        let finished = kind.is_empty();
        let mut this = Self {
            sender: Some(sender),
            kind,
            remaining,
            total_bytes: 0,
            finished,
        };
        if finished {
            this.sender = None;
        }
        this
    }

    /// Returns the body kind.
    #[must_use]
    pub fn kind(&self) -> BodyKind {
        self.kind
    }

    /// Returns true if finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Returns the total bytes sent.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Sends a Bytes chunk.
    pub async fn send_bytes(&mut self, cx: &Cx, data: Bytes) -> Result<(), HttpError> {
        if self.finished {
            return Err(HttpError::BodyChannelClosed);
        }
        if data.is_empty() {
            return Ok(());
        }

        let len = data.len() as u64;
        if matches!(self.kind, BodyKind::ContentLength(_)) && len > self.remaining {
            return Err(HttpError::BadContentLength);
        }
        self.send_frame(cx, Frame::Data(BytesCursor::new(data)))
            .await?;

        if matches!(self.kind, BodyKind::ContentLength(_)) {
            self.remaining -= len;
        }
        self.total_bytes = self.total_bytes.saturating_add(len);
        Ok(())
    }

    /// Sends a slice (copies into Bytes).
    pub async fn send_chunk(&mut self, cx: &Cx, data: &[u8]) -> Result<(), HttpError> {
        if data.is_empty() {
            return Ok(());
        }
        self.send_bytes(cx, Bytes::copy_from_slice(data)).await
    }

    /// Sends trailing headers (only valid for chunked bodies).
    pub async fn send_trailers(&mut self, cx: &Cx, trailers: HeaderMap) -> Result<(), HttpError> {
        if !matches!(self.kind, BodyKind::Chunked) {
            return Err(HttpError::TrailersNotAllowed);
        }
        if self.finished {
            return Err(HttpError::BodyChannelClosed);
        }
        for (name, value) in trailers.iter() {
            let value = value.to_str().map_err(|_| HttpError::InvalidHeaderValue)?;
            validate_header_field(name.as_str(), value)?;
            if is_forbidden_trailer(name.as_str()) {
                return Err(HttpError::BadHeader);
            }
        }
        self.send_frame(cx, Frame::Trailers(trailers)).await?;
        self.finished = true;
        self.close_sender();
        Ok(())
    }

    /// Finishes the body (no trailers).
    pub fn finish(&mut self, _cx: &Cx) -> Result<(), HttpError> {
        if self.finished {
            return Ok(());
        }
        if matches!(self.kind, BodyKind::ContentLength(_)) && self.remaining != 0 {
            return Err(HttpError::BadContentLength);
        }
        self.finished = true;
        self.close_sender();
        Ok(())
    }

    fn close_sender(&mut self) {
        self.sender.take();
    }

    async fn send_frame(&self, cx: &Cx, frame: Frame<BytesCursor>) -> Result<(), HttpError> {
        let Some(sender) = self.sender.as_ref() else {
            return Err(HttpError::BodyChannelClosed);
        };
        match sender
            .send(
                cx,
                Ok::<crate::http::body::Frame<BytesCursor>, HttpError>(frame),
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(SendError::Disconnected(_) | SendError::Full(_)) => {
                Err(HttpError::BodyChannelClosed)
            }
            Err(SendError::Cancelled(_)) => Err(HttpError::BodyCancelled),
        }
    }
}

/// Streaming request head (without body).
#[derive(Debug, Clone)]
pub struct RequestHead {
    /// HTTP method.
    pub method: super::types::Method,
    /// Request URI.
    pub uri: String,
    /// HTTP version.
    pub version: super::types::Version,
    /// Request headers.
    pub headers: Vec<(String, String)>,
}

impl RequestHead {
    /// Returns the Content-Length header value, if present and valid.
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| {
                let value = trim_ows(value);
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    None
                } else {
                    value.parse().ok()
                }
            })
    }

    /// Returns true if Transfer-Encoding: chunked is set (strict single-token check).
    #[must_use]
    pub fn is_chunked(&self) -> bool {
        self.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                // Preserve this public helper's established single-token
                // behavior: a trailing/leading empty list element such as
                // `chunked,` is not the one supported coding.
                && !value.contains(',')
                && require_transfer_encoding_chunked(value).is_ok()
        })
    }

    /// Determines the body kind from headers.
    ///
    /// When both Transfer-Encoding and Content-Length are present,
    /// Content-Length is ignored per RFC 7230 §3.3.3: the Transfer-Encoding
    /// takes precedence.
    #[must_use]
    pub fn body_kind(&self) -> BodyKind {
        // RFC 7230 §3.3.3: If TE is present, ignore Content-Length.
        if self.is_chunked() {
            BodyKind::Chunked
        } else if let Some(len) = self.content_length() {
            if len == 0 {
                BodyKind::Empty
            } else {
                BodyKind::ContentLength(len)
            }
        } else {
            BodyKind::Empty
        }
    }
}

/// Streaming response head (without body).
#[derive(Debug, Clone)]
pub struct ResponseHead {
    /// HTTP version.
    pub version: super::types::Version,
    /// Status code.
    pub status: u16,
    /// Reason phrase.
    pub reason: String,
    /// Response headers.
    pub headers: Vec<(String, String)>,
}

impl ResponseHead {
    /// Creates a new response head with default HTTP/1.1.
    #[must_use]
    pub fn new(status: u16, reason: impl Into<String>) -> Self {
        Self {
            version: super::types::Version::Http11,
            status,
            reason: reason.into(),
            headers: Vec::new(),
        }
    }

    /// Adds a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Serializes the response head to bytes.
    #[must_use]
    pub fn serialize(&self) -> BytesMut {
        let reason = if self.reason.is_empty() {
            super::types::default_reason(self.status)
        } else {
            &self.reason
        };

        let mut buf = BytesMut::with_capacity(256);
        // Write status line components directly to avoid a format! heap allocation.
        buf.extend_from_slice(self.version.as_str().as_bytes());
        buf.extend_from_slice(b" ");
        {
            let mut tmp = [0u8; 5]; // max u16 = 65535
            let n = {
                let mut v = self.status;
                if v == 0 {
                    tmp[0] = b'0';
                    1
                } else {
                    let mut pos = 0;
                    while v > 0 {
                        tmp[pos] = b'0' + (v % 10) as u8;
                        pos += 1;
                        v /= 10;
                    }
                    tmp[..pos].reverse();
                    pos
                }
            };
            buf.extend_from_slice(&tmp[..n]);
        }
        buf.extend_from_slice(b" ");
        // Sanitize reason phrase: strip CR/LF to prevent response splitting.
        // RFC 7230 reason-phrase = *( HTAB / SP / VCHAR / obs-text ).
        for &b in reason.as_bytes() {
            if b != b'\r' && b != b'\n' {
                buf.extend_from_slice(&[b]);
            }
        }
        buf.extend_from_slice(b"\r\n");

        for (name, value) in &self.headers {
            // Reject headers containing CRLF to prevent response splitting.
            if name.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n')
                || value.as_bytes().iter().any(|&b| b == b'\r' || b == b'\n')
            {
                continue;
            }
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }

        buf.extend_from_slice(b"\r\n");
        buf
    }
}

/// A backwards-compatible streaming request with separate head and body.
#[derive(Debug)]
pub struct StreamingRequest {
    /// Request head (method, URI, headers).
    pub head: RequestHead,
    /// Request body.
    pub body: IncomingBody,
}

impl StreamingRequest {
    /// Creates a new streaming request.
    #[must_use]
    pub fn new(head: RequestHead, body: IncomingBody) -> Self {
        Self { head, body }
    }

    /// Creates a streaming request with a channel-backed body.
    #[must_use]
    pub fn channel(head: RequestHead, cx: &Cx, capacity: usize) -> (IncomingBodyWriter, Self) {
        let (writer, body) = IncomingBody::channel_with_capacity(cx, head.body_kind(), capacity);
        (writer, Self { head, body })
    }
}

/// Typed request published by [`crate::http::h1::Http1StreamingServer`].
///
/// This additive API carries listener metadata and the hardened request-body
/// error surface without changing the 0.4.3 [`StreamingRequest`] layout.
#[derive(Debug)]
#[non_exhaustive]
pub struct StreamingServerRequest {
    /// Request head (method, URI, headers).
    pub head: RequestHead,
    /// Remote peer address, when supplied by the listener.
    pub peer_addr: Option<std::net::SocketAddr>,
    /// Typed request body.
    pub body: IncomingRequestBody,
}

impl StreamingServerRequest {
    /// Creates a typed streaming-server request without peer metadata.
    #[must_use]
    pub fn new(head: RequestHead, body: IncomingRequestBody) -> Self {
        Self {
            head,
            peer_addr: None,
            body,
        }
    }

    /// Creates a typed request with a channel-backed body.
    #[must_use]
    pub fn channel(
        head: RequestHead,
        cx: &Cx,
        capacity: usize,
    ) -> (IncomingRequestBodyWriter, Self) {
        let (writer, body) =
            IncomingRequestBody::channel_with_capacity(cx, head.body_kind(), capacity);
        (writer, Self::new(head, body))
    }
}

/// A streaming response with separate head and body.
#[derive(Debug)]
pub struct StreamingResponse {
    /// Response head (status, headers).
    pub head: ResponseHead,
    /// Response body.
    pub body: OutgoingBody,
}

pub(crate) type Http1ProducedResponseFuture =
    Pin<Box<dyn Future<Output = Result<OutgoingBodySender, HttpError>> + Send + 'static>>;
type Http1ProducedResponseFactory =
    Box<dyn FnOnce(Cx, OutgoingBodySender) -> Http1ProducedResponseFuture + Send + 'static>;

/// A channel-bound HTTP/1.1 chunked response and its supervised producer.
///
/// Construction records a response head, frame capacity, and producer factory.
/// The server creates the [`StreamingResponse`] and [`OutgoingBodySender`] as
/// one pair under the authoritative request [`Cx`], so callers cannot attach a
/// producer to another channel or context. The producer returns its sender on
/// clean completion; the server accepts EOF only when that sender reports
/// [`OutgoingBodySender::is_finished`].
///
/// This low-level response is consumed by
/// [`crate::http::h1::Http1StreamingServer::serve_produced`]. It is additive to
/// the buffered web and HTTP/1 response APIs.
pub struct Http1ProducedResponse {
    head: ResponseHead,
    capacity: NonZeroUsize,
    producer: Http1ProducedResponseFactory,
}

impl std::fmt::Debug for Http1ProducedResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http1ProducedResponse")
            .field("head", &self.head)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl Http1ProducedResponse {
    /// Create a bounded chunked response whose producer is owned by the server.
    ///
    /// The producer receives the authoritative request [`Cx`] and the sole
    /// body sender only after the server validates the request method, HTTP
    /// version, and response head. It must call [`OutgoingBodySender::finish`] or
    /// [`OutgoingBodySender::send_trailers`] and return the sender to establish
    /// authoritative clean completion. Producer errors close the connection
    /// without a successful chunk terminator.
    #[must_use]
    pub fn chunked<P, Fut>(
        capacity: NonZeroUsize,
        status: u16,
        reason: impl Into<String>,
        producer: P,
    ) -> Self
    where
        P: FnOnce(Cx, OutgoingBodySender) -> Fut + Send + 'static,
        Fut: Future<Output = Result<OutgoingBodySender, HttpError>> + Send + 'static,
    {
        let head = ResponseHead::new(status, reason).with_header("Transfer-Encoding", "chunked");
        Self {
            head,
            capacity,
            producer: Box::new(move |cx, sender| Box::pin(producer(cx, sender))),
        }
    }

    /// Append one response header for validation and serialization by the server.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.head.headers.push((name.into(), value.into()));
        self
    }

    pub(crate) fn into_head(self) -> ResponseHead {
        self.head
    }

    pub(crate) fn head_mut(&mut self) -> &mut ResponseHead {
        &mut self.head
    }

    pub(crate) fn into_parts(self, cx: &Cx) -> (StreamingResponse, Http1ProducedResponseFuture) {
        let (sender, body) =
            OutgoingBody::channel_with_capacity(cx, BodyKind::Chunked, self.capacity.get());
        let producer = (self.producer)(cx.clone(), sender);
        (
            StreamingResponse {
                head: self.head,
                body,
            },
            producer,
        )
    }
}

impl StreamingResponse {
    /// Creates a new streaming response with chunked encoding.
    #[must_use]
    pub fn chunked(
        cx: &Cx,
        capacity: usize,
        status: u16,
        reason: impl Into<String>,
    ) -> (Self, OutgoingBodySender) {
        let head = ResponseHead::new(status, reason).with_header("Transfer-Encoding", "chunked");
        let (sender, body) = OutgoingBody::channel_with_capacity(cx, BodyKind::Chunked, capacity);
        (Self { head, body }, sender)
    }

    /// Creates a new streaming response with known Content-Length.
    #[must_use]
    pub fn with_content_length(
        cx: &Cx,
        capacity: usize,
        status: u16,
        reason: impl Into<String>,
        length: u64,
    ) -> (Self, OutgoingBodySender) {
        let head =
            ResponseHead::new(status, reason).with_header("Content-Length", length.to_string());
        let (sender, body) =
            OutgoingBody::channel_with_capacity(cx, BodyKind::ContentLength(length), capacity);
        (Self { head, body }, sender)
    }

    /// Creates an empty response (no body).
    #[must_use]
    pub fn empty(cx: &Cx, status: u16, reason: impl Into<String>) -> Self {
        let head = ResponseHead::new(status, reason).with_header("Content-Length", "0");
        Self {
            head,
            body: OutgoingBody::empty(cx),
        }
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
    use crate::types::CancelKind;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Waker;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn counting_waker(counter: Arc<AtomicUsize>) -> Waker {
        struct CountingWaker {
            counter: Arc<AtomicUsize>,
        }

        use std::task::Wake;
        impl Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        Waker::from(Arc::new(CountingWaker { counter }))
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = std::pin::pin!(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn poll_body<B: Body + Unpin>(body: &mut B) -> Option<Result<Frame<B::Data>, B::Error>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        loop {
            match Pin::new(&mut *body).poll_frame(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn body_kind_properties() {
        assert!(BodyKind::Empty.is_empty());
        assert!(BodyKind::ContentLength(0).is_empty());
        assert!(!BodyKind::ContentLength(10).is_empty());
        assert!(!BodyKind::Chunked.is_empty());

        assert!(!BodyKind::Empty.is_chunked());
        assert!(!BodyKind::ContentLength(10).is_chunked());
        assert!(BodyKind::Chunked.is_chunked());

        assert_eq!(BodyKind::Empty.exact_size(), Some(0));
        assert_eq!(BodyKind::ContentLength(42).exact_size(), Some(42));
        assert_eq!(BodyKind::Chunked.exact_size(), None);
    }

    #[test]
    fn incoming_body_content_length() {
        let cx: Cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(5));

        block_on(writer.push_bytes(&cx, b"hello")).expect("push bytes");

        let frame = poll_body(&mut body).unwrap().unwrap();
        let data = frame.into_data().unwrap();
        assert_eq!(data.chunk(), b"hello");
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_content_length_hint_tracks_delivered_bytes() {
        let cx: Cx = Cx::for_testing();
        let (writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(5));
        let mut writer = writer.max_chunk_size(2);

        block_on(writer.push_bytes(&cx, b"hello")).expect("push bytes");

        let first = poll_body(&mut body)
            .expect("first data frame")
            .expect("first frame should be valid");
        assert_eq!(first.into_data().expect("first data").chunk(), b"he");
        assert_eq!(body.size_hint().exact(), Some(3));

        let second = poll_body(&mut body)
            .expect("second data frame")
            .expect("second frame should be valid");
        assert_eq!(second.into_data().expect("second data").chunk(), b"ll");
        assert_eq!(body.size_hint().exact(), Some(1));

        let third = poll_body(&mut body)
            .expect("third data frame")
            .expect("third frame should be valid");
        assert_eq!(third.into_data().expect("third data").chunk(), b"o");
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_unfinished_producer_drop_is_not_eof() {
        let cx: Cx = Cx::for_testing();
        let (writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(5));

        drop(writer);

        let result = poll_body(&mut body).expect("unfinished producer must yield an error");
        assert!(matches!(result, Err(IncomingBodyError::SourceDisconnected)));
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_completed_chunked_without_trailers_ends_cleanly() {
        let cx: Cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);

        block_on(writer.push_bytes(&cx, b"0\r\n\r\n")).expect("finish chunked body");

        assert!(poll_body(&mut body).is_none());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_chunked_with_trailers() {
        let cx: Cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);

        block_on(writer.push_bytes(&cx, b"5\r\nhello\r\n0\r\nX-Trailer: test\r\n\r\n"))
            .expect("push bytes");

        let frame = poll_body(&mut body).unwrap().unwrap();
        assert_eq!(frame.into_data().unwrap().chunk(), b"hello");

        let frame = poll_body(&mut body).unwrap().unwrap();
        let trailers = frame.into_trailers().unwrap();
        assert_eq!(trailers.len(), 1);

        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_chunked_trailer_limit_does_not_count_terminal_crlf() {
        let cx: Cx = Cx::for_testing();
        let (writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);
        let mut writer = writer.max_trailers_size(7);

        // "X: y\r\n" consumes 6 trailer bytes; terminal "\r\n" should not count.
        block_on(writer.push_bytes(&cx, b"0\r\nX: y\r\n\r\n"))
            .expect("valid trailers should fit configured trailer limit");

        let frame = poll_body(&mut body)
            .expect("trailers frame")
            .expect("ok frame");
        let trailers = frame.into_trailers().expect("trailers");
        assert_eq!(trailers.len(), 1);
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_pending_poll_keeps_waker_registration() {
        let cx: Cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(1));

        let wake_count = Arc::new(AtomicUsize::new(0));
        let frame_waker = counting_waker(Arc::clone(&wake_count));
        let mut task_cx = Context::from_waker(&frame_waker);

        let first = Pin::new(&mut body).poll_frame(&mut task_cx);
        assert!(matches!(first, Poll::Pending));

        block_on(writer.push_bytes(&cx, b"x")).expect("push bytes");
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);

        let second = Pin::new(&mut body).poll_frame(&mut task_cx);
        let frame = match second {
            Poll::Ready(Some(Ok(frame))) => frame,
            _other => return, // Ignore in this test
        };
        let data = frame.into_data().expect("data frame");
        assert_eq!(data.chunk(), b"x");
    }

    #[test]
    fn incoming_body_chunked_finish_incomplete_errors() {
        let cx: Cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::Chunked);

        block_on(writer.push_bytes(&cx, b"5\r\nhello\r\n")).expect("push bytes");
        let err = writer.finish(&cx).expect_err("finish should error");
        assert!(matches!(err, IncomingBodyError::BadChunkedEncoding));

        let frame = poll_body(&mut body)
            .expect("queued data frame")
            .expect("queued data remains valid");
        assert_eq!(frame.into_data().expect("data frame").chunk(), b"hello");
        let terminal = poll_body(&mut body).expect("framing error after queued data");
        assert!(matches!(
            terminal,
            Err(IncomingBodyError::BadChunkedEncoding)
        ));
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_limit_refuses_whole_crossing_frame_and_surfaces_error() {
        let cx: Cx = Cx::for_testing();
        let (writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(4));
        let mut writer = writer.max_chunk_size(2).max_body_size(3);

        let error = block_on(writer.push_bytes(&cx, b"data"))
            .expect_err("second two-byte frame crosses the three-byte limit");
        assert!(matches!(error, IncomingBodyError::BodyTooLarge { .. }));

        let frame = poll_body(&mut body)
            .expect("first frame remains queued")
            .expect("first frame is within the limit");
        assert_eq!(frame.into_data().expect("data frame").chunk(), b"da");
        let terminal = poll_body(&mut body).expect("limit error follows accepted frame");
        assert!(matches!(
            terminal,
            Err(IncomingBodyError::BodyTooLarge { .. })
        ));
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_repoll_after_eof_fails_closed() {
        let cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(1));

        block_on(writer.push_bytes(&cx, b"x")).expect("one-byte body");
        let frame = poll_body(&mut body)
            .expect("data frame")
            .expect("valid data frame");
        assert_eq!(frame.into_data().expect("data").chunk(), b"x");
        assert!(poll_body(&mut body).is_none(), "first terminal poll is EOF");
        assert!(matches!(
            poll_body(&mut body),
            Some(Err(IncomingBodyError::AlreadyTerminal))
        ));
    }

    #[test]
    fn v0_4_3_compatibility_incoming_body_preserves_http_error_and_repeat_eof_contract() {
        let cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingBody::channel(&cx, BodyKind::ContentLength(1));

        block_on(writer.push_bytes(&cx, b"x")).expect("legacy one-byte body");
        let frame = poll_body(&mut body)
            .expect("legacy data frame")
            .expect("valid legacy data frame");
        assert_eq!(frame.into_data().expect("legacy data").chunk(), b"x");
        assert!(poll_body(&mut body).is_none(), "legacy first terminal poll");
        assert!(
            poll_body(&mut body).is_none(),
            "0.4.3 legacy bodies must keep returning EOF after termination"
        );

        let (writer, mut unfinished) = IncomingBody::channel(&cx, BodyKind::ContentLength(1));
        drop(writer);
        assert!(matches!(
            poll_body(&mut unfinished),
            Some(Err(HttpError::BodyChannelClosed))
        ));
        assert!(poll_body(&mut unfinished).is_none());

        let (mut limited_writer, _limited_body) =
            IncomingBody::channel(&cx, BodyKind::ContentLength(1));
        limited_writer = limited_writer.max_body_size(0);
        assert!(matches!(
            block_on(limited_writer.push_bytes(&cx, b"x")),
            Err(HttpError::BodyTooLarge)
        ));

        let (mut malformed_writer, _malformed_body) = IncomingBody::channel(&cx, BodyKind::Chunked);
        assert!(matches!(
            block_on(malformed_writer.push_bytes(&cx, b"0\r\nnot-a-field\r\n\r\n")),
            Err(HttpError::BadHeader)
        ));
    }

    #[test]
    fn incoming_body_cancellation_preserves_exact_kind() {
        let base_cx = Cx::for_testing();
        let (mut writer, mut body) =
            IncomingRequestBody::channel(&base_cx, BodyKind::ContentLength(1));
        let cancelled_cx = Cx::for_testing();
        cancelled_cx.cancel_fast(CancelKind::Deadline);

        let error = block_on(writer.push_bytes(&cancelled_cx, b"x"))
            .expect_err("cancelled producer must fail");
        assert_eq!(
            error,
            IncomingBodyError::Cancelled {
                kind: CancelKind::Deadline,
            }
        );
        assert!(matches!(
            poll_body(&mut body),
            Some(Err(IncomingBodyError::Cancelled {
                kind: CancelKind::Deadline,
            }))
        ));
    }

    #[test]
    fn incoming_body_queue_bytes_backpressure_independently_of_frame_slots() {
        let cx = Cx::for_testing();
        let (writer, mut body) =
            IncomingRequestBody::channel_with_limits(&cx, BodyKind::ContentLength(4), 8, 2);
        let mut writer = writer.max_chunk_size(2);
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);

        {
            let mut push = std::pin::pin!(writer.push_bytes(&cx, b"data"));
            assert!(matches!(push.as_mut().poll(&mut task_cx), Poll::Pending));
            assert_eq!(body.queued_bytes(), 2);

            let first = poll_body(&mut body)
                .expect("first frame")
                .expect("valid first frame");
            assert_eq!(first.into_data().expect("data").chunk(), b"da");
            assert!(matches!(
                push.as_mut().poll(&mut task_cx),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(body.queued_bytes(), 2);
        }

        let second = poll_body(&mut body)
            .expect("second frame")
            .expect("valid second frame");
        assert_eq!(second.into_data().expect("data").chunk(), b"ta");
        assert_eq!(body.queued_bytes(), 0);
    }

    #[test]
    fn incoming_body_queue_byte_wait_is_woken_by_cancellation() {
        let cx = Cx::for_testing();
        let (writer, body) =
            IncomingRequestBody::channel_with_limits(&cx, BodyKind::ContentLength(4), 8, 2);
        let mut writer = writer.max_chunk_size(2);
        let wake_count = Arc::new(AtomicUsize::new(0));
        let reserve_waker = counting_waker(Arc::clone(&wake_count));
        let mut task_cx = Context::from_waker(&reserve_waker);

        let mut push = std::pin::pin!(writer.push_bytes(&cx, b"data"));
        assert!(matches!(push.as_mut().poll(&mut task_cx), Poll::Pending));
        assert_eq!(body.queued_bytes(), 2, "first frame holds the byte cap");

        cx.cancel_fast(CancelKind::Deadline);
        assert_eq!(
            wake_count.load(Ordering::SeqCst),
            1,
            "context cancellation must wake the byte-budget waiter"
        );
        assert!(matches!(
            push.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(IncomingBodyError::Cancelled {
                kind: CancelKind::Deadline,
            }))
        ));
    }

    #[test]
    fn incoming_body_consumer_drop_drains_and_preserves_pipeline_remainder() {
        let cx = Cx::for_testing();
        let (mut writer, body) = IncomingRequestBody::channel(&cx, BodyKind::ContentLength(5));
        drop(body);

        assert!(writer.consumer_dropped());
        let error = block_on(writer.push_bytes(&cx, b"hello"))
            .expect_err("driver must observe early consumer drop");
        assert_eq!(error, IncomingBodyError::ConsumerDropped);

        let progress = writer
            .discard_bytes(b"helloGET /next HTTP/1.1\r\n")
            .expect("bounded discard keeps framing synchronized");
        assert_eq!(progress.frames, 1);
        assert_eq!(progress.bytes, 5);
        assert!(progress.synchronized_eof);
        assert_eq!(writer.take_remainder().as_ref(), b"GET /next HTTP/1.1\r\n");
    }

    #[test]
    fn incoming_body_consumer_drop_counts_exact_queued_frames() {
        let cx = Cx::for_testing();
        let (writer, body) =
            IncomingRequestBody::channel_with_limits(&cx, BodyKind::ContentLength(4), 8, 8);
        let mut writer = writer.max_chunk_size(2);

        block_on(writer.push_bytes(&cx, b"data")).expect("queue complete body");
        assert_eq!(body.queued_bytes(), 4);
        drop(body);

        let progress = writer.drain_progress();
        assert_eq!(progress.frames, 2);
        assert_eq!(progress.bytes, 4);
        assert!(progress.synchronized_eof);
    }

    #[test]
    fn chunked_encoder_simple() {
        let encoded_chunk = ChunkedEncoder::encode_chunk(b"hello");
        assert_eq!(encoded_chunk.as_ref(), b"5\r\nhello\r\n");
    }

    #[test]
    fn chunked_encoder_final_with_trailers() {
        let mut encoder = ChunkedEncoder::new();
        let mut trailers = HeaderMap::new();
        trailers.insert(
            crate::http::body::HeaderName::from_static("x-checksum"),
            crate::http::body::HeaderValue::from_static("abc123"),
        );

        let final_chunk = encoder.encode_final(Some(&trailers));
        let expected = b"0\r\nx-checksum: abc123\r\n\r\n";
        assert_eq!(final_chunk.as_ref(), expected);
    }

    #[test]
    fn chunked_encoder_skips_invalid_trailer_fields() {
        let mut encoder = ChunkedEncoder::new();
        let mut trailers = HeaderMap::new();
        trailers.insert(
            crate::http::body::HeaderName::from_static("x-safe"),
            crate::http::body::HeaderValue::from_static("ok"),
        );
        trailers.insert(
            crate::http::body::HeaderName::from_string("x-bad\r\ninjected: nope"),
            crate::http::body::HeaderValue::from_static("bad"),
        );
        trailers.insert(
            crate::http::body::HeaderName::from_static("x-bad-value"),
            crate::http::body::HeaderValue::from_bytes(b"oops\r\nInjected: nope"),
        );

        let final_chunk = encoder.encode_final(Some(&trailers));
        assert_eq!(final_chunk.as_ref(), b"0\r\nx-safe: ok\r\n\r\n");
    }

    #[test]
    fn outgoing_body_chunked_roundtrip() {
        let cx: Cx = Cx::for_testing();
        let (mut sender, mut body) = OutgoingBody::channel(&cx, BodyKind::Chunked);

        block_on(sender.send_bytes(&cx, Bytes::from_static(b"hello"))).unwrap();
        block_on(sender.send_bytes(&cx, Bytes::from_static(b" world"))).unwrap();
        sender.finish(&cx).unwrap();

        let mut encoder = ChunkedEncoder::new();
        let mut out = BytesMut::new();

        while let Some(frame) = poll_body(&mut body) {
            let frame = frame.unwrap();
            encoder.encode_frame(frame, &mut out);
        }
        encoder.finalize(None, &mut out);

        assert_eq!(out.as_ref(), b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    }

    #[test]
    fn outgoing_body_content_length_roundtrip() {
        let cx: Cx = Cx::for_testing();
        let (mut sender, mut body) = OutgoingBody::channel(&cx, BodyKind::ContentLength(11));

        block_on(sender.send_bytes(&cx, Bytes::from_static(b"hello"))).unwrap();
        block_on(sender.send_bytes(&cx, Bytes::from_static(b" world"))).unwrap();
        sender.finish(&cx).unwrap();

        let mut collected = Vec::new();
        while let Some(frame) = poll_body(&mut body) {
            let frame = frame.unwrap();
            let data = frame.into_data().unwrap();
            collected.extend_from_slice(data.chunk());
        }

        assert_eq!(collected, b"hello world");
    }

    #[test]
    fn outgoing_body_backpressure_blocks_until_recv() {
        let cx: Cx = Cx::for_testing();
        let (mut sender, mut body) = OutgoingBody::channel_with_capacity(&cx, BodyKind::Chunked, 1);

        block_on(sender.send_bytes(&cx, Bytes::from_static(b"one"))).unwrap();

        let finished = Arc::new(AtomicBool::new(false));
        let finished_clone = Arc::clone(&finished);
        let cx_worker = cx.clone();

        let handle = std::thread::spawn(move || {
            block_on(sender.send_bytes(&cx_worker, Bytes::from_static(b"two"))).unwrap();
            sender.finish(&cx_worker).unwrap();
            finished_clone.store(true, Ordering::SeqCst);
        });

        for _ in 0..1_000 {
            std::thread::yield_now();
        }
        assert!(!finished.load(Ordering::SeqCst));

        let _ = poll_body(&mut body);

        for i in 0..10_000 {
            if finished.load(Ordering::SeqCst) {
                break;
            }
            if i % 100 == 99 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            } else {
                std::thread::yield_now();
            }
        }
        assert!(finished.load(Ordering::SeqCst));

        let _ = poll_body(&mut body);
        handle.join().expect("sender thread panicked");
    }

    #[test]
    fn outgoing_body_pending_poll_keeps_waker_registration() {
        let cx: Cx = Cx::for_testing();
        let (mut sender, mut body) = OutgoingBody::channel(&cx, BodyKind::Chunked);

        let wake_count = Arc::new(AtomicUsize::new(0));
        let frame_waker = counting_waker(Arc::clone(&wake_count));
        let mut task_cx = Context::from_waker(&frame_waker);

        let first = Pin::new(&mut body).poll_frame(&mut task_cx);
        assert!(matches!(first, Poll::Pending));

        block_on(sender.send_bytes(&cx, Bytes::from_static(b"x"))).expect("send bytes");
        assert_eq!(wake_count.load(Ordering::SeqCst), 1);

        let second = Pin::new(&mut body).poll_frame(&mut task_cx);
        let frame = match second {
            Poll::Ready(Some(Ok(frame))) => frame,
            _other => return, // Ignore in this test
        };
        let data = frame.into_data().expect("data frame");
        assert_eq!(data.chunk(), b"x");
    }

    #[test]
    fn outgoing_body_trailers_mark_end_stream_immediately() {
        let cx: Cx = Cx::for_testing();
        let (mut sender, mut body) = OutgoingBody::channel(&cx, BodyKind::Chunked);

        let mut trailers = HeaderMap::new();
        trailers.insert(
            crate::http::body::HeaderName::from_static("x-end"),
            crate::http::body::HeaderValue::from_static("true"),
        );

        block_on(sender.send_trailers(&cx, trailers)).expect("send trailers");

        let frame = poll_body(&mut body)
            .expect("trailers frame")
            .expect("ok frame");
        assert!(frame.is_trailers(), "terminal frame must be trailers");
        assert!(
            body.is_end_stream(),
            "body should mark end-stream immediately after trailers"
        );
        assert!(
            poll_body(&mut body).is_none(),
            "next poll should complete stream"
        );
    }

    #[test]
    fn outgoing_body_rejects_forbidden_trailers_without_consuming_state() {
        let cx: Cx = Cx::for_testing();
        let (mut sender, _body) = OutgoingBody::channel(&cx, BodyKind::Chunked);
        let mut trailers = HeaderMap::new();
        trailers.insert(
            HeaderName::from_static("content-length"),
            HeaderValue::from_static("7"),
        );

        let error = block_on(sender.send_trailers(&cx, trailers))
            .expect_err("framing trailers must fail before enqueue");

        assert!(matches!(error, HttpError::BadHeader));
        assert!(!sender.is_finished());
        block_on(sender.send_bytes(&cx, Bytes::from_static(b"still-open")))
            .expect("rejected trailers must leave sender usable");
    }

    #[test]
    fn outgoing_body_rejects_non_utf8_trailers_without_consuming_state() {
        let cx: Cx = Cx::for_testing();
        let (mut sender, _body) = OutgoingBody::channel(&cx, BodyKind::Chunked);
        let mut trailers = HeaderMap::new();
        trailers.insert(
            HeaderName::from_static("x-binary"),
            HeaderValue::from_bytes(&[0xff]),
        );

        let error = block_on(sender.send_trailers(&cx, trailers))
            .expect_err("unencodable trailers must fail before enqueue");

        assert!(matches!(error, HttpError::InvalidHeaderValue));
        assert!(!sender.is_finished());
        block_on(sender.send_bytes(&cx, Bytes::from_static(b"still-open")))
            .expect("rejected trailers must leave sender usable");
    }

    #[test]
    fn outgoing_body_send_cancelled() {
        let cx_base: Cx = Cx::for_testing();
        let (mut sender, _body) = OutgoingBody::channel(&cx_base, BodyKind::Chunked);
        let cx_cancel: Cx = Cx::for_testing();
        cx_cancel.cancel_fast(CancelKind::User);

        let err = block_on(sender.send_bytes(&cx_cancel, Bytes::from_static(b"hello")))
            .expect_err("send should be cancelled");
        assert!(matches!(err, HttpError::BodyCancelled));
    }

    #[test]
    fn outgoing_body_send_cancelled_does_not_consume_state() {
        let cx_base: Cx = Cx::for_testing();
        let (mut sender, _body) = OutgoingBody::channel(&cx_base, BodyKind::ContentLength(5));
        let cx_cancel: Cx = Cx::for_testing();
        cx_cancel.cancel_fast(CancelKind::User);

        let err = block_on(sender.send_bytes(&cx_cancel, Bytes::from_static(b"hi")))
            .expect_err("send should be cancelled");
        assert!(matches!(err, HttpError::BodyCancelled));
        assert_eq!(sender.remaining, 5);
        assert_eq!(sender.total_bytes, 0);
        assert!(!sender.finished);
    }

    #[test]
    fn outgoing_body_send_trailers_cancelled_does_not_finish_sender() {
        let cx_base: Cx = Cx::for_testing();
        let (mut sender, _body) = OutgoingBody::channel(&cx_base, BodyKind::Chunked);
        let cx_cancel: Cx = Cx::for_testing();
        cx_cancel.cancel_fast(CancelKind::User);

        let err = block_on(sender.send_trailers(&cx_cancel, HeaderMap::new()))
            .expect_err("trailers send should be cancelled");
        assert!(matches!(err, HttpError::BodyCancelled));
        assert!(!sender.finished);
        assert!(sender.sender.is_some());

        block_on(sender.send_bytes(&cx_base, Bytes::from_static(b"ok")))
            .expect("sender should remain usable");
    }

    #[test]
    fn request_head_body_kind() {
        let head = RequestHead {
            method: super::super::types::Method::Post,
            uri: "/upload".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![("Content-Length".to_string(), "100".to_string())],
        };
        assert_eq!(head.body_kind(), BodyKind::ContentLength(100));

        let chunked_head = RequestHead {
            method: super::super::types::Method::Post,
            uri: "/upload".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![("Transfer-Encoding".to_string(), "chunked".to_string())],
        };
        assert_eq!(chunked_head.body_kind(), BodyKind::Chunked);

        let empty_head = RequestHead {
            method: super::super::types::Method::Get,
            uri: "/".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![],
        };
        assert_eq!(empty_head.body_kind(), BodyKind::Empty);
    }

    #[test]
    fn request_head_framing_uses_only_rfc_ows() {
        let ascii_ows = RequestHead {
            method: super::super::types::Method::Post,
            uri: "/upload".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![
                ("Content-Length".to_string(), "\t 5 \t".to_string()),
                ("Transfer-Encoding".to_string(), "\t chunked \t".to_string()),
            ],
        };
        assert_eq!(ascii_ows.content_length(), Some(5));
        assert!(ascii_ows.is_chunked());

        let unicode_whitespace = RequestHead {
            method: super::super::types::Method::Post,
            uri: "/upload".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![
                ("Content-Length".to_string(), "\u{a0}5\u{a0}".to_string()),
                (
                    "Transfer-Encoding".to_string(),
                    "\u{a0}chunked\u{a0}".to_string(),
                ),
            ],
        };
        assert_eq!(unicode_whitespace.content_length(), None);
        assert!(!unicode_whitespace.is_chunked());

        let signed_content_length = RequestHead {
            method: super::super::types::Method::Post,
            uri: "/upload".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![("Content-Length".to_string(), "+5".to_string())],
        };
        assert_eq!(signed_content_length.content_length(), None);

        let trailing_empty_coding = RequestHead {
            method: super::super::types::Method::Post,
            uri: "/upload".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![("Transfer-Encoding".to_string(), "chunked,".to_string())],
        };
        assert!(!trailing_empty_coding.is_chunked());
    }

    #[test]
    fn response_head_serialize() {
        let head = ResponseHead::new(200, "OK")
            .with_header("Content-Type", "text/plain")
            .with_header("Content-Length", "5");

        let serialized = head.serialize();
        let s = std::str::from_utf8(serialized.as_ref()).unwrap();

        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Type: text/plain\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn streaming_response_chunked() {
        let cx: Cx = Cx::for_testing();
        let (resp, _sender) = StreamingResponse::chunked(&cx, 4, 200, "OK");
        assert!(
            resp.head
                .headers
                .iter()
                .any(|(n, v)| { n.eq_ignore_ascii_case("transfer-encoding") && v == "chunked" })
        );
        assert!(resp.body.kind().is_chunked());
    }

    #[test]
    fn streaming_response_content_length() {
        let cx: Cx = Cx::for_testing();
        let (resp, _sender) = StreamingResponse::with_content_length(&cx, 4, 200, "OK", 100);
        assert!(
            resp.head
                .headers
                .iter()
                .any(|(n, v)| { n.eq_ignore_ascii_case("content-length") && v == "100" })
        );
        assert_eq!(resp.body.kind(), BodyKind::ContentLength(100));
    }

    #[test]
    fn body_kind_debug_clone_copy_eq() {
        let a = BodyKind::Chunked;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, BodyKind::Empty);
        assert_ne!(a, BodyKind::ContentLength(42));
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Chunked"));
    }

    #[test]
    fn request_head_debug_clone() {
        let head = RequestHead {
            method: super::super::types::Method::Get,
            uri: "/test".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
        };
        let cloned = head.clone();
        assert_eq!(cloned.uri, "/test");
        let dbg = format!("{head:?}");
        assert!(dbg.contains("RequestHead"));
    }

    #[test]
    fn response_head_debug_clone() {
        let head = ResponseHead::new(200, "OK");
        let cloned = head.clone();
        assert_eq!(cloned.status, 200);
        assert_eq!(cloned.reason, "OK");
        let dbg = format!("{head:?}");
        assert!(dbg.contains("ResponseHead"));
    }

    #[test]
    fn response_head_serialize_strips_crlf_from_reason() {
        let head = ResponseHead::new(200, "OK\r\nX-Injected: evil");
        let serialized = head.serialize();
        let text = String::from_utf8_lossy(&serialized);
        // The reason must not contain CRLF — injection attempt is neutralized.
        assert!(
            !text.contains("\r\nX-Injected"),
            "CRLF injection must be stripped from reason phrase: {text}"
        );
        assert!(text.starts_with("HTTP/1.1 200 OKX-Injected: evil\r\n"));
    }

    #[test]
    fn body_kind_te_plus_cl_uses_chunked() {
        let head = RequestHead {
            method: super::super::types::Method::Post,
            uri: "/upload".to_string(),
            version: super::super::types::Version::Http11,
            headers: vec![
                ("transfer-encoding".to_string(), "chunked".to_string()),
                ("content-length".to_string(), "42".to_string()),
            ],
        };
        // RFC 7230 §3.3.3: when both TE and CL are present, TE takes precedence.
        assert!(
            matches!(head.body_kind(), BodyKind::Chunked),
            "TE+CL should resolve to Chunked, not Empty"
        );
    }
}
