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
    HttpError, find_chunk_size_line_end, is_forbidden_trailer, parse_chunk_size_line,
    parse_header_line, require_transfer_encoding_chunked, trim_ows, validate_header_field,
};
use crate::types::CancelKind;

#[cfg(not(target_arch = "wasm32"))]
mod obligation;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use obligation::IncomingBodyAdmissionError;
#[cfg(not(target_arch = "wasm32"))]
use obligation::IncomingBodyObligation;
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
))]
pub(crate) use obligation::FramedIncomingBodyGuard;

/// Chunk-extension bytes a request body may carry beyond its data bytes.
const CHUNK_EXTENSION_ALLOWANCE_BYTES: u64 = 16 * 1024;
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
    /// The client transport failed before synchronized body EOF.
    ClientAborted,
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
            Self::ClientAborted => write!(f, "request body client transport aborted"),
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
            Self::ClientAborted
            | Self::SourceDisconnected
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
    peak: usize,
    queued_frames: usize,
    frame_peak: usize,
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
                peak: 0,
                queued_frames: 0,
                frame_peak: 0,
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
        state.queued_frames = state
            .queued_frames
            .checked_sub(1)
            .expect("queued request-body frame accounting underflow");
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
            let Some(next_frames) = state.queued_frames.checked_add(1) else {
                drop(state);
                drop(incoming_waker);
                return self.finish_error(IncomingBodyError::AccountingOverflow);
            };

            if next <= budget.limit {
                state.queued = next;
                state.peak = state.peak.max(next);
                state.queued_frames = next_frames;
                state.frame_peak = state.frame_peak.max(next_frames);
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
    policy_max_body_size: AtomicU64,
    terminal_error: Mutex<Option<IncomingBodyError>>,
    queued_bytes: Arc<QueuedByteBudget>,
    abandoned_frames: AtomicU64,
    abandoned_bytes: AtomicU64,
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
    ))]
    framed_consumer_waker: Mutex<Option<Waker>>,
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
    ))]
    framed_consumer_error: Mutex<Option<IncomingBodyError>>,
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
    ))]
    framed_holder_waker: Mutex<Option<Waker>>,
    #[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
    framed_consumed_data: AtomicU64,
    #[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
    framed_consumed_waker: Mutex<Option<Waker>>,
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

    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
    ))]
    fn wake_framed_producer(&self) {
        let waker = self.framed_consumer_waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// The wire producer and the task-local owner share one terminal decision.
    /// Holding the error lock serializes that decision without putting any
    /// obligation settlement, channel operation, or waker callback under it.
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
    ))]
    fn set_framed_terminal(
        &self,
        result: Result<(), IncomingBodyError>,
    ) -> Result<(), IncomingBodyError> {
        let mut terminal_error = self.terminal_error.lock();
        match IncomingProducerTerminal::load(&self.producer_terminal) {
            IncomingProducerTerminal::Finished => Ok(()),
            IncomingProducerTerminal::Failed => Err(terminal_error
                .clone()
                .unwrap_or(IncomingBodyError::SourceDisconnected)),
            IncomingProducerTerminal::Open => {
                let terminal = match &result {
                    Ok(()) => IncomingProducerTerminal::Finished,
                    Err(error) => {
                        *terminal_error = Some(error.clone());
                        IncomingProducerTerminal::Failed
                    }
                };
                self.producer_terminal.store(terminal as u8, Ordering::Release);
                result
            }
        }
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
    ))]
    fn framed_terminal(&self) -> Option<Result<(), IncomingBodyError>> {
        let error = self.terminal_error.lock();
        match IncomingProducerTerminal::load(&self.producer_terminal) {
            IncomingProducerTerminal::Open => None,
            IncomingProducerTerminal::Finished => Some(Ok(())),
            IncomingProducerTerminal::Failed => Some(Err(error
                .clone()
                .unwrap_or(IncomingBodyError::SourceDisconnected))),
        }
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
    ))]
    fn wake_framed_holder(&self) {
        let waker = self.framed_holder_waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
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
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
    ))]
    framed: bool,
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
            policy_max_body_size: AtomicU64::new(u64::MAX),
            terminal_error: Mutex::new(None),
            queued_bytes: QueuedByteBudget::new(queued_byte_limit),
            abandoned_frames: AtomicU64::new(0),
            abandoned_bytes: AtomicU64::new(0),
            #[cfg(all(
                not(target_arch = "wasm32"),
                any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
            ))]
            framed_consumer_waker: Mutex::new(None),
            #[cfg(all(
                not(target_arch = "wasm32"),
                any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
            ))]
            framed_consumer_error: Mutex::new(None),
            #[cfg(all(
                not(target_arch = "wasm32"),
                any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
            ))]
            framed_holder_waker: Mutex::new(None),
            #[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
            framed_consumed_data: AtomicU64::new(0),
            #[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
            framed_consumed_waker: Mutex::new(None),
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
            #[cfg(all(
                not(target_arch = "wasm32"),
                any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
            ))]
            framed: false,
        };
        let writer = IncomingRequestBodyWriter::new(tx, kind, shared);
        (writer, body)
    }

    /// Admit a framed body under its actual request task after route policy.
    ///
    /// The protocol may retain the writer in a connection driver, but the
    /// returned guard must run the entire request task's body work. It owns
    /// the registered credit and settles it before that task retires, even if
    /// the driver has not observed a panic or cancellation yet. A declared
    /// zero length remains pending until the protocol explicitly finishes.
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
    ))]
    pub(crate) fn framed_channel_with_limits_checked(
        cx: &Cx,
        declared_length: Option<u64>,
        frame_capacity: usize,
        queued_byte_limit: usize,
        max_body_size: u64,
    ) -> Result<
        (FramedIncomingRequestBodyWriter, Self, FramedIncomingBodyGuard),
        IncomingBodyAdmissionError,
    > {
        if let Some(actual) = declared_length
            && actual > max_body_size
        {
            return Err(IncomingBodyAdmissionError::Policy(
                IncomingBodyError::BodyTooLarge {
                    actual: Some(actual),
                    limit: max_body_size,
                },
            ));
        }
        let obligation = IncomingBodyObligation::admit(cx)?;
        let (writer, body) = Self::framed_channel_with_limits(
            cx,
            declared_length,
            frame_capacity,
            queued_byte_limit,
        );
        body.tighten_max_body_size(max_body_size);
        let mut writer = writer.max_body_size(max_body_size);
        writer.checked_owner = Some(cx.clone());
        let guard = FramedIncomingBodyGuard::new(
            obligation,
            Arc::clone(&body.shared),
            writer.sender.as_ref().expect("new open framed body").downgrade(),
        );
        Ok((writer, body, guard))
    }

    /// Create a body only after transport and caller-selected static policy
    /// admission, with a checked credit owned by the actual request task.
    ///
    /// The writer must remain in that task until synchronized EOF or a
    /// terminal failure. Moving the consumer to a descendant does not move
    /// the writer's holder liability. Legacy constructors remain untracked.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn channel_with_limits_checked(
        cx: &Cx,
        kind: BodyKind,
        frame_capacity: usize,
        queued_byte_limit: usize,
        max_body_size: u64,
    ) -> Result<(IncomingRequestBodyWriter, Self), IncomingBodyAdmissionError> {
        if let Some(actual) = kind.exact_size()
            && actual > max_body_size
        {
            return Err(IncomingBodyAdmissionError::Policy(
                IncomingBodyError::BodyTooLarge {
                    actual: Some(actual),
                    limit: max_body_size,
                },
            ));
        }
        let mut obligation = IncomingBodyObligation::admit(cx)?;
        let (mut writer, body) =
            Self::channel_with_limits(cx, kind, frame_capacity, queued_byte_limit);
        body.tighten_max_body_size(max_body_size);
        writer.max_body_size = max_body_size;
        if kind.is_empty() {
            // A validated zero-length H1 body is already synchronized. It
            // still passes checked admission and settles that one credit.
            obligation.commit();
        } else {
            writer.obligation = Some(obligation);
        }
        Ok((writer, body))
    }

    /// Adapt already decoded protocol frames without parsing HTTP/1 bytes.
    ///
    /// Only the protocol driver's explicit `finish` publishes EOF. A declared
    /// length of zero, the last declared data byte, and trailers all remain
    /// open until that signal. The existing body-kind descriptor reports
    /// `ContentLength` when known and `Chunked` for unknown-length streaming;
    /// this adapter never interprets chunked transfer syntax.
    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
    ))]
    pub(crate) fn framed_channel_with_limits(
        cx: &Cx,
        declared_length: Option<u64>,
        frame_capacity: usize,
        queued_byte_limit: usize,
    ) -> (FramedIncomingRequestBodyWriter, Self) {
        // Construct an open channel even for Content-Length: 0. The ordinary
        // HTTP/1 constructor legitimately closes that case before any I/O.
        let (mut wire_writer, mut body) =
            Self::channel_with_limits(cx, BodyKind::Chunked, frame_capacity, queued_byte_limit);
        body.kind = declared_length.map_or(BodyKind::Chunked, BodyKind::ContentLength);
        body.size_hint = body.kind.size_hint();
        body.framed = true;
        let writer = FramedIncomingRequestBodyWriter {
            sender: wire_writer.sender.take(),
            shared: Arc::clone(&body.shared),
            checked_owner: None,
            pending: None,
            cancel_registration: None,
            declared_length,
            total_bytes: 0,
            trailers_sent: false,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            max_trailers_size: DEFAULT_MAX_TRAILERS_SIZE,
        };
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

    /// Returns the maximum queued request-body bytes retained so far.
    ///
    /// The high-water mark is updated under the same lock as byte-permit
    /// admission, before the bounded channel send. It therefore includes a
    /// producer frame whose send is pending behind a full frame queue and
    /// remains available after the consumer drains the queue.
    #[must_use]
    pub fn queued_bytes_peak(&self) -> usize {
        self.shared.queued_bytes.state.lock().peak
    }

    /// Returns the number of body frames holding producer-side queue permits.
    ///
    /// This includes a frame whose channel send is pending behind a full frame
    /// queue, matching the ownership boundary used by [`Self::queued_bytes`].
    #[must_use]
    pub fn queued_frames(&self) -> usize {
        self.shared.queued_bytes.state.lock().queued_frames
    }

    /// Returns the maximum number of producer-admitted body frames so far.
    ///
    /// A capacity-`N` channel can report `N + 1` here when one producer frame
    /// owns its queue permit while waiting for a consumer to free a slot.
    #[must_use]
    pub fn queued_frames_peak(&self) -> usize {
        self.shared.queued_bytes.state.lock().frame_peak
    }

    /// Tighten the aggregate body limit shared with the protocol writer.
    ///
    /// This is crate-private because application-facing policy is authored at
    /// the web Router boundary. The minimum is retained atomically so a nested
    /// route can never race an outer policy into a looser value.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn tighten_max_body_size(&self, bytes: u64) {
        self.shared
            .policy_max_body_size
            .fetch_min(bytes, Ordering::AcqRel);
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
    ))]
    fn record_framed_consumer_error(&self, error: IncomingBodyError) {
        if self.framed {
            self.shared
                .framed_consumer_error
                .lock()
                .get_or_insert(error);
        }
    }

    #[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
    fn record_framed_data_consumed(&self, bytes: u64) {
        if !self.framed || bytes == 0 {
            return;
        }
        // The sole consumer has already checked its cumulative received-byte
        // count. This undrained subset therefore cannot overflow that count.
        self.shared
            .framed_consumed_data
            .fetch_add(bytes, Ordering::AcqRel);
        let waker = self.shared.framed_consumed_waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
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
                #[cfg(all(
                    not(target_arch = "wasm32"),
                    any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
                ))]
                let trailers_finish = frame.is_trailers() && !self.framed;
                #[cfg(not(all(
                    not(target_arch = "wasm32"),
                    any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
                )))]
                let trailers_finish = frame.is_trailers();
                if trailers_finish {
                    // Trailers mark the end of a chunked body.
                    self.done = true;
                    self.size_hint = SizeHint::with_exact(0);
                } else if let Some(data) = frame.data_ref() {
                    let Ok(data_len) = u64::try_from(data.remaining()) else {
                        self.done = true;
                        self.size_hint = SizeHint::with_exact(0);
                        self.terminal_observed = true;
                        #[cfg(all(
                            not(target_arch = "wasm32"),
                            any(
                                feature = "http2-streaming",
                                all(feature = "http3", feature = "tls")
                            )
                        ))]
                        self.record_framed_consumer_error(IncomingBodyError::AccountingOverflow);
                        self.shared
                            .consumer_terminal
                            .store(IncomingConsumerTerminal::Failed as u8, Ordering::Release);
                        #[cfg(all(
                            not(target_arch = "wasm32"),
                            any(
                                feature = "http2-streaming",
                                all(feature = "http3", feature = "tls")
                            )
                        ))]
                        self.shared.wake_framed_producer();
                        return Poll::Ready(Some(Err(IncomingBodyError::AccountingOverflow)));
                    };
                    let Some(received) = self.received.checked_add(data_len) else {
                        self.done = true;
                        self.size_hint = SizeHint::with_exact(0);
                        self.terminal_observed = true;
                        #[cfg(all(
                            not(target_arch = "wasm32"),
                            any(
                                feature = "http2-streaming",
                                all(feature = "http3", feature = "tls")
                            )
                        ))]
                        self.record_framed_consumer_error(IncomingBodyError::AccountingOverflow);
                        self.shared
                            .consumer_terminal
                            .store(IncomingConsumerTerminal::Failed as u8, Ordering::Release);
                        #[cfg(all(
                            not(target_arch = "wasm32"),
                            any(
                                feature = "http2-streaming",
                                all(feature = "http3", feature = "tls")
                            )
                        ))]
                        self.shared.wake_framed_producer();
                        return Poll::Ready(Some(Err(IncomingBodyError::AccountingOverflow)));
                    };
                    let policy_limit = self.shared.policy_max_body_size.load(Ordering::Acquire);
                    if received > policy_limit {
                        self.done = true;
                        self.size_hint = SizeHint::with_exact(0);
                        self.terminal_observed = true;
                        #[cfg(all(
                            not(target_arch = "wasm32"),
                            any(
                                feature = "http2-streaming",
                                all(feature = "http3", feature = "tls")
                            )
                        ))]
                        self.record_framed_consumer_error(IncomingBodyError::BodyTooLarge {
                            actual: Some(received),
                            limit: policy_limit,
                        });
                        self.shared
                            .consumer_terminal
                            .store(IncomingConsumerTerminal::Failed as u8, Ordering::Release);
                        #[cfg(all(
                            not(target_arch = "wasm32"),
                            any(
                                feature = "http2-streaming",
                                all(feature = "http3", feature = "tls")
                            )
                        ))]
                        self.shared.wake_framed_producer();
                        return Poll::Ready(Some(Err(IncomingBodyError::BodyTooLarge {
                            actual: Some(received),
                            limit: policy_limit,
                        })));
                    }
                    if let BodyKind::ContentLength(expected) = self.kind {
                        if received > expected {
                            self.done = true;
                            self.size_hint = SizeHint::with_exact(0);
                            self.terminal_observed = true;
                            #[cfg(all(
                                not(target_arch = "wasm32"),
                                any(
                                    feature = "http2-streaming",
                                    all(feature = "http3", feature = "tls")
                                )
                            ))]
                            self.record_framed_consumer_error(IncomingBodyError::BadContentLength);
                            self.shared
                                .consumer_terminal
                                .store(IncomingConsumerTerminal::Failed as u8, Ordering::Release);
                            #[cfg(all(
                                not(target_arch = "wasm32"),
                                any(
                                    feature = "http2-streaming",
                                    all(feature = "http3", feature = "tls")
                                )
                            ))]
                            self.shared.wake_framed_producer();
                            return Poll::Ready(Some(Err(IncomingBodyError::BadContentLength)));
                        }
                        if received == expected {
                            self.done = true;
                            #[cfg(all(
                                not(target_arch = "wasm32"),
                                any(
                                    feature = "http2-streaming",
                                    all(feature = "http3", feature = "tls")
                                )
                            ))]
                            if self.framed {
                                self.done = false;
                            }
                        }
                        self.size_hint = SizeHint::with_exact(expected - received);
                    }
                    self.received = received;
                    #[cfg(all(feature = "http2-streaming", not(target_arch = "wasm32")))]
                    self.record_framed_data_consumed(data_len);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Err(RecvError::Cancelled)) => {
                let error = IncomingBodyError::cancelled(&self.cx);
                // The driver publishes a peer/reset/framing cause before
                // cancelling its owned handler. Preserve that earlier cause
                // instead of turning a concrete transport failure into the
                // subsequent region's generic cancellation classification.
                let error = if IncomingProducerTerminal::load(&self.shared.producer_terminal)
                    == IncomingProducerTerminal::Failed
                {
                    self.shared.terminal_error.lock().clone().unwrap_or(error)
                } else {
                    error
                };
                self.done = true;
                self.terminal_observed = true;
                self.size_hint = SizeHint::with_exact(0);
                #[cfg(all(
                    not(target_arch = "wasm32"),
                    any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
                ))]
                self.record_framed_consumer_error(error.clone());
                self.shared
                    .consumer_terminal
                    .store(IncomingConsumerTerminal::Failed as u8, Ordering::Release);
                #[cfg(all(
                    not(target_arch = "wasm32"),
                    any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
                ))]
                self.shared.wake_framed_producer();
                Poll::Ready(Some(Err(error)))
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
                        let error = self
                            .shared
                            .terminal_error
                            .lock()
                            .clone()
                            .unwrap_or(IncomingBodyError::SourceDisconnected);
                        #[cfg(all(
                            not(target_arch = "wasm32"),
                            any(
                                feature = "http2-streaming",
                                all(feature = "http3", feature = "tls")
                            )
                        ))]
                        self.record_framed_consumer_error(error.clone());
                        self.shared
                            .consumer_terminal
                            .store(IncomingConsumerTerminal::Failed as u8, Ordering::Release);
                        #[cfg(all(
                            not(target_arch = "wasm32"),
                            any(
                                feature = "http2-streaming",
                                all(feature = "http3", feature = "tls")
                            )
                        ))]
                        self.shared.wake_framed_producer();
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
        if self.done {
            return SizeHint::with_exact(0);
        }
        let policy_limit = self.shared.policy_max_body_size.load(Ordering::Acquire);
        let remaining_policy = policy_limit.saturating_sub(self.received);
        let mut hint = SizeHint::new();
        match self.size_hint.upper() {
            Some(upper) => hint.set_upper(upper.min(remaining_policy)),
            None if policy_limit != u64::MAX => hint.set_upper(remaining_policy),
            None => {}
        }
        hint.set_lower(self.size_hint.lower().min(remaining_policy));
        hint
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
            #[cfg(all(
                not(target_arch = "wasm32"),
                any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
            ))]
            self.shared.wake_framed_producer();
        }
    }
}

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
))]
type FramedIncomingSend =
    Pin<Box<dyn Future<Output = Result<(), IncomingBodyError>> + Send + 'static>>;

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
))]
struct FramedIncomingCancellation {
    cx: Cx,
    token: CancelWakerToken,
}

/// Bounded producer for protocol-validated DATA and trailers.
///
/// The listener owns this value; the handler only receives
/// [`IncomingRequestBody`]. One pending send retains its exact frame across
/// polls, so pausing a native request stream never requires replaying bytes.
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
))]
pub(crate) struct FramedIncomingRequestBodyWriter {
    sender: Option<mpsc::Sender<QueuedIncomingFrame>>,
    shared: Arc<IncomingBodyShared>,
    // A checked task can acknowledge cancellation and drop its body inside a
    // user poll before the guard observes that poll's return. The connection
    // driver must not classify that known cancellation as ordinary abandon.
    checked_owner: Option<Cx>,
    pending: Option<FramedIncomingSend>,
    cancel_registration: Option<FramedIncomingCancellation>,
    declared_length: Option<u64>,
    total_bytes: u64,
    trailers_sent: bool,
    max_body_size: u64,
    max_trailers_size: usize,
}

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
))]
impl std::fmt::Debug for FramedIncomingRequestBodyWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FramedIncomingRequestBodyWriter")
            .field("declared_length", &self.declared_length)
            .field("total_bytes", &self.total_bytes)
            .field("pending", &self.pending.is_some())
            .field("done", &self.is_done())
            .finish_non_exhaustive()
    }
}

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
))]
impl FramedIncomingRequestBodyWriter {
    #[must_use]
    pub(crate) fn max_body_size(mut self, bytes: u64) -> Self {
        self.max_body_size = bytes;
        self
    }

    #[must_use]
    pub(crate) fn max_trailers_size(mut self, bytes: usize) -> Self {
        self.max_trailers_size = bytes;
        self
    }

    #[must_use]
    pub(crate) fn is_done(&self) -> bool {
        IncomingProducerTerminal::load(&self.shared.producer_terminal)
            != IncomingProducerTerminal::Open
    }

    #[must_use]
    pub(crate) fn has_pending_frame(&self) -> bool {
        self.pending.is_some()
    }

    /// Whether the handler abandoned the body without first observing an error.
    #[must_use]
    pub(crate) fn consumer_dropped(&self) -> bool {
        self.shared.consumer_dropped()
    }

    fn consumer_drop_error(&self) -> IncomingBodyError {
        self.checked_owner
            .as_ref()
            .filter(|owner| owner.is_cancel_requested())
            .map_or(IncomingBodyError::ConsumerDropped, IncomingBodyError::cancelled)
    }

    /// Take the DATA bytes delivered to the consumer since the previous call.
    ///
    /// Register the connection driver's waker before draining the count so a
    /// concurrent consumer cannot lose a receive-window wakeup. Only frames
    /// successfully returned to the caller count: trailer metadata, rejected
    /// frames, and frames discarded on cancellation or body drop do not.
    /// Protocol drivers own any credit for padding or discarded stream data.
    ///
    /// This remains usable after `finish` or `fail` while accepted DATA drains.
    /// It has a separate waker from consumer-drop detection because finishing
    /// the wire body does not mean that its queued DATA has been consumed.
    #[cfg(feature = "http2-streaming")]
    pub(crate) fn poll_consumed_data(&self, task_cx: &mut Context<'_>) -> u64 {
        let mut incoming = Some(task_cx.waker().clone());
        let mut registered = self.shared.framed_consumed_waker.lock();
        let retired = if registered
            .as_ref()
            .is_some_and(|waker| waker.will_wake(task_cx.waker()))
        {
            None
        } else {
            std::mem::replace(&mut *registered, incoming.take())
        };
        let consumed = self.shared.framed_consumed_data.swap(0, Ordering::AcqRel);
        drop(registered);
        drop(retired);
        drop(incoming);
        consumed
    }

    /// Register the transport driver's waker even when no DATA send is pending.
    /// This makes an idle handler's early body drop stop receive promptly.
    /// A body failure returns its exact error, so a listener cannot mistake a
    /// caught validation error for an ordinary early response. A task guard's
    /// unfinished-input stop is also visible before a descendant consumes it;
    /// `ConsumerDropped` retains the ordinary early-response classification.
    pub(crate) fn poll_consumer_dropped(
        &self,
        task_cx: &mut Context<'_>,
    ) -> Poll<Result<(), IncomingBodyError>> {
        let mut incoming = Some(task_cx.waker().clone());
        let mut registered = self.shared.framed_consumer_waker.lock();
        let terminal = self.shared.consumer_terminal.load(Ordering::Acquire);
        let producer_failed = IncomingProducerTerminal::load(&self.shared.producer_terminal)
            == IncomingProducerTerminal::Failed;
        if producer_failed
            || terminal == IncomingConsumerTerminal::Dropped as u8
            || terminal == IncomingConsumerTerminal::Failed as u8
        {
            let result = if producer_failed {
                match self.terminal_error() {
                    IncomingBodyError::ConsumerDropped => Ok(()),
                    error => Err(error),
                }
            } else if terminal == IncomingConsumerTerminal::Failed as u8 {
                Err(self
                    .shared
                    .framed_consumer_error
                    .lock()
                    .clone()
                    .unwrap_or(IncomingBodyError::SourceDisconnected))
            } else {
                match self.consumer_drop_error() {
                    IncomingBodyError::ConsumerDropped => Ok(()),
                    error => Err(error),
                }
            };
            let retired = registered.take();
            drop(registered);
            drop(retired);
            drop(incoming);
            return Poll::Ready(result);
        }
        let retired = if registered
            .as_ref()
            .is_some_and(|waker| waker.will_wake(task_cx.waker()))
        {
            None
        } else {
            std::mem::replace(&mut *registered, incoming.take())
        };
        drop(registered);
        drop(retired);
        drop(incoming);
        Poll::Pending
    }

    fn terminal_error(&self) -> IncomingBodyError {
        self.shared
            .terminal_error
            .lock()
            .clone()
            .unwrap_or(IncomingBodyError::AlreadyTerminal)
    }

    fn refresh_cancellation(&mut self, cx: &Cx, waker: &Waker) {
        if let Some(registered) = &mut self.cancel_registration {
            registered.token = registered
                .cx
                .refresh_cancel_waker(Some(registered.token), waker);
        } else {
            self.cancel_registration = Some(FramedIncomingCancellation {
                cx: cx.clone(),
                token: cx.refresh_cancel_waker(None, waker),
            });
        }
    }

    fn clear_cancellation(&mut self) {
        if let Some(registered) = self.cancel_registration.take() {
            registered.cx.clear_cancel_waker(registered.token);
        }
    }

    fn validate_frame(&self, frame: &Frame<BytesCursor>) -> Result<u64, IncomingBodyError> {
        if self.trailers_sent {
            return Err(IncomingBodyError::BadHeader);
        }
        let retained_bytes = queued_frame_bytes(frame)?;
        if retained_bytes > self.shared.queued_bytes.limit {
            return Err(IncomingBodyError::QueueFrameTooLarge {
                actual: retained_bytes,
                limit: self.shared.queued_bytes.limit,
            });
        }
        match frame {
            Frame::Data(data) => {
                let bytes = u64::try_from(data.remaining())
                    .map_err(|_| IncomingBodyError::AccountingOverflow)?;
                let total = self
                    .total_bytes
                    .checked_add(bytes)
                    .ok_or(IncomingBodyError::AccountingOverflow)?;
                let limit = self
                    .max_body_size
                    .min(self.shared.policy_max_body_size.load(Ordering::Acquire));
                if total > limit {
                    return Err(IncomingBodyError::BodyTooLarge {
                        actual: Some(total),
                        limit,
                    });
                }
                if self.declared_length.is_some_and(|length| total > length) {
                    return Err(IncomingBodyError::BadContentLength);
                }
                Ok(total)
            }
            Frame::Trailers(trailers) => {
                if retained_bytes > self.max_trailers_size {
                    return Err(IncomingBodyError::TrailersTooLarge);
                }
                for (name, value) in trailers.iter() {
                    let value = value
                        .to_str()
                        .map_err(|_| IncomingBodyError::InvalidHeaderValue)?;
                    validate_header_field(name.as_str(), value).map_err(|error| {
                        IncomingBodyError::from_http_error(&error, self.max_body_size)
                    })?;
                    if is_forbidden_trailer(name.as_str()) {
                        return Err(IncomingBodyError::BadHeader);
                    }
                }
                Ok(self.total_bytes)
            }
        }
    }

    /// Start or continue one frame send without blocking the connection pump.
    ///
    /// The first poll takes `frame`; a pending send owns it until completion.
    /// Retry with the same now-empty slot and do not supply another frame until
    /// this returns `Ready`. Queue-byte and channel-capacity wakeups rearm the
    /// supplied transport-driver waker. A rejected frame remains in the slot.
    pub(crate) fn poll_send_frame(
        &mut self,
        cx: &Cx,
        task_cx: &mut Context<'_>,
        frame: &mut Option<Frame<BytesCursor>>,
    ) -> Poll<Result<(), IncomingBodyError>> {
        assert!(
            self.pending.is_none() || frame.is_none(),
            "a framed body send must complete before accepting another frame"
        );
        if self.is_done() {
            return Poll::Ready(Err(self.terminal_error()));
        }
        if let Poll::Ready(result) = self.poll_consumer_dropped(task_cx) {
            let error = result.err().unwrap_or(IncomingBodyError::ConsumerDropped);
            self.fail(error.clone());
            return Poll::Ready(Err(error));
        }
        if self.pending.is_none() && frame.is_none() {
            return Poll::Ready(Ok(()));
        }
        // The connection driver polls this send with the request's Cx. MPSC
        // normally relies on its owning task's cancellation wakeup, but that
        // task is not the connection driver. Retain an explicit registration
        // through both byte-credit waits and frame-capacity waits.
        self.refresh_cancellation(cx, task_cx.waker());
        if cx.checkpoint().is_err() {
            let error = IncomingBodyError::cancelled(cx);
            self.fail(error.clone());
            return Poll::Ready(Err(error));
        }
        if self.pending.is_none() {
            let Some(offered) = frame.as_ref() else {
                return Poll::Ready(Ok(()));
            };
            let total = match self.validate_frame(offered) {
                Ok(total) => total,
                Err(error) => {
                    self.fail(error.clone());
                    return Poll::Ready(Err(error));
                }
            };
            self.total_bytes = total;
            self.trailers_sent = offered.is_trailers();
            let frame = frame.take().expect("offered frame just validated");
            let retained_bytes =
                queued_frame_bytes(&frame).expect("validated frame has checked byte accounting");
            let sender = self.sender.as_ref().expect("open framed writer").clone();
            let shared = Arc::clone(&self.shared);
            let cx = cx.clone();
            self.pending = Some(Box::pin(async move {
                let byte_permit = shared.queued_bytes.reserve(&cx, retained_bytes).await?;
                let limit = shared.policy_max_body_size.load(Ordering::Acquire);
                if total > limit {
                    return Err(IncomingBodyError::BodyTooLarge {
                        actual: Some(total),
                        limit,
                    });
                }
                let queued = QueuedIncomingFrame {
                    frame,
                    _byte_permit: byte_permit,
                };
                match sender.send(&cx, queued).await {
                    Ok(()) => Ok(()),
                    Err(SendError::Disconnected(_) | SendError::Full(_)) => {
                        let error = shared.framed_consumer_error.lock().clone();
                        Err(error.unwrap_or(IncomingBodyError::ConsumerDropped))
                    }
                    Err(SendError::Cancelled(_)) => {
                        let error = shared.framed_consumer_error.lock().clone();
                        Err(error.unwrap_or_else(|| IncomingBodyError::cancelled(&cx)))
                    }
                }
            }));
        }
        match self
            .pending
            .as_mut()
            .expect("frame installed or send already pending")
            .as_mut()
            .poll(task_cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending.take();
                self.clear_cancellation();
                if let Err(error) = &result {
                    self.fail(error.clone());
                }
                Poll::Ready(result)
            }
        }
    }

    /// Certify protocol END_STREAM or FIN after the final pending frame completed.
    /// An in-flight frame is a caller sequencing error and remains retryable.
    pub(crate) fn finish(&mut self, cx: &Cx) -> Result<(), IncomingBodyError> {
        match IncomingProducerTerminal::load(&self.shared.producer_terminal) {
            IncomingProducerTerminal::Finished => return Ok(()),
            IncomingProducerTerminal::Failed => return Err(self.terminal_error()),
            IncomingProducerTerminal::Open => {}
        }
        if self.pending.is_some() {
            return Err(IncomingBodyError::AlreadyTerminal);
        }
        let policy_limit = self
            .max_body_size
            .min(self.shared.policy_max_body_size.load(Ordering::Acquire));
        let error = if let Some(error) = self.shared.framed_consumer_error.lock().clone() {
            Some(error)
        } else if cx.checkpoint().is_err() {
            Some(IncomingBodyError::cancelled(cx))
        } else if self.total_bytes > policy_limit {
            Some(IncomingBodyError::BodyTooLarge {
                actual: Some(self.total_bytes),
                limit: policy_limit,
            })
        } else if self.consumer_dropped() {
            Some(IncomingBodyError::ConsumerDropped)
        } else if self
            .declared_length
            .is_some_and(|length| length != self.total_bytes)
        {
            Some(IncomingBodyError::BadContentLength)
        } else {
            None
        };
        if let Some(error) = error {
            self.fail(error.clone());
            return Err(error);
        }
        if let Err(error) = self.shared.set_framed_terminal(Ok(())) {
            self.fail(error.clone());
            return Err(error);
        }
        let retired_waker = self.shared.framed_consumer_waker.lock().take();
        drop(retired_waker);
        self.clear_cancellation();
        self.sender.take();
        self.shared.wake_framed_holder();
        Ok(())
    }

    /// Preserve the first transport failure and release every pending permit.
    pub(crate) fn fail(&mut self, error: IncomingBodyError) {
        let error = if error == IncomingBodyError::ConsumerDropped {
            self.consumer_drop_error()
        } else {
            error
        };
        let _ = self.shared.set_framed_terminal(Err(error));
        let retired_waker = self.shared.framed_consumer_waker.lock().take();
        drop(retired_waker);
        self.clear_cancellation();
        self.pending.take();
        self.sender.take();
        self.shared.wake_framed_holder();
    }
}

#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "http2-streaming", all(feature = "http3", feature = "tls"))
))]
impl Drop for FramedIncomingRequestBodyWriter {
    fn drop(&mut self) {
        let error = self.checked_owner
            .as_ref()
            .filter(|owner| owner.is_cancel_requested())
            .map_or(IncomingBodyError::SourceDisconnected, IncomingBodyError::cancelled);
        self.fail(error);
        #[cfg(feature = "http2-streaming")]
        {
            let retired_waker = self.shared.framed_consumed_waker.lock().take();
            drop(retired_waker);
        }
    }
}

/// Writer for feeding bytes into a typed incoming request body.
#[derive(Debug)]
pub struct IncomingRequestBodyWriter {
    sender: Option<mpsc::Sender<QueuedIncomingFrame>>,
    shared: Arc<IncomingBodyShared>,
    #[cfg(not(target_arch = "wasm32"))]
    obligation: Option<IncomingBodyObligation>,
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
    /// Chunk-extension bytes received so far, bounded by `total_bytes` plus
    /// `CHUNK_EXTENSION_ALLOWANCE_BYTES`.
    chunk_extension_bytes: u64,
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
            #[cfg(not(target_arch = "wasm32"))]
            obligation: None,
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
            chunk_extension_bytes: 0,
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
        if self.synchronized_eof() {
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
            synchronized_eof: self.synchronized_eof(),
        }
    }

    fn synchronized_eof(&self) -> bool {
        self.done
            && IncomingProducerTerminal::load(&self.shared.producer_terminal)
                == IncomingProducerTerminal::Finished
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
            // br-asupersync-hw83se: the driver handed us these bytes because it
            // saw a live consumer, then called `push_bytes` rather than
            // `discard_bytes`; if the consumer dropped in that window, retain
            // the bytes (bounded by the buffer cap) so the driver's follow-up
            // `discard_bytes(&[])` can still decode this body's framing and the
            // start of the next pipelined request. Returning here without
            // buffering silently lost them and desynchronized the keep-alive
            // connection. Best-effort under the cap: an over-cap chunk is not
            // retained (the connection is closing regardless).
            if !data.is_empty()
                && self
                    .buffer
                    .len()
                    .checked_add(data.len())
                    .is_some_and(|total| total <= self.max_buffered_bytes)
            {
                self.buffer.extend_from_slice(data);
            }
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
        let completed = self
            .shared
            .producer_terminal
            .compare_exchange(
                IncomingProducerTerminal::Open as u8,
                IncomingProducerTerminal::Finished as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        #[cfg(not(target_arch = "wasm32"))]
        if completed
            && let Some(mut obligation) = self.obligation.take()
        {
            obligation.commit();
        }
        #[cfg(target_arch = "wasm32")]
        let _ = completed;
        self.sender.take();
    }

    fn fail_sender(&mut self, error: IncomingBodyError) {
        // The sole mutable writer selects the first terminal cause. Later
        // cancellation or drop must not replace a concrete framing failure.
        if IncomingProducerTerminal::load(&self.shared.producer_terminal)
            == IncomingProducerTerminal::Open
        {
            *self.shared.terminal_error.lock() = Some(error.clone());
            self.shared
                .producer_terminal
                .store(IncomingProducerTerminal::Failed as u8, Ordering::Release);
            #[cfg(not(target_arch = "wasm32"))]
            if let Some(mut obligation) = self.obligation.take() {
                obligation.abort(&error);
            }
        }
        self.done = true;
        self.sender.take();
    }

    /// Preserve a transport-selected terminal cause for the body consumer.
    ///
    /// This is crate-private because protocol drivers, rather than application
    /// code, own the authority to classify an underlying connection failure.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn fail(&mut self, error: IncomingBodyError) {
        self.fail_sender(error);
    }

    fn checked_total_bytes(&self, additional: usize) -> Result<u64, HttpError> {
        let additional = u64::try_from(additional).map_err(|_| HttpError::BodyTooLarge)?;
        let total = self
            .total_bytes
            .checked_add(additional)
            .ok_or(HttpError::BodyTooLarge)?;
        let max_body_size = self
            .max_body_size
            .min(self.shared.policy_max_body_size.load(Ordering::Acquire));
        if total > max_body_size {
            return Err(HttpError::BodyTooLargeDetailed {
                actual: total,
                limit: max_body_size,
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
                    let Some(line_end) = find_chunk_size_line_end(self.buffer.as_ref())? else {
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
                    // Extensions carry no body bytes, so the body limit never
                    // sees them. Bound them by the data received so far plus a
                    // fixed allowance, or each body byte could cost a client's
                    // peer a whole line of extensions (CVE-2024-22019).
                    let extension = line
                        .iter()
                        .position(|&byte| byte == b';')
                        .map_or(0, |start| line_end - start);
                    self.chunk_extension_bytes = self
                        .chunk_extension_bytes
                        .saturating_add(u64::try_from(extension).unwrap_or(u64::MAX));
                    if self.chunk_extension_bytes
                        > self
                            .total_bytes
                            .saturating_add(CHUNK_EXTENSION_ALLOWANCE_BYTES)
                    {
                        return Err(HttpError::BadChunkedEncoding);
                    }

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
        #[cfg(not(target_arch = "wasm32"))]
        let obligation_open = self.obligation.is_some();
        #[cfg(target_arch = "wasm32")]
        let obligation_open = false;
        if self.sender.is_some() || obligation_open {
            #[cfg(not(target_arch = "wasm32"))]
            let error = self.obligation.as_ref().map_or(
                IncomingBodyError::SourceDisconnected,
                IncomingBodyObligation::abandoned_error,
            );
            #[cfg(target_arch = "wasm32")]
            let error = IncomingBodyError::SourceDisconnected;
            // Consumer abandonment has already removed `sender`; the
            // protocol credit must survive until this drain-or-close edge.
            self.fail_sender(error);
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

/// Private allocation identity shared by exactly one outgoing channel pair.
#[derive(Debug)]
struct OutgoingBodyChannelIdentity;

/// Body receiver for outgoing streams.
#[derive(Debug)]
pub struct OutgoingBody {
    receiver: mpsc::Receiver<Result<Frame<BytesCursor>, HttpError>>,
    cx: Cx,
    // The native server validates sender/body pairing; browser callers retain
    // the same channel representation without that transport entry point.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    channel_identity: Arc<OutgoingBodyChannelIdentity>,
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
        Self::channel_with_capacity_and_frame_limit(cx, kind, capacity, None)
    }

    /// Creates a bounded outgoing body channel with custom frame capacity and
    /// an enforced maximum DATA-frame size.
    ///
    /// The limit is checked before a DATA frame enters the channel. It covers
    /// logical DATA payload bytes only: trailer allocations, shared [`Bytes`]
    /// backing capacity, framing/control metadata, and application-owned bytes
    /// before `send_bytes` are outside this limit.
    #[must_use]
    pub fn channel_with_capacity_and_max_frame_bytes(
        cx: &Cx,
        kind: BodyKind,
        capacity: usize,
        max_frame_bytes: NonZeroUsize,
    ) -> (OutgoingBodySender, Self) {
        Self::channel_with_capacity_and_frame_limit(cx, kind, capacity, Some(max_frame_bytes))
    }

    fn channel_with_capacity_and_frame_limit(
        cx: &Cx,
        kind: BodyKind,
        capacity: usize,
        max_frame_bytes: Option<NonZeroUsize>,
    ) -> (OutgoingBodySender, Self) {
        let (tx, rx) = mpsc::channel(capacity);
        let channel_identity = Arc::new(OutgoingBodyChannelIdentity);
        let body = Self {
            receiver: rx,
            cx: cx.clone(),
            channel_identity: Arc::clone(&channel_identity),
            done: kind.is_empty(),
            size_hint: kind.size_hint(),
            kind,
        };
        let sender = OutgoingBodySender::new(tx, channel_identity, kind, max_frame_bytes);
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

impl OutgoingBody {
    /// Polls the next frame, delivering frames the producer already committed
    /// before observing cancellation of the producer's context.
    ///
    /// A cancelled producer may still commit terminal protocol frames under a
    /// mask, such as gRPC status trailers. Cancellation stops production; it
    /// must not discard output that is already queued. Once nothing committed
    /// remains, this behaves exactly like [`Body::poll_frame`], including
    /// reporting a cancelled context as [`HttpError::BodyCancelled`].
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn poll_committed_frame(
        &mut self,
        poll_cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<BytesCursor>, HttpError>>> {
        if self.done {
            return Poll::Ready(None);
        }
        if let Some(frame) = self.take_committed_frame() {
            return Poll::Ready(Some(frame));
        }
        match Pin::new(&mut *self).poll_frame(poll_cx) {
            // A frame committed between the drain above and the cancelled
            // receive still precedes the cancellation.
            Poll::Ready(Some(Err(HttpError::BodyCancelled))) => Poll::Ready(Some(
                self.take_committed_frame()
                    .unwrap_or(Err(HttpError::BodyCancelled)),
            )),
            other => other,
        }
    }

    /// Reads the next frame once the producer has returned.
    ///
    /// Every frame the producer sent is queued by then, including terminal
    /// frames it committed under a mask after its context was cancelled. So
    /// this reads the queue without consulting that context, and ignores an
    /// earlier cancelled receive. `None` means the queue is empty: the body
    /// has ended.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn take_frame_after_producer_returned(
        &mut self,
    ) -> Option<Result<Frame<BytesCursor>, HttpError>> {
        let frame = self.take_committed_frame();
        if frame.is_none() {
            self.done = true;
        }
        frame
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    fn take_committed_frame(&mut self) -> Option<Result<Frame<BytesCursor>, HttpError>> {
        let frame = self.receiver.try_recv().ok()?;
        // Trailers are terminal for chunked bodies; any other frame leaves the
        // body open even if a cancelled receive already marked it done.
        self.done = matches!(&frame, Ok(frame) if frame.is_trailers());
        Some(frame)
    }
}

/// Sender for outgoing bodies.
#[derive(Debug)]
pub struct OutgoingBodySender {
    sender: Option<mpsc::Sender<Result<Frame<BytesCursor>, HttpError>>>,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    channel_identity: Arc<OutgoingBodyChannelIdentity>,
    kind: BodyKind,
    max_frame_bytes: Option<NonZeroUsize>,
    remaining: u64,
    total_bytes: u64,
    finished: bool,
}

impl OutgoingBodySender {
    fn new(
        sender: mpsc::Sender<Result<Frame<BytesCursor>, HttpError>>,
        channel_identity: Arc<OutgoingBodyChannelIdentity>,
        kind: BodyKind,
        max_frame_bytes: Option<NonZeroUsize>,
    ) -> Self {
        let remaining = match kind {
            BodyKind::ContentLength(n) => n,
            _ => 0,
        };
        let finished = kind.is_empty();
        let mut this = Self {
            sender: Some(sender),
            channel_identity,
            kind,
            max_frame_bytes,
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

    /// Returns whether this sender is the authoritative peer of `body`.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn is_peer_of(&self, body: &OutgoingBody) -> bool {
        Arc::ptr_eq(&self.channel_identity, &body.channel_identity)
    }

    /// Returns the total bytes sent.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Returns the configured DATA-frame ceiling, when one is enforced.
    #[must_use]
    pub fn max_frame_bytes(&self) -> Option<NonZeroUsize> {
        self.max_frame_bytes
    }

    /// Sends a Bytes chunk.
    pub async fn send_bytes(&mut self, cx: &Cx, data: Bytes) -> Result<(), HttpError> {
        if self.finished {
            return Err(HttpError::BodyChannelClosed);
        }
        if data.is_empty() {
            return Ok(());
        }

        if let Some(limit) = self.max_frame_bytes
            && data.len() > limit.get()
        {
            return Err(HttpError::BodyTooLargeDetailed {
                actual: u64::try_from(data.len()).unwrap_or(u64::MAX),
                limit: u64::try_from(limit.get()).unwrap_or(u64::MAX),
            });
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

/// A channel-bound HTTP/1.1 response and its supervised producer.
///
/// Construction records a response head, frame capacity, DATA-frame ceiling,
/// and producer factory. The server creates the [`StreamingResponse`] and
/// [`OutgoingBodySender`] as one pair under the authoritative request [`Cx`],
/// so callers cannot attach a producer to another channel or context. The
/// producer returns its sender on clean completion; the server accepts EOF only
/// when that sender reports [`OutgoingBodySender::is_finished`].
///
/// For a capacity of `N` and a frame ceiling of `M`, the supervised path keeps
/// a conservative bound of `(N + 2) * M` logical DATA bytes across the channel,
/// one pending send, the driver frame, and its wire-encoding buffer. This is
/// not a total heap or RSS bound: shared [`Bytes`] backing capacity, trailers,
/// framing/control metadata, and application-owned bytes before `send_bytes`
/// are excluded.
///
/// This low-level response is consumed by
/// [`crate::http::h1::Http1StreamingServer::serve_produced`]. It is additive to
/// the buffered web and HTTP/1 response APIs.
pub struct Http1ProducedResponse {
    head: ResponseHead,
    body_kind: BodyKind,
    capacity: NonZeroUsize,
    max_frame_bytes: NonZeroUsize,
    // Retain ownership (including captured-value Drop) on all targets; only
    // the native server starts the producer through `into_parts`.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    producer: Http1ProducedResponseFactory,
}

impl std::fmt::Debug for Http1ProducedResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http1ProducedResponse")
            .field("head", &self.head)
            .field("body_kind", &self.body_kind)
            .field("capacity", &self.capacity)
            .field("max_frame_bytes", &self.max_frame_bytes)
            .finish_non_exhaustive()
    }
}

impl Http1ProducedResponse {
    /// Default maximum DATA bytes accepted from one produced-response send.
    pub const DEFAULT_MAX_FRAME_BYTES: usize = 64 * 1024;

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
        Self::chunked_with_max_frame_bytes(
            capacity,
            NonZeroUsize::new(Self::DEFAULT_MAX_FRAME_BYTES)
                .expect("the default HTTP/1 produced frame limit is nonzero"),
            status,
            reason,
            producer,
        )
    }

    /// Create a supervised chunked response with an explicit DATA-frame limit.
    ///
    /// The selected limit is enforced before a frame enters the response body
    /// channel. Sending a larger frame fails with
    /// [`HttpError::BodyTooLargeDetailed`] and cannot emit that DATA or a clean
    /// chunk terminator.
    #[must_use]
    pub fn chunked_with_max_frame_bytes<P, Fut>(
        capacity: NonZeroUsize,
        max_frame_bytes: NonZeroUsize,
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
            body_kind: BodyKind::Chunked,
            capacity,
            max_frame_bytes,
            producer: Box::new(move |cx, sender| Box::pin(producer(cx, sender))),
        }
    }

    /// Create a fixed-length supervised response.
    ///
    /// The server owns the `Content-Length` header and writes produced DATA
    /// without chunk coding. The sender refuses an overrun before channel
    /// admission and refuses `finish` until exactly `length` bytes have been
    /// admitted. Producer errors after head commit close the connection, so a
    /// short body cannot be mistaken for a complete response.
    ///
    /// For a `HEAD` request, the listener preserves `Content-Length` as
    /// metadata for the corresponding `GET` representation and drops the
    /// factory without creating or polling the producer. A successful HEAD
    /// therefore does not prove that `length` bytes were produced.
    #[must_use]
    pub fn with_content_length<P, Fut>(
        capacity: NonZeroUsize,
        status: u16,
        reason: impl Into<String>,
        length: u64,
        producer: P,
    ) -> Self
    where
        P: FnOnce(Cx, OutgoingBodySender) -> Fut + Send + 'static,
        Fut: Future<Output = Result<OutgoingBodySender, HttpError>> + Send + 'static,
    {
        Self::with_content_length_and_max_frame_bytes(
            capacity,
            NonZeroUsize::new(Self::DEFAULT_MAX_FRAME_BYTES)
                .expect("the default HTTP/1 produced frame limit is nonzero"),
            status,
            reason,
            length,
            producer,
        )
    }

    /// Create a fixed-length response with an explicit DATA-frame limit.
    #[must_use]
    pub fn with_content_length_and_max_frame_bytes<P, Fut>(
        capacity: NonZeroUsize,
        max_frame_bytes: NonZeroUsize,
        status: u16,
        reason: impl Into<String>,
        length: u64,
        producer: P,
    ) -> Self
    where
        P: FnOnce(Cx, OutgoingBodySender) -> Fut + Send + 'static,
        Fut: Future<Output = Result<OutgoingBodySender, HttpError>> + Send + 'static,
    {
        let body_kind = BodyKind::ContentLength(length);
        let head =
            ResponseHead::new(status, reason).with_header("Content-Length", length.to_string());
        Self {
            head,
            body_kind,
            capacity,
            max_frame_bytes,
            producer: Box::new(move |cx, sender| Box::pin(producer(cx, sender))),
        }
    }

    /// Framing selected for this produced body.
    #[must_use]
    pub fn body_kind(&self) -> BodyKind {
        self.body_kind
    }

    /// Maximum DATA bytes admitted from one producer send.
    #[must_use]
    pub fn max_frame_bytes(&self) -> NonZeroUsize {
        self.max_frame_bytes
    }

    /// Maximum logical DATA payload bytes retained by this response pipeline.
    ///
    /// With channel capacity `N` and per-frame limit `M`, at most `N` DATA
    /// frames are queued, one is held by the producer's pending channel send,
    /// and one is held by the transport while its write or flush is pending.
    /// The resulting logical-DATA envelope is `(N + 2) * M` bytes.
    ///
    /// This is not a total heap or RSS bound: shared [`Bytes`] backing capacity,
    /// trailers, framing/control metadata, and application-owned bytes before
    /// `send_bytes` are excluded.
    #[must_use]
    pub fn max_retained_data_bytes(&self) -> u128 {
        let capacity = u128::try_from(self.capacity.get()).expect("usize fits in u128");
        let max_frame_bytes =
            u128::try_from(self.max_frame_bytes.get()).expect("usize fits in u128");
        (capacity + 2) * max_frame_bytes
    }

    /// Append one response header for validation and serialization by the server.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.head.headers.push((name.into(), value.into()));
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn into_head(self) -> ResponseHead {
        self.head
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn head_mut(&mut self) -> &mut ResponseHead {
        &mut self.head
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn into_parts(self, cx: &Cx) -> (StreamingResponse, Http1ProducedResponseFuture) {
        let (sender, body) = OutgoingBody::channel_with_capacity_and_max_frame_bytes(
            cx,
            self.body_kind,
            self.capacity.get(),
            self.max_frame_bytes,
        );
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
#[path = "stream_inline_tests.rs"]
mod tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "stream_obligation_inline_tests.rs"]
mod obligation_tests;
