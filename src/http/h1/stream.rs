//! HTTP/1 body streaming support.
//!
//! This module provides streaming body types for HTTP/1.1 that integrate with
//! asupersync's cancel-safety guarantees and backpressure mechanisms.
//!
//! # Overview
//!
//! - [`IncomingBody`]: Streaming reader for request/response bodies
//! - [`IncomingBodyWriter`]: Feeds bytes into an incoming body with backpressure
//! - [`OutgoingBody`]: Streaming writer-facing body (consumer reads frames)
//! - [`OutgoingBodySender`]: Sends body frames with backpressure + cancellation
//! - [`ChunkedEncoder`]: Encoder for HTTP/1.1 chunked transfer encoding
//! - [`BodyKind`]: Body length determination (fixed vs chunked)

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::bytes::{Buf, Bytes, BytesCursor, BytesMut};
use crate::channel::mpsc;
use crate::channel::mpsc::{RecvError, SendError};
use crate::cx::Cx;
use crate::http::body::{Body, Frame, HeaderMap, SizeHint};
use crate::http::h1::codec::HttpError;

const DEFAULT_MAX_BODY_SIZE: u64 = 16 * 1024 * 1024;
const DEFAULT_MAX_TRAILERS_SIZE: usize = 16 * 1024;
const DEFAULT_MAX_BUFFERED_BYTES: usize = 256 * 1024;
const DEFAULT_BODY_CHANNEL_CAPACITY: usize = 8;

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

/// Streaming incoming body receiver.
#[derive(Debug)]
pub struct IncomingBody {
    receiver: mpsc::Receiver<Result<Frame<BytesCursor>, HttpError>>,
    cx: Cx,
    done: bool,
    size_hint: SizeHint,
    kind: BodyKind,
}

impl IncomingBody {
    /// Creates a bounded incoming body channel.
    #[must_use]
    pub fn channel(cx: Cx, kind: BodyKind) -> (IncomingBodyWriter, IncomingBody) {
        Self::channel_with_capacity(cx, kind, DEFAULT_BODY_CHANNEL_CAPACITY)
    }

    /// Creates a bounded incoming body channel with custom capacity.
    #[must_use]
    pub fn channel_with_capacity(
        cx: Cx,
        kind: BodyKind,
        capacity: usize,
    ) -> (IncomingBodyWriter, IncomingBody) {
        let (tx, rx) = mpsc::channel(capacity);
        let size_hint = match kind {
            BodyKind::Empty => SizeHint::with_exact(0),
            BodyKind::ContentLength(n) => SizeHint::with_exact(n),
            BodyKind::Chunked => SizeHint::default(),
        };
        let done = kind.is_empty();
        let body = IncomingBody {
            receiver: rx,
            cx: cx.clone(),
            done,
            size_hint,
            kind,
        };
        let writer = IncomingBodyWriter::new(tx, kind);
        (writer, body)
    }

    /// Returns the body kind.
    #[must_use]
    pub fn kind(&self) -> BodyKind {
        self.kind
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

        let recv_future = self.receiver.recv(&self.cx);
        let mut pinned = std::pin::pin!(recv_future);
        match pinned.as_mut().poll(poll_cx) {
            Poll::Ready(Ok(frame)) => Poll::Ready(Some(frame)),
            Poll::Ready(Err(RecvError::Cancelled)) => {
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

/// Writer for feeding bytes into an incoming body.
#[derive(Debug)]
pub struct IncomingBodyWriter {
    sender: Option<mpsc::Sender<Result<Frame<BytesCursor>, HttpError>>>,
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
}

impl IncomingBodyWriter {
    fn new(sender: mpsc::Sender<Result<Frame<BytesCursor>, HttpError>>, kind: BodyKind) -> Self {
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
            buffer: BytesMut::with_capacity(8192),
            kind,
            remaining,
            chunked_state,
            trailers: HeaderMap::new(),
            trailers_bytes: 0,
            done,
            max_chunk_size: IncomingBodyWriter::DEFAULT_MAX_CHUNK_SIZE,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            max_trailers_size: DEFAULT_MAX_TRAILERS_SIZE,
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
            total_bytes: 0,
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

    /// Pushes raw bytes into the body stream.
    pub async fn push_bytes(&mut self, cx: &Cx, data: &[u8]) -> Result<(), HttpError> {
        if self.done {
            return Ok(());
        }

        if !data.is_empty() {
            self.buffer.extend_from_slice(data);
            if self.buffer.len() > self.max_buffered_bytes {
                return Err(HttpError::BodyTooLarge);
            }
        }

        self.drain_frames(cx).await
    }

    /// Signals EOF with no additional bytes.
    pub async fn finish(&mut self, _cx: &Cx) -> Result<(), HttpError> {
        if self.done {
            return Ok(());
        }

        if matches!(self.kind, BodyKind::ContentLength(_)) && self.remaining != 0 {
            return Err(HttpError::BadContentLength);
        }

        self.done = true;
        self.close_sender();
        Ok(())
    }

    async fn drain_frames(&mut self, cx: &Cx) -> Result<(), HttpError> {
        loop {
            let frame = match self.try_decode_frame()? {
                Some(frame) => frame,
                None => break,
            };
            self.send_frame(cx, frame).await?;
            if self.done {
                self.close_sender();
                break;
            }
        }

        if self.done {
            self.close_sender();
        }

        Ok(())
    }

    fn close_sender(&mut self) {
        self.sender.take();
    }

    async fn send_frame(&mut self, cx: &Cx, frame: Frame<BytesCursor>) -> Result<(), HttpError> {
        let Some(sender) = self.sender.as_ref() else {
            return Err(HttpError::BodyChannelClosed);
        };
        match sender.send(cx, Ok(frame)).await {
            Ok(()) => Ok(()),
            Err(SendError::Disconnected(_)) => Err(HttpError::BodyChannelClosed),
            Err(SendError::Cancelled(_)) => Err(HttpError::BodyCancelled),
            Err(SendError::Full(_)) => Err(HttpError::BodyChannelClosed),
        }
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

        let chunk = self.buffer.split_to(to_yield);
        self.remaining = self.remaining.saturating_sub(to_yield as u64);
        self.total_bytes = self.total_bytes.saturating_add(to_yield as u64);

        if self.total_bytes > self.max_body_size {
            return Err(HttpError::BodyTooLarge);
        }

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
                    let line_str =
                        std::str::from_utf8(line).map_err(|_| HttpError::BadChunkedEncoding)?;
                    let size_part = line_str.split(';').next().unwrap_or("").trim();
                    if size_part.is_empty() {
                        return Err(HttpError::BadChunkedEncoding);
                    }

                    let chunk_size = usize::from_str_radix(size_part, 16)
                        .map_err(|_| HttpError::BadChunkedEncoding)?;

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

                    let chunk = self.buffer.split_to(to_yield);
                    let remaining = remaining.saturating_sub(to_yield);
                    self.chunked_state = if remaining == 0 {
                        ChunkedReadState::DataCrlf
                    } else {
                        ChunkedReadState::Data { remaining }
                    };

                    self.total_bytes = self.total_bytes.saturating_add(to_yield as u64);
                    if self.total_bytes > self.max_body_size {
                        return Err(HttpError::BodyTooLarge);
                    }

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
                    if self.trailers_bytes + self.buffer.len() > self.max_trailers_size {
                        return Err(HttpError::HeadersTooLarge);
                    }

                    let line_end = self.buffer.as_ref().windows(2).position(|w| w == b"\r\n");
                    let Some(line_end) = line_end else {
                        return Ok(None);
                    };

                    let line = self.buffer.split_to(line_end);
                    let _ = self.buffer.split_to(2);

                    if line.is_empty() {
                        self.done = true;
                        self.chunked_state = ChunkedReadState::Done;
                        if !self.trailers.is_empty() {
                            return Ok(Some(Frame::Trailers(std::mem::take(&mut self.trailers))));
                        }
                        return Ok(None);
                    }

                    self.trailers_bytes = self.trailers_bytes.saturating_add(line.len() + 2);
                    if self.trailers_bytes > self.max_trailers_size {
                        return Err(HttpError::HeadersTooLarge);
                    }

                    let line_str =
                        std::str::from_utf8(line.as_ref()).map_err(|_| HttpError::BadHeader)?;
                    let Some(colon) = line_str.find(':') else {
                        return Err(HttpError::BadHeader);
                    };

                    let name = line_str[..colon].trim();
                    let value = line_str[colon + 1..].trim();
                    use crate::http::body::{HeaderName, HeaderValue};
                    self.trailers.append(
                        HeaderName::from_string(name),
                        HeaderValue::from_bytes(value.as_bytes()),
                    );
                }

                ChunkedReadState::Done => return Ok(None),
            }
        }
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
    pub fn encode_chunk(&self, data: &[u8]) -> BytesMut {
        let mut buf = BytesMut::with_capacity(data.len() + 32);
        self.encode_chunk_into(data, &mut buf);
        buf
    }

    fn encode_chunk_into(&self, data: &[u8], dst: &mut BytesMut) {
        let size_line = format!("{:X}\r\n", data.len());
        dst.extend_from_slice(size_line.as_bytes());
        dst.extend_from_slice(data);
        dst.extend_from_slice(b"\r\n");
    }

    /// Encodes the final chunk (zero-length) with optional trailers.
    pub fn encode_final(&mut self, trailers: Option<&HeaderMap>) -> BytesMut {
        let mut buf = BytesMut::with_capacity(256);
        let _ = self.encode_final_into(trailers, &mut buf);
        buf
    }

    fn encode_final_into(
        &mut self,
        trailers: Option<&HeaderMap>,
        dst: &mut BytesMut,
    ) -> Result<(), HttpError> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        dst.extend_from_slice(b"0\r\n");
        if let Some(trailers) = trailers {
            for (name, value) in trailers.iter() {
                dst.extend_from_slice(name.as_str().as_bytes());
                dst.extend_from_slice(b": ");
                dst.extend_from_slice(value.as_bytes());
                dst.extend_from_slice(b"\r\n");
            }
        }
        dst.extend_from_slice(b"\r\n");
        Ok(())
    }

    /// Encodes a body frame into chunked format.
    pub fn encode_frame<B: Buf>(
        &mut self,
        frame: Frame<B>,
        dst: &mut BytesMut,
    ) -> Result<(), HttpError> {
        match frame {
            Frame::Data(mut data) => {
                while data.remaining() > 0 {
                    let chunk = data.chunk();
                    if chunk.is_empty() {
                        break;
                    }
                    self.encode_chunk_into(chunk, dst);
                    data.advance(chunk.len());
                }
                Ok(())
            }
            Frame::Trailers(trailers) => self.encode_final_into(Some(&trailers), dst),
        }
    }

    /// Writes the final chunk if not already finished.
    pub fn finalize(
        &mut self,
        trailers: Option<&HeaderMap>,
        dst: &mut BytesMut,
    ) -> Result<(), HttpError> {
        self.encode_final_into(trailers, dst)
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
    pub fn channel(cx: Cx, kind: BodyKind) -> (OutgoingBodySender, OutgoingBody) {
        Self::channel_with_capacity(cx, kind, DEFAULT_BODY_CHANNEL_CAPACITY)
    }

    /// Creates a bounded outgoing body channel with custom capacity.
    #[must_use]
    pub fn channel_with_capacity(
        cx: Cx,
        kind: BodyKind,
        capacity: usize,
    ) -> (OutgoingBodySender, OutgoingBody) {
        let (tx, rx) = mpsc::channel(capacity);
        let size_hint = match kind {
            BodyKind::Empty => SizeHint::with_exact(0),
            BodyKind::ContentLength(n) => SizeHint::with_exact(n),
            BodyKind::Chunked => SizeHint::default(),
        };
        let body = OutgoingBody {
            receiver: rx,
            cx: cx.clone(),
            done: kind.is_empty(),
            size_hint,
            kind,
        };
        let sender = OutgoingBodySender::new(tx, kind);
        (sender, body)
    }

    /// Creates an empty outgoing body.
    #[must_use]
    pub fn empty(cx: Cx) -> Self {
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

        let recv_future = self.receiver.recv(&self.cx);
        let mut pinned = std::pin::pin!(recv_future);
        match pinned.as_mut().poll(poll_cx) {
            Poll::Ready(Ok(frame)) => Poll::Ready(Some(frame)),
            Poll::Ready(Err(RecvError::Cancelled)) => {
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
        if matches!(self.kind, BodyKind::ContentLength(_)) {
            if len > self.remaining {
                return Err(HttpError::BadContentLength);
            }
            self.remaining -= len;
        }
        self.total_bytes = self.total_bytes.saturating_add(len);
        self.send_frame(cx, Frame::Data(BytesCursor::new(data)))
            .await
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
        self.finished = true;
        self.send_frame(cx, Frame::Trailers(trailers)).await?;
        self.close_sender();
        Ok(())
    }

    /// Finishes the body (no trailers).
    pub async fn finish(&mut self, _cx: &Cx) -> Result<(), HttpError> {
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

    async fn send_frame(&mut self, cx: &Cx, frame: Frame<BytesCursor>) -> Result<(), HttpError> {
        let Some(sender) = self.sender.as_ref() else {
            return Err(HttpError::BodyChannelClosed);
        };
        match sender.send(cx, Ok(frame)).await {
            Ok(()) => Ok(()),
            Err(SendError::Disconnected(_)) => Err(HttpError::BodyChannelClosed),
            Err(SendError::Cancelled(_)) => Err(HttpError::BodyCancelled),
            Err(SendError::Full(_)) => Err(HttpError::BodyChannelClosed),
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
            .and_then(|(_, value)| value.parse().ok())
    }

    /// Returns true if Transfer-Encoding: chunked is set.
    #[must_use]
    pub fn is_chunked(&self) -> bool {
        self.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_lowercase().contains("chunked")
        })
    }

    /// Determines the body kind from headers.
    #[must_use]
    pub fn body_kind(&self) -> BodyKind {
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
    pub fn serialize(&self) -> BytesMut {
        let reason = if self.reason.is_empty() {
            super::types::default_reason(self.status)
        } else {
            &self.reason
        };

        let mut buf = BytesMut::with_capacity(256);
        let line = format!("{} {} {}\r\n", self.version, self.status, reason);
        buf.extend_from_slice(line.as_bytes());

        for (name, value) in &self.headers {
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }

        buf.extend_from_slice(b"\r\n");
        buf
    }
}

/// A streaming request with separate head and body.
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
    pub fn channel(
        head: RequestHead,
        cx: Cx,
        capacity: usize,
    ) -> (IncomingBodyWriter, StreamingRequest) {
        let (writer, body) = IncomingBody::channel_with_capacity(cx, head.body_kind(), capacity);
        (writer, StreamingRequest { head, body })
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

impl StreamingResponse {
    /// Creates a new streaming response with chunked encoding.
    #[must_use]
    pub fn chunked(
        cx: Cx,
        capacity: usize,
        status: u16,
        reason: impl Into<String>,
    ) -> (StreamingResponse, OutgoingBodySender) {
        let head = ResponseHead::new(status, reason).with_header("Transfer-Encoding", "chunked");
        let (sender, body) = OutgoingBody::channel_with_capacity(cx, BodyKind::Chunked, capacity);
        (StreamingResponse { head, body }, sender)
    }

    /// Creates a new streaming response with known Content-Length.
    #[must_use]
    pub fn with_content_length(
        cx: Cx,
        capacity: usize,
        status: u16,
        reason: impl Into<String>,
        length: u64,
    ) -> (StreamingResponse, OutgoingBodySender) {
        let head =
            ResponseHead::new(status, reason).with_header("Content-Length", length.to_string());
        let (sender, body) =
            OutgoingBody::channel_with_capacity(cx, BodyKind::ContentLength(length), capacity);
        (StreamingResponse { head, body }, sender)
    }

    /// Creates an empty response (no body).
    #[must_use]
    pub fn empty(cx: Cx, status: u16, reason: impl Into<String>) -> StreamingResponse {
        let head = ResponseHead::new(status, reason).with_header("Content-Length", "0");
        StreamingResponse {
            head,
            body: OutgoingBody::empty(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CancelKind;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::task::{Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
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

    fn poll_body<B: Body + Unpin>(
        body: &mut B,
    ) -> Option<Result<Frame<B::Data>, B::Error>> {
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
        let cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingBody::channel(cx.clone(), BodyKind::ContentLength(5));

        block_on(writer.push_bytes(&cx, b"hello")).expect("push bytes");

        let frame = poll_body(&mut body).unwrap().unwrap();
        let data = frame.into_data().unwrap();
        assert_eq!(data.chunk(), b"hello");
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_chunked_with_trailers() {
        let cx = Cx::for_testing();
        let (mut writer, mut body) = IncomingBody::channel(cx.clone(), BodyKind::Chunked);

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
    fn chunked_encoder_simple() {
        let encoder = ChunkedEncoder::new();
        let encoded = encoder.encode_chunk(b"hello");
        assert_eq!(encoded.as_ref(), b"5\r\nhello\r\n");
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
    fn outgoing_body_chunked_roundtrip() {
        let cx = Cx::for_testing();
        let (mut sender, mut body) = OutgoingBody::channel(cx.clone(), BodyKind::Chunked);

        block_on(sender.send_bytes(&cx, Bytes::from_static(b"hello"))).unwrap();
        block_on(sender.send_bytes(&cx, Bytes::from_static(b" world"))).unwrap();
        block_on(sender.finish(&cx)).unwrap();

        let mut encoder = ChunkedEncoder::new();
        let mut out = BytesMut::new();

        while let Some(frame) = poll_body(&mut body) {
            let frame = frame.unwrap();
            encoder.encode_frame(frame, &mut out).unwrap();
        }
        encoder.finalize(None, &mut out).unwrap();

        assert_eq!(out.as_ref(), b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    }

    #[test]
    fn outgoing_body_content_length_roundtrip() {
        let cx = Cx::for_testing();
        let (mut sender, mut body) = OutgoingBody::channel(cx.clone(), BodyKind::ContentLength(11));

        block_on(sender.send_bytes(&cx, Bytes::from_static(b"hello"))).unwrap();
        block_on(sender.send_bytes(&cx, Bytes::from_static(b" world"))).unwrap();
        block_on(sender.finish(&cx)).unwrap();

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
        let cx = Cx::for_testing();
        let (mut sender, mut body) =
            OutgoingBody::channel_with_capacity(cx.clone(), BodyKind::Chunked, 1);

        block_on(sender.send_bytes(&cx, Bytes::from_static(b"one"))).unwrap();

        let finished = Arc::new(AtomicBool::new(false));
        let finished_clone = Arc::clone(&finished);
        let cx_worker = cx.clone();

        let handle = std::thread::spawn(move || {
            block_on(sender.send_bytes(&cx_worker, Bytes::from_static(b"two"))).unwrap();
            block_on(sender.finish(&cx_worker)).unwrap();
            finished_clone.store(true, Ordering::SeqCst);
        });

        for _ in 0..1_000 {
            std::thread::yield_now();
        }
        assert!(!finished.load(Ordering::SeqCst));

        let _ = poll_body(&mut body);

        for _ in 0..10_000 {
            if finished.load(Ordering::SeqCst) {
                break;
            }
            std::thread::yield_now();
        }
        assert!(finished.load(Ordering::SeqCst));

        let _ = poll_body(&mut body);
        handle.join().expect("sender thread panicked");
    }

    #[test]
    fn outgoing_body_send_cancelled() {
        let cx = Cx::for_testing();
        let (mut sender, _body) = OutgoingBody::channel(cx.clone(), BodyKind::Chunked);
        cx.cancel_fast(CancelKind::User);

        let err = block_on(sender.send_bytes(&cx, Bytes::from_static(b"hello")))
            .expect_err("send should be cancelled");
        assert!(matches!(err, HttpError::BodyCancelled));
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
        let cx = Cx::for_testing();
        let (resp, _sender) = StreamingResponse::chunked(cx, 4, 200, "OK");
        assert!(resp
            .head
            .headers
            .iter()
            .any(|(n, v)| { n.eq_ignore_ascii_case("transfer-encoding") && v == "chunked" }));
        assert!(resp.body.kind().is_chunked());
    }

    #[test]
    fn streaming_response_content_length() {
        let cx = Cx::for_testing();
        let (resp, _sender) = StreamingResponse::with_content_length(cx, 4, 200, "OK", 100);
        assert!(resp
            .head
            .headers
            .iter()
            .any(|(n, v)| { n.eq_ignore_ascii_case("content-length") && v == "100" }));
        assert_eq!(resp.body.kind(), BodyKind::ContentLength(100));
    }
}
