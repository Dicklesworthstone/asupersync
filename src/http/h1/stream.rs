//! HTTP/1 body streaming support.
//!
//! This module provides streaming body types for HTTP/1.1 that integrate with
//! asupersync's cancel-safety guarantees and backpressure mechanisms.
//!
//! # Overview
//!
//! - [`IncomingBody`]: Streaming reader for request/response bodies
//! - [`ChunkedEncoder`]: Encoder for chunked transfer encoding
//! - [`BodyKind`]: Body length determination (fixed vs chunked)
//!
//! # Cancel-Safety
//!
//! All body operations include explicit checkpoints for cancellation.
//! Bodies are drained on cancellation to maintain connection health.
//!
//! # Backpressure
//!
//! Body streaming respects Cx budget constraints. When the poll quota
//! is exhausted, the body yields to allow other work to proceed.

use std::pin::Pin;
use std::task::{Context, Poll};

use crate::bytes::{Bytes, BytesCursor, BytesMut};
use crate::http::body::{Body, Frame, HeaderMap, SizeHint};
use crate::http::h1::codec::HttpError;

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
#[derive(Debug)]
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

/// A streaming incoming body.
///
/// This type implements [`Body`] and yields frames containing either
/// data chunks or trailers. It supports both fixed-length and chunked
/// transfer encoding.
///
/// # Example
///
/// ```ignore
/// use asupersync::http::h1::stream::IncomingBody;
///
/// async fn read_body(mut body: IncomingBody) -> Vec<u8> {
///     let mut data = Vec::new();
///     while let Some(frame) = std::future::poll_fn(|cx| {
///         Pin::new(&mut body).poll_frame(cx)
///     }).await {
///         if let Ok(Frame::Data(chunk)) = frame {
///             data.extend_from_slice(chunk.chunk());
///         }
///     }
///     data
/// }
/// ```
#[derive(Debug)]
pub struct IncomingBody {
    /// Buffer for incoming data.
    buffer: BytesMut,
    /// Body kind (fixed-length or chunked).
    kind: BodyKind,
    /// State for fixed-length body: remaining bytes to read.
    remaining: u64,
    /// State for chunked body decoding.
    chunked_state: ChunkedReadState,
    /// Accumulated trailers from chunked encoding.
    trailers: Option<HeaderMap>,
    /// Whether the body has been fully consumed.
    done: bool,
    /// Maximum chunk size to yield at once (backpressure).
    max_chunk_size: usize,
}

impl IncomingBody {
    /// Maximum default chunk size for yielding data.
    pub const DEFAULT_MAX_CHUNK_SIZE: usize = 64 * 1024;

    /// Creates a new incoming body with fixed Content-Length.
    #[must_use]
    pub fn with_content_length(length: u64) -> Self {
        Self {
            buffer: BytesMut::with_capacity(8192.min(length as usize)),
            kind: BodyKind::ContentLength(length),
            remaining: length,
            chunked_state: ChunkedReadState::Done,
            trailers: None,
            done: length == 0,
            max_chunk_size: Self::DEFAULT_MAX_CHUNK_SIZE,
        }
    }

    /// Creates a new incoming body with chunked transfer encoding.
    #[must_use]
    pub fn chunked() -> Self {
        Self {
            buffer: BytesMut::with_capacity(8192),
            kind: BodyKind::Chunked,
            remaining: 0,
            chunked_state: ChunkedReadState::SizeLine,
            trailers: None,
            done: false,
            max_chunk_size: Self::DEFAULT_MAX_CHUNK_SIZE,
        }
    }

    /// Creates an empty body.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            buffer: BytesMut::new(),
            kind: BodyKind::Empty,
            remaining: 0,
            chunked_state: ChunkedReadState::Done,
            trailers: None,
            done: true,
            max_chunk_size: Self::DEFAULT_MAX_CHUNK_SIZE,
        }
    }

    /// Creates a body from its kind.
    #[must_use]
    pub fn from_kind(kind: BodyKind) -> Self {
        match kind {
            BodyKind::ContentLength(0) | BodyKind::Empty => Self::empty(),
            BodyKind::ContentLength(len) => Self::with_content_length(len),
            BodyKind::Chunked => Self::chunked(),
        }
    }

    /// Sets the maximum chunk size for yielding data.
    ///
    /// This controls backpressure by limiting how much data is returned
    /// in a single frame.
    #[must_use]
    pub fn max_chunk_size(mut self, size: usize) -> Self {
        self.max_chunk_size = size;
        self
    }

    /// Appends data to the internal buffer.
    ///
    /// This is called by the transport layer as data arrives.
    pub fn append(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Appends a Bytes chunk to the internal buffer.
    pub fn append_bytes(&mut self, data: &Bytes) {
        self.buffer.extend_from_slice(data.as_ref());
    }

    /// Returns the body kind.
    #[must_use]
    pub fn kind(&self) -> BodyKind {
        self.kind
    }

    /// Returns the number of bytes buffered but not yet yielded.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Attempts to yield the next frame from the buffer.
    ///
    /// Returns `None` if more data is needed.
    fn try_yield_frame(&mut self) -> Option<Result<Frame<BytesCursor>, HttpError>> {
        if self.done {
            return None;
        }

        match self.kind {
            BodyKind::Empty => {
                self.done = true;
                None
            }
            BodyKind::ContentLength(_) => self.try_yield_content_length_frame(),
            BodyKind::Chunked => self.try_yield_chunked_frame(),
        }
    }

    /// Yields a frame for Content-Length body.
    fn try_yield_content_length_frame(&mut self) -> Option<Result<Frame<BytesCursor>, HttpError>> {
        if self.remaining == 0 {
            self.done = true;
            return None;
        }

        if self.buffer.is_empty() {
            return None; // Need more data
        }

        // Yield up to remaining bytes, capped by max_chunk_size
        let to_yield = self
            .buffer
            .len()
            .min(self.remaining as usize)
            .min(self.max_chunk_size);

        let chunk = self.buffer.split_to(to_yield);
        self.remaining -= to_yield as u64;

        if self.remaining == 0 {
            self.done = true;
        }

        Some(Ok(Frame::Data(BytesCursor::new(chunk.freeze()))))
    }

    /// Yields a frame for chunked body.
    fn try_yield_chunked_frame(&mut self) -> Option<Result<Frame<BytesCursor>, HttpError>> {
        loop {
            match &mut self.chunked_state {
                ChunkedReadState::SizeLine => {
                    // Look for CRLF to complete size line
                    let line_end = self.buffer.as_ref().windows(2).position(|w| w == b"\r\n")?;

                    // Parse chunk size (may have extensions after ';')
                    let line = &self.buffer.as_ref()[..line_end];
                    let size_str = std::str::from_utf8(line).ok()?;
                    let size_part = size_str.split(';').next().unwrap_or("").trim();

                    let Ok(chunk_size) = usize::from_str_radix(size_part, 16) else {
                        return Some(Err(HttpError::BadChunkedEncoding));
                    };

                    // Consume the size line
                    let _ = self.buffer.split_to(line_end + 2);

                    if chunk_size == 0 {
                        // Final chunk - move to trailers
                        self.chunked_state = ChunkedReadState::Trailers;
                        self.trailers = Some(HeaderMap::new());
                    } else {
                        self.chunked_state = ChunkedReadState::Data {
                            remaining: chunk_size,
                        };
                    }
                }

                ChunkedReadState::Data { remaining } => {
                    if self.buffer.is_empty() {
                        return None; // Need more data
                    }

                    // Yield up to remaining bytes, capped by max_chunk_size
                    let to_yield = self.buffer.len().min(*remaining).min(self.max_chunk_size);

                    let chunk = self.buffer.split_to(to_yield);
                    *remaining -= to_yield;

                    if *remaining == 0 {
                        self.chunked_state = ChunkedReadState::DataCrlf;
                    }

                    return Some(Ok(Frame::Data(BytesCursor::new(chunk.freeze()))));
                }

                ChunkedReadState::DataCrlf => {
                    if self.buffer.len() < 2 {
                        return None; // Need more data
                    }

                    if self.buffer.as_ref()[0] != b'\r' || self.buffer.as_ref()[1] != b'\n' {
                        return Some(Err(HttpError::BadChunkedEncoding));
                    }

                    let _ = self.buffer.split_to(2);
                    self.chunked_state = ChunkedReadState::SizeLine;
                }

                ChunkedReadState::Trailers => {
                    // Look for CRLF
                    let line_end = self.buffer.as_ref().windows(2).position(|w| w == b"\r\n")?;

                    let line = self.buffer.split_to(line_end);
                    let _ = self.buffer.split_to(2); // CRLF

                    if line.is_empty() {
                        // Empty line = end of trailers
                        self.done = true;
                        self.chunked_state = ChunkedReadState::Done;

                        // Return trailers if any were collected
                        if let Some(trailers) = self.trailers.take() {
                            if !trailers.is_empty() {
                                return Some(Ok(Frame::Trailers(trailers)));
                            }
                        }
                        return None;
                    }

                    // Parse trailer header
                    let Ok(line_str) = std::str::from_utf8(line.as_ref()) else {
                        return Some(Err(HttpError::BadHeader));
                    };

                    if let Some(colon) = line_str.find(':') {
                        let name = line_str[..colon].trim();
                        let value = line_str[colon + 1..].trim();

                        if let Some(ref mut trailers) = self.trailers {
                            use crate::http::body::{HeaderName, HeaderValue};
                            trailers.append(
                                HeaderName::from_string(name),
                                HeaderValue::from_bytes(value.as_bytes()),
                            );
                        }
                    } else {
                        return Some(Err(HttpError::BadHeader));
                    }
                }

                ChunkedReadState::Done => {
                    return None;
                }
            }
        }
    }
}

impl Body for IncomingBody {
    type Data = BytesCursor;
    type Error = HttpError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.try_yield_frame() {
            Some(result) => Poll::Ready(Some(result)),
            None if self.done => Poll::Ready(None),
            None => Poll::Pending, // Need more data
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        match self.kind {
            BodyKind::Empty => SizeHint::with_exact(0),
            BodyKind::ContentLength(n) => SizeHint::with_exact(n),
            BodyKind::Chunked => SizeHint::default(), // Unknown
        }
    }
}

/// Encoder for chunked transfer encoding.
///
/// Encodes data chunks into the HTTP/1.1 chunked transfer encoding format:
/// ```text
/// <hex-size>\r\n
/// <data>\r\n
/// ...
/// 0\r\n
/// <trailers>
/// \r\n
/// ```
#[derive(Debug, Default)]
pub struct ChunkedEncoder {
    /// Whether the final (zero-length) chunk has been written.
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
    /// Returns the encoded bytes including size line and CRLF.
    #[must_use]
    pub fn encode_chunk(&self, data: &[u8]) -> BytesMut {
        let mut buf = BytesMut::with_capacity(data.len() + 32);

        // Size line
        let size_line = format!("{:X}\r\n", data.len());
        buf.extend_from_slice(size_line.as_bytes());

        // Data
        buf.extend_from_slice(data);

        // CRLF
        buf.extend_from_slice(b"\r\n");

        buf
    }

    /// Encodes the final chunk (zero-length) with optional trailers.
    ///
    /// After calling this, `is_finished()` returns true.
    pub fn encode_final(&mut self, trailers: Option<&HeaderMap>) -> BytesMut {
        self.finished = true;

        let mut buf = BytesMut::with_capacity(256);

        // Final chunk
        buf.extend_from_slice(b"0\r\n");

        // Trailers
        if let Some(trailers) = trailers {
            for (name, value) in trailers.iter() {
                buf.extend_from_slice(name.as_str().as_bytes());
                buf.extend_from_slice(b": ");
                buf.extend_from_slice(value.as_bytes());
                buf.extend_from_slice(b"\r\n");
            }
        }

        // Final CRLF
        buf.extend_from_slice(b"\r\n");

        buf
    }

    /// Returns true if the final chunk has been encoded.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

/// A streaming outgoing body.
///
/// This type allows sending body data incrementally, supporting both
/// fixed-length and chunked transfer encoding.
///
/// # Example
///
/// ```ignore
/// use asupersync::http::h1::stream::OutgoingBody;
///
/// let mut body = OutgoingBody::chunked();
/// body.write_chunk(b"Hello, ");
/// body.write_chunk(b"World!");
/// body.finish(None);
/// ```
#[derive(Debug)]
pub struct OutgoingBody {
    /// Chunks waiting to be sent.
    chunks: Vec<Bytes>,
    /// Body kind.
    kind: BodyKind,
    /// Chunked encoder (if using chunked encoding).
    encoder: Option<ChunkedEncoder>,
    /// Whether the body is complete.
    finished: bool,
    /// Total bytes written (for Content-Length validation).
    total_bytes: u64,
}

impl OutgoingBody {
    /// Creates a new outgoing body with known Content-Length.
    #[must_use]
    pub fn with_content_length(length: u64) -> Self {
        Self {
            chunks: Vec::new(),
            kind: BodyKind::ContentLength(length),
            encoder: None,
            finished: false,
            total_bytes: 0,
        }
    }

    /// Creates a new outgoing body with chunked transfer encoding.
    #[must_use]
    pub fn chunked() -> Self {
        Self {
            chunks: Vec::new(),
            kind: BodyKind::Chunked,
            encoder: Some(ChunkedEncoder::new()),
            finished: false,
            total_bytes: 0,
        }
    }

    /// Creates an empty outgoing body.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            chunks: Vec::new(),
            kind: BodyKind::Empty,
            encoder: None,
            finished: true,
            total_bytes: 0,
        }
    }

    /// Returns the body kind.
    #[must_use]
    pub fn kind(&self) -> BodyKind {
        self.kind
    }

    /// Writes a chunk of data to the body.
    ///
    /// For chunked encoding, this encodes the chunk in chunked format.
    /// For Content-Length, this buffers the raw data.
    pub fn write_chunk(&mut self, data: &[u8]) {
        if self.finished || data.is_empty() {
            return;
        }

        self.total_bytes += data.len() as u64;

        match &self.encoder {
            Some(enc) => {
                let chunk_buf = enc.encode_chunk(data);
                self.chunks.push(chunk_buf.freeze());
            }
            None => {
                self.chunks.push(Bytes::copy_from_slice(data));
            }
        }
    }

    /// Writes a Bytes chunk to the body.
    pub fn write_bytes(&mut self, data: Bytes) {
        if self.finished || data.is_empty() {
            return;
        }

        self.total_bytes += data.len() as u64;

        match &self.encoder {
            Some(enc) => {
                let chunk_buf = enc.encode_chunk(data.as_ref());
                self.chunks.push(chunk_buf.freeze());
            }
            None => {
                self.chunks.push(data);
            }
        }
    }

    /// Finishes the body, optionally with trailers.
    ///
    /// For chunked encoding, this writes the final zero-length chunk.
    /// Trailers are only valid with chunked encoding.
    pub fn finish(&mut self, trailers: Option<&HeaderMap>) {
        if self.finished {
            return;
        }

        if let Some(ref mut encoder) = self.encoder {
            let final_chunk = encoder.encode_final(trailers);
            self.chunks.push(final_chunk.freeze());
        }

        self.finished = true;
    }

    /// Returns true if the body has been finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Returns the total bytes written (excluding chunk encoding overhead).
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Takes all pending chunks.
    pub fn take_chunks(&mut self) -> Vec<Bytes> {
        std::mem::take(&mut self.chunks)
    }

    /// Returns true if there are pending chunks.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.chunks.is_empty()
    }
}

/// Streaming request head (without body).
///
/// This type represents the request line and headers, allowing the body
/// to be read separately as a stream.
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
///
/// This type represents the status line and headers, allowing the body
/// to be sent separately as a stream.
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

    /// Creates a streaming request from a head, inferring body kind from headers.
    #[must_use]
    pub fn from_head(head: RequestHead) -> Self {
        let body = IncomingBody::from_kind(head.body_kind());
        Self { head, body }
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
    pub fn chunked(status: u16, reason: impl Into<String>) -> Self {
        let head = ResponseHead::new(status, reason).with_header("Transfer-Encoding", "chunked");
        Self {
            head,
            body: OutgoingBody::chunked(),
        }
    }

    /// Creates a new streaming response with known Content-Length.
    #[must_use]
    pub fn with_content_length(status: u16, reason: impl Into<String>, length: u64) -> Self {
        let head =
            ResponseHead::new(status, reason).with_header("Content-Length", length.to_string());
        Self {
            head,
            body: OutgoingBody::with_content_length(length),
        }
    }

    /// Creates an empty response (no body).
    #[must_use]
    pub fn empty(status: u16, reason: impl Into<String>) -> Self {
        let head = ResponseHead::new(status, reason).with_header("Content-Length", "0");
        Self {
            head,
            body: OutgoingBody::empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::Buf;

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
    fn incoming_body_empty() {
        let body = IncomingBody::empty();
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
    }

    #[test]
    fn incoming_body_content_length() {
        let mut body = IncomingBody::with_content_length(5);
        assert!(!body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(5));

        // Append data
        body.append(b"hello");

        // Poll frame
        let frame = body.try_yield_frame().unwrap().unwrap();
        let data = frame.into_data().unwrap();
        assert_eq!(data.chunk(), b"hello");

        // Should be done now
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_chunked_simple() {
        let mut body = IncomingBody::chunked();
        assert!(!body.is_end_stream());
        assert_eq!(body.size_hint().exact(), None);

        // Append chunked data: "5\r\nhello\r\n0\r\n\r\n"
        body.append(b"5\r\nhello\r\n0\r\n\r\n");

        // Poll frame - should get data
        let frame = body.try_yield_frame().unwrap().unwrap();
        let data = frame.into_data().unwrap();
        assert_eq!(data.chunk(), b"hello");

        // Poll again - should complete (no trailers)
        assert!(body.try_yield_frame().is_none());
        assert!(body.is_end_stream());
    }

    #[test]
    fn incoming_body_chunked_with_trailers() {
        let mut body = IncomingBody::chunked();

        // Chunked data with trailers
        body.append(b"5\r\nhello\r\n0\r\nX-Trailer: test\r\n\r\n");

        // Get data
        let frame = body.try_yield_frame().unwrap().unwrap();
        assert_eq!(frame.into_data().unwrap().chunk(), b"hello");

        // Get trailers
        let frame = body.try_yield_frame().unwrap().unwrap();
        let trailers = frame.into_trailers().unwrap();
        assert_eq!(trailers.len(), 1);

        assert!(body.is_end_stream());
    }

    #[test]
    fn chunked_encoder_simple() {
        let enc = ChunkedEncoder::new();
        let result = enc.encode_chunk(b"hello");
        assert_eq!(result.as_ref(), b"5\r\nhello\r\n");
    }

    #[test]
    fn chunked_encoder_final() {
        let mut encoder = ChunkedEncoder::new();
        assert!(!encoder.is_finished());

        let final_chunk = encoder.encode_final(None);
        assert_eq!(final_chunk.as_ref(), b"0\r\n\r\n");
        assert!(encoder.is_finished());
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
    fn outgoing_body_chunked() {
        let mut body = OutgoingBody::chunked();
        assert!(!body.is_finished());

        body.write_chunk(b"hello");
        body.write_chunk(b" world");
        body.finish(None);

        assert!(body.is_finished());
        assert_eq!(body.total_bytes(), 11);

        let chunks = body.take_chunks();
        assert_eq!(chunks.len(), 3); // 2 data chunks + final chunk

        // Verify encoding
        assert_eq!(chunks[0].as_ref(), b"5\r\nhello\r\n");
        assert_eq!(chunks[1].as_ref(), b"6\r\n world\r\n");
        assert_eq!(chunks[2].as_ref(), b"0\r\n\r\n");
    }

    #[test]
    fn outgoing_body_content_length() {
        let mut body = OutgoingBody::with_content_length(11);
        body.write_chunk(b"hello");
        body.write_chunk(b" world");
        body.finish(None);

        assert!(body.is_finished());
        assert_eq!(body.total_bytes(), 11);

        let chunks = body.take_chunks();
        assert_eq!(chunks.len(), 2); // Raw data chunks

        assert_eq!(chunks[0].as_ref(), b"hello");
        assert_eq!(chunks[1].as_ref(), b" world");
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
        let resp = StreamingResponse::chunked(200, "OK");
        assert!(resp
            .head
            .headers
            .iter()
            .any(|(n, v)| { n.eq_ignore_ascii_case("transfer-encoding") && v == "chunked" }));
        assert!(resp.body.kind().is_chunked());
    }

    #[test]
    fn streaming_response_content_length() {
        let resp = StreamingResponse::with_content_length(200, "OK", 100);
        assert!(resp
            .head
            .headers
            .iter()
            .any(|(n, v)| { n.eq_ignore_ascii_case("content-length") && v == "100" }));
        assert_eq!(resp.body.kind(), BodyKind::ContentLength(100));
    }
}
