//! HTTP/1.1 client for sending requests over a transport.
//!
//! [`Http1Client`] sends a single HTTP/1.1 request and reads the response.

use crate::bytes::{Buf, BytesCursor, BytesMut};
use crate::codec::Encoder;
use crate::http::body::{Body, Frame, HeaderMap, HeaderName, HeaderValue, SizeHint};
use crate::http::h1::codec::{
    ChunkedBodyDecoder, HttpError, parse_header_line, require_transfer_encoding_chunked,
    unique_header_value, validate_header_field,
};
use crate::http::h1::types::{Method, Request, Response, Version};
use crate::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use std::fmt::Write;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::Poll;

/// Maximum allowed header block size (64 KiB).
const DEFAULT_MAX_HEADERS_SIZE: usize = 64 * 1024;

/// Maximum allowed body size (16 MiB).
const DEFAULT_MAX_BODY_SIZE: usize = 16 * 1024 * 1024;

/// Maximum number of headers.
const MAX_HEADERS: usize = 128;

/// HTTP/1.1 client codec that encodes *requests* and decodes *responses*.
///
/// This is the mirror of [`Http1Codec`](super::Http1Codec) which decodes
/// requests and encodes responses. The client codec is used with
/// [`Framed`] for client-side connections.
///
/// # Limits
///
/// - Maximum header block size: 64 KiB (configurable via [`max_headers_size`](Self::max_headers_size))
/// - Maximum body size: 16 MiB (configurable via [`max_body_size`](Self::max_body_size))
/// - Maximum number of headers: 128
pub struct Http1ClientCodec {
    state: ClientDecodeState,
    max_headers_size: usize,
    max_body_size: usize,
}

enum ClientDecodeState {
    Head,
    Body {
        version: Version,
        status: u16,
        reason: String,
        headers: Vec<(String, String)>,
        remaining: usize,
    },
    Chunked {
        version: Version,
        status: u16,
        reason: String,
        headers: Vec<(String, String)>,
        chunked: ChunkedBodyDecoder,
    },
    /// Response body is delimited by EOF (no Content-Length/Transfer-Encoding).
    Eof {
        version: Version,
        status: u16,
        reason: String,
        headers: Vec<(String, String)>,
    },
}

impl Http1ClientCodec {
    /// Create a new client codec with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: ClientDecodeState::Head,
            max_headers_size: DEFAULT_MAX_HEADERS_SIZE,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
        }
    }

    /// Set the maximum header block size.
    #[must_use]
    pub fn max_headers_size(mut self, size: usize) -> Self {
        self.max_headers_size = size;
        self
    }

    /// Set the maximum body size.
    #[must_use]
    pub fn max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }
}

impl Default for Http1ClientCodec {
    fn default() -> Self {
        Self::new()
    }
}

/// Find `\r\n\r\n` delimiter.
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Parse status line: `HTTP/1.1 200 OK`.
fn parse_status_line(line: &str) -> Result<(Version, u16, String), HttpError> {
    let mut parts = line.splitn(3, ' ');
    let ver = parts.next().ok_or(HttpError::BadRequestLine)?;
    let code = parts.next().ok_or(HttpError::BadRequestLine)?;
    let reason = parts.next().unwrap_or("").to_owned();

    let version = Version::from_bytes(ver.as_bytes()).ok_or(HttpError::UnsupportedVersion)?;
    let status: u16 = code.parse().map_err(|_| HttpError::BadRequestLine)?;

    Ok((version, status, reason))
}

impl crate::codec::Decoder for Http1ClientCodec {
    type Item = Response;
    type Error = HttpError;

    #[allow(clippy::too_many_lines)]
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Response>, HttpError> {
        loop {
            match &mut self.state {
                state @ ClientDecodeState::Head => {
                    let Some(end) = find_headers_end(src.as_ref()) else {
                        // Check for header overflow while waiting for more data
                        if src.len() > self.max_headers_size {
                            return Err(HttpError::HeadersTooLarge);
                        }
                        return Ok(None);
                    };

                    if end > self.max_headers_size {
                        return Err(HttpError::HeadersTooLarge);
                    }

                    let head_bytes = src.split_to(end);
                    let head_str = std::str::from_utf8(head_bytes.as_ref())
                        .map_err(|_| HttpError::BadRequestLine)?;

                    let mut lines = head_str.split("\r\n");
                    let status_line = lines.next().ok_or(HttpError::BadRequestLine)?;
                    let (version, status, reason) = parse_status_line(status_line)?;

                    let mut headers = Vec::new();
                    for line in lines {
                        if line.is_empty() {
                            break;
                        }
                        headers.push(parse_header_line(line)?);
                        if headers.len() > MAX_HEADERS {
                            return Err(HttpError::TooManyHeaders);
                        }
                    }

                    // RFC 7230/9110: responses with these status codes have no body.
                    if matches!(status, 100..=199 | 204 | 304) {
                        *state = ClientDecodeState::Head;
                        return Ok(Some(Response {
                            version,
                            status,
                            reason,
                            headers,
                            body: Vec::new(),
                            trailers: Vec::new(),
                        }));
                    }

                    // RFC 7230 3.3.3: Reject responses with both Transfer-Encoding
                    // and Content-Length to prevent response smuggling.
                    let te = unique_header_value(&headers, "Transfer-Encoding")?;
                    let cl = unique_header_value(&headers, "Content-Length")?;
                    if te.is_some() && cl.is_some() {
                        return Err(HttpError::AmbiguousBodyLength);
                    }

                    if let Some(te) = te {
                        require_transfer_encoding_chunked(te)?;
                        *state = ClientDecodeState::Chunked {
                            version,
                            status,
                            reason,
                            headers,
                            chunked: ChunkedBodyDecoder::new(
                                self.max_body_size,
                                self.max_headers_size,
                            ),
                        };
                        continue;
                    }

                    if let Some(cl) = cl {
                        let content_length: usize =
                            cl.trim().parse().map_err(|_| HttpError::BadContentLength)?;

                        if content_length == 0 {
                            *state = ClientDecodeState::Head;
                            return Ok(Some(Response {
                                version,
                                status,
                                reason,
                                headers,
                                body: Vec::new(),
                                trailers: Vec::new(),
                            }));
                        }

                        // Check body size limit upfront for Content-Length
                        if content_length > self.max_body_size {
                            return Err(HttpError::BodyTooLarge);
                        }

                        *state = ClientDecodeState::Body {
                            version,
                            status,
                            reason,
                            headers,
                            remaining: content_length,
                        };
                        continue;
                    }

                    // No Content-Length/Transfer-Encoding: body is delimited by EOF.
                    if src.len() > self.max_body_size {
                        return Err(HttpError::BodyTooLarge);
                    }

                    *state = ClientDecodeState::Eof {
                        version,
                        status,
                        reason,
                        headers,
                    };
                    return Ok(None);
                }

                ClientDecodeState::Body { remaining, .. } => {
                    let need = *remaining;
                    if src.len() < need {
                        return Ok(None);
                    }

                    let body_bytes = src.split_to(need);
                    let old = std::mem::replace(&mut self.state, ClientDecodeState::Head);
                    let ClientDecodeState::Body {
                        version,
                        status,
                        reason,
                        headers,
                        ..
                    } = old
                    else {
                        unreachable!()
                    };

                    return Ok(Some(Response {
                        version,
                        status,
                        reason,
                        headers,
                        body: body_bytes.to_vec(),
                        trailers: Vec::new(),
                    }));
                }

                ClientDecodeState::Chunked { chunked, .. } => {
                    let Some((body, trailers)) = chunked.decode(src)? else {
                        return Ok(None);
                    };

                    let old = std::mem::replace(&mut self.state, ClientDecodeState::Head);
                    let ClientDecodeState::Chunked {
                        version,
                        status,
                        reason,
                        headers,
                        ..
                    } = old
                    else {
                        unreachable!()
                    };

                    return Ok(Some(Response {
                        version,
                        status,
                        reason,
                        headers,
                        body,
                        trailers,
                    }));
                }

                ClientDecodeState::Eof { .. } => {
                    if src.len() > self.max_body_size {
                        return Err(HttpError::BodyTooLarge);
                    }
                    return Ok(None);
                }
            }
        }
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Response>, HttpError> {
        if matches!(&self.state, ClientDecodeState::Eof { .. }) {
            let old = std::mem::replace(&mut self.state, ClientDecodeState::Head);
            let ClientDecodeState::Eof {
                version,
                status,
                reason,
                headers,
            } = old
            else {
                unreachable!()
            };

            if src.len() > self.max_body_size {
                return Err(HttpError::BodyTooLarge);
            }

            let body = src.split_to(src.len()).to_vec();
            return Ok(Some(Response {
                version,
                status,
                reason,
                headers,
                body,
                trailers: Vec::new(),
            }));
        }

        match self.decode(src)? {
            Some(frame) => Ok(Some(frame)),
            None if src.is_empty() => Ok(None),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete frame at EOF",
            )
            .into()),
        }
    }
}

impl crate::codec::Encoder<Request> for Http1ClientCodec {
    type Error = HttpError;

    fn encode(&mut self, req: Request, dst: &mut BytesMut) -> Result<(), HttpError> {
        if req.uri.contains('\r')
            || req.uri.contains('\n')
            || req.uri.contains(' ')
            || req.uri.contains('\t')
        {
            return Err(HttpError::BadRequestLine);
        }
        if req.method.as_str().contains('\r')
            || req.method.as_str().contains('\n')
            || req.method.as_str().contains(' ')
            || req.method.as_str().contains('\t')
        {
            return Err(HttpError::BadMethod);
        }

        let te = unique_header_value(&req.headers, "Transfer-Encoding")?;
        let cl = unique_header_value(&req.headers, "Content-Length")?;

        let chunked = match te {
            Some(value) => {
                require_transfer_encoding_chunked(value)?;
                true
            }
            None => false,
        };

        if chunked && cl.is_some() {
            return Err(HttpError::AmbiguousBodyLength);
        }
        if !chunked && !req.trailers.is_empty() {
            return Err(HttpError::TrailersNotAllowed);
        }
        if !chunked {
            if let Some(cl) = cl {
                let declared: usize = cl.trim().parse().map_err(|_| HttpError::BadContentLength)?;
                if declared != req.body.len() {
                    return Err(HttpError::BadContentLength);
                }
            }
        }

        // Request line
        let mut head = String::with_capacity(256);
        let _ = write!(head, "{} {} {}\r\n", req.method, req.uri, req.version);

        // Headers
        let mut has_content_length = false;
        for (name, value) in &req.headers {
            validate_header_field(name, value)?;
            if name.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
            }
            let _ = write!(head, "{name}: {value}\r\n");
        }

        if chunked {
            head.push_str("\r\n");
            dst.extend_from_slice(head.as_bytes());

            if !req.body.is_empty() {
                let mut chunk_line = String::with_capacity(16);
                let _ = write!(chunk_line, "{:X}\r\n", req.body.len());
                dst.extend_from_slice(chunk_line.as_bytes());
                dst.extend_from_slice(&req.body);
                dst.extend_from_slice(b"\r\n");
            }

            dst.extend_from_slice(b"0\r\n");
            if !req.trailers.is_empty() {
                let mut trailer_block = String::with_capacity(256);
                for (name, value) in &req.trailers {
                    validate_header_field(name, value)?;
                    let _ = write!(trailer_block, "{name}: {value}\r\n");
                }
                dst.extend_from_slice(trailer_block.as_bytes());
            }
            dst.extend_from_slice(b"\r\n");
            return Ok(());
        }

        if !has_content_length && !req.body.is_empty() {
            let _ = write!(head, "Content-Length: {}\r\n", req.body.len());
        }

        head.push_str("\r\n");

        dst.extend_from_slice(head.as_bytes());
        if !req.body.is_empty() {
            dst.extend_from_slice(&req.body);
        }

        Ok(())
    }
}

/// A simple HTTP/1.1 client for sending a single request over a transport.
pub struct Http1Client;

impl Http1Client {
    /// Send a request over the given transport and return the response.
    pub async fn request<T>(io: T, req: Request) -> Result<Response, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // Reuse the method-aware streaming implementation so HEAD responses
        // correctly ignore Content-Length/Transfer-Encoding bodies.
        let mut streaming = Self::request_streaming(io, req).await?;

        let mut response = Response {
            version: streaming.head.version,
            status: streaming.head.status,
            reason: streaming.head.reason,
            headers: streaming.head.headers,
            body: Vec::new(),
            trailers: Vec::new(),
        };

        while let Some(frame) = poll_fn(|cx| Pin::new(&mut streaming.body).poll_frame(cx)).await {
            match frame? {
                Frame::Data(mut buf) => {
                    while buf.has_remaining() {
                        let chunk = buf.chunk();
                        response.body.extend_from_slice(chunk);
                        buf.advance(chunk.len());
                    }
                }
                Frame::Trailers(trailers) => {
                    for (name, value) in trailers.iter() {
                        let value = value.to_str().map_or_else(
                            |_| String::from_utf8_lossy(value.as_bytes()).into_owned(),
                            std::borrow::ToOwned::to_owned,
                        );
                        response.trailers.push((name.as_str().to_string(), value));
                    }
                }
            }
        }

        Ok(response)
    }

    /// Send a request and return a streaming response body.
    ///
    /// This returns the response head immediately, and a [`Body`] implementation
    /// that reads the response body incrementally as it is polled.
    ///
    /// Supported body framing:
    /// - `Content-Length`
    /// - `Transfer-Encoding: chunked` (including trailers)
    /// - EOF-delimited bodies (no length headers)
    pub async fn request_streaming<T>(
        mut io: T,
        req: Request,
    ) -> Result<ClientStreamingResponse<T>, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let request_method = req.method.clone();

        // Encode request to bytes (reuse the existing validated encoder).
        let mut codec = Http1ClientCodec::new();
        let mut write_buf = BytesMut::with_capacity(1024);
        codec.encode(req, &mut write_buf)?;

        // Write request bytes.
        io.write_all(write_buf.as_ref()).await?;
        io.flush().await?;

        // Read response head (status line + headers).
        let mut read_buf = BytesMut::with_capacity(8192);
        let mut scratch = [0u8; 8192];
        loop {
            if let Some(end) = find_headers_end(read_buf.as_ref()) {
                if end > DEFAULT_MAX_HEADERS_SIZE {
                    return Err(HttpError::HeadersTooLarge);
                }

                let head_bytes = read_buf.split_to(end);
                let head_str = std::str::from_utf8(head_bytes.as_ref())
                    .map_err(|_| HttpError::BadRequestLine)?;

                let mut lines = head_str.split("\r\n");
                let status_line = lines.next().ok_or(HttpError::BadRequestLine)?;
                let (version, status, reason) = parse_status_line(status_line)?;

                let mut headers = Vec::new();
                for line in lines {
                    if line.is_empty() {
                        break;
                    }
                    headers.push(parse_header_line(line)?);
                    if headers.len() > MAX_HEADERS {
                        return Err(HttpError::TooManyHeaders);
                    }
                }

                // RFC 7230/9110: responses with these status codes have no body.
                let no_body_status = matches!(status, 100..=199 | 204 | 304);
                let kind = if no_body_status || request_method == Method::Head {
                    ClientBodyKind::Empty
                } else {
                    let te = unique_header_value(&headers, "Transfer-Encoding")?;
                    let cl = unique_header_value(&headers, "Content-Length")?;

                    // RFC 7230 3.3.3: Reject responses with both Transfer-Encoding
                    // and Content-Length to prevent response smuggling.
                    if te.is_some() && cl.is_some() {
                        return Err(HttpError::AmbiguousBodyLength);
                    }

                    if let Some(te) = te {
                        require_transfer_encoding_chunked(te)?;
                        ClientBodyKind::Chunked {
                            state: ChunkedReadState::SizeLine,
                            trailers: HeaderMap::new(),
                            trailers_bytes: 0,
                        }
                    } else if let Some(cl) = cl {
                        let content_length: u64 =
                            cl.trim().parse().map_err(|_| HttpError::BadContentLength)?;

                        if content_length == 0 {
                            ClientBodyKind::Empty
                        } else {
                            let max_body_size =
                                u64::try_from(DEFAULT_MAX_BODY_SIZE).unwrap_or(u64::MAX);
                            if content_length > max_body_size {
                                return Err(HttpError::BodyTooLarge);
                            }

                            ClientBodyKind::ContentLength {
                                remaining: content_length,
                            }
                        }
                    } else {
                        ClientBodyKind::Eof
                    }
                };

                let head = crate::http::h1::stream::ResponseHead {
                    version,
                    status,
                    reason,
                    headers,
                };

                // If no body, drop any already-buffered bytes.
                let body_buf = if matches!(kind, ClientBodyKind::Empty) {
                    BytesMut::new()
                } else {
                    read_buf
                };

                let body = ClientIncomingBody::new(io, kind, body_buf);
                return Ok(ClientStreamingResponse { head, body });
            }

            if read_buf.len() > DEFAULT_MAX_HEADERS_SIZE {
                return Err(HttpError::HeadersTooLarge);
            }

            let n = poll_fn(|cx| {
                let mut rb = ReadBuf::new(&mut scratch);
                match Pin::new(&mut io).poll_read(cx, &mut rb) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                }
            })
            .await?;

            if n == 0 {
                return Err(HttpError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before response headers",
                )));
            }

            read_buf.extend_from_slice(&scratch[..n]);
        }
    }
}

/// A streaming HTTP/1 response (head + body).
#[derive(Debug)]
pub struct ClientStreamingResponse<T> {
    /// Response head (status line + headers).
    pub head: crate::http::h1::stream::ResponseHead,
    /// Streaming response body.
    pub body: ClientIncomingBody<T>,
}

#[derive(Debug, Clone)]
enum ClientBodyKind {
    Empty,
    ContentLength {
        remaining: u64,
    },
    Chunked {
        state: ChunkedReadState,
        trailers: HeaderMap,
        trailers_bytes: usize,
    },
    Eof,
}

#[derive(Debug, Clone, Copy)]
enum ChunkedReadState {
    SizeLine,
    Data { remaining: usize },
    DataCrlf,
    Trailers,
    Done,
}

/// A streaming HTTP/1 response body that reads from the underlying transport.
#[derive(Debug)]
pub struct ClientIncomingBody<T> {
    io: T,
    buffer: BytesMut,
    kind: ClientBodyKind,
    done: bool,
    received: u64,
    size_hint: SizeHint,
    max_chunk_size: usize,
    max_body_size: u64,
    max_trailers_size: usize,
    max_buffered_bytes: usize,
}

impl<T> ClientIncomingBody<T> {
    const DEFAULT_MAX_CHUNK_SIZE: usize = 64 * 1024;
    const DEFAULT_MAX_TRAILERS_SIZE: usize = 16 * 1024;
    const DEFAULT_MAX_BUFFERED_BYTES: usize = 256 * 1024;

    fn new(io: T, kind: ClientBodyKind, buffer: BytesMut) -> Self {
        let size_hint = match &kind {
            ClientBodyKind::Empty => SizeHint::with_exact(0),
            ClientBodyKind::ContentLength { remaining } => SizeHint::with_exact(*remaining),
            ClientBodyKind::Chunked { .. } | ClientBodyKind::Eof => SizeHint::default(),
        };

        Self {
            io,
            buffer,
            done: matches!(kind, ClientBodyKind::Empty),
            kind,
            received: 0,
            size_hint,
            max_chunk_size: Self::DEFAULT_MAX_CHUNK_SIZE,
            max_body_size: u64::try_from(DEFAULT_MAX_BODY_SIZE).unwrap_or(u64::MAX),
            max_trailers_size: Self::DEFAULT_MAX_TRAILERS_SIZE,
            max_buffered_bytes: Self::DEFAULT_MAX_BUFFERED_BYTES,
        }
    }

    fn try_decode_frame(&mut self) -> Result<Option<Frame<BytesCursor>>, HttpError> {
        if self.done {
            return Ok(None);
        }

        // Temporarily move `kind` out to avoid borrowing `self.kind` across
        // calls that also mutably borrow `self`.
        let mut kind = std::mem::replace(&mut self.kind, ClientBodyKind::Empty);
        let result = match &mut kind {
            ClientBodyKind::Empty => {
                self.done = true;
                Ok(None)
            }
            ClientBodyKind::ContentLength { remaining } => {
                self.try_decode_content_length_frame(remaining)
            }
            ClientBodyKind::Eof => self.try_decode_eof_frame(),
            ClientBodyKind::Chunked {
                state,
                trailers,
                trailers_bytes,
            } => self.try_decode_chunked_frame(state, trailers, trailers_bytes),
        };
        self.kind = kind;
        result
    }

    fn try_decode_content_length_frame(
        &mut self,
        remaining: &mut u64,
    ) -> Result<Option<Frame<BytesCursor>>, HttpError> {
        if *remaining == 0 {
            self.done = true;
            return Ok(None);
        }
        if self.buffer.is_empty() {
            return Ok(None);
        }

        let max = usize::try_from(*remaining).unwrap_or(usize::MAX);
        let to_yield = self.buffer.len().min(max).min(self.max_chunk_size);
        let chunk = self.buffer.split_to(to_yield);

        *remaining = remaining.saturating_sub(to_yield as u64);
        self.received = self.received.saturating_add(to_yield as u64);
        if self.received > self.max_body_size {
            return Err(HttpError::BodyTooLarge);
        }

        if *remaining == 0 {
            self.done = true;
        }

        Ok(Some(Frame::Data(BytesCursor::new(chunk.freeze()))))
    }

    fn try_decode_eof_frame(&mut self) -> Result<Option<Frame<BytesCursor>>, HttpError> {
        if self.buffer.is_empty() {
            return Ok(None);
        }

        let to_yield = self.buffer.len().min(self.max_chunk_size);
        let chunk = self.buffer.split_to(to_yield);

        self.received = self.received.saturating_add(to_yield as u64);
        if self.received > self.max_body_size {
            return Err(HttpError::BodyTooLarge);
        }

        Ok(Some(Frame::Data(BytesCursor::new(chunk.freeze()))))
    }

    #[allow(clippy::too_many_lines)]
    fn try_decode_chunked_frame(
        &mut self,
        state: &mut ChunkedReadState,
        trailers: &mut HeaderMap,
        trailers_bytes: &mut usize,
    ) -> Result<Option<Frame<BytesCursor>>, HttpError> {
        loop {
            match *state {
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
                        *state = ChunkedReadState::Trailers;
                        *trailers = HeaderMap::new();
                        *trailers_bytes = 0;
                    } else {
                        *state = ChunkedReadState::Data {
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

                    let next = remaining.saturating_sub(to_yield);
                    *state = if next == 0 {
                        ChunkedReadState::DataCrlf
                    } else {
                        ChunkedReadState::Data { remaining: next }
                    };

                    self.received = self.received.saturating_add(to_yield as u64);
                    if self.received > self.max_body_size {
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
                    *state = ChunkedReadState::SizeLine;
                }

                ChunkedReadState::Trailers => {
                    if *trailers_bytes + self.buffer.len() > self.max_trailers_size {
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
                        *state = ChunkedReadState::Done;
                        if !trailers.is_empty() {
                            return Ok(Some(Frame::Trailers(std::mem::take(trailers))));
                        }
                        return Ok(None);
                    }

                    *trailers_bytes = trailers_bytes.saturating_add(line.len() + 2);
                    if *trailers_bytes > self.max_trailers_size {
                        return Err(HttpError::HeadersTooLarge);
                    }

                    let line_str =
                        std::str::from_utf8(line.as_ref()).map_err(|_| HttpError::BadHeader)?;
                    let Some(colon) = line_str.find(':') else {
                        return Err(HttpError::BadHeader);
                    };

                    let name = line_str[..colon].trim();
                    let value = line_str[colon + 1..].trim();
                    trailers.append(
                        HeaderName::from_string(name),
                        HeaderValue::from_bytes(value.as_bytes()),
                    );
                }

                ChunkedReadState::Done => return Ok(None),
            }
        }
    }
}

impl<T> Body for ClientIncomingBody<T>
where
    T: AsyncRead + Unpin,
{
    type Data = BytesCursor;
    type Error = HttpError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            // Decode any already-buffered frames first.
            match self.try_decode_frame() {
                Ok(Some(frame)) => return Poll::Ready(Some(Ok(frame))),
                Ok(None) => {}
                Err(e) => {
                    self.done = true;
                    return Poll::Ready(Some(Err(e)));
                }
            }

            if self.done {
                return Poll::Ready(None);
            }

            // Need more bytes.
            let mut scratch = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.io).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        // EOF: validate based on framing mode.
                        match &self.kind {
                            ClientBodyKind::ContentLength { remaining } if *remaining != 0 => {
                                self.done = true;
                                return Poll::Ready(Some(Err(HttpError::BadContentLength)));
                            }
                            ClientBodyKind::Chunked { .. } => {
                                self.done = true;
                                return Poll::Ready(Some(Err(HttpError::BadChunkedEncoding)));
                            }
                            _ => {
                                self.done = true;
                                return Poll::Ready(None);
                            }
                        }
                    }

                    self.buffer.extend_from_slice(&scratch[..n]);
                    if self.buffer.len() > self.max_buffered_bytes {
                        self.done = true;
                        return Poll::Ready(Some(Err(HttpError::BodyTooLarge)));
                    }
                }
                Poll::Ready(Err(e)) => {
                    self.done = true;
                    return Poll::Ready(Some(Err(HttpError::Io(e))));
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        self.size_hint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::{Buf, BytesMut};
    use crate::codec::Decoder;
    use std::pin::Pin;
    use std::task::{Context, Wake, Waker};

    #[test]
    fn decode_simple_response() {
        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"[..]);
        let resp = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.version, Version::Http11);
        assert_eq!(resp.body, b"hello");
        assert!(resp.trailers.is_empty());
    }

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: std::sync::Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(std::sync::Arc::new(NoopWaker))
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

    #[derive(Debug)]
    struct TestIo {
        read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl TestIo {
        fn new(read_bytes: &[u8]) -> Self {
            Self {
                read: std::io::Cursor::new(read_bytes.to_vec()),
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for TestIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let dst = buf.unfilled();
            let n = std::io::Read::read(&mut self.read, dst)?;
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            src: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.written.extend_from_slice(src);
            Poll::Ready(Ok(src.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn request_streaming_content_length() {
        let response_bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let io = TestIo::new(response_bytes);

        let req = Request {
            method: Method::Get,
            uri: "/".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let mut resp = block_on(Http1Client::request_streaming(io, req)).expect("streaming resp");
        assert_eq!(resp.head.status, 200);

        let mut collected = Vec::new();
        while let Some(frame) = poll_body(&mut resp.body) {
            let frame = frame.expect("frame ok");
            match frame {
                Frame::Data(mut buf) => {
                    while buf.has_remaining() {
                        let chunk = buf.chunk();
                        collected.extend_from_slice(chunk);
                        buf.advance(chunk.len());
                    }
                }
                Frame::Trailers(_) => {}
            }
        }

        assert_eq!(collected, b"hello");
    }

    #[test]
    fn request_streaming_chunked_with_trailers() {
        let response_bytes = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nFoo: Bar\r\n\r\n";
        let io = TestIo::new(response_bytes);

        let req = Request {
            method: Method::Get,
            uri: "/".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let mut resp = block_on(Http1Client::request_streaming(io, req)).expect("streaming resp");
        assert_eq!(resp.head.status, 200);

        let mut data = Vec::new();
        let mut saw_trailers = false;

        while let Some(frame) = poll_body(&mut resp.body) {
            let frame = frame.expect("frame ok");
            match frame {
                Frame::Data(mut buf) => {
                    while buf.has_remaining() {
                        let chunk = buf.chunk();
                        data.extend_from_slice(chunk);
                        buf.advance(chunk.len());
                    }
                }
                Frame::Trailers(trailers) => {
                    saw_trailers = true;
                    let foo = trailers.get(&HeaderName::from_static("foo")).unwrap();
                    assert_eq!(foo.as_bytes(), b"Bar");
                }
            }
        }

        assert_eq!(data, b"hello");
        assert!(saw_trailers);
    }

    #[test]
    fn request_head_response_ignores_content_length_body() {
        let response_bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        let io = TestIo::new(response_bytes);

        let req = Request {
            method: Method::Head,
            uri: "/".to_string(),
            version: Version::Http11,
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };

        let resp = block_on(Http1Client::request(io, req)).expect("head response");
        assert_eq!(resp.status, 200);
        assert!(resp.body.is_empty());
        assert!(resp.trailers.is_empty());
    }

    #[test]
    fn decode_response_no_body() {
        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(&b"HTTP/1.1 204 No Content\r\n\r\n"[..]);
        let resp = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(resp.status, 204);
        assert!(resp.body.is_empty());
        assert!(resp.trailers.is_empty());
    }

    #[test]
    fn decode_response_incomplete() {
        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhel"[..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn encode_request() {
        let mut codec = Http1ClientCodec::new();
        let req = Request {
            method: crate::http::h1::types::Method::Get,
            uri: "/index.html".into(),
            version: Version::Http11,
            headers: vec![("Host".into(), "example.com".into())],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };
        let mut buf = BytesMut::with_capacity(256);
        crate::codec::Encoder::encode(&mut codec, req, &mut buf).unwrap();
        let s = String::from_utf8(buf.to_vec()).unwrap();
        assert!(s.starts_with("GET /index.html HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com\r\n"));
    }

    #[test]
    fn encode_request_with_body() {
        let mut codec = Http1ClientCodec::new();
        let req = Request {
            method: crate::http::h1::types::Method::Post,
            uri: "/api".into(),
            version: Version::Http11,
            headers: vec![("Host".into(), "api.example.com".into())],
            body: b"data".to_vec(),
            trailers: Vec::new(),
            peer_addr: None,
        };
        let mut buf = BytesMut::with_capacity(256);
        crate::codec::Encoder::encode(&mut codec, req, &mut buf).unwrap();
        let s = String::from_utf8(buf.to_vec()).unwrap();
        assert!(s.contains("Content-Length: 4\r\n"));
        assert!(s.ends_with("\r\n\r\ndata"));
    }

    #[test]
    fn decode_chunked_response() {
        let mut codec = Http1ClientCodec::new();
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let resp = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello world");
        assert!(resp.trailers.is_empty());
    }

    #[test]
    fn decode_chunked_response_with_trailers() {
        let mut codec = Http1ClientCodec::new();
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n0\r\nX-Trailer: one\r\nY-Trailer: two\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let resp = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(resp.body, b"hello");
        assert_eq!(resp.trailers.len(), 2);
        assert_eq!(resp.trailers[0].0, "X-Trailer");
        assert_eq!(resp.trailers[0].1, "one");
    }

    #[test]
    fn decode_response_without_length_is_eof_delimited() {
        let mut codec = Http1ClientCodec::new();
        let raw = b"HTTP/1.1 200 OK\r\n\r\nhello";
        let mut buf = BytesMut::from(&raw[..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        let resp = codec.decode_eof(&mut buf).unwrap().unwrap();
        assert_eq!(resp.body, b"hello");
    }

    #[test]
    fn decode_headers_too_large() {
        let mut codec = Http1ClientCodec::new().max_headers_size(32);
        let mut buf = BytesMut::from(&b"HTTP/1.1 200 OK\r\nX-Large: aaaaaaaaaaaaaaa\r\n\r\n"[..]);
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(HttpError::HeadersTooLarge)));
    }

    #[test]
    fn decode_body_too_large_content_length() {
        let mut codec = Http1ClientCodec::new().max_body_size(10);
        let mut buf = BytesMut::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"[..]);
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(HttpError::BodyTooLarge)));
    }

    #[test]
    fn decode_body_too_large_chunked() {
        let mut codec = Http1ClientCodec::new().max_body_size(10);
        // Chunked body with 20 bytes total (exceeds 10 byte limit)
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    14\r\n01234567890123456789\r\n0\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(HttpError::BodyTooLarge)));
    }

    #[test]
    fn decode_body_at_limit_succeeds() {
        let mut codec = Http1ClientCodec::new().max_body_size(5);
        let mut buf = BytesMut::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"[..]);
        let resp = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(resp.body, b"hello");
    }

    #[test]
    fn reject_both_content_length_and_transfer_encoding() {
        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
        );
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(HttpError::AmbiguousBodyLength)));
    }

    #[test]
    fn reject_invalid_crlf_after_chunk() {
        let mut codec = Http1ClientCodec::new();
        // Invalid: missing proper CRLF after chunk data
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhelloXX0\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(HttpError::BadChunkedEncoding)));
    }
}
