//! HTTP/1.1 client for sending requests over a transport.
//!
//! [`Http1Client`] sends a single HTTP/1.1 request and reads the response.

use crate::bytes::{Buf, BytesCursor, BytesMut};
use crate::codec::Encoder;
use crate::http::body::{Body, Frame, HeaderMap, HeaderName, HeaderValue, SizeHint};
use crate::http::h1::codec::{
    ChunkedBodyDecoder, HttpError, append_chunk_size_line, append_decimal,
    find_chunk_size_line_end, is_forbidden_trailer, parse_chunk_size_line, parse_header_line,
    require_transfer_encoding_chunked, trim_ows, unique_header_value, validate_header_field,
};
use crate::http::h1::types::{Method, Request, Response, Version};
use crate::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use memchr::memmem;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

/// Maximum allowed header block size (64 KiB).
const DEFAULT_MAX_HEADERS_SIZE: usize = 64 * 1024;

/// Maximum allowed body size (16 MiB).
const DEFAULT_MAX_BODY_SIZE: usize = 16 * 1024 * 1024;

/// Maximum allowed trailer block size (64 KiB).
const DEFAULT_MAX_TRAILERS_SIZE: usize = 64 * 1024;

/// Maximum number of headers.
const MAX_HEADERS: usize = 128;

/// Maximum informational responses accepted before a final response is required.
const MAX_INFORMATIONAL_RESPONSES: usize = 8;

/// How long an `Expect: 100-continue` request waits for any response before
/// sending its body anyway (RFC 9110 section 10.1.1). Servers that ignore the
/// expectation never send `100 Continue`.
const EXPECT_CONTINUE_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// HTTP/1.1 client codec that encodes *requests* and decodes *responses*.
///
/// This is the mirror of [`Http1Codec`](super::Http1Codec) which decodes
/// requests and encodes responses. The client codec is used with
/// [`Framed`](crate::codec::Framed) for client-side connections.
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
    max_trailers_size: usize,
    /// Methods of the requests this codec encoded that have no final response
    /// yet, oldest first.
    pending_methods: std::collections::VecDeque<Method>,
    /// Set once an entry of `pending_methods` was dropped. Every later
    /// response would then be paired with the wrong request, so decoding a
    /// final response fails instead.
    pending_methods_dropped: bool,
}

/// Requests remembered for response framing. A codec used only to encode
/// never pops them, so the oldest are dropped past this depth; a codec that
/// also decodes then refuses to frame responses (it cannot tell which
/// request each one answers).
const MAX_PENDING_METHODS: usize = 1024;

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
    /// Codec encountered a fatal error and is permanently poisoned.
    Poisoned,
}

impl Http1ClientCodec {
    /// Create a new client codec with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: ClientDecodeState::Head,
            max_headers_size: DEFAULT_MAX_HEADERS_SIZE,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            max_trailers_size: DEFAULT_MAX_TRAILERS_SIZE,
            pending_methods: std::collections::VecDeque::new(),
            pending_methods_dropped: false,
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

    /// Set the maximum trailer block size for chunked responses.
    #[must_use]
    pub fn max_trailers_size(mut self, size: usize) -> Self {
        self.max_trailers_size = size;
        self
    }
}

impl Default for Http1ClientCodec {
    fn default() -> Self {
        Self::new()
    }
}

/// A response head as text.
///
/// Heads are ASCII apart from obs-text (0x80-0xFF) in field values and the
/// reason phrase, which legacy servers send as Latin-1, for example in a
/// Content-Disposition filename. Valid UTF-8 is kept as it is; any other line
/// is decoded byte for byte as Latin-1, as the server-side parser does for
/// field values. The field syntax is still validated afterwards.
fn response_head_str(head: &[u8]) -> std::borrow::Cow<'_, str> {
    if let Ok(text) = std::str::from_utf8(head) {
        return std::borrow::Cow::Borrowed(text);
    }
    std::borrow::Cow::Owned(
        head.split_inclusive(|&byte| byte == b'\n')
            .map(|line| {
                std::str::from_utf8(line).map_or_else(
                    |_| line.iter().copied().map(char::from).collect::<String>(),
                    str::to_owned,
                )
            })
            .collect(),
    )
}

/// Find `\r\n\r\n` delimiter.
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    memmem::find(buf, b"\r\n\r\n").map(|idx| idx + 4)
}

#[inline]
fn is_valid_reason_phrase_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff)
}

/// Parse status line: `HTTP/1.1 200 OK`.
fn parse_status_line(line: &str) -> Result<(Version, u16, String), HttpError> {
    let mut parts = line.splitn(3, ' ');
    let ver = parts.next().ok_or(HttpError::BadRequestLine)?;
    let code = parts.next().ok_or(HttpError::BadRequestLine)?;
    let reason = parts.next().unwrap_or("");

    let version = Version::from_bytes(ver.as_bytes()).ok_or(HttpError::UnsupportedVersion)?;
    // RFC 9110 §15: status codes are three-digit integers (100–999).
    if code.len() != 3 || !code.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(HttpError::BadRequestLine);
    }
    let status: u16 = code.parse().map_err(|_| HttpError::BadRequestLine)?;
    if !(100..=999).contains(&status) {
        return Err(HttpError::BadRequestLine);
    }
    if !reason
        .as_bytes()
        .iter()
        .copied()
        .all(is_valid_reason_phrase_byte)
    {
        return Err(HttpError::BadRequestLine);
    }

    Ok((version, status, reason.to_owned()))
}

fn response_body_kind(
    headers: &[(String, String)],
    status: u16,
    request_method: &Method,
    max_body_size_limit: usize,
) -> Result<ClientBodyKind, HttpError> {
    // Responses with these status codes have no body.
    let no_body_status = (100..=199).contains(&status) || matches!(status, 204 | 304);
    if no_body_status || *request_method == Method::Head {
        return Ok(ClientBodyKind::Empty);
    }

    let te = unique_header_value(headers, "Transfer-Encoding")?;
    let cl = unique_header_value(headers, "Content-Length")?;

    // RFC 7230 3.3.3: Reject responses with both Transfer-Encoding
    // and Content-Length to prevent response smuggling.
    if te.is_some() && cl.is_some() {
        return Err(HttpError::AmbiguousBodyLength);
    }

    if let Some(te) = te {
        require_transfer_encoding_chunked(te)?;
        return Ok(ClientBodyKind::Chunked {
            state: ChunkedReadState::SizeLine,
            trailers: HeaderMap::new(),
            trailers_bytes: 0,
        });
    }

    if let Some(cl) = cl {
        // RFC 9110 §8.6: Content-Length = 1*DIGIT (no sign). `str::parse` accepts
        // a leading '+' (e.g. "+5"), which can disagree with stricter
        // intermediaries (nginx/envoy) and is a response-smuggling primitive.
        // Reject any non-digit input before parsing, mirroring the hardened
        // server request path in codec.rs.
        let cl_str = trim_ows(cl);
        if cl_str.is_empty() || !cl_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(HttpError::BadContentLength);
        }
        let content_length: u64 = cl_str.parse().map_err(|_| HttpError::BadContentLength)?;
        if content_length == 0 {
            return Ok(ClientBodyKind::Empty);
        }

        let max_body_size = u64::try_from(max_body_size_limit).unwrap_or(u64::MAX);
        if content_length > max_body_size {
            return Err(HttpError::BodyTooLargeDetailed {
                actual: content_length,
                limit: max_body_size,
            });
        }

        return Ok(ClientBodyKind::ContentLength {
            remaining: content_length,
        });
    }

    Ok(ClientBodyKind::Eof)
}

impl crate::codec::Decoder for Http1ClientCodec {
    type Item = Response;
    type Error = HttpError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Response>, HttpError> {
        match self.decode_inner(src) {
            Err(e) => {
                self.state = ClientDecodeState::Poisoned;
                Err(e)
            }
            Ok(v) => Ok(v),
        }
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Response>, HttpError> {
        match self.decode_inner_eof(src) {
            Err(e) => {
                self.state = ClientDecodeState::Poisoned;
                Err(e)
            }
            Ok(v) => Ok(v),
        }
    }
}

impl Http1ClientCodec {
    #[allow(clippy::too_many_lines)]
    fn decode_inner(&mut self, src: &mut BytesMut) -> Result<Option<Response>, HttpError> {
        loop {
            match &mut self.state {
                ClientDecodeState::Poisoned => {
                    return Err(HttpError::BadHeader); // Generic error for poisoned state
                }
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
                    let head_str = response_head_str(head_bytes.as_ref());

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

                    // A final response answers the oldest request this codec
                    // encoded. A response to HEAD, or a 2xx to CONNECT, has no
                    // body whatever its headers say (RFC 9110 §6.4.1).
                    let request_method = if matches!(status, 100..=199) && status != 101 {
                        None
                    } else if self.pending_methods_dropped {
                        // A dropped method shifts every later pairing: a
                        // response to HEAD would be read with a body, or a body
                        // parsed as the next response's head.
                        return Err(HttpError::Io(std::io::Error::other(
                            "more than 1024 requests awaited responses; response framing is lost",
                        )));
                    } else {
                        self.pending_methods.pop_front()
                    };
                    let bodyless_request = match request_method {
                        Some(Method::Head) => true,
                        Some(Method::Connect) => (200..=299).contains(&status),
                        _ => false,
                    };

                    // RFC 7230/9110: responses with these status codes have no body.
                    if matches!(status, 100..=199 | 204 | 304) || bodyless_request {
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
                                self.max_trailers_size,
                            ),
                        };
                        continue;
                    }

                    if let Some(cl) = cl {
                        // RFC 9110 §8.6: Content-Length = 1*DIGIT (no sign);
                        // reject non-digit input (smuggling parity with codec.rs).
                        let cl_str = trim_ows(cl);
                        if cl_str.is_empty() || !cl_str.bytes().all(|b| b.is_ascii_digit()) {
                            return Err(HttpError::BadContentLength);
                        }
                        let content_length: usize =
                            cl_str.parse().map_err(|_| HttpError::BadContentLength)?;

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
                        return Err(HttpError::BadHeader);
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
                        return Err(HttpError::BadHeader);
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

    fn decode_inner_eof(&mut self, src: &mut BytesMut) -> Result<Option<Response>, HttpError> {
        // EOF decoding is a complete decoding entry point. In particular,
        // framed transports do not call `decode` between successive final
        // frames, so this call may itself discover a close-delimited body.
        if let Some(response) = self.decode_inner(src)? {
            return Ok(Some(response));
        }
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

        // Only between responses is an end of input a clean end of the
        // stream. Mid-body the decoder may already have consumed every
        // buffered byte, and the response is truncated, not complete
        // (br-asupersync-vxmjgn).
        if src.is_empty() && matches!(self.state, ClientDecodeState::Head) {
            Ok(None)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete frame at EOF",
            )
            .into())
        }
    }
}

impl crate::codec::Encoder<Request> for Http1ClientCodec {
    type Error = HttpError;

    fn encode(&mut self, req: Request, dst: &mut BytesMut) -> Result<(), HttpError> {
        let method = req.method.clone();
        Self::encode_request(req, dst)?;
        // The decoder needs the method of the request each response answers:
        // a response to HEAD has no body, whatever its headers say.
        if self.pending_methods.len() >= MAX_PENDING_METHODS {
            self.pending_methods.pop_front();
            self.pending_methods_dropped = true;
        }
        self.pending_methods.push_back(method);
        Ok(())
    }
}

impl Http1ClientCodec {
    fn encode_request(req: Request, dst: &mut BytesMut) -> Result<(), HttpError> {
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

        if chunked && req.version == Version::Http10 {
            return Err(HttpError::BadTransferEncoding);
        }
        if chunked && cl.is_some() {
            return Err(HttpError::AmbiguousBodyLength);
        }
        if !chunked && !req.trailers.is_empty() {
            return Err(HttpError::TrailersNotAllowed);
        }
        if !chunked {
            if let Some(cl) = cl {
                // RFC 9110 §8.6: Content-Length = 1*DIGIT (no sign); reject
                // non-digit input (smuggling parity with codec.rs).
                let cl_str = trim_ows(cl);
                if cl_str.is_empty() || !cl_str.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(HttpError::BadContentLength);
                }
                let declared: usize = cl_str.parse().map_err(|_| HttpError::BadContentLength)?;
                if declared != req.body.len() {
                    return Err(HttpError::BadContentLength);
                }
            }
        }

        // Pre-validate all headers (and trailers for chunked).
        let mut has_content_length = false;
        for (name, value) in &req.headers {
            validate_header_field(name, value)?;
            if name.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
            }
        }
        if chunked {
            for (name, value) in &req.trailers {
                validate_header_field(name, value)?;
            }
        }

        // Pre-reserve capacity.
        let headers_bytes: usize = req.headers.iter().map(|(n, v)| n.len() + v.len() + 4).sum();
        dst.reserve(64 + req.uri.len() + headers_bytes + req.body.len());

        // Request line: "GET /path HTTP/1.1\r\n"
        dst.extend_from_slice(req.method.as_str().as_bytes());
        dst.extend_from_slice(b" ");
        dst.extend_from_slice(req.uri.as_bytes());
        dst.extend_from_slice(b" ");
        dst.extend_from_slice(req.version.as_str().as_bytes());
        dst.extend_from_slice(b"\r\n");

        // Headers
        for (name, value) in &req.headers {
            dst.extend_from_slice(name.as_bytes());
            dst.extend_from_slice(b": ");
            dst.extend_from_slice(value.as_bytes());
            dst.extend_from_slice(b"\r\n");
        }

        if chunked {
            dst.extend_from_slice(b"\r\n");

            if !req.body.is_empty() {
                append_chunk_size_line(dst, req.body.len());
                dst.extend_from_slice(&req.body);
                dst.extend_from_slice(b"\r\n");
            }

            dst.extend_from_slice(b"0\r\n");
            for (name, value) in &req.trailers {
                dst.extend_from_slice(name.as_bytes());
                dst.extend_from_slice(b": ");
                dst.extend_from_slice(value.as_bytes());
                dst.extend_from_slice(b"\r\n");
            }
            dst.extend_from_slice(b"\r\n");
            return Ok(());
        }

        if !has_content_length {
            if !req.body.is_empty() {
                dst.extend_from_slice(b"Content-Length: ");
                append_decimal(dst, req.body.len());
                dst.extend_from_slice(b"\r\n");
            } else if req.method == Method::Post || req.method == Method::Put {
                dst.extend_from_slice(b"Content-Length: 0\r\n");
            }
        }

        dst.extend_from_slice(b"\r\n");
        if !req.body.is_empty() {
            dst.extend_from_slice(&req.body);
        }

        Ok(())
    }
}

/// A simple HTTP/1.1 client for sending a single request over a transport.
pub struct Http1Client;

impl Http1Client {
    /// Send a streaming request body and return a streaming response.
    ///
    /// Unlike [`Self::request_streaming`], this does not collect the upload.
    /// It retains at most one producer frame, writes its [`Buf`] segments
    /// directly, and polls the response while the producer or socket is
    /// blocked. An early final response stops the upload and sets
    /// [`ClientStreamingResponse::body_withheld`], so its transport must not
    /// be reused for another request.
    ///
    /// An explicit `Content-Length` is enforced exactly. Otherwise an exact
    /// [`Body::size_hint`] selects that framing, and an unknown length selects
    /// chunked framing on HTTP/1.1. Unknown-length HTTP/1.0 uploads are refused.
    /// Producers with trailers must explicitly select chunked framing; one
    /// trailer frame is allowed, followed by end of stream. Invalid framing,
    /// producer errors, and cancellation discard the owned transport.
    ///
    /// `Expect: 100-continue` delays producer polling until a `100` response
    /// or the one-second expectation wait expires. Headers and trailers are
    /// each limited to 64 KiB and 128 fields. Data frames are not copied or
    /// prefetched; their allocation size remains the producer's responsibility.
    /// The explicit context observes cancellation even for a producer that
    /// never wakes. After the head is returned, response-body polling follows
    /// the ordinary [`ClientIncomingBody`] contract.
    pub async fn request_with_body<T, B>(
        cx: &crate::cx::Cx,
        io: T,
        head: crate::http::h1::stream::RequestHead,
        body: B,
    ) -> Result<ClientStreamingResponse<T>, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        B: Body,
        B::Error: std::fmt::Display,
    {
        Self::request_with_body_and_max_body_size(cx, io, head, body, DEFAULT_MAX_BODY_SIZE).await
    }

    /// Like [`Self::request_with_body`], with an explicit maximum response
    /// body size. This limit does not collect or limit the request body.
    pub async fn request_with_body_and_max_body_size<T, B>(
        cx: &crate::cx::Cx,
        mut io: T,
        head: crate::http::h1::stream::RequestHead,
        body: B,
        max_body_size: usize,
    ) -> Result<ClientStreamingResponse<T>, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        B: Body,
        B::Error: std::fmt::Display,
    {
        let exchange = async {
            let (wire, framing, expect_continue) =
                streaming_request_head(&head, body.size_hint().exact())?;
            let mut upload = RequestBodyUpload::new(wire, framing, !expect_continue);
            let mut body = std::pin::pin!(body);
            let mut read_buf = BytesMut::with_capacity(8192);
            let mut scratch = [0u8; 8192];
            let mut informational_responses = 0usize;
            let mut expectation_wait = None;
            let mut upload_error = None;

            let response_head = poll_fn(|task| {
                // This poll runs under the explicit owner's restricted
                // ambient context, including for caller-supplied transports.
                crate::cx::io_gate::require_ambient_io("http::h1::request_with_body")?;
                let mut read_blocked = false;
                // Bound ready/empty producer frames and socket work per poll.
                // Every accepted byte and frame remains owned across yielding.
                for _ in 0..64 {
                    while let Some(response) = take_streaming_response_head(&mut read_buf)? {
                        if (100..=199).contains(&response.status) && response.status != 101 {
                            informational_responses += 1;
                            if informational_responses > MAX_INFORMATIONAL_RESPONSES {
                                return Poll::Ready(Err(HttpError::TooManyInformationalResponses {
                                    actual: informational_responses,
                                    limit: MAX_INFORMATIONAL_RESPONSES,
                                }));
                            }
                            if response.status == 100 {
                                upload.allow_body();
                                expectation_wait = None;
                            }
                            // Parse a coalesced final response before polling
                            // the producer, even when a 100 preceded it.
                            continue;
                        }
                        return Poll::Ready(Ok(response));
                    }

                    if (upload.started() || upload_error.is_some()) && !read_blocked {
                        let mut buf = ReadBuf::new(&mut scratch);
                        match Pin::new(&mut io).poll_read(task, &mut buf) {
                            Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                                return Poll::Ready(Err(HttpError::Io(
                                    upload_error.take().unwrap_or_else(|| {
                                        std::io::Error::new(
                                            std::io::ErrorKind::UnexpectedEof,
                                            "connection closed before response headers",
                                        )
                                    }),
                                )));
                            }
                            Poll::Ready(Ok(())) => {
                                read_buf.extend_from_slice(buf.filled());
                                continue;
                            }
                            Poll::Ready(Err(error)) => {
                                return Poll::Ready(Err(HttpError::Io(
                                    upload_error.take().unwrap_or(error),
                                )));
                            }
                            Poll::Pending => read_blocked = true,
                        }
                    }

                    if upload.waiting_for_continue() {
                        let wait = expectation_wait.get_or_insert_with(|| {
                            if let Some(driver) = cx.timer_driver() {
                                let deadline = driver.now().saturating_add_nanos(1_000_000_000);
                                crate::time::Sleep::with_timer_driver(deadline, driver)
                            } else {
                                crate::time::Sleep::after(cx.now(), EXPECT_CONTINUE_WAIT)
                            }
                        });
                        if Pin::new(wait).poll_deadline(task).is_ready() {
                            upload.allow_body();
                            expectation_wait = None;
                            // Check for a final response once more before
                            // sending a body whose expectation just expired.
                            read_blocked = false;
                            continue;
                        }
                    }

                    if upload_error.is_some() {
                        return Poll::Pending;
                    }
                    match upload.poll_step(body.as_mut(), &mut io, task) {
                        // The step made progress: loop to poll the response again.
                        Poll::Ready(Ok(true)) => {}
                        Poll::Ready(Ok(false)) | Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(HttpError::Io(error)))
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::BrokenPipe
                                    | std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::ConnectionAborted
                            ) =>
                        {
                            // A peer can reject an upload and close its read
                            // half. Preserve its final 401/413 if available.
                            upload_error = Some(error);
                            read_blocked = false;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    }
                }
                task.waker().wake_by_ref();
                Poll::Pending
            })
            .await?;

            let kind = response_body_kind(
                &response_head.headers,
                response_head.status,
                &head.method,
                max_body_size,
            )?;
            Ok(ClientStreamingResponse {
                head: response_head,
                body: ClientIncomingBody::with_max_body_size(io, kind, read_buf, max_body_size),
                body_withheld: !upload.complete() || upload_error.is_some(),
            })
        };
        let mut exchange = std::pin::pin!(cx.with_ambient(exchange));
        let mut cancelled = std::pin::pin!(cx.cancelled());
        poll_fn(|task| {
            // Check the polling caller before installing the stored owner.
            crate::cx::io_gate::require_ambient_io("http::h1::request_with_body")?;
            if cx.checkpoint().is_err() {
                return Poll::Ready(Err(HttpError::BodyCancelled));
            }
            if cancelled.as_mut().poll(task).is_ready() && cx.checkpoint().is_err() {
                return Poll::Ready(Err(HttpError::BodyCancelled));
            }
            exchange.as_mut().poll(task)
        })
        .await
    }

    /// Send a request over the given transport and return the response.
    pub async fn request<T>(io: T, req: Request) -> Result<Response, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let (response, _io, _body_withheld) = Self::request_with_io(io, req).await?;
        Ok(response)
    }

    /// Send a request over the given transport and return both response + transport.
    ///
    /// This is useful for higher-level clients that want to support HTTP/1.1
    /// keep-alive connection reuse after fully draining the response body.
    ///
    /// Returns [`HttpError::PrefetchedDataRemaining`] if unread bytes remain
    /// in the parser buffer after body drain (for example protocol upgrade
    /// bytes). Callers should use [`request_streaming`](Self::request_streaming)
    /// in that case.
    /// Returns `(response, io, body_withheld)`. `body_withheld` is true when an
    /// `Expect: 100-continue` request body was never written (the server sent a
    /// final response without a `100 Continue`); a caller that pools the returned
    /// `io` MUST NOT reuse it in that case
    /// (br-asupersync-h1-expect-100-pool-h9le7v).
    pub async fn request_with_io<T>(io: T, req: Request) -> Result<(Response, T, bool), HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        Self::request_with_io_and_max_body_size(io, req, DEFAULT_MAX_BODY_SIZE).await
    }

    /// Like [`request_with_io`](Self::request_with_io) but with an explicit
    /// maximum body size limit. Returns `(response, io, body_withheld)`; see
    /// [`request_with_io`](Self::request_with_io) for the `body_withheld` contract.
    pub async fn request_with_io_and_max_body_size<T>(
        io: T,
        req: Request,
        max_body_size: usize,
    ) -> Result<(Response, T, bool), HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // Reuse the method-aware streaming implementation so HEAD responses
        // correctly ignore Content-Length/Transfer-Encoding bodies.
        let mut streaming =
            Self::request_streaming_with_max_body_size(io, req, max_body_size).await?;
        let body_withheld = streaming.body_withheld;

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

        let (io, prefetched) = streaming.body.into_inner_with_buffer();
        if !prefetched.is_empty() {
            return Err(HttpError::PrefetchedDataRemaining(prefetched.len()));
        }
        Ok((response, io, body_withheld))
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
        io: T,
        req: Request,
    ) -> Result<ClientStreamingResponse<T>, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        Self::request_streaming_with_max_body_size(io, req, DEFAULT_MAX_BODY_SIZE).await
    }

    /// Like [`request_streaming`](Self::request_streaming) but with an explicit
    /// maximum body size limit.
    ///
    /// Use this when downloading large files that exceed the default 16 MiB limit.
    pub async fn request_streaming_with_max_body_size<T>(
        mut io: T,
        req: Request,
        max_body_size: usize,
    ) -> Result<ClientStreamingResponse<T>, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let request_method = req.method.clone();

        let expect_continue = unique_header_value(&req.headers, "Expect")?
            .is_some_and(|value| trim_ows(value).eq_ignore_ascii_case("100-continue"));

        // Encode request to bytes (reuse the existing validated encoder).
        let mut codec = Http1ClientCodec::new();
        let mut write_buf = BytesMut::with_capacity(1024);
        codec.encode(req, &mut write_buf)?;

        let header_end = find_headers_end(write_buf.as_ref()).ok_or(HttpError::BadRequestLine)?;
        let (head_bytes, body_bytes) = write_buf.as_ref().split_at(header_end);
        let mut request_body_sent = !expect_continue || body_bytes.is_empty();

        // A body upload that failed because the peer closed. The server may
        // already have answered (for example 413 or 401, then close), so its
        // response is read before this error is reported.
        let mut upload_error: Option<std::io::Error> = None;

        // With `Expect: 100-continue`, send only the request head first and
        // wait for either an interim 100 or a final response before sending the
        // body bytes. This prevents eager upload of large/request-smuggling-
        // sensitive payloads when the server intends to reject early.
        if expect_continue {
            io.write_all(head_bytes).await?;
            io.flush().await?;
        } else {
            upload_error = upload_until_peer_closes(&mut io, write_buf.as_ref()).await?;
        }

        // Read response head (status line + headers).
        let mut read_buf = BytesMut::with_capacity(8192);
        let mut scratch = [0u8; 8192];
        let mut informational_responses = 0usize;
        loop {
            if let Some(end) = find_headers_end(read_buf.as_ref()) {
                if end > DEFAULT_MAX_HEADERS_SIZE {
                    return Err(HttpError::HeadersTooLarge);
                }

                let head_bytes = read_buf.split_to(end);
                let head_str = response_head_str(head_bytes.as_ref());

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

                // RFC 9110: 1xx are informational responses. Keep reading
                // until a final response is received, except 101 which is
                // terminal. `100 Continue` is the signal that allows a deferred
                // request body to be sent.
                if (100..=199).contains(&status) && status != 101 {
                    informational_responses += 1;
                    if informational_responses > MAX_INFORMATIONAL_RESPONSES {
                        return Err(HttpError::TooManyInformationalResponses {
                            actual: informational_responses,
                            limit: MAX_INFORMATIONAL_RESPONSES,
                        });
                    }
                    if status == 100 && !request_body_sent {
                        upload_error = upload_until_peer_closes(&mut io, body_bytes).await?;
                        request_body_sent = true;
                    }
                    continue;
                }

                let kind = response_body_kind(&headers, status, &request_method, max_body_size)?;

                let head = crate::http::h1::stream::ResponseHead {
                    version,
                    status,
                    reason,
                    headers,
                };

                // Preserve any already-buffered bytes even for empty-body
                // responses. On protocol upgrades (101), these bytes belong to
                // the upgraded stream.
                let body_buf = read_buf;

                let body =
                    ClientIncomingBody::with_max_body_size(io, kind, body_buf, max_body_size);
                // `request_body_sent` is false only when an `Expect: 100-continue`
                // body was withheld because this final response arrived without a
                // preceding `100 Continue` (br-asupersync-h1-expect-100-pool-h9le7v).
                return Ok(ClientStreamingResponse {
                    head,
                    body,
                    body_withheld: !request_body_sent || upload_error.is_some(),
                });
            }

            if read_buf.len() > DEFAULT_MAX_HEADERS_SIZE {
                return Err(HttpError::HeadersTooLarge);
            }

            let read = poll_fn(|cx| {
                let mut rb = ReadBuf::new(&mut scratch);
                match Pin::new(&mut io).poll_read(cx, &mut rb) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                }
            });
            let read = if request_body_sent || !read_buf.is_empty() {
                read.await
            } else {
                // Nothing has answered the expectation yet. A server that
                // ignores it would wait for the body forever, so send it once
                // the wait elapses. Dropping the pending read loses nothing.
                let now = crate::cx::Cx::with_current(|cx| cx.timer_driver())
                    .flatten()
                    .map_or_else(crate::time::wall_now, |timer| timer.now());
                let waited =
                    crate::time::timeout(now, EXPECT_CONTINUE_WAIT, std::pin::pin!(read)).await;
                match waited {
                    Ok(read) => read,
                    Err(_elapsed) => {
                        // The deadline can win a poll in which the answer has
                        // already arrived. Look once more, without waiting,
                        // before uploading.
                        let ready = poll_fn(|cx| {
                            let mut rb = ReadBuf::new(&mut scratch);
                            Poll::Ready(match Pin::new(&mut io).poll_read(cx, &mut rb) {
                                Poll::Pending => None,
                                Poll::Ready(Ok(())) => Some(Ok(rb.filled().len())),
                                Poll::Ready(Err(e)) => Some(Err(e)),
                            })
                        })
                        .await;
                        if let Some(read) = ready {
                            read
                        } else {
                            upload_error = upload_until_peer_closes(&mut io, body_bytes).await?;
                            request_body_sent = true;
                            continue;
                        }
                    }
                }
            };

            let n = match read {
                Ok(n) => n,
                Err(error) => return Err(HttpError::Io(upload_error.take().unwrap_or(error))),
            };
            if n == 0 {
                return Err(HttpError::Io(upload_error.take().unwrap_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed before response headers",
                    )
                })));
            }

            read_buf.extend_from_slice(&scratch[..n]);
        }
    }
}

#[derive(Clone, Copy)]
enum UploadFraming {
    ContentLength(u64),
    Chunked,
}

/// Validate the whole head before emitting any bytes. In particular, a size
/// hint only chooses framing; the upload state still checks its actual EOF.
fn streaming_request_head(
    head: &crate::http::h1::stream::RequestHead,
    exact_hint: Option<u64>,
) -> Result<(BytesMut, UploadFraming, bool), HttpError> {
    if Method::from_bytes(head.method.as_str().as_bytes()).is_none() {
        return Err(HttpError::BadMethod);
    }
    if head.uri.is_empty() || head.uri.bytes().any(|byte| byte <= b' ' || byte == 0x7f) {
        return Err(HttpError::BadRequestLine);
    }
    if !matches!(head.version, Version::Http10 | Version::Http11) {
        return Err(HttpError::UnsupportedVersion);
    }
    let te = unique_header_value(&head.headers, "Transfer-Encoding")?;
    let cl = unique_header_value(&head.headers, "Content-Length")?;
    if te.is_some() && cl.is_some() {
        return Err(HttpError::AmbiguousBodyLength);
    }
    let framing = if let Some(te) = te {
        require_transfer_encoding_chunked(te)?;
        if head.version != Version::Http11 {
            return Err(HttpError::BadTransferEncoding);
        }
        UploadFraming::Chunked
    } else if let Some(cl) = cl {
        let value = trim_ows(cl);
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(HttpError::BadContentLength);
        }
        UploadFraming::ContentLength(value.parse().map_err(|_| HttpError::BadContentLength)?)
    } else if let Some(length) = exact_hint {
        UploadFraming::ContentLength(length)
    } else if head.version == Version::Http11 {
        UploadFraming::Chunked
    } else {
        return Err(HttpError::BadContentLength);
    };
    let generated = if te.is_none() && cl.is_none() {
        Some(match framing {
            UploadFraming::ContentLength(length) => ("Content-Length", length.to_string()),
            UploadFraming::Chunked => ("Transfer-Encoding", "chunked".to_owned()),
        })
    } else {
        None
    };
    if head.headers.len().saturating_add(usize::from(generated.is_some())) > MAX_HEADERS {
        return Err(HttpError::TooManyHeaders);
    }
    let expect_continue = unique_header_value(&head.headers, "Expect")?
        .is_some_and(|value| trim_ows(value).eq_ignore_ascii_case("100-continue"));
    let mut length = head
        .method
        .as_str()
        .len()
        .saturating_add(head.uri.len())
        .saturating_add(head.version.as_str().len())
        .saturating_add(6);
    for (name, value) in &head.headers {
        validate_header_field(name, value)?;
        length = length
            .saturating_add(name.len())
            .saturating_add(value.len())
            .saturating_add(4);
    }
    if let Some((name, value)) = &generated {
        length = length
            .saturating_add(name.len())
            .saturating_add(value.len())
            .saturating_add(4);
    }
    if length > DEFAULT_MAX_HEADERS_SIZE {
        return Err(HttpError::HeadersTooLarge);
    }
    let mut wire = BytesMut::with_capacity(length);
    wire.extend_from_slice(head.method.as_str().as_bytes());
    wire.extend_from_slice(b" ");
    wire.extend_from_slice(head.uri.as_bytes());
    wire.extend_from_slice(b" ");
    wire.extend_from_slice(head.version.as_str().as_bytes());
    wire.extend_from_slice(b"\r\n");
    for (name, value) in &head.headers {
        wire.extend_from_slice(name.as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(value.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    if let Some((name, value)) = generated {
        wire.extend_from_slice(name.as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(value.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"\r\n");
    Ok((wire, framing, expect_continue))
}

fn take_streaming_response_head(
    bytes: &mut BytesMut,
) -> Result<Option<crate::http::h1::stream::ResponseHead>, HttpError> {
    let Some(end) = find_headers_end(bytes.as_ref()) else {
        return if bytes.len() > DEFAULT_MAX_HEADERS_SIZE {
            Err(HttpError::HeadersTooLarge)
        } else {
            Ok(None)
        };
    };
    if end > DEFAULT_MAX_HEADERS_SIZE {
        return Err(HttpError::HeadersTooLarge);
    }
    let encoded = bytes.split_to(end);
    let text = response_head_str(encoded.as_ref());
    let mut lines = text.split("\r\n");
    let (version, status, reason) =
        parse_status_line(lines.next().ok_or(HttpError::BadRequestLine)?)?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if headers.len() == MAX_HEADERS {
            return Err(HttpError::TooManyHeaders);
        }
        headers.push(parse_header_line(line)?);
    }
    Ok(Some(crate::http::h1::stream::ResponseHead {
        version,
        status,
        reason,
        headers,
    }))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UploadPhase {
    Head,
    FlushHead,
    WaitContinue,
    NextFrame,
    ChunkPrefix,
    Data,
    ChunkSuffix,
    FinalBytes,
    FlushBody,
    Complete,
}

/// The only retained producer data is the current frame. Control bytes have
/// their own bounded buffer, and every cursor advances only after a write.
struct RequestBodyUpload<D> {
    phase: UploadPhase,
    framing: UploadFraming,
    wire: BytesMut,
    wire_offset: usize,
    data: Option<D>,
    trailers: Option<BytesMut>,
    body_allowed: bool,
}

impl<D: Buf> RequestBodyUpload<D> {
    fn new(wire: BytesMut, framing: UploadFraming, body_allowed: bool) -> Self {
        Self {
            phase: UploadPhase::Head,
            framing,
            wire,
            wire_offset: 0,
            data: None,
            trailers: None,
            body_allowed,
        }
    }

    fn started(&self) -> bool {
        self.phase != UploadPhase::Head || self.wire_offset != 0
    }

    fn complete(&self) -> bool {
        self.phase == UploadPhase::Complete
    }

    fn waiting_for_continue(&self) -> bool {
        self.phase == UploadPhase::WaitContinue
    }

    fn allow_body(&mut self) {
        self.body_allowed = true;
        if self.phase == UploadPhase::WaitContinue {
            self.phase = UploadPhase::NextFrame;
        }
    }

    /// One bounded write, producer poll, or state transition. `true` means
    /// progress, `false` means the complete upload has been flushed.
    fn poll_step<T, B>(
        &mut self,
        mut body: Pin<&mut B>,
        io: &mut T,
        task: &mut std::task::Context<'_>,
    ) -> Poll<Result<bool, HttpError>>
    where
        T: AsyncWrite + Unpin,
        B: Body<Data = D>,
        B::Error: std::fmt::Display,
    {
        match self.phase {
            UploadPhase::Head
            | UploadPhase::ChunkPrefix
            | UploadPhase::ChunkSuffix
            | UploadPhase::FinalBytes => {
                if self.wire_offset < self.wire.len() {
                    let end = self.wire.len().min(self.wire_offset.saturating_add(16 * 1024));
                    let remaining = &self.wire[self.wire_offset..end];
                    let written =
                        std::task::ready!(Pin::new(&mut *io).poll_write(task, remaining))?;
                    validate_upload_write(written, remaining.len())?;
                    self.wire_offset += written;
                }
                if self.wire_offset == self.wire.len() {
                    self.wire.clear();
                    self.wire_offset = 0;
                    self.phase = match self.phase {
                        UploadPhase::Head => UploadPhase::FlushHead,
                        UploadPhase::ChunkPrefix => UploadPhase::Data,
                        UploadPhase::ChunkSuffix => UploadPhase::NextFrame,
                        UploadPhase::FinalBytes => UploadPhase::FlushBody,
                        _ => unreachable!(),
                    };
                    if self.phase == UploadPhase::FlushBody {
                        // The terminating chunk was accepted. Finish its
                        // flush before classifying an immediately arriving
                        // response as an early rejection.
                        return self.poll_step(body, io, task);
                    }
                }
            }
            UploadPhase::FlushHead => {
                std::task::ready!(Pin::new(&mut *io).poll_flush(task))?;
                self.phase = if self.body_allowed {
                    UploadPhase::NextFrame
                } else {
                    UploadPhase::WaitContinue
                };
            }
            UploadPhase::WaitContinue => return Poll::Pending,
            UploadPhase::NextFrame => {
                match std::task::ready!(body.as_mut().poll_frame(task)) {
                    Some(Err(error)) => {
                        return Poll::Ready(Err(HttpError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("request body producer failed: {error}"),
                        ))));
                    }
                    Some(Ok(Frame::Data(data))) => {
                        if self.trailers.is_some() {
                            return Poll::Ready(Err(HttpError::TrailersNotAllowed));
                        }
                        let length = data.remaining();
                        let bytes = u64::try_from(length).map_err(|_| HttpError::BodyTooLarge)?;
                        if let UploadFraming::ContentLength(remaining) = &mut self.framing {
                            if bytes > *remaining {
                                return Poll::Ready(Err(HttpError::BadContentLength));
                            }
                            *remaining -= bytes;
                        }
                        if length != 0 {
                            self.data = Some(data);
                            self.phase = if matches!(self.framing, UploadFraming::Chunked) {
                                append_chunk_size_line(&mut self.wire, length);
                                UploadPhase::ChunkPrefix
                            } else {
                                UploadPhase::Data
                            };
                        }
                    }
                    Some(Ok(Frame::Trailers(trailers))) => {
                        if !matches!(self.framing, UploadFraming::Chunked) || self.trailers.is_some()
                        {
                            return Poll::Ready(Err(HttpError::TrailersNotAllowed));
                        }
                        self.trailers = Some(streaming_request_trailers(&trailers)?);
                        // Confirm producer EOF before committing the final
                        // chunk; a second trailer/data frame is an error.
                    }
                    None => {
                        if matches!(self.framing, UploadFraming::ContentLength(left) if left != 0) {
                            return Poll::Ready(Err(HttpError::BadContentLength));
                        }
                        if matches!(self.framing, UploadFraming::Chunked) {
                            self.wire = self
                                .trailers
                                .take()
                                .unwrap_or_else(|| BytesMut::from(&b"0\r\n\r\n"[..]));
                            self.phase = UploadPhase::FinalBytes;
                        } else {
                            self.phase = UploadPhase::FlushBody;
                            return self.poll_step(body, io, task);
                        }
                    }
                }
            }
            UploadPhase::Data => {
                let data = self.data.as_mut().expect("upload data phase owns a frame");
                let chunk = data.chunk();
                if chunk.is_empty() {
                    return Poll::Ready(Err(HttpError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "request body Buf has remaining bytes but an empty chunk",
                    ))));
                }
                let length = chunk.len().min(16 * 1024);
                let written =
                    std::task::ready!(Pin::new(&mut *io).poll_write(task, &chunk[..length]))?;
                validate_upload_write(written, length)?;
                data.advance(written);
                if !data.has_remaining() {
                    self.data = None;
                    self.phase = if matches!(self.framing, UploadFraming::Chunked) {
                        self.wire.extend_from_slice(b"\r\n");
                        UploadPhase::ChunkSuffix
                    } else {
                        UploadPhase::NextFrame
                    };
                    if self.phase == UploadPhase::NextFrame {
                        // A fixed-length body still owes an actual EOF.
                        // Give it one poll after its last accepted bytes,
                        // so a ready EOF/flush retires before the response.
                        return self.poll_step(body, io, task);
                    }
                }
            }
            UploadPhase::FlushBody => {
                std::task::ready!(Pin::new(&mut *io).poll_flush(task))?;
                self.phase = UploadPhase::Complete;
            }
            UploadPhase::Complete => return Poll::Ready(Ok(false)),
        }
        Poll::Ready(Ok(true))
    }
}

fn validate_upload_write(written: usize, offered: usize) -> Result<(), HttpError> {
    if written == 0 {
        Err(HttpError::Io(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "transport accepted no request bytes",
        )))
    } else if written > offered {
        Err(HttpError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "transport reported more request bytes than offered",
        )))
    } else {
        Ok(())
    }
}

fn streaming_request_trailers(trailers: &HeaderMap) -> Result<BytesMut, HttpError> {
    if trailers.len() > MAX_HEADERS {
        return Err(HttpError::TooManyHeaders);
    }
    let mut length = 5usize; // Last chunk and final CRLF.
    for (name, value) in trailers.iter() {
        if is_forbidden_trailer(name.as_str()) {
            return Err(HttpError::TrailersNotAllowed);
        }
        length = length
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(4);
        if length > DEFAULT_MAX_TRAILERS_SIZE {
            return Err(HttpError::HeadersTooLarge);
        }
        // Lossy conversion preserves all forbidden ASCII controls while
        // allowing legal obs-text; the original bytes go on the wire. The
        // length bound above also bounds this validation allocation.
        validate_header_field(name.as_str(), &String::from_utf8_lossy(value.as_bytes()))?;
    }
    let mut wire = BytesMut::with_capacity(length);
    wire.extend_from_slice(b"0\r\n");
    for (name, value) in trailers.iter() {
        wire.extend_from_slice(name.as_str().as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(value.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"\r\n");
    Ok(wire)
}

/// Writes and flushes request bytes: a whole request, or a deferred
/// `Expect: 100-continue` body. When the peer closed during the upload, it may
/// already have answered (for example 413 or 401, then close), so that error is
/// returned for the caller to report only if no response can be read. Any other
/// write failure is returned at once.
async fn upload_until_peer_closes<T: AsyncWrite + Unpin>(
    io: &mut T,
    body: &[u8],
) -> std::io::Result<Option<std::io::Error>> {
    let uploaded = async {
        io.write_all(body).await?;
        io.flush().await
    }
    .await;
    match uploaded {
        Ok(()) => Ok(None),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ) =>
        {
            Ok(Some(error))
        }
        Err(error) => Err(error),
    }
}

/// A streaming HTTP/1 response (head + body).
#[derive(Debug)]
pub struct ClientStreamingResponse<T> {
    /// Response head (status line + headers).
    pub head: crate::http::h1::stream::ResponseHead,
    /// Streaming response body.
    pub body: ClientIncomingBody<T>,
    /// True when an `Expect: 100-continue` request body was withheld because a
    /// final (non-100) response arrived before the interim `100 Continue`. The
    /// encoder advertised `Content-Length: N` but never wrote the N body bytes,
    /// so the connection is in an indeterminate framing state and MUST NOT be
    /// returned to a keep-alive pool — the next request written on it would be
    /// consumed by the server as this request's missing body
    /// (br-asupersync-h1-expect-100-pool-h9le7v). Mirrors hyper disabling
    /// keep-alive in this case. It is also true when the body upload failed
    /// because the peer closed, and this response was read afterwards.
    pub body_withheld: bool,
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

    fn with_max_body_size(
        io: T,
        kind: ClientBodyKind,
        buffer: BytesMut,
        max_body_size: usize,
    ) -> Self {
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
            max_body_size: u64::try_from(max_body_size).unwrap_or(u64::MAX),
            max_trailers_size: Self::DEFAULT_MAX_TRAILERS_SIZE,
            max_buffered_bytes: Self::DEFAULT_MAX_BUFFERED_BYTES,
        }
    }

    /// Consume the body and return the underlying transport plus prefetched bytes.
    ///
    /// Prefetched bytes are bytes already read while parsing response headers.
    /// This is important for protocol upgrades (for example `101 Switching
    /// Protocols`) where upgraded-protocol bytes can arrive in the same read
    /// as the terminal HTTP response head.
    ///
    /// Callers should only use this once the body has been fully drained.
    #[must_use]
    pub fn into_inner_with_buffer(self) -> (T, BytesMut) {
        (self.io, self.buffer)
    }

    /// Consume the body and return the underlying transport.
    ///
    /// This drops any prefetched bytes. Use
    /// [`into_inner_with_buffer`](Self::into_inner_with_buffer) when callers
    /// need to preserve bytes that were read ahead.
    ///
    /// Callers should only use this once the body has been fully drained.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.into_inner_with_buffer().0
    }

    /// Whether this body reached an unambiguous reusable HTTP message boundary.
    /// The pool additionally checks response/request connection policy. An EOF
    /// body, unconsumed read-ahead, or a partial/error framing state is never
    /// sufficient, even if the body has become terminal.
    pub(super) fn is_complete_for_reuse(&self) -> bool {
        self.is_at_message_end() && self.buffer.is_empty()
    }

    /// Used only on a fresh body or after a successful frame poll. This also
    /// recognizes Content-Length: 0 before the caller performs an EOF poll.
    pub(super) fn is_at_message_end(&self) -> bool {
        matches!(
            self.kind,
            ClientBodyKind::Empty
                | ClientBodyKind::ContentLength { remaining: 0 }
                | ClientBodyKind::Chunked {
                    state: ChunkedReadState::Done,
                    ..
                }
        )
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
                    let Some(line_end) = find_chunk_size_line_end(self.buffer.as_ref())? else {
                        return Ok(None);
                    };

                    let line = &self.buffer.as_ref()[..line_end];
                    let chunk_size = parse_chunk_size_line(line)?;

                    self.buffer.advance(line_end + 2);

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
                    self.buffer.advance(2);
                    *state = ChunkedReadState::SizeLine;
                }

                ChunkedReadState::Trailers => {
                    let line_end = self.buffer.as_ref().windows(2).position(|w| w == b"\r\n");
                    let Some(line_end) = line_end else {
                        if *trailers_bytes + self.buffer.len() > self.max_trailers_size {
                            return Err(HttpError::HeadersTooLarge);
                        }
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
                    let (name, value) = parse_header_line(line_str)?;
                    // br-asupersync-135g0e: RFC 9110 §6.5.1 forbids framing /
                    // routing / auth / payload / cache-control trailers in either
                    // direction. Mirror the codec path so a response trailer can't
                    // smuggle a Content-Length / Transfer-Encoding override into an
                    // intermediary that merges trailers into the header set.
                    if is_forbidden_trailer(&name) {
                        return Err(HttpError::BadHeader);
                    }
                    trailers.append(
                        HeaderName::from_string(&name),
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
#[path = "client_inline_tests.rs"]
mod tests;
