//! HTTP/1.1 codec for framed transports.
//!
//! [`Http1Codec`] implements [`Decoder`] for parsing HTTP/1.1 requests and
//! [`Encoder`] for serializing HTTP/1.1 responses, suitable for use with
//! [`Framed`](crate::codec::Framed).

use crate::bytes::BytesMut;
use crate::codec::{Decoder, Encoder};
use crate::http::h1::types::{self, Method, Request, Response, Version};
use std::fmt;
use std::io;

/// Maximum allowed header block size (64 KiB).
const DEFAULT_MAX_HEADERS_SIZE: usize = 64 * 1024;

/// Maximum number of headers.
const MAX_HEADERS: usize = 128;

/// Maximum allowed request line length.
const MAX_REQUEST_LINE: usize = 8192;

/// HTTP/1.1 protocol errors.
#[derive(Debug)]
pub enum HttpError {
    /// An I/O error from the transport.
    Io(io::Error),
    /// The request line is malformed.
    BadRequestLine,
    /// A header line is malformed.
    BadHeader,
    /// Unsupported HTTP version in request.
    UnsupportedVersion,
    /// Unrecognised HTTP method.
    BadMethod,
    /// Content-Length header is not a valid integer.
    BadContentLength,
    /// Header block exceeds the configured limit.
    HeadersTooLarge,
    /// Too many headers.
    TooManyHeaders,
    /// Request line too long.
    RequestLineTooLong,
    /// Incomplete chunked encoding.
    BadChunkedEncoding,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::BadRequestLine => write!(f, "malformed request line"),
            Self::BadHeader => write!(f, "malformed header"),
            Self::UnsupportedVersion => write!(f, "unsupported HTTP version"),
            Self::BadMethod => write!(f, "unrecognised HTTP method"),
            Self::BadContentLength => write!(f, "invalid Content-Length"),
            Self::HeadersTooLarge => write!(f, "header block too large"),
            Self::TooManyHeaders => write!(f, "too many headers"),
            Self::RequestLineTooLong => write!(f, "request line too long"),
            Self::BadChunkedEncoding => write!(f, "malformed chunked encoding"),
        }
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for HttpError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Codec state machine.
#[derive(Debug)]
enum DecodeState {
    /// Waiting for a complete request line + headers block.
    Head,
    /// Headers parsed; reading exactly `remaining` body bytes.
    Body {
        method: Method,
        uri: String,
        version: Version,
        headers: Vec<(String, String)>,
        remaining: usize,
    },
    /// Headers parsed; reading chunked transfer-encoding body.
    Chunked {
        method: Method,
        uri: String,
        version: Version,
        headers: Vec<(String, String)>,
    },
}

/// HTTP/1.1 request decoder and response encoder.
///
/// Implements [`Decoder<Item = Request>`] for parsing incoming HTTP/1.1
/// requests and [`Encoder<Response>`] for serializing outgoing responses.
///
/// # Limits
///
/// - Maximum header block size: 64 KiB (configurable via [`max_headers_size`](Self::max_headers_size))
/// - Maximum number of headers: 128
/// - Maximum request line: 8 KiB
pub struct Http1Codec {
    state: DecodeState,
    max_headers_size: usize,
}

impl Http1Codec {
    /// Create a new codec with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: DecodeState::Head,
            max_headers_size: DEFAULT_MAX_HEADERS_SIZE,
        }
    }

    /// Set the maximum header block size.
    #[must_use]
    pub fn max_headers_size(mut self, size: usize) -> Self {
        self.max_headers_size = size;
        self
    }
}

impl Default for Http1Codec {
    fn default() -> Self {
        Self::new()
    }
}

/// Find the position of `\r\n\r\n` in `buf`, returning the index of the
/// first byte after the delimiter.
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Parse the request line: `METHOD SP URI SP VERSION CRLF`.
fn parse_request_line(line: &str) -> Result<(Method, String, Version), HttpError> {
    let mut parts = line.splitn(3, ' ');
    let method_str = parts.next().ok_or(HttpError::BadRequestLine)?;
    let uri = parts.next().ok_or(HttpError::BadRequestLine)?;
    let version_str = parts.next().ok_or(HttpError::BadRequestLine)?;

    let method = Method::from_bytes(method_str.as_bytes()).ok_or(HttpError::BadMethod)?;
    let version =
        Version::from_bytes(version_str.as_bytes()).ok_or(HttpError::UnsupportedVersion)?;

    Ok((method, uri.to_owned(), version))
}

/// Parse a single `Name: Value` header line.
fn parse_header_line(line: &str) -> Result<(String, String), HttpError> {
    let colon = line.find(':').ok_or(HttpError::BadHeader)?;
    let name = line[..colon].trim().to_owned();
    let value = line[colon + 1..].trim().to_owned();
    if name.is_empty() {
        return Err(HttpError::BadHeader);
    }
    Ok((name, value))
}

/// Look up a header value (case-insensitive name match).
fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Determine body length from headers.
fn body_length(headers: &[(String, String)]) -> Result<BodyKind, HttpError> {
    if let Some(te) = header_value(headers, "Transfer-Encoding") {
        if te.eq_ignore_ascii_case("chunked") {
            return Ok(BodyKind::Chunked);
        }
    }
    if let Some(cl) = header_value(headers, "Content-Length") {
        let len: usize = cl.parse().map_err(|_| HttpError::BadContentLength)?;
        return Ok(BodyKind::ContentLength(len));
    }
    Ok(BodyKind::ContentLength(0))
}

enum BodyKind {
    ContentLength(usize),
    Chunked,
}

/// Decode a chunked body from `buf`. Returns `Some((body, consumed))` when
/// complete, or `None` if more data is needed.
fn decode_chunked(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, HttpError> {
    let mut body = Vec::new();
    let mut pos = 0;

    loop {
        let remaining = &buf[pos..];
        let Some(line_end) = remaining.windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };

        let size_str = std::str::from_utf8(&remaining[..line_end])
            .map_err(|_| HttpError::BadChunkedEncoding)?;
        let chunk_size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|_| HttpError::BadChunkedEncoding)?;

        pos += line_end + 2; // skip size line + CRLF

        if chunk_size == 0 {
            // Terminal chunk. Expect trailing CRLF.
            if buf.len() < pos + 2 {
                return Ok(None);
            }
            pos += 2;
            return Ok(Some((body, pos)));
        }

        // Need chunk_size bytes + CRLF
        if buf.len() < pos + chunk_size + 2 {
            return Ok(None);
        }
        body.extend_from_slice(&buf[pos..pos + chunk_size]);
        pos += chunk_size + 2;
    }
}

/// Parse the head (request line + headers) from `src`, splitting off the
/// consumed bytes. Returns `None` if the full header block hasn't arrived yet.
#[allow(clippy::type_complexity)]
fn decode_head(
    src: &mut BytesMut,
    max_headers_size: usize,
) -> Result<Option<(Method, String, Version, Vec<(String, String)>, BodyKind)>, HttpError> {
    // Check request-line length limit
    if let Some(line_end) = src.as_ref().windows(2).position(|w| w == b"\r\n") {
        if line_end > MAX_REQUEST_LINE {
            return Err(HttpError::RequestLineTooLong);
        }
    }

    let Some(end) = find_headers_end(src.as_ref()) else {
        if src.len() > max_headers_size {
            return Err(HttpError::HeadersTooLarge);
        }
        return Ok(None);
    };

    if end > max_headers_size {
        return Err(HttpError::HeadersTooLarge);
    }

    let head_bytes = src.split_to(end);
    let head_str =
        std::str::from_utf8(head_bytes.as_ref()).map_err(|_| HttpError::BadRequestLine)?;

    let mut lines = head_str.split("\r\n");
    let request_line = lines.next().ok_or(HttpError::BadRequestLine)?;
    let (method, uri, version) = parse_request_line(request_line)?;

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

    let kind = body_length(&headers)?;
    Ok(Some((method, uri, version, headers, kind)))
}

/// Extract the head fields from a `DecodeState::Body` or `DecodeState::Chunked`.
fn take_head(state: DecodeState) -> (Method, String, Version, Vec<(String, String)>) {
    match state {
        DecodeState::Body {
            method,
            uri,
            version,
            headers,
            ..
        }
        | DecodeState::Chunked {
            method,
            uri,
            version,
            headers,
        } => (method, uri, version, headers),
        DecodeState::Head => unreachable!("take_head called in Head state"),
    }
}

impl Decoder for Http1Codec {
    type Item = Request;
    type Error = HttpError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Request>, HttpError> {
        loop {
            match &self.state {
                DecodeState::Head => {
                    let Some((method, uri, version, headers, kind)) =
                        decode_head(src, self.max_headers_size)?
                    else {
                        return Ok(None);
                    };

                    match kind {
                        BodyKind::ContentLength(0) => {
                            return Ok(Some(Request {
                                method,
                                uri,
                                version,
                                headers,
                                body: Vec::new(),
                            }));
                        }
                        BodyKind::ContentLength(len) => {
                            self.state = DecodeState::Body {
                                method,
                                uri,
                                version,
                                headers,
                                remaining: len,
                            };
                        }
                        BodyKind::Chunked => {
                            self.state = DecodeState::Chunked {
                                method,
                                uri,
                                version,
                                headers,
                            };
                        }
                    }
                }

                DecodeState::Body { remaining, .. } => {
                    let need = *remaining;
                    if src.len() < need {
                        return Ok(None);
                    }

                    let body_bytes = src.split_to(need);
                    let old = std::mem::replace(&mut self.state, DecodeState::Head);
                    let (method, uri, version, headers) = take_head(old);

                    return Ok(Some(Request {
                        method,
                        uri,
                        version,
                        headers,
                        body: body_bytes.to_vec(),
                    }));
                }

                DecodeState::Chunked { .. } => {
                    let Some((body, consumed)) = decode_chunked(src.as_ref())? else {
                        return Ok(None);
                    };
                    let _ = src.split_to(consumed);

                    let old = std::mem::replace(&mut self.state, DecodeState::Head);
                    let (method, uri, version, headers) = take_head(old);

                    return Ok(Some(Request {
                        method,
                        uri,
                        version,
                        headers,
                        body,
                    }));
                }
            }
        }
    }
}

impl Encoder<Response> for Http1Codec {
    type Error = HttpError;

    fn encode(&mut self, resp: Response, dst: &mut BytesMut) -> Result<(), HttpError> {
        use std::fmt::Write;

        let reason = if resp.reason.is_empty() {
            types::default_reason(resp.status)
        } else {
            &resp.reason
        };

        // Status line
        let mut head = String::with_capacity(256);
        let _ = write!(head, "{} {} {}\r\n", resp.version, resp.status, reason);

        // Headers
        let mut has_content_length = false;
        for (name, value) in &resp.headers {
            if name.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
            }
            let _ = write!(head, "{name}: {value}\r\n");
        }

        // Auto-add Content-Length if not present
        if !has_content_length {
            let _ = write!(head, "Content-Length: {}\r\n", resp.body.len());
        }

        head.push_str("\r\n");

        dst.extend_from_slice(head.as_bytes());
        if !resp.body.is_empty() {
            dst.extend_from_slice(&resp.body);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_one(codec: &mut Http1Codec, data: &[u8]) -> Result<Option<Request>, HttpError> {
        let mut buf = BytesMut::from(data);
        codec.decode(&mut buf)
    }

    fn encode_one(codec: &mut Http1Codec, resp: Response) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(1024);
        codec.encode(resp, &mut buf).unwrap();
        buf.to_vec()
    }

    #[test]
    fn decode_simple_get() {
        let mut codec = Http1Codec::new();
        let req = decode_one(&mut codec, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(req.method, Method::Get);
        assert_eq!(req.uri, "/");
        assert_eq!(req.version, Version::Http11);
        assert_eq!(req.headers.len(), 1);
        assert_eq!(req.headers[0].0, "Host");
        assert_eq!(req.headers[0].1, "localhost");
        assert!(req.body.is_empty());
    }

    #[test]
    fn decode_post_with_body() {
        let mut codec = Http1Codec::new();
        let raw = b"POST /data HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let req = decode_one(&mut codec, raw).unwrap().unwrap();
        assert_eq!(req.method, Method::Post);
        assert_eq!(req.uri, "/data");
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn decode_chunked_body() {
        let mut codec = Http1Codec::new();
        let raw = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                     5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let req = decode_one(&mut codec, raw).unwrap().unwrap();
        assert_eq!(req.body, b"hello world");
    }

    #[test]
    fn decode_incomplete_returns_none() {
        let mut codec = Http1Codec::new();
        let result = decode_one(&mut codec, b"GET / HTTP/1.1\r\nHost:");
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn decode_incomplete_body_returns_none() {
        let mut codec = Http1Codec::new();
        let result = decode_one(
            &mut codec,
            b"POST /x HTTP/1.1\r\nContent-Length: 10\r\n\r\nhel",
        );
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn decode_extension_method() {
        let mut codec = Http1Codec::new();
        let req = decode_one(&mut codec, b"PURGE /cache HTTP/1.1\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(req.method, Method::Extension("PURGE".into()));
    }

    #[test]
    fn decode_unsupported_version() {
        let mut codec = Http1Codec::new();
        let result = decode_one(&mut codec, b"GET / HTTP/2.0\r\n\r\n");
        assert!(matches!(result, Err(HttpError::UnsupportedVersion)));
    }

    #[test]
    fn decode_headers_too_large() {
        let mut codec = Http1Codec::new().max_headers_size(32);
        let result = decode_one(
            &mut codec,
            b"GET / HTTP/1.1\r\nX-Large: aaaaaaaaaaaaaaa\r\n\r\n",
        );
        assert!(matches!(result, Err(HttpError::HeadersTooLarge)));
    }

    #[test]
    fn decode_bad_content_length() {
        let mut codec = Http1Codec::new();
        let result = decode_one(
            &mut codec,
            b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
        );
        assert!(matches!(result, Err(HttpError::BadContentLength)));
    }

    #[test]
    fn decode_multiple_headers() {
        let mut codec = Http1Codec::new();
        let req = decode_one(
            &mut codec,
            b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(req.headers.len(), 3);
    }

    #[test]
    fn decode_http10() {
        let mut codec = Http1Codec::new();
        let req = decode_one(&mut codec, b"GET / HTTP/1.0\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(req.version, Version::Http10);
    }

    #[test]
    fn encode_simple_response() {
        let mut codec = Http1Codec::new();
        let resp = Response::new(200, "OK", b"hello".to_vec());
        let bytes = encode_one(&mut codec, resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn encode_empty_body() {
        let mut codec = Http1Codec::new();
        let resp = Response::new(204, "No Content", Vec::new());
        let bytes = encode_one(&mut codec, resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Content-Length: 0\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn encode_with_explicit_headers() {
        let mut codec = Http1Codec::new();
        let resp = Response::new(200, "OK", b"{}".to_vec())
            .with_header("Content-Type", "application/json")
            .with_header("Content-Length", "2");
        let bytes = encode_one(&mut codec, resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Content-Type: application/json\r\n"));
        assert_eq!(s.matches("Content-Length").count(), 1);
    }

    #[test]
    fn encode_default_reason_phrase() {
        let mut codec = Http1Codec::new();
        let resp = Response::new(404, "", Vec::new());
        let bytes = encode_one(&mut codec, resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn decode_sequential_requests() {
        let mut codec = Http1Codec::new();
        let raw = b"GET /a HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\nHost: b\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);

        let r1 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(r1.uri, "/a");

        let r2 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(r2.uri, "/b");
    }
}
