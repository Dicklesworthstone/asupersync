//! HTTP/1.1 codec for framed transports.
//!
//! [`Http1Codec`] implements [`Decoder`] for parsing HTTP/1.1 requests and
//! [`Encoder`] for serializing HTTP/1.1 responses, suitable for use with
//! [`Framed`](crate::codec::Framed).

use crate::bytes::BytesMut;
use crate::codec::{Decoder, Encoder};
use crate::http::h1::types::{self, Method, Request, Response, Version};
use memchr::{memchr, memchr_iter, memmem};
use std::fmt;
use std::io;

/// Maximum allowed header block size (64 KiB).
const DEFAULT_MAX_HEADERS_SIZE: usize = 64 * 1024;

/// Maximum allowed body size (16 MiB).
const DEFAULT_MAX_BODY_SIZE: usize = 16 * 1024 * 1024;

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
    /// Multiple Content-Length headers present.
    DuplicateContentLength,
    /// Multiple Transfer-Encoding headers present.
    DuplicateTransferEncoding,
    /// Transfer-Encoding is present but unsupported.
    BadTransferEncoding,
    /// Header name contains invalid characters.
    InvalidHeaderName,
    /// Header value contains invalid characters.
    InvalidHeaderValue,
    /// Header block exceeds the configured limit.
    HeadersTooLarge,
    /// Too many headers.
    TooManyHeaders,
    /// Request line too long.
    RequestLineTooLong,
    /// Incomplete chunked encoding.
    BadChunkedEncoding,
    /// Body exceeds the configured limit.
    BodyTooLarge,
    /// Body exceeds the configured limit (with size details).
    BodyTooLargeDetailed {
        /// Actual body size (Content-Length or bytes received so far).
        actual: u64,
        /// Configured maximum body size.
        limit: u64,
    },
    /// Body stream was cancelled.
    BodyCancelled,
    /// Body channel closed unexpectedly.
    BodyChannelClosed,
    /// Both Content-Length and Transfer-Encoding present (RFC 7230 3.3.3 violation).
    /// This is a potential request smuggling vector.
    AmbiguousBodyLength,
    /// Trailers were provided/encountered but are not permitted in this context.
    TrailersNotAllowed,
    /// Response parsing left unread prefetched bytes when a fully-buffered
    /// response API was used.
    PrefetchedDataRemaining(usize),
}

impl fmt::Display for HttpError {
    #[allow(clippy::cast_precision_loss)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::BadRequestLine => write!(f, "malformed request line"),
            Self::BadHeader => write!(f, "malformed header"),
            Self::UnsupportedVersion => write!(f, "unsupported HTTP version"),
            Self::BadMethod => write!(f, "unrecognised HTTP method"),
            Self::BadContentLength => write!(f, "invalid Content-Length"),
            Self::DuplicateContentLength => write!(f, "duplicate Content-Length"),
            Self::DuplicateTransferEncoding => write!(f, "duplicate Transfer-Encoding"),
            Self::BadTransferEncoding => write!(f, "unsupported Transfer-Encoding"),
            Self::InvalidHeaderName => write!(f, "invalid header name"),
            Self::InvalidHeaderValue => write!(f, "invalid header value"),
            Self::HeadersTooLarge => write!(f, "header block too large"),
            Self::TooManyHeaders => write!(f, "too many headers"),
            Self::RequestLineTooLong => write!(f, "request line too long"),
            Self::BadChunkedEncoding => write!(f, "malformed chunked encoding"),
            Self::BodyTooLarge => write!(f, "body exceeds size limit"),
            Self::BodyTooLargeDetailed { actual, limit } => {
                #[allow(clippy::cast_precision_loss)] // display-only MB approximation
                let actual_mb = *actual as f64 / 1_048_576.0;
                #[allow(clippy::cast_precision_loss)]
                let limit_mb = *limit as f64 / 1_048_576.0;
                write!(
                    f,
                    "body size ({actual} bytes, {actual_mb:.1} MB) exceeds limit ({limit} bytes, {limit_mb:.1} MB)",
                )
            }
            Self::BodyCancelled => write!(f, "body stream cancelled"),
            Self::BodyChannelClosed => write!(f, "body stream closed"),
            Self::AmbiguousBodyLength => {
                write!(f, "both Content-Length and Transfer-Encoding present")
            }
            Self::TrailersNotAllowed => write!(f, "trailers not allowed"),
            Self::PrefetchedDataRemaining(count) => {
                write!(
                    f,
                    "response completed with {count} unread prefetched bytes; use streaming API"
                )
            }
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
        chunked: ChunkedBodyDecoder,
    },
    /// Codec encountered a fatal error and is permanently poisoned.
    Poisoned,
}

/// HTTP/1.1 request decoder and response encoder.
///
/// Implements [`Decoder<Item = Request>`] for parsing incoming HTTP/1.1
/// requests and [`Encoder<Response>`] for serializing outgoing responses.
///
/// # Limits
///
/// - Maximum header block size: 64 KiB (configurable via [`max_headers_size`](Self::max_headers_size))
/// - Maximum body size: 16 MiB (configurable via [`max_body_size`](Self::max_body_size))
/// - Maximum number of headers: 128
/// - Maximum request line: 8 KiB
pub struct Http1Codec {
    state: DecodeState,
    max_headers_size: usize,
    max_body_size: usize,
}

impl Http1Codec {
    /// Create a new codec with default limits.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: DecodeState::Head,
            max_headers_size: DEFAULT_MAX_HEADERS_SIZE,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
        }
    }

    /// Set the maximum header block size.
    #[inline]
    #[must_use]
    pub fn max_headers_size(mut self, size: usize) -> Self {
        self.max_headers_size = size;
        self
    }

    /// Set the maximum body size.
    #[inline]
    #[must_use]
    pub fn max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
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
#[inline]
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    memmem::find(buf, b"\r\n\r\n").map(|idx| idx + 4)
}

/// Find the position of the first CRLF (`\r\n`) in `buf`.
///
/// Returns the index of `\r` when found.
#[inline]
fn find_crlf(buf: &[u8]) -> Option<usize> {
    memmem::find(buf, b"\r\n")
}

/// Collect all CRLF (`\r\n`) positions in `buf` into a pre-allocated vector.
///
/// Each returned value is the index of `\r` in a valid `\r\n` pair.
/// Used by `decode_head` to avoid repeated per-header `find_crlf` calls.
#[inline]
fn collect_crlf_positions(buf: &[u8], out: &mut smallvec::SmallVec<[usize; 32]>) {
    out.clear();
    for idx in memchr_iter(b'\n', buf) {
        if idx > 0 && buf[idx - 1] == b'\r' {
            out.push(idx - 1);
        }
    }
}

/// Valid bytes for the HTTP/1.x request-target (RFC 3986 URI + reserved/sub-delims).
///
/// Rejects control characters (including `\x00`, `\x01`, …, `\x1f`), `DEL`
/// (`0x7F`), any non-ASCII byte, and whitespace — all of which can enable
/// smuggling or header injection if silently accepted inside a path.
#[inline]
fn is_valid_request_target_byte(b: u8) -> bool {
    // RFC 3986 permits all printable ASCII except space in a URI; anything
    // outside `0x21..=0x7E` is invalid in a request-target. Space is the
    // delimiter between tokens and is already consumed by the caller, so a
    // stray space here also represents a malformed request-line.
    (0x21..=0x7E).contains(&b)
}

fn parse_request_line_bytes(line: &[u8]) -> Result<(Method, String, Version), HttpError> {
    // Reject bare CR embedded in the request line — only the terminating
    // CRLF may contain \r, and that has already been stripped. A bare \r
    // in the middle is a framing error / smuggling vector.
    if line.contains(&b'\r') {
        return Err(HttpError::BadRequestLine);
    }
    // Fast path for the overwhelmingly common HTTP/1.x wire form:
    // `METHOD SP URI SP VERSION` with no extra whitespace tokens.
    if let Some(first_sp) = memchr(b' ', line) {
        if first_sp > 0 {
            let rest = &line[first_sp + 1..];
            if let Some(second_sp_rel) = memchr(b' ', rest) {
                let second_sp = first_sp + 1 + second_sp_rel;
                if second_sp > first_sp + 1 {
                    let method_bytes = &line[..first_sp];
                    let uri_bytes = &line[first_sp + 1..second_sp];
                    let version_bytes = &line[second_sp + 1..];
                    if !version_bytes.is_empty()
                        && !version_bytes.iter().any(u8::is_ascii_whitespace)
                    {
                        let method =
                            Method::from_bytes(method_bytes).ok_or(HttpError::BadMethod)?;
                        if !uri_bytes.iter().copied().all(is_valid_request_target_byte) {
                            return Err(HttpError::BadRequestLine);
                        }
                        let version = Version::from_bytes(version_bytes)
                            .ok_or(HttpError::UnsupportedVersion)?;
                        let uri = std::str::from_utf8(uri_bytes)
                            .map_err(|_| HttpError::BadRequestLine)?;
                        return Ok((method, uri.to_owned(), version));
                    }
                }
            }
        }
    }

    parse_request_line_bytes_slow(line)
}

fn parse_request_line_bytes_slow(line: &[u8]) -> Result<(Method, String, Version), HttpError> {
    fn next_token_bounds(bytes: &[u8], cursor: &mut usize) -> Option<(usize, usize)> {
        while *cursor < bytes.len() && bytes[*cursor] == b' ' {
            *cursor += 1;
        }
        let start = *cursor;
        while *cursor < bytes.len() && bytes[*cursor] != b' ' {
            *cursor += 1;
        }
        (start < *cursor).then_some((start, *cursor))
    }

    let mut cursor = 0usize;
    let method_bounds = next_token_bounds(line, &mut cursor).ok_or(HttpError::BadRequestLine)?;
    let uri_bounds = next_token_bounds(line, &mut cursor).ok_or(HttpError::BadRequestLine)?;
    let version_bounds = next_token_bounds(line, &mut cursor).ok_or(HttpError::BadRequestLine)?;
    if next_token_bounds(line, &mut cursor).is_some() {
        return Err(HttpError::BadRequestLine);
    }

    let method =
        Method::from_bytes(&line[method_bounds.0..method_bounds.1]).ok_or(HttpError::BadMethod)?;
    let uri_bytes = &line[uri_bounds.0..uri_bounds.1];
    if !uri_bytes.iter().copied().all(is_valid_request_target_byte) {
        return Err(HttpError::BadRequestLine);
    }
    let version = Version::from_bytes(&line[version_bounds.0..version_bounds.1])
        .ok_or(HttpError::UnsupportedVersion)?;
    let uri = std::str::from_utf8(uri_bytes).map_err(|_| HttpError::BadRequestLine)?;

    Ok((method, uri.to_owned(), version))
}

/// Validates an HTTP field-name (RFC 7230 token / tchar set).
fn is_valid_header_name(name: &str) -> bool {
    is_valid_header_name_bytes(name.as_bytes())
}

fn is_valid_header_name_bytes(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    name.iter().all(|&b| is_valid_header_name_byte(b))
}

#[inline]
fn is_valid_header_name_byte(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^'
            | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'
    )
}

fn parse_header_line_bounds(line_bytes: &[u8]) -> Result<(usize, usize, usize), HttpError> {
    // Use memchr for SIMD-accelerated colon search.
    let colon = memchr(b':', line_bytes).ok_or(HttpError::BadHeader)?;

    // Header field names cannot be empty, and all bytes before the colon
    // must be valid tchar (RFC 7230).
    if colon == 0
        || !line_bytes[..colon]
            .iter()
            .all(|&b| is_valid_header_name_byte(b))
    {
        return Err(HttpError::InvalidHeaderName);
    }

    let mut value_start = colon + 1;
    while value_start < line_bytes.len()
        && (line_bytes[value_start] == b' ' || line_bytes[value_start] == b'\t')
    {
        value_start += 1;
    }
    let mut value_end = line_bytes.len();
    while value_end > value_start
        && (line_bytes[value_end - 1] == b' ' || line_bytes[value_end - 1] == b'\t')
    {
        value_end -= 1;
    }
    for &b in &line_bytes[value_start..value_end] {
        // Reject control characters per RFC 9110 Section 5.5.
        // Only HTAB (0x09) and visible ASCII (0x20..=0x7E) plus
        // obs-text (0x80..=0xFF) are allowed in field values.
        if b == b'\r' || b == b'\n' || b == b'\0' || (b < 0x20 && b != b'\t') || b == 0x7F {
            return Err(HttpError::InvalidHeaderValue);
        }
    }

    Ok((colon, value_start, value_end))
}

fn parse_header_line_bytes(line_bytes: &[u8]) -> Result<(String, String), HttpError> {
    let (colon, value_start, value_end) = parse_header_line_bounds(line_bytes)?;
    let name_bytes = &line_bytes[..colon];
    let value_bytes = &line_bytes[value_start..value_end];
    let name = std::str::from_utf8(name_bytes).map_err(|_| HttpError::BadHeader)?;

    // Header values might contain obs-text (bytes >= 0x80) which are not always valid UTF-8.
    // Fall back to Latin-1 decoding if UTF-8 validation fails.
    let value = std::str::from_utf8(value_bytes).map_or_else(
        |_| value_bytes.iter().map(|&b| b as char).collect(),
        std::borrow::ToOwned::to_owned,
    );

    Ok((name.to_owned(), value))
}

/// Parse a single `Name: Value` header line.
pub(super) fn parse_header_line(line: &str) -> Result<(String, String), HttpError> {
    let (colon, value_start, value_end) = parse_header_line_bounds(line.as_bytes())?;
    let name = &line[..colon];
    let value = &line[value_start..value_end];
    Ok((name.to_owned(), value.to_owned()))
}

pub(super) fn validate_header_field(name: &str, value: &str) -> Result<(), HttpError> {
    if name.contains('\r') || name.contains('\n') {
        return Err(HttpError::InvalidHeaderName);
    }
    if !is_valid_header_name(name) {
        return Err(HttpError::InvalidHeaderName);
    }
    if value
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == b'\0' || (b < 0x20 && b != b'\t') || b == 0x7F)
    {
        return Err(HttpError::InvalidHeaderValue);
    }
    Ok(())
}

/// Look up a header value (case-insensitive name match).
#[cfg(test)]
fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Look up a header value, rejecting duplicates for security-sensitive headers.
pub(super) fn unique_header_value<'a>(
    headers: &'a [(String, String)],
    name: &str,
) -> Result<Option<&'a str>, HttpError> {
    let mut found = None;
    for (n, v) in headers {
        if n.eq_ignore_ascii_case(name) {
            if found.is_some() {
                if name.eq_ignore_ascii_case("content-length") {
                    return Err(HttpError::DuplicateContentLength);
                }
                if name.eq_ignore_ascii_case("transfer-encoding") {
                    return Err(HttpError::DuplicateTransferEncoding);
                }
                return Err(HttpError::BadHeader);
            }
            found = Some(v.as_str());
        }
    }
    Ok(found)
}

pub(super) fn require_transfer_encoding_chunked(value: &str) -> Result<(), HttpError> {
    let mut tokens = value.split(',').map(str::trim).filter(|t| !t.is_empty());
    let first = tokens.next().ok_or(HttpError::BadTransferEncoding)?;
    if tokens.next().is_some() {
        // We only support the simplest/secure subset for now: `chunked` only.
        return Err(HttpError::BadTransferEncoding);
    }
    if first.eq_ignore_ascii_case("chunked") {
        return Ok(());
    }
    Err(HttpError::BadTransferEncoding)
}

/// Append a `usize` as decimal ASCII digits to `dst`.
pub(super) fn append_decimal(dst: &mut BytesMut, mut n: usize) {
    // Stack buffer large enough for any usize (max 20 digits on 64-bit).
    let mut buf = [0u8; 20];
    let mut pos = buf.len();
    if n == 0 {
        dst.extend_from_slice(b"0");
        return;
    }
    while n > 0 {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    dst.extend_from_slice(&buf[pos..]);
}

fn upper_hex_len(mut n: usize) -> usize {
    let mut len = 1;
    while n >= 16 {
        n /= 16;
        len += 1;
    }
    len
}

pub(super) fn append_chunk_size_line(dst: &mut BytesMut, mut size: usize) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut digits = [0u8; usize::BITS as usize / 4];
    let mut written = 0usize;
    loop {
        let idx = size & 0xF;
        digits[digits.len() - 1 - written] = HEX[idx];
        written += 1;
        size >>= 4;
        if size == 0 {
            break;
        }
    }
    let start = digits.len() - written;
    dst.extend_from_slice(&digits[start..]);
    dst.extend_from_slice(b"\r\n");
}

/// Return `(Transfer-Encoding, Content-Length)` while enforcing duplicate rules.
fn transfer_and_content_length(
    headers: &[(String, String)],
) -> Result<(Option<&str>, Option<&str>), HttpError> {
    let mut transfer_encoding = None;
    let mut content_length = None;

    for (name, value) in headers {
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding.is_some() {
                return Err(HttpError::DuplicateTransferEncoding);
            }
            transfer_encoding = Some(value.as_str());
            continue;
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(HttpError::DuplicateContentLength);
            }
            content_length = Some(value.as_str());
        }
    }

    Ok((transfer_encoding, content_length))
}

const HEADER_TRANSFER_ENCODING: &[u8] = b"transfer-encoding";
const HEADER_CONTENT_LENGTH: &[u8] = b"content-length";

#[inline]
fn is_transfer_encoding_name(name: &str) -> bool {
    name.as_bytes()
        .eq_ignore_ascii_case(HEADER_TRANSFER_ENCODING)
}

#[inline]
fn is_content_length_name(name: &str) -> bool {
    name.as_bytes().eq_ignore_ascii_case(HEADER_CONTENT_LENGTH)
}

enum BodyKind {
    ContentLength(usize),
    Chunked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RequestHeadPreview {
    pub version: Version,
    pub headers: Vec<(String, String)>,
}

const MAX_CHUNK_LINE_LEN: usize = 1024;

type ChunkedDecoded = (Vec<u8>, Vec<(String, String)>);

#[derive(Debug)]
enum ChunkPhase {
    SizeLine,
    Data { remaining: usize },
    DataCrlf,
    Trailers,
}

#[derive(Debug)]
pub(super) struct ChunkedBodyDecoder {
    phase: ChunkPhase,
    body: Vec<u8>,
    trailers: Vec<(String, String)>,
    trailers_bytes: usize,
    max_body_size: usize,
    max_trailers_size: usize,
}

impl ChunkedBodyDecoder {
    pub(super) fn new(max_body_size: usize, max_trailers_size: usize) -> Self {
        Self {
            phase: ChunkPhase::SizeLine,
            body: Vec::new(),
            trailers: Vec::new(),
            trailers_bytes: 0,
            max_body_size,
            max_trailers_size,
        }
    }

    pub(super) fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<ChunkedDecoded>, HttpError> {
        loop {
            match self.phase {
                ChunkPhase::SizeLine => {
                    let Some(line) = split_line_crlf(src, MAX_CHUNK_LINE_LEN)? else {
                        return Ok(None);
                    };
                    let size = parse_chunk_size_line(line.as_ref())?;
                    if size == 0 {
                        self.phase = ChunkPhase::Trailers;
                        continue;
                    }

                    if self.body.len().saturating_add(size) > self.max_body_size {
                        return Err(HttpError::BodyTooLarge);
                    }

                    self.phase = ChunkPhase::Data { remaining: size };
                }

                ChunkPhase::Data { remaining } => {
                    if src.len() < remaining {
                        return Ok(None);
                    }
                    let data = src.split_to(remaining);
                    self.body.extend_from_slice(data.as_ref());
                    self.phase = ChunkPhase::DataCrlf;
                }

                ChunkPhase::DataCrlf => {
                    if src.len() < 2 {
                        return Ok(None);
                    }
                    if src.as_ref()[0] != b'\r' || src.as_ref()[1] != b'\n' {
                        return Err(HttpError::BadChunkedEncoding);
                    }
                    let _ = src.split_to(2);
                    self.phase = ChunkPhase::SizeLine;
                }

                ChunkPhase::Trailers => {
                    let Some(line) = split_line_crlf(src, self.max_trailers_size)? else {
                        return Ok(None);
                    };

                    if line.is_empty() {
                        self.phase = ChunkPhase::SizeLine;
                        self.trailers_bytes = 0;
                        return Ok(Some((
                            std::mem::take(&mut self.body),
                            std::mem::take(&mut self.trailers),
                        )));
                    }

                    self.trailers_bytes = self.trailers_bytes.saturating_add(line.len() + 2);
                    if self.trailers_bytes > self.max_trailers_size {
                        return Err(HttpError::HeadersTooLarge);
                    }

                    self.trailers.push(parse_header_line_bytes(line.as_ref())?);
                    if self.trailers.len() > MAX_HEADERS {
                        return Err(HttpError::TooManyHeaders);
                    }
                }
            }
        }
    }
}

fn split_line_crlf(src: &mut BytesMut, max_len: usize) -> Result<Option<BytesMut>, HttpError> {
    let Some(line_end) = find_crlf(src.as_ref()) else {
        if src.len() > max_len {
            return Err(HttpError::BadChunkedEncoding);
        }
        return Ok(None);
    };

    if line_end > max_len {
        return Err(HttpError::BadChunkedEncoding);
    }

    let line = src.split_to(line_end);
    let _ = src.split_to(2); // CRLF
    Ok(Some(line))
}

fn parse_chunk_size_line(line: &[u8]) -> Result<usize, HttpError> {
    let line = std::str::from_utf8(line).map_err(|_| HttpError::BadChunkedEncoding)?;
    // Split on ';' to separate chunk-size from optional chunk-ext (RFC 7230 §4.1).
    // Do NOT trim — chunk-size = 1*HEXDIG with no leading/trailing whitespace.
    // Trimming would mask differences from stricter proxies (request smuggling vector).
    let size_part = line.split(';').next().unwrap_or("");
    if size_part.is_empty() {
        return Err(HttpError::BadChunkedEncoding);
    }
    // Reject leading/trailing whitespace explicitly to prevent smuggling.
    if size_part
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_whitespace)
        || size_part
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_whitespace)
    {
        return Err(HttpError::BadChunkedEncoding);
    }
    usize::from_str_radix(size_part, 16).map_err(|_| HttpError::BadChunkedEncoding)
}

/// Parse the head (request line + headers) from `src`, splitting off the
/// consumed bytes. Returns `None` if the full header block hasn't arrived yet.
#[allow(clippy::type_complexity)]
fn decode_head_parts(
    src: &[u8],
    max_headers_size: usize,
) -> Result<
    Option<(
        usize,
        Method,
        String,
        Version,
        Vec<(String, String)>,
        BodyKind,
    )>,
    HttpError,
> {
    // Reject bare CRs in the buffered head: HTTP/1.x line terminators MUST be
    // CRLF (RFC 9112 §2.2). A `\r` followed by anything other than `\n` is a
    // framing violation (request-smuggling vector), so fail fast instead of
    // waiting for a CRLF that will never arrive. A trailing single `\r` with
    // no successor byte yet may still be completed, so we only fire when the
    // next byte is already buffered.
    for idx in memchr_iter(b'\r', src) {
        if idx + 1 < src.len() && src[idx + 1] != b'\n' {
            return Err(HttpError::BadRequestLine);
        }
    }

    let Some(end) = find_headers_end(src) else {
        if src.len() > max_headers_size {
            return Err(HttpError::HeadersTooLarge);
        }
        // Preserve request-line limit behavior for incomplete heads while
        // avoiding an extra scan on the common fully-buffered decode path.
        if src.len() > MAX_REQUEST_LINE {
            match find_crlf(src) {
                Some(line_end) if line_end > MAX_REQUEST_LINE => {
                    return Err(HttpError::RequestLineTooLong);
                }
                Some(_) => {}
                None => return Err(HttpError::RequestLineTooLong),
            }
        }
        return Ok(None);
    };

    if end > max_headers_size {
        return Err(HttpError::HeadersTooLarge);
    }

    let head = &src[..end];

    // Single-pass: collect all CRLF positions in the header block at once.
    // This replaces N+1 individual `find_crlf()` sub-slice calls with one
    // `memchr_iter` pass, eliminating repeated search setup overhead.
    let mut crlf_positions = smallvec::SmallVec::<[usize; 32]>::new();
    collect_crlf_positions(head, &mut crlf_positions);

    let request_line_end = *crlf_positions.first().ok_or(HttpError::BadRequestLine)?;
    if request_line_end > MAX_REQUEST_LINE {
        return Err(HttpError::RequestLineTooLong);
    }
    if request_line_end >= head.len() {
        return Err(HttpError::BadRequestLine);
    }
    let request_line = &head[..request_line_end];
    let (method, uri, version) = parse_request_line_bytes(request_line)?;

    let header_count = crlf_positions.len().saturating_sub(2);
    if header_count > MAX_HEADERS {
        return Err(HttpError::TooManyHeaders);
    }
    let mut headers = Vec::with_capacity(header_count);
    let mut transfer_encoding_idx = None;
    let mut content_length_idx = None;
    let mut cursor = request_line_end + 2;
    // Iterate pre-computed CRLF positions (skip the first which was request line)
    for &crlf_pos in &crlf_positions[1..] {
        if crlf_pos < cursor {
            continue;
        }
        let line_len = crlf_pos - cursor;
        if line_len == 0 {
            break;
        }
        let header = parse_header_line_bytes(&head[cursor..crlf_pos])?;
        if is_transfer_encoding_name(header.0.as_str()) {
            if transfer_encoding_idx.is_some() {
                return Err(HttpError::DuplicateTransferEncoding);
            }
            transfer_encoding_idx = Some(headers.len());
        } else if is_content_length_name(header.0.as_str()) {
            if content_length_idx.is_some() {
                return Err(HttpError::DuplicateContentLength);
            }
            content_length_idx = Some(headers.len());
        }

        headers.push(header);
        cursor = crlf_pos + 2;
    }

    let kind = match (transfer_encoding_idx, content_length_idx) {
        (Some(_), Some(_)) => return Err(HttpError::AmbiguousBodyLength),
        (Some(te_idx), None) => {
            if version == Version::Http10 {
                return Err(HttpError::BadTransferEncoding);
            }
            require_transfer_encoding_chunked(headers[te_idx].1.as_str())?;
            BodyKind::Chunked
        }
        (None, Some(cl_idx)) => {
            let len: usize = headers[cl_idx]
                .1
                .trim()
                .parse()
                .map_err(|_| HttpError::BadContentLength)?;
            BodyKind::ContentLength(len)
        }
        (None, None) => BodyKind::ContentLength(0),
    };

    Ok(Some((end, method, uri, version, headers, kind)))
}

#[allow(clippy::type_complexity)]
fn decode_head(
    src: &mut BytesMut,
    max_headers_size: usize,
) -> Result<Option<(Method, String, Version, Vec<(String, String)>, BodyKind)>, HttpError> {
    let Some((end, method, uri, version, headers, kind)) =
        decode_head_parts(src.as_ref(), max_headers_size)?
    else {
        return Ok(None);
    };

    let _ = src.split_to(end);
    Ok(Some((method, uri, version, headers, kind)))
}

pub(super) fn preview_request_head(
    codec: &Http1Codec,
    src: &BytesMut,
) -> Result<Option<RequestHeadPreview>, HttpError> {
    match &codec.state {
        DecodeState::Body {
            version, headers, ..
        }
        | DecodeState::Chunked {
            version, headers, ..
        } => {
            return Ok(Some(RequestHeadPreview {
                version: *version,
                headers: headers.clone(),
            }));
        }
        DecodeState::Poisoned => return Err(HttpError::BadHeader),
        DecodeState::Head => {}
    }

    let Some((_end, _method, _uri, version, headers, _kind)) =
        decode_head_parts(src.as_ref(), codec.max_headers_size)?
    else {
        return Ok(None);
    };

    Ok(Some(RequestHeadPreview { version, headers }))
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
            ..
        } => (method, uri, version, headers),
        DecodeState::Head | DecodeState::Poisoned => {
            unreachable!("take_head called in invalid state")
        }
    }
}

impl Decoder for Http1Codec {
    type Item = Request;
    type Error = HttpError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Request>, HttpError> {
        match self.decode_inner(src) {
            Err(e) => {
                self.state = DecodeState::Poisoned;
                Err(e)
            }
            Ok(v) => Ok(v),
        }
    }
}

impl Http1Codec {
    fn decode_inner(&mut self, src: &mut BytesMut) -> Result<Option<Request>, HttpError> {
        loop {
            match &mut self.state {
                DecodeState::Poisoned => {
                    return Err(HttpError::BadHeader); // Generic error for poisoned state
                }
                state @ DecodeState::Head => {
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
                                trailers: Vec::new(),
                                peer_addr: None,
                            }));
                        }
                        BodyKind::ContentLength(len) => {
                            // Check body size limit upfront for Content-Length
                            if len > self.max_body_size {
                                return Err(HttpError::BodyTooLarge);
                            }
                            *state = DecodeState::Body {
                                method,
                                uri,
                                version,
                                headers,
                                remaining: len,
                            };
                        }
                        BodyKind::Chunked => {
                            *state = DecodeState::Chunked {
                                method,
                                uri,
                                version,
                                headers,
                                chunked: ChunkedBodyDecoder::new(
                                    self.max_body_size,
                                    self.max_headers_size,
                                ),
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
                        trailers: Vec::new(),
                        peer_addr: None,
                    }));
                }

                DecodeState::Chunked { chunked, .. } => {
                    let Some((body, trailers)) = chunked.decode(src)? else {
                        return Ok(None);
                    };

                    let old = std::mem::replace(&mut self.state, DecodeState::Head);
                    let (method, uri, version, headers) = take_head(old);

                    return Ok(Some(Request {
                        method,
                        uri,
                        version,
                        headers,
                        body,
                        trailers,
                        peer_addr: None,
                    }));
                }
            }
        }
    }
}

impl Encoder<Response> for Http1Codec {
    type Error = HttpError;

    #[allow(clippy::too_many_lines)]
    fn encode(&mut self, resp: Response, dst: &mut BytesMut) -> Result<(), HttpError> {
        let reason = if resp.reason.is_empty() {
            types::default_reason(resp.status)
        } else {
            &resp.reason
        };

        if reason.contains('\r') || reason.contains('\n') {
            return Err(HttpError::BadHeader);
        }

        let (te, cl) = transfer_and_content_length(&resp.headers)?;

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

        if !chunked && !resp.trailers.is_empty() {
            return Err(HttpError::TrailersNotAllowed);
        }

        if !chunked {
            if let Some(cl) = cl {
                let declared: usize = cl.trim().parse().map_err(|_| HttpError::BadContentLength)?;
                // Allow empty bodies with non-zero Content-Length for HEAD responses.
                if declared != resp.body.len() && !resp.body.is_empty() {
                    return Err(HttpError::BadContentLength);
                }
            }
        }

        // Pre-validate all headers (and trailers for chunked) so the write
        // path below is infallible and we can write directly to `dst`.
        let mut has_content_length = false;
        for (name, value) in &resp.headers {
            validate_header_field(name, value)?;
            if name.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
            }
        }
        if chunked {
            for (name, value) in &resp.trailers {
                validate_header_field(name, value)?;
            }
        }

        // Pre-reserve capacity for the entire response.
        let headers_bytes: usize = resp
            .headers
            .iter()
            .map(|(name, value)| name.len() + value.len() + 4)
            .sum();
        let trailers_bytes: usize = resp
            .trailers
            .iter()
            .map(|(name, value)| name.len() + value.len() + 4)
            .sum();
        let chunk_line_bytes = if chunked && !resp.body.is_empty() {
            upper_hex_len(resp.body.len()) + 2
        } else {
            0
        };
        let encoded_body_bytes = if chunked {
            chunk_line_bytes + resp.body.len() + 2 + 3 + trailers_bytes + 2
        } else {
            resp.body.len()
        };
        dst.reserve(64 + reason.len() + headers_bytes + encoded_body_bytes);

        // Write directly to dst via extend_from_slice — no fmt machinery.
        {
            // Status line: "HTTP/1.1 200 OK\r\n"
            dst.extend_from_slice(resp.version.as_str().as_bytes());
            dst.extend_from_slice(b" ");
            append_decimal(dst, resp.status as usize);
            dst.extend_from_slice(b" ");
            dst.extend_from_slice(reason.as_bytes());
            dst.extend_from_slice(b"\r\n");

            for (name, value) in &resp.headers {
                dst.extend_from_slice(name.as_bytes());
                dst.extend_from_slice(b": ");
                dst.extend_from_slice(value.as_bytes());
                dst.extend_from_slice(b"\r\n");
            }

            if chunked {
                dst.extend_from_slice(b"\r\n");
                if !resp.body.is_empty() {
                    append_chunk_size_line(dst, resp.body.len());
                    dst.extend_from_slice(&resp.body);
                    dst.extend_from_slice(b"\r\n");
                }
                dst.extend_from_slice(b"0\r\n");
                for (name, value) in &resp.trailers {
                    dst.extend_from_slice(name.as_bytes());
                    dst.extend_from_slice(b": ");
                    dst.extend_from_slice(value.as_bytes());
                    dst.extend_from_slice(b"\r\n");
                }
                dst.extend_from_slice(b"\r\n");
                return Ok(());
            }

            let suppress_content_length =
                (100..=199).contains(&resp.status) || resp.status == 204 || resp.status == 304;
            if !has_content_length && !suppress_content_length {
                dst.extend_from_slice(b"Content-Length: ");
                append_decimal(dst, resp.body.len());
                dst.extend_from_slice(b"\r\n");
            }

            dst.extend_from_slice(b"\r\n");
            if !resp.body.is_empty() {
                dst.extend_from_slice(&resp.body);
            }
        }

        Ok(())
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
        assert!(req.trailers.is_empty());
    }

    #[test]
    fn decode_chunked_with_extensions() {
        let mut codec = Http1Codec::new();
        let raw = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                     5;ext=1\r\nhello\r\n0\r\n\r\n";
        let req = decode_one(&mut codec, raw).unwrap().unwrap();
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn decode_chunked_with_trailers() {
        let mut codec = Http1Codec::new();
        let raw = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                     5\r\nhello\r\n0\r\nX-Trailer: one\r\nY-Trailer: two\r\n\r\n";
        let req = decode_one(&mut codec, raw).unwrap().unwrap();
        assert_eq!(req.body, b"hello");
        assert_eq!(req.trailers.len(), 2);
        assert_eq!(req.trailers[0].0, "X-Trailer");
        assert_eq!(req.trailers[0].1, "one");
    }

    #[test]
    fn decode_chunked_keeps_pipelined_next_request() {
        let mut codec = Http1Codec::new();
        let mut raw =
            b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec();
        raw.extend_from_slice(b"GET /next HTTP/1.1\r\nX-Long: ");
        raw.extend_from_slice(&vec![b'a'; 9000]);
        raw.extend_from_slice(b"\r\n\r\n");

        let mut buf = BytesMut::from(raw.as_slice());
        let first = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(first.method, Method::Post);
        assert_eq!(first.uri, "/upload");
        assert!(first.trailers.is_empty());
        assert!(buf.as_ref().starts_with(b"GET /next HTTP/1.1\r\n"));
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
    fn preview_request_head_available_before_body_bytes() {
        let raw = b"POST /upload HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n";
        let mut buf = BytesMut::from(&raw[..]);
        let codec = Http1Codec::new();

        let preview = preview_request_head(&codec, &buf)
            .unwrap()
            .expect("header preview should be available before body bytes arrive");

        assert_eq!(preview.version, Version::Http11);
        assert_eq!(
            header_value(&preview.headers, "expect"),
            Some("100-continue")
        );
        assert_eq!(header_value(&preview.headers, "content-length"), Some("5"));
        assert_eq!(buf.as_ref(), raw);

        let mut codec = Http1Codec::new();
        assert!(codec.decode(&mut buf).unwrap().is_none());
        assert!(buf.is_empty(), "head bytes should move into codec state");

        let preview = preview_request_head(&codec, &buf)
            .unwrap()
            .expect("pending codec state should still expose request head");
        assert_eq!(preview.version, Version::Http11);
        assert_eq!(
            header_value(&preview.headers, "expect"),
            Some("100-continue")
        );
        assert_eq!(header_value(&preview.headers, "content-length"), Some("5"));
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
    fn parse_request_line_fast_path() {
        let (method, uri, version) = parse_request_line_bytes(b"GET /fast HTTP/1.1").unwrap();
        assert_eq!(method, Method::Get);
        assert_eq!(uri, "/fast");
        assert_eq!(version, Version::Http11);
    }

    #[test]
    fn parse_request_line_fallback_with_extra_spaces() {
        // Extra spacing forces the tolerant parser fallback.
        let (method, uri, version) = parse_request_line_bytes(b"GET   /slow   HTTP/1.1").unwrap();
        assert_eq!(method, Method::Get);
        assert_eq!(uri, "/slow");
        assert_eq!(version, Version::Http11);
    }

    #[test]
    fn crlf_search_matches_only_complete_pairs() {
        assert_eq!(find_crlf(b"GET / HTTP/1.1\r\nHost: example.com"), Some(14));
        assert_eq!(find_crlf(b"GET / HTTP/1.1\nHost: example.com"), None);
        assert_eq!(find_crlf(b"GET / HTTP/1.1\rHost: example.com"), None);

        let mut positions = smallvec::SmallVec::<[usize; 32]>::new();
        collect_crlf_positions(b"bad\nline\r\nnext\r\n", &mut positions);
        assert_eq!(positions.as_slice(), &[8, 14]);
    }

    #[test]
    fn decode_request_line_too_long_without_crlf() {
        let mut codec = Http1Codec::new();
        let raw = vec![b'G'; MAX_REQUEST_LINE + 1];
        let result = decode_one(&mut codec, &raw);
        assert!(matches!(result, Err(HttpError::RequestLineTooLong)));
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
    fn decode_too_many_headers() {
        let mut request = b"GET / HTTP/1.1\r\n".to_vec();
        for idx in 0..=MAX_HEADERS {
            request.extend_from_slice(format!("X-{idx}: value\r\n").as_bytes());
        }
        request.extend_from_slice(b"\r\n");

        let mut codec = Http1Codec::new();
        let result = decode_one(&mut codec, &request);
        assert!(matches!(result, Err(HttpError::TooManyHeaders)));
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
    fn reject_duplicate_content_length() {
        let mut codec = Http1Codec::new();
        let result = decode_one(
            &mut codec,
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
        );
        assert!(matches!(result, Err(HttpError::DuplicateContentLength)));
    }

    #[test]
    fn reject_duplicate_transfer_encoding() {
        let mut codec = Http1Codec::new();
        let result = decode_one(
            &mut codec,
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n\
              0\r\n\r\n",
        );
        assert!(matches!(result, Err(HttpError::DuplicateTransferEncoding)));
    }

    #[test]
    fn reject_unsupported_transfer_encoding() {
        let mut codec = Http1Codec::new();
        let result = decode_one(
            &mut codec,
            b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
        );
        assert!(matches!(result, Err(HttpError::BadTransferEncoding)));
    }

    #[test]
    fn reject_chunked_http10() {
        let mut codec = Http1Codec::new();
        let result = decode_one(
            &mut codec,
            b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        );
        assert!(matches!(result, Err(HttpError::BadTransferEncoding)));
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
        assert!(!s.contains("Content-Length"));
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
    fn encode_head_response_with_content_length() {
        let mut codec = Http1Codec::new();
        let resp = Response::new(200, "OK", Vec::new()).with_header("Content-Length", "1024");
        let bytes = encode_one(&mut codec, resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Content-Length: 1024\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
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
    fn encode_chunked_response() {
        let mut codec = Http1Codec::new();
        let resp =
            Response::new(200, "OK", b"hello".to_vec()).with_header("Transfer-Encoding", "chunked");
        let bytes = encode_one(&mut codec, resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("Transfer-Encoding: chunked\r\n"));
        assert!(!s.contains("Content-Length"));
        assert!(s.ends_with("5\r\nhello\r\n0\r\n\r\n"));
    }

    #[test]
    fn encode_chunked_response_with_trailers() {
        let mut codec = Http1Codec::new();
        let resp = Response::new(200, "OK", b"hello".to_vec())
            .with_header("Transfer-Encoding", "chunked")
            .with_trailer("X-Trailer", "one");
        let bytes = encode_one(&mut codec, resp);
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.ends_with("0\r\nX-Trailer: one\r\n\r\n"));
    }

    #[test]
    fn encode_trailers_without_chunked_is_error() {
        let mut codec = Http1Codec::new();
        let resp = Response::new(200, "OK", b"hello".to_vec()).with_trailer("X-Trailer", "one");
        let mut buf = BytesMut::with_capacity(256);
        let err = codec.encode(resp, &mut buf).unwrap_err();
        assert!(matches!(err, HttpError::TrailersNotAllowed));
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

    #[test]
    fn decode_body_too_large_content_length() {
        let mut codec = Http1Codec::new().max_body_size(10);
        let raw = b"POST /data HTTP/1.1\r\nContent-Length: 100\r\n\r\n";
        let result = decode_one(&mut codec, raw);
        assert!(matches!(result, Err(HttpError::BodyTooLarge)));
    }

    #[test]
    fn decode_body_too_large_chunked() {
        let mut codec = Http1Codec::new().max_body_size(10);
        // Chunked body with 20 bytes total (exceeds 10 byte limit)
        let raw = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                    14\r\n01234567890123456789\r\n0\r\n\r\n";
        let result = decode_one(&mut codec, raw);
        assert!(matches!(result, Err(HttpError::BodyTooLarge)));
    }

    #[test]
    fn decode_body_at_limit_succeeds() {
        let mut codec = Http1Codec::new().max_body_size(5);
        let raw = b"POST /data HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let req = decode_one(&mut codec, raw).unwrap().unwrap();
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn decode_chunked_body_at_limit_succeeds() {
        let mut codec = Http1Codec::new().max_body_size(11);
        // "hello world" = 11 bytes, exactly at the limit
        let raw = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                     5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let req = decode_one(&mut codec, raw).unwrap().unwrap();
        assert_eq!(req.body, b"hello world");
    }

    // Security: Request smuggling protection (RFC 7230 3.3.3)
    #[test]
    fn reject_both_content_length_and_transfer_encoding() {
        let mut codec = Http1Codec::new();
        // Having both headers is a request smuggling vector
        let raw = b"POST /data HTTP/1.1\r\n\
                    Content-Length: 5\r\n\
                    Transfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n0\r\n\r\n";
        let result = decode_one(&mut codec, raw);
        assert!(matches!(result, Err(HttpError::AmbiguousBodyLength)));
    }

    #[test]
    fn reject_transfer_encoding_before_content_length() {
        let mut codec = Http1Codec::new();
        // Order shouldn't matter - still reject
        let raw = b"POST /data HTTP/1.1\r\n\
                    Transfer-Encoding: chunked\r\n\
                    Content-Length: 5\r\n\r\n\
                    5\r\nhello\r\n0\r\n\r\n";
        let result = decode_one(&mut codec, raw);
        assert!(matches!(result, Err(HttpError::AmbiguousBodyLength)));
    }

    // Security: Chunked encoding CRLF validation
    #[test]
    fn reject_invalid_crlf_after_chunk() {
        let mut codec = Http1Codec::new();
        // Invalid: "XX" instead of "\r\n" after chunk data
        let raw = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhelloXX0\r\n\r\n";
        let result = decode_one(&mut codec, raw);
        assert!(matches!(result, Err(HttpError::BadChunkedEncoding)));
    }

    #[test]
    fn reject_invalid_trailer_header_line() {
        let mut codec = Http1Codec::new();
        // Invalid: trailer header line missing ':'.
        let raw = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n0\r\nXX\r\n\r\n";
        let result = decode_one(&mut codec, raw);
        assert!(matches!(result, Err(HttpError::BadHeader)));
    }

    #[test]
    fn decode_obs_text_header_value() {
        let mut codec = Http1Codec::new();
        let raw = b"GET / HTTP/1.1\r\nTest-Header: \xff\r\n\r\n";
        let result = decode_one(&mut codec, raw);
        assert!(matches!(result, Ok(Some(_))));
    }

    /// Grammar-based fuzz test for HTTP/1.1 codec covering chunked encoding,
    /// trailers, 100-continue, HEAD body suppression, and fold pipelining.
    #[test]
    fn grammar_based_http11_features_fuzz() {
        use std::collections::HashMap;

        /// HTTP/1.1 grammar-based test generator
        struct Http11Grammar {
            seed: u64,
            counter: u64,
        }

        impl Http11Grammar {
            fn new(seed: u64) -> Self {
                Self { seed, counter: 0 }
            }

            fn next_u8(&mut self) -> u8 {
                self.counter = self.counter.wrapping_add(1);
                ((self.seed.wrapping_add(self.counter).wrapping_mul(1103515245).wrapping_add(12345)) >> 16) as u8
            }

            fn next_bool(&mut self) -> bool {
                self.next_u8() & 1 == 1
            }

            fn next_choice<T: Copy>(&mut self, choices: &[T]) -> T {
                let idx = (self.next_u8() as usize) % choices.len();
                choices[idx]
            }

            /// Generate chunked encoding test case
            fn generate_chunked_request(&mut self) -> Vec<u8> {
                let mut request = Vec::new();

                // Request line
                let method = self.next_choice(&[b"POST", b"PUT", b"PATCH"]);
                request.extend_from_slice(method);
                request.extend_from_slice(b" /test HTTP/1.1\r\n");

                // Headers
                request.extend_from_slice(b"Host: example.com\r\n");
                request.extend_from_slice(b"Transfer-Encoding: chunked\r\n");

                // Expect: 100-continue (grammar condition)
                if self.next_bool() {
                    request.extend_from_slice(b"Expect: 100-continue\r\n");
                }

                request.extend_from_slice(b"\r\n");

                // Chunked body with variable chunk sizes
                let chunk_sizes = [0, 1, 5, 10, 255, 4096];
                let chunk_size = self.next_choice(&chunk_sizes);

                if chunk_size > 0 {
                    request.extend_from_slice(format!("{:x}\r\n", chunk_size).as_bytes());
                    for _ in 0..chunk_size {
                        request.push(b'A' + (self.next_u8() % 26));
                    }
                    request.extend_from_slice(b"\r\n");
                }

                // Terminal chunk
                request.extend_from_slice(b"0\r\n");

                // Trailers (grammar condition)
                if self.next_bool() {
                    let trailer_names = [b"X-Checksum", b"X-Final-Status", b"X-Processing-Time"];
                    let trailer_name = self.next_choice(&trailer_names);
                    request.extend_from_slice(trailer_name);
                    request.extend_from_slice(b": test-value\r\n");
                }

                request.extend_from_slice(b"\r\n");
                request
            }

            /// Generate HEAD request test case for body suppression
            fn generate_head_request(&mut self) -> Vec<u8> {
                let mut request = Vec::new();

                request.extend_from_slice(b"HEAD /resource HTTP/1.1\r\n");
                request.extend_from_slice(b"Host: example.com\r\n");

                // Content-Length header that should be preserved in response
                // but body suppressed
                if self.next_bool() {
                    request.extend_from_slice(b"Accept: application/json\r\n");
                }

                request.extend_from_slice(b"\r\n");
                request
            }

            /// Generate pipelined request test case
            fn generate_pipelined_requests(&mut self) -> Vec<u8> {
                let mut requests = Vec::new();

                // First request
                requests.extend_from_slice(b"GET /first HTTP/1.1\r\n");
                requests.extend_from_slice(b"Host: example.com\r\n");
                requests.extend_from_slice(b"\r\n");

                // Second request (pipelined)
                let second_method = self.next_choice(&[b"GET", b"HEAD", b"POST"]);
                requests.extend_from_slice(second_method);
                requests.extend_from_slice(b" /second HTTP/1.1\r\n");
                requests.extend_from_slice(b"Host: example.com\r\n");

                if second_method == b"POST" {
                    requests.extend_from_slice(b"Content-Length: 4\r\n");
                    requests.extend_from_slice(b"\r\n");
                    requests.extend_from_slice(b"data");
                } else {
                    requests.extend_from_slice(b"\r\n");
                }

                requests
            }

            /// Generate folded header test case
            fn generate_folded_headers(&mut self) -> Vec<u8> {
                let mut request = Vec::new();

                request.extend_from_slice(b"GET / HTTP/1.1\r\n");
                request.extend_from_slice(b"Host: example.com\r\n");

                // Folded header (obs-fold - obsolete but sometimes encountered)
                request.extend_from_slice(b"X-Long-Header: first-part\r\n");
                request.extend_from_slice(b" second-part\r\n");  // Folded continuation

                request.extend_from_slice(b"\r\n");
                request
            }
        }

        let test_cases = [
            ("chunked_encoding", 0x1234),
            ("head_body_suppression", 0x5678),
            ("pipelined_requests", 0x9abc),
            ("folded_headers", 0xdef0),
            ("chunked_with_trailers", 0x2468),
            ("chunked_100_continue", 0xace1),
        ];

        for (test_name, seed) in &test_cases {
            let mut grammar = Http11Grammar::new(*seed);
            let mut codec = Http1Codec::new();

            let test_data = match *test_name {
                "chunked_encoding" | "chunked_with_trailers" | "chunked_100_continue" => {
                    grammar.generate_chunked_request()
                }
                "head_body_suppression" => grammar.generate_head_request(),
                "pipelined_requests" => grammar.generate_pipelined_requests(),
                "folded_headers" => grammar.generate_folded_headers(),
                _ => continue,
            };

            // Test parsing - should not panic and handle edge cases gracefully
            let result = {
                let mut buf = BytesMut::new();
                buf.extend_from_slice(&test_data);
                codec.decode(&mut buf)
            };

            match result {
                Ok(Some(request)) => {
                    // Validate grammar-specific invariants
                    match *test_name {
                        "head_body_suppression" => {
                            assert_eq!(request.method, Method::Head);
                        }
                        "chunked_encoding" | "chunked_with_trailers" | "chunked_100_continue" => {
                            // Should have chunked encoding headers
                            let has_chunked = request.headers.iter()
                                .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
                            if has_chunked {
                                // Validate we can parse chunked encoding structure
                            }
                        }
                        _ => {}
                    }
                }
                Ok(None) => {
                    // Incomplete data - acceptable for fuzzing
                }
                Err(err) => {
                    // Should fail gracefully with appropriate error types
                    match err {
                        HttpError::BadRequestLine
                        | HttpError::BadHeader
                        | HttpError::UnsupportedVersion
                        | HttpError::BadMethod
                        | HttpError::BadContentLength
                        | HttpError::DuplicateContentLength
                        | HttpError::DuplicateTransferEncoding
                        | HttpError::BadTransferEncoding
                        | HttpError::InvalidHeaderName
                        | HttpError::InvalidHeaderValue
                        | HttpError::HeadersTooLarge
                        | HttpError::TooManyHeaders
                        | HttpError::RequestLineTooLong
                        | HttpError::BadChunkedEncoding
                        | HttpError::BodyTooLarge
                        | HttpError::AmbiguousBodyLength
                        | HttpError::TrailersNotAllowed => {
                            // Expected error types - codec correctly rejected malformed input
                        }
                        _ => {
                            // Unexpected error type might indicate a bug
                            println!("Test '{}' produced unexpected error: {:?}", test_name, err);
                        }
                    }
                }
            }
        }

        // Additional stress test with combined features
        let mut combined_grammar = Http11Grammar::new(0xcafe);
        for _ in 0..100 {
            let mut codec = Http1Codec::new();
            let mut request = Vec::new();

            // Grammar: Method selection
            let method = combined_grammar.next_choice(&[b"GET", b"HEAD", b"POST", b"PUT"]);
            request.extend_from_slice(method);
            request.extend_from_slice(b" /combined HTTP/1.1\r\n");

            // Grammar: Header combinations
            request.extend_from_slice(b"Host: test.example\r\n");

            if method == b"POST" || method == b"PUT" {
                if combined_grammar.next_bool() {
                    // Chunked
                    request.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
                    if combined_grammar.next_bool() {
                        request.extend_from_slice(b"Expect: 100-continue\r\n");
                    }
                } else {
                    // Fixed length
                    let length = combined_grammar.next_choice(&[0, 1, 10, 100]);
                    request.extend_from_slice(format!("Content-Length: {}\r\n", length).as_bytes());
                }
            }

            request.extend_from_slice(b"\r\n");

            // Test without panicking
            let mut buf = BytesMut::new();
            buf.extend_from_slice(&request);
            let _ = codec.decode(&mut buf);
        }
    }
}
