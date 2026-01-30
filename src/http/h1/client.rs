//! HTTP/1.1 client for sending requests over a transport.
//!
//! [`Http1Client`] sends a single HTTP/1.1 request and reads the response.

use crate::bytes::BytesMut;
use crate::codec::Framed;
use crate::http::h1::codec::HttpError;
use crate::http::h1::types::{Request, Response, Version};
use crate::io::{AsyncRead, AsyncWrite};
use crate::stream::Stream;
use std::fmt::Write;
use std::pin::Pin;

/// HTTP/1.1 client codec that encodes *requests* and decodes *responses*.
///
/// This is the mirror of [`Http1Codec`](super::Http1Codec) which decodes
/// requests and encodes responses. The client codec is used with
/// [`Framed`] for client-side connections.
pub struct Http1ClientCodec {
    state: ClientDecodeState,
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
    },
}

impl Http1ClientCodec {
    /// Create a new client codec.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: ClientDecodeState::Head,
        }
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

fn parse_header_line(line: &str) -> Result<(String, String), HttpError> {
    let colon = line.find(':').ok_or(HttpError::BadHeader)?;
    let name = line[..colon].trim().to_owned();
    let value = line[colon + 1..].trim().to_owned();
    if name.is_empty() {
        return Err(HttpError::BadHeader);
    }
    Ok((name, value))
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn is_chunked(headers: &[(String, String)]) -> bool {
    let Some(te) = header_value(headers, "Transfer-Encoding") else {
        return false;
    };
    te.split(',')
        .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
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
            if buf.len() < pos + 2 {
                return Ok(None);
            }
            pos += 2;
            return Ok(Some((body, pos)));
        }

        if buf.len() < pos + chunk_size + 2 {
            return Ok(None);
        }
        body.extend_from_slice(&buf[pos..pos + chunk_size]);
        pos += chunk_size + 2;
    }
}

impl crate::codec::Decoder for Http1ClientCodec {
    type Item = Response;
    type Error = HttpError;

    #[allow(clippy::too_many_lines)]
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Response>, HttpError> {
        loop {
            match &self.state {
                ClientDecodeState::Head => {
                    let Some(end) = find_headers_end(src.as_ref()) else {
                        return Ok(None);
                    };

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
                    }

                    if is_chunked(&headers) {
                        self.state = ClientDecodeState::Chunked {
                            version,
                            status,
                            reason,
                            headers,
                        };
                        continue;
                    }

                    let content_length = header_value(&headers, "Content-Length")
                        .map(str::parse::<usize>)
                        .transpose()
                        .map_err(|_| HttpError::BadContentLength)?
                        .unwrap_or(0);

                    if content_length == 0 {
                        self.state = ClientDecodeState::Head;
                        return Ok(Some(Response {
                            version,
                            status,
                            reason,
                            headers,
                            body: Vec::new(),
                        }));
                    }

                    self.state = ClientDecodeState::Body {
                        version,
                        status,
                        reason,
                        headers,
                        remaining: content_length,
                    };
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
                    }));
                }

                ClientDecodeState::Chunked { .. } => {
                    let Some((body, consumed)) = decode_chunked(src.as_ref())? else {
                        return Ok(None);
                    };
                    let _ = src.split_to(consumed);

                    let old = std::mem::replace(&mut self.state, ClientDecodeState::Head);
                    let ClientDecodeState::Chunked {
                        version,
                        status,
                        reason,
                        headers,
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
                    }));
                }
            }
        }
    }
}

impl crate::codec::Encoder<Request> for Http1ClientCodec {
    type Error = HttpError;

    fn encode(&mut self, req: Request, dst: &mut BytesMut) -> Result<(), HttpError> {
        // Request line
        let mut head = String::with_capacity(256);
        let _ = write!(head, "{} {} {}\r\n", req.method, req.uri, req.version);

        // Headers
        let mut has_content_length = false;
        for (name, value) in &req.headers {
            if name.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
            }
            let _ = write!(head, "{name}: {value}\r\n");
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
        let codec = Http1ClientCodec::new();
        let mut framed = Framed::new(io, codec);

        // Encode and buffer the request
        framed.send(req)?;

        // Read response
        match std::future::poll_fn(|cx| Pin::new(&mut framed).poll_next(cx)).await {
            Some(Ok(resp)) => Ok(resp),
            Some(Err(e)) => Err(e),
            None => Err(HttpError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before response",
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::BytesMut;
    use crate::codec::Decoder;

    #[test]
    fn decode_simple_response() {
        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"[..]);
        let resp = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.version, Version::Http11);
        assert_eq!(resp.body, b"hello");
    }

    #[test]
    fn decode_response_no_body() {
        let mut codec = Http1ClientCodec::new();
        let mut buf = BytesMut::from(&b"HTTP/1.1 204 No Content\r\n\r\n"[..]);
        let resp = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(resp.status, 204);
        assert!(resp.body.is_empty());
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
    }
}
