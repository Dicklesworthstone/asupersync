//! HTTP/2 server listener surface (br-asupersync-eprpk6).
//!
//! Increment 1: request/response mapping between the h2 frame layer
//! ([`crate::http::h2::connection::ReceivedFrame::Headers`] header blocks)
//! and the shared [`crate::http::h1::types`] `Request`/`Response` handler
//! types, so one `Fn(Request) -> impl Future<Output = Response>` handler
//! serves both the HTTP/1.1 and HTTP/2 listener stacks.
//!
//! The accept-loop `Http2Listener` and per-connection frame-pump driver land
//! in the next increments (full design recorded on the bead): preface +
//! SETTINGS handshake over `Framed<TcpStream, FrameCodec>`, per-stream
//! handler dispatch through a response funnel, and request-aware graceful
//! drain via the D2.3 two-stage GOAWAY primitives on
//! [`crate::http::h2::connection::Connection`].

use crate::http::h1::types::{Method, Request, Response, Version};
use crate::http::h2::error::H2Error;
use crate::http::h2::hpack::Header;
use std::net::SocketAddr;

/// Connection-specific h1 headers that MUST NOT be carried into HTTP/2
/// messages (RFC 9113 §8.2.2). `te` is handled separately: it is permitted
/// with the single value `trailers`.
#[allow(dead_code)] // consumed by the connection driver in increment 2 (br-asupersync-eprpk6)
const CONNECTION_SPECIFIC_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// Build a handler [`Request`] from a decoded h2 request header block plus
/// its assembled body.
///
/// The caller (the connection driver) is expected to feed header blocks that
/// already passed the connection's RFC 9113 §8.3.1 pseudo-header structural
/// validation; this function extracts `:method` / `:path` / `:authority`,
/// surfaces the authority as a `host` header for h1 handler parity (unless
/// the request carried an explicit `host`), and rejects shapes it cannot
/// represent (`CONNECT` requests have no `:path` and are not supported by
/// this listener surface yet).
///
/// # Errors
///
/// Returns a protocol-level [`H2Error`] when required pseudo-headers are
/// missing, the method token is invalid, or an unknown request pseudo-header
/// appears.
#[allow(dead_code)] // consumed by the connection driver in increment 2 (br-asupersync-eprpk6)
pub(crate) fn request_from_h2_headers(
    headers: Vec<Header>,
    body: Vec<u8>,
    peer_addr: Option<SocketAddr>,
) -> Result<Request, H2Error> {
    let mut method = None;
    let mut path = None;
    let mut authority = None;
    let mut regular = Vec::with_capacity(headers.len());
    for header in headers {
        match header.name.as_str() {
            ":method" => method = Some(header.value),
            ":path" => path = Some(header.value),
            ":authority" => authority = Some(header.value),
            // `:scheme` has no h1 `Request` equivalent; `:protocol` is the
            // RFC 8441 extended-CONNECT marker, validated upstream.
            ":scheme" | ":protocol" => {}
            name if name.starts_with(':') => {
                return Err(H2Error::protocol(format!(
                    "unexpected request pseudo-header {name}"
                )));
            }
            _ => regular.push((header.name, header.value)),
        }
    }

    let method_text = method.ok_or_else(|| H2Error::protocol(":method pseudo-header missing"))?;
    let method = Method::from_bytes(method_text.as_bytes())
        .ok_or_else(|| H2Error::protocol("invalid :method token"))?;
    let uri = path.ok_or_else(|| {
        H2Error::protocol(":path pseudo-header missing (CONNECT is not supported by this listener)")
    })?;

    let mut request_headers = Vec::with_capacity(regular.len() + 1);
    if let Some(authority) = authority
        && !regular
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        // RFC 9113 §8.3.1: the authority carries what h1 put in Host.
        request_headers.push(("host".to_owned(), authority));
    }
    request_headers.extend(regular);

    Ok(Request {
        method,
        uri,
        version: Version::Http2,
        headers: request_headers,
        body,
        trailers: Vec::new(),
        peer_addr,
    })
}

/// Map a handler [`Response`] to an h2 response header block.
///
/// Emits `:status` first (RFC 9113 §8.3.2), lowercases field names (h2
/// field names are lowercase on the wire), and strips connection-specific
/// h1 headers that MUST NOT appear in h2 messages (RFC 9113 §8.2.2),
/// including any `te` value other than `trailers`.
#[allow(dead_code)] // consumed by the connection driver in increment 2 (br-asupersync-eprpk6)
pub(crate) fn h2_headers_from_response(response: &Response) -> Vec<Header> {
    let mut out = Vec::with_capacity(response.headers.len() + 1);
    out.push(Header::new(":status", response.status.to_string()));
    for (name, value) in &response.headers {
        let lowered = name.to_ascii_lowercase();
        if CONNECTION_SPECIFIC_HEADERS.contains(&lowered.as_str()) {
            continue;
        }
        if lowered == "te" && !value.eq_ignore_ascii_case("trailers") {
            continue;
        }
        out.push(Header::new(lowered, value.clone()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_block(extra: &[(&str, &str)]) -> Vec<Header> {
        let mut headers = vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":path", "/widgets?q=1"),
            Header::new(":authority", "example.com:8443"),
        ];
        for (name, value) in extra {
            headers.push(Header::new(*name, *value));
        }
        headers
    }

    #[test]
    fn request_mapping_extracts_pseudo_headers_and_synthesizes_host() {
        let request =
            request_from_h2_headers(request_block(&[("x-trace", "abc")]), b"body".to_vec(), None)
                .expect("valid request block");
        assert_eq!(request.method, Method::Get);
        assert_eq!(request.uri, "/widgets?q=1");
        assert_eq!(request.version, Version::Http2);
        assert_eq!(request.body, b"body");
        assert_eq!(
            request.headers,
            vec![
                ("host".to_owned(), "example.com:8443".to_owned()),
                ("x-trace".to_owned(), "abc".to_owned()),
            ]
        );
    }

    #[test]
    fn request_mapping_keeps_explicit_host_over_authority() {
        let request = request_from_h2_headers(
            request_block(&[("host", "explicit.example")]),
            Vec::new(),
            None,
        )
        .expect("valid request block");
        let hosts: Vec<_> = request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .collect();
        assert_eq!(hosts.len(), 1, "no duplicate host header");
        assert_eq!(hosts[0].1, "explicit.example");
    }

    #[test]
    fn request_mapping_rejects_missing_method_and_path() {
        let no_method = vec![Header::new(":path", "/"), Header::new(":scheme", "https")];
        assert!(request_from_h2_headers(no_method, Vec::new(), None).is_err());

        let no_path = vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
        ];
        assert!(request_from_h2_headers(no_path, Vec::new(), None).is_err());
    }

    #[test]
    fn request_mapping_rejects_unknown_pseudo_header() {
        let block = request_block(&[(":bogus", "x")]);
        assert!(request_from_h2_headers(block, Vec::new(), None).is_err());
    }

    #[test]
    fn response_mapping_emits_status_first_and_strips_h1_connection_headers() {
        let response = Response {
            version: Version::Http2,
            status: 204,
            reason: "No Content".to_owned(),
            headers: vec![
                ("Connection".to_owned(), "close".to_owned()),
                ("Transfer-Encoding".to_owned(), "chunked".to_owned()),
                ("TE".to_owned(), "gzip".to_owned()),
                ("X-Trace".to_owned(), "abc".to_owned()),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        let block = h2_headers_from_response(&response);
        assert_eq!(block[0], Header::new(":status", "204"));
        assert_eq!(block.len(), 2, "connection-specific headers stripped");
        assert_eq!(block[1], Header::new("x-trace", "abc"));
    }

    #[test]
    fn response_mapping_keeps_te_trailers() {
        let response = Response {
            version: Version::Http2,
            status: 200,
            reason: "OK".to_owned(),
            headers: vec![("te".to_owned(), "trailers".to_owned())],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        let block = h2_headers_from_response(&response);
        assert_eq!(block.len(), 2);
        assert_eq!(block[1], Header::new("te", "trailers"));
    }
}
