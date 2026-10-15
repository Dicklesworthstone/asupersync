//! HTTP/1.1 Trailer Field-Name Restrictions (RFC 9112 §10.6.2)
//!
//! Tests the live parser contract for RFC 9112 §10.6.2 trailer restrictions.
//! High-risk routing, framing, and authorization fields must be rejected when
//! supplied as chunked trailers; benign extension trailers must still parse.

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::Request;
use asupersync::http::h1::codec::{Http1Codec, HttpError};

fn parse(raw: &[u8]) -> Result<Option<Request>, HttpError> {
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(raw);
    codec.decode(&mut buf)
}

fn create_chunked_with_trailers(trailers: &[(&str, &str)]) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(
        b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    request.extend_from_slice(b"5\r\nhello\r\n");
    request.extend_from_slice(b"0\r\n");
    for (name, value) in trailers {
        request.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
    }
    request.extend_from_slice(b"\r\n");
    request
}

#[test]
fn allowed_trailer_field_names_are_preserved() {
    let req = create_chunked_with_trailers(&[
        ("X-Checksum", "abc123"),
        ("Server-Timing", "cpu;dur=2.3"),
        ("X-Request-ID", "req-456"),
    ]);
    let decoded = parse(&req)
        .unwrap_or_else(|err| panic!("safe trailers should parse: {err:?}"))
        .expect("complete request");
    assert_eq!(decoded.body, b"hello");
    assert_eq!(decoded.trailers.len(), 3);
    assert_eq!(
        decoded.trailers[0],
        ("X-Checksum".to_string(), "abc123".to_string())
    );
    assert_eq!(
        decoded.trailers[1],
        ("Server-Timing".to_string(), "cpu;dur=2.3".to_string())
    );
    assert_eq!(
        decoded.trailers[2],
        ("X-Request-ID".to_string(), "req-456".to_string())
    );
}

#[test]
fn repeated_safe_trailers_are_preserved_in_order() {
    let req = create_chunked_with_trailers(&[
        ("X-Trace", "one"),
        ("X-Trace", "two"),
        ("X-Trace", "three"),
    ]);
    let decoded = parse(&req)
        .unwrap_or_else(|err| panic!("repeated safe trailers should parse: {err:?}"))
        .expect("complete request");
    assert_eq!(decoded.trailers.len(), 3);
    assert_eq!(decoded.trailers[0].1, "one");
    assert_eq!(decoded.trailers[1].1, "two");
    assert_eq!(decoded.trailers[2].1, "three");
}

#[test]
fn forbidden_trailer_field_names_are_rejected() {
    let forbidden = [
        ("Transfer-Encoding", "gzip"),
        ("Content-Length", "5"),
        ("Host", "evil.example"),
        ("Authorization", "Bearer token123"),
        ("Content-Encoding", "gzip"),
        ("Content-Range", "bytes 0-4/5"),
        ("Trailer", "X-Next"),
    ];

    for (name, value) in forbidden {
        let req = create_chunked_with_trailers(&[(name, value)]);
        let err = parse(&req).expect_err("forbidden trailer must be rejected");
        assert!(
            matches!(err, HttpError::BadHeader),
            "expected BadHeader for forbidden trailer {name:?}, got {err:?}"
        );
    }
}

#[test]
fn forbidden_trailer_field_names_are_rejected_case_insensitively() {
    let forbidden = [
        ("transfer-encoding", "gzip"),
        ("TRANSFER-ENCODING", "gzip"),
        ("content-length", "5"),
        ("CONTENT-LENGTH", "5"),
        ("host", "evil.example"),
        ("HOST", "evil.example"),
        ("authorization", "Bearer token123"),
        ("AUTHORIZATION", "Bearer token123"),
        ("trailer", "X-Next"),
        ("TRAILER", "X-Next"),
    ];

    for (name, value) in forbidden {
        let req = create_chunked_with_trailers(&[(name, value)]);
        let err = parse(&req).expect_err("mixed-case forbidden trailer must be rejected");
        assert!(
            matches!(err, HttpError::BadHeader),
            "expected BadHeader for mixed-case forbidden trailer {name:?}, got {err:?}"
        );
    }
}

#[test]
fn repeated_forbidden_trailers_are_rejected() {
    let repeated = [
        &[
            ("Authorization", "Bearer first"),
            ("Authorization", "Bearer second"),
        ][..],
        &[("Content-Length", "5"), ("Content-Length", "7")][..],
        &[
            ("X-Trace", "ok"),
            ("Trailer", "X-Override"),
            ("Trailer", "X-Override-Again"),
        ][..],
    ];

    for trailers in repeated {
        let req = create_chunked_with_trailers(trailers);
        let err = parse(&req).expect_err("repeated forbidden trailers must be rejected");
        assert!(
            matches!(err, HttpError::BadHeader),
            "expected BadHeader for repeated forbidden trailers {trailers:?}, got {err:?}"
        );
    }
}
