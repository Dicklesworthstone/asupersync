//! Conformance Tests: HTTP/1.1 Chunked Transfer Encoding (RFC 9112 §7)
//!
//! Validates live `Http1Codec` chunked request decoding and response encoding.

#![cfg(test)]

use asupersync::{
    bytes::BytesMut,
    codec::{Decoder, Encoder},
    http::h1::{
        codec::{Http1Codec, HttpError},
        types::{Method, Request, Response},
    },
};

fn encode_response(resp: Response) -> Result<String, HttpError> {
    let mut codec = Http1Codec::new();
    let mut dst = BytesMut::with_capacity(1024);
    codec.encode(resp, &mut dst)?;
    String::from_utf8(dst.to_vec()).map_err(|_| HttpError::BadHeader)
}

fn decode_request(data: &[u8]) -> Result<Option<Request>, HttpError> {
    let mut codec = Http1Codec::new();
    let mut src = BytesMut::from(data);
    codec.decode(&mut src)
}

fn decode_request_with_remainder(data: &[u8]) -> Result<(Request, Vec<u8>), HttpError> {
    let mut codec = Http1Codec::new();
    let mut src = BytesMut::from(data);
    let request = codec.decode(&mut src)?.expect("request should be complete");
    Ok((request, src.to_vec()))
}

fn create_chunked_request(chunks: &[&[u8]], trailers: &[(&str, &str)]) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(
        b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
    );

    for data in chunks {
        request.extend_from_slice(format!("{:X}\r\n", data.len()).as_bytes());
        request.extend_from_slice(data);
        request.extend_from_slice(b"\r\n");
    }

    request.extend_from_slice(b"0\r\n");
    for (name, value) in trailers {
        request.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
    }
    request.extend_from_slice(b"\r\n");

    request
}

#[test]
fn mr1_chunk_hex_crlf_roundtrip() {
    let large = vec![b'X'; 1024];
    let cases: Vec<Vec<&[u8]>> = vec![
        vec![b"foo"],
        vec![b"hello", b" world"],
        vec![b"a", b"b", b"c"],
        vec![large.as_slice()],
        vec![b"0123456789", b"abcde", b"XXXXXXXXXXXXXXX"],
    ];

    for chunks in cases {
        let expected_body: Vec<u8> = chunks
            .iter()
            .flat_map(|data| data.iter().copied())
            .collect();
        let request_data = create_chunked_request(&chunks, &[]);

        let req = decode_request(&request_data)
            .expect("decode should succeed")
            .expect("request should be complete");

        assert_eq!(req.method, Method::Post);
        assert_eq!(req.uri, "/upload");
        assert_eq!(
            req.body, expected_body,
            "chunked round-trip should preserve body bytes"
        );
        assert!(
            req.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("transfer-encoding")
                    && value.eq_ignore_ascii_case("chunked")
            }),
            "Transfer-Encoding: chunked header should be preserved"
        );
    }
}

#[test]
fn mr2_zero_chunk_trailers_termination() {
    let cases: Vec<(Vec<&[u8]>, Vec<(&str, &str)>)> = vec![
        (vec![b"hello"], vec![]),
        (vec![b"hello"], vec![("X-Trace", "abc123")]),
        (
            vec![b"hello"],
            vec![
                ("X-Trace", "abc123"),
                ("X-Timing", "50ms"),
                ("X-Server", "asupersync"),
            ],
        ),
        (vec![], vec![("X-Empty", "true")]),
        (
            vec![b"foo", b"bar", b"baz"],
            vec![("X-Chunks", "3"), ("X-Length", "9")],
        ),
    ];

    for (chunks, trailers) in cases {
        let expected_body: Vec<u8> = chunks
            .iter()
            .flat_map(|data| data.iter().copied())
            .collect();
        let request_data = create_chunked_request(&chunks, &trailers);

        let req = decode_request(&request_data)
            .expect("decode should succeed")
            .expect("request should be complete");

        assert_eq!(req.body, expected_body, "body should be assembled");
        assert_eq!(req.trailers.len(), trailers.len(), "trailer count");

        for (expected_name, expected_value) in &trailers {
            let found = req.trailers.iter().find(|(name, value)| {
                name.eq_ignore_ascii_case(expected_name) && value == expected_value
            });
            assert!(
                found.is_some(),
                "trailer {expected_name}: {expected_value} should be preserved"
            );
        }
    }
}

#[test]
fn mr3_oversized_chunk_size_rejection() {
    let cases = [
        ("FFFFFFFF", "maximum 32-bit value"),
        ("7FFFFFFFFFFFFFFF", "near 64-bit signed max"),
        ("100000000", "huge chunk size"),
        ("FFFFFFFFFFFFFFFFF", "usize overflow on 64-bit"),
    ];

    for (chunk_size, description) in cases {
        let mut request = Vec::new();
        request.extend_from_slice(
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        request.extend_from_slice(chunk_size.as_bytes());
        request.extend_from_slice(b"\r\n");

        match decode_request(&request) {
            Err(HttpError::BodyTooLarge | HttpError::BadChunkedEncoding) | Ok(None) => {}
            other => {
                panic!(
                    "expected bounded rejection or incomplete parse for {description}, got {other:?}"
                )
            }
        }
    }
}

#[test]
fn mr4_invalid_hex_chars_rejection() {
    let cases = [
        ("G", "invalid hex char G"),
        ("1G", "invalid hex char in middle"),
        ("ZZ", "multiple invalid hex chars"),
        ("1Z2", "invalid hex char between valid ones"),
        ("@", "invalid symbol"),
        ("1@", "invalid symbol after valid hex"),
        ("", "empty chunk size"),
        (" 5", "leading whitespace"),
        ("5 ", "trailing whitespace"),
        (" 5 ", "both leading and trailing whitespace"),
        ("1-2", "dash in chunk size"),
        ("1+2", "plus in chunk size"),
        ("5.", "decimal point"),
    ];

    for (chunk_size, description) in cases {
        let mut request = Vec::new();
        request.extend_from_slice(
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        request.extend_from_slice(chunk_size.as_bytes());
        request.extend_from_slice(b"\r\nhello\r\n0\r\n\r\n");

        match decode_request(&request) {
            Err(HttpError::BadChunkedEncoding) => {}
            other => panic!("expected BadChunkedEncoding for {description}, got {other:?}"),
        }
    }
}

#[test]
fn mr5_chunked_response_header_exclusivity() {
    let chunked_resp = Response::new(200, "OK", b"hello world".to_vec())
        .with_header("Transfer-Encoding", "chunked");

    let encoded = encode_response(chunked_resp).expect("encoding should succeed");

    assert!(encoded.contains("Transfer-Encoding: chunked\r\n"));
    assert!(!encoded.contains("Content-Length"));
    assert!(encoded.contains("B\r\nhello world\r\n0\r\n\r\n"));

    let invalid_resp = Response::new(200, "OK", b"test".to_vec())
        .with_header("Transfer-Encoding", "chunked")
        .with_header("Content-Length", "4");
    assert!(matches!(
        encode_response(invalid_resp),
        Err(HttpError::AmbiguousBodyLength)
    ));

    let normal_resp = Response::new(200, "OK", b"test".to_vec());
    let encoded = encode_response(normal_resp).expect("encoding should succeed");

    assert!(encoded.contains("Content-Length: 4\r\n"));
    assert!(!encoded.contains("Transfer-Encoding"));
    assert!(encoded.ends_with("\r\n\r\ntest"));

    let chunked_with_trailers = Response::new(200, "OK", b"data".to_vec())
        .with_header("Transfer-Encoding", "chunked")
        .with_trailer("X-Trace", "abc123")
        .with_trailer("X-Timing", "50ms");
    let encoded = encode_response(chunked_with_trailers).expect("encoding should succeed");

    assert!(encoded.contains("Transfer-Encoding: chunked\r\n"));
    assert!(!encoded.contains("Content-Length"));
    assert!(encoded.ends_with("0\r\nX-Trace: abc123\r\nX-Timing: 50ms\r\n\r\n"));

    let invalid_trailers =
        Response::new(200, "OK", b"test".to_vec()).with_trailer("X-Trace", "abc123");
    assert!(matches!(
        encode_response(invalid_trailers),
        Err(HttpError::TrailersNotAllowed)
    ));
}

#[test]
fn property_chunk_extensions_ignored() {
    let cases = [
        ("5;name=value", b"hello" as &[u8]),
        ("5;name=value;other=data", b"hello"),
        ("5;flag", b"hello"),
        ("A;charset=utf-8;boundary=something", b"helloworld"),
        ("5;name=\"value\"", b"hello"),
    ];

    for (chunk_line, data) in cases {
        let mut request = Vec::new();
        request.extend_from_slice(
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        request.extend_from_slice(chunk_line.as_bytes());
        request.extend_from_slice(b"\r\n");
        request.extend_from_slice(data);
        request.extend_from_slice(b"\r\n0\r\n\r\n");

        let req = decode_request(&request)
            .expect("decode should succeed")
            .expect("request should be complete");

        assert_eq!(req.body, data, "chunk extensions should not affect body");
    }
}

#[test]
fn edge_case_empty_and_zero_chunks() {
    let empty_chunked = create_chunked_request(&[], &[]);
    let req = decode_request(&empty_chunked)
        .expect("decode should succeed")
        .expect("request should be complete");
    assert!(req.body.is_empty());

    let mut pipelined = create_chunked_request(&[], &[]);
    pipelined.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
    let (req, remaining) =
        decode_request_with_remainder(&pipelined).expect("zero chunk should complete request");
    assert!(req.body.is_empty());
    assert_eq!(remaining, b"5\r\nhello\r\n0\r\n\r\n");

    let empty_chunked_resp =
        Response::new(200, "OK", Vec::<u8>::new()).with_header("Transfer-Encoding", "chunked");
    let encoded = encode_response(empty_chunked_resp).expect("encoding should succeed");

    assert!(encoded.ends_with("0\r\n\r\n"));
    assert!(!encoded.contains("Content-Length"));
}

#[test]
fn edge_case_chunk_size_boundaries() {
    let data_sets = [
        Vec::new(),
        vec![b'X'; 1],
        vec![b'X'; 15],
        vec![b'X'; 16],
        vec![b'X'; 255],
        vec![b'X'; 256],
        vec![b'X'; 4095],
    ];

    for expected_data in data_sets {
        let request = create_chunked_request(&[expected_data.as_slice()], &[]);
        let req = decode_request(&request)
            .expect("decode should succeed")
            .expect("request should be complete");

        assert_eq!(
            req.body,
            expected_data,
            "chunk size should decode {} bytes",
            expected_data.len()
        );
    }
}

#[test]
fn security_crlf_handling() {
    let cases = [
        (b"line1\r\nline2" as &[u8], "CRLF in data"),
        (b"\r\n\r\n", "multiple CRLFs"),
        (b"line1\rline2", "CR only"),
        (b"line1\nline2", "LF only"),
    ];

    for (chunk_data, description) in cases {
        let request = create_chunked_request(&[chunk_data], &[]);
        let req = decode_request(&request)
            .unwrap_or_else(|err| panic!("decode should succeed for {description}: {err:?}"))
            .expect("request should be complete");

        assert_eq!(
            req.body, chunk_data,
            "{description}: chunk data bytes should be preserved"
        );
    }
}
