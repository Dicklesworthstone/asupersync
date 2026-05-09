#![no_main]

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::{Http1Codec, HttpError};
use asupersync::http::h1::{Method, Request, Version};
use libfuzzer_sys::fuzz_target;

// Maximum data size to prevent timeouts on extremely large inputs
const MAX_DATA_SIZE: usize = 10 * 1024 * 1024; // 10MB

fn decode_once(raw: &[u8]) -> Result<Option<Request>, HttpError> {
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(raw);
    codec.decode(&mut buf)
}

fn decode_with_limits(
    raw: &[u8],
    max_headers_size: usize,
    max_body_size: usize,
) -> Result<Option<Request>, HttpError> {
    let mut codec = Http1Codec::new()
        .max_headers_size(max_headers_size)
        .max_body_size(max_body_size);
    let mut buf = BytesMut::from(raw);
    codec.decode(&mut buf)
}

fn expect_complete_request(raw: &[u8]) -> Request {
    decode_once(raw)
        .expect("valid HTTP/1 request must not return an error")
        .expect("valid HTTP/1 request must decode completely")
}

fn assert_header(headers: &[(String, String)], name: &str, value: &str) {
    assert!(
        headers
            .iter()
            .any(|(header_name, header_value)| header_name == name && header_value == value),
        "expected header {name}: {value}, got {headers:?}"
    );
}

fn run_fixed_canaries() {
    let get = expect_complete_request(
        b"GET /health?ready=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: fuzz\r\n\r\n",
    );
    assert_eq!(get.method, Method::Get);
    assert_eq!(get.uri, "/health?ready=1");
    assert_eq!(get.version, Version::Http11);
    assert!(get.body.is_empty());
    assert!(get.trailers.is_empty());
    assert_header(&get.headers, "Host", "example.com");
    assert_header(&get.headers, "User-Agent", "fuzz");

    let post = expect_complete_request(
        b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
    );
    assert_eq!(post.method, Method::Post);
    assert_eq!(post.uri, "/upload");
    assert_eq!(post.version, Version::Http11);
    assert_eq!(post.body, b"hello");
    assert!(post.trailers.is_empty());

    let chunked = expect_complete_request(
        b"POST /chunked HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: done\r\n\r\n",
    );
    assert_eq!(chunked.method, Method::Post);
    assert_eq!(chunked.uri, "/chunked");
    assert_eq!(chunked.body, b"hello world");
    assert_header(&chunked.trailers, "X-Trailer", "done");

    let incomplete = decode_once(b"GET /partial HTTP/1.1\r\nHost: example.com\r\n")
        .expect("partial head must not be a protocol error");
    assert!(
        incomplete.is_none(),
        "partial request head must wait for more bytes"
    );

    let malformed_line = decode_once(b"GET  /double-space HTTP/1.1\r\nHost: example.com\r\n\r\n");
    assert!(
        matches!(malformed_line, Err(HttpError::BadRequestLine)),
        "repeated request-line delimiter must reject, got {malformed_line:?}"
    );

    let duplicate_content_length =
        decode_once(b"POST /dup HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na");
    assert!(
        matches!(
            duplicate_content_length,
            Err(HttpError::DuplicateContentLength)
        ),
        "duplicate Content-Length must reject, got {duplicate_content_length:?}"
    );

    let ambiguous_body_length = decode_once(
        b"POST /ambiguous HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    );
    assert!(
        matches!(ambiguous_body_length, Err(HttpError::AmbiguousBodyLength)),
        "Transfer-Encoding plus Content-Length must reject, got {ambiguous_body_length:?}"
    );

    let headers_too_large = decode_with_limits(
        b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Long: abcdef\r\n\r\n",
        32,
        256,
    );
    assert!(
        matches!(headers_too_large, Err(HttpError::HeadersTooLarge)),
        "headers over configured limit must reject, got {headers_too_large:?}"
    );

    let body_too_large =
        decode_with_limits(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello", 256, 4);
    assert!(
        matches!(body_too_large, Err(HttpError::BodyTooLarge)),
        "body over configured limit must reject, got {body_too_large:?}"
    );
}

fuzz_target!(|data: &[u8]| {
    run_fixed_canaries();

    // Size guard to prevent timeout on massive inputs
    if data.len() > MAX_DATA_SIZE {
        return;
    }

    // Create a new codec instance for each test
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(data);

    // Test request parsing - must not panic
    let _ = codec.decode(&mut buf);

    // Test multiple decode calls on the same buffer (simulates pipelined requests)
    let _ = codec.decode(&mut buf);

    // Test with different buffer sizes to trigger boundary conditions
    if data.len() > 1 {
        let mut small_buf = BytesMut::from(&data[..1]);
        let _ = codec.decode(&mut small_buf);
    }

    // Test with mid-sized buffer
    if data.len() > 100 {
        let mid = data.len() / 2;
        let mut mid_buf = BytesMut::from(&data[..mid]);
        let _ = codec.decode(&mut mid_buf);
    }

    // Test codec with different size limits
    let mut small_headers_codec = Http1Codec::new().max_headers_size(256);
    let mut small_body_codec = Http1Codec::new().max_body_size(256);

    let mut buf_copy1 = BytesMut::from(data);
    let mut buf_copy2 = BytesMut::from(data);

    let _ = small_headers_codec.decode(&mut buf_copy1);
    let _ = small_body_codec.decode(&mut buf_copy2);
});
