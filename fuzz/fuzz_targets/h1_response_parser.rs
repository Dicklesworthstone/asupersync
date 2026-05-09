//! HTTP/1.1 Client Response Parser Fuzzing
//!
//! This fuzzes the HTTP/1.1 client-side response parsing functionality
//! in src/http/h1/client.rs. Specifically tests Http1ClientCodec::decode
//! and Http1ClientCodec::decode_eof for parsing arbitrary HTTP response bytes.

#![no_main]

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::client::Http1ClientCodec;
use asupersync::http::h1::codec::HttpError;
use asupersync::http::h1::types::Response;
use libfuzzer_sys::fuzz_target;
use std::io::ErrorKind;

const MAX_DATA_SIZE: usize = 10_000_000; // 10MB limit to prevent OOM

fuzz_target!(|data: &[u8]| {
    // Size guard to prevent OOM
    if data.len() > MAX_DATA_SIZE {
        return;
    }

    // Create a fresh codec for each input
    let mut codec = Http1ClientCodec::new();

    // Copy data to BytesMut for decoding
    let mut buf = BytesMut::from(data);

    // Try to decode HTTP response - should never panic
    observe_decode_result(codec.decode(&mut buf));

    // Also test decode_eof for edge cases where connection closes mid-response
    let mut buf2 = BytesMut::from(data);
    observe_decode_result(Http1ClientCodec::new().decode_eof(&mut buf2));

    // Test codec reuse after potential error
    let mut buf3 = BytesMut::from(data);
    observe_decode_result(Http1ClientCodec::new().decode(&mut buf3));

    test_fixed_response_canaries();
});

fn observe_decode_result(result: Result<Option<Response>, HttpError>) {
    match result {
        Ok(Some(response)) => {
            assert!(
                (100..=999).contains(&response.status),
                "decoded response status must remain in HTTP status-code range"
            );
            let debug = format!("{response:?}");
            assert!(
                !debug.is_empty(),
                "decoded response debug should not be empty"
            );
        }
        Ok(None) => {}
        Err(error) => {
            let display = format!("{error}");
            assert!(
                !display.is_empty(),
                "decode error display should not be empty"
            );
        }
    }
}

fn test_fixed_response_canaries() {
    let fixed_length =
        expect_decode_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: yes\r\n\r\nhello");
    assert_eq!(fixed_length.status, 200);
    assert_eq!(fixed_length.reason, "OK");
    assert_eq!(fixed_length.body, b"hello");
    assert!(
        fixed_length
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-test") && value == "yes")
    );

    let eof_delimited = expect_decode_eof_complete(b"HTTP/1.1 200 OK\r\n\r\nhello");
    assert_eq!(eof_delimited.status, 200);
    assert_eq!(eof_delimited.body, b"hello");

    expect_error_variant(
        b"HTTP/1.1 99 Bad\r\nContent-Length: 0\r\n\r\n",
        matches_bad_request_line,
        "status below 100 must reject as bad status line",
    );
    expect_error_variant(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
        matches_ambiguous_body_length,
        "TE+CL response must reject as ambiguous body length",
    );
    expect_incomplete_then_eof_error(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe");
}

fn expect_decode_complete(input: &[u8]) -> Response {
    let mut codec = Http1ClientCodec::new();
    let mut buf = BytesMut::from(input);
    match codec.decode(&mut buf) {
        Ok(Some(response)) => response,
        Ok(None) => panic!("expected complete response, got pending decode"),
        Err(error) => panic!("expected complete response, got {error:?}"),
    }
}

fn expect_decode_eof_complete(input: &[u8]) -> Response {
    let mut codec = Http1ClientCodec::new();
    let mut buf = BytesMut::from(input);
    match codec.decode(&mut buf) {
        Ok(None) => {}
        Ok(Some(response)) => return response,
        Err(error) => panic!("expected EOF-delimited response head, got {error:?}"),
    }
    match codec.decode_eof(&mut buf) {
        Ok(Some(response)) => response,
        Ok(None) => panic!("expected EOF-delimited response, got pending decode"),
        Err(error) => panic!("expected EOF-delimited response, got {error:?}"),
    }
}

fn expect_error_variant(input: &[u8], predicate: fn(&HttpError) -> bool, message: &str) {
    let mut codec = Http1ClientCodec::new();
    let mut buf = BytesMut::from(input);
    match codec.decode(&mut buf) {
        Err(error) if predicate(&error) => {}
        Ok(result) => panic!("{message}: unexpected successful result {result:?}"),
        Err(error) => panic!("{message}: unexpected error {error:?}"),
    }
}

fn expect_incomplete_then_eof_error(input: &[u8]) {
    let mut codec = Http1ClientCodec::new();
    let mut buf = BytesMut::from(input);
    match codec.decode(&mut buf) {
        Ok(None) => {}
        Ok(Some(response)) => panic!("expected incomplete body, got {response:?}"),
        Err(error) => panic!("expected incomplete body, got {error:?}"),
    }
    match codec.decode_eof(&mut buf) {
        Err(HttpError::Io(error)) if error.kind() == ErrorKind::UnexpectedEof => {}
        Ok(result) => panic!("expected EOF error for incomplete body, got {result:?}"),
        Err(error) => panic!("expected EOF error for incomplete body, got {error:?}"),
    }
}

fn matches_bad_request_line(error: &HttpError) -> bool {
    matches!(error, HttpError::BadRequestLine)
}

fn matches_ambiguous_body_length(error: &HttpError) -> bool {
    matches!(error, HttpError::AmbiguousBodyLength)
}
