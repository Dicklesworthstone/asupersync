//! br-asupersync-sbc0pi — Fuzz `H1 parse_request_line_bytes` against
//! adversarial request-line bytes: oversize request lines, invalid method
//! tokens, malformed URIs, invalid HTTP versions, embedded CRLF, control
//! characters, mixed whitespace, and other parsing edge cases.
//!
//! Invariants asserted:
//!   * Parser panics, if any, surface directly to libFuzzer.
//!   * Parser returns Result; on malformed input it returns
//!     `HttpError`, not a wrapped value.
//!   * Valid request lines parse to expected method/uri/version triple.

#![no_main]

use asupersync::http::h1::codec::{HttpError, fuzz_parse_request_line_bytes};
use asupersync::http::h1::types::Version;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 8192; // HTTP/1.1 request line limit
const BAD_REQUEST_LINE_DISPLAY: &str = "malformed request line";
const BAD_METHOD_DISPLAY: &str = "unrecognised HTTP method";
const UNSUPPORTED_VERSION_DISPLAY: &str = "unsupported HTTP version";

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    observe_request_line_parse(data);

    assert_parse_ok(b"GET / HTTP/1.1", "GET", "/", Version::Http11);
    assert_parse_ok(b"POST /path HTTP/1.0", "POST", "/path", Version::Http10);
    assert_parse_ok(
        b"HEAD /index.html HTTP/1.1",
        "HEAD",
        "/index.html",
        Version::Http11,
    );
    assert_parse_ok(b"OPTIONS * HTTP/1.1", "OPTIONS", "*", Version::Http11);
    assert_parse_ok(
        b"CONNECT proxy.example.com:8080 HTTP/1.1",
        "CONNECT",
        "proxy.example.com:8080",
        Version::Http11,
    );
    assert_parse_ok(
        b"GET http://example.com/path HTTP/1.1",
        "GET",
        "http://example.com/path",
        Version::Http11,
    );
    assert_parse_ok(
        b"CUSTOM /custom HTTP/1.1",
        "CUSTOM",
        "/custom",
        Version::Http11,
    );

    assert_bad_request_line(b"");
    assert_bad_request_line(b"GET");
    assert_bad_request_line(b"GET /");
    assert_bad_request_line(b"GET  /path  HTTP/1.1");
    assert_bad_request_line(b"GET\t/path\tHTTP/1.1");
    assert_bad_request_line(b"GET //ambiguous HTTP/1.1");
    assert_bad_request_line(b"POST * HTTP/1.1");
    assert_bad_request_line(b"CONNECT /path HTTP/1.1");
    assert_bad_request_line(b"GET\r/path HTTP/1.1");
    assert_bad_request_line(b"GET /\npath HTTP/1.1");
    assert_bad_request_line(b"GET /\0path HTTP/1.1");
    assert_bad_request_line(b"GET /path\xFF HTTP/1.1");
    assert_bad_request_line(b"GET /path/\x01\x02\x03 HTTP/1.1");

    assert_bad_method(b"BAD() / HTTP/1.1");
    assert_unsupported_version(b"GET / HTTP/2.0");
    assert_unsupported_version(b"GET / HTTP");
});

fn assert_parse_ok(
    line: &[u8],
    expected_method: &str,
    expected_uri: &str,
    expected_version: Version,
) {
    let (method, uri, version) =
        fuzz_parse_request_line_bytes(line).expect("valid request line candidate");
    assert_eq!(
        method.as_str(),
        expected_method,
        "method mismatch for {line:?}"
    );
    assert_eq!(uri, expected_uri, "uri mismatch for {line:?}");
    assert_eq!(version, expected_version, "version mismatch for {line:?}");
}

fn observe_request_line_parse(line: &[u8]) {
    match fuzz_parse_request_line_bytes(line) {
        Ok((method, uri, version)) => {
            assert!(
                is_method_token(method.as_str()),
                "accepted invalid method token {:?} for {line:?}",
                method.as_str()
            );
            assert!(
                is_visible_uri(&uri),
                "accepted invalid request target {uri:?} for {line:?}"
            );
            assert!(
                matches!(version, Version::Http10 | Version::Http11),
                "accepted unsupported HTTP version {version:?} for {line:?}"
            );
        }
        Err(err) => {
            assert!(
                !err.to_string().is_empty(),
                "request-line parser errors should be observable"
            );
        }
    }
}

fn is_method_token(method: &str) -> bool {
    !method.is_empty() && method.bytes().all(is_http_token_byte)
}

fn is_http_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_'
            | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
    )
}

fn is_visible_uri(uri: &str) -> bool {
    !uri.is_empty()
        && uri.len() <= MAX_INPUT_LEN
        && uri
            .bytes()
            .all(|byte| !byte.is_ascii_control() && byte != b' ')
}

fn assert_bad_request_line(line: &[u8]) {
    assert_request_line_error(
        line,
        HttpError::BadRequestLine,
        BAD_REQUEST_LINE_DISPLAY,
        "BadRequestLine",
    );
}

fn assert_bad_method(line: &[u8]) {
    assert_request_line_error(line, HttpError::BadMethod, BAD_METHOD_DISPLAY, "BadMethod");
}

fn assert_unsupported_version(line: &[u8]) {
    assert_request_line_error(
        line,
        HttpError::UnsupportedVersion,
        UNSUPPORTED_VERSION_DISPLAY,
        "UnsupportedVersion",
    );
}

fn assert_request_line_error(
    line: &[u8],
    expected: HttpError,
    expected_display: &str,
    label: &str,
) {
    let Err(error) = fuzz_parse_request_line_bytes(line) else {
        panic!("expected {label} for {line:?}");
    };
    assert_eq!(
        std::mem::discriminant(&error),
        std::mem::discriminant(&expected),
        "expected {label} for {line:?}, got {error:?}"
    );
    assert_eq!(
        error.to_string(),
        expected_display,
        "request-line parser diagnostic changed for {label}"
    );
}
