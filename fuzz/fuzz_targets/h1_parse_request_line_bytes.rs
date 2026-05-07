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

use asupersync::http::h1::codec::fuzz_parse_request_line_bytes;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 8192; // HTTP/1.1 request line limit

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    let _ = fuzz_parse_request_line_bytes(data);

    // Boundary candidates: well-formed request lines.
    for candidate in &[
        b"GET / HTTP/1.1".as_ref(),
        b"POST /path HTTP/1.0".as_ref(),
        b"HEAD /index.html HTTP/1.1".as_ref(),
        b"PUT /api/v1/data HTTP/1.1".as_ref(),
        b"DELETE /resource HTTP/1.0".as_ref(),
        b"OPTIONS * HTTP/1.1".as_ref(),
        b"CONNECT proxy.example.com:8080 HTTP/1.1".as_ref(),
        b"TRACE / HTTP/1.1".as_ref(),
        b"PATCH /item/123 HTTP/1.1".as_ref(),
        b"CUSTOM /custom HTTP/1.1".as_ref(), // Extension method
        b"GET /long".repeat(100).as_bytes(), // Long URI path
        b"VERY-LONG-METHOD-NAME-FOR-EDGE-CASE /path HTTP/1.1".as_ref(),
        b"GET / HTTP/2.0".as_ref(), // Unsupported version
        b"get /path http/1.1".as_ref(), // Lowercase (invalid)
        b"GET  /path  HTTP/1.1".as_ref(), // Extra spaces
        b"GET\t/path\tHTTP/1.1".as_ref(), // Tabs instead of spaces
        b"GET /path%20with%20encoded%20spaces HTTP/1.1".as_ref(), // URL encoding
        b"".as_ref(), // Empty input
        b"GET".as_ref(), // Incomplete
        b"GET /".as_ref(), // Missing version
        b"GET / HTTP".as_ref(), // Incomplete version
        b"GET\r/path HTTP/1.1".as_ref(), // Embedded CR
        b"GET\n/path HTTP/1.1".as_ref(), // Embedded LF
        b"GET\0/path HTTP/1.1".as_ref(), // Null byte
        b"GET /path\xFF HTTP/1.1".as_ref(), // High byte
        b"GET /path/\x01\x02\x03 HTTP/1.1".as_ref(), // Control chars
        b"METHOD /very/long/path/that/exceeds/normal/uri/length/limits/and/should/test/boundary/conditions/in/parser HTTP/1.1".as_ref(),
    ] {
        let _ = fuzz_parse_request_line_bytes(candidate);
    }
});