//! HTTP/1.1 obsolete text handling tests.
//!
//! Test suite for verifying correct handling of obs-text in HTTP/1.1 headers.
//! Obsolete text allows characters outside the ASCII range (0x80-0xFF) in
//! header values for backward compatibility with legacy systems.
//!
//! # Standards Compliance
//! - RFC 7230 Section 3.2.6 (Field Value Components)
//! - Latin-1 fallback encoding for non-ASCII bytes
//! - Proper rejection of invalid character sequences

use crate::bytes::BytesMut;
use crate::codec::Decoder;
use crate::http::h1::codec::Http1Codec;

#[test]
fn obs_text_header_value_decodes_with_latin1_fallback() {
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::new();

    buf.extend_from_slice(b"GET / HTTP/1.1\r\n");
    buf.extend_from_slice(b"Test-Header: \xff\r\n");
    buf.extend_from_slice(b"\r\n");

    let request = codec
        .decode(&mut buf)
        .expect("obs-text header value should be syntactically valid")
        .expect("complete request should decode");

    assert_eq!(request.headers, vec![("Test-Header".into(), "ÿ".into())]);
}
