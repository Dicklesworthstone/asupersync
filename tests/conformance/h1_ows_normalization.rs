//! HTTP/1.1 Optional Whitespace (OWS) Normalization Tests (RFC 9112 §3.2)
//!
//! RFC 9112 field-line grammar permits optional whitespace *after* the `:`
//! separator (`field-name ":" OWS field-value OWS`), but whitespace *before*
//! the colon is invalid. These vectors pin the parser's handling of SP/HTAB
//! trimming, internal whitespace preservation, and obs-fold rejection.

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::Request;
use asupersync::http::h1::codec::{Http1Codec, HttpError};

/// Parse a single request from raw bytes
fn parse(raw: &[u8]) -> Result<Option<Request>, HttpError> {
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(raw);
    codec.decode(&mut buf)
}

fn header_value<'a>(request: &'a Request, name: &str) -> &'a str {
    request
        .headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .unwrap_or_else(|| panic!("missing header {name}"))
}

#[test]
fn ows_after_colon_trims_mixed_sp_and_htab() {
    let req = b"GET / HTTP/1.1\r\nHost:   example.com   \r\nUser-Agent:\t\tMyAgent\t\t\r\n\r\n";

    let decoded = parse(req)
        .expect("mixed OWS request should not error")
        .expect("complete request must decode");

    assert_eq!(header_value(&decoded, "Host"), "example.com");
    assert_eq!(header_value(&decoded, "User-Agent"), "MyAgent");
}

#[test]
fn zero_length_ows_is_accepted_without_inserting_whitespace() {
    let req = b"GET / HTTP/1.1\r\nHost:example.com\r\nConnection:keep-alive\r\n\r\n";

    let decoded = parse(req)
        .expect("zero-length OWS request should not error")
        .expect("complete request must decode");

    assert_eq!(header_value(&decoded, "Host"), "example.com");
    assert_eq!(header_value(&decoded, "Connection"), "keep-alive");
}

#[test]
fn internal_whitespace_is_preserved() {
    let req =
        b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Spacing: token\t spaced  value\tinside\r\n\r\n";

    let decoded = parse(req)
        .expect("internal whitespace request should not error")
        .expect("complete request must decode");

    assert_eq!(
        header_value(&decoded, "X-Spacing"),
        "token\t spaced  value\tinside"
    );
}

#[test]
fn whitespace_before_colon_is_rejected() {
    for req in [
        b"GET / HTTP/1.1\r\nHost : example.com\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\r\nHost\t: example.com\r\n\r\n".as_slice(),
    ] {
        let result = parse(req);
        assert!(
            matches!(result, Err(HttpError::InvalidHeaderName)),
            "OWS before ':' must be rejected, got {result:?}"
        );
    }
}

#[test]
fn obs_fold_with_space_continuation_is_rejected() {
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Test: one\r\n two\r\n\r\n";
    let result = parse(req);
    assert!(
        result.is_err(),
        "obs-fold with SP continuation must be rejected"
    );
}

#[test]
fn obs_fold_with_tab_continuation_is_rejected() {
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Test: one\r\n\ttwo\r\n\r\n";
    let result = parse(req);
    assert!(
        result.is_err(),
        "obs-fold with HTAB continuation must be rejected"
    );
}

#[test]
fn excessive_ows_is_trimmed_without_altering_value() {
    let mut req = b"GET / HTTP/1.1\r\nHost:".to_vec();
    req.extend(std::iter::repeat_n(b' ', 512));
    req.extend_from_slice(b"example.com");
    req.extend(std::iter::repeat_n(b'\t', 512));
    req.extend_from_slice(b"\r\n\r\n");

    let decoded = parse(&req)
        .expect("excessive OWS request should not error")
        .expect("complete request must decode");

    assert_eq!(header_value(&decoded, "Host"), "example.com");
}
