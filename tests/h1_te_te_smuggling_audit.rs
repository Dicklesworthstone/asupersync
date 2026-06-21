#![allow(missing_docs)]
#![allow(clippy::all)]

//! br-asupersync-u8cwpr — TE.TE / TE-injection smuggling audit.
//!
//! `src/http/h1/codec.rs::reject_duplicate_transfer_encoding` only
//! covers two IDENTICAL `Transfer-Encoding: chunked` lines. The
//! HIGH-RISK smuggling primitive is when the duplicate Transfer-Encoding
//! lines have DIFFERENT values, or use case variation, or smuggle the
//! second TE via header-value CRLF injection — front-end and back-end
//! proxies disagree on which header wins, opening a CL.TE / TE.TE
//! desync. This audit pins the rejection per RFC 9112 §6.1 / §5.1 /
//! RFC 9110 §5.5 across each smuggling shape:
//!
//!   1. `Transfer-Encoding: chunked` + `Transfer-Encoding: identity`
//!      (different values, the canonical smuggling case)
//!   2. `Transfer-Encoding: chunked, identity`
//!      (single line, multiple codings — chunked must be FINAL per §6.1)
//!   3. `Transfer-Encoding: chunked` + `transfer-encoding: chunked`
//!      (case-insensitive duplicate per RFC 9110 §5.1)
//!   4. `Foo: bar\r\nTransfer-Encoding: chunked` smuggled in a value
//!      (header-name CRLF injection per RFC 9110 §5.5)
//!   5. `Transfer-Encoding : chunked` (whitespace before colon)
//!      (RFC 9112 §5.1: invalid)
//!   6. `Transfer-Encoding: Chunked` (mixed-case value — must still
//!      be honoured as chunked, not silently fall through to a
//!      content-length read)

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::{Http1Codec, HttpError};
use asupersync::http::h1::types::Request;

fn decode(data: &[u8]) -> Result<Option<Request>, HttpError> {
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(data);
    codec.decode(&mut buf)
}

/// Smuggling primitive: a peer sends two Transfer-Encoding header lines
/// with DIFFERENT codings. Some proxies pick the first, others the
/// last; the gap creates a TE.TE desync. RFC 9112 §6.1 requires us to
/// reject as malformed; asupersync uses `DuplicateTransferEncoding`.
#[test]
fn te_te_chunked_identity_must_reject_as_duplicate_te() {
    let raw = b"POST /api HTTP/1.1\r\n\
                Host: example.com\r\n\
                Transfer-Encoding: chunked\r\n\
                Transfer-Encoding: identity\r\n\r\n\
                0\r\n\r\n";
    let result = decode(raw);
    assert!(
        matches!(result, Err(HttpError::DuplicateTransferEncoding)),
        "TE.TE smuggling (chunked+identity) must fail closed; got {result:?}",
    );
}

/// Inverse ordering — front-end might honour the first TE, back-end
/// the last. Either way, the request is malformed.
#[test]
fn te_te_identity_chunked_must_reject_as_duplicate_te() {
    let raw = b"POST /api HTTP/1.1\r\n\
                Host: example.com\r\n\
                Transfer-Encoding: identity\r\n\
                Transfer-Encoding: chunked\r\n\r\n\
                0\r\n\r\n";
    let result = decode(raw);
    assert!(
        matches!(result, Err(HttpError::DuplicateTransferEncoding)),
        "TE.TE smuggling (identity+chunked) must fail closed; got {result:?}",
    );
}

/// RFC 9112 §6.1: the chunked transfer coding MUST be the final
/// encoding when present. Multi-coding values like
/// `Transfer-Encoding: chunked, identity` create an identical desync
/// risk to TE.TE. asupersync's stricter posture rejects ANY
/// multi-coding TE value via `BadTransferEncoding`.
#[test]
fn te_chunked_then_identity_in_one_line_must_reject() {
    let raw = b"POST /api HTTP/1.1\r\n\
                Host: example.com\r\n\
                Transfer-Encoding: chunked, identity\r\n\r\n\
                0\r\n\r\n";
    let result = decode(raw);
    assert!(
        matches!(result, Err(HttpError::BadTransferEncoding)),
        "multi-coding TE (chunked, identity) must fail closed; got {result:?}",
    );
}

/// RFC 9110 §5.1: header field names are case-insensitive.
/// `Transfer-Encoding` and `transfer-encoding` MUST be treated as the
/// SAME field; presenting both lines is a duplicate, not two distinct
/// headers a proxy could pick between.
#[test]
fn te_te_case_insensitive_duplicate_must_reject() {
    let raw = b"POST /api HTTP/1.1\r\n\
                Host: example.com\r\n\
                Transfer-Encoding: chunked\r\n\
                transfer-encoding: chunked\r\n\r\n\
                0\r\n\r\n";
    let result = decode(raw);
    assert!(
        matches!(result, Err(HttpError::DuplicateTransferEncoding)),
        "case-variant TE duplicate must fail closed; got {result:?}",
    );
}

/// RFC 9110 §5.5: "A field value containing CR, LF, or NUL characters
/// is invalid." At this raw HTTP/1 parser boundary the injected CRLF has
/// already materialized as a separate `Transfer-Encoding` header line; the
/// required security outcome is still fail-closed before body parsing. With a
/// smuggled TE plus `Content-Length`, asupersync rejects the message as an
/// ambiguous body-length request-smuggling vector.
#[test]
fn header_value_crlf_injection_smuggling_te_must_reject() {
    let raw = b"POST /api HTTP/1.1\r\n\
                Host: example.com\r\n\
                X-Forwarded-For: attacker\r\nTransfer-Encoding: chunked\r\n\
                Content-Length: 5\r\n\r\n\
                hello";
    let result = decode(raw);
    assert!(
        matches!(result, Err(HttpError::AmbiguousBodyLength)),
        "CRLF injection smuggling TE must fail closed; got {result:?}",
    );
}

/// RFC 9112 §5.1: "no whitespace is allowed between the field name and
/// the colon." `Transfer-Encoding : chunked` (space before colon) is
/// rejected by some proxies and accepted by others — a smuggling
/// primitive. asupersync's `parse_header_line_bounds` requires every
/// pre-colon byte to be a valid `tchar` (no SP/HTAB), surfacing the
/// violation as `InvalidHeaderName`.
#[test]
fn te_with_whitespace_before_colon_must_reject() {
    let raw = b"POST /api HTTP/1.1\r\n\
                Host: example.com\r\n\
                Transfer-Encoding : chunked\r\n\r\n\
                0\r\n\r\n";
    let result = decode(raw);
    assert!(
        matches!(result, Err(HttpError::InvalidHeaderName)),
        "whitespace-before-colon TE must fail closed; got {result:?}",
    );
}

/// Positive control: mixed-case `Chunked` value MUST still be honoured
/// as chunked encoding (RFC 9112 §7.1: transfer codings are
/// case-insensitive token names). A regression that read the body as
/// content-length-zero would silently truncate the request.
#[test]
fn te_chunked_mixed_case_value_must_be_accepted() {
    let raw = b"POST /api HTTP/1.1\r\n\
                Host: example.com\r\n\
                Transfer-Encoding: Chunked\r\n\r\n\
                5\r\nhello\r\n0\r\n\r\n";
    let req = decode(raw)
        .expect("mixed-case chunked must parse")
        .expect("expected complete request");
    assert_eq!(req.body, b"hello");
}
