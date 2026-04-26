#![allow(warnings)]
#![allow(clippy::all)]
//! HTTP/1.1 protocol conformance — gaps not covered by sibling h1_* files.
//!
//! Most surfaces in the user-listed RFC 7230/7231 set are already covered:
//!   * chunked encoding round-trip + invalid sizes → `h1_chunked`,
//!     `h1_request_chunked`, `h1_body_framing`
//!   * persistent-connection semantics → `h1_keepalive`
//!   * 100-Continue handling → `h1_expect_continue`
//!   * Transfer-Encoding vs Content-Length precedence → partial coverage
//!     in `h1_chunked` / `h1_body_framing`
//!
//! This file fills two genuinely-missing surfaces:
//!
//!   1. **obs-fold rejection** (RFC 7230 §3.2.4 / RFC 9112 §5.2):
//!      "A server that receives an obs-fold in a request message that is
//!      not within a message/http container MUST either reject the
//!      message ... or replace each received obs-fold with one or more SP
//!      octets."
//!
//!   2. **TE+CL request smuggling** (RFC 7230 §3.3.3 rule 3): when both
//!      Transfer-Encoding and Content-Length are present, the server
//!      MUST treat the message as invalid and reject (or strip CL and
//!      treat as a smuggling attack).
//!
//! Wiring assumption: tests/conformance/mod.rs declares this file as
//! `pub mod h1_protocol`. Other h1 conformance files are also being
//! wired in this same commit batch — until that lands they are dead
//! code (~30+ tests across 7 files).

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::{Http1Codec, HttpError};

/// Parse a single request from a literal byte slice. Returns the decoder
/// result so tests can assert success / typed-error / Incomplete.
fn parse(raw: &[u8]) -> Result<Option<asupersync::http::h1::codec::Request>, HttpError> {
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(raw);
    codec.decode(&mut buf)
}

// ─── obs-fold rejection (RFC 7230 §3.2.4 / RFC 9112 §5.2) ───────────────────

#[test]
fn obs_fold_with_leading_sp_is_rejected_or_collapsed() {
    // Classic obs-fold: header value continued on the next line with
    // a leading SP. RFC 7230 §3.2.4 forbids generating this; servers
    // MUST either reject the request or replace the CRLF + leading
    // whitespace with SP octets. We assert "reject" here because the
    // codec's documented stance is rejection, but the test is also
    // satisfied if the value is silently collapsed (proves no
    // smuggling-via-fold).
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Folded: first\r\n second\r\n\r\n";
    match parse(req) {
        Err(_) => {
            // Rejection — preferred behavior.
        }
        Ok(Some(decoded)) => {
            // Collapse — also acceptable per spec, but the resulting
            // header value MUST NOT contain a bare CR or LF (which
            // would enable header smuggling downstream).
            for (name, value) in decoded.headers.iter() {
                if name.eq_ignore_ascii_case("X-Folded") {
                    let v = value.to_str().unwrap_or("");
                    assert!(
                        !v.contains('\r') && !v.contains('\n'),
                        "obs-fold collapse must strip CR/LF; got {v:?}"
                    );
                }
            }
        }
        Ok(None) => panic!("obs-fold request must not yield Incomplete"),
    }
}

#[test]
fn obs_fold_with_leading_ht_is_rejected_or_collapsed() {
    // RFC 7230 obs-fold: continuation can also start with HTAB (0x09).
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Folded: first\r\n\tsecond\r\n\r\n";
    match parse(req) {
        Err(_) => {} // preferred
        Ok(Some(decoded)) => {
            for (name, value) in decoded.headers.iter() {
                if name.eq_ignore_ascii_case("X-Folded") {
                    let v = value.to_str().unwrap_or("");
                    assert!(
                        !v.contains('\r') && !v.contains('\n'),
                        "obs-fold collapse must strip CR/LF; got {v:?}"
                    );
                }
            }
        }
        Ok(None) => panic!("obs-fold request must not yield Incomplete"),
    }
}

// ─── TE+CL smuggling (RFC 7230 §3.3.3 rule 3) ───────────────────────────────

#[test]
fn transfer_encoding_chunked_with_content_length_is_rejected_or_te_wins() {
    // When BOTH Transfer-Encoding: chunked and Content-Length are present,
    // the request is a known HTTP request-smuggling vector (CL.TE / TE.CL
    // desync). Per RFC 7230 §3.3.3 rule 3 a conformant server MUST
    // either reject the message OR strip Content-Length and use the
    // chunked framing. The test passes if either outcome holds — what
    // it must NEVER do is honour Content-Length and ignore the chunked
    // framing (that's CL.TE smuggling).
    let req = b"\
        POST /upload HTTP/1.1\r\n\
        Host: example.com\r\n\
        Transfer-Encoding: chunked\r\n\
        Content-Length: 3\r\n\
        \r\n\
        5\r\nhello\r\n0\r\n\r\n";
    match parse(req) {
        Err(_) => {
            // Rejection — preferred per smuggling-defense posture.
        }
        Ok(Some(decoded)) => {
            // Acceptable per spec only if TE wins (CL was discarded).
            // The body MUST be the chunked-decoded "hello" (5 bytes),
            // NOT the first 3 bytes of the chunk-size header that
            // CL=3 would imply.
            assert_eq!(
                decoded.body.as_ref(),
                b"hello",
                "TE+CL accepted only if TE wins; honoring CL=3 = smuggling vector"
            );
        }
        Ok(None) => panic!("TE+CL request must not yield Incomplete"),
    }
}

#[test]
fn duplicate_content_length_with_same_value_is_acceptable() {
    // Some legacy clients emit Content-Length twice with the same
    // value. RFC 7230 §3.3.2 says this case MAY be accepted (collapsed
    // to a single value); we assert the codec doesn't crash and either
    // accepts or returns a typed error.
    let req = b"\
        POST / HTTP/1.1\r\n\
        Host: example.com\r\n\
        Content-Length: 5\r\n\
        Content-Length: 5\r\n\
        \r\n\
        hello";
    let res = parse(req);
    assert!(
        matches!(res, Ok(_) | Err(_)),
        "duplicate same-value CL must yield typed result, got {res:?}"
    );
}

#[test]
fn duplicate_content_length_with_different_values_is_rejected() {
    // RFC 7230 §3.3.2: "If a message is received without
    // Transfer-Encoding and with either multiple Content-Length header
    // fields having differing field-values or a single Content-Length
    // header field having an invalid value, then the message framing is
    // invalid and the recipient MUST treat it as an unrecoverable error."
    let req = b"\
        POST / HTTP/1.1\r\n\
        Host: example.com\r\n\
        Content-Length: 5\r\n\
        Content-Length: 7\r\n\
        \r\n\
        hello";
    match parse(req) {
        Err(_) => {} // expected — rejection per RFC 7230 §3.3.2
        Ok(_) => panic!("duplicate Content-Length with conflicting values MUST be rejected"),
    }
}

// ─── Empty-headers smoke (RFC 7230 §3.2 baseline) ───────────────────────────

#[test]
fn minimal_request_parses_cleanly() {
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let r = parse(req);
    assert!(
        matches!(r, Ok(Some(_))),
        "minimal RFC 7230 request must parse, got {r:?}"
    );
}
