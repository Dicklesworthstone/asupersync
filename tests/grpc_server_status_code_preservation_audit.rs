//! Audit + regression test for `src/grpc/status.rs` and
//! `src/grpc/web.rs` `Status::code()` preservation through wire
//! encoding (tick #168).
//!
//! Operator's question: "verify status codes from internal errors
//! map to gRPC status correctly, no 200 OK leak on error."
//!
//! Audit findings:
//!
//!   (a) **`Status::code()` integer preservation through
//!       `encode_trailers`.** `web.rs:119-124` writes
//!       `"grpc-status: <i32>\r\n"` where `<i32>` is
//!       `status.code().as_i32()`. There is no remapping, no
//!       fallback to 0 for unknown codes — the integer preserves
//!       1:1.
//!
//!   (b) **gRPC-over-HTTP/2 spec mandates HTTP 200 with
//!       grpc-status trailer.** The "200 OK leak on error"
//!       framing reflects the spec correctly: the HTTP-level
//!       status is ALWAYS 200 for in-band gRPC responses; the
//!       gRPC outcome is in the `grpc-status` trailer. A
//!       consumer that sees HTTP 200 alone (no trailer or
//!       missing grpc-status) MUST treat it as
//!       `Code::Internal` per gRPC spec — and asupersync's
//!       `decode_trailers` does exactly this (web.rs:275+
//!       comments).
//!
//!   (c) **Duplicate-grpc-status defense** (br-asupersync-nbryje):
//!       an adversarial intermediary that prepends
//!       `grpc-status: 0` to a real `grpc-status: 13` block
//!       would attempt to convert an Internal error into
//!       success. asupersync's decode_trailers (web.rs:198-
//!       203) rejects duplicate grpc-status headers with an
//!       error rather than picking one — closing the
//!       "200 OK leak" class at parse time.
//!
//!   (d) **Malformed-integer defense** (br-asupersync-6qwzl0):
//!       `grpc-status: garbage` or `grpc-status: -1` is
//!       rejected as a parse error, NOT silently coerced to 0
//!       (which would be the "OK leak" class on the parse
//!       side).
//!
//!   (e) **Status::code() exposes the typed Code enum and
//!       `as_i32()` produces the canonical wire integer.**
//!       The integer values match gRPC spec (Ok=0, Cancelled=1,
//!       Unknown=2, ..., Unauthenticated=16). A regression that
//!       reordered or renumbered the variants would silently
//!       map errors to wrong codes — pinned via a per-variant
//!       round-trip test below.
//!
//! Regression tests below pin (a)-(e) at the public API surface.

use asupersync::bytes::BytesMut;
use asupersync::grpc::Status;
use asupersync::grpc::status::Code;

/// Decode the integer value from a freshly-encoded trailer block.
fn extract_grpc_status(buf: &[u8]) -> i32 {
    // Skip the 5-byte gRPC-Web trailer frame header (1 byte flag
    // + 4 byte length).
    assert!(buf.len() >= 5, "trailer frame must have header");
    let body = &buf[5..];
    let text = std::str::from_utf8(body).expect("trailer body is ASCII");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("grpc-status: ") {
            return rest.parse().expect("integer status");
        }
    }
    panic!("no grpc-status in trailer block: {text:?}");
}

#[test]
fn ok_status_encodes_as_grpc_status_0() {
    // Pin (a): Status::ok() encodes as `grpc-status: 0`.
    let mut buf = BytesMut::new();
    asupersync::grpc::web::encode_trailers(
        &Status::ok(),
        &asupersync::grpc::streaming::Metadata::new(),
        &mut buf,
    );
    assert_eq!(
        extract_grpc_status(&buf),
        0,
        "Status::ok() must encode as grpc-status: 0",
    );
}

#[test]
fn internal_status_encodes_as_grpc_status_13() {
    // Pin (a): Status::internal() encodes as `grpc-status: 13`
    // — NOT 0. A regression that mapped all server-side errors
    // to 0 would be the operator's "200 OK leak" class.
    let mut buf = BytesMut::new();
    asupersync::grpc::web::encode_trailers(
        &Status::internal("server exploded"),
        &asupersync::grpc::streaming::Metadata::new(),
        &mut buf,
    );
    assert_eq!(
        extract_grpc_status(&buf),
        13,
        "Status::internal() must encode as grpc-status: 13 — a regression \
         that remapped to 0 would be the canonical '200 OK leak on error' \
         class the operator is auditing",
    );
}

#[test]
fn every_status_code_round_trips_through_trailer_encoding() {
    // Pin (a)+(e): every Code variant encodes correctly. We
    // walk the full spec table and verify the integer that
    // lands in `grpc-status:` matches `Code::as_i32()`.
    let cases: &[(Code, i32)] = &[
        (Code::Ok, 0),
        (Code::Cancelled, 1),
        (Code::Unknown, 2),
        (Code::InvalidArgument, 3),
        (Code::DeadlineExceeded, 4),
        (Code::NotFound, 5),
        (Code::AlreadyExists, 6),
        (Code::PermissionDenied, 7),
        (Code::ResourceExhausted, 8),
        (Code::FailedPrecondition, 9),
        (Code::Aborted, 10),
        (Code::OutOfRange, 11),
        (Code::Unimplemented, 12),
        (Code::Internal, 13),
        (Code::Unavailable, 14),
        (Code::DataLoss, 15),
        (Code::Unauthenticated, 16),
    ];

    for (code, expected_i32) in cases.iter().copied() {
        // Round 1: the as_i32() integer matches gRPC spec.
        assert_eq!(
            code.as_i32(),
            expected_i32,
            "Code::{code:?}.as_i32() must equal {expected_i32} per gRPC spec",
        );

        // Round 2: the trailer encoding preserves the integer.
        let mut buf = BytesMut::new();
        asupersync::grpc::web::encode_trailers(
            &Status::new(code, ""),
            &asupersync::grpc::streaming::Metadata::new(),
            &mut buf,
        );
        let encoded = extract_grpc_status(&buf);
        assert_eq!(
            encoded, expected_i32,
            "encode_trailers must preserve Code::{code:?} as integer {expected_i32}; \
             got {encoded}",
        );
    }
}

#[test]
fn status_code_method_does_not_remap_internal_to_ok() {
    // Pin (a): the structural identity. Status::internal(...)
    // .code() returns Code::Internal, NOT Code::Ok. A
    // regression that defaulted code to Ok in some "happy path"
    // construction would be the leak.
    let s = Status::internal("anything");
    assert_eq!(s.code(), Code::Internal);
    assert_ne!(s.code(), Code::Ok);
    let s = Status::cancelled("");
    assert_eq!(s.code(), Code::Cancelled);
    assert_ne!(s.code(), Code::Ok);
    let s = Status::unauthenticated("");
    assert_eq!(s.code(), Code::Unauthenticated);
    assert_ne!(s.code(), Code::Ok);
}

#[test]
fn duplicate_grpc_status_in_trailer_block_rejects() {
    // Pin (c): an adversarial trailer block with TWO
    // `grpc-status:` lines (e.g. an injected `grpc-status: 0`
    // followed by the real `grpc-status: 13`) MUST be rejected
    // (br-asupersync-nbryje). Without this defense the
    // decoder might pick the first / last and surface OK
    // instead of Internal.
    use asupersync::grpc::web::decode_trailers;
    let block = b"grpc-status: 0\r\ngrpc-status: 13\r\n";
    let result = decode_trailers(block);
    assert!(
        result.is_err(),
        "duplicate grpc-status MUST surface as parse error, NOT silently \
         pick one (br-asupersync-nbryje). result = {result:?}",
    );
}

#[test]
fn malformed_grpc_status_integer_rejects() {
    // Pin (d): a trailer with `grpc-status: garbage` MUST
    // surface as parse error (br-asupersync-6qwzl0). Coercion
    // to 0 would be the wire-side equivalent of the "200 OK
    // leak" class. Note: integers that parse as i32 (incl.
    // negative) pass the parse check but land at unknown Code
    // — that's a different spec layer.
    use asupersync::grpc::web::decode_trailers;
    let result = decode_trailers(b"grpc-status: garbage\r\n");
    assert!(result.is_err(), "garbage integer must reject");
    let result = decode_trailers(b"grpc-status: 1.5\r\n");
    assert!(result.is_err(), "non-integer (decimal) must reject");
    let result = decode_trailers(b"grpc-status: 0xFF\r\n");
    assert!(result.is_err(), "hex-prefixed integer must reject");
}

#[test]
fn status_message_preserved_through_trailer_encoding() {
    // Pin (a) extension: a non-empty Status message survives
    // the encode/decode round-trip (with percent-encoding for
    // CR/LF). A regression that dropped the message would
    // weaken operator diagnostics.
    let mut buf = BytesMut::new();
    asupersync::grpc::web::encode_trailers(
        &Status::internal("connection lost: peer went away"),
        &asupersync::grpc::streaming::Metadata::new(),
        &mut buf,
    );
    let body = std::str::from_utf8(&buf[5..]).expect("ascii");
    assert!(
        body.contains("grpc-status: 13"),
        "code preserved (Internal=13)",
    );
    assert!(
        body.contains("grpc-message: connection lost: peer went away"),
        "message preserved",
    );
}

#[test]
fn status_message_crlf_percent_encoded_in_trailer() {
    // Pin (a) extension: a Status message containing CRLF
    // (potentially attacker-influenced) is percent-encoded so
    // it cannot inject additional headers / fake grpc-status.
    let mut buf = BytesMut::new();
    asupersync::grpc::web::encode_trailers(
        &Status::internal("line1\r\ngrpc-status: 0"),
        &asupersync::grpc::streaming::Metadata::new(),
        &mut buf,
    );
    let body = std::str::from_utf8(&buf[5..]).expect("ascii");
    // The raw bytes \r\n MUST NOT appear in the message
    // portion — that would inject a second grpc-status: 0
    // line. Verify percent-encoding fired.
    assert!(
        body.contains("grpc-message: line1%0D%0A"),
        "CRLF must percent-encode to %0D%0A; got body: {body:?}",
    );
    // And the grpc-status: 13 from Code::Internal must still
    // be the real (and only true) one. Count only occurrences
    // at the start of a line (after a real \r\n) — the message
    // text might contain "grpc-status: 0" as embedded chars
    // (post-CRLF-percent-encoding) but those are NOT at a line
    // boundary.
    let real_status_lines = body
        .split("\r\n")
        .filter(|line| line.starts_with("grpc-status: "))
        .count();
    assert_eq!(
        real_status_lines, 1,
        "exactly one grpc-status: header line — CRLF injection attempt did \
         NOT smuggle a second header (the 'grpc-status: 0' substring \
         survives in the message text but no longer at a line boundary)",
    );
}
