//! Audit + regression test for `src/grpc/web.rs` Trailers-Only
//! response shape (tick #171).
//!
//! Operator's question: "verify error responses with no body use
//! HEADERS+END_STREAM (Trailers-Only) per gRPC spec."
//!
//! gRPC Spec context:
//!
//!   The gRPC spec allows TWO terminal-response shapes:
//!     * **Trailers-Only**: a single HEADERS frame with
//!       `END_STREAM = 1` carrying both the response headers
//!       (`:status: 200`, `content-type: application/grpc`)
//!       AND the gRPC trailers (`grpc-status: <i>`,
//!       `grpc-message: <s>`). Used for "error before any body
//!       could be sent" — handler returned Err before emitting
//!       any DATA frame.
//!     * **Response with Trailers**: HEADERS + N×DATA frames +
//!       TRAILERS frame. Used for normal responses where the
//!       server has a body to emit.
//!
//! Audit findings:
//!
//!   (a) **`encode_trailers` (web.rs:119) produces a
//!       self-contained trailer frame** — flag `0x80`, length-
//!       prefixed HTTP/1.1 header block. It does NOT require a
//!       preceding DATA frame to be valid. This is the
//!       structural property that makes Trailers-Only possible:
//!       the trailer frame carries everything the consumer
//!       needs to decode the gRPC outcome.
//!
//!   (b) **Status::ok() and Status::* errors use the SAME
//!       trailer-frame shape.** A regression that special-cased
//!       error responses (e.g. by inserting an empty DATA frame
//!       before the trailers) would break Trailers-Only. The
//!       golden snapshot at `src/grpc/snapshots/...frame_layouts.snap`
//!       pins the bytes for both `[error_trailers_only]` and
//!       `[trailers_only]` (Status::ok with metadata only).
//!
//!   (c) **Trailer block is RFC 9110-conformant** — `\r\n`-
//!       delimited header lines. A consumer that follows the
//!       gRPC-Web spec can decode the block via standard HTTP
//!       header parsing, with no special "Trailers-Only"
//!       framing.
//!
//!   (d) **The transport adapter (HTTP/2 server in
//!       `src/http/h2/server.rs` — out of this audit's scope)
//!       is responsible for emitting the HEADERS+END_STREAM
//!       wire frame** when the handler returns Err with no
//!       body. The asupersync `Server::dispatch_unary` returns
//!       `Result<Response<Bytes>, Status>` — the transport sees
//!       Err and emits Trailers-Only; sees Ok with body and
//!       emits HEADERS+DATA+TRAILERS.
//!
//! Regression tests below pin (a)+(b)+(c) at the public
//! `encode_trailers` API surface. (d) is structurally reliant
//! on transport-adapter compliance and is exercised by the
//! HTTP/2 server's own conformance tests.

use asupersync::bytes::BytesMut;
use asupersync::grpc::Status;
use asupersync::grpc::status::Code;
use asupersync::grpc::streaming::{Metadata, MetadataValue};
use asupersync::grpc::web::{TrailerFrame, decode_trailers, encode_trailers};

/// gRPC-Web trailer frame flag byte: high bit set, low 7 bits = 0.
const TRAILER_FLAG: u8 = 0x80;
/// Standard 5-byte gRPC-Web frame header: 1 byte flag + 4 byte BE length.
const FRAME_HEADER_SIZE: usize = 5;

#[test]
fn error_status_encodes_as_self_contained_trailer_frame() {
    // Pin (a): an error Status produces a complete trailer
    // frame with no preceding body required. The frame's flag
    // byte is 0x80 (trailer marker per gRPC-Web spec).
    let mut buf = BytesMut::new();
    encode_trailers(&Status::not_found("missing"), &Metadata::new(), &mut buf);
    assert!(buf.len() >= FRAME_HEADER_SIZE, "frame must include header");
    assert_eq!(
        buf[0], TRAILER_FLAG,
        "trailer frame's first byte MUST be 0x80 — without this the \
         consumer cannot distinguish trailers from data and Trailers-Only \
         response cannot be parsed",
    );
    let length = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    assert_eq!(
        length,
        buf.len() - FRAME_HEADER_SIZE,
        "length prefix must equal trailer-block byte count",
    );

    // The consumer can decode the trailer block standalone —
    // no body frame needed.
    let decoded = decode_trailers(&buf[FRAME_HEADER_SIZE..])
        .expect("Trailers-Only block decodes without preceding body");
    assert_eq!(decoded.status.code().as_i32(), Code::NotFound.as_i32());
    assert_eq!(decoded.status.message(), "missing");
}

#[test]
fn ok_status_with_no_body_encodes_as_trailers_only_shape() {
    // Pin (b): even a SUCCESS response with no body uses the
    // exact same trailer-frame shape. Some servers respond with
    // `Status::ok` and only metadata — gRPC spec allows this as
    // a Trailers-Only success (e.g. a cache hit confirmation).
    let mut metadata = Metadata::new();
    assert!(metadata.insert("x-cache", "MISS"));
    let mut buf = BytesMut::new();
    encode_trailers(&Status::ok(), &metadata, &mut buf);

    assert_eq!(buf[0], TRAILER_FLAG);
    let decoded = decode_trailers(&buf[FRAME_HEADER_SIZE..]).expect("Trailers-Only OK decodes");
    assert_eq!(decoded.status.code().as_i32(), 0);
    assert_eq!(
        decoded.metadata.get("x-cache").and_then(|v| match v {
            MetadataValue::Ascii(s) => Some(s.as_str()),
            MetadataValue::Binary(_) => None,
        }),
        Some("MISS"),
        "trailer-block metadata round-trips",
    );
}

#[test]
fn trailer_block_is_rfc9110_crlf_delimited() {
    // Pin (c): trailer block uses CRLF line delimiters per
    // RFC 9110. A regression that switched to LF-only or to
    // some custom separator would break interop with
    // grpc-web.js / grpcurl / browser fetch().
    let mut buf = BytesMut::new();
    encode_trailers(
        &Status::internal("server error"),
        &Metadata::new(),
        &mut buf,
    );
    let body = std::str::from_utf8(&buf[FRAME_HEADER_SIZE..]).expect("ascii");
    assert!(
        body.contains("\r\n"),
        "trailer block MUST use CRLF line delimiters",
    );
    assert!(
        body.starts_with("grpc-status: "),
        "trailer block MUST start with grpc-status: header",
    );
}

#[test]
fn trailers_only_carries_status_metadata_in_single_frame() {
    // Pin (a)+(b): everything a consumer needs (status code,
    // optional message, additional trailing metadata) lives in
    // a SINGLE trailer frame. No DATA frame is required for the
    // consumer to decode the gRPC outcome.
    let mut metadata = Metadata::new();
    assert!(metadata.insert("retry-after", "3"));
    assert!(metadata.insert("x-trace-id", "abc-123"));

    let mut buf = BytesMut::new();
    encode_trailers(
        &Status::resource_exhausted("rate limited"),
        &metadata,
        &mut buf,
    );
    let TrailerFrame {
        status,
        metadata: decoded_metadata,
        ..
    } = decode_trailers(&buf[FRAME_HEADER_SIZE..]).expect("trailers-only frame decodes");
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(status.message(), "rate limited");
    assert_eq!(
        decoded_metadata.get("retry-after").and_then(|v| match v {
            MetadataValue::Ascii(s) => Some(s.as_str()),
            MetadataValue::Binary(_) => None,
        }),
        Some("3"),
    );
    assert_eq!(
        decoded_metadata.get("x-trace-id").and_then(|v| match v {
            MetadataValue::Ascii(s) => Some(s.as_str()),
            MetadataValue::Binary(_) => None,
        }),
        Some("abc-123"),
    );
}

#[test]
fn trailers_only_no_metadata_minimal_byte_layout() {
    // Pin: a Status::ok() with no metadata produces a minimal
    // trailer frame containing ONLY `grpc-status: 0\r\n`.
    // Pinned to lock in the wire shape — a regression that
    // added an empty `grpc-message: \r\n` line or extra
    // padding would change byte counts and break consumer
    // assumptions.
    let mut buf = BytesMut::new();
    encode_trailers(&Status::ok(), &Metadata::new(), &mut buf);
    let body = std::str::from_utf8(&buf[FRAME_HEADER_SIZE..]).expect("ascii");
    assert_eq!(
        body, "grpc-status: 0\r\n",
        "minimal Status::ok() trailers-only is exactly grpc-status: 0\\r\\n",
    );
}

#[test]
fn error_trailers_message_is_percent_encoded() {
    // Pin (b)+(c): error trailer messages with bytes that are
    // unsafe in HTTP header values (CR, LF, %) are percent-
    // encoded. A regression that wrote raw \n into the trailer
    // block would corrupt the frame and break the
    // single-frame-decoded property.
    let mut buf = BytesMut::new();
    encode_trailers(
        &Status::invalid_argument("bad\nfield"),
        &Metadata::new(),
        &mut buf,
    );
    let body = std::str::from_utf8(&buf[FRAME_HEADER_SIZE..]).expect("ascii");
    assert!(
        body.contains("grpc-message: bad%0Afield"),
        "newline in message MUST be percent-encoded; got body: {body:?}",
    );
    // The decode side reverses the percent-encoding.
    let decoded = decode_trailers(&buf[FRAME_HEADER_SIZE..]).expect("decode");
    assert_eq!(
        decoded.status.message(),
        "bad\nfield",
        "percent-decoded message recovers the original bytes",
    );
}

#[test]
fn empty_status_ok_with_metadata_still_decodes_as_ok() {
    // Pin (b): Status::ok() with metadata DOES not need a body
    // — the trailer frame is sufficient. A consumer that
    // received this Trailers-Only response sees code=0 and the
    // metadata.
    let mut metadata = Metadata::new();
    assert!(metadata.insert("x-served-by", "cache-hit"));
    let mut buf = BytesMut::new();
    encode_trailers(&Status::ok(), &metadata, &mut buf);

    let decoded =
        decode_trailers(&buf[FRAME_HEADER_SIZE..]).expect("OK + metadata trailers-only decodes");
    assert_eq!(decoded.status.code().as_i32(), 0);
    // status_message is "OK" or empty — both are valid for
    // Status::ok(). Pin that it does NOT carry the metadata
    // value (no cross-pollination between message and metadata).
    assert!(
        decoded.status.message().is_empty() || decoded.status.message() == "OK",
        "OK status message must be empty or 'OK'; got {:?}",
        decoded.status.message(),
    );
}
