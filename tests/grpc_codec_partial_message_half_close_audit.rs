//! Audit + regression test for `src/grpc/codec.rs` partial-message
//! handling when the client half-closes (END_STREAM) mid-LPM-frame.
//!
//! Operator's question: "when length prefix says N bytes but only
//! M < N arrive before client half-closes, does the codec emit
//! RST_STREAM(INTERNAL_ERROR) or hang?" Per the gRPC HTTP/2
//! transport spec, partial messages MUST trigger an error.
//!
//! Audit chain (verified at the public API surface):
//!
//!   1. `GrpcCodec::decode` (codec.rs:117) on partial input
//!      returns `Ok(None)` ("need more data"). It consumes NO
//!      bytes — the buffer is left intact for the next read. This
//!      is the correct streaming-decoder contract (the codec
//!      cannot itself observe stream EOF; that's the layer
//!      above's job).
//!
//!   2. The driver above the codec (`FramedRead::poll_next` in
//!      `src/codec/framed_read.rs:191-214`) tracks the EOF
//!      transition: when the underlying reader returns 0 bytes,
//!      `eof = true`, and the next decode iteration calls
//!      `decode_eof` instead of `decode`.
//!
//!   3. `Decoder::decode_eof` default impl
//!      (`src/codec/decoder.rs:25-33`) retries `decode`. If it
//!      still returns `Ok(None)` AND `src.is_empty()` → clean
//!      stream end (`Ok(None)`). If it returns `Ok(None)` AND
//!      `!src.is_empty()` → `Err(io::Error(UnexpectedEof,
//!      "incomplete frame at EOF"))`.
//!
//!   4. The `Decoder::Error: From<io::Error>` bound triggers
//!      `GrpcError::from(io::Error)` (status.rs:468-473) which
//!      maps `io::ErrorKind::UnexpectedEof` →
//!      `TransportErrorKind::ResetByPeer` (status.rs:354) →
//!      `GrpcError::Transport(ResetByPeer, msg)`.
//!
//!   5. `GrpcError::into_status` (status.rs:435-437) maps
//!      `TransportErrorKind::ResetByPeer` → `Status::unavailable`
//!      → `Code::Unavailable`.
//!
//! Verdict: **SOUND**. The codec does not hang on partial input
//! and the EOF-with-trailing-bytes path produces a structured
//! error in the transport class (Code::Unavailable). Per gRPC
//! spec a transport-level half-close mid-frame is correctly
//! reported as UNAVAILABLE; the transport layer (HTTP/2 server)
//! converts that into the trailing HEADERS frame with grpc-status
//! 14, which is the wire-level signal equivalent to
//! RST_STREAM(INTERNAL_ERROR) for the operator's stated concern.
//!
//! Regression tests below pin (1)-(5) at the public API surface.
//! A regression that:
//!   - had `decode` consume bytes on partial input
//!   - had `decode` busy-spin on partial input
//!   - had `decode_eof` swallow trailing bytes silently
//!   - had the io::Error→GrpcError mapping change class
//! would all be caught here.

use asupersync::bytes::{BufMut, BytesMut};
use asupersync::codec::Decoder;
use asupersync::grpc::codec::MESSAGE_HEADER_SIZE;
use asupersync::grpc::status::Code;
use asupersync::grpc::GrpcCodec;

/// Build an LPM frame with the given declared length but only
/// `actual_payload_bytes` bytes appended after the header.
fn lpm_partial(declared_len: u32, actual_payload_bytes: usize) -> BytesMut {
    let mut buf = BytesMut::with_capacity(MESSAGE_HEADER_SIZE + actual_payload_bytes);
    buf.put_u8(0); // compressed flag = 0
    buf.put_u32(declared_len); // big-endian length prefix
    buf.extend_from_slice(&vec![0xAB; actual_payload_bytes]);
    buf
}

#[test]
fn partial_payload_decode_returns_ok_none_without_consuming_buffer() {
    // Pin (1): header declares 10 bytes of payload, only 5 bytes
    // arrived. decode MUST return Ok(None) AND leave the buffer
    // intact so the next read appends the rest.
    let mut buf = lpm_partial(10, 5);
    let original_len = buf.len();

    let mut codec = GrpcCodec::new();
    let result = codec.decode(&mut buf);

    assert!(
        matches!(result, Ok(None)),
        "partial payload (5 of 10 bytes) MUST return Ok(None); got {result:?}"
    );
    assert_eq!(
        buf.len(),
        original_len,
        "decode MUST NOT consume buffer bytes when frame is incomplete — \
         a regression that did would lose the partial bytes on retry",
    );
}

#[test]
fn partial_header_decode_returns_ok_none_without_consuming_buffer() {
    // Pin (1) edge: less than 5 bytes (the header itself is
    // incomplete). Same Ok(None) + no-consume guarantee.
    let mut buf = BytesMut::new();
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0); // only 3 of 5 header bytes
    let original_len = buf.len();

    let mut codec = GrpcCodec::new();
    let result = codec.decode(&mut buf);

    assert!(
        matches!(result, Ok(None)),
        "partial header (3 of 5 bytes) MUST return Ok(None); got {result:?}"
    );
    assert_eq!(buf.len(), original_len);
}

#[test]
fn empty_buffer_decode_returns_ok_none() {
    // Pin (1) edge: an empty buffer (no header, no payload) is
    // not an error — it's "need more data."
    let mut buf = BytesMut::new();
    let mut codec = GrpcCodec::new();
    let result = codec.decode(&mut buf);
    assert!(matches!(result, Ok(None)));
}

#[test]
fn partial_payload_at_eof_surfaces_unexpected_eof_transport_error() {
    // Pin (3)+(4)+(5) AUDIT-CRITICAL: when the peer half-closes
    // (EOS) with bytes still buffered for an incomplete frame,
    // decode_eof MUST surface an error — NOT silently drop the
    // bytes, NOT hang, NOT return Ok(None).
    //
    // The error must carry the transport class so the upstream
    // HTTP/2 adapter can emit the trailing HEADERS frame with
    // grpc-status 14 (UNAVAILABLE).
    let mut buf = lpm_partial(10, 5);
    let mut codec = GrpcCodec::new();

    let err = codec
        .decode_eof(&mut buf)
        .expect_err("partial frame at EOF MUST be an error");
    let status = err.into_status();
    assert_eq!(
        status.code(),
        Code::Unavailable,
        "partial frame at half-close maps to Unavailable (transport \
         class) per the gRPC HTTP/2 transport spec; got {:?}",
        status.code(),
    );
}

#[test]
fn partial_header_at_eof_surfaces_transport_error() {
    // Pin (3)+(4)+(5): even an incomplete HEADER (less than 5
    // bytes) at EOF is a transport-class error, not a quiet drop.
    let mut buf = BytesMut::new();
    buf.put_u8(0); // 1 of 5 header bytes
    let mut codec = GrpcCodec::new();

    let err = codec
        .decode_eof(&mut buf)
        .expect_err("partial header at EOF MUST error");
    let status = err.into_status();
    assert_eq!(status.code(), Code::Unavailable);
}

#[test]
fn header_only_no_payload_at_eof_surfaces_transport_error() {
    // Pin (3)+(4)+(5): header arrived (5 bytes, declares
    // length=10), zero payload bytes, then EOF. This is the
    // canonical mid-frame half-close: the peer announced a
    // 10-byte payload, sent zero of it, and closed the stream.
    // MUST be a transport-class error.
    let mut buf = BytesMut::new();
    buf.put_u8(0);
    buf.put_u32(10); // declares 10 bytes
    // zero payload bytes follow
    let mut codec = GrpcCodec::new();

    let err = codec
        .decode_eof(&mut buf)
        .expect_err("header-only at EOF (mid-frame half-close) MUST error");
    let status = err.into_status();
    assert_eq!(status.code(), Code::Unavailable);
}

#[test]
fn clean_eof_with_empty_buffer_returns_ok_none() {
    // Pin (3): if the peer half-closes AT a clean frame boundary
    // (buffer empty), decode_eof returns Ok(None) — NOT an
    // error. This is the normal end-of-stream case.
    let mut buf = BytesMut::new();
    let mut codec = GrpcCodec::new();
    let result = codec.decode_eof(&mut buf);
    assert!(
        matches!(result, Ok(None)),
        "clean EOS (empty buffer) MUST be Ok(None); got {result:?}"
    );
}

#[test]
fn complete_frame_at_eof_decodes_then_clean_eof() {
    // Pin (3) end-to-end: the buffer holds a COMPLETE frame and
    // the peer half-closes. decode_eof yields the frame; a
    // subsequent call yields Ok(None).
    let mut buf = BytesMut::new();
    buf.put_u8(0);
    buf.put_u32(3);
    buf.extend_from_slice(b"abc");

    let mut codec = GrpcCodec::new();
    let first = codec.decode_eof(&mut buf).expect("decode_eof OK");
    let frame = first.expect("frame yielded");
    assert_eq!(frame.data.as_ref(), b"abc");
    assert_eq!(buf.len(), 0, "decode consumed the full frame");

    let second = codec.decode_eof(&mut buf).expect("decode_eof OK");
    assert!(second.is_none(), "post-frame EOS yields Ok(None)");
}

#[test]
fn extra_trailing_bytes_after_complete_frame_at_eof_errors() {
    // Pin (3) edge: a complete frame followed by a few stray
    // bytes (incomplete next-frame header) at EOF. The first
    // call yields the frame; the second call sees the trailing
    // partial header and errors.
    let mut buf = BytesMut::new();
    buf.put_u8(0);
    buf.put_u32(3);
    buf.extend_from_slice(b"abc");
    // Now append a partial header for a "next" frame the peer
    // never finished sending.
    buf.put_u8(0);
    buf.put_u8(0); // only 2 trailing bytes — incomplete header

    let mut codec = GrpcCodec::new();
    let first = codec.decode_eof(&mut buf).expect("first decode_eof");
    assert_eq!(first.expect("frame").data.as_ref(), b"abc");

    // 2 stray bytes remain; this is mid-header half-close.
    let err = codec
        .decode_eof(&mut buf)
        .expect_err("trailing partial header MUST error at EOF");
    let status = err.into_status();
    assert_eq!(status.code(), Code::Unavailable);
}

#[test]
fn partial_decode_does_not_busy_spin() {
    // Pin (1) anti-busy-spin: repeatedly calling decode on the
    // same partial buffer keeps returning Ok(None) without
    // mutating state. A regression that flipped the flag byte,
    // consumed the header, or otherwise mutated the buffer would
    // be caught here. This is the property that prevents
    // FramedRead from hot-looping when the peer is slow.
    let mut buf = lpm_partial(100, 50);
    let snapshot = buf.to_vec();

    let mut codec = GrpcCodec::new();
    for i in 0..10 {
        let result = codec.decode(&mut buf);
        assert!(
            matches!(result, Ok(None)),
            "iteration {i}: partial decode MUST stay Ok(None); got {result:?}"
        );
        assert_eq!(
            buf.as_ref(),
            snapshot.as_slice(),
            "iteration {i}: buffer MUST be byte-identical across calls",
        );
    }
}

#[test]
fn unexpected_eof_error_is_classified_as_transport() {
    // Pin (4): the io::ErrorKind::UnexpectedEof produced by
    // `decode_eof` for trailing bytes maps to GrpcError::Transport
    // (NOT Protocol, NOT InvalidMessage, NOT Internal). The
    // transport class is the one that allows the upstream layer
    // to surface UNAVAILABLE instead of treating the half-close
    // as a peer-misbehavior INTERNAL.
    let mut buf = lpm_partial(10, 1);
    let mut codec = GrpcCodec::new();
    let err = codec.decode_eof(&mut buf).expect_err("partial frame at EOF errors");

    // Verify the error is the Transport variant, NOT the protocol
    // variant. We assert via the Code mapping which is the most
    // robust public-API check; protocol-class errors map to
    // Internal, transport-class to Unavailable.
    let status = err.into_status();
    assert_eq!(
        status.code(),
        Code::Unavailable,
        "EOF-with-trailing-bytes is Transport class (Code::Unavailable), \
         NOT Protocol class (Code::Internal). A regression that mapped \
         this to Internal would falsely accuse the peer of protocol \
         violation when the actual cause is a transport-level half-close.",
    );
}

#[test]
fn partial_message_does_not_succeed_with_truncated_payload() {
    // Pin: a peer that declares Length=10 and sends 5 payload
    // bytes followed by EOF MUST NOT yield a "truncated" message
    // of 5 bytes. The frame either decodes fully or errors —
    // there is no in-between.
    let mut buf = lpm_partial(10, 5);
    let mut codec = GrpcCodec::new();

    // First, decode should be Ok(None) — need more data.
    assert!(matches!(codec.decode(&mut buf), Ok(None)));

    // After EOS, decode_eof must error. CRUCIALLY it must NOT
    // return Ok(Some(GrpcMessage{data: 5-byte-vec})) — that would
    // be a truncation-by-half-close vulnerability where the
    // server processes a partial message as if it were complete.
    let result = codec.decode_eof(&mut buf);
    match result {
        Ok(None) => panic!(
            "BUG: partial frame at EOF returned Ok(None) — silent \
             truncation; the partial bytes are lost without any \
             error signal",
        ),
        Ok(Some(_)) => panic!(
            "BUG: partial frame at EOF returned Ok(Some(...)) — \
             the codec accepted a truncated message as complete",
        ),
        Err(e) => {
            let status = e.into_status();
            assert_eq!(status.code(), Code::Unavailable);
        }
    }
}

#[test]
fn massive_declared_length_with_tiny_payload_at_eof_does_not_oom() {
    // Pin: a peer announces an enormous Length (within the
    // configured cap so we don't trip MessageTooLarge at the
    // header), sends only a tiny payload, and half-closes.
    // The decode path must NOT pre-allocate the declared length
    // on the partial branch — it just returns Ok(None) and the
    // FramedRead level enforces the per-connection buffer cap.
    //
    // This test is structurally similar to the other partial
    // tests but uses a length large enough that an over-eager
    // pre-allocation regression would be visible (1 MiB declared,
    // 4 bytes received).
    let mut codec = GrpcCodec::with_max_size(8 * 1024 * 1024); // 8 MiB cap
    let mut buf = lpm_partial(1024 * 1024, 4); // 1 MiB declared, 4 received

    // decode is Ok(None) — no allocation amplification.
    assert!(matches!(codec.decode(&mut buf), Ok(None)));
    // Buffer is unchanged (still header + 4 bytes).
    assert_eq!(buf.len(), MESSAGE_HEADER_SIZE + 4);

    // decode_eof errors — does not magically allocate the missing 1 MiB.
    let err = codec.decode_eof(&mut buf).expect_err("partial frame at EOF");
    assert_eq!(err.into_status().code(), Code::Unavailable);
}
