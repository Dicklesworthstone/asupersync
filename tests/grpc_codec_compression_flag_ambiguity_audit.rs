//! Audit + regression test for `src/grpc/codec.rs` compression
//! flag ambiguity (tick #175).
//!
//! Operator's question: "verify gzip-with-no-data still legal
//! per gRPC spec."
//!
//! gRPC Spec context (compression.md):
//!
//!   * `compressed_flag = 0` → uncompressed payload
//!   * `compressed_flag = 1` → compressed payload (server's
//!     advertised compression)
//!   * Any other value → INVALID per spec, decoder MUST reject
//!     with PROTOCOL_ERROR
//!   * Length = 0 is LEGAL with either flag — represents an
//!     empty message. `compressed_flag = 1` + length = 0 is the
//!     "empty compressed message" case the operator is asking
//!     about — perfectly legal even though it's structurally
//!     redundant (compression of empty data).
//!
//! Audit findings:
//!
//!   (a) **`flag = 1, length = 0` decodes successfully.** The
//!       decoder (codec.rs:117-164) parses flag → 1, length →
//!       0, validates length under cap (0 ≤ max), reads 0 body
//!       bytes, returns `GrpcMessage { compressed: true, data:
//!       <empty> }`. No spurious rejection.
//!
//!   (b) **`flag = 0, length = 0` also decodes successfully.**
//!       Same path, with `compressed: false`. The empty-message
//!       case for both directions.
//!
//!   (c) **Round-trip preservation of the compressed flag.**
//!       `GrpcMessage::compressed(empty_bytes)` encodes to
//!       `[0x01, 0x00, 0x00, 0x00, 0x00]` (5 header bytes, no
//!       body) and decodes back to a GrpcMessage with
//!       `compressed = true` and empty data. Pin so a regression
//!       that flipped the flag bit (or dropped it on
//!       length-zero) would surface here.
//!
//!   (d) **`flag >= 2` rejects with PROTOCOL_ERROR** per spec
//!       (codec.rs:147-156). Length-zero variant of this case
//!       also rejects — the flag check fires regardless of
//!       length. Pin: a peer cannot smuggle past the flag
//!       validator by setting length=0.
//!
//!   (e) **Frame consumes its bytes on flag-error**
//!       (br-asupersync-o7e5xu). Even with length=0, the
//!       decoder advances `MESSAGE_HEADER_SIZE + 0 = 5` bytes
//!       so the next decode call doesn't loop on the same
//!       prefix.
//!
//! Regression tests below pin (a)-(e).

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::{GrpcCodec, GrpcMessage};

/// 5-byte gRPC LPM header: 1 byte compressed flag + 4 byte BE length.
const MESSAGE_HEADER_SIZE: usize = 5;

/// Build an LPM frame from raw flag, declared length, and body bytes.
fn lpm_frame(compressed_flag: u8, declared_length: u32, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MESSAGE_HEADER_SIZE + body.len());
    buf.push(compressed_flag);
    buf.extend_from_slice(&declared_length.to_be_bytes());
    buf.extend_from_slice(body);
    buf
}

#[test]
fn decode_compressed_flag_with_zero_length_is_legal() {
    // Pin (a): flag=1, length=0 → GrpcMessage with
    // compressed=true and empty data. This is the "empty
    // compressed message" the operator asks about.
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let frame = lpm_frame(1, 0, b"");
    let mut buf = BytesMut::from(&frame[..]);

    let msg = codec
        .decode(&mut buf)
        .expect("flag=1+length=0 must decode (gRPC spec compliant)")
        .expect("frame is complete");
    assert!(
        msg.compressed,
        "compressed flag must round-trip — flag=1 means compressed=true",
    );
    assert_eq!(
        msg.data.len(),
        0,
        "length=0 frame produces empty data",
    );
    assert_eq!(
        buf.len(),
        0,
        "all 5 header bytes consumed; no body bytes to read",
    );
}

#[test]
fn decode_uncompressed_flag_with_zero_length_is_legal() {
    // Pin (b): flag=0, length=0 → empty uncompressed message.
    // The other direction of the empty-message contract.
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let frame = lpm_frame(0, 0, b"");
    let mut buf = BytesMut::from(&frame[..]);

    let msg = codec
        .decode(&mut buf)
        .expect("flag=0+length=0 must decode")
        .expect("frame complete");
    assert!(!msg.compressed, "flag=0 means compressed=false");
    assert_eq!(msg.data.len(), 0);
}

#[test]
fn empty_compressed_message_round_trips_through_codec() {
    // Pin (c): a `GrpcMessage::compressed(Bytes::new())`
    // encodes to a 5-byte header + 0 body, and decodes back to
    // an equivalent message. The compressed flag is preserved.
    let original = GrpcMessage::compressed(Bytes::new());
    assert!(original.compressed);
    assert_eq!(original.data.len(), 0);

    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let mut wire = BytesMut::new();
    codec
        .encode(original, &mut wire)
        .expect("encode empty compressed must succeed");
    assert_eq!(
        wire.as_ref(),
        &[0x01, 0x00, 0x00, 0x00, 0x00][..],
        "wire bytes are the 5-byte header: flag=0x01 + 4-byte BE \
         length=0; no body",
    );

    let decoded = codec
        .decode(&mut wire)
        .expect("decode")
        .expect("frame complete");
    assert!(decoded.compressed);
    assert_eq!(decoded.data.len(), 0);
}

#[test]
fn decode_invalid_flag_with_zero_length_still_rejects() {
    // Pin (d): flag=2 with length=0 — a peer might attempt to
    // smuggle by claiming "no body so my malformed flag should
    // be ignored." The decoder must STILL reject.
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let frame = lpm_frame(2, 0, b"");
    let mut buf = BytesMut::from(&frame[..]);

    let err = codec
        .decode(&mut buf)
        .expect_err("flag=2 must reject regardless of length");
    let err_str = format!("{err:?}");
    assert!(
        err_str.to_lowercase().contains("protocol")
            || err_str.to_lowercase().contains("compression"),
        "flag=2+length=0 must reject as protocol error; got {err_str}",
    );
    // Pin (e): the bad-flag frame's bytes are consumed so the
    // next decode call doesn't loop. With length=0, that's
    // exactly 5 header bytes consumed.
    assert_eq!(
        buf.len(),
        0,
        "consume-then-Err: even an empty bad-flag frame consumes its 5 \
         header bytes",
    );
}

#[test]
fn decode_invalid_flag_high_byte_with_zero_length_rejects() {
    // Pin (d) extension: flag=0xFF (clearly out of spec) with
    // length=0 must reject. Documents that the decoder isn't
    // doing a `flag != 0` truthy check (which would treat 0xFF
    // as "compressed").
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let frame = lpm_frame(0xFF, 0, b"");
    let mut buf = BytesMut::from(&frame[..]);

    codec
        .decode(&mut buf)
        .expect_err("flag=0xFF must reject");
    assert_eq!(buf.len(), 0, "consume-then-Err");
}

#[test]
fn empty_compressed_frame_in_stream_does_not_block_subsequent() {
    // Pin (a)+(c): a stream with an empty-compressed-frame
    // followed by a normal frame decodes both. The empty frame
    // must not leave the buffer in a state that blocks
    // subsequent decodes.
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let mut wire = BytesMut::new();

    // Frame 1: empty compressed.
    codec
        .encode(GrpcMessage::compressed(Bytes::new()), &mut wire)
        .expect("encode empty compressed");
    // Frame 2: small uncompressed.
    codec
        .encode(GrpcMessage::new(Bytes::from_static(b"second")), &mut wire)
        .expect("encode second");

    // Decode frame 1.
    let msg1 = codec
        .decode(&mut wire)
        .expect("decode 1")
        .expect("frame 1 complete");
    assert!(msg1.compressed);
    assert_eq!(msg1.data.len(), 0);

    // Decode frame 2.
    let msg2 = codec
        .decode(&mut wire)
        .expect("decode 2")
        .expect("frame 2 complete");
    assert!(!msg2.compressed);
    assert_eq!(msg2.data.as_ref(), b"second");

    // Buffer is now empty.
    assert_eq!(wire.len(), 0);
}

#[test]
fn empty_uncompressed_frame_round_trips() {
    // Pin (b): symmetric — a `GrpcMessage::new(Bytes::new())`
    // round-trips with `compressed: false`.
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let mut wire = BytesMut::new();
    codec
        .encode(GrpcMessage::new(Bytes::new()), &mut wire)
        .expect("encode");
    assert_eq!(
        wire.as_ref(),
        &[0x00, 0x00, 0x00, 0x00, 0x00][..],
        "uncompressed empty: flag=0x00 + length=0",
    );
    let decoded = codec.decode(&mut wire).expect("decode").expect("complete");
    assert!(!decoded.compressed);
    assert_eq!(decoded.data.len(), 0);
}
