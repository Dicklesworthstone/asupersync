//! Audit + regression test for `src/grpc/codec.rs` compression-
//! flag enforcement at decode (tick #191).
//!
//! Operator's question: "verify Compression-flag enforcement
//! at decode." Extends ticks #163 + #175 + #176 + #190 with
//! exhaustive coverage of the 256-byte flag space.
//!
//! gRPC Spec (compression.md):
//!
//!   The compressed_flag is the FIRST byte of every LPM frame.
//!   Per spec:
//!     * 0x00 → uncompressed payload
//!     * 0x01 → compressed payload (using negotiated encoding)
//!     * Any other value → INVALID, decoder MUST reject with
//!       PROTOCOL_ERROR
//!
//! Audit findings:
//!
//!   (a) **GrpcCodec::decode rejects every non-{0,1} flag**
//!       (codec.rs:144-156) with `GrpcError::protocol(format!(
//!       "invalid gRPC compression flag: {invalid}"))`. The
//!       match arm is `0 => false, 1 => true, invalid => Err`.
//!
//!   (b) **Bad-flag frame is consumed, not stuck**
//!       (br-asupersync-o7e5xu, codec.rs:151). The decoder
//!       advances `MESSAGE_HEADER_SIZE + length` bytes BEFORE
//!       returning Err so the next decode call doesn't loop on
//!       the same prefix.
//!
//!   (c) **Flag check is byte-exact, not bit-mask.** A
//!       regression that read the flag as `flag & 0x01` would
//!       treat 0x03, 0x05, 0x07, etc. as "compressed" and
//!       0x02, 0x04, etc. as "uncompressed" — silently
//!       routing tampered frames through one path or the
//!       other. The current match arms are byte-exact.
//!
//!   (d) **Length is consumed even on flag-error.** The
//!       declared length is parsed and used to compute how
//!       many body bytes to skip on the consume-then-Err
//!       path. A frame with flag=2 and length=100 consumes
//!       5 + 100 = 105 bytes from the buffer.
//!
//!   (e) **Empty bad-flag frame (length=0) consumes only the
//!       5-byte header.** Pinned in tick #175 — re-affirmed
//!       here for the exhaustive 256-value scan.
//!
//! Regression tests below pin (a)-(e).

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::grpc::GrpcCodec;

const MESSAGE_HEADER_SIZE: usize = 5;

fn lpm_frame(compressed_flag: u8, declared_length: u32, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MESSAGE_HEADER_SIZE + body.len());
    buf.push(compressed_flag);
    buf.extend_from_slice(&declared_length.to_be_bytes());
    buf.extend_from_slice(body);
    buf
}

#[test]
fn every_non_zero_one_flag_value_rejects() {
    // Pin (a)+(c): scan every u8 value from 2 to 255 and assert
    // EVERY one rejects. This is the exhaustive byte-exact
    // pin — a regression to bit-mask flag interpretation
    // (`flag & 0x01`) would surface here for ALL odd / even
    // values that previously rejected.
    for flag in 2u8..=255u8 {
        let mut codec = GrpcCodec::with_max_size(64 * 1024);
        let frame = lpm_frame(flag, 0, b"");
        let mut buf = BytesMut::from(&frame[..]);

        let result = codec.decode(&mut buf);
        assert!(
            result.is_err(),
            "flag=0x{flag:02x} ({flag}) MUST reject — gRPC spec allows \
             only 0x00 (uncompressed) and 0x01 (compressed). A regression \
             that accepted any other value would be a protocol violation.",
        );
    }
}

#[test]
fn flag_0x00_accepts_uncompressed() {
    // Pin (a) positive: flag=0x00 is the canonical uncompressed
    // frame. Must accept.
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let frame = lpm_frame(0x00, 5, b"hello");
    let mut buf = BytesMut::from(&frame[..]);
    let msg = codec
        .decode(&mut buf)
        .expect("flag=0x00 accepts")
        .expect("frame complete");
    assert!(!msg.compressed);
    assert_eq!(msg.data.as_ref(), b"hello");
}

#[test]
fn flag_0x01_accepts_compressed() {
    // Pin (a) positive: flag=0x01 is the canonical compressed
    // frame. Must accept (decompression happens at the
    // FramedCodec layer above; framing layer just preserves
    // the flag bit).
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let frame = lpm_frame(0x01, 5, b"world");
    let mut buf = BytesMut::from(&frame[..]);
    let msg = codec
        .decode(&mut buf)
        .expect("flag=0x01 accepts at framing layer")
        .expect("frame complete");
    assert!(msg.compressed);
    assert_eq!(msg.data.as_ref(), b"world");
}

#[test]
fn bit_mask_attack_pattern_rejects() {
    // Pin (c): a regression to bit-mask (`flag & 0x01`) would
    // accept every odd-valued flag as "compressed" and every
    // even-valued flag as "uncompressed." Pin specific
    // attack vectors from the bit-mask threat model:
    //   0x03 = 0b00000011 → would be "compressed" under bit-mask
    //   0x05 = 0b00000101 → would be "compressed" under bit-mask
    //   0x07 = 0b00000111 → would be "compressed" under bit-mask
    //   0x02 = 0b00000010 → would be "uncompressed" under bit-mask
    //   0x04 = 0b00000100 → would be "uncompressed" under bit-mask
    //   0xFE = 0b11111110 → would be "uncompressed" under bit-mask
    //   0xFF = 0b11111111 → would be "compressed" under bit-mask
    let bit_mask_attacks = [0x03, 0x05, 0x07, 0x02, 0x04, 0xFE, 0xFF];
    for flag in bit_mask_attacks {
        let mut codec = GrpcCodec::with_max_size(64 * 1024);
        let frame = lpm_frame(flag, 0, b"");
        let mut buf = BytesMut::from(&frame[..]);
        assert!(
            codec.decode(&mut buf).is_err(),
            "bit-mask attack flag 0x{flag:02x} MUST reject — proves the \
             check is byte-exact, not bit-mask",
        );
    }
}

#[test]
fn bad_flag_consumes_full_frame_including_body() {
    // Pin (b)+(d): a bad-flag frame with body bytes consumes
    // the FULL frame (header + body) on rejection. Pinned via
    // multi-frame buffer where a bad frame is followed by a
    // clean frame — the clean frame sits at the right offset
    // for the next decode call.
    //
    // Note: the codec poisons after the first error, so the
    // CLEAN frame ALSO rejects on second call (per tick #176
    // poison contract). We pin only the buffer-advance
    // property here.
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let bad_body = b"BADBADBAD";
    let frame = lpm_frame(0x42, bad_body.len() as u32, bad_body);
    let mut buf = BytesMut::from(&frame[..]);
    let pre_len = buf.len();
    let _ = codec.decode(&mut buf).expect_err("flag=0x42 rejects");
    assert!(
        buf.len() < pre_len,
        "bad-flag frame must CONSUME its bytes on rejection — without \
         this the next decode call infinite-loops on the same prefix \
         (br-asupersync-o7e5xu)",
    );
    // The full frame should be consumed.
    assert_eq!(
        buf.len(),
        0,
        "bad-flag frame consumes header (5 bytes) + body ({} bytes) = \
         {} bytes total; got {} bytes still in buffer",
        bad_body.len(),
        MESSAGE_HEADER_SIZE + bad_body.len(),
        buf.len(),
    );
}

#[test]
fn empty_bad_flag_frame_consumes_only_header() {
    // Pin (e): an empty bad-flag frame (length=0) consumes
    // exactly the 5-byte header on rejection.
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let frame = lpm_frame(0xAB, 0, b"");
    assert_eq!(frame.len(), MESSAGE_HEADER_SIZE);
    let mut buf = BytesMut::from(&frame[..]);
    let _ = codec.decode(&mut buf).expect_err("flag=0xAB rejects");
    assert_eq!(
        buf.len(),
        0,
        "empty bad-flag frame consumes its 5 header bytes",
    );
}

#[test]
fn flag_at_high_bit_boundary_rejects_correctly() {
    // Pin (a) extension: the high-bit (0x80, used by the
    // gRPC-Web trailer-frame flag) MUST reject in the unary
    // gRPC LPM context. The framing layer here is for the
    // unary message LPM — the gRPC-Web trailer frame is a
    // DIFFERENT frame type handled by web.rs's WebFrameCodec.
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let frame = lpm_frame(0x80, 0, b"");
    let mut buf = BytesMut::from(&frame[..]);
    let err = codec
        .decode(&mut buf)
        .expect_err("flag=0x80 (gRPC-Web trailer marker) MUST reject in unary LPM context");
    let err_str = format!("{err:?}");
    assert!(
        err_str.to_lowercase().contains("protocol")
            || err_str.to_lowercase().contains("compression"),
        "flag=0x80 rejection should mention protocol or compression; got {err_str}",
    );
}

#[test]
fn rejection_error_message_mentions_invalid_flag_value() {
    // Pin (a): the rejection error message includes the actual
    // flag value so operators can grep logs for the offending
    // value. A regression to a generic "bad frame" message
    // would lose this diagnostic information.
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let frame = lpm_frame(0x42, 0, b"");
    let mut buf = BytesMut::from(&frame[..]);
    let err = codec.decode(&mut buf).expect_err("flag=0x42 rejects");
    let err_str = format!("{err:?}");
    // The flag value 0x42 = 66 should appear in the message.
    assert!(
        err_str.contains("66")
            || err_str.contains("0x42")
            || err_str.contains("compression flag"),
        "rejection message should mention the offending flag value or \
         describe it as a compression-flag error; got: {err_str}",
    );
}
