//! Regression test for `LengthDelimitedCodec` skip-recovery with a non-zero
//! `length_adjustment` (br-asupersync-o7e5xu).
//!
//! When a frame's adjusted length exceeds `max_frame_length`, the codec
//! consumes the header and drains the offending frame's body so it can
//! resynchronize on the following frame. The drain count must be the ADJUSTED
//! body length (raw length-field value + `length_adjustment`), not the raw
//! value: with a non-zero adjustment the two differ, and draining the raw value
//! leaves the stream desynchronized (the next frame is mis-parsed). Every
//! in-crate test uses `length_adjustment == 0`, so this path was untested.
//!
//! Runs as a standalone integration crate (reliable proof lane; the lib
//! unit-test target stalls on the conformance dev-dep).

use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, LengthDelimitedCodec};

#[test]
fn skip_recovery_drains_adjusted_body_then_parses_next_frame() {
    // Length field counts the payload only; the +2 adjustment accounts for the
    // 2-byte length field, so the body following the header is (raw + 2) bytes.
    let mut codec = LengthDelimitedCodec::builder()
        .length_field_length(2)
        .length_adjustment(2)
        .max_frame_length(4)
        .big_endian()
        .new_codec();

    let mut buf = BytesMut::new();
    // Frame 1 (oversized): raw length-field = 5 -> adjusted body = 7 bytes.
    buf.extend_from_slice(&[0x00, 0x05]);
    buf.extend_from_slice(b"OVERLNG"); // exactly 7 body bytes
    // Frame 2 (valid): raw length-field = 2 -> adjusted body = 4 bytes.
    buf.extend_from_slice(&[0x00, 0x02]);
    buf.extend_from_slice(b"GOOD"); // exactly 4 body bytes

    // First decode: the adjusted length (7) exceeds max_frame_length (4), so the
    // codec errors and arms its skip-drain over the 7-byte body.
    let first = codec.decode(&mut buf);
    assert!(
        first.is_err(),
        "oversized frame (adjusted len 7 > max 4) must error, got {first:?}"
    );

    // Second decode: the codec must have drained exactly the 7-byte body, so the
    // next frame parses cleanly. With the raw-length bug it would drain only 5
    // bytes, leaving 2 stray body bytes that get mis-parsed as a bogus header.
    let second = codec
        .decode(&mut buf)
        .expect("decode after skip-recovery must not error on the valid following frame");
    let frame = second.expect("a complete, correctly-framed second frame");
    assert_eq!(
        frame,
        BytesMut::from(&b"GOOD"[..]),
        "post-recovery frame must be the real next frame, not desynchronized garbage"
    );
}
