//! Audit + regression test for `src/grpc/codec.rs` length-prefix
//! bound enforcement (tick #163).
//!
//! Operator's question: "verify length-prefix bound BEFORE
//! allocation, no DoS via huge length."
//!
//! Audit findings:
//!
//!   (a) **Length-prefix size cap fires BEFORE allocation**
//!       (codec.rs:135 — `if length > self.max_decode_message_size
//!       { return Err(GrpcError::MessageTooLarge); }`). The check
//!       happens after parsing the 4-byte big-endian u32 length
//!       prefix and BEFORE any further reads from the buffer.
//!       A peer declaring Length=u32::MAX with any compression
//!       flag returns `MessageTooLarge` IMMEDIATELY without
//!       waiting for or allocating the body bytes.
//!
//!   (b) **Compressed AND uncompressed paths share the cap.**
//!       The check at codec.rs:135 is the SAME for both
//!       compressed-flag=0 and compressed-flag=1. A regression
//!       that gated only uncompressed frames would let a peer
//!       smuggle a 4 GiB-declared compressed frame (asupersync-
//!       6o5iax) — the comment at codec.rs:127-134 documents
//!       this defense rationale.
//!
//!   (c) **Need-more-bytes path doesn't pre-allocate.** When
//!       `src.len() < MESSAGE_HEADER_SIZE.saturating_add(length)`
//!       (codec.rs:140) the decoder returns `Ok(None)` —
//!       waiting for the upstream buffer to fill. Critically
//!       this check happens AFTER the size cap (line 135), so
//!       a bad-length frame is rejected before need-more-bytes
//!       can balloon the upstream buffer.
//!
//!   (d) **`saturating_add` on `MESSAGE_HEADER_SIZE + length`**
//!       (codec.rs:140) cannot overflow even if the size cap
//!       were ever bypassed — defense-in-depth against integer
//!       overflow class (saturating_add caps at usize::MAX).
//!
//!   (e) **Bad compression flag triggers consume-then-Err**
//!       (codec.rs:147-156). The decoder consumes the bad
//!       frame's bytes BEFORE returning Err so the next
//!       `decode` call doesn't infinite-loop on the same
//!       prefix. Pinned at codec.rs:36-49 doc-comment
//!       (br-asupersync-o7e5xu).
//!
//! Regression tests below pin (a)-(e) at the public API surface.

use asupersync::bytes::{Bytes, BytesMut, BufMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::{GrpcCodec, GrpcMessage};

const MESSAGE_HEADER_SIZE: usize = 5;

/// Build a single LPM frame: 1 byte compressed flag + 4-byte BE
/// length + payload bytes.
fn lpm_frame(compressed_flag: u8, declared_length: u32, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MESSAGE_HEADER_SIZE + body.len());
    buf.push(compressed_flag);
    buf.extend_from_slice(&declared_length.to_be_bytes());
    buf.extend_from_slice(body);
    buf
}

#[test]
fn decode_rejects_huge_length_before_buffer_grows() {
    // Pin (a): a peer declares Length=u32::MAX with EMPTY body.
    // The decoder MUST reject with MessageTooLarge IMMEDIATELY
    // — without waiting for the buffer to reach 4 GiB.
    let mut codec = GrpcCodec::with_max_size(64 * 1024); // 64 KiB cap
    let frame = lpm_frame(0, u32::MAX, b""); // declared 4 GiB, actual 0 body
    let mut buf = BytesMut::from(&frame[..]);

    // First decode — header is present (5 bytes), length parsed,
    // size cap fires immediately.
    let result = codec.decode(&mut buf);
    let err = result.expect_err(
        "u32::MAX-declared length must reject IMMEDIATELY — \
         the size cap fires before need-more-bytes",
    );
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("MessageTooLarge") || err_str.to_lowercase().contains("too large"),
        "rejection must surface as MessageTooLarge; got {err_str}",
    );
}

#[test]
fn decode_rejects_huge_length_with_compressed_flag_set() {
    // Pin (b): the same cap applies to compressed frames. A
    // peer cannot bypass the size limit by setting flag=1 and
    // hoping the cap was decode-after-decompression-only.
    // (asupersync-6o5iax)
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let frame = lpm_frame(1, u32::MAX, b"");
    let mut buf = BytesMut::from(&frame[..]);

    let err = codec
        .decode(&mut buf)
        .expect_err("compressed-flag=1 must NOT bypass the size cap");
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("MessageTooLarge") || err_str.to_lowercase().contains("too large"),
        "compressed-flag=1 rejection must surface as MessageTooLarge; got {err_str}",
    );
}

#[test]
fn decode_size_cap_fires_strict_greater_than() {
    // Pin (a) boundary: the check is `length > max_decode_message_size`
    // (strict `>`). A frame at EXACTLY the cap succeeds. A regression
    // that flipped to `>=` would silently reject legitimate at-cap
    // payloads.
    let cap = 1024;
    let mut codec = GrpcCodec::with_max_size(cap);
    let body = vec![b'X'; cap];
    let frame = lpm_frame(0, cap as u32, &body);
    let mut buf = BytesMut::from(&frame[..]);

    let msg = codec
        .decode(&mut buf)
        .expect("at-cap decode must succeed")
        .expect("frame is complete");
    assert_eq!(msg.data.len(), cap);
    assert!(!msg.compressed);
}

#[test]
fn decode_size_cap_rejects_one_byte_over() {
    // Pin (a) boundary: a frame whose declared length is
    // `cap + 1` is rejected.
    let cap = 1024;
    let mut codec = GrpcCodec::with_max_size(cap);
    // Buffer carries the full body bytes but the declared
    // length exceeds cap by 1.
    let body = vec![b'Y'; cap + 1];
    let frame = lpm_frame(0, (cap + 1) as u32, &body);
    let mut buf = BytesMut::from(&frame[..]);

    let err = codec
        .decode(&mut buf)
        .expect_err("cap+1 must reject");
    let err_str = format!("{err:?}");
    assert!(err_str.contains("MessageTooLarge") || err_str.to_lowercase().contains("too large"));
}

#[test]
fn decode_with_partial_buffer_returns_need_more_bytes_only_under_cap() {
    // Pin (c): when the declared length is UNDER cap but the
    // buffer doesn't yet have all the body bytes, the decoder
    // returns Ok(None) (need-more-bytes). Importantly, the
    // size-cap check has ALREADY fired — so this Ok(None) only
    // happens for frames that WILL fit. A regression that
    // flipped the check order would let a huge-length frame
    // sit in the buffer indefinitely waiting for body bytes
    // that should have been rejected.
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    // Declare 100 bytes, deliver only 30 bytes of body.
    let mut buf = BytesMut::new();
    buf.put_u8(0); // compressed flag
    buf.put_u32(100); // declared length
    buf.put_slice(&[b'A'; 30]); // partial body

    let result = codec.decode(&mut buf);
    match result {
        Ok(None) => {} // need-more-bytes — correct under-cap path
        other => panic!(
            "under-cap partial frame must return Ok(None) (need more bytes); got {other:?}",
        ),
    }
    // The buffer is unchanged — partial-frame state preserved
    // for the next decode call.
    assert_eq!(buf.len(), MESSAGE_HEADER_SIZE + 30);
}

#[test]
fn decode_partial_buffer_with_oversize_length_rejects_immediately() {
    // Pin (a)+(c) interaction: even with a partial buffer (no
    // body bytes yet), an OVERSIZE declared length is rejected
    // IMMEDIATELY without waiting for the body. This is the
    // critical anti-DoS property — the upstream HTTP/2 buffer
    // CANNOT be coerced to grow toward the declared length.
    let mut codec = GrpcCodec::with_max_size(1024);
    let mut buf = BytesMut::new();
    buf.put_u8(0);
    buf.put_u32(u32::MAX); // declared 4 GiB
    // No body bytes at all.

    let err = codec
        .decode(&mut buf)
        .expect_err("oversize declared length must reject without body");
    let err_str = format!("{err:?}");
    assert!(err_str.contains("MessageTooLarge") || err_str.to_lowercase().contains("too large"));
}

#[test]
fn decode_after_oversize_does_not_infinite_loop_on_same_prefix() {
    // Pin (e) for oversize: after the decoder rejects an
    // oversize-declared frame, the buffer position state must
    // not cause an infinite loop. We verify by re-calling
    // decode on the same buffer — the error continues
    // (or buffer is consumed, both are acceptable). What MUST
    // NOT happen: a panic, OR an infinite Ok(Some) loop on
    // the same prefix.
    let mut codec = GrpcCodec::with_max_size(1024);
    let mut buf = BytesMut::new();
    buf.put_u8(0);
    buf.put_u32(u32::MAX);

    let _ = codec.decode(&mut buf); // first call: Err
    let pre_len = buf.len();
    let second = codec.decode(&mut buf); // second call: must not panic
    // Buffer must NOT have grown.
    assert!(
        buf.len() <= pre_len,
        "second decode must not increase buffer size",
    );
    // Second call result is acceptable as Err OR Ok(None) —
    // both are bounded.
    match second {
        Err(_) | Ok(None) => {}
        Ok(Some(_)) => panic!("second decode unexpectedly produced a frame"),
    }
}

#[test]
fn bad_compression_flag_consumes_frame_then_errs() {
    // Pin (e): a frame with flag=2 (or anything outside {0,1})
    // is rejected with `GrpcError::protocol(...)` AND the
    // decoder consumes the bad frame's bytes so the next
    // decode call doesn't loop on the same prefix
    // (br-asupersync-o7e5xu).
    let mut codec = GrpcCodec::with_max_size(64 * 1024);
    let body = vec![b'Z'; 32];
    let frame = lpm_frame(2, 32, &body); // flag=2 invalid
    let mut buf = BytesMut::from(&frame[..]);

    let err = codec
        .decode(&mut buf)
        .expect_err("flag=2 must surface as protocol error");
    let err_str = format!("{err:?}");
    assert!(
        err_str.to_lowercase().contains("protocol")
            || err_str.to_lowercase().contains("compression"),
        "expected protocol-error / compression-flag complaint; got {err_str}",
    );
    // Critically, the bad frame's bytes have been CONSUMED so
    // the next decode call sees an empty buffer.
    assert_eq!(
        buf.len(),
        0,
        "consume-then-Err: bad frame's bytes must be consumed so the \
         next decode call doesn't infinite-loop on the same prefix",
    );
}

#[test]
fn decode_round_trip_preserves_data_under_cap() {
    // Sanity: the encoder + decoder agree on bytes for a
    // legitimate under-cap payload. This is the happy-path pin
    // that ensures the DoS-defense changes haven't broken
    // normal operation.
    let mut codec = GrpcCodec::with_max_size(8 * 1024);
    let body = b"hello round trip";
    let mut wire = BytesMut::new();
    codec
        .encode(GrpcMessage::new(Bytes::from_static(body)), &mut wire)
        .expect("encode OK");

    let msg = codec
        .decode(&mut wire)
        .expect("decode Ok")
        .expect("frame complete");
    assert_eq!(msg.data.as_ref(), body);
    assert!(!msg.compressed);
    assert!(wire.is_empty(), "decoder consumed all bytes");
}
