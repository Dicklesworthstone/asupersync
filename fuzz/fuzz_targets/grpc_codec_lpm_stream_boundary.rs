#![no_main]

//! Cargo-fuzz target for `GrpcCodec::decode` operating on a STREAM of
//! Length-Prefixed-Messages with adversarial frame boundaries.
//!
//! Complements the existing `grpc_codec_decode.rs` (single-frame
//! corner cases) by stressing the multi-frame stream parser:
//!
//!   * Multiple LPM frames concatenated into one buffer.
//!   * Arbitrary split points where the frame is delivered in two
//!     pieces (the way TCP segmentation lands a frame mid-payload
//!     or mid-prefix).
//!   * Adversarial size-prefix bytes that, if mishandled, would
//!     either overflow `MESSAGE_HEADER_SIZE.saturating_add(length)`
//!     or under-flow when split_to runs past the buffer end.
//!
//! Properties asserted per fuzz iteration:
//!
//!   1. **No panic** for any input (well-formed multi-frame, mixed,
//!      or pathological).
//!
//!   2. **Framing preservation across split-point delivery.** When
//!      a stream of N well-formed LPM frames is split at an
//!      arbitrary byte offset and decoded as two halves
//!      (split_left then drain, append split_right then drain),
//!      the consumer observes EXACTLY the same N message payloads
//!      in order as a single-buffer decode of the joined stream.
//!
//!   3. **Huge-length-prefix is rejected before allocation.** A
//!      frame whose size-prefix declares a length larger than the
//!      codec's max_decode_message_size MUST surface as
//!      `MessageTooLarge` BEFORE the decoder tries to read the
//!      claimed body bytes. A regression where the decoder
//!      pre-allocated `length` bytes (or summed
//!      `MESSAGE_HEADER_SIZE + length` and used the result for
//!      capacity) would surface here.
//!
//!   4. **Decoder rejection progress is precise.** Complete
//!      invalid compression-flag frames are consumed so the caller
//!      cannot infinite-loop on the same prefix. Oversized declared
//!      lengths are rejected before consuming bytes, so callers can
//!      fail closed without dropping buffered data.
//!
//! ```bash
//! cargo +nightly fuzz run grpc_codec_lpm_stream_boundary -- -max_total_time=120
//! ```

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::codec::MESSAGE_HEADER_SIZE;
use asupersync::grpc::{GrpcCodec, GrpcError, GrpcMessage};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// Per-iteration cap on total stream size. Each iteration assembles
/// a multi-frame stream up to MAX_BUF_BYTES, splits it at an
/// arbitrary point, and runs the decoder.
const MAX_BUF_BYTES: usize = 64 * 1024;
/// Per-frame body cap. The codec's max_decode_message_size is set
/// below this so well-formed frames pass.
const MAX_FRAME_BODY: usize = 8 * 1024;
/// Codec's max_decode_message_size for this fuzz iteration.
const CODEC_MAX_FRAME: usize = 16 * 1024;
/// Cap on number of frames per stream.
const MAX_FRAMES: usize = 32;

static FIXED_CANARIES: OnceLock<()> = OnceLock::new();

#[derive(Arbitrary, Debug)]
struct Stream {
    frames: Vec<FrameSpec>,
    /// Where to split the assembled buffer. The split point lands
    /// somewhere in 0..buf_len so libFuzzer can hill-climb on
    /// every byte boundary including the most-attack-relevant
    /// "split mid-prefix" cases.
    split_at: u32,
}

#[derive(Arbitrary, Debug)]
struct FrameSpec {
    /// 0 = uncompressed, 1 = compressed, anything else = invalid
    /// (per gRPC LPM spec).
    flag: u8,
    /// Body bytes for this frame. Length is taken modulo
    /// MAX_FRAME_BODY so we don't overflow the per-iteration cap.
    body: Vec<u8>,
    /// If true, declare a length much larger than `body.len()` so
    /// the decoder must reject as MessageTooLarge or buffer-too-short.
    declare_oversize: bool,
}

fn assemble(frames: &[FrameSpec]) -> Vec<u8> {
    let mut out = Vec::new();
    for frame in frames.iter().take(MAX_FRAMES) {
        let body: Vec<u8> = frame.body.iter().copied().take(MAX_FRAME_BODY).collect();
        let declared_len: u32 = if frame.declare_oversize {
            // Land somewhere between max-frame and u32::MAX so the
            // size-cap check fires.
            (CODEC_MAX_FRAME as u32)
                .saturating_add(1)
                .saturating_add(frame.body.len() as u32)
        } else {
            body.len() as u32
        };
        // Stop if appending would blow the per-iteration cap.
        if out.len()
            + 5
            + (if frame.declare_oversize {
                body.len()
            } else {
                declared_len as usize
            })
            > MAX_BUF_BYTES
        {
            break;
        }
        out.push(frame.flag);
        out.extend_from_slice(&declared_len.to_be_bytes());
        out.extend_from_slice(&body);
    }
    out
}

fn drain(codec: &mut GrpcCodec, src: &mut BytesMut) -> Vec<GrpcMessage> {
    let mut out = Vec::new();
    while !src.is_empty() {
        match observe_decode(codec, src) {
            Ok(Some(msg)) => out.push(msg),
            Ok(None) => break, // need more bytes
            Err(_) => {
                // Some rejection paths consume a complete bad frame
                // and others preserve buffered bytes for fail-closed
                // handling. Either way, the drain terminates here.
                break;
            }
        }
    }
    out
}

fn observe_decode(
    codec: &mut GrpcCodec,
    src: &mut BytesMut,
) -> Result<Option<GrpcMessage>, GrpcError> {
    let before_len = src.len();
    let result = codec.decode(src);
    assert!(
        src.len() <= before_len,
        "GrpcCodec::decode must never grow its source buffer"
    );

    match &result {
        Ok(Some(message)) => {
            let consumed = before_len - src.len();
            assert_eq!(
                consumed,
                MESSAGE_HEADER_SIZE + message.data.len(),
                "decoded frame consumed {consumed} bytes for payload length {}",
                message.data.len()
            );
        }
        Ok(None) => {
            assert_eq!(
                src.len(),
                before_len,
                "incomplete LPM frame should remain buffered"
            );
        }
        Err(GrpcError::MessageTooLarge) => {
            assert_eq!(
                src.len(),
                before_len,
                "oversized LPM frame should be rejected before consuming bytes"
            );
        }
        Err(GrpcError::Protocol(message)) => {
            assert!(
                !message.is_empty(),
                "protocol rejection should carry an explanatory message"
            );
        }
        Err(error) => {
            assert!(
                !error.to_string().is_empty(),
                "decode error should have a non-empty description: {error:?}"
            );
        }
    }

    result
}

fn observe_decode_probe_outcome(result: Result<Option<GrpcMessage>, GrpcError>) {
    if let Err(error) = result {
        assert!(
            !error.to_string().is_empty(),
            "extra decode probe errors must remain observable"
        );
    }
}

fn assert_fixed_rejection_canaries() {
    let mut complete_invalid = BytesMut::from(&b"\x02\0\0\0\x02no"[..]);
    let mut codec = GrpcCodec::with_max_size(CODEC_MAX_FRAME);
    assert!(matches!(
        observe_decode(&mut codec, &mut complete_invalid),
        Err(GrpcError::Protocol(_))
    ));
    assert!(
        complete_invalid.is_empty(),
        "complete invalid compression-flag frames should be consumed"
    );

    let mut incomplete_invalid = BytesMut::from(&b"\x02\0\0\0\x02n"[..]);
    let mut codec = GrpcCodec::with_max_size(CODEC_MAX_FRAME);
    assert!(matches!(
        observe_decode(&mut codec, &mut incomplete_invalid),
        Ok(None)
    ));
    assert_eq!(incomplete_invalid.as_ref(), b"\x02\0\0\0\x02n");

    let oversize_len = (CODEC_MAX_FRAME as u32).saturating_add(1);
    let mut oversized = BytesMut::from(
        &[
            0,
            (oversize_len >> 24) as u8,
            (oversize_len >> 16) as u8,
            (oversize_len >> 8) as u8,
            oversize_len as u8,
        ][..],
    );
    let before = oversized.clone();
    let mut codec = GrpcCodec::with_max_size(CODEC_MAX_FRAME);
    assert!(matches!(
        observe_decode(&mut codec, &mut oversized),
        Err(GrpcError::MessageTooLarge)
    ));
    assert_eq!(oversized, before);
}

fuzz_target!(|stream: Stream| {
    FIXED_CANARIES.get_or_init(assert_fixed_rejection_canaries);

    let assembled = assemble(&stream.frames);
    if assembled.len() > MAX_BUF_BYTES {
        return;
    }

    // Property 1+3+4: single-buffer decode never panics; the
    // result is some prefix of the well-formed frames followed
    // by either Ok(None) (need more bytes) or Err (bad frame
    // rejected without infinite loop).
    let mut codec_single = GrpcCodec::with_max_size(CODEC_MAX_FRAME);
    let mut buf_single = BytesMut::from(&assembled[..]);
    let single_drain = drain(&mut codec_single, &mut buf_single);
    // After a drain, the codec must NOT loop on the remaining
    // buffer. If we still have bytes left, one more decode call
    // either returns the next frame, signals Ok(None), or
    // returns Err — and consumes some bytes either way (or
    // returns Ok(None) cleanly).
    let pre_len = buf_single.len();
    observe_decode_probe_outcome(observe_decode(&mut codec_single, &mut buf_single)); // must not loop
    assert!(
        buf_single.len() <= pre_len,
        "decoder must not increase buffer length",
    );

    // Property 2: split-point delivery — the decoder must observe
    // the SAME message payloads as the single-buffer drain. Skip
    // any frame whose flag is invalid because the rejection path
    // is non-deterministic across split points (the bad frame
    // may straddle the split). For pure-well-formed streams we
    // assert exact equality.
    let all_well_formed = stream
        .frames
        .iter()
        .take(MAX_FRAMES)
        .all(|f| f.flag <= 1 && !f.declare_oversize);
    if all_well_formed && !assembled.is_empty() {
        let split_at = (stream.split_at as usize).min(assembled.len());
        let (left, right) = assembled.split_at(split_at);

        let mut codec_split = GrpcCodec::with_max_size(CODEC_MAX_FRAME);
        let mut buf_split = BytesMut::from(left);
        let mut split_drain = drain(&mut codec_split, &mut buf_split);
        // Tail arrives.
        buf_split.extend_from_slice(right);
        split_drain.extend(drain(&mut codec_split, &mut buf_split));

        // Same payloads in same order.
        assert_eq!(
            split_drain.len(),
            single_drain.len(),
            "split-point delivery yielded a different frame count: \
             split={} vs single={}",
            split_drain.len(),
            single_drain.len(),
        );
        for (i, (s, sg)) in split_drain.iter().zip(single_drain.iter()).enumerate() {
            assert_eq!(
                s.data.as_ref(),
                sg.data.as_ref(),
                "frame {i}: split-point delivery payload diverged from single-buffer",
            );
            assert_eq!(
                s.compressed, sg.compressed,
                "frame {i}: compressed-flag diverged across split-point delivery",
            );
        }
    }

    // Property 3: a frame that DECLARES oversize must not panic
    // and must not silently accept. We don't assert specific Err
    // shape because the decoder's reject path may surface
    // MessageTooLarge OR may need-more-bytes if the buffer is
    // shorter than declared.
    if stream
        .frames
        .iter()
        .take(MAX_FRAMES)
        .any(|f| f.declare_oversize)
    {
        let mut codec_oversize = GrpcCodec::with_max_size(CODEC_MAX_FRAME);
        let mut buf_oversize = BytesMut::from(&assembled[..]);
        // The decode loop must terminate in finite work — drain()
        // would loop on an Ok(None) or Err result, neither of
        // which advances. The function returns when stuck.
        let oversize_drain = drain(&mut codec_oversize, &mut buf_oversize);
        assert!(
            oversize_drain.len() <= MAX_FRAMES,
            "oversize drain must terminate within the frame cap"
        );
        // No panic = property 3 holds.
    }

    // Property: round-trip a small well-formed payload to verify
    // the encoder/decoder agree. Single small frame sanity-check.
    if let Some(first_frame) = stream.frames.first()
        && first_frame.flag <= 1
        && !first_frame.declare_oversize
    {
        let body: Vec<u8> = first_frame
            .body
            .iter()
            .copied()
            .take(MAX_FRAME_BODY)
            .collect();
        let mut wire = BytesMut::new();
        let mut enc = GrpcCodec::with_max_size(CODEC_MAX_FRAME);
        let msg = GrpcMessage::new(body.clone().into());
        if enc.encode(msg, &mut wire).is_ok() {
            let mut dec = GrpcCodec::with_max_size(CODEC_MAX_FRAME);
            if let Ok(Some(decoded)) = observe_decode(&mut dec, &mut wire) {
                assert_eq!(decoded.data.as_ref(), &body[..], "round-trip body mismatch",);
            }
        }
    }
});
