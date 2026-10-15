//! Fuzz target for `asupersync::grpc::codec::GrpcCodec::decode`.
//!
//! gRPC frame format (Length-Prefixed Message, LPM):
//!     1 byte     compressed flag (0 = uncompressed, 1 = compressed,
//!                                 anything else = COMPRESSION_ERROR)
//!     4 bytes    big-endian u32 message length L
//!     L bytes    message payload
//!
//! This target is structure-aware: a 5-arm enum (`Scenario`) drives the
//! decoder through the corner cases the bead requested:
//!   1. RandomBytes: arbitrary input for dispatch and all-zero/all-ones edges.
//!   2. LengthPrefixOverflow: length near `u32::MAX` to exercise cast and
//!      `saturating_add(MESSAGE_HEADER_SIZE)` rim behavior.
//!   3. CompressedFlagMismatch: every compression-flag byte, including the
//!      legal `{0, 1}` values and the protocol-error path.
//!   4. ZeroLengthMessage: length=0 must yield an empty message, not `None`.
//!   5. SizeLimitEnforcement: length straddles `max_decode_message_size`.
//!
//! Decoder outcomes are contract-checked at the framing boundary:
//! `Ok(Some)` must preserve the compressed flag, payload length, and
//! consumption amount; `Ok(None)` is only legal for incomplete in-cap frames;
//! `Err(MessageTooLarge)` is required for over-cap lengths; and invalid
//! compression flags must be consumed as protocol errors.
//!
//! ```bash
//! cargo +nightly fuzz run grpc_codec_decode -- -max_total_time=120
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::grpc::codec::{GrpcCodec, MESSAGE_HEADER_SIZE};
use asupersync::grpc::{Code, GrpcError};
use libfuzzer_sys::fuzz_target;

/// Hard cap on the buffer we hand to the decoder. The decoder itself caps
/// per-message via `max_decode_message_size` but we still need an outer
/// guard so a fuzz seed can't ask for a 4 GiB allocation.
const MAX_BUF_BYTES: usize = 1 << 20; // 1 MiB

/// Bound on the codec's own size limit. We deliberately keep this small
/// so SizeLimitEnforcement scenarios actually exercise the
/// MessageTooLarge path on realistic seed sizes.
const MAX_CODEC_LIMIT: usize = 64 * 1024;

#[derive(Arbitrary, Debug)]
enum Scenario {
    /// Vector 1: arbitrary bytes. Tests dispatch + buffer-too-small +
    /// invalid-flag + multi-frame parse loops in one bucket.
    RandomBytes(Vec<u8>),
    /// Vector 2: length prefix near or past u32::MAX. Forces the
    /// `as usize` cast and the saturating header addition through their
    /// edge cases on 64-bit targets.
    LengthPrefixOverflow {
        /// Bumps the advertised length: we pick u32::MAX - bump as the
        /// header value so seeds drive the rim from both sides.
        bump: u32,
        compressed_flag: u8,
        /// Payload bytes appended after the 5-byte header. Truncated to
        /// MAX_BUF_BYTES.
        payload: Vec<u8>,
        /// If true, also append a second frame after this one to test
        /// the "decoder consumed the wrong amount" failure mode (would
        /// surface as a misframed second decode).
        chain_second_frame: bool,
    },
    /// Vector 3: every legal + illegal compression flag. The decoder
    /// MUST accept 0 and 1 only; any other byte must be a
    /// COMPRESSION_ERROR (Err), never a panic, never silently treated
    /// as 0 or 1.
    CompressedFlagMismatch {
        flag: u8,
        length: u16,
        payload: Vec<u8>,
    },
    /// Vector 4: header with length=0. The decoder MUST return
    /// Some(GrpcMessage{ data: Bytes::new(), .. }) — NOT None (would
    /// stall the framer) and NOT Err.
    ZeroLengthMessage { compressed: bool },
    /// Vector 5: message length straddles the configured cap.
    /// `length_offset` is added to the cap so the seed sweeps just-below,
    /// at, and just-above the boundary.
    SizeLimitEnforcement {
        cap: u16,
        length_offset: i32,
        compressed: bool,
        payload: Vec<u8>,
    },
}

fuzz_target!(|s: Scenario| {
    assert_known_decode_outcomes();

    match s {
        Scenario::RandomBytes(buf) => fuzz_random_bytes(&buf),
        Scenario::LengthPrefixOverflow {
            bump,
            compressed_flag,
            payload,
            chain_second_frame,
        } => fuzz_length_prefix_overflow(bump, compressed_flag, &payload, chain_second_frame),
        Scenario::CompressedFlagMismatch {
            flag,
            length,
            payload,
        } => fuzz_compressed_flag_mismatch(flag, length, &payload),
        Scenario::ZeroLengthMessage { compressed } => fuzz_zero_length_message(compressed),
        Scenario::SizeLimitEnforcement {
            cap,
            length_offset,
            compressed,
            payload,
        } => fuzz_size_limit_enforcement(cap, length_offset, compressed, &payload),
    }
});

fn assert_known_decode_outcomes() {
    let mut empty = frame(0, b"");
    assert_decode_contract(&mut GrpcCodec::with_max_size(4), &mut empty, 0, 0);

    let mut compressed_empty = frame(1, b"");
    assert_decode_contract(
        &mut GrpcCodec::with_max_size(4),
        &mut compressed_empty,
        1,
        0,
    );

    let mut exact_cap = frame(0, b"1234");
    assert_decode_contract(&mut GrpcCodec::with_max_size(4), &mut exact_cap, 0, 4);

    let mut over_cap = frame(0, b"12345");
    assert_decode_contract(&mut GrpcCodec::with_max_size(4), &mut over_cap, 0, 5);

    let mut invalid_then_valid = frame(7, b"z");
    invalid_then_valid.extend_from_slice(&frame(0, b"ok"));
    assert_decode_contract(
        &mut GrpcCodec::with_max_size(8),
        &mut invalid_then_valid,
        7,
        1,
    );
    assert_decode_contract(
        &mut GrpcCodec::with_max_size(8),
        &mut invalid_then_valid,
        0,
        2,
    );

    let mut truncated = BytesMut::new();
    truncated.extend_from_slice(&[0, 0, 0, 0, 3, b'a', b'b']);
    assert_decode_contract(&mut GrpcCodec::with_max_size(8), &mut truncated, 0, 3);
}

fn frame(flag: u8, payload: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(MESSAGE_HEADER_SIZE + payload.len());
    buf.extend_from_slice(&[flag]);
    let advertised_len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&advertised_len.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

fn assert_decode_contract(
    codec: &mut GrpcCodec,
    buf: &mut BytesMut,
    flag: u8,
    advertised_len: usize,
) {
    let before_len = buf.len();
    let available_payload_len = before_len.saturating_sub(MESSAGE_HEADER_SIZE);
    let max_decode_size = codec.max_decode_message_size();
    let result = codec.decode(buf);

    if advertised_len > max_decode_size {
        let err = match result {
            Err(err) => err,
            Ok(result) => {
                panic!(
                    "over-cap gRPC frame length {advertised_len} must reject with MessageTooLarge; got {result:?}"
                )
            }
        };
        assert_message_too_large_status(err);
        assert_eq!(
            buf.len(),
            before_len,
            "over-cap gRPC frame must reject before consuming buffered bytes"
        );
        return;
    }

    if available_payload_len < advertised_len {
        assert!(
            matches!(&result, Ok(None)),
            "incomplete in-cap gRPC frame length {advertised_len} with {available_payload_len} bytes must wait; got {result:?}"
        );
        assert_eq!(
            buf.len(),
            before_len,
            "incomplete gRPC frame must remain buffered"
        );
        return;
    }

    let expected_remaining = before_len - MESSAGE_HEADER_SIZE - advertised_len;
    match flag {
        0 | 1 => {
            let message = match result {
                Ok(Some(message)) => message,
                other => panic!(
                    "complete valid gRPC frame flag={flag} len={advertised_len} must decode; got {other:?}"
                ),
            };
            assert_eq!(
                message.compressed,
                flag == 1,
                "decoded compressed flag must mirror the frame header"
            );
            assert_eq!(
                message.data.len(),
                advertised_len,
                "decoded payload length must match the advertised length"
            );
            assert_eq!(
                buf.len(),
                expected_remaining,
                "complete valid gRPC frame must consume exactly header + payload"
            );
        }
        _ => {
            let err = match result {
                Err(err) => err,
                Ok(result) => {
                    panic!(
                        "invalid gRPC compression flag {flag} must reject as Protocol; got {result:?}"
                    )
                }
            };
            assert_invalid_compression_flag_status(err, flag);
            assert_eq!(
                buf.len(),
                expected_remaining,
                "invalid complete gRPC frame must consume only the malformed frame"
            );
        }
    }
}

fn assert_message_too_large_status(error: GrpcError) {
    assert!(
        matches!(&error, GrpcError::MessageTooLarge),
        "expected MessageTooLarge, got {error:?}"
    );
    assert_eq!(
        error.to_string(),
        "message too large",
        "MessageTooLarge display changed"
    );
    let status = error.into_status();
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(
        status.message(),
        "message too large",
        "MessageTooLarge status message changed"
    );
}

fn assert_invalid_compression_flag_status(error: GrpcError, flag: u8) {
    let expected_message = format!("invalid gRPC compression flag: {flag}");
    match &error {
        GrpcError::Protocol(message) => {
            assert_eq!(
                message, &expected_message,
                "invalid compression flag protocol message changed"
            );
        }
        other => panic!("expected invalid compression flag Protocol error, got {other:?}"),
    }

    let expected_display = format!("protocol error: {expected_message}");
    assert_eq!(
        error.to_string(),
        expected_display,
        "invalid compression flag display changed"
    );
    let status = error.into_status();
    assert_eq!(status.code(), Code::Internal);
    assert_eq!(
        status.message(),
        expected_display,
        "invalid compression flag status message changed"
    );
}

// =========================================================================
// Vector 1: random byte stream
// =========================================================================

fn fuzz_random_bytes(input: &[u8]) {
    if input.len() > MAX_BUF_BYTES {
        return;
    }
    let mut codec = GrpcCodec::new();
    let mut buf = BytesMut::from(input);
    // Drain the buffer in a loop — a real codec consumer calls decode in
    // a loop until it returns Ok(None) or Err. Each iteration must
    // either produce a frame, return Ok(None) (need more bytes), or
    // surface an Err. Crashes / hangs / panics are the only findings.
    let mut iterations = 0;
    while iterations < 64 {
        iterations += 1;
        match codec.decode(&mut buf) {
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => break,
        }
    }
}

// =========================================================================
// Vector 2: length-prefix overflow
// =========================================================================

fn fuzz_length_prefix_overflow(
    bump: u32,
    compressed_flag: u8,
    payload: &[u8],
    chain_second_frame: bool,
) {
    // Pick an advertised length near u32::MAX. saturating_sub keeps the
    // value within u32 range; the decoder's `length as usize +
    // MESSAGE_HEADER_SIZE` then sits at the 64-bit rim.
    let advertised_len = u32::MAX.saturating_sub(bump);
    let mut buf = Vec::with_capacity(MESSAGE_HEADER_SIZE + payload.len() + 5);
    buf.push(compressed_flag);
    buf.extend_from_slice(&advertised_len.to_be_bytes());
    let take = payload
        .len()
        .min(MAX_BUF_BYTES.saturating_sub(MESSAGE_HEADER_SIZE));
    buf.extend_from_slice(&payload[..take]);

    if chain_second_frame {
        // A trailing well-formed frame so a "decoder consumed wrong N
        // bytes" bug surfaces as a misframed second decode.
        buf.push(0);
        buf.extend_from_slice(&3_u32.to_be_bytes());
        buf.extend_from_slice(b"abc");
    }

    let mut codec = GrpcCodec::new();
    let mut bm = BytesMut::from(buf.as_slice());
    let advertised_len = usize::try_from(advertised_len).unwrap_or(usize::MAX);
    assert_decode_contract(&mut codec, &mut bm, compressed_flag, advertised_len);
}

// =========================================================================
// Vector 3: compression-flag mismatch (every byte value)
// =========================================================================

fn fuzz_compressed_flag_mismatch(flag: u8, length: u16, payload: &[u8]) {
    let len = length as usize;
    let mut buf = Vec::with_capacity(MESSAGE_HEADER_SIZE + len);
    buf.push(flag);
    buf.extend_from_slice(&u32::from(length).to_be_bytes());
    let take = payload.len().min(len);
    buf.extend_from_slice(&payload[..take]);
    // Pad with zeros if the payload was shorter than the advertised
    // length so the decoder sees a well-framed message.
    buf.resize(MESSAGE_HEADER_SIZE + len, 0);

    let mut codec = GrpcCodec::new();
    let mut bm = BytesMut::from(buf.as_slice());
    assert_decode_contract(&mut codec, &mut bm, flag, len);
}

// =========================================================================
// Vector 4: zero-length message
// =========================================================================

fn fuzz_zero_length_message(compressed: bool) {
    let mut buf = Vec::with_capacity(MESSAGE_HEADER_SIZE);
    buf.push(u8::from(compressed));
    buf.extend_from_slice(&0_u32.to_be_bytes());
    let mut codec = GrpcCodec::new();
    let mut bm = BytesMut::from(buf.as_slice());
    assert_decode_contract(&mut codec, &mut bm, u8::from(compressed), 0);
}

// =========================================================================
// Vector 5: max-message-size cap enforcement
// =========================================================================

fn fuzz_size_limit_enforcement(cap: u16, length_offset: i32, compressed: bool, payload: &[u8]) {
    // Configure a small codec cap so the seed can sit just below / at /
    // above the boundary without needing megabytes of payload.
    let cap_usize = (cap as usize).clamp(1, MAX_CODEC_LIMIT);
    let mut codec = GrpcCodec::with_max_size(cap_usize);

    // Advertised length = cap + offset (with bounds clamping).
    let advertised: usize = (cap_usize as i64 + length_offset as i64)
        .max(0)
        .min(MAX_BUF_BYTES as i64) as usize;

    let mut buf = Vec::with_capacity(MESSAGE_HEADER_SIZE + advertised.min(payload.len()));
    buf.push(u8::from(compressed));
    let advertised_u32: u32 = u32::try_from(advertised).unwrap_or(u32::MAX);
    buf.extend_from_slice(&advertised_u32.to_be_bytes());
    let body_len = advertised.min(payload.len()).min(MAX_BUF_BYTES);
    buf.extend_from_slice(&payload[..body_len]);

    let mut bm = BytesMut::from(buf.as_slice());
    assert_decode_contract(&mut codec, &mut bm, u8::from(compressed), advertised);
}
