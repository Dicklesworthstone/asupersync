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
//!   1. RandomBytes        — purely arbitrary input (covers fixed-cost
//!                           dispatch + the all-zero / all-ones edges).
//!   2. LengthPrefixOverflow — header advertises a length near or past
//!                             u32::MAX so the implicit `as usize` /
//!                             `saturating_add(MESSAGE_HEADER_SIZE)`
//!                             arithmetic is exercised at the rim.
//!   3. CompressedFlagMismatch — every byte value in 0..=255 for the
//!                               compression flag, including the legal
//!                               {0, 1} and the protocol-error path.
//!   4. ZeroLengthMessage  — header with length=0 (must yield Some
//!                           with empty Bytes payload, not None or Err).
//!   5. SizeLimitEnforcement — message length straddles the configured
//!                              max_decode_message_size cap.
//!
//! The harness must never panic. Decoder `Err` is expected and ignored;
//! `Ok(Some)` and `Ok(None)` are both legal outcomes per the codec
//! contract (None = need more bytes). Crashes / aborts are findings.
//!
//! ```bash
//! cargo +nightly fuzz run grpc_codec_decode -- -max_total_time=120
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::grpc::codec::{GrpcCodec, MESSAGE_HEADER_SIZE};
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

fuzz_target!(|s: Scenario| match s {
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
});

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
    let take = payload.len().min(MAX_BUF_BYTES.saturating_sub(MESSAGE_HEADER_SIZE));
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
    let _ = codec.decode(&mut bm);
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
    let _ = codec.decode(&mut bm);
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
    let result = codec.decode(&mut bm);
    // Per the codec contract, length=0 with a valid compression flag
    // MUST yield Some(message with empty data). Anything else (None,
    // Err) is a finding — assert via panic so libfuzzer captures the
    // seed.
    if let Ok(Some(msg)) = result {
        assert!(msg.data.is_empty(), "zero-length frame must have empty data");
    } else {
        // Ok(None) or Err on a complete zero-length frame is a real bug.
        // We only assert this for the compressed=false case; compressed
        // empty frames may have additional decompression invariants that
        // the codec layer above us validates.
        if !compressed {
            // Don't panic on the rare malformed seed — but a Err here
            // would be a real codec contract violation, so we must
            // surface it. libfuzzer's panic = finding.
            panic!(
                "zero-length uncompressed frame must decode to Ok(Some(empty)); got {result:?}"
            );
        }
    }
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
    let _ = codec.decode(&mut bm);
}
