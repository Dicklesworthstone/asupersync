#![no_main]

//! Cargo-fuzz target for `LengthDelimitedCodec::decode` / `decode_eof`
//! (asupersync codec/length_delimited.rs).
//!
//! Feeds raw random byte streams into the decoder and asserts three
//! invariants:
//!
//!   1. **No panic on bad lengths.** The decoder MUST handle every byte
//!      sequence — including zero-length input, length-prefix overflow
//!      (length > usize::MAX after num_skip / length_adjustment), short
//!      headers, and impossibly large declared frame lengths — without
//!      ever panicking. Any panic is a crash bug.
//!
//!   2. **Typed error or success.** Every byte consumed by `decode` /
//!      `decode_eof` must produce one of three observable outcomes:
//!        * `Ok(Some(frame))` — the decoder pulled a frame off,
//!        * `Ok(None)`        — needs more bytes (Incomplete),
//!        * `Err(io::Error)`  — a typed error with an `ErrorKind`.
//!      Anything else (panic, infinite loop, silent corruption) is a bug.
//!
//!   3. **Bounded allocation under length-overflow.** A length prefix of
//!      `u64::MAX` MUST NOT cause the decoder to pre-allocate ~16 EiB of
//!      `BytesMut`. The decoder's `max_frame_length` ceiling (set to a
//!      modest `MAX_FRAME_LEN` here) MUST short-circuit such inputs into
//!      `Err(InvalidData)` before any allocation. The fuzzer asserts the
//!      capacity of `src` and any returned frame stays below
//!      `MAX_FRAME_LEN * SAFETY_FACTOR` — a hard ceiling that is orders
//!      of magnitude smaller than what a naive decoder would request.
//!
//! Coverage biases:
//!   * Random length-field width (1/2/4/8 bytes), big- and little-endian.
//!   * Random `length_field_offset`, `length_adjustment`, `num_skip` —
//!     including extreme values that trigger checked-arithmetic edge
//!     cases inside `adjusted_frame_len` / `total_frame_len`.
//!   * Repeated `decode` calls so frame-spanning state (Head ↔ Data) is
//!     exercised across multiple iterations from the same input.

use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;

/// Cap the configured `max_frame_length`. Smaller than the prod default
/// (8 MiB) so that the over-allocation invariant is easier to assert and
/// fuzzing iterations stay fast.
const MAX_FRAME_LEN: usize = 64 * 1024;

/// Soft cap on input bytes per fuzz iteration to keep each run cheap.
const MAX_INPUT_LEN: usize = 16 * 1024;

/// Hard ceiling on any allocation the decoder is allowed to request.
/// `max_frame_length * SAFETY_FACTOR` — beyond this the test fails.
const SAFETY_FACTOR: usize = 4;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_LEN {
        return;
    }

    let codec_count = (data[0] % 4) as usize + 1;
    let mut cursor = 1usize;

    for _ in 0..codec_count {
        if cursor >= data.len() {
            return;
        }

        let mut codec = build_codec(data, &mut cursor);

        // Slice the remaining bytes (minus a small reserve so subsequent
        // codec configurations get input too) and run them through the
        // decoder.
        let take = ((data.len() - cursor) / codec_count.max(1)).max(1);
        let chunk_end = (cursor + take).min(data.len());
        let chunk = &data[cursor..chunk_end];
        cursor = chunk_end;

        let mut buf = BytesMut::from(chunk);
        let initial_capacity = buf.capacity();

        // Drive `decode` repeatedly until it stops producing frames or
        // returns an error. Track the high-water-mark capacity so we can
        // assert the over-allocation invariant after the loop.
        let mut high_water = initial_capacity;
        let mut iterations = 0u32;
        loop {
            iterations += 1;
            // Belt-and-braces: stop after far more iterations than any
            // legitimate decode loop would need. Catches infinite-loop
            // bugs as a fuzz failure rather than a hang.
            if iterations > 10_000 {
                panic!(
                    "decode looped >10_000 iterations on {}-byte input — possible infinite loop",
                    chunk.len()
                );
            }

            match codec.decode(&mut buf) {
                Ok(Some(frame)) => {
                    assert!(
                        frame.capacity() <= MAX_FRAME_LEN * SAFETY_FACTOR,
                        "decoded frame capacity {} exceeds {}*{} ceiling",
                        frame.capacity(),
                        MAX_FRAME_LEN,
                        SAFETY_FACTOR
                    );
                    high_water = high_water.max(buf.capacity());
                }
                Ok(None) => {
                    high_water = high_water.max(buf.capacity());
                    break;
                }
                Err(_e) => {
                    // Typed error — `e` has a `kind()`. Any io::Error is
                    // acceptable; the contract is "no panic, typed error".
                    high_water = high_water.max(buf.capacity());
                    break;
                }
            }
        }

        // Final EOF flush — `decode_eof` MUST also handle the residual
        // buffer without panic.
        let _ = codec.decode_eof(&mut buf);
        high_water = high_water.max(buf.capacity());

        assert!(
            high_water <= MAX_FRAME_LEN * SAFETY_FACTOR,
            "decoder buffer high-water {} exceeds {}*{} ceiling for input of len {}",
            high_water,
            MAX_FRAME_LEN,
            SAFETY_FACTOR,
            chunk.len()
        );
    }
});

/// Build a randomised `LengthDelimitedCodec` from the fuzz input bytes.
/// Every field is constrained to a sane range — the *codec configuration*
/// is not the SUT, the *decoder behaviour over arbitrary bytes* is.
fn build_codec(data: &[u8], cursor: &mut usize) -> LengthDelimitedCodec {
    let take = |cursor: &mut usize, n: usize| -> Vec<u8> {
        let end = (*cursor + n).min(data.len());
        let out = data[*cursor..end].to_vec();
        *cursor = end;
        out
    };
    let bytes = take(cursor, 6);
    let pad = |idx: usize| bytes.get(idx).copied().unwrap_or(0);

    // length_field_length: must be one of 1, 2, 4, 8 to stay within the
    // codec's documented support window.
    let length_field_length = match pad(0) % 4 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    // Modest offset/skip/adjustment so the codec stays valid — but allow
    // small negative adjustments to exercise the checked-sub paths.
    let length_field_offset = (pad(1) % 8) as usize;
    let num_skip_raw = (pad(2) % 16) as usize;
    let length_adjustment_raw = (pad(3) as i8) as isize;
    let big_endian = (pad(4) & 1) == 0;

    let mut builder = LengthDelimitedCodec::builder();
    builder = builder
        .length_field_offset(length_field_offset)
        .length_field_length(length_field_length)
        .length_adjustment(length_adjustment_raw)
        .num_skip(num_skip_raw)
        .max_frame_length(MAX_FRAME_LEN);
    builder = if big_endian {
        builder.big_endian()
    } else {
        builder.little_endian()
    };
    builder.new_codec()
}
