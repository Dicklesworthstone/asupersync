#![no_main]

//! Cargo-fuzz target for `LengthDelimitedCodec::decode` / `decode_eof`
//! (asupersync codec/length_delimited.rs).
//!
//! Feeds raw random byte streams into the decoder and asserts three
//! invariants:
//!
//! 1. No panic on bad lengths. The decoder must handle every byte sequence,
//!    including zero-length input, length-prefix overflow, short headers, and
//!    impossibly large declared frame lengths.
//! 2. Typed error or success. Every `decode` / `decode_eof` call must produce
//!    `Ok(Some(frame))`, `Ok(None)`, or a typed `io::Error` with an
//!    `ErrorKind`; silent corruption and infinite loops are bugs.
//! 3. Bounded allocation under length overflow. A length prefix of `u64::MAX`
//!    must not cause the decoder to pre-allocate ~16 EiB of `BytesMut`; frame
//!    and buffer capacities stay under `MAX_FRAME_LEN * SAFETY_FACTOR`.
//!
//! Coverage biases:
//! - Random length-field width (1/2/4/8 bytes), big- and little-endian.
//! - Random `length_field_offset`, `length_adjustment`, `num_skip`, including
//!   values that trigger checked-arithmetic edge cases.
//! - Repeated `decode` calls so frame-spanning state is exercised across
//!   multiple iterations from the same input.

use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;
use std::io::ErrorKind;

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
    assert_known_eof_outcomes();

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
        high_water = observe_decode_eof(&mut codec, &mut buf, high_water);

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

fn assert_known_eof_outcomes() {
    let mut full = default_frame(b"abc");
    let mut full_codec = LengthDelimitedCodec::new();
    let full_capacity = full.capacity();
    let high_water = observe_decode_eof(&mut full_codec, &mut full, full_capacity);
    assert!(full.is_empty(), "complete EOF frame must fully drain");
    assert!(
        high_water <= MAX_FRAME_LEN * SAFETY_FACTOR,
        "complete EOF canary exceeded allocation ceiling"
    );

    let mut incomplete = BytesMut::from(&[0, 0, 0, 3, b'a', b'b'][..]);
    let mut incomplete_codec = LengthDelimitedCodec::new();
    let incomplete_result = incomplete_codec.decode_eof(&mut incomplete);
    assert!(
        matches!(&incomplete_result, Err(e) if e.kind() == ErrorKind::UnexpectedEof),
        "incomplete EOF must surface UnexpectedEof; got {incomplete_result:?}"
    );
    assert_eq!(
        incomplete.as_ref(),
        b"ab",
        "incomplete EOF keeps residual body bytes buffered"
    );

    let mut over_cap = default_frame(b"abc");
    let mut over_cap_codec = LengthDelimitedCodec::builder()
        .max_frame_length(2)
        .new_codec();
    let over_cap_result = over_cap_codec.decode_eof(&mut over_cap);
    assert!(
        matches!(&over_cap_result, Err(e) if e.kind() == ErrorKind::InvalidData),
        "over-cap EOF must surface InvalidData; got {over_cap_result:?}"
    );
    assert_eq!(
        over_cap.as_ref(),
        b"abc",
        "over-cap EOF consumes the header and leaves body bytes for skip draining"
    );
    let drained = match over_cap_codec.decode_eof(&mut over_cap) {
        Ok(drained) => drained,
        Err(error) => panic!("skip drain must not re-emit the size error: {error}"),
    };
    assert!(
        drained.is_none(),
        "skip-drained over-cap EOF should finish without a frame"
    );
    assert!(
        over_cap.is_empty(),
        "skip drain must consume the body bytes"
    );
}

fn default_frame(payload: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(4 + payload.len());
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

fn observe_decode_eof(
    codec: &mut LengthDelimitedCodec,
    buf: &mut BytesMut,
    mut high_water: usize,
) -> usize {
    match codec.decode_eof(buf) {
        Ok(Some(frame)) => {
            assert!(
                frame.capacity() <= MAX_FRAME_LEN * SAFETY_FACTOR,
                "EOF frame capacity {} exceeds {}*{} ceiling",
                frame.capacity(),
                MAX_FRAME_LEN,
                SAFETY_FACTOR
            );
            high_water = high_water.max(frame.capacity()).max(buf.capacity());
        }
        Ok(None) => {
            assert!(
                buf.is_empty(),
                "decode_eof Ok(None) is only valid after all buffered bytes drain"
            );
            high_water = high_water.max(buf.capacity());
        }
        Err(error) => {
            assert!(
                matches!(
                    error.kind(),
                    ErrorKind::InvalidData | ErrorKind::UnexpectedEof
                ),
                "decode_eof must surface a framing error kind, got {:?}: {error}",
                error.kind()
            );
            high_water = high_water.max(buf.capacity());
        }
    }
    high_water
}

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
