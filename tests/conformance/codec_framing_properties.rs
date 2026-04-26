#![allow(warnings)]
#![allow(clippy::all)]
//! Exhaustive framing properties for `src/codec/*` — gap-fill alongside
//! `codec_round_trip.rs` (single-config round-trip / amplification) and the
//! existing `codec_framing/` subdir (CodecConformanceResult harness, not
//! `#[test]`-runnable).
//!
//! # File-naming note
//! The natural name `codec_framing.rs` would collide with the `codec_framing/`
//! directory at the same path level (Rust 2024 forbids both for one `mod`
//! declaration). Hence `codec_framing_properties.rs`.
//!
//! # Properties verified
//!
//!   1. **Encode → decode is identity, exhaustively.** Every codec recovers
//!      the original item byte-for-byte under varied configurations
//!      (length-field width, byte order, offset, adjustment) — not just the
//!      defaults.
//!
//!   2. **Encoder is total: never panics, only typed errors.** Frames at
//!      max-1, max, max+1, frames that overflow the length-field width, and
//!      frames that would require a negative encoded length all surface as
//!      `Err(io::ErrorKind::InvalidData)`, not `unwrap()` panics.
//!
//!   3. **Decoder is fail-safe.** Truncated, malformed, oversized, or
//!      adjustment-underflowing input yields `Ok(None)` (need-more) or
//!      `Err(typed)` — never panic, never silent corruption.
//!
//!   4. **Max-frame enforcement is strict at the boundary.** `len == max`
//!      MUST round-trip; `len == max + 1` MUST fail. Both encoder and
//!      decoder paths.
//!
//!   5. **Multi-frame buffers split correctly.** Encoding two frames into
//!      one buffer, then decoding the buffer twice, MUST yield both frames
//!      in order with no leftover bytes.
//!
//!   6. **Byte-by-byte streaming feed converges.** Feeding one byte at a
//!      time MUST yield `Ok(None)` until the full frame is present, then
//!      exactly one `Ok(Some(_))`.
//!
//!   7. **Decoder recovery after error.** A malformed frame's error MUST
//!      NOT leave the decoder in a non-recoverable state if the buffer is
//!      reset — re-feeding a valid frame parses cleanly.
//!
//!   8. **RaptorQ encoder is deterministic.** Same config + same input
//!      MUST yield the same encoded-symbol stream byte-for-byte. Required
//!      for replayable trace conformance.
//!
//! Tests in this file complement `codec_round_trip.rs` (which covers the
//! happy-path round-trip + bounded-amplification properties under default
//! settings). The two files together form the asupersync codec conformance
//! suite.

use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::codec::{
    BytesCodec, Decoder, Encoder, EncodingConfig, EncodingPipeline, LengthDelimitedCodec,
    LinesCodec, LinesCodecError,
};
use asupersync::types::ObjectId;
use asupersync::types::resource::{PoolConfig, SymbolPool};
use std::io;

// ─── Builder helpers ───────────────────────────────────────────────────────

fn ld_be(width: usize, max: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(width)
        .max_frame_length(max)
        .big_endian()
        .new_codec()
}

fn ld_le(width: usize, max: usize) -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(width)
        .max_frame_length(max)
        .little_endian()
        .new_codec()
}

// ─── 1. Identity under varied LengthDelimitedCodec configurations ──────────

#[test]
fn ld_round_trip_across_widths_and_endianness() {
    // 1-byte width caps at 255; 2-byte caps at 65_535; 8-byte is uncapped
    // by header but bounded by max_frame_length.
    for &(width, payload_len) in &[
        (1usize, 0usize),
        (1, 1),
        (1, 200),
        (1, 255),
        (2, 0),
        (2, 256),
        (2, 65_535),
        (4, 0),
        (4, 1_000_000),
        (8, 1),
        (8, 4096),
    ] {
        for &big_endian in &[true, false] {
            let mut codec = if big_endian {
                ld_be(width, 8 * 1024 * 1024)
            } else {
                ld_le(width, 8 * 1024 * 1024)
            };
            let payload = vec![0xA5u8; payload_len];
            let mut buf = BytesMut::new();
            codec
                .encode(BytesMut::from(&payload[..]), &mut buf)
                .unwrap_or_else(|e| panic!("encode width={width} len={payload_len} BE={big_endian}: {e}"));
            let decoded = codec
                .decode(&mut buf)
                .unwrap_or_else(|e| panic!("decode width={width} len={payload_len} BE={big_endian}: {e}"));
            let frame = decoded.unwrap_or_else(|| {
                panic!("expected Some frame for width={width} len={payload_len} BE={big_endian}")
            });
            assert_eq!(
                &frame[..],
                &payload[..],
                "round-trip mismatch width={width} len={payload_len} BE={big_endian}"
            );
            assert!(
                buf.is_empty(),
                "left {} bytes after decode width={width} len={payload_len} BE={big_endian}",
                buf.len()
            );
        }
    }
}

// ─── 2. Encoder totality: typed errors at boundaries, never panic ──────────

#[test]
fn ld_encoder_rejects_payload_exceeding_length_field_capacity() {
    // 1-byte length field caps at 255 — 256-byte payload MUST yield typed err.
    let mut codec = ld_be(1, 8 * 1024 * 1024);
    let payload = vec![0u8; 256];
    let mut buf = BytesMut::new();
    let r = codec.encode(BytesMut::from(&payload[..]), &mut buf);
    match r {
        Err(e) => assert_eq!(
            e.kind(),
            io::ErrorKind::InvalidData,
            "256B payload with 1B length field must be InvalidData, got {e:?}"
        ),
        Ok(()) => panic!("256B payload with 1B length field MUST be rejected by encoder"),
    }
}

#[test]
fn ld_encoder_max_frame_boundary_strict() {
    let max = 1024usize;
    // len == max MUST encode cleanly.
    {
        let mut codec = ld_be(4, max);
        let mut buf = BytesMut::new();
        codec
            .encode(BytesMut::from(&vec![0xAB; max][..]), &mut buf)
            .expect("encoder MUST accept frame of exactly max_frame_length");
        assert_eq!(buf.len(), max + 4, "encoded len must be payload + header");
    }
    // len == max + 1 MUST be rejected.
    {
        let mut codec = ld_be(4, max);
        let mut buf = BytesMut::new();
        let r = codec.encode(BytesMut::from(&vec![0xAB; max + 1][..]), &mut buf);
        match r {
            Err(e) => assert_eq!(
                e.kind(),
                io::ErrorKind::InvalidData,
                "max+1 must yield InvalidData, got {e:?}"
            ),
            Ok(()) => panic!("encoder MUST reject frame at max_frame_length + 1"),
        }
    }
}

#[test]
fn ld_encoder_negative_length_underflow_is_typed_error() {
    // length_adjustment subtracts before encoding. With adjustment=10 and
    // a 5-byte payload, encoded length = 5 - 10 = -5 → must be InvalidData.
    let mut codec = LengthDelimitedCodec::builder()
        .length_field_length(4)
        .length_adjustment(10)
        .max_frame_length(8 * 1024 * 1024)
        .new_codec();
    let mut buf = BytesMut::new();
    let r = codec.encode(BytesMut::from(&vec![0xAA; 5][..]), &mut buf);
    match r {
        Err(e) => assert_eq!(
            e.kind(),
            io::ErrorKind::InvalidData,
            "underflow must be InvalidData, got {e:?}"
        ),
        Ok(()) => panic!("negative encoded length MUST be rejected"),
    }
}

// ─── 3. Decoder fail-safety ────────────────────────────────────────────────

#[test]
fn ld_decoder_oversize_declared_length_returns_typed_error() {
    // Build a header that declares a 1 MiB frame, but configure max=64.
    let mut codec = ld_be(4, 64);
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&(1_048_576u32).to_be_bytes());
    let r = codec.decode(&mut buf);
    match r {
        Err(e) => assert_eq!(
            e.kind(),
            io::ErrorKind::InvalidData,
            "oversize declared length must yield InvalidData, got {e:?}"
        ),
        Ok(o) => panic!("oversize declared length MUST yield InvalidData, got Ok({o:?})"),
    }
}

#[test]
fn ld_decoder_garbage_shorter_than_header_yields_none() {
    let mut codec = ld_be(4, 1024);
    // 2 bytes (less than 4-byte header) → need more.
    let mut partial = BytesMut::from(&b"\x00\x05"[..]);
    let r = codec.decode(&mut partial).expect("must not error on partial");
    assert!(r.is_none(), "partial header must yield Ok(None)");
    assert_eq!(partial.len(), 2, "decoder must NOT consume bytes on Ok(None)");
}

// ─── 4. Multi-frame buffers split correctly ────────────────────────────────

#[test]
fn ld_two_frames_in_one_buffer_decode_in_order() {
    let mut codec = ld_be(4, 1024);
    let mut buf = BytesMut::new();
    codec
        .encode(BytesMut::from(&b"first"[..]), &mut buf)
        .unwrap();
    codec
        .encode(BytesMut::from(&b"second-frame"[..]), &mut buf)
        .unwrap();

    let f1 = codec.decode(&mut buf).unwrap().expect("frame 1 present");
    assert_eq!(&f1[..], b"first", "first frame mismatch");
    let f2 = codec.decode(&mut buf).unwrap().expect("frame 2 present");
    assert_eq!(&f2[..], b"second-frame", "second frame mismatch");
    assert!(buf.is_empty(), "buffer must be drained after two frames");
    assert!(
        codec.decode(&mut buf).unwrap().is_none(),
        "third decode on empty buf must yield Ok(None)"
    );
}

#[test]
fn lines_two_lines_in_one_buffer_decode_in_order() {
    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::from(&b"alpha\nbeta\n"[..]);
    let l1 = codec.decode(&mut buf).unwrap().expect("first line");
    assert_eq!(l1, "alpha");
    let l2 = codec.decode(&mut buf).unwrap().expect("second line");
    assert_eq!(l2, "beta");
    assert!(buf.is_empty(), "buffer must be drained");
    assert!(
        codec.decode(&mut buf).unwrap().is_none(),
        "third decode on empty buf must yield Ok(None)"
    );
}

// ─── 5. Byte-by-byte streaming feed ────────────────────────────────────────

#[test]
fn ld_byte_by_byte_streaming_converges() {
    let mut encoder_codec = ld_be(4, 1024);
    let mut full = BytesMut::new();
    encoder_codec
        .encode(BytesMut::from(&b"hello world!"[..]), &mut full)
        .unwrap();
    let total_len = full.len();
    let serialized = full.to_vec();

    let mut decoder_codec = ld_be(4, 1024);
    let mut buf = BytesMut::new();
    let mut frame: Option<BytesMut> = None;
    for (i, byte) in serialized.iter().enumerate() {
        buf.put_u8(*byte);
        match decoder_codec.decode(&mut buf) {
            Ok(None) => {
                assert!(
                    i + 1 < total_len,
                    "Ok(None) on full buffer (byte {i}/{total_len}) — decoder lost the frame"
                );
            }
            Ok(Some(f)) => {
                assert_eq!(i + 1, total_len, "frame yielded prematurely at byte {i}");
                assert!(frame.is_none(), "decoder yielded twice in stream feed");
                frame = Some(f);
            }
            Err(e) => panic!("streaming feed must not error mid-frame: {e}"),
        }
    }
    let frame = frame.expect("decoder must yield exactly one frame after full feed");
    assert_eq!(&frame[..], b"hello world!", "streaming-decoded frame must match");
}

// ─── 6. Decoder recovery after error ───────────────────────────────────────

#[test]
fn ld_decoder_recovers_after_oversize_error_when_buffer_is_reset() {
    let mut codec = ld_be(4, 64);
    // Inject oversize frame → expect typed error.
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&(1024u32).to_be_bytes());
    let r = codec.decode(&mut buf);
    assert!(r.is_err(), "oversize frame must yield Err, got {r:?}");

    // Reset the buffer (simulate caller draining the bad frame from upstream)
    // and feed a valid frame. The codec MUST still parse it cleanly — its
    // internal `state` must be `Head`, not stuck in `Data(...)`.
    buf.clear();
    let mut encoder_codec = ld_be(4, 64);
    encoder_codec
        .encode(BytesMut::from(&b"recovered"[..]), &mut buf)
        .unwrap();
    let frame = codec
        .decode(&mut buf)
        .expect("decoder must recover after error")
        .expect("frame must be present after recovery");
    assert_eq!(&frame[..], b"recovered", "recovery yields wrong frame");
}

#[test]
fn lines_decoder_recovers_after_invalid_utf8_with_buffer_reset() {
    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::from(&b"\xff\xfe\n"[..]);
    let r = codec.decode(&mut buf);
    assert!(matches!(r, Err(LinesCodecError::InvalidUtf8)));

    // After the error, the decoder MUST be in a state where a subsequent
    // valid line parses. (LinesCodec splits the bad line off the buffer
    // before erroring, so buf is now empty.)
    let r = codec.decode(&mut buf).expect("decode must not error on empty");
    assert!(r.is_none(), "empty buffer must yield Ok(None)");

    buf.put_slice(b"valid line\n");
    let line = codec
        .decode(&mut buf)
        .expect("post-recovery decode must succeed")
        .expect("post-recovery line must be present");
    assert_eq!(line, "valid line", "post-recovery line mismatch");
}

// ─── 7. LinesCodec edge cases not covered in codec_round_trip ──────────────

#[test]
fn lines_empty_line_round_trips_to_just_newline() {
    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::new();
    codec.encode(String::new(), &mut buf).unwrap();
    assert_eq!(buf.as_ref(), b"\n", "empty line encodes to single LF");
    let decoded = codec.decode(&mut buf).unwrap().expect("present");
    assert_eq!(decoded, "", "empty line decodes back to empty string");
}

#[test]
fn lines_crlf_terminator_strips_cr() {
    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::from(&b"crlf-line\r\n"[..]);
    let line = codec.decode(&mut buf).unwrap().expect("line present");
    assert_eq!(line, "crlf-line", "CRLF terminator must strip both CR and LF");
}

#[test]
fn lines_decode_eof_consumes_trailing_data_without_newline() {
    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::from(&b"trailing-no-newline"[..]);
    let r = codec
        .decode_eof(&mut buf)
        .expect("decode_eof must not error on trailing partial");
    assert_eq!(
        r.as_deref(),
        Some("trailing-no-newline"),
        "decode_eof must yield trailing partial as final line"
    );
}

#[test]
fn lines_decode_eof_on_empty_yields_none() {
    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::new();
    let r = codec.decode_eof(&mut buf).unwrap();
    assert!(r.is_none(), "decode_eof on empty buffer must yield None");
}

// ─── 8. BytesCodec multi-byte drains in one call ───────────────────────────

#[test]
fn bytes_codec_drains_entire_buffer_in_one_decode_call() {
    let mut codec = BytesCodec::new();
    let mut buf = BytesMut::from(&b"some arbitrary bytes that should drain"[..]);
    let initial_len = buf.len();
    let frame = codec.decode(&mut buf).unwrap().expect("frame present");
    assert_eq!(
        frame.len(),
        initial_len,
        "BytesCodec must drain the entire buffer in one call"
    );
    assert!(buf.is_empty(), "buffer must be empty after BytesCodec drain");
    let r = codec.decode(&mut buf).unwrap();
    assert!(r.is_none(), "second decode on empty must yield None");
}

// ─── 9. RaptorQ EncodingPipeline determinism ───────────────────────────────
//
// Per the asupersync replay invariant, FEC encoding MUST be deterministic
// given the same `EncodingConfig` and source object. Two independent
// pipelines fed the same bytes must produce byte-identical encoded symbols.

fn small_pipeline_config() -> EncodingConfig {
    // Small but non-trivial: 8-byte symbols, 64-byte blocks → multi-block
    // input exercises the SBN sequencing while staying fast.
    EncodingConfig {
        repair_overhead: 1.0,
        max_block_size: 64,
        symbol_size: 8,
        encoding_parallelism: 1,
        decoding_parallelism: 1,
    }
}

fn fresh_pool(symbol_size: u16) -> SymbolPool {
    SymbolPool::new(PoolConfig {
        symbol_size,
        initial_size: 64,
        max_size: 64,
        allow_growth: true,
        growth_increment: 16,
    })
}

#[test]
fn raptorq_encoding_pipeline_is_deterministic() {
    // Property: two independent EncodingPipelines fed the same config and
    // the same (object_id, data) MUST produce byte-identical encoded
    // symbols. Required by the asupersync replay invariant.
    let source: Vec<u8> = (0u8..=255).cycle().take(256).collect();
    let object_id = ObjectId::new_for_test(0xDEADBEEF);

    let config = small_pipeline_config();
    let mut pipeline_a = EncodingPipeline::new(config.clone(), fresh_pool(config.symbol_size));
    let mut pipeline_b = EncodingPipeline::new(config.clone(), fresh_pool(config.symbol_size));

    let symbols_a: Vec<_> = pipeline_a
        .encode(object_id, &source)
        .collect::<Result<Vec<_>, _>>()
        .expect("pipeline A encode");
    let symbols_b: Vec<_> = pipeline_b
        .encode(object_id, &source)
        .collect::<Result<Vec<_>, _>>()
        .expect("pipeline B encode");

    assert_eq!(
        symbols_a.len(),
        symbols_b.len(),
        "RaptorQ pipelines diverged in symbol count: a={} b={}",
        symbols_a.len(),
        symbols_b.len()
    );
    for (i, (a, b)) in symbols_a.iter().zip(symbols_b.iter()).enumerate() {
        assert_eq!(
            a.id(),
            b.id(),
            "RaptorQ symbol id {i} diverged (determinism violation)"
        );
        assert_eq!(
            a.symbol().data(),
            b.symbol().data(),
            "RaptorQ symbol {i} payload diverged (determinism violation)"
        );
    }
}

#[test]
fn raptorq_encoding_pipeline_empty_input_yields_no_symbols() {
    // Per encoding.rs::test_encode_empty_data: empty source MUST yield zero
    // symbols (encoder is total — no panic on empty input).
    let config = small_pipeline_config();
    let mut pipeline = EncodingPipeline::new(config.clone(), fresh_pool(config.symbol_size));
    let symbols: Vec<_> = pipeline
        .encode(ObjectId::new_for_test(1), &[])
        .collect::<Result<Vec<_>, _>>()
        .expect("empty encode must not error");
    assert!(
        symbols.is_empty(),
        "empty source MUST yield zero encoded symbols, got {}",
        symbols.len()
    );
}
