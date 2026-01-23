//! Codec Framework E2E Verification Suite (bd-22vb)
//!
//! Comprehensive verification for the codec framework ensuring correct
//! encoding/decoding and framing behavior.
//!
//! Test Coverage:
//! - Decoder trait: decode, decode_eof
//! - Encoder trait: encode
//! - LinesCodec: newline delimiter, CRLF, max length
//! - LengthDelimitedCodec: length-prefixed frames, endianness
//! - Edge cases: empty frames, partial frames, malformed input
//! - Error propagation and recovery

#![allow(missing_docs)]

#[macro_use]
mod common;

use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, Encoder, LengthDelimitedCodec, LinesCodec, LinesCodecError};
use common::*;
use std::io;

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

// ============================================================================
// LINES CODEC TESTS
// ============================================================================

/// E2E-CODEC-001: LinesCodec decodes multiple lines correctly
///
/// Verifies that LinesCodec can decode multiple newline-delimited lines
/// from a single buffer.
#[test]
fn e2e_codec_001_lines_multi_decode() {
    init_test("e2e_codec_001_lines_multi_decode");
    test_section!("setup");

    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::from("line1\nline2\nline3\n");

    test_section!("decode");
    let line1 = codec.decode(&mut buf).expect("decode 1").expect("line 1");
    let line2 = codec.decode(&mut buf).expect("decode 2").expect("line 2");
    let line3 = codec.decode(&mut buf).expect("decode 3").expect("line 3");
    let none = codec.decode(&mut buf).expect("decode 4");

    test_section!("verify");
    assert_with_log!(line1 == "line1", "line1", "line1", line1);
    assert_with_log!(line2 == "line2", "line2", "line2", line2);
    assert_with_log!(line3 == "line3", "line3", "line3", line3);
    assert_with_log!(none.is_none(), "no more lines", true, none.is_none());

    test_complete!("e2e_codec_001_lines_multi_decode");
}

/// E2E-CODEC-002: LinesCodec handles CRLF line endings
///
/// Verifies correct handling of Windows-style CRLF line endings.
#[test]
fn e2e_codec_002_lines_crlf() {
    init_test("e2e_codec_002_lines_crlf");
    test_section!("setup");

    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::from("windows\r\nunix\nmixed\r\n");

    test_section!("decode");
    let win = codec.decode(&mut buf).expect("decode 1").expect("windows");
    let unix = codec.decode(&mut buf).expect("decode 2").expect("unix");
    let mixed = codec.decode(&mut buf).expect("decode 3").expect("mixed");

    test_section!("verify");
    assert_with_log!(win == "windows", "windows line", "windows", win);
    assert_with_log!(unix == "unix", "unix line", "unix", unix);
    assert_with_log!(mixed == "mixed", "mixed line", "mixed", mixed);

    test_complete!("e2e_codec_002_lines_crlf");
}

/// E2E-CODEC-003: LinesCodec enforces max line length
///
/// Verifies that LinesCodec rejects lines exceeding the configured maximum.
#[test]
fn e2e_codec_003_lines_max_length() {
    init_test("e2e_codec_003_lines_max_length");
    test_section!("setup");

    let mut codec = LinesCodec::new_with_max_length(10);

    test_section!("short line ok");
    let mut buf = BytesMut::from("short\n");
    let short = codec
        .decode(&mut buf)
        .expect("decode short")
        .expect("short");
    assert_with_log!(short == "short", "short line ok", "short", short);

    test_section!("exact limit ok");
    let mut buf = BytesMut::from("exactly10!\n");
    let exact = codec
        .decode(&mut buf)
        .expect("decode exact")
        .expect("exact");
    assert_with_log!(exact == "exactly10!", "exact limit ok", "exactly10!", exact);

    test_section!("over limit rejected");
    let mut codec2 = LinesCodec::new_with_max_length(10);
    let mut buf = BytesMut::from("this_is_way_too_long\n");
    let err = codec2.decode(&mut buf).expect_err("should reject");
    assert_with_log!(
        err == LinesCodecError::MaxLineLengthExceeded,
        "max length error",
        LinesCodecError::MaxLineLengthExceeded,
        err
    );

    test_complete!("e2e_codec_003_lines_max_length");
}

/// E2E-CODEC-004: LinesCodec handles partial lines correctly
///
/// Verifies that incomplete lines return None until newline arrives.
#[test]
fn e2e_codec_004_lines_partial() {
    init_test("e2e_codec_004_lines_partial");
    test_section!("setup");

    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::from("partial");

    test_section!("partial returns none");
    let none = codec.decode(&mut buf).expect("decode partial");
    assert_with_log!(none.is_none(), "partial is none", true, none.is_none());

    test_section!("complete with more data");
    buf.put_slice(b" line\n");
    let complete = codec
        .decode(&mut buf)
        .expect("decode complete")
        .expect("complete");
    assert_with_log!(
        complete == "partial line",
        "completed line",
        "partial line",
        complete
    );

    test_complete!("e2e_codec_004_lines_partial");
}

/// E2E-CODEC-005: LinesCodec encode roundtrip
///
/// Verifies that encoding and decoding produces the original data.
#[test]
fn e2e_codec_005_lines_roundtrip() {
    init_test("e2e_codec_005_lines_roundtrip");
    test_section!("setup");

    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::new();
    let original = "hello world".to_string();

    test_section!("encode");
    codec
        .encode(original.clone(), &mut buf)
        .expect("encode failed");

    test_section!("decode");
    let decoded = codec.decode(&mut buf).expect("decode").expect("line");

    test_section!("verify");
    assert_with_log!(decoded == original, "roundtrip", original, decoded);

    test_complete!("e2e_codec_005_lines_roundtrip");
}

/// E2E-CODEC-006: LinesCodec decode_eof behavior
///
/// Verifies correct EOF handling with incomplete and complete data.
#[test]
fn e2e_codec_006_lines_decode_eof() {
    init_test("e2e_codec_006_lines_decode_eof");

    test_section!("empty buffer at eof");
    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::new();
    let result = codec.decode_eof(&mut buf).expect("empty eof ok");
    assert_with_log!(
        result.is_none(),
        "empty eof is none",
        true,
        result.is_none()
    );

    test_section!("incomplete line at eof errors");
    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::from("no newline");
    let err = codec
        .decode_eof(&mut buf)
        .expect_err("incomplete should error");
    // LinesCodecError::InvalidUtf8 is used for io::Error conversion
    assert_with_log!(
        matches!(err, LinesCodecError::InvalidUtf8),
        "incomplete eof error",
        "InvalidUtf8",
        err
    );

    test_complete!("e2e_codec_006_lines_decode_eof");
}

// ============================================================================
// LENGTH DELIMITED CODEC TESTS
// ============================================================================

/// E2E-CODEC-010: LengthDelimitedCodec basic decode
///
/// Verifies basic length-prefixed frame decoding with big-endian u32 length.
#[test]
fn e2e_codec_010_length_delimited_basic() {
    init_test("e2e_codec_010_length_delimited_basic");
    test_section!("setup");

    let mut codec = LengthDelimitedCodec::new();
    let mut buf = BytesMut::new();

    // Frame: 4-byte BE length (5) + 5-byte payload "hello"
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(5);
    buf.put_slice(b"hello");

    test_section!("decode");
    let frame = codec.decode(&mut buf).expect("decode").expect("frame");

    test_section!("verify");
    assert_with_log!(&frame[..] == b"hello", "frame content", "hello", &frame[..]);
    assert_with_log!(buf.is_empty(), "buffer empty", true, buf.is_empty());

    test_complete!("e2e_codec_010_length_delimited_basic");
}

/// E2E-CODEC-011: LengthDelimitedCodec partial frame handling
///
/// Verifies correct behavior when frame data arrives incrementally.
#[test]
fn e2e_codec_011_length_delimited_partial() {
    init_test("e2e_codec_011_length_delimited_partial");
    test_section!("setup");

    let mut codec = LengthDelimitedCodec::new();
    let mut buf = BytesMut::new();

    test_section!("header only");
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(10);
    let none = codec.decode(&mut buf).expect("decode header only");
    assert_with_log!(none.is_none(), "header only is none", true, none.is_none());

    test_section!("partial payload");
    buf.put_slice(b"part");
    let none = codec.decode(&mut buf).expect("decode partial");
    assert_with_log!(none.is_none(), "partial is none", true, none.is_none());

    test_section!("complete");
    buf.put_slice(b"ial_da");
    let frame = codec
        .decode(&mut buf)
        .expect("decode complete")
        .expect("frame");
    assert_with_log!(
        &frame[..] == b"partial_da",
        "frame content",
        "partial_da",
        &frame[..]
    );

    test_complete!("e2e_codec_011_length_delimited_partial");
}

/// E2E-CODEC-012: LengthDelimitedCodec little endian
///
/// Verifies little-endian length field handling.
#[test]
fn e2e_codec_012_length_delimited_little_endian() {
    init_test("e2e_codec_012_length_delimited_little_endian");
    test_section!("setup");

    let mut codec = LengthDelimitedCodec::builder().little_endian().new_codec();
    let mut buf = BytesMut::new();

    // Frame: 4-byte LE length (5) + 5-byte payload "hello"
    buf.put_u8(5); // LSB
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0); // MSB
    buf.put_slice(b"hello");

    test_section!("decode");
    let frame = codec.decode(&mut buf).expect("decode").expect("frame");

    test_section!("verify");
    assert_with_log!(&frame[..] == b"hello", "frame content", "hello", &frame[..]);

    test_complete!("e2e_codec_012_length_delimited_little_endian");
}

/// E2E-CODEC-013: LengthDelimitedCodec max frame length enforcement
///
/// Verifies that frames exceeding max_frame_length are rejected.
#[test]
fn e2e_codec_013_length_delimited_max_frame() {
    init_test("e2e_codec_013_length_delimited_max_frame");
    test_section!("setup");

    let mut codec = LengthDelimitedCodec::builder()
        .max_frame_length(100)
        .new_codec();
    let mut buf = BytesMut::new();

    // Frame with length 1000 (exceeds max of 100)
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0x03);
    buf.put_u8(0xE8); // 1000 in BE
    buf.put_slice(&[0u8; 100]); // some data

    test_section!("decode rejects");
    let err = codec.decode(&mut buf).expect_err("should reject");
    assert_with_log!(
        err.kind() == io::ErrorKind::InvalidData,
        "error kind",
        io::ErrorKind::InvalidData,
        err.kind()
    );

    test_complete!("e2e_codec_013_length_delimited_max_frame");
}

/// E2E-CODEC-014: LengthDelimitedCodec length adjustment
///
/// Verifies that length_adjustment correctly modifies frame length.
#[test]
fn e2e_codec_014_length_delimited_adjustment() {
    init_test("e2e_codec_014_length_delimited_adjustment");
    test_section!("setup");

    // length_adjustment adds to the decoded length value
    // If header says 3 and adjustment is 2, frame length is 5
    let mut codec = LengthDelimitedCodec::builder()
        .length_adjustment(2)
        .num_skip(4)
        .new_codec();
    let mut buf = BytesMut::new();

    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(3); // length field = 3, adjusted = 5
    buf.put_slice(b"hello"); // 5 bytes

    test_section!("decode");
    let frame = codec.decode(&mut buf).expect("decode").expect("frame");

    test_section!("verify");
    assert_with_log!(&frame[..] == b"hello", "frame content", "hello", &frame[..]);

    test_complete!("e2e_codec_014_length_delimited_adjustment");
}

/// E2E-CODEC-015: LengthDelimitedCodec different field lengths
///
/// Verifies 1-byte, 2-byte, and 4-byte length field configurations.
#[test]
fn e2e_codec_015_length_delimited_field_lengths() {
    init_test("e2e_codec_015_length_delimited_field_lengths");

    test_section!("1-byte length field");
    let mut codec = LengthDelimitedCodec::builder()
        .length_field_length(1)
        .num_skip(1)
        .new_codec();
    let mut buf = BytesMut::new();
    buf.put_u8(5);
    buf.put_slice(b"hello");
    let frame = codec
        .decode(&mut buf)
        .expect("decode 1-byte")
        .expect("frame");
    assert_with_log!(&frame[..] == b"hello", "1-byte field", "hello", &frame[..]);

    test_section!("2-byte length field");
    let mut codec = LengthDelimitedCodec::builder()
        .length_field_length(2)
        .num_skip(2)
        .new_codec();
    let mut buf = BytesMut::new();
    buf.put_u8(0);
    buf.put_u8(5);
    buf.put_slice(b"hello");
    let frame = codec
        .decode(&mut buf)
        .expect("decode 2-byte")
        .expect("frame");
    assert_with_log!(&frame[..] == b"hello", "2-byte field", "hello", &frame[..]);

    test_complete!("e2e_codec_015_length_delimited_field_lengths");
}

/// E2E-CODEC-016: LengthDelimitedCodec multiple frames
///
/// Verifies decoding multiple consecutive frames from a single buffer.
#[test]
fn e2e_codec_016_length_delimited_multi_frame() {
    init_test("e2e_codec_016_length_delimited_multi_frame");
    test_section!("setup");

    let mut codec = LengthDelimitedCodec::new();
    let mut buf = BytesMut::new();

    // Frame 1: "hello"
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(5);
    buf.put_slice(b"hello");

    // Frame 2: "world"
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(5);
    buf.put_slice(b"world");

    test_section!("decode frames");
    let frame1 = codec.decode(&mut buf).expect("decode 1").expect("frame 1");
    let frame2 = codec.decode(&mut buf).expect("decode 2").expect("frame 2");
    let none = codec.decode(&mut buf).expect("decode 3");

    test_section!("verify");
    assert_with_log!(&frame1[..] == b"hello", "frame 1", "hello", &frame1[..]);
    assert_with_log!(&frame2[..] == b"world", "frame 2", "world", &frame2[..]);
    assert_with_log!(none.is_none(), "no more frames", true, none.is_none());

    test_complete!("e2e_codec_016_length_delimited_multi_frame");
}

// ============================================================================
// EDGE CASES
// ============================================================================

/// E2E-CODEC-020: Empty frames
///
/// Verifies handling of zero-length frames.
#[test]
fn e2e_codec_020_empty_frames() {
    init_test("e2e_codec_020_empty_frames");

    test_section!("empty line");
    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::from("\n");
    let empty = codec.decode(&mut buf).expect("decode").expect("empty line");
    assert_with_log!(empty.is_empty(), "empty line", true, empty.is_empty());

    test_section!("empty length-delimited frame");
    let mut codec = LengthDelimitedCodec::new();
    let mut buf = BytesMut::new();
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    let empty = codec
        .decode(&mut buf)
        .expect("decode")
        .expect("empty frame");
    assert_with_log!(empty.is_empty(), "empty frame", true, empty.is_empty());

    test_complete!("e2e_codec_020_empty_frames");
}

/// E2E-CODEC-021: Unicode content in lines
///
/// Verifies correct handling of UTF-8 content.
#[test]
fn e2e_codec_021_unicode_content() {
    init_test("e2e_codec_021_unicode_content");
    test_section!("setup");

    let mut codec = LinesCodec::new();
    let unicode_line = "Hello 世界 🦀 Привет\n";
    let mut buf = BytesMut::from(unicode_line);

    test_section!("decode");
    let decoded = codec.decode(&mut buf).expect("decode").expect("unicode");

    test_section!("verify");
    assert_with_log!(
        decoded == "Hello 世界 🦀 Привет",
        "unicode content",
        "Hello 世界 🦀 Привет",
        decoded
    );

    test_complete!("e2e_codec_021_unicode_content");
}

/// E2E-CODEC-022: Invalid UTF-8 in LinesCodec
///
/// Verifies that invalid UTF-8 sequences are rejected.
#[test]
fn e2e_codec_022_invalid_utf8() {
    init_test("e2e_codec_022_invalid_utf8");
    test_section!("setup");

    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::new();
    buf.put_slice(&[0xFF, 0xFE, b'\n']); // Invalid UTF-8

    test_section!("decode fails");
    let err = codec.decode(&mut buf).expect_err("should fail");
    assert_with_log!(
        err == LinesCodecError::InvalidUtf8,
        "invalid utf8 error",
        LinesCodecError::InvalidUtf8,
        err
    );

    test_complete!("e2e_codec_022_invalid_utf8");
}

/// E2E-CODEC-023: Buffer state preservation on partial decode
///
/// Verifies that buffer state is correctly preserved across partial decodes.
#[test]
fn e2e_codec_023_buffer_state_preservation() {
    init_test("e2e_codec_023_buffer_state_preservation");
    test_section!("setup");

    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::from("partial");
    let initial_len = buf.len();

    test_section!("first decode - partial");
    let _ = codec.decode(&mut buf).expect("decode partial");
    assert_with_log!(
        buf.len() == initial_len,
        "buffer unchanged",
        initial_len,
        buf.len()
    );

    test_section!("second decode - still partial");
    buf.put_slice(b" more");
    let len_after = buf.len();
    let _ = codec.decode(&mut buf).expect("decode partial 2");
    assert_with_log!(
        buf.len() == len_after,
        "buffer unchanged after second partial",
        len_after,
        buf.len()
    );

    test_section!("complete");
    buf.put_slice(b"\n");
    let line = codec.decode(&mut buf).expect("decode").expect("line");
    assert_with_log!(
        line == "partial more",
        "completed line",
        "partial more",
        line
    );
    assert_with_log!(buf.is_empty(), "buffer empty", true, buf.is_empty());

    test_complete!("e2e_codec_023_buffer_state_preservation");
}

/// E2E-CODEC-024: Length field offset
///
/// Verifies that length_field_offset correctly skips header bytes.
#[test]
fn e2e_codec_024_length_field_offset() {
    init_test("e2e_codec_024_length_field_offset");
    test_section!("setup");

    // Protocol: 2-byte magic, then 4-byte length, then data
    // The full header is consumed by num_skip
    let mut codec = LengthDelimitedCodec::builder()
        .length_field_offset(2) // Skip 2 bytes of magic
        .length_field_length(4)
        .num_skip(6) // Skip magic + length field
        .new_codec();

    let mut buf = BytesMut::new();
    buf.put_slice(&[0xCA, 0xFE]); // Magic bytes
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(5); // Length = 5
    buf.put_slice(b"hello");

    test_section!("decode");
    let frame = codec.decode(&mut buf).expect("decode").expect("frame");

    test_section!("verify");
    assert_with_log!(&frame[..] == b"hello", "frame content", "hello", &frame[..]);

    test_complete!("e2e_codec_024_length_field_offset");
}

// ============================================================================
// STRESS TESTS
// ============================================================================

/// E2E-CODEC-030: Many small frames
///
/// Verifies correct handling of many small consecutive frames.
#[test]
fn e2e_codec_030_many_small_frames() {
    init_test("e2e_codec_030_many_small_frames");
    test_section!("setup");

    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::new();
    let count = 1000;

    for i in 0..count {
        buf.put_slice(format!("line{i}\n").as_bytes());
    }

    test_section!("decode all");
    let mut decoded = 0;
    while let Some(_line) = codec.decode(&mut buf).expect("decode") {
        decoded += 1;
    }

    test_section!("verify");
    assert_with_log!(decoded == count, "decoded count", count, decoded);

    test_complete!("e2e_codec_030_many_small_frames");
}

/// E2E-CODEC-031: Large frame handling
///
/// Verifies correct handling of large frames approaching the limit.
#[test]
fn e2e_codec_031_large_frame() {
    init_test("e2e_codec_031_large_frame");
    test_section!("setup");

    let frame_size = 64 * 1024; // 64KB
    let mut codec = LengthDelimitedCodec::builder()
        .max_frame_length(frame_size + 100)
        .new_codec();

    let mut buf = BytesMut::new();
    let len_bytes = (frame_size as u32).to_be_bytes();
    buf.put_slice(&len_bytes);
    buf.put_slice(&vec![b'X'; frame_size]);

    test_section!("decode");
    let frame = codec.decode(&mut buf).expect("decode").expect("frame");

    test_section!("verify");
    assert_with_log!(
        frame.len() == frame_size,
        "frame size",
        frame_size,
        frame.len()
    );
    assert_with_log!(frame.iter().all(|&b| b == b'X'), "all X", true, true);

    test_complete!("e2e_codec_031_large_frame");
}

/// E2E-CODEC-032: Incremental byte-by-byte arrival
///
/// Simulates data arriving one byte at a time.
#[test]
fn e2e_codec_032_byte_by_byte() {
    init_test("e2e_codec_032_byte_by_byte");
    test_section!("setup");

    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::new();
    let input = b"hello\n";

    test_section!("feed bytes");
    for (i, &byte) in input.iter().enumerate() {
        buf.put_u8(byte);
        let result = codec.decode(&mut buf).expect("decode");
        if i < input.len() - 1 {
            assert_with_log!(result.is_none(), "partial", true, result.is_none());
        } else {
            let line = result.expect("final should have line");
            assert_with_log!(line == "hello", "final line", "hello", line);
        }
    }

    test_complete!("e2e_codec_032_byte_by_byte");
}

// ============================================================================
// CODEC STATE TESTS
// ============================================================================

/// E2E-CODEC-040: Codec reuse after successful decode
///
/// Verifies that codecs can be reused for multiple decode cycles.
#[test]
fn e2e_codec_040_codec_reuse() {
    init_test("e2e_codec_040_codec_reuse");
    test_section!("setup");

    let mut codec = LinesCodec::new();

    test_section!("first cycle");
    let mut buf = BytesMut::from("first\n");
    let first = codec.decode(&mut buf).expect("decode 1").expect("first");
    assert_with_log!(first == "first", "first", "first", first);

    test_section!("second cycle - new buffer");
    let mut buf = BytesMut::from("second\n");
    let second = codec.decode(&mut buf).expect("decode 2").expect("second");
    assert_with_log!(second == "second", "second", "second", second);

    test_complete!("e2e_codec_040_codec_reuse");
}

/// E2E-CODEC-041: LengthDelimited state machine reset
///
/// Verifies that the length-delimited codec properly resets state between frames.
#[test]
fn e2e_codec_041_length_delimited_state_reset() {
    init_test("e2e_codec_041_length_delimited_state_reset");
    test_section!("setup");

    let mut codec = LengthDelimitedCodec::new();
    let mut buf = BytesMut::new();

    test_section!("frame 1 - complete");
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(3);
    buf.put_slice(b"abc");
    let f1 = codec.decode(&mut buf).expect("decode 1").expect("frame 1");
    assert_with_log!(&f1[..] == b"abc", "frame 1", "abc", &f1[..]);

    test_section!("frame 2 - complete");
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(0);
    buf.put_u8(3);
    buf.put_slice(b"xyz");
    let f2 = codec.decode(&mut buf).expect("decode 2").expect("frame 2");
    assert_with_log!(&f2[..] == b"xyz", "frame 2", "xyz", &f2[..]);

    test_complete!("e2e_codec_041_length_delimited_state_reset");
}

// ============================================================================
// ENCODER TESTS
// ============================================================================

/// E2E-CODEC-050: LinesCodec encode multiple lines
///
/// Verifies that multiple lines can be encoded into a single buffer.
#[test]
fn e2e_codec_050_lines_encode_multi() {
    init_test("e2e_codec_050_lines_encode_multi");
    test_section!("setup");

    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::new();

    test_section!("encode");
    codec
        .encode("line1".to_string(), &mut buf)
        .expect("encode 1");
    codec
        .encode("line2".to_string(), &mut buf)
        .expect("encode 2");
    codec
        .encode("line3".to_string(), &mut buf)
        .expect("encode 3");

    test_section!("verify");
    assert_with_log!(
        &buf[..] == b"line1\nline2\nline3\n",
        "encoded content",
        "line1\\nline2\\nline3\\n",
        String::from_utf8_lossy(&buf)
    );

    test_complete!("e2e_codec_050_lines_encode_multi");
}

/// E2E-CODEC-051: Encode-decode symmetry
///
/// Verifies that encode followed by decode produces the original data.
#[test]
fn e2e_codec_051_encode_decode_symmetry() {
    init_test("e2e_codec_051_encode_decode_symmetry");
    test_section!("setup");

    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::new();
    let lines = vec!["hello".to_string(), "world".to_string(), "test".to_string()];

    test_section!("encode all");
    for line in &lines {
        codec.encode(line.clone(), &mut buf).expect("encode");
    }

    test_section!("decode all");
    let mut decoded = Vec::new();
    while let Some(line) = codec.decode(&mut buf).expect("decode") {
        decoded.push(line);
    }

    test_section!("verify");
    assert_with_log!(decoded == lines, "symmetry", lines, decoded);

    test_complete!("e2e_codec_051_encode_decode_symmetry");
}
