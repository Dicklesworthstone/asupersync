//! Wire-frame goldens for `src/codec/`: `LengthDelimitedCodec` and
//! `LinesCodec`.
//!
//! Bead: br-asupersync-do7c8r
//!
//! Captures byte-exact encoder output and decoder behavior across the
//! canonical edge cases (empty payload, single byte, multi-byte,
//! multi-frame buffer, partial header) so any drift between
//! asupersync's codecs and the on-the-wire framing is caught at
//! unit-test time.
//!
//! Run with:
//!     rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_codec_wire_frame_goldens cargo test --test codec_wire_frame_goldens
//!
//! Update on intentional change:
//!     rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_codec_wire_frame_goldens cargo insta review

#![cfg(test)]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::bytes::BytesMut;
use asupersync::codec::{Decoder, Encoder, LengthDelimitedCodec, LinesCodec};

/// `xxd`-style hexdump renderer; same shape as
/// `tests/database_wire_frame_goldens.rs::hexdump` so reviewers can
/// compare diffs across both golden suites without context-switching.
fn hexdump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let offset = row * 16;
        out.push_str(&format!("{offset:04x}  "));
        for (i, b) in chunk.iter().enumerate() {
            out.push_str(&format!("{b:02x} "));
            if i == 7 {
                out.push(' ');
            }
        }
        for i in chunk.len()..16 {
            out.push_str("   ");
            if i == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        for b in chunk {
            let c = if (0x20..0x7f).contains(b) {
                *b as char
            } else {
                '.'
            };
            out.push(c);
        }
        out.push_str("|\n");
    }
    out.push_str(&format!("({} bytes)\n", bytes.len()));
    out
}

// ---------------------------------------------------------------------------
// LengthDelimitedCodec — encoder
// ---------------------------------------------------------------------------
//
// Default builder (length_field_length = 4, big-endian, max_frame_length =
// 8 MiB, no offset/adjustment) per src/codec/length_delimited.rs:75-78.

/// Encoding an EMPTY payload yields a 4-byte length prefix of zeros and
/// no body. Total = 4 bytes.
#[test]
fn length_delimited_encode_empty_payload() {
    let mut codec = LengthDelimitedCodec::new();
    let mut dst = BytesMut::new();
    codec
        .encode(BytesMut::new(), &mut dst)
        .expect("encode empty");
    insta::assert_snapshot!("length_delimited_encode_empty", hexdump(&dst));
}

/// Single-byte payload `0x42` — length prefix `00 00 00 01`, then `42`.
#[test]
fn length_delimited_encode_single_byte_payload() {
    let mut codec = LengthDelimitedCodec::new();
    let mut dst = BytesMut::new();
    codec
        .encode(BytesMut::from(&b"B"[..]), &mut dst)
        .expect("encode single byte");
    insta::assert_snapshot!("length_delimited_encode_single_byte", hexdump(&dst));
}

/// Multi-byte payload `b"hello"` — length prefix `00 00 00 05`, then
/// `68 65 6c 6c 6f`.
#[test]
fn length_delimited_encode_hello() {
    let mut codec = LengthDelimitedCodec::new();
    let mut dst = BytesMut::new();
    codec
        .encode(BytesMut::from(&b"hello"[..]), &mut dst)
        .expect("encode hello");
    insta::assert_snapshot!("length_delimited_encode_hello", hexdump(&dst));
}

// ---------------------------------------------------------------------------
// LengthDelimitedCodec — decoder
// ---------------------------------------------------------------------------

/// Decoding an EMPTY buffer returns `Ok(None)` and consumes nothing —
/// the codec is waiting for more bytes. Snapshot the (result_label,
/// remaining_bytes) tuple so any change in either fails noticeably.
#[test]
fn length_delimited_decode_empty_buffer() {
    let mut codec = LengthDelimitedCodec::new();
    let mut buf = BytesMut::new();
    let result = codec.decode(&mut buf).expect("decode empty");
    insta::assert_debug_snapshot!(
        "length_delimited_decode_empty_buffer",
        (
            "result",
            decode_label(&result),
            "remaining_bytes",
            buf.len()
        )
    );
}

/// Decoding a buffer that contains only 3 bytes of the 4-byte length
/// prefix returns `Ok(None)` and leaves the partial header in the
/// buffer for the next call.
#[test]
fn length_delimited_decode_partial_header() {
    let mut codec = LengthDelimitedCodec::new();
    let mut buf = BytesMut::from(&[0x00, 0x00, 0x00][..]); // 3 of 4 length bytes
    let result = codec.decode(&mut buf).expect("decode partial header");
    insta::assert_debug_snapshot!(
        "length_delimited_decode_partial_header",
        (
            "result",
            decode_label(&result),
            "remaining_bytes",
            buf.len()
        )
    );
}

/// Decoding a single complete frame consumes exactly the header + body
/// and returns `Some(payload)`. Snapshot the body hex + remaining
/// bytes so any cursor-management drift is visible.
#[test]
fn length_delimited_decode_single_complete_frame() {
    let mut codec = LengthDelimitedCodec::new();
    // length=5 BE, payload "hello"
    let mut buf = BytesMut::from(&[0x00, 0x00, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o'][..]);
    let result = codec.decode(&mut buf).expect("decode single frame");
    let payload = result.expect("Some(payload)");
    insta::assert_debug_snapshot!(
        "length_delimited_decode_single_complete_frame",
        (
            "payload_hex",
            payload
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
            "remaining_bytes",
            buf.len()
        )
    );
}

/// Decoding a buffer with TWO complete frames pulls only the first;
/// the second remains in the buffer for the next `decode()` call. This
/// is the canonical FramedRead pull-loop interaction and the easiest
/// place to regress when refactoring the head/data state machine.
#[test]
fn length_delimited_decode_first_of_two_frames_leaves_second() {
    let mut codec = LengthDelimitedCodec::new();
    // [len=2, "ab"] [len=3, "xyz"] = 4+2+4+3 = 13 bytes total.
    let wire = &[
        0x00, 0x00, 0x00, 0x02, b'a', b'b', // frame 1
        0x00, 0x00, 0x00, 0x03, b'x', b'y', b'z', // frame 2
    ];
    let mut buf = BytesMut::from(&wire[..]);
    let first = codec
        .decode(&mut buf)
        .expect("decode first")
        .expect("Some(first)");
    insta::assert_debug_snapshot!(
        "length_delimited_decode_first_of_two_frames",
        (
            "first_payload_hex",
            first
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
            "remaining_bytes",
            buf.len(),
            "remaining_hex",
            buf.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        )
    );
}

// ---------------------------------------------------------------------------
// LinesCodec — encoder
// ---------------------------------------------------------------------------

/// Encoding an empty line writes only the trailing `\n` separator.
#[test]
fn lines_encode_empty_line() {
    let mut codec = LinesCodec::new();
    let mut dst = BytesMut::new();
    codec.encode(String::new(), &mut dst).expect("encode empty");
    insta::assert_snapshot!("lines_encode_empty", hexdump(&dst));
}

/// Encoding a single-character line writes the char + `\n`.
#[test]
fn lines_encode_single_char() {
    let mut codec = LinesCodec::new();
    let mut dst = BytesMut::new();
    codec
        .encode("x".to_string(), &mut dst)
        .expect("encode single char");
    insta::assert_snapshot!("lines_encode_single_char", hexdump(&dst));
}

// ---------------------------------------------------------------------------
// LinesCodec — decoder
// ---------------------------------------------------------------------------

/// Empty buffer yields `Ok(None)`.
#[test]
fn lines_decode_empty_buffer() {
    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::new();
    let result = codec.decode(&mut buf).expect("decode empty");
    insta::assert_debug_snapshot!(
        "lines_decode_empty_buffer",
        (
            "result_is_some",
            result.is_some(),
            "remaining_bytes",
            buf.len()
        )
    );
}

/// Two complete lines `"hello\nworld\n"` — first decode returns
/// `"hello"` and consumes `b"hello\n"` (6 bytes); the second 6 bytes
/// remain.
#[test]
fn lines_decode_first_of_two_lines_leaves_second() {
    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::from(&b"hello\nworld\n"[..]);
    let first = codec
        .decode(&mut buf)
        .expect("decode first")
        .expect("Some(first)");
    insta::assert_debug_snapshot!(
        "lines_decode_first_of_two_lines",
        (
            "first_line",
            first,
            "remaining_bytes",
            buf.len(),
            "remaining_str",
            std::str::from_utf8(&buf)
                .unwrap_or("<invalid utf8>")
                .to_string()
        )
    );
}

/// Buffer with `"partial"` (no trailing `\n`) returns `Ok(None)` and
/// leaves the bytes in place — the codec is waiting for the line
/// terminator.
#[test]
fn lines_decode_partial_line_no_newline() {
    let mut codec = LinesCodec::new();
    let mut buf = BytesMut::from(&b"partial"[..]);
    let result = codec.decode(&mut buf).expect("decode partial");
    insta::assert_debug_snapshot!(
        "lines_decode_partial_line_no_newline",
        (
            "result_is_some",
            result.is_some(),
            "remaining_bytes",
            buf.len(),
            "remaining_str",
            std::str::from_utf8(&buf)
                .unwrap_or("<invalid utf8>")
                .to_string()
        )
    );
}

fn decode_label<T>(result: &Option<T>) -> &'static str {
    if result.is_some() { "Some" } else { "None" }
}
