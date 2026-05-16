//! br-asupersync-8dl9j7 — Fuzz `H1 parse_chunk_size_line` against
//! adversarial chunk-size fields: oversize hex (>usize::MAX),
//! embedded extensions, mixed-case hex, leading/trailing
//! whitespace, embedded NUL, CRLF in unexpected places.
//!
//! Invariants asserted:
//!   * Parser panics, if any, surface directly to libFuzzer.
//!   * Parser returns Result; on overflow / malformed it returns
//!     `HttpError`, not a wrapped value.

#![no_main]

use asupersync::http::h1::codec::{HttpError, fuzz_parse_chunk_size_line};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const MAX_INPUT_LEN: usize = 4096;
const BAD_CHUNKED_ENCODING_DISPLAY: &str = "malformed chunked encoding";

static FIXED_CANARIES: OnceLock<()> = OnceLock::new();

fn assert_bad_chunked_encoding(error: HttpError) {
    assert!(
        matches!(error, HttpError::BadChunkedEncoding),
        "chunk-size parser should fail closed with BadChunkedEncoding, got {error:?}"
    );
    assert_eq!(
        error.to_string(),
        BAD_CHUNKED_ENCODING_DISPLAY,
        "chunk-size parser should preserve the exact BadChunkedEncoding diagnostic"
    );
}

fn observe_chunk_size_parse(data: &[u8]) {
    match fuzz_parse_chunk_size_line(data) {
        Ok(parsed) => {
            let text = std::str::from_utf8(data).expect("successful parse requires UTF-8");
            let size_part = text
                .split(';')
                .next()
                .expect("split always yields a first chunk-size field");

            assert!(
                !size_part.is_empty(),
                "successful parse must have a non-empty chunk-size"
            );
            assert!(
                !size_part
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_whitespace),
                "successful parse must reject leading whitespace"
            );
            assert!(
                !size_part
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_whitespace),
                "successful parse must reject trailing whitespace"
            );
            assert!(
                size_part.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "successful parse must only accept hex chunk-size digits"
            );
            assert_eq!(
                usize::from_str_radix(size_part, 16).expect("validated hex size should fit"),
                parsed,
                "parser result should match the hexadecimal chunk-size field"
            );
        }
        Err(error) => {
            assert_bad_chunked_encoding(error);
        }
    }
}

fn assert_fixed_chunk_size_canaries() {
    // The parser receives the field bytes after CRLF splitting.
    for (candidate, expected) in [
        (b"0".as_ref(), 0),
        (b"1".as_ref(), 1),
        (b"ff".as_ref(), 255),
        (b"FF".as_ref(), 255),
        (b"aA; ext=val".as_ref(), 170),
        (b"1;\0ignored-extension".as_ref(), 1),
    ] {
        assert_eq!(
            fuzz_parse_chunk_size_line(candidate).expect("valid chunk-size candidate"),
            expected
        );
        observe_chunk_size_parse(candidate);
    }

    let max_usize = format!("{:X}", usize::MAX);
    assert_eq!(
        fuzz_parse_chunk_size_line(max_usize.as_bytes())
            .expect("usize::MAX hexadecimal chunk-size should parse"),
        usize::MAX
    );
    observe_chunk_size_parse(max_usize.as_bytes());

    let overflow = format!("{max_usize}0");
    for candidate in [
        b"".as_ref(),
        b"\r\n".as_ref(),
        b"+1".as_ref(),
        b"-1".as_ref(),
        b" 1".as_ref(),
        b"1 ".as_ref(),
        b"xyz".as_ref(),
        b"1\0".as_ref(),
        b"\xff".as_ref(),
        b"100000000000000000000000000000000".as_ref(),
        overflow.as_bytes(),
    ] {
        let error = fuzz_parse_chunk_size_line(candidate)
            .expect_err("malformed chunk-size candidate should be rejected");
        assert_bad_chunked_encoding(error);
        observe_chunk_size_parse(candidate);
    }
}

fuzz_target!(|data: &[u8]| {
    FIXED_CANARIES.get_or_init(assert_fixed_chunk_size_canaries);

    if data.len() > MAX_INPUT_LEN {
        return;
    }

    observe_chunk_size_parse(data);
});
