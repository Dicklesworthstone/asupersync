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

const MAX_INPUT_LEN: usize = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    let _ = fuzz_parse_chunk_size_line(data);

    // The parser receives the field bytes after CRLF splitting.
    for (candidate, expected) in [
        (b"0".as_ref(), 0),
        (b"1".as_ref(), 1),
        (b"ff".as_ref(), 255),
        (b"FF".as_ref(), 255),
        (b"aA; ext=val".as_ref(), 170),
    ] {
        assert_eq!(
            fuzz_parse_chunk_size_line(candidate).expect("valid chunk-size candidate"),
            expected
        );
    }

    for candidate in [
        b"".as_ref(),
        b"\r\n".as_ref(),
        b"+1".as_ref(),
        b"-1".as_ref(),
        b" 1".as_ref(),
        b"1 ".as_ref(),
        b"xyz".as_ref(),
        b"1\0".as_ref(),
        b"100000000000000000000000000000000".as_ref(),
    ] {
        assert!(matches!(
            fuzz_parse_chunk_size_line(candidate),
            Err(HttpError::BadChunkedEncoding)
        ));
    }
});
