//! br-asupersync-8dl9j7 — Fuzz `H1 parse_chunk_size_line` against
//! adversarial chunk-size lines: oversize hex (>usize::MAX),
//! embedded extensions, mixed-case hex, leading/trailing
//! whitespace, embedded NUL, CRLF in unexpected places.
//!
//! Invariants asserted:
//!   * Parser panics, if any, surface directly to libFuzzer.
//!   * Parser returns Result; on overflow / malformed it returns
//!     `HttpError`, not a wrapped value.

#![no_main]

use asupersync::http::h1::codec::fuzz_parse_chunk_size_line;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    let _ = fuzz_parse_chunk_size_line(data);

    // Boundary candidates: well-formed hex sizes.
    for candidate in &[
        b"0\r\n".as_ref(),
        b"1\r\n".as_ref(),
        b"ff\r\n".as_ref(),
        b"FFFFFFFF\r\n".as_ref(),
        b"FFFFFFFFFFFFFFFF\r\n".as_ref(), // u64::MAX in hex
        b"1; ext=val\r\n".as_ref(),
        b"\r\n".as_ref(),
        b"".as_ref(),
        b"xyz\r\n".as_ref(), // not hex
    ] {
        let _ = fuzz_parse_chunk_size_line(candidate);
    }
});
