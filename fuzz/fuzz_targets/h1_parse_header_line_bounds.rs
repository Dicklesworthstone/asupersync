//! br-asupersync-zepgmq — Fuzz `H1 parse_header_line_bounds`
//! against adversarial header-line bytes: missing colon, leading
//! colon (empty name), CR/LF in name or value, embedded NUL,
//! invalid tchar bytes (0x00..=0x20 + DEL + separator chars per
//! RFC 7230), oversized lines.
//!
//! Invariants:
//!   * No panic on any byte sequence (header-line is on the parse
//!     hot path of every HTTP/1 request — a panic here is a
//!     remote DoS).
//!   * Parser returns Result; the (name_end, value_start, value_end)
//!     triple, when Ok, must satisfy
//!     name_end <= value_start <= value_end <= line.len().

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use asupersync::http::h1::codec::fuzz_parse_header_line_bounds;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 8192;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    let r = catch_unwind(AssertUnwindSafe(|| fuzz_parse_header_line_bounds(data)));
    assert!(
        r.is_ok(),
        "parse_header_line_bounds panicked on {} bytes",
        data.len()
    );

    if let Ok(Ok((name_end, value_start, value_end))) = r {
        assert!(
            name_end <= value_start && value_start <= value_end && value_end <= data.len(),
            "parse_header_line_bounds returned inconsistent indices: \
             name_end={name_end}, value_start={value_start}, value_end={value_end}, len={}",
            data.len()
        );
    }

    // Stress: append boundary suffixes to the random input.
    for suffix in &[b": value".as_ref(), b":\r\n".as_ref(), b"\r\n\r\n".as_ref()] {
        let mut combined = data.to_vec();
        combined.extend_from_slice(suffix);
        if combined.len() > MAX_INPUT_LEN {
            continue;
        }
        let r = catch_unwind(AssertUnwindSafe(|| {
            fuzz_parse_header_line_bounds(&combined)
        }));
        assert!(r.is_ok());
    }
});
