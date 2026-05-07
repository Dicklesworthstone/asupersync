//! br-asupersync-zepgmq — Fuzz `H1 parse_header_line_bounds`
//! against adversarial header-line bytes: missing colon, leading
//! colon (empty name), CR/LF in name or value, embedded NUL,
//! invalid tchar bytes (0x00..=0x20 + DEL + separator chars per
//! RFC 7230), oversized lines.
//!
//! Invariants:
//!   * Parser panics, if any, surface directly to libFuzzer.
//!   * Parser returns Result; the (name_end, value_start, value_end)
//!     triple, when Ok, must satisfy
//!     name_end <= value_start <= value_end <= line.len().

#![no_main]

use asupersync::http::h1::codec::fuzz_parse_header_line_bounds;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 8192;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    assert_consistent_bounds(data);

    // Stress: append boundary suffixes to the random input.
    for suffix in &[b": value".as_ref(), b":\r\n".as_ref(), b"\r\n\r\n".as_ref()] {
        let mut combined = data.to_vec();
        combined.extend_from_slice(suffix);
        if combined.len() > MAX_INPUT_LEN {
            continue;
        }
        assert_consistent_bounds(&combined);
    }
});

fn assert_consistent_bounds(line: &[u8]) {
    if let Ok((name_end, value_start, value_end)) = fuzz_parse_header_line_bounds(line) {
        assert!(
            name_end <= value_start && value_start <= value_end && value_end <= line.len(),
            "parse_header_line_bounds returned inconsistent indices: \
             name_end={name_end}, value_start={value_start}, value_end={value_end}, len={}",
            line.len()
        );
    }
}
