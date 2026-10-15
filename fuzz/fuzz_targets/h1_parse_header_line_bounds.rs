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

use asupersync::http::h1::codec::{HttpError, fuzz_parse_header_line_bounds};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const MAX_INPUT_LEN: usize = 8192;

static FIXED_HEADER_LINE_CANARIES: OnceLock<()> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    FIXED_HEADER_LINE_CANARIES.get_or_init(assert_fixed_header_line_canaries);

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

fn assert_fixed_header_line_canaries() {
    assert_bounds(b"Host: example.com", 4, 6, b"Host: example.com".len());
    assert_bounds(b"X-Test:\t value \t", 6, 9, 14);
    assert_bounds(b"Accept:*/*", 6, 7, b"Accept:*/*".len());
    assert_bounds(b"Obs: \xFF", 3, 5, b"Obs: \xFF".len());

    assert_bad_header(b"MissingColon");
    assert_invalid_header_name(b": value");
    assert_invalid_header_name(b"Bad Name: value");
    assert_invalid_header_name(b"Bad(Name): value");
    assert_invalid_header_name(b"Bad\rName: value");

    assert_invalid_header_value(b"X: \r");
    assert_invalid_header_value(b"X: \n");
    assert_invalid_header_value(b"X: \0");
    assert_invalid_header_value(b"X: \x1F");
    assert_invalid_header_value(b"X: \x7F");
}

fn assert_bounds(
    line: &[u8],
    expected_name_end: usize,
    expected_value_start: usize,
    expected_value_end: usize,
) {
    let (name_end, value_start, value_end) =
        fuzz_parse_header_line_bounds(line).expect("valid header-line candidate");
    assert_eq!(
        name_end, expected_name_end,
        "name_end mismatch for {line:?}"
    );
    assert_eq!(
        value_start, expected_value_start,
        "value_start mismatch for {line:?}"
    );
    assert_eq!(
        value_end, expected_value_end,
        "value_end mismatch for {line:?}"
    );
}

fn assert_bad_header(line: &[u8]) {
    assert_header_error(
        line,
        matches_bad_header,
        "malformed header",
        "expected BadHeader for header-line candidate",
    );
}

fn assert_invalid_header_name(line: &[u8]) {
    assert_header_error(
        line,
        matches_invalid_header_name,
        "invalid header name",
        "expected InvalidHeaderName for header-line candidate",
    );
}

fn assert_invalid_header_value(line: &[u8]) {
    assert_header_error(
        line,
        matches_invalid_header_value,
        "invalid header value",
        "expected InvalidHeaderValue for header-line candidate",
    );
}

fn assert_header_error(
    line: &[u8],
    predicate: fn(&HttpError) -> bool,
    expected_display: &str,
    message: &str,
) {
    match fuzz_parse_header_line_bounds(line) {
        Err(error) if predicate(&error) => {
            assert_eq!(error.to_string(), expected_display, "{message}: {line:?}");
        }
        Ok(bounds) => panic!("{message}: unexpected bounds {bounds:?} for {line:?}"),
        Err(error) => panic!("{message}: unexpected error {error:?} for {line:?}"),
    }
}

fn matches_bad_header(error: &HttpError) -> bool {
    matches!(error, HttpError::BadHeader)
}

fn matches_invalid_header_name(error: &HttpError) -> bool {
    matches!(error, HttpError::InvalidHeaderName)
}

fn matches_invalid_header_value(error: &HttpError) -> bool {
    matches!(error, HttpError::InvalidHeaderValue)
}

fn assert_consistent_bounds(line: &[u8]) {
    match fuzz_parse_header_line_bounds(line) {
        Ok((name_end, value_start, value_end)) => {
            assert!(
                name_end <= value_start && value_start <= value_end && value_end <= line.len(),
                "parse_header_line_bounds returned inconsistent indices: \
                 name_end={name_end}, value_start={value_start}, value_end={value_end}, len={}",
                line.len()
            );
        }
        Err(err) => {
            assert!(
                !err.to_string().is_empty(),
                "header-line parser errors should be observable"
            );
        }
    }
}
