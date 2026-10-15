//! br-asupersync-mbn0uo — Fuzz the H3 status-code parser
//! (`fuzz_parse_status_code`). Asserts no panic on adversarial
//! UTF-8 input including bidi U+202E, embedded NUL, leading
//! whitespace, hex/octal prefixes, and i32::MAX boundary values.

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use asupersync::http::h3_native::fuzz_parse_status_code;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    let s = String::from_utf8_lossy(data).into_owned();
    let r = catch_unwind(AssertUnwindSafe(|| fuzz_parse_status_code(&s)));
    assert!(r.is_ok(), "parse_status_code panicked on {} bytes", s.len());

    if let Ok(Ok(code)) = r {
        // RFC 9110: status codes are 3 digits. Parser must never
        // return a value outside [100, 999].
        assert!(
            (100..=999).contains(&code),
            "parse_status_code returned out-of-range value: {code}"
        );
    }

    // Stress: append boundary suffixes.
    for suffix in &["", "0", "9", "00", "99", "999", "1000", "65535", "-1"] {
        let combined = format!("{s}{suffix}");
        if combined.len() > MAX_INPUT_LEN {
            continue;
        }
        let r = catch_unwind(AssertUnwindSafe(|| fuzz_parse_status_code(&combined)));
        assert!(r.is_ok());
    }
});
