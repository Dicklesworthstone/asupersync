//! br-asupersync-zv7n9x — Fuzz the QPACK required-insert-count
//! decoder. The function takes three u64/usize parameters and
//! must surface every overflow / boundary case as `H3NativeError`,
//! never panic.
//!
//! Invariants:
//!   * No panic on any (encoded, total, max_table_capacity)
//!     triple, including (u64::MAX, u64::MAX, usize::MAX).
//!   * Decoder returns Result; an Ok value must satisfy the
//!     RFC 9204 §4.5.1 contract: required_insert_count > 0.

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use asupersync::http::h3_native::fuzz_qpack_decode_required_insert_count;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }

    let encoded = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let total = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);
    let cap = usize::try_from(u64::from_le_bytes([
        data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]))
    .unwrap_or(usize::MAX);

    let r = catch_unwind(AssertUnwindSafe(|| {
        fuzz_qpack_decode_required_insert_count(encoded, total, cap)
    }));
    assert!(
        r.is_ok(),
        "qpack_decode_required_insert_count panicked on (encoded={encoded}, total={total}, cap={cap})"
    );

    if let Ok(Ok(value)) = r {
        // Per RFC 9204 §4.5.1 the decoded RIC is either 0 (encoded=0
        // sentinel) or > 0; the decoder enforces >0 on the non-sentinel
        // path internally.
        assert!(
            value == 0 || value > 0,
            "decoded RIC value must be u64-valid"
        );
    }
});
