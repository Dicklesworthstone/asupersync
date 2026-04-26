//! br-asupersync-czy6d8 — Fuzz the QPACK base decoder. Three u64 /
//! bool inputs; both paths (positive sign, negative sign) must
//! surface overflow/underflow as `H3NativeError`, never panic.
//!
//! Invariants:
//!   * No panic on any (RIC, sign, delta_base) triple, including
//!     (0, true, u64::MAX) and (u64::MAX, false, u64::MAX).
//!   * On the negative-sign path, `delta_base + 1` is computed
//!     internally and must not panic on overflow (the implementation
//!     uses unchecked + 1 then checked_sub, but the +1 itself can
//!     panic on `delta_base = u64::MAX`).
//!   * Result must be either Ok(u64) or Err.

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use asupersync::http::h3_native::fuzz_qpack_decode_base;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 17 {
        return;
    }

    let ric = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let sign = (data[8] & 1) != 0;
    let delta = u64::from_le_bytes([
        data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
    ]);

    let r = catch_unwind(AssertUnwindSafe(|| {
        fuzz_qpack_decode_base(ric, sign, delta)
    }));
    assert!(
        r.is_ok(),
        "qpack_decode_base panicked on (ric={ric}, sign={sign}, delta={delta})"
    );

    // Boundary triples that exercise overflow paths.
    let boundary = [
        (0u64, true, u64::MAX),
        (u64::MAX, false, u64::MAX),
        (u64::MAX, false, 0),
        (0, false, 0),
        (1, true, 0),
        (1, true, 1),
    ];
    for (r, s, d) in &boundary {
        let result = catch_unwind(AssertUnwindSafe(|| fuzz_qpack_decode_base(*r, *s, *d)));
        assert!(
            result.is_ok(),
            "panicked on boundary (ric={r}, sign={s}, delta={d})"
        );
    }
});
