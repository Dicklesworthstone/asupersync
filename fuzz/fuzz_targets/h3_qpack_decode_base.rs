//! br-asupersync-czy6d8 — Fuzz the QPACK base decoder. Three u64 /
//! bool inputs; both paths (positive sign, negative sign) must
//! surface overflow/underflow as `H3NativeError`, never panic.
//!
//! Invariants:
//!   * No panic on any (RIC, sign, delta_base) triple, including
//!     (0, true, u64::MAX) and (u64::MAX, false, u64::MAX).
//!   * On the negative-sign path, `delta_base + 1` is computed
//!     internally and must return an error rather than panic on
//!     overflow.
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

    observe_decode_base(ric, sign, delta);

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
        observe_decode_base(*r, *s, *d);
    }
});

fn observe_decode_base(ric: u64, sign: bool, delta: u64) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        fuzz_qpack_decode_base(ric, sign, delta)
    }));
    let outcome = result.unwrap_or_else(|_| {
        panic!("qpack_decode_base panicked on (ric={ric}, sign={sign}, delta={delta})")
    });

    match outcome {
        Ok(base) => {
            if sign {
                assert!(
                    base < ric,
                    "negative-sign decode base must be below RIC; ric={ric}, delta={delta}, base={base}"
                );
            } else {
                assert!(
                    base >= ric,
                    "positive-sign decode base must be at or above RIC; ric={ric}, delta={delta}, base={base}"
                );
            }
        }
        Err(err) => {
            let diagnostic = err.to_string();
            assert!(
                !diagnostic.trim().is_empty(),
                "qpack_decode_base error diagnostics must be non-empty"
            );
        }
    }
}
