//! Conformance crate for `DenseRow::try_set` — the fallible, panic-free
//! GF(256) cell setter introduced by br-asupersync-tda3x0 as the DoS-hardened
//! sibling of [`DenseRow::set`].
//!
//! ## Why this surface matters (bd-3uox5)
//!
//! Production decode paths driven by network-supplied FEC-OTI schedules can
//! route an *attacker-chosen* column index into a dense row. The infallible
//! [`DenseRow::set`] panics on an out-of-range index — which, on adversarial
//! input, would crash the decoder process. `try_set` is the contract that lets
//! those paths surface the rejection as a decoder-level error instead. Before
//! this crate `try_set` had ZERO test references anywhere in the tree, so the
//! one property the whole hardening rests on — "errors exactly where `set`
//! would panic, and never mutates on rejection" — was unpinned.
//!
//! Every assertion here is oracle-free: it is derived from `try_set`'s own
//! definitional contract (write-or-reject) and cross-checked against the
//! infallible `set`/`get` it shadows. No decode run, no features required;
//! `DenseRow`, `DenseRowIndexError`, and `Gf256` are all ungated `pub`.
//!
//! Note: `Gf256` derives no `Debug`, so equality is asserted on `.raw()` (the
//! transparent `u8`) rather than on the field element directly.

use std::panic::{self, AssertUnwindSafe};

use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::linalg::{DenseRow, DenseRowIndexError};

/// A deterministic-but-varied byte for index `i` so rows are not uniform
/// (uniform rows would hide off-by-one writes against a zero background).
fn fill_byte(i: usize) -> u8 {
    // Coprime stride keeps the low bits cycling; +0x37 avoids an all-zero seed.
    ((i.wrapping_mul(167).wrapping_add(0x37)) & 0xFF) as u8
}

// ===========================================================================
// 1. In-bounds: returns Ok(()) and stores the raw byte verbatim.
// ===========================================================================

#[test]
fn try_set_in_bounds_returns_ok_and_stores_raw_byte() {
    let mut row = DenseRow::zeros(8);
    for i in 0..row.len() {
        let v = fill_byte(i);
        assert_eq!(
            row.try_set(i, Gf256::new(v)),
            Ok(()),
            "in-bounds try_set at {i} must succeed"
        );
        // Visible through every read surface, byte-identical.
        assert_eq!(row.get(i).raw(), v, "get must read back the written byte");
        assert_eq!(row.as_slice()[i], v, "slice must hold the written byte");
        assert_eq!(
            row.try_get(i).map(Gf256::raw),
            Some(v),
            "try_get must read back the written byte"
        );
    }
}

// ===========================================================================
// 2. Differential equivalence: on the in-bounds domain, try_set produces
//    byte-identical state to the infallible set it shadows.
// ===========================================================================

#[test]
fn try_set_is_byte_identical_to_set_on_in_bounds_domain() {
    for len in [1usize, 2, 3, 16, 64, 256] {
        let mut via_set = DenseRow::zeros(len);
        let mut via_try = DenseRow::zeros(len);
        for i in 0..len {
            let v = Gf256::new(fill_byte(i ^ (len << 1)));
            via_set.set(i, v);
            assert_eq!(
                via_try.try_set(i, v),
                Ok(()),
                "len={len} idx={i}: try_set must accept every in-bounds index"
            );
        }
        assert_eq!(
            via_set.as_slice(),
            via_try.as_slice(),
            "len={len}: try_set must reproduce set's resulting bytes exactly"
        );
    }
}

// ===========================================================================
// 3. Out-of-bounds: exact error payload, no panic, and NO mutation.
// ===========================================================================

#[test]
fn try_set_out_of_bounds_errors_exactly_without_mutating() {
    let len = 4;
    let mut row = DenseRow::new((0..len).map(fill_byte).collect());
    let before: Vec<u8> = row.as_slice().to_vec();

    for &bad in &[len, len + 1, 100, usize::MAX] {
        let err = row
            .try_set(bad, Gf256::new(0xAB))
            .expect_err("out-of-range index must be rejected, not written");
        // Exact payload: the requested index and the row's current length.
        assert_eq!(
            err,
            DenseRowIndexError { index: bad, len },
            "rejection must report the offending index and the live length"
        );
        // Fail-closed: a rejected write leaves the row byte-for-byte untouched.
        assert_eq!(
            row.as_slice(),
            before.as_slice(),
            "a rejected try_set must perform no partial mutation (idx={bad})"
        );
    }
}

// ===========================================================================
// 4. Empty row: every index is out of range; length reported is 0.
// ===========================================================================

#[test]
fn try_set_on_empty_row_always_rejects_with_len_zero() {
    for mut row in [DenseRow::new(Vec::new()), DenseRow::zeros(0)] {
        assert!(row.is_empty(), "precondition: the row is empty");
        for &idx in &[0usize, 1, 7, usize::MAX] {
            assert_eq!(
                row.try_set(idx, Gf256::ONE),
                Err(DenseRowIndexError { index: idx, len: 0 }),
                "empty row must reject index {idx} with len=0"
            );
        }
        assert!(row.is_empty(), "rejected writes must not grow the row");
    }
}

// ===========================================================================
// 5. The accept/reject boundary sits exactly at `index < len`.
// ===========================================================================

#[test]
fn try_set_boundary_is_last_valid_vs_first_invalid_index() {
    for len in [1usize, 2, 3, 16, 256] {
        let mut row = DenseRow::zeros(len);
        // Last valid index succeeds and writes.
        let last = len - 1;
        assert_eq!(
            row.try_set(last, Gf256::new(0x5A)),
            Ok(()),
            "len={len}: index len-1 must be accepted"
        );
        assert_eq!(row.get(last).raw(), 0x5A);
        // First invalid index (== len) is rejected with the live length.
        assert_eq!(
            row.try_set(len, Gf256::new(0x5A)),
            Err(DenseRowIndexError { index: len, len }),
            "len={len}: index len must be the first rejected index"
        );
    }
}

// ===========================================================================
// 6. Repeated writes to the same slot are last-write-wins.
// ===========================================================================

#[test]
fn try_set_same_index_is_last_write_wins() {
    let mut row = DenseRow::zeros(5);
    let writes = [0x11u8, 0x00, 0xFF, 0x42, 0x42, 0x01];
    for &w in &writes {
        assert_eq!(row.try_set(2, Gf256::new(w)), Ok(()));
        assert_eq!(row.get(2).raw(), w, "each accepted write must take effect");
    }
    // Other slots untouched by the repeated writes to slot 2.
    for i in [0usize, 1, 3, 4] {
        assert_eq!(row.get(i).raw(), 0, "slot {i} must remain its initial zero");
    }
}

// ===========================================================================
// 7. Locality: an accepted write mutates only the targeted slot.
// ===========================================================================

#[test]
fn try_set_mutates_only_the_target_slot() {
    let len = 8;
    let mut row = DenseRow::new((0..len).map(fill_byte).collect());
    let mut expected: Vec<u8> = row.as_slice().to_vec();

    let target = 3;
    let new_val = 0xC3;
    assert_eq!(row.try_set(target, Gf256::new(new_val)), Ok(()));
    expected[target] = new_val;

    assert_eq!(
        row.as_slice(),
        expected.as_slice(),
        "only the targeted slot may change; all others stay put"
    );
}

// ===========================================================================
// 8. Metamorphic: try_set errors EXACTLY where set panics. This is the
//    security contract — try_set is the faithful non-panicking sibling.
// ===========================================================================

#[test]
fn try_set_error_boundary_equals_set_panic_boundary() {
    let len = 6;
    // Suppress the default panic hook for the duration so probing `set`'s
    // panic boundary does not spam stderr; restore it afterward so concurrent
    // and subsequent tests keep their normal diagnostics.
    let prev = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    for idx in 0..(len + 4) {
        // `set` panics on out-of-range; clone per-probe so a write that
        // precedes a panic (there is none — `set` asserts first — but be
        // defensive) cannot leak across probes.
        let mut probe_set = DenseRow::zeros(len);
        let set_panicked = panic::catch_unwind(AssertUnwindSafe(|| {
            probe_set.set(idx, Gf256::new(0x9E));
        }))
        .is_err();

        let mut probe_try = DenseRow::zeros(len);
        let try_errored = probe_try.try_set(idx, Gf256::new(0x9E)).is_err();

        assert_eq!(
            set_panicked, try_errored,
            "idx={idx}: try_set must reject iff set would panic (boundary parity)"
        );
    }

    panic::set_hook(prev);
}

// ===========================================================================
// 9. Value fidelity across the full GF(256) value range.
// ===========================================================================

#[test]
fn try_set_round_trips_every_gf256_value() {
    let mut row = DenseRow::zeros(256);
    for v in 0u16..=255 {
        let v = v as u8;
        assert_eq!(row.try_set(v as usize, Gf256::new(v)), Ok(()));
    }
    for v in 0u16..=255 {
        let v = v as u8;
        let i = v as usize;
        assert_eq!(row.get(i).raw(), v, "get fidelity for value {v}");
        assert_eq!(
            row.try_get(i).map(Gf256::raw),
            Some(v),
            "try_get fidelity for {v}"
        );
        assert_eq!(row.as_slice()[i], v, "slice fidelity for value {v}");
    }
}

// ===========================================================================
// 10. The error type itself: payload, Copy, and value equality.
// ===========================================================================

#[test]
fn dense_row_index_error_payload_is_exact_and_copyable() {
    let mut row = DenseRow::zeros(3);
    let err = row
        .try_set(9, Gf256::new(0x01))
        .expect_err("index 9 in a length-3 row must be rejected");

    assert_eq!(err.index, 9, "error carries the requested index");
    assert_eq!(err.len, 3, "error carries the row's current length");

    // `DenseRowIndexError` is Copy + PartialEq: a structural twin compares equal,
    // and reading the original after copying it out is still valid.
    let twin = DenseRowIndexError { index: 9, len: 3 };
    let copied = err;
    assert_eq!(err, twin, "value equality against a structural twin");
    assert_eq!(
        copied, err,
        "Copy preserves the payload and leaves the source live"
    );

    // A different index or length is a distinct error value.
    assert_ne!(err, DenseRowIndexError { index: 9, len: 4 });
    assert_ne!(err, DenseRowIndexError { index: 8, len: 3 });
}
