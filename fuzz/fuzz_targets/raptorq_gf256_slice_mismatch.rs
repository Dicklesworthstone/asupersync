//! br-asupersync-i9d6b6 — Fuzz `gf256_add_slice`, `gf256_addmul_slice`,
//! `gf256_add_slices2`, `gf256_addmul_slices2`, `gf256_mul_slices2`
//! with deliberately mismatched slice lengths.
//!
//! Invariants asserted:
//!   1. Length-mismatched calls panic with the documented
//!      "slice length mismatch" assertion message. They MUST NOT
//!      silently succeed, MUST NOT produce out-of-bounds reads/writes,
//!      and MUST NOT hang.
//!   2. Length-matched calls of any size (including 0 and 1) must
//!      not panic — that's the happy-path invariant, included here so
//!      the fuzzer also exercises edge sizes alongside the panic
//!      paths.
//!   3. SIMD and scalar dispatch paths must agree: for length-matched
//!      `gf256_add_slice`, the result must equal byte-wise XOR.

#![no_main]

use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};

use asupersync::raptorq::gf256::{
    Gf256, gf256_add_slice, gf256_add_slices2, gf256_addmul_slice, gf256_addmul_slices2,
    gf256_mul_slices2,
};
use libfuzzer_sys::fuzz_target;

const MAX_SLICE_LEN: usize = 4096;
const SLICE_MISMATCH_PANIC: &str = "slice length mismatch";

fn panic_payload_contains(payload: &(dyn Any + Send), needle: &str) -> bool {
    payload
        .downcast_ref::<String>()
        .is_some_and(|message| message.contains(needle))
        || payload
            .downcast_ref::<&'static str>()
            .is_some_and(|message| message.contains(needle))
}

fn assert_slice_mismatch_panic(label: &str, f: impl FnOnce()) {
    let result = catch_unwind(AssertUnwindSafe(f));
    match result {
        Ok(()) => panic!("{label} silently accepted mismatched slice lengths"),
        Err(payload) => assert!(
            panic_payload_contains(payload.as_ref(), SLICE_MISMATCH_PANIC),
            "{label} panicked without documented mismatch message"
        ),
    }
}

fn addmul_expected(dst: &[u8], src: &[u8], coef: u8) -> Vec<u8> {
    dst.iter()
        .zip(src)
        .map(|(d, s)| *d ^ Gf256::new(*s).mul_field(Gf256::new(coef)).raw())
        .collect()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Pull two length-controlling bytes; the rest is byte material.
    let len_a_byte = data[0];
    let len_b_byte = data[1];
    let coef = data[2];
    let payload = &data[3..];

    let len_a = (len_a_byte as usize) % (MAX_SLICE_LEN + 1);
    let len_b = (len_b_byte as usize) % (MAX_SLICE_LEN + 1);
    if payload.len() < len_a + len_b {
        return;
    }

    // === Mismatched length: gf256_add_slice ===
    if len_a != len_b {
        let mut dst = payload[..len_a].to_vec();
        let src: Vec<u8> = payload[len_a..len_a + len_b].to_vec();
        assert_slice_mismatch_panic("gf256_add_slice", || gf256_add_slice(&mut dst, &src));
    }

    // === Mismatched length: gf256_addmul_slice ===
    if len_a != len_b {
        let mut dst = payload[..len_a].to_vec();
        let src: Vec<u8> = payload[len_a..len_a + len_b].to_vec();
        assert_slice_mismatch_panic("gf256_addmul_slice", || {
            gf256_addmul_slice(&mut dst, &src, Gf256::new(coef));
        });
    }

    // === Mismatched length on slices2 helpers ===
    // Each public two-lane helper checks both destination/source pairs before
    // dispatch, so either lane mismatch must surface the documented panic.
    if len_a != len_b {
        let matched_len = len_a.min(len_b);
        let mut dst_a = payload[..len_a].to_vec();
        let src_a: Vec<u8> = payload[len_a..len_a + len_b].to_vec();

        let mut dst_b = payload[..matched_len].to_vec();
        let src_b = payload[..matched_len].to_vec();
        assert_slice_mismatch_panic("gf256_add_slices2 first lane", || {
            gf256_add_slices2(&mut dst_a, &src_a, &mut dst_b, &src_b);
        });

        let mut dst_a = payload[..matched_len].to_vec();
        let src_a = payload[..matched_len].to_vec();
        let mut dst_b = payload[..len_a].to_vec();
        let src_b: Vec<u8> = payload[len_a..len_a + len_b].to_vec();
        assert_slice_mismatch_panic("gf256_add_slices2 second lane", || {
            gf256_add_slices2(&mut dst_a, &src_a, &mut dst_b, &src_b);
        });

        let mut dst_a = payload[..len_a].to_vec();
        let src_a: Vec<u8> = payload[len_a..len_a + len_b].to_vec();
        let mut dst_b = payload[..matched_len].to_vec();
        let src_b = payload[..matched_len].to_vec();
        assert_slice_mismatch_panic("gf256_addmul_slices2 first lane", || {
            gf256_addmul_slices2(&mut dst_a, &src_a, &mut dst_b, &src_b, Gf256::new(coef));
        });

        let mut dst_a = payload[..matched_len].to_vec();
        let src_a = payload[..matched_len].to_vec();
        let mut dst_b = payload[..len_a].to_vec();
        let src_b: Vec<u8> = payload[len_a..len_a + len_b].to_vec();
        assert_slice_mismatch_panic("gf256_addmul_slices2 second lane", || {
            gf256_addmul_slices2(&mut dst_a, &src_a, &mut dst_b, &src_b, Gf256::new(coef));
        });
    }

    // === Length-matched happy-path: must not panic, result is XOR ===
    if payload.len() >= 2 * len_a {
        let mut dst = payload[..len_a].to_vec();
        let src: Vec<u8> = payload[len_a..2 * len_a].to_vec();
        let expected: Vec<u8> = dst.iter().zip(src.iter()).map(|(d, s)| d ^ s).collect();
        gf256_add_slice(&mut dst, &src);
        assert_eq!(dst, expected, "gf256_add_slice must equal byte-wise XOR");

        let mut dst = payload[..len_a].to_vec();
        let expected = addmul_expected(&dst, &src, coef);
        gf256_addmul_slice(&mut dst, &src, Gf256::new(coef));
        assert_eq!(
            dst, expected,
            "gf256_addmul_slice must equal byte-wise addmul"
        );
    }

    if payload.len() >= 4 * len_a {
        let mut dst_a = payload[..len_a].to_vec();
        let src_a = payload[len_a..2 * len_a].to_vec();
        let mut dst_b = payload[2 * len_a..3 * len_a].to_vec();
        let src_b = payload[3 * len_a..4 * len_a].to_vec();
        let expected_a: Vec<u8> = dst_a.iter().zip(&src_a).map(|(d, s)| d ^ s).collect();
        let expected_b: Vec<u8> = dst_b.iter().zip(&src_b).map(|(d, s)| d ^ s).collect();
        gf256_add_slices2(&mut dst_a, &src_a, &mut dst_b, &src_b);
        assert_eq!(dst_a, expected_a, "gf256_add_slices2 lane A mismatch");
        assert_eq!(dst_b, expected_b, "gf256_add_slices2 lane B mismatch");

        let mut dst_a = payload[..len_a].to_vec();
        let src_a = payload[len_a..2 * len_a].to_vec();
        let mut dst_b = payload[2 * len_a..3 * len_a].to_vec();
        let src_b = payload[3 * len_a..4 * len_a].to_vec();
        let expected_a = addmul_expected(&dst_a, &src_a, coef);
        let expected_b = addmul_expected(&dst_b, &src_b, coef);
        gf256_addmul_slices2(&mut dst_a, &src_a, &mut dst_b, &src_b, Gf256::new(coef));
        assert_eq!(dst_a, expected_a, "gf256_addmul_slices2 lane A mismatch");
        assert_eq!(dst_b, expected_b, "gf256_addmul_slices2 lane B mismatch");
    }

    // gf256_mul_slices2 has no src parameters; just exercises non-panic
    // on degenerate sizes.
    if len_a > 0 && len_a == len_b && payload.len() >= 2 * len_a {
        let mut dst_a = payload[..len_a].to_vec();
        let mut dst_b = payload[len_a..2 * len_a].to_vec();
        let r = catch_unwind(AssertUnwindSafe(|| {
            gf256_mul_slices2(&mut dst_a, &mut dst_b, Gf256::new(coef));
        }));
        assert!(
            r.is_ok(),
            "gf256_mul_slices2 panicked on length-matched inputs"
        );
    }
});
