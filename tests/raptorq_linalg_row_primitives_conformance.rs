//! RaptorQ linalg: low-level GF(256) row-primitive conformance.
//!
//! Bead bd-3uox5 (RAPTORQ-RFC6330). Pins the zero-allocation slice primitives in
//! `raptorq::linalg` that Gaussian elimination is built on and that had ZERO
//! integration coverage: `row_xor`, `row_scale`, `row_swap`, `row_nonzero_count`,
//! and `row_first_nonzero_from`.
//!
//! Strategy: algebraic + differential against an independent oracle. The
//! scale/add behaviour is cross-checked against the heavily tested
//! `row_scale_add` kernel via two field identities that route through a
//! *different* call shape:
//!   * `row_xor(dst, src)`        ≡ `row_scale_add(dst, src, 1)`   (XOR is +)
//!   * `row_scale(row, c)`        ≡ `row_scale_add(0, row, c)`     (c·row = 0 + c·row)
//!
//! plus the GF(256) group laws that need no oracle at all (XOR involution,
//! scale by 1 = identity, scale by 0 = zero, scale by `c` then `c⁻¹` = identity).
//!
//! The index/count helpers are checked differentially against naive scans.
//!
//! Every test is pure and deterministic (no runtime, no entropy — a seeded LCG
//! drives inputs).
//!
//! Repro: `cargo test -p asupersync --test raptorq_linalg_row_primitives_conformance`

use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::linalg::{
    DenseRow, row_first_nonzero_from, row_nonzero_count, row_scale, row_scale_add, row_swap,
    row_xor,
};

/// Deterministic LCG (Knuth MMIX constants) for reproducible row generation.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

/// Builds a pseudo-random byte row. `density` is the per-byte probability (out
/// of 256) that a position carries a (possibly zero) value; the rest are forced
/// to zero so sparse rows are exercised by the count/index helpers.
fn random_row(len: usize, seed: u64, density: u8) -> Vec<u8> {
    let mut s = seed ^ 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            let r = lcg(&mut s);
            if (r & 0xFF) < u64::from(density) {
                (r >> 23) as u8
            } else {
                0
            }
        })
        .collect()
}

const LENS: [usize; 7] = [0, 1, 7, 16, 31, 32, 129];
const DENSITIES: [u8; 4] = [8, 64, 160, 255];
const SCALARS: [u8; 6] = [0, 1, 2, 7, 128, 255];

// ---------------------------------------------------------------------------
// row_xor: XOR is GF(256) addition.
// ---------------------------------------------------------------------------

#[test]
fn row_xor_equals_scale_add_by_one() {
    for &len in &LENS {
        for &density in &DENSITIES {
            for seed in 0..16u64 {
                let mut dst_x = random_row(len, seed, density);
                let src = random_row(len, seed ^ 0x55, density);

                let mut dst_ref = dst_x.clone();
                row_scale_add(&mut dst_ref, &src, Gf256::ONE);
                row_xor(&mut dst_x, &src);

                assert_eq!(
                    dst_x, dst_ref,
                    "row_xor != row_scale_add(·, ·, 1) (len={len}, density={density}, seed={seed})"
                );
            }
        }
    }
}

#[test]
fn row_xor_is_involutive_and_self_cancels() {
    for &len in &LENS {
        for seed in 0..16u64 {
            let original = random_row(len, seed, 200);
            let src = random_row(len, seed ^ 0x11, 200);

            // Applying the same XOR twice restores the original.
            let mut dst = original.clone();
            row_xor(&mut dst, &src);
            row_xor(&mut dst, &src);
            assert_eq!(
                dst, original,
                "row_xor not involutive (len={len}, seed={seed})"
            );

            // XOR with self yields the zero row (a ^ a = 0).
            let mut self_x = original.clone();
            let copy = original.clone();
            row_xor(&mut self_x, &copy);
            assert!(
                self_x.iter().all(|&b| b == 0),
                "row_xor with self must zero the row (len={len}, seed={seed})"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// row_scale: in-place GF(256) scalar multiply.
// ---------------------------------------------------------------------------

#[test]
fn row_scale_equals_scale_add_into_zero() {
    for &len in &LENS {
        for &density in &DENSITIES {
            for &raw_c in &SCALARS {
                for seed in 0..8u64 {
                    let c = Gf256::new(raw_c);
                    let row = random_row(len, seed, density);

                    // Oracle: 0 + c·row, via the tested addmul kernel.
                    let mut oracle = vec![0u8; len];
                    row_scale_add(&mut oracle, &row, c);

                    let mut scaled = row.clone();
                    row_scale(&mut scaled, c);

                    assert_eq!(
                        scaled, oracle,
                        "row_scale != 0 + c·row (len={len}, density={density}, c={raw_c}, seed={seed})"
                    );
                }
            }
        }
    }
}

#[test]
fn row_scale_group_laws() {
    for &len in &LENS {
        for seed in 0..12u64 {
            let row = random_row(len, seed, 220);

            // Scale by 1 is the identity.
            let mut by_one = row.clone();
            row_scale(&mut by_one, Gf256::ONE);
            assert_eq!(by_one, row, "row_scale by 1 must be identity (len={len})");

            // Scale by 0 yields the zero row.
            let mut by_zero = row.clone();
            row_scale(&mut by_zero, Gf256::ZERO);
            assert!(
                by_zero.iter().all(|&b| b == 0),
                "row_scale by 0 must zero the row (len={len})"
            );

            // Scale by c then by c⁻¹ restores the original (c != 0).
            for &raw_c in &[2u8, 7, 128, 255] {
                let c = Gf256::new(raw_c);
                let mut rt = row.clone();
                row_scale(&mut rt, c);
                row_scale(&mut rt, c.inv());
                assert_eq!(
                    rt, row,
                    "row_scale by c then c⁻¹ must restore original (len={len}, c={raw_c})"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// row_swap / DenseRow::swap: content exchange.
// ---------------------------------------------------------------------------

#[test]
fn row_swap_exchanges_and_is_involutive() {
    for &len in &LENS {
        for seed in 0..16u64 {
            let a0 = random_row(len, seed, 200);
            let b0 = random_row(len, seed ^ 0x77, 200);

            let mut a = a0.clone();
            let mut b = b0.clone();
            row_swap(&mut a, &mut b);
            assert_eq!(a, b0, "row_swap: a must become old b (len={len})");
            assert_eq!(b, a0, "row_swap: b must become old a (len={len})");

            // Swapping again restores both.
            row_swap(&mut a, &mut b);
            assert_eq!(a, a0, "row_swap not involutive on a (len={len})");
            assert_eq!(b, b0, "row_swap not involutive on b (len={len})");
        }
    }
}

#[test]
fn dense_row_swap_matches_free_function() {
    for &len in &LENS {
        for seed in 0..12u64 {
            let a0 = random_row(len, seed, 200);
            let b0 = random_row(len, seed ^ 0x33, 200);

            let mut a = DenseRow::new(a0.clone());
            let mut b = DenseRow::new(b0.clone());
            a.swap(&mut b);

            assert_eq!(
                a.as_slice(),
                b0.as_slice(),
                "DenseRow::swap: a must become old b"
            );
            assert_eq!(
                b.as_slice(),
                a0.as_slice(),
                "DenseRow::swap: b must become old a"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// row_nonzero_count / row_first_nonzero_from: differential vs naive scans.
// ---------------------------------------------------------------------------

#[test]
fn row_nonzero_count_matches_naive() {
    for &len in &LENS {
        for &density in &DENSITIES {
            for seed in 0..16u64 {
                let row = random_row(len, seed, density);
                let naive = row.iter().filter(|&&b| b != 0).count();
                assert_eq!(
                    row_nonzero_count(&row),
                    naive,
                    "row_nonzero_count mismatch (len={len}, density={density}, seed={seed})"
                );
            }
        }
    }
}

#[test]
fn row_first_nonzero_from_matches_naive() {
    for &len in &LENS {
        for &density in &DENSITIES {
            for seed in 0..12u64 {
                let row = random_row(len, seed, density);
                // Sweep every start including out-of-range (len, len+1).
                for start in 0..=len + 1 {
                    let naive = if start >= row.len() {
                        None
                    } else {
                        row[start..].iter().position(|&b| b != 0).map(|i| start + i)
                    };
                    assert_eq!(
                        row_first_nonzero_from(&row, start),
                        naive,
                        "row_first_nonzero_from mismatch (len={len}, density={density}, seed={seed}, start={start})"
                    );
                }
            }
        }
    }
}

/// Explicit edge pins: all-zero row → always None; a single planted nonzero is
/// found from any start at or before it and missed from any start after it.
#[test]
fn row_first_nonzero_from_edge_cases() {
    // All-zero row → None from every start.
    let zeros = vec![0u8; 10];
    for start in 0..=12 {
        assert_eq!(row_first_nonzero_from(&zeros, start), None);
    }
    assert_eq!(row_nonzero_count(&zeros), 0);

    // Single nonzero planted at index 5.
    let mut one = vec![0u8; 10];
    one[5] = 0x9A;
    for start in 0..=5 {
        assert_eq!(
            row_first_nonzero_from(&one, start),
            Some(5),
            "start={start}"
        );
    }
    for start in 6..=12 {
        assert_eq!(row_first_nonzero_from(&one, start), None, "start={start}");
    }
    assert_eq!(row_nonzero_count(&one), 1);
}
